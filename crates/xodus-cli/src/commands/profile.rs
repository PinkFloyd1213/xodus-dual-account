//! Optional, bounded Xbox profile read. Never provisions a device or opens login.
use std::{process::ExitCode, time::Duration};
use base64::{Engine, prelude::BASE64_STANDARD};
use serde_json::{Value, json};
use xodus::{models::{live::ExchangeUserTokenOutcome, secrets::Token, soap}, tokens::TokenManager};

const PROFILE: &str = "https://profile.xboxlive.com/users/me/profile/settings?settings=Gamertag,PublicGamerpic";
const MAX_IMAGE: usize = 2 * 1024 * 1024;

pub(super) async fn bounded(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, &'static str> {
    if !response.status().is_success() { return Err("http-status"); }
    if response.content_length().is_some_and(|size| size > limit as u64) { return Err("response-size"); }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "response-read")? {
        if bytes.len() + chunk.len() > limit { return Err("response-size"); }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub(super) fn picture_url(text: &str) -> Option<reqwest::Url> {
    let url = reqwest::Url::parse(text).ok()?;
    let host = url.host_str()?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() || url.port().is_some()
        || !["gamerpic.xboxlive.com", "images-eds-ssl.xboxlive.com", "avatar-ssl.xboxlive.com", "xboxavatargamerpic.azureedge.net"].contains(&host) {
        return None;
    }
    Some(url)
}

fn fields(value: &Value) -> Result<(String, Option<reqwest::Url>), &'static str> {
    let users = value["profileUsers"].as_array().ok_or("profile-shape")?;
    if users.len() != 1 { return Err("profile-count"); }
    let settings = users[0]["settings"].as_array().ok_or("profile-settings")?;
    let setting = |name| settings.iter().find(|item| item["id"] == name).and_then(|item| item["value"].as_str());
    let gamertag = setting("Gamertag").map(str::trim).filter(|name| !name.is_empty()
        && name.len() <= 256 && !name.chars().any(char::is_control)).ok_or("gamertag")?;
    Ok((gamertag.to_owned(), setting("PublicGamerpic").and_then(picture_url)))
}

fn image_data(bytes: &[u8]) -> Option<String> {
    let mime = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") { "image/png" }
        else if bytes.starts_with(b"\xff\xd8\xff") { "image/jpeg" }
        else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") { "image/webp" }
        else { return None; };
    Some(format!("data:{mime};base64,{}", BASE64_STANDARD.encode(bytes)))
}

pub(super) async fn xbox_session(tokens: &TokenManager) -> Result<(reqwest::Client, String, String), &'static str> {
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
        .timeout(super::session::REQUEST_TIMEOUT).user_agent("xodus-nexus-profile/1").build().map_err(|_| "http-client")?;
    let (account, device, user) = super::session::prepare(tokens, &client).await.map_err(|stage| {
        super::session::diagnostic(stage); stage
    })?;
    // Reuse the upstream RPS -> Xbox user -> XSTS exchange. This is a bearer
    // user token (no ProofKey); it must not use the runtime's PoP-bound token.
    let outcome = super::session::exchange(|| async { xodus::api::live::exchange_user_token(&client, user.clone(), account.clone(), device.clone(),
        None, Some("Silent".into()), "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".into(),
        &[("user.auth.xboxlive.com".into(), Some(soap::PolicyReference::mbi_ssl()))])
        .await.map_err(|error| super::session::classify(&error)) }).await?;
    if let Some(stage) = super::session::rejection(&outcome) { return Err(stage); }
    let token: Token = match outcome {
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection)) if !collection.security_tokens.is_empty() => Token::try_from(collection.security_tokens.remove(0)).map_err(|_| "ticket-response-parse")?,
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(response)) => Token::try_from(*response).map_err(|_| "ticket-response-parse")?,
        _ => return Err("msa-response"),
    };
    let Token::Compact(ticket) = token else { return Err("msa-ticket"); };
    let user = xodus::api::xbox::authenticate_xbox_user(&client, ticket).await.map_err(|_| "xbox-user")?;
    let xsts = xodus::api::xbox::request_xsts_token(&client, user.token, "http://xboxlive.com").await.map_err(|_| "xsts")?;
    let uhs = xsts.user_hash().ok_or("xsts-claim")?;
    let authorization = format!("XBL3.0 x={uhs};{}", xsts.token);
    Ok((client, authorization, account))
}

async fn profile(tokens: &TokenManager) -> Result<Value, &'static str> {
    let (client, authorization, account) = xbox_session(tokens).await?;
    let response = client.get(PROFILE).header("Authorization", authorization)
        .header("x-xbl-contract-version", "2").send().await.map_err(|_| "profile-request")?;
    let body = bounded(response, 128 * 1024).await?;
    let (gamertag, picture) = fields(&serde_json::from_slice(&body).map_err(|_| "profile-json")?)?;
    // Fresh request, no Authorization/Signature or redirects to the image CDN.
    let image = if let Some(url) = picture {
        match client.get(url).send().await {
            Ok(response) => bounded(response, MAX_IMAGE).await.ok().and_then(|bytes| image_data(&bytes)),
            Err(_) => None,
        }
    } else { None };
    if tokens.get_user().map_err(|_| "account-changed")?.username != account { return Err("account-changed"); }
    Ok(json!({ "schema": 1, "account": account, "gamertag": gamertag, "gamerpicDataUrl": image }))
}

pub async fn run(tokens: &TokenManager, json_output: bool) -> ExitCode {
    let account = tokens.get_user().ok().map(|user|user.username);
    let membership = async {
        match account.as_deref() {
            Some(account) => super::subscription::lookup(tokens, account).await,
            None => json!({"status":"unknown"}),
        }
    };
    // Independent optional membership lookup must not delay the profile request
    // beyond its existing deadline or trigger interactive authentication.
    let (result, subscription) = tokio::join!(tokio::time::timeout(Duration::from_secs(45), profile(tokens)), membership);
    match result {
        Ok(Ok(mut value)) => {
            if value["account"].as_str() == account.as_deref() { value["subscription"] = subscription; }
            if json_output { println!("{value}"); } else { println!("{}", value["gamertag"].as_str().unwrap_or_default()); }
            ExitCode::SUCCESS
        }
        Ok(Err(stage)) => { eprintln!("Xbox profile is temporarily unavailable ({stage}); stored account is unchanged."); ExitCode::FAILURE }
        Err(_) => { eprintln!("Xbox profile request timed out; stored account is unchanged."); ExitCode::FAILURE }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_settings_are_validated_without_exposing_other_fields() {
        let value = json!({"profileUsers":[{"id":"private-id", "settings":[
            {"id":"Gamertag","value":"Example Gamer"},
            {"id":"PublicGamerpic","value":"https://gamerpic.xboxlive.com/avatar.png"}]}]});
        let (name, picture) = fields(&value).unwrap();
        assert_eq!(name, "Example Gamer"); assert!(picture.is_some());
        assert!(fields(&json!({"profileUsers":[]})).is_err());
        assert!(fields(&json!({"profileUsers":[{},{}]})).is_err());
        assert!(picture_url("http://gamerpic.xboxlive.com/a").is_none());
        assert!(picture_url("https://evil.test/a").is_none());
        assert!(picture_url("https://user:secret@gamerpic.xboxlive.com/a").is_none());
        assert!(image_data(b"<svg/>").is_none());
    }
}
