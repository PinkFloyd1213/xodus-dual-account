use xodus::licensing::splicense::{DeviceKey, SPLicense};
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::Token;
use xodus::models::soap;
use xodus::tokens::TokenManager;

pub async fn get_license(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    market: String,
) -> std::result::Result<(DeviceKey, SPLicense), String> {
    let dev_token = tokens
        .get_device_sts_token()
        .map_err(|error| error.to_string())?;
    let Token::Legacy(dev_token) = dev_token else {
        return Err("Invalid STS token".to_string());
    };
    let user = tokens.get_user().map_err(|error| error.to_string())?;
    let user_token = tokens
        .get_user_sts_token()
        .map_err(|error| error.to_string())?;
    let Token::Legacy(legacy) = user_token else {
        return Err("Unspported user token".to_string());
    };

    let ms_device_token = xodus::api::live::exchange_device_token(
        client,
        dev_token.clone(),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        "www.microsoft.com".to_owned(),
        Some(soap::PolicyReference::mbi_ssl()),
    )
    .await
    .map_err(|_| {
        "Microsoft device-ticket request failed. Check your connection and sign-in.".to_string()
    })?;

    let user_token = xodus::api::live::exchange_user_token(
        client,
        legacy,
        user.username,
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "www.microsoft.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .map_err(|_| {
        "Microsoft user-ticket request failed. Check your connection and sign-in.".to_string()
    })?;

    let ms_device_token = Token::try_from(ms_device_token).map_err(|error| error.to_string())?;
    let Token::Compact(ms_device_token) = ms_device_token else {
        return Err("Unsupported token".to_string());
    };

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            return Err("Failed to get exchange MS token".to_string());
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(collection),
        ) => {
            let token = collection
                .security_tokens
                .into_iter()
                .next()
                .ok_or("Microsoft returned no content-licensing user ticket.")?;
            Token::try_from(token).map_err(|error| error.to_string())?
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => Token::try_from(*token).map_err(|error| error.to_string())?,
        _ => return Err("Microsoft returned an unsupported content-licensing user ticket.".into()),
    };
    let Token::Compact(user_token) = user_token else {
        return Err("Unsupported token".to_string());
    };
    let user_token = xodus::models::secrets::licensing_ticket(user_token);

    let (_content, game_license) = xodus::licensing::content::get_license_content(
        client,
        ms_device_token,
        user_token,
        user.puid,
        content_id,
        market,
    )
    .await
    .map_err(|err| err.to_string())?;

    license_material(tokens, &game_license.splicense_block)
}

fn license_material(tokens: &TokenManager, block: &str) -> Result<(DeviceKey, SPLicense), String> {
    let game_splicense = SPLicense::parse_base64(block).map_err(|_| {
        eprintln!("NEXUS_CONTENT_LICENSE_DIAGNOSTIC_V1 content-license-blob 0");
        "Microsoft returned an invalid content-license block. Share the backend diagnostic log."
            .to_string()
    })?;

    let dev_license = tokens
        .get_device_license()
        .map_err(|error| error.to_string())?;
    let device_license = SPLicense::parse_base64(&dev_license.splicense).map_err(|_| {
        "Stored device-license data is invalid. Sign in again in Settings.".to_string()
    })?;
    let key = device_license
        .encrypted_device_key
        .ok_or("Stored device license has no decryption key. Sign in again in Settings.")?
        .derive_device_key();
    Ok((key, game_splicense))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, prelude::BASE64_STANDARD};
    use xodus::models::secrets::Device;
    #[test]
    fn content_license_bad_blocks_return_fixed_errors_without_touching_credentials() {
        let tokens = TokenManager::with_memory();
        let error = license_material(&tokens, "private-secret-bad-base64")
            .err()
            .unwrap();
        assert!(error.contains("invalid content-license block"));
        assert!(!error.contains("private-secret"));
        assert!(tokens.get_device_license().is_err());
        let empty = BASE64_STANDARD.encode([0u8; 8]);
        assert!(license_material(&tokens, &empty).is_err());
        tokens
            .save_device_license(&Device {
                username: "synthetic".into(),
                password: "unused".into(),
                puid: "unused".into(),
                hwid: "unchanged".into(),
                device_id: "unchanged".into(),
                splicense: empty.clone(),
            })
            .unwrap();
        assert!(
            license_material(&tokens, &empty)
                .err()
                .unwrap()
                .contains("no decryption key")
        );
        assert_eq!(tokens.get_device_license().unwrap().hwid, "unchanged");
    }
}
