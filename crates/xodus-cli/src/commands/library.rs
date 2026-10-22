//! Read-only Store entitlements. No interactive auth, provisioning, or cloud writes.
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use serde_json::{Value, json};
use std::{collections::BTreeMap, collections::HashSet, process::ExitCode, time::Duration};
use xodus::tokens::TokenManager;

fn product_id(id: &str) -> bool {
    id.len() == 12
        && id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn entries(body: &Value) -> Result<BTreeMap<String, Value>, &'static str> {
    let entries = body["entitlements"]
        .as_object()
        .ok_or("entitlement-shape")?;
    if entries.len() > 10_000 {
        return Err("entitlement-count");
    }
    entries.iter().map(|(id, item)| {
        if !product_id(id) || !item.is_object() { return Err("entitlement-product"); }
        let status = item["status"].as_str().filter(|s|s.len()<40).ok_or("entitlement-status")?;
        let trial = item["isTrial"].as_bool().ok_or("entitlement-trial")?;
        let sharing = item["sharingSource"].as_str().filter(|s|s.len()<40).ok_or("entitlement-sharing")?;
        let expiry = item["endDate"].as_str().filter(|s|s.len()<50)
            .filter(|s|chrono::DateTime::parse_from_rfc3339(s).is_ok()).ok_or("entitlement-expiry")?;
        let parent = match item.get("satisfiedByProductId") {
            None | Some(Value::Null) => None,
            Some(Value::String(id)) if product_id(id) => Some(id.as_str()),
            _ => return Err("entitlement-parent"),
        };
        // Unknown special licensing flags never become permanent ownership.
        let special = item.get("isPositron").map(|v|v.as_bool()!=Some(false)).unwrap_or(false);
        Ok((id.clone(), json!({"productId":id,"status":status,"isTrial":trial,
            "sharingSource":sharing,"endDate":expiry,"satisfiedByProductId":parent,"special":special})))
    }).collect()
}

async fn query(tokens: &TokenManager, market: &str) -> Result<Value, &'static str> {
    if market.len() != 2 || !market.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err("market");
    }
    let account = tokens.get_user().map_err(|_| "stored-account")?.username;
    let (client, ticket) = super::subscription::store_session(tokens, &account).await?;
    let mut all = BTreeMap::new();
    let mut continuation: Option<String> = None;
    let mut seen = HashSet::new();
    let mut total_bytes = 0;
    for _ in 0..20 {
        let cv = format!(
            "{}.0",
            STANDARD_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes())
        );
        let url = format!(
            "https://beige.xboxservices.com/PCGAFD/entitlements?market={market}&language=en-US&appVersion=0.2.3"
        );
        let mut request = client
            .get(url)
            .header("Authorization", &ticket)
            .header("X-MS-API-Version", "1.1")
            .header("Calling-App-Name", "Xodus-Nexus")
            .header("MS-CV", cv);
        if let Some(ref cursor) = continuation {
            request = request.header("x-ms-ct", cursor);
        }
        let mut response = request.send().await.map_err(|_| "entitlements-request")?;
        if !response.status().is_success() {
            return Err("entitlements-http");
        }
        continuation = match response.headers().get("x-ms-ct") {
            None => None,
            Some(value) => {
                let value = value.to_str().map_err(|_| "entitlements-cursor")?;
                if value.is_empty() {
                    None
                } else if value.len() > 4096 || !seen.insert(value.to_owned()) {
                    return Err("entitlements-pagination");
                } else {
                    Some(value.to_owned())
                }
            }
        };
        if response.content_length().is_some_and(|n| n > 4_194_304) {
            return Err("entitlements-size");
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "entitlements-read")? {
            total_bytes += chunk.len();
            if bytes.len() + chunk.len() > 4_194_304 || total_bytes > 16_777_216 {
                return Err("entitlements-size");
            }
            bytes.extend_from_slice(&chunk);
        }
        let page: Value = serde_json::from_slice(&bytes).map_err(|_| "entitlements-json")?;
        for (id, value) in entries(&page)? {
            if all.get(&id).is_some_and(|old| old != &value) {
                return Err("entitlements-inconsistent");
            }
            all.insert(id, value);
        }
        if all.len() > 10_000 {
            return Err("entitlement-count");
        }
        if continuation.is_none() {
            if tokens.get_user().map_err(|_| "account-check")?.username != account {
                return Err("account-changed");
            }
            return Ok(json!({"schema":1,"account":account,"market":market,
                "checkedAt":chrono::Utc::now().to_rfc3339(),"entitlements":all.into_values().collect::<Vec<_>>()}));
        }
    }
    Err("entitlements-pagination")
}

pub async fn run(tokens: &TokenManager, json_output: bool, market: String) -> ExitCode {
    if !json_output {
        eprintln!("Use library --json for the Nexus entitlement protocol.");
        return ExitCode::FAILURE;
    }
    match tokio::time::timeout(
        Duration::from_secs(45),
        query(tokens, &market.to_ascii_uppercase()),
    )
    .await
    {
        Ok(Ok(value)) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Ok(Err(stage)) => {
            eprintln!(
                "Account library unavailable ({stage}); credentials and installed games are unchanged."
            );
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("Account library timed out; installed games are unchanged.");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keeps_only_license_fields_no_account_tokens_or_renewal_details() {
        let row = json!({"status":"Active","isTrial":false,"sharingSource":"None","endDate":"2099-01-01T00:00:00Z","satisfiedByProductId":"CFQ7TTC0KGQ8","secret":"not-output"});
        let result = entries(&json!({"entitlements":{"9AAAAAAAAAAA":row}})).unwrap();
        assert_eq!(
            result["9AAAAAAAAAAA"]["satisfiedByProductId"],
            "CFQ7TTC0KGQ8"
        );
        assert!(result["9AAAAAAAAAAA"].get("secret").is_none());
        assert!(entries(&json!({})).is_err());
        assert!(entries(&json!({"entitlements":{"bad":{}}})).is_err());
    }
}
