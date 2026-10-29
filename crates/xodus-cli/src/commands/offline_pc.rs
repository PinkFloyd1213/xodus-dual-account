//! Shows or changes whether this device is the Microsoft account's designated
//! offline PC, the setting the Xbox app calls "Offline permissions".
//!
//! The Xbox PC app reads and changes it through the PC Game App Front Door:
//!   GET  https://beige.xboxservices.com/pcgafd/config/offlinepc
//!   POST https://beige.xboxservices.com/pcgafd/config/offlinepc/{true|false}
//! authenticated with an XSTS token for relying party `http://mp.microsoft.com/`
//! that carries device, title and user claims. Microsoft allows one offline PC
//! per account and a few changes per year, so the write path requires an
//! explicit confirmation flag.
//!
//! Output contract (stdout, one JSON line, schema 1):
//! `{"schema":1,"enabled":bool,"requestSuccess":bool,"remainingToggles":n,
//!   "maxToggles":n,"periodDays":n,"nextChangeAt":"<RFC 3339>"|null}`
//! Diagnostics go to stderr as `NEXUS_OFFLINE_PC_V1 <stage> <status>`.
//!
//! With `--license-cache` the answer also governs the stored offline
//! licenses: a status that reads "not designated" and every applied change
//! remove them all, as the Xbox app requires one launch while online after
//! designating a device.
use std::process::ExitCode;

use base64::{Engine, prelude::BASE64_STANDARD};
use serde_json::{Value, json};
use xodus::tokens::TokenManager;

const ENDPOINT: &str = "https://beige.xboxservices.com/pcgafd/config/offlinepc";
const RELYING_PARTY: &str = "http://mp.microsoft.com/";
// Same client identity Xodus uses for its Xbox sign-in flows.
const CLIENT_ID: &str = "000000004424da1f";
const TITLE_ID: i64 = 704208617;
const MAX_BODY: usize = 64 * 1024;

fn diagnostic(stage: &str, status: u16) {
    eprintln!("NEXUS_OFFLINE_PC_V1 {stage} {status}");
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    set: Option<bool>,
    confirm: bool,
    license_cache: Option<&std::path::Path>,
) -> ExitCode {
    if set.is_some() && !confirm {
        diagnostic("confirm-required", 0);
        eprintln!(
            "Refusing to change the offline PC designation without --confirm: Microsoft allows only a few changes per year and designating this device un-designates any other."
        );
        return ExitCode::FAILURE;
    }
    // Device-bound Xbox sign-in: device token + title token + user token -> XSTS.
    let (_authenticator, sisu, device) =
        match xodus::auth::do_sisu(client, tokens, CLIENT_ID, TITLE_ID).await {
            Ok(result) => result,
            Err(_) => {
                diagnostic("device-sign-in", 0);
                eprintln!("Xbox device sign-in for the offline-permission request failed. Check your connection and sign-in.");
                return ExitCode::FAILURE;
            }
        };
    let xsts = match xodus::auth::get_xsts_token(
        Some(&device),
        Some(&sisu.title_token),
        Some(&sisu.user_token),
        RELYING_PARTY,
    )
    .await
    {
        Ok(token) => token,
        Err(_) => {
            diagnostic("xsts", 0);
            eprintln!("Xbox authorization for the offline-permission request failed. Check your connection and sign-in.");
            return ExitCode::FAILURE;
        }
    };
    let correlation = format!(
        "{}.0",
        BASE64_STANDARD.encode(uuid::Uuid::new_v4().as_bytes()).trim_end_matches('=')
    );
    let request = match set {
        None => client.get(ENDPOINT),
        Some(value) => client
            .post(format!("{ENDPOINT}/{value}"))
            .header("Content-Length", "0"),
    };
    let response = request
        .header("Authorization", xsts.authorization_header_value())
        .header("Accept", "application/json")
        .header("Accept-Language", "en-US")
        .header("X-MS-API-Version", "1.0")
        .header("x-xbl-contract-version", "1")
        .header("MS-CV", correlation.as_str())
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            diagnostic(if error.is_timeout() { "timeout" } else { "request" }, 0);
            eprintln!("Microsoft could not be reached for the offline-permission request. Check your connection and try again.");
            return ExitCode::FAILURE;
        }
    };
    let status = response.status().as_u16();
    let body = match response.bytes().await {
        Ok(bytes) if bytes.len() <= MAX_BODY => bytes,
        _ => {
            diagnostic("read", status);
            eprintln!("The offline-permission response could not be read.");
            return ExitCode::FAILURE;
        }
    };
    if !(200..300).contains(&status) {
        diagnostic("http", status);
        eprintln!(
            "Microsoft refused the offline-permission request (HTTP {status}).{}",
            if status == 401 || status == 403 { " Sign in again in Settings." } else { "" }
        );
        return ExitCode::FAILURE;
    }
    let Some(summary) = summarize(&body) else {
        diagnostic("schema", status);
        eprintln!("Microsoft returned an unrecognized offline-permission response.");
        return ExitCode::FAILURE;
    };
    diagnostic("ok", status);
    println!("{summary}");
    if let Some(root) = license_cache
        && designation_revokes(set, &summary)
    {
        match crate::license_cache::LicenseCache::new(root).revoke_all() {
            Ok(removed) => {
                eprintln!("Removed {removed} stored offline license(s): this device is not, or is no longer, the designated offline device.");
                crate::license_cache::diagnostic("content-cache-revoked");
            }
            Err(_) => crate::license_cache::diagnostic("content-cache-write-failed"),
        }
    }
    // A change Microsoft declined (for example no toggles left) is a failure
    // even though the status was readable.
    if set.is_some() && summary.get("requestSuccess") != Some(&Value::Bool(true)) {
        diagnostic("declined", status);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Whether Microsoft's answer ends the stored offline licenses: the device is
/// not designated, or the designation changed (either direction starts over).
fn designation_revokes(set: Option<bool>, summary: &Value) -> bool {
    let applied = set.is_some() && summary.get("requestSuccess") == Some(&Value::Bool(true));
    applied || summary.get("enabled") != Some(&Value::Bool(true))
}

/// Reduces Microsoft's response to the fields Nexus acts on. Dates before
/// 1970 (Microsoft's "no date" sentinel is 1601-01-01) become null.
fn summarize(body: &[u8]) -> Option<Value> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let permissions = value.get("offlinePermissions")?;
    let enabled = permissions.get("enabled")?.as_bool()?;
    let request = permissions.get("requestData").cloned().unwrap_or(Value::Null);
    let count = |key: &str| request.get(key).and_then(Value::as_u64).filter(|n| *n <= 10_000);
    let next_change_at = request
        .get("nextTimeToAdd")
        .and_then(Value::as_str)
        .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok())
        .filter(|time| time.timestamp() > 0)
        .map(|time| time.with_timezone(&chrono::Utc).to_rfc3339());
    Some(json!({
        "schema": 1,
        "enabled": enabled,
        "requestSuccess": request.get("success").and_then(Value::as_bool).unwrap_or(false),
        "remainingToggles": count("remainingTogglesForPeriod"),
        "maxToggles": count("maxTogglesPerPeriod"),
        "periodDays": count("periodLengthDays"),
        "nextChangeAt": next_change_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_offline_licenses_end_when_this_device_is_not_or_no_longer_designated() {
        let status = |enabled: bool, success: bool| json!({"schema": 1, "enabled": enabled, "requestSuccess": success});
        // Reading: designated keeps them, anything else revokes (device A after B was designated).
        assert!(!designation_revokes(None, &status(true, false)));
        assert!(designation_revokes(None, &status(false, false)));
        assert!(designation_revokes(None, &json!({"schema": 1})));
        // Turning offline play off locally revokes; so does turning it on, which needs fresh launches.
        assert!(designation_revokes(Some(false), &status(false, true)));
        assert!(designation_revokes(Some(true), &status(true, true)));
        // A declined change keeps whatever the status says.
        assert!(!designation_revokes(Some(false), &status(true, false)));
        assert!(designation_revokes(Some(true), &status(false, false)));
    }

    #[test]
    fn offline_pc_summary_keeps_only_allowlisted_fields_and_drops_the_sentinel_date() {
        let body = br#"{"offlinePermissions":{"enabled":true,"requestData":{"success":true,"maxTogglesPerPeriod":3,"remainingTogglesForPeriod":1,"periodLengthDays":365,"nextTimeToAdd":"1601-01-01T00:00:00+00:00"},"extra":"ignored"}}"#;
        let summary = summarize(body).unwrap();
        assert_eq!(summary["schema"], 1);
        assert_eq!(summary["enabled"], true);
        assert_eq!(summary["requestSuccess"], true);
        assert_eq!(summary["remainingToggles"], 1);
        assert_eq!(summary["maxToggles"], 3);
        assert_eq!(summary["periodDays"], 365);
        assert!(summary["nextChangeAt"].is_null());
        assert!(summary.get("extra").is_none());
        let later = br#"{"offlinePermissions":{"enabled":false,"requestData":{"success":false,"maxTogglesPerPeriod":3,"remainingTogglesForPeriod":0,"periodLengthDays":365,"nextTimeToAdd":"2027-03-01T10:00:00+00:00"}}}"#;
        let summary = summarize(later).unwrap();
        assert_eq!(summary["requestSuccess"], false);
        assert_eq!(summary["remainingToggles"], 0);
        assert_eq!(summary["nextChangeAt"], "2027-03-01T10:00:00+00:00");
        for bad in [&b"not json"[..], br#"{"offlinePermissions":{}}"#, br#"{"offlinePermissions":{"enabled":"yes"}}"#] {
            assert!(summarize(bad).is_none());
        }
        let minimal = br#"{"offlinePermissions":{"enabled":true}}"#;
        let summary = summarize(minimal).unwrap();
        assert_eq!(summary["requestSuccess"], false);
        assert!(summary["remainingToggles"].is_null());
    }
}
