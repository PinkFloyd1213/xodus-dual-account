//! Compatibility metadata from authenticated MSA sessions, not an entitlement.
use xodus::models::secrets::User;

fn account_id(puid: &str) -> Option<String> {
    if puid.len() != 16 || !puid.bytes().all(|c| c.is_ascii_hexdigit()) || puid.bytes().all(|c| c == b'0') {
        return None;
    }
    Some(puid.to_ascii_lowercase())
}

pub fn bound_ids(ticket: Option<&User>, store: Option<&User>) -> (Option<String>, Option<String>) {
    let Some((ticket, store)) = ticket.zip(store) else { return (None, None) };
    let Some(xbox) = account_id(&ticket.puid) else { return (None, None) };
    let Some(store_id) = account_id(&store.puid) else { return (None, None) };
    // A change/logout while exchanging tickets must not publish a mixed pair.
    if xbox != store_id || ticket.username.is_empty() || !ticket.username.eq_ignore_ascii_case(&store.username) {
        return (None, None);
    }
    (Some(xbox), Some(store_id))
}

/// Dual-account (store/play): the Xbox id comes from the play session that
/// issued the ticket, checked against a re-read of that same session; the Store
/// id from the store session. As on Windows, the two accounts may differ. With
/// no play account both sessions are the store one, so this equals `bound_ids`.
pub fn bound_ids_for_roles(ticket: Option<&User>, current: Option<&User>, store: Option<&User>) -> (Option<String>, Option<String>) {
    let (Some(xbox), _) = bound_ids(ticket, current) else { return (None, None) };
    let Some(store_id) = store.and_then(|store| account_id(&store.puid)) else { return (None, None) };
    (Some(xbox), Some(store_id))
}

#[cfg(test)]
mod tests {
    #[test]
    fn account_metadata_pairs_play_and_store_like_windows() {
        let play = user("0123456789ABCDEF");
        let store = User { puid: "fedcba9876543210".into(), username: "store@example.invalid".into() };
        assert_eq!(bound_ids_for_roles(Some(&play), Some(&play), Some(&store)),
            (Some("0123456789abcdef".into()), Some("fedcba9876543210".into())));
        // Single account (play falls back to store): identical to bound_ids.
        assert_eq!(bound_ids_for_roles(Some(&store), Some(&store), Some(&store)), bound_ids(Some(&store), Some(&store)));
        // The play session changed during the exchange, or a session is missing.
        assert_eq!(bound_ids_for_roles(Some(&play), Some(&store), Some(&store)), (None, None));
        assert_eq!(bound_ids_for_roles(Some(&play), None, Some(&store)), (None, None));
        assert_eq!(bound_ids_for_roles(Some(&play), Some(&play), None), (None, None));
        assert_eq!(bound_ids_for_roles(Some(&play), Some(&play), Some(&user("0000000000000000"))), (None, None));
    }
    use super::*;
    fn user(puid: &str) -> User { User { puid: puid.into(), username: "synthetic@example.invalid".into() } }
    #[test]
    fn account_metadata_uses_real_session_ids_and_rejects_mixed_accounts() {
        let a = user("0123456789ABCDEF");
        let b = user("fedcba9876543210");
        assert_eq!(bound_ids(Some(&a), Some(&a)), (Some("0123456789abcdef".into()), Some("0123456789abcdef".into())));
        assert_eq!(bound_ids(Some(&a), Some(&b)), (None, None));
        assert_eq!(bound_ids(Some(&a), None), (None, None));
        assert_eq!(bound_ids(None, Some(&a)), (None, None));
        let renamed = User { puid: a.puid.clone(), username: "other@example.invalid".into() };
        assert_eq!(bound_ids(Some(&a), Some(&renamed)), (None, None));
    }
    #[test]
    fn account_metadata_rejects_placeholder_malformed_and_empty_ids() {
        for value in ["", "0", "0000000000000000", "281474000000000000000", "synthetic", "0123456789abcdeg", "0123456789abcdef\n"] {
            let bad = user(value);
            assert_eq!(bound_ids(Some(&bad), Some(&bad)), (None, None));
        }
    }
    #[test]
    fn account_metadata_xml_is_additive_and_omitted_for_unbound_sessions() {
        use xodus::models::xgameruntime::xuser::MSATokenResponse;
        let mut value = MSATokenResponse { token: "synthetic-ticket".into(), expiry: 1, device_rps: "synthetic-device".into(), device_expiry: 2, xbox_msa_account_id: None, store_msa_account_id: None };
        let xml = quick_xml::se::to_string(&value).unwrap();
        assert!(!xml.contains("MsaAccountId"));
        value.xbox_msa_account_id = Some("0123456789abcdef".into());
        value.store_msa_account_id = Some("0123456789abcdef".into());
        let xml = quick_xml::se::to_string(&value).unwrap();
        assert!(xml.contains("<XboxMsaAccountId>0123456789abcdef</XboxMsaAccountId>"));
        assert!(xml.contains("<StoreMsaAccountId>0123456789abcdef</StoreMsaAccountId>"));
    }
}
