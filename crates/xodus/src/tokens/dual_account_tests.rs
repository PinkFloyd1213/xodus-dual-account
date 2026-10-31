//! Store/play account roles. Synthetic credentials and in-memory storage only.
use super::{
    backend::MemoryBackend,
    manager::{AccountRole, PASSPORT_STS, TokenManager},
    store::{TokenBackend, TokenStoreError},
};
use crate::models::secrets::{Token, User};
use std::{collections::HashMap, sync::Arc};

fn setup() -> (Arc<MemoryBackend>, TokenManager) {
    let backend = Arc::new(MemoryBackend::default());
    let manager = TokenManager::new(backend.clone(), Arc::new(MemoryBackend::default()));
    (backend, manager)
}

fn sign_in(manager: &TokenManager, name: &str) {
    let user = User {
        puid: format!("{name}-puid"),
        username: format!("{name}@example.test"),
    };
    let tokens = HashMap::from([(
        PASSPORT_STS.to_string(),
        Token::Compact(format!("{name}-sts")),
    )]);
    manager.save_user_session(user, tokens).unwrap();
}

fn sts(manager: &TokenManager) -> String {
    match manager.get_user_sts_token().unwrap() {
        Token::Compact(value) => value,
        Token::Legacy(_) => panic!("unexpected token kind"),
    }
}

#[test]
fn credential_dual_account_default_role_keeps_historical_keys() {
    let (backend, manager) = setup();
    assert_eq!(manager.role(), AccountRole::Store);
    sign_in(&manager, "store");
    assert!(backend.get("user-session").unwrap().is_some());
    assert!(backend.get("play/user-session").unwrap().is_none());
}

#[test]
fn credential_dual_account_roles_are_isolated() {
    let (backend, manager) = setup();
    sign_in(&manager, "store");
    sign_in(&manager.for_role(AccountRole::Play), "play");
    assert!(backend.get("play/user-session").unwrap().is_some());
    assert_eq!(manager.get_user().unwrap().username, "store@example.test");
    assert_eq!(sts(&manager), "store-sts");
    let play = manager.for_role(AccountRole::Play);
    assert_eq!(play.get_user().unwrap().username, "play@example.test");
    assert_eq!(sts(&play), "play-sts");
}

#[test]
fn credential_dual_account_play_falls_back_to_store() {
    let (_, manager) = setup();
    sign_in(&manager, "store");
    assert!(!manager.for_role(AccountRole::Play).has_user().unwrap());
    let resolved = manager.resolve(AccountRole::Play).unwrap();
    assert_eq!(resolved.role(), AccountRole::Store);
    assert_eq!(resolved.get_user().unwrap().username, "store@example.test");
    assert_eq!(sts(&resolved), "store-sts");

    sign_in(&manager.for_role(AccountRole::Play), "play");
    let resolved = manager.resolve(AccountRole::Play).unwrap();
    assert_eq!(resolved.role(), AccountRole::Play);
    assert_eq!(resolved.get_user().unwrap().username, "play@example.test");
    // Store requests never fall forward to the play account.
    assert_eq!(
        manager.resolve(AccountRole::Store).unwrap().role(),
        AccountRole::Store
    );
}

#[test]
fn credential_dual_account_fallback_reads_legacy_store_entries() {
    let (_, manager) = setup();
    manager
        .save_user(&User {
            puid: "legacy-puid".into(),
            username: "legacy@example.test".into(),
        })
        .unwrap();
    manager
        .save_user_token(PASSPORT_STS.into(), Token::Compact("legacy-sts".into()))
        .unwrap();
    let resolved = manager.resolve(AccountRole::Play).unwrap();
    assert_eq!(resolved.role(), AccountRole::Store);
    assert_eq!(sts(&resolved), "legacy-sts");
}

#[test]
fn credential_dual_account_play_logout_keeps_store_and_device() {
    let (backend, manager) = setup();
    manager
        .save_device_token(PASSPORT_STS.into(), Token::Compact("device-sts".into()))
        .unwrap();
    sign_in(&manager, "store");
    let play = manager.for_role(AccountRole::Play);
    sign_in(&play, "play");
    play.remove_persistent().unwrap();
    assert!(!play.has_user().unwrap());
    assert!(backend.get("play/user-session").unwrap().is_none());
    assert_eq!(manager.get_user().unwrap().username, "store@example.test");
    assert!(manager.get_device_sts_token().is_ok());
    assert_eq!(
        manager.resolve(AccountRole::Play).unwrap().role(),
        AccountRole::Store
    );
}

#[test]
fn credential_dual_account_store_logout_keeps_play() {
    let (_, manager) = setup();
    manager
        .save_device_token(PASSPORT_STS.into(), Token::Compact("device-sts".into()))
        .unwrap();
    sign_in(&manager, "store");
    sign_in(&manager.for_role(AccountRole::Play), "play");
    manager.remove_persistent().unwrap();
    assert!(matches!(manager.get_user(), Err(TokenStoreError::NotFound)));
    assert!(manager.get_device_sts_token().is_err());
    let play = manager.for_role(AccountRole::Play);
    assert_eq!(play.get_user().unwrap().username, "play@example.test");
}

#[test]
fn credential_dual_account_play_refresh_never_touches_store() {
    let (_, manager) = setup();
    sign_in(&manager, "store");
    sign_in(&manager.for_role(AccountRole::Play), "play");
    let resolved = manager.resolve(AccountRole::Play).unwrap();
    resolved
        .save_user_token(PASSPORT_STS.into(), Token::Compact("play-refreshed".into()))
        .unwrap();
    assert_eq!(sts(&resolved), "play-refreshed");
    assert_eq!(sts(&manager), "store-sts");
    assert_eq!(manager.get_user().unwrap().username, "store@example.test");
}

#[test]
fn credential_dual_account_fallback_refresh_stays_in_store() {
    let (backend, manager) = setup();
    sign_in(&manager, "store");
    let resolved = manager.resolve(AccountRole::Play).unwrap();
    resolved
        .save_user_token(
            PASSPORT_STS.into(),
            Token::Compact("store-refreshed".into()),
        )
        .unwrap();
    assert_eq!(sts(&manager), "store-refreshed");
    // Falling back never creates a play account as a side effect.
    assert!(backend.get("play/user-session").unwrap().is_none());
    assert!(backend.get("play/user-tokens").unwrap().is_none());
    assert!(!manager.for_role(AccountRole::Play).has_user().unwrap());
}
