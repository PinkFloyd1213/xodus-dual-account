use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::models::secrets::{Device, Token, TokenStore, User};
use crate::models::xbox::XstsResponse;
use crate::tokens::backend::{KeychainBackend, MemoryBackend};
use crate::tokens::store::{ExpiringTokenBackend, TokenBackend, TokenStoreError};

mod keys {
    pub const DEV_LICENSE: &str = "dev_license";
    pub const DEVICE_TOKENS: &str = "device-tokens";
    pub const USER_TOKENS: &str = "user-tokens";
    pub const USER_INFO: &str = "user-DA";
    pub const USER_SESSION: &str = "user-session";
}

#[derive(serde::Serialize, serde::Deserialize)]
struct UserSession {
    user: User,
    tokens: HashMap<String, Token>,
}

pub const PASSPORT_STS: &str = "http://Passport.NET/STS";

/// Which Microsoft account a user operation targets. `Store` owns licenses and
/// entitlements and keeps the historical keyring keys; `Play` is the identity a
/// running game sees and uses the same keys under a `play/` prefix. Device
/// identity and device tokens are shared by both roles.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccountRole {
    #[default]
    Store,
    Play,
}

impl AccountRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Play => "play",
        }
    }

    fn key(self, key: &'static str) -> Cow<'static, str> {
        match self {
            Self::Store => Cow::Borrowed(key),
            Self::Play => Cow::Owned(format!("play/{key}")),
        }
    }
}

/// Semantic facade over the two storage tiers: a persistent, keychain-backed tier
/// for STS/device/user credentials, and an ephemeral tier for short-lived
/// per-relying-party XSTS tokens. Centralizes the read-merge-write pattern that was
/// previously duplicated across `xodus-cli` and `xodus-service`.
#[derive(Clone)]
pub struct TokenManager {
    persistent: Arc<dyn TokenBackend>,
    ephemeral: Arc<dyn ExpiringTokenBackend>,
    role: AccountRole,
}

impl TokenManager {
    pub fn new(
        persistent: Arc<dyn TokenBackend>,
        ephemeral: Arc<dyn ExpiringTokenBackend>,
    ) -> Self {
        Self {
            persistent,
            ephemeral,
            role: AccountRole::Store,
        }
    }

    /// Keychain for persistent storage, in-memory for ephemeral - the default
    /// wiring for both `xodus-cli` and `xodus-service` today.
    pub fn with_keychain_and_memory() -> Self {
        Self::new(
            Arc::new(KeychainBackend),
            Arc::new(MemoryBackend::default()),
        )
    }

    /// Keychain for persistent storage, in-memory for ephemeral - the default
    /// wiring for both `xodus-cli` and `xodus-service` today.
    pub fn with_memory() -> Self {
        Self::new(
            Arc::new(MemoryBackend::default()),
            Arc::new(MemoryBackend::default()),
        )
    }

    /// The same storage, scoped to `role` for every user operation.
    pub fn for_role(&self, role: AccountRole) -> Self {
        Self {
            role,
            ..self.clone()
        }
    }

    pub fn role(&self) -> AccountRole {
        self.role
    }

    /// `Play` falls back to `Store` while no play account is stored, so a
    /// single-account setup keeps its exact behavior. Resolve once and use the
    /// returned manager for both reads and refreshed-token writes.
    pub fn resolve(&self, role: AccountRole) -> Result<Self, TokenStoreError> {
        let scoped = self.for_role(role);
        if role == AccountRole::Play && !scoped.has_user()? {
            return Ok(self.for_role(AccountRole::Store));
        }
        Ok(scoped)
    }

    pub fn has_user(&self) -> Result<bool, TokenStoreError> {
        Ok(self
            .persistent
            .get(&self.role.key(keys::USER_SESSION))?
            .is_some()
            || self
                .persistent
                .get(&self.role.key(keys::USER_INFO))?
                .is_some())
    }

    /// Removes this role's account. Device tokens belong to the store sign-in
    /// lifecycle and are never removed by a play logout.
    pub fn remove_persistent(&self) -> Result<(), TokenStoreError> {
        if self.role == AccountRole::Store {
            self.persistent.remove(keys::DEVICE_TOKENS)?;
        }
        self.persistent.remove(&self.role.key(keys::USER_TOKENS))?;
        self.persistent.remove(&self.role.key(keys::USER_INFO))?;
        // Clear legacy entries first so a failed logout never exposes a stale
        // account underneath a still-valid session.
        self.persistent.remove(&self.role.key(keys::USER_SESSION))
    }

    // ---- Device identity / license -----------------------------------------

    pub fn get_device_license(&self) -> Result<Device, TokenStoreError> {
        let bytes = self
            .persistent
            .get(keys::DEV_LICENSE)?
            .ok_or(TokenStoreError::NotFound)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save_device_license(&self, device: &Device) -> Result<(), TokenStoreError> {
        Self::write_verified(
            &*self.persistent,
            keys::DEV_LICENSE,
            &serde_json::to_vec(device)?,
        )
    }

    pub fn remove_device_license(&self) -> Result<(), TokenStoreError> {
        self.persistent.remove(keys::DEV_LICENSE)
    }

    // ---- Device STS tokens (keyed by SOAP "applies_to" address) -----------

    pub fn get_device_token_for(&self, address: &str) -> Result<Option<Token>, TokenStoreError> {
        Self::read_token_store(&*self.persistent, keys::DEVICE_TOKENS, address)
    }

    pub fn save_device_token(&self, address: String, token: Token) -> Result<(), TokenStoreError> {
        Self::write_token_store(&*self.persistent, keys::DEVICE_TOKENS, address, token)
    }

    pub fn get_device_sts_token(&self) -> Result<Token, TokenStoreError> {
        self.get_device_token_for(PASSPORT_STS)?
            .ok_or(TokenStoreError::NotFound)
    }

    // ---- User STS tokens (keyed by SOAP "applies_to" address) --------------

    pub fn get_user_token_for(&self, address: &str) -> Result<Option<Token>, TokenStoreError> {
        if let Some(session) = self.user_session()? {
            return Ok(session.tokens.get(address).cloned());
        }
        Self::read_token_store(
            &*self.persistent,
            &self.role.key(keys::USER_TOKENS),
            address,
        )
    }

    pub fn save_user_token(&self, address: String, token: Token) -> Result<(), TokenStoreError> {
        if let Some(mut session) = self.user_session()? {
            session.tokens.insert(address, token);
            return Self::write_verified(
                &*self.persistent,
                &self.role.key(keys::USER_SESSION),
                &serde_json::to_vec(&session)?,
            );
        }
        Self::write_token_store(
            &*self.persistent,
            &self.role.key(keys::USER_TOKENS),
            address,
            token,
        )
    }

    pub fn get_user_sts_token(&self) -> Result<Token, TokenStoreError> {
        self.get_user_token_for(PASSPORT_STS)?
            .ok_or(TokenStoreError::NotFound)
    }

    // ---- User info -----------------------------------------------------------

    pub fn get_user(&self) -> Result<User, TokenStoreError> {
        if let Some(session) = self.user_session()? {
            return Ok(session.user);
        }
        let bytes = self
            .persistent
            .get(&self.role.key(keys::USER_INFO))?
            .ok_or(TokenStoreError::NotFound)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save_user(&self, user: &User) -> Result<(), TokenStoreError> {
        Self::write_verified(
            &*self.persistent,
            &self.role.key(keys::USER_INFO),
            &serde_json::to_vec(user)?,
        )
    }

    fn user_session(&self) -> Result<Option<UserSession>, TokenStoreError> {
        self.persistent
            .get(&self.role.key(keys::USER_SESSION))?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
            .transpose()
    }

    /// Publish a newly authenticated account and its complete token set using
    /// one keyring value. Never merge tokens belonging to the previous account.
    /// Legacy entries remain readable until the first successful session save.
    pub fn save_user_session(
        &self,
        user: User,
        tokens: HashMap<String, Token>,
    ) -> Result<(), TokenStoreError> {
        if tokens.is_empty() || user.username.trim().is_empty() || user.puid.is_empty() {
            return Err(TokenStoreError::NotFound);
        }
        let session = UserSession { user, tokens };
        Self::write_verified(
            &*self.persistent,
            &self.role.key(keys::USER_SESSION),
            &serde_json::to_vec(&session)?,
        )
    }

    // ---- Ephemeral XSTS-by-relying-party cache --------------------------------
    // Keyed by relying party only (no callers today); include the role in the
    // key before caching user-bound XSTS for more than one account.

    pub fn get_cached_xsts(&self, relying_party: &str) -> Option<XstsResponse> {
        let bytes = self.ephemeral.get(relying_party).ok()??;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn cache_xsts(&self, relying_party: &str, token: &XstsResponse) {
        self.cache_xsts_response(relying_party, token);
    }

    fn cache_xsts_response(&self, key: &str, token: &XstsResponse) {
        let Ok(bytes) = serde_json::to_vec(token) else {
            return;
        };
        let remaining = (token.not_after - chrono::Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        let _ = self
            .ephemeral
            .set_with_expiry(key, &bytes, Instant::now() + remaining);
    }

    // ---- shared TokenStore read/modify/write helper ---------------------------

    fn write_verified(
        backend: &dyn TokenBackend,
        key: &str,
        bytes: &[u8],
    ) -> Result<(), TokenStoreError> {
        backend.set(key, bytes)?;
        match backend.get(key)? {
            Some(saved) if saved == bytes => Ok(()),
            _ => Err(TokenStoreError::WriteVerification),
        }
    }

    fn read_token_store(
        backend: &dyn TokenBackend,
        key: &str,
        address: &str,
    ) -> Result<Option<Token>, TokenStoreError> {
        let Some(bytes) = backend.get(key)? else {
            return Ok(None);
        };
        let store: TokenStore = serde_json::from_slice(&bytes)?;
        Ok(store.tokens.get(address).cloned())
    }

    fn write_token_store(
        backend: &dyn TokenBackend,
        key: &str,
        address: String,
        token: Token,
    ) -> Result<(), TokenStoreError> {
        let mut tokens: HashMap<String, Token> = match backend.get(key)? {
            Some(bytes) if !bytes.is_empty() => {
                match serde_json::from_slice::<TokenStore>(&bytes) {
                    Ok(store) => store.tokens,
                    // Only a freshly authenticated device token may replace its
                    // damaged cache. Never discard device identity or user tokens.
                    Err(_) if key == keys::DEVICE_TOKENS => HashMap::new(),
                    Err(error) => return Err(error.into()),
                }
            }
            _ => HashMap::new(),
        };
        tokens.insert(address, token);
        Self::write_verified(backend, key, &serde_json::to_vec(&TokenStore { tokens })?)
    }
}
