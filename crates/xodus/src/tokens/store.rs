use std::time::Instant;

pub trait TokenBackend: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, TokenStoreError>;
    fn set(&self, key: &str, value: &[u8]) -> Result<(), TokenStoreError>;
    fn remove(&self, key: &str) -> Result<(), TokenStoreError>;
}

pub trait ExpiringTokenBackend: TokenBackend {
    fn set_with_expiry(
        &self,
        key: &str,
        value: &[u8],
        expires_at: Instant,
    ) -> Result<(), TokenStoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TokenStoreError {
    #[error("The system keyring could not be accessed. Check that it is running and unlocked.")]
    Keychain(#[from] keyring_core::Error),
    #[error("Stored Xodus credentials could not be read or saved.")]
    Io(#[from] std::io::Error),
    #[error("Stored Xodus credentials are empty or invalid. Check the system keyring.")]
    Serde(#[from] serde_json::Error),
    #[error("Required Xodus credentials are missing. Please sign in again.")]
    NotFound,
    #[error(
        "The system keyring did not return the credentials just saved. Check the keyring service before trying sign-in again."
    )]
    WriteVerification,
    #[error("Device authentication did not complete. Check the network connection and try again.")]
    DeviceAuthentication,
}

impl TokenStoreError {
    /// Stable allowlist, never includes provider messages or stored JSON values.
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::Keychain(_) => "keyring-unavailable",
            Self::Io(_) => "credential-io",
            Self::Serde(_) => "keyring-invalid-data",
            Self::NotFound => "keyring-missing-data",
            Self::WriteVerification => "keyring-write-verification",
            Self::DeviceAuthentication => "device-authentication",
        }
    }
    pub fn report(&self) {
        eprintln!("NEXUS_CREDENTIAL_ERROR_V1 {}", self.diagnostic_code());
        eprintln!("{self}");
    }
}
