use crate::hardware;
use crate::licensing::splicense::SPLicense;
use crate::licensing::utils::{generate_string, parse_bcrypt_rsa_private};
use crate::models::devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo};
use crate::models::secrets::Device;
use crate::models::soap::BodyContent;
use crate::tokens::manager::TokenManager;
use crate::tokens::store::TokenStoreError;

/// Provisions a device (if none is stored yet) or re-authenticates an existing one
/// (if its STS token is missing/expired), persisting the result through `tokens`.
pub async fn ensure_device_credentials(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> Result<(), TokenStoreError> {
    match tokens.get_device_license() {
        Err(TokenStoreError::NotFound) => provision_device(client, tokens).await?,
        Err(error) => return Err(error),
        Ok(license) => match tokens.get_device_sts_token() {
            Ok(_) => {}
            Err(TokenStoreError::NotFound | TokenStoreError::Serde(_)) => {
                reauthenticate_device(client, tokens, license).await?;
            }
            Err(error) => return Err(error),
        },
    }
    // Network success alone does not prove that a usable token was saved.
    tokens.get_device_sts_token()?;
    Ok(())
}

async fn provision_device(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> Result<(), TokenStoreError> {
    let username = format!("02{}", generate_string(14));
    let password = generate_string(20);
    let provision = DeviceAddRequest {
        client_info: ClientInfo::default(),
        authentication: Authentication::new(username.clone(), password.clone()),
        device_info: Some(DeviceInfo {
            id: "DeviceInfo".to_string(),
            components: hardware::probe_provision_components(),
            tpm_info: None,
        }),
    };

    let dev = crate::api::live::login_device_credential(client, provision)
        .await
        .map_err(|_| TokenStoreError::DeviceAuthentication)?;

    let device = Device {
        username: username.clone(),
        password: password.clone(),
        puid: dev.puid,
        hwid: dev.hw_device_id,
        device_id: dev.license.binding.device_id.unwrap_or_default(),
        splicense: dev.license.splicense_block,
    };

    tokens.save_device_license(&device)?;

    reauthenticate_device(client, tokens, device).await
}

async fn reauthenticate_device(
    client: &reqwest::Client,
    tokens: &TokenManager,
    license: Device,
) -> Result<(), TokenStoreError> {
    let sp_license = SPLicense::parse_base64(&license.splicense)
        .map_err(|_| TokenStoreError::DeviceAuthentication)?;
    let clep_sign_state = sp_license
        .clep_sign_state
        .ok_or(TokenStoreError::DeviceAuthentication)?;
    let key = clep_sign_state.get_rsa_key();
    let private_key =
        parse_bcrypt_rsa_private(&key).map_err(|_| TokenStoreError::DeviceAuthentication)?;
    let resp = crate::api::live::authenticate_device(client, license.username, private_key)
        .await
        .map_err(|_| TokenStoreError::DeviceAuthentication)?;

    if let BodyContent::RequestSecurityTokenResponse(resp) = resp.body.body {
        save_device_sts_token(tokens, resp)
    } else {
        Err(TokenStoreError::DeviceAuthentication)
    }
}

fn save_device_sts_token(
    tokens: &TokenManager,
    resp: Box<crate::models::soap::RequestSecurityTokenResponse>,
) -> Result<(), TokenStoreError> {
    let key_name = resp
        .requested_security_token
        .encrypted_data
        .as_ref()
        .ok_or(TokenStoreError::DeviceAuthentication)?
        .key_info
        .key_name
        .as_ref()
        .ok_or(TokenStoreError::DeviceAuthentication)?
        .clone();
    let token = (*resp).into();
    tokens.save_device_token(key_name, token)
}
