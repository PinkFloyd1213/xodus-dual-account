use std::process::ExitCode;

use xodus::models::live::{DAProperty, ExchangeUserTokenOutcome};
use xodus::models::{secrets, soap};
use xodus::tokens::TokenManager;

use crate::webview;

pub(super) const CLIENT_ID: &str = "000000004424da1f";
const LOGIN_MARKET: &str = "en-US";
const USER_AUTH_SCOPE: &str = "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0";

pub async fn run(client: &reqwest::Client, tokens: &TokenManager) -> ExitCode {
    super::subscription::clear();
    let token = match tokens.get_device_sts_token() {
        Ok(token) => token,
        Err(error) => {
            error.report();
            return ExitCode::FAILURE;
        }
    };
    let secrets::Token::Legacy(token) = token else {
        eprintln!("Invalid STS token");
        return ExitCode::FAILURE;
    };
    let handler = LoginHandler::new(client.clone(), token);
    let output = match webview::run_sessions(handler) {
        Ok(output) => output.flatten(),
        Err(error) => {
            if let Some(error) = error.downcast_ref::<xodus::tokens::store::TokenStoreError>() {
                error.report();
            } else {
                eprintln!("Sign-in did not complete.");
            }
            return ExitCode::FAILURE;
        }
    };
    let Some((user, body)) = output else {
        eprintln!("Sign-in did not complete.");
        return ExitCode::FAILURE;
    };
    let issued_tokens = match body {
        soap::BodyContent::RequestSecurityTokenResponseCollection(collection) => {
            collection.security_tokens
        }
        soap::BodyContent::RequestSecurityTokenResponse(token) => vec![*token],
        _ => {
            eprintln!("Microsoft returned an unsupported sign-in response.");
            return ExitCode::FAILURE;
        }
    };

    if issued_tokens.is_empty() {
        return ExitCode::FAILURE;
    }
    let mut issued = std::collections::HashMap::new();
    for token in issued_tokens {
        let address = token.applies_to.endpoint_reference.address.clone();
        let token = match secrets::Token::try_from(token) {
            Ok(token) => token,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
        };
        let address = if let secrets::Token::Legacy(legacy) = &token {
            legacy.key_name.clone().unwrap_or(address)
        } else {
            address
        };
        issued.insert(address, token);
    }
    if let Err(error) = tokens.save_user_session(user, issued) {
        error.report();
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

struct LoginHandler {
    client: reqwest::Client,
    device: xodus::models::secrets::LegacyToken,
    client_id: String,
    finish: bool,
}

impl LoginHandler {
    fn new(client: reqwest::Client, device: xodus::models::secrets::LegacyToken) -> Self {
        Self {
            client,
            device,
            client_id: CLIENT_ID.to_string(),
            finish: false,
        }
    }

    fn exchange_user_token(
        &self,
        prop: DAProperty,
    ) -> Result<ExchangeUserTokenOutcome, Box<dyn std::error::Error>> {
        let client = self.client.clone();
        let device_token = self.device.clone();
        let client_id = self.client_id.clone();
        let username = prop.username;
        let inline_ft = prop.sts_inline_flow_token;
        let user_token = xodus::models::secrets::LegacyToken {
            key_name: None,
            token: prop.da_token,
            binary_secret: None,
            tpm_key: None,
            lifetime: soap::Timestamp {
                id: None,
                created: prop.da_start_time,
                expires: prop.da_expires,
            },
        };

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let mut scopes = vec![(
                    USER_AUTH_SCOPE.to_string(),
                    Some(soap::PolicyReference::token_broker()),
                )];

                if self.finish {
                    scopes.push(("http://Passport.NET/tb".to_string(), None));
                }

                xodus::api::live::exchange_user_token(
                    &client,
                    user_token,
                    username,
                    device_token,
                    Some(inline_ft),
                    None,
                    client_id,
                    &scopes,
                )
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            })
        })
    }
}

impl webview::SessionHandler for LoginHandler {
    type Output = Option<(secrets::User, soap::BodyContent)>;

    fn bootstrap(
        &mut self,
        runtime: &mut webview::RuntimeCommands,
    ) -> Result<(), Box<dyn std::error::Error>> {
        runtime.open_session(webview::login_request(
            self.client_id.clone(),
            LOGIN_MARKET.to_string(),
        ));
        Ok(())
    }

    fn on_token(
        &mut self,
        session_id: webview::SessionId,
        data: DAProperty,
        runtime: &mut webview::RuntimeCommands,
    ) -> Result<webview::HandlerControl<Self::Output>, Box<dyn std::error::Error>> {
        let exchanged = self.exchange_user_token(data.clone())?;

        match exchanged {
            ExchangeUserTokenOutcome::Fault(pp) => {
                if let Some(pp) = pp
                    && let Some(auth_url) = pp.inline_auth_url
                {
                    runtime.close_session(session_id);
                    self.finish = true;
                    runtime.open_session(webview::finalize_request(auth_url));
                    return Ok(webview::HandlerControl::Continue);
                }

                println!("User token exchange returned a fault without inline auth");
                runtime.close_session(session_id);
                Ok(webview::HandlerControl::Complete(None))
            }
            ExchangeUserTokenOutcome::Issued(da) => {
                runtime.close_session(session_id);
                let user = secrets::User {
                    puid: data.puid,
                    username: data.username,
                };
                Ok(webview::HandlerControl::Complete(Some((user, da))))
            }
        }
    }

    fn on_closed(
        &mut self,
        _session_id: webview::SessionId,
        _runtime: &mut webview::RuntimeCommands,
    ) -> Result<webview::HandlerControl<Self::Output>, Box<dyn std::error::Error>> {
        Ok(webview::HandlerControl::Complete(None))
    }
}
