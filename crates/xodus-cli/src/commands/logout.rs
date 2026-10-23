use std::process::ExitCode;
use xodus::tokens::{AccountRole, TokenManager};

pub async fn run(tokens: &TokenManager, device: bool) -> ExitCode {
    // A play logout keeps the store account, device and membership cache.
    if tokens.role() == AccountRole::Play {
        if device {
            eprintln!("--device cannot be combined with --account play");
            return ExitCode::FAILURE;
        }
    } else {
        super::subscription::clear();
        // A device reset invalidates every account bound to that device, so a
        // full sign-out also removes the play account.
        if device
            && tokens
                .for_role(AccountRole::Play)
                .remove_persistent()
                .is_err()
        {
            return ExitCode::FAILURE;
        }
    }
    if device && tokens.remove_device_license().is_err() {
        return ExitCode::FAILURE;
    }
    match tokens.remove_persistent() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("Failed to logout {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use xodus::models::secrets::{Device, Token, User};
    use xodus::tokens::PASSPORT_STS;

    fn sign_in(tokens: &TokenManager, name: &str) {
        let user = User {
            puid: format!("{name}-puid"),
            username: format!("{name}@example.test"),
        };
        let issued = HashMap::from([(
            PASSPORT_STS.to_string(),
            Token::Compact(format!("{name}-sts")),
        )]);
        tokens.save_user_session(user, issued).unwrap();
    }

    fn setup() -> TokenManager {
        let tokens = TokenManager::with_memory();
        tokens
            .save_device_license(&Device {
                puid: "synthetic".into(),
                hwid: "synthetic".into(),
                device_id: "synthetic".into(),
                password: "synthetic".into(),
                username: "synthetic".into(),
                splicense: "synthetic".into(),
            })
            .unwrap();
        sign_in(&tokens, "store");
        sign_in(&tokens.for_role(AccountRole::Play), "play");
        tokens
    }

    #[tokio::test]
    async fn device_reset_signs_out_both_accounts() {
        let tokens = setup();
        assert_eq!(run(&tokens, true).await, ExitCode::SUCCESS);
        assert!(tokens.get_device_license().is_err());
        assert!(!tokens.has_user().unwrap());
        assert!(!tokens.for_role(AccountRole::Play).has_user().unwrap());
    }

    #[tokio::test]
    async fn plain_store_logout_keeps_play_and_play_logout_keeps_store() {
        let tokens = setup();
        assert_eq!(run(&tokens, false).await, ExitCode::SUCCESS);
        assert!(tokens.get_device_license().is_ok());
        assert!(tokens.for_role(AccountRole::Play).has_user().unwrap());
        let tokens = setup();
        assert_eq!(
            run(&tokens.for_role(AccountRole::Play), false).await,
            ExitCode::SUCCESS
        );
        assert!(tokens.has_user().unwrap());
        assert!(!tokens.for_role(AccountRole::Play).has_user().unwrap());
        assert_eq!(
            run(&tokens.for_role(AccountRole::Play), true).await,
            ExitCode::FAILURE
        );
    }
}
