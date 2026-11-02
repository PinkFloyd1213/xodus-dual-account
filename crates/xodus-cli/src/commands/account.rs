//! `account --account play`: which account a game would run as. The default
//! `account` output stays in main.rs, unchanged for existing launchers.
use std::process::ExitCode;

use serde_json::json;
use xodus::tokens::store::TokenStoreError;
use xodus::tokens::{AccountRole, TokenManager};

/// Same `stored`/`username` fields as the store output, plus the role actually
/// used and whether play falls back to the store account.
pub fn play(tokens: &TokenManager, json_output: bool) -> ExitCode {
    let resolved = tokens.resolve(AccountRole::Play);
    let role = resolved
        .as_ref()
        .map_or(AccountRole::Play, TokenManager::role);
    let fallback = role != AccountRole::Play;
    let mut value = json!({ "role": role.as_str(), "fallback": fallback });
    match resolved.and_then(|tokens| tokens.get_user()) {
        Ok(user) => {
            value["stored"] = true.into();
            if !json_output {
                let source = if fallback { "store fallback" } else { "play" };
                println!("{} ({source})", user.username);
            }
            value["username"] = user.username.into();
        }
        Err(TokenStoreError::NotFound) => {
            value["stored"] = false.into();
            if !json_output {
                println!("No stored Microsoft account");
            }
        }
        Err(error) => {
            eprintln!("Unable to read the stored account: {error}");
            return ExitCode::FAILURE;
        }
    }
    if json_output {
        println!("{value}");
    }
    ExitCode::SUCCESS
}
