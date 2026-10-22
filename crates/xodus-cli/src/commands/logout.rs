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
