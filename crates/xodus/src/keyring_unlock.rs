//! Explicit Secret Service unlock. No credentials, sessions, items or network.
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use dbus::{arg::{RefArg, Variant}, blocking::{Connection, stdintf::org_freedesktop_dbus::Properties}, message::MatchRule, Path};
#[path = "keyring_prompt_window.rs"]
mod prompt_window;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockState { Ready, Stopped, NeedsSetup, Locked, Cancelled, TimedOut, Unavailable }
impl UnlockState {
    pub fn as_str(self) -> &'static str {
        match self { Self::Ready => "ready", Self::Stopped => "stopped", Self::NeedsSetup => "needs-setup",
            Self::Locked => "locked", Self::Cancelled => "cancelled", Self::TimedOut => "timed-out", Self::Unavailable => "unavailable" }
    }
}

fn valid_window_id(value: &str) -> bool {
    value.len() <= 20 && value.bytes().all(|b| b.is_ascii_digit())
}

pub fn unlock_default(window_id: &str, cancelled: &AtomicBool) -> UnlockState {
    if !valid_window_id(window_id) { return UnlockState::Unavailable; }
    let Ok(connection) = Connection::new_session() else { return UnlockState::Unavailable; };
    let gamescope = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().split(':').any(|v| v.eq_ignore_ascii_case("gamescope"));
    unlock_scoped(&connection, window_id, cancelled, Duration::from_secs(90), gamescope).unwrap_or(UnlockState::Unavailable)
}

#[cfg(test)]
fn unlock_on(connection: &Connection, window_id: &str, cancelled: &AtomicBool, timeout: Duration) -> Result<UnlockState, dbus::Error> {
    unlock_scoped(connection, window_id, cancelled, timeout, false)
}
fn unlock_scoped(connection: &Connection, window_id: &str, cancelled: &AtomicBool, timeout: Duration, gamescope: bool) -> Result<UnlockState, dbus::Error> {
    let bus = connection.with_proxy("org.freedesktop.DBus", "/org/freedesktop/DBus", Duration::from_secs(3));
    let (owned,): (bool,) = bus.method_call("org.freedesktop.DBus", "NameHasOwner", ("org.freedesktop.secrets",))?;
    if !owned { return Ok(UnlockState::Stopped); }
    // Bind all operations and the signal to the current owner. Never activate
    // a replacement provider or accept a completion from another connection.
    let (owner,): (String,) = bus.method_call("org.freedesktop.DBus", "GetNameOwner", ("org.freedesktop.secrets",))?;
    let service = connection.with_proxy(owner.clone(), "/org/freedesktop/secrets", Duration::from_secs(3));
    let (collection,): (Path<'static>,) = service.method_call("org.freedesktop.Secret.Service", "ReadAlias", ("default",))?;
    if collection.to_string() == "/" { return Ok(UnlockState::NeedsSetup); }
    let locked = || -> Result<bool, dbus::Error> {
        connection.with_proxy(owner.clone(), collection.clone(), Duration::from_secs(3))
            .get("org.freedesktop.Secret.Collection", "Locked")
    };
    if !locked()? { return Ok(UnlockState::Ready); }
    if cancelled.load(Ordering::SeqCst) { return Ok(UnlockState::Cancelled); }
    let (pid,): (u32,) = bus.method_call("org.freedesktop.DBus", "GetConnectionUnixProcessID", (owner.clone(),))?;
    let mut windows = window_id.parse().ok().and_then(|parent| prompt_window::PromptWindows::new(parent, pid, gamescope));
    if gamescope && windows.is_none() { return Ok(UnlockState::Unavailable); }
    let (_unlocked, prompt): (Vec<Path<'static>>, Path<'static>) = service.method_call(
        "org.freedesktop.Secret.Service", "Unlock", (vec![collection.clone()],))?;
    if prompt.to_string() == "/" { return Ok(if locked()? { UnlockState::Locked } else { UnlockState::Ready }); }
    let complete = Arc::new(Mutex::new(None));
    let output = complete.clone();
    let rule = MatchRule::new_signal("org.freedesktop.Secret.Prompt", "Completed")
        .with_path(prompt.clone()).with_sender(owner.clone());
    let token = connection.add_match(rule, move |(dismissed, _): (bool, Variant<Box<dyn RefArg>>), _, _| {
        *output.lock().unwrap() = Some(dismissed);
        true
    })?;
    let proxy = connection.with_proxy(owner.clone(), prompt, Duration::from_secs(3));
    // A prompt is connection-specific. Keep this connection alive from Unlock
    // through Completed; separate busctl invocations cannot implement this.
    let result = (|| {
        let _: () = proxy.method_call("org.freedesktop.Secret.Prompt", "Prompt", (window_id,))?;
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(windows) = &mut windows { windows.update(); }
            if let Some(dismissed) = *complete.lock().unwrap() {
                return Ok(if dismissed { UnlockState::Cancelled }
                    else if locked()? { UnlockState::Locked } else { UnlockState::Ready });
            }
            if cancelled.load(Ordering::SeqCst) || Instant::now() >= deadline {
                if let Some(windows) = &windows { windows.dismiss(); }
                let _: Result<(), _> = proxy.method_call("org.freedesktop.Secret.Prompt", "Dismiss", ());
                return Ok(if cancelled.load(Ordering::SeqCst) { UnlockState::Cancelled } else { UnlockState::TimedOut });
            }
            connection.process(Duration::from_millis(100))?;
        }
    })();
    let _ = connection.remove_match(token);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keyring_unlock_window_id_is_bounded_and_not_an_arbitrary_argument() {
        for value in ["", "0", "12345", "18446744073709551615"] { assert!(valid_window_id(value)); }
        for value in ["-1", "1\n", "0x123", "--secret", "123456789012345678901"] { assert!(!valid_window_id(value)); }
    }
    #[test]
    fn keyring_unlock_states_are_fixed_and_never_contain_provider_text() {
        for state in [UnlockState::Ready, UnlockState::Stopped, UnlockState::NeedsSetup, UnlockState::Locked,
            UnlockState::Cancelled, UnlockState::TimedOut, UnlockState::Unavailable] {
            assert!(state.as_str().bytes().all(|b| b.is_ascii_lowercase() || b == b'-'));
        }
    }
}

#[cfg(test)]
#[path = "keyring_unlock_tests.rs"]
mod transport_tests;
