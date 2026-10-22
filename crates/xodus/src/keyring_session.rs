//! Graceful shutdown of a Nexus-owned session provider. No credentials or wallet policy.
use dbus::blocking::Connection;
use std::{fs, os::unix::fs::MetadataExt, path::Path, thread, time::{Duration, Instant}};

#[derive(Debug, PartialEq, Eq)]
pub enum StopState { Stopped, Skipped, Unavailable }
impl StopState {
    pub fn as_str(&self) -> &'static str {
        match self { Self::Stopped => "stopped", Self::Skipped => "skipped", Self::Unavailable => "unavailable" }
    }
}

fn session_cgroup(text: &str) -> bool {
    if text.len() > 16_384 { return false; }
    text.lines().any(|line| {
        let Some(path) = line.strip_prefix("0::/") else { return false; };
        let Some(unit) = path.rsplit('/').next() else { return false; };
        let Some(id) = unit.strip_prefix("xodus-nexus-keyring-").and_then(|s| s.strip_suffix(".service")) else { return false; };
        id.len() == 36 && id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_digit() || (b'a'..=b'f').contains(&b) }
        })
    })
}

fn managed_provider(pid: u32, uid: u32) -> bool {
    let process = format!("/proc/{pid}");
    let Ok(meta) = fs::metadata(&process) else { return false; };
    if pid < 2 || meta.uid() != uid { return false; }
    let Ok(binary) = fs::read_link(format!("{process}/exe")) else { return false; };
    if !["/usr/bin/ksecretd", "/usr/bin/kwalletd6", "/usr/bin/kwalletd5"].iter().any(|p| binary == Path::new(p)) { return false; }
    let Ok(meta) = fs::metadata(binary) else { return false; };
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 { return false; }
    fs::read_to_string(format!("{process}/cgroup")).is_ok_and(|text| session_cgroup(&text))
}

pub fn stop_session_provider(pid: u32) -> StopState {
    let Ok(meta) = fs::metadata("/proc/self") else { return StopState::Unavailable; };
    let uid = meta.uid();
    if !managed_provider(pid, uid) { return StopState::Skipped; }
    let Ok(connection) = Connection::new_session() else { return StopState::Unavailable; };
    stop_on(&connection, pid, uid, |p| managed_provider(p, uid), Duration::from_secs(8)).unwrap_or(StopState::Unavailable)
}

fn stop_on(connection: &Connection, pid: u32, uid: u32, verify: impl FnOnce(u32) -> bool, timeout: Duration) -> Result<StopState, dbus::Error> {
    let deadline = Instant::now() + timeout;
    let bus = connection.with_proxy("org.freedesktop.DBus", "/org/freedesktop/DBus", timeout.min(Duration::from_secs(3)));
    let owner = match bus.method_call::<(String,), _, _, _>("org.freedesktop.DBus", "GetNameOwner", ("org.freedesktop.secrets",)) {
        Ok((owner,)) => owner,
        Err(error) if error.name() == Some("org.freedesktop.DBus.Error.NameHasNoOwner") => return Ok(StopState::Skipped),
        Err(error) => return Err(error),
    };
    let (owner_pid,): (u32,) = bus.method_call("org.freedesktop.DBus", "GetConnectionUnixProcessID", (&owner,))?;
    let (owner_uid,): (u32,) = bus.method_call("org.freedesktop.DBus", "GetConnectionUnixUser", (&owner,))?;
    if owner_pid != pid || owner_uid != uid || !verify(pid) { return Ok(StopState::Skipped); }
    let (current,): (String,) = bus.method_call("org.freedesktop.DBus", "GetNameOwner", ("org.freedesktop.secrets",))?;
    if current != owner { return Ok(StopState::Skipped); }
    // Bind to the verified unique connection, never a replacement service.
    // Qt's normal event-loop exit runs the provider's destructor and flushes
    // pending writes. SIGTERM alone does not provide that lifecycle guarantee.
    let app = connection.with_proxy(owner.as_str(), "/MainApplication", timeout.min(Duration::from_secs(3)));
    let _: () = app.method_call("org.qtproject.Qt.QCoreApplication", "quit", ())?;
    loop {
        let (alive,): (bool,) = bus.method_call("org.freedesktop.DBus", "NameHasOwner", (&owner,))?;
        if !alive { return Ok(StopState::Stopped); }
        if Instant::now() >= deadline { return Ok(StopState::Unavailable); }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
#[path = "keyring_session_tests.rs"]
mod tests;
