use super::*;
use dbus::{channel::{MatchingReceiver, Sender}, message::MatchRule};
use std::{io::{BufRead, BufReader}, process::{Child, Command, Stdio}, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}};
use std::os::unix::fs::PermissionsExt;

struct Bus { child: Child, root: std::path::PathBuf, address: String }
impl Bus {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("nexus-stop-test-{}-{}", std::process::id(), rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut child = Command::new("dbus-daemon").args(["--session", "--nofork", "--print-address=1", &format!("--address=unix:path={}/bus", root.display())])
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut address = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut address).unwrap();
        assert!(!address.trim().is_empty(), "Private test bus unavailable; local Unix sockets must be allowed");
        Self { child, root, address: address.trim().into() }
    }
}
impl Drop for Bus { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = fs::remove_dir_all(&self.root); } }

fn probe(mode: &'static str, wrong_pid: bool, wrong_uid: bool, managed: bool) -> (StopState, Vec<String>) {
    let bus = Bus::new();
    let connection = Connection::new_address(&bus.address).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (replace_tx, replace_rx) = std::sync::mpsc::channel();
    let (replaced_tx, replaced_rx) = std::sync::mpsc::channel();
    let address = bus.address.clone();
    let server_stop = stop.clone();
    let server_calls = calls.clone();
    let server = thread::spawn(move || {
        let service = Connection::new_address(&address).unwrap();
        let replacement = Connection::new_address(&address).unwrap();
        if mode != "stopped" { service.request_name("org.freedesktop.secrets", false, true, false).unwrap(); }
        let should_exit = server_stop.clone();
        service.start_receive(MatchRule::new_method_call(), Box::new(move |msg, connection| {
            assert_eq!(msg.path().unwrap().to_string(), "/MainApplication");
            assert_eq!(msg.interface().unwrap().to_string(), "org.qtproject.Qt.QCoreApplication");
            let method = msg.member().unwrap().to_string();
            assert_eq!(method, "quit", "No credential or wallet methods permitted");
            server_calls.lock().unwrap().push(method);
            if mode != "no-reply" { connection.send(msg.method_return()).unwrap(); }
            if mode == "complete" { should_exit.store(true, Ordering::SeqCst); }
            true
        }));
        ready_tx.send(()).unwrap();
        while !server_stop.load(Ordering::SeqCst) {
            if replace_rx.try_recv().is_ok() {
                service.release_name("org.freedesktop.secrets").unwrap();
                replacement.request_name("org.freedesktop.secrets", false, true, false).unwrap();
                replaced_tx.send(()).unwrap();
            }
            service.process(Duration::from_millis(2)).unwrap();
        }
    });
    ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let uid = fs::metadata("/proc/self").unwrap().uid() + u32::from(wrong_uid);
    let pid = std::process::id() + u32::from(wrong_pid);
    let result = stop_on(&connection, pid, uid, |_| {
        if mode == "replace" {
            replace_tx.send(()).unwrap();
            replaced_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        }
        managed
    }, Duration::from_millis(100)).unwrap_or(StopState::Unavailable);
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    let calls = calls.lock().unwrap().clone();
    (result, calls)
}

#[test]
fn keyring_session_stop_accepts_only_exact_nexus_service_cgroups() {
    let unit = "xodus-nexus-keyring-d07347b6-4b75-4707-9925-73b09ea38b21.service";
    assert!(session_cgroup(&format!("0::/user.slice/user-1000.slice/user@1000.service/app.slice/{unit}\n")));
    for value in ["0::/app.slice/plasma-ksecretd.service".to_string(),
        format!("1:cpu:/app.slice/{unit}"), format!("0::/app.slice/{unit}/child"),
        format!("0::/app.slice/{unit}.other"), "0::/app.slice/xodus-nexus-keyring-foreign.service".into(),
        format!("0::/app.slice/{}", unit.replace("d07347b6", "d07347B6")), "x".repeat(16_385)] {
        assert!(!session_cgroup(&value), "must reject unowned cgroup");
    }
}
#[test]
fn keyring_session_stop_rejects_unmanaged_process_before_connecting_to_user_bus() {
    assert_eq!(stop_session_provider(0), StopState::Skipped);
    assert_eq!(stop_session_provider(std::process::id()), StopState::Skipped);
}
#[test]
fn keyring_session_stop_private_bus_quits_only_verified_unique_owner_and_waits_for_exit() {
    let (state, calls) = probe("complete", false, false, true);
    assert_eq!(state, StopState::Stopped);
    assert_eq!(calls, ["quit"]);
}
#[test]
fn keyring_session_stop_private_bus_never_activates_an_absent_provider() {
    assert_eq!(probe("stopped", false, false, true), (StopState::Skipped, vec![]));
}
#[test]
fn keyring_session_stop_private_bus_rejects_foreign_pid_uid_and_cgroup() {
    for (pid, uid, managed) in [(true, false, true), (false, true, true), (false, false, false)] {
        assert_eq!(probe("complete", pid, uid, managed), (StopState::Skipped, vec![]));
    }
}
#[test]
fn keyring_session_stop_private_bus_never_quits_a_replacement_owner() {
    assert_eq!(probe("replace", false, false, true), (StopState::Skipped, vec![]));
}
#[test]
fn keyring_session_stop_private_bus_bounds_unresponsive_and_nonexiting_providers() {
    for mode in ["timeout", "no-reply"] {
        let (state, calls) = probe(mode, false, false, true);
        assert_eq!(state, StopState::Unavailable);
        assert_eq!(calls, ["quit"]);
    }
}
