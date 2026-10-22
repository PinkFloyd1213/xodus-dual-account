use super::*;
use dbus::channel::{MatchingReceiver, Sender};
use std::{fs, io::{BufRead, BufReader}, process::{Child, Command, Stdio}, thread};
use std::os::unix::fs::PermissionsExt;

struct Bus { child: Child, root: std::path::PathBuf, address: String }
impl Bus {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("nexus-keyring-test-{}-{}", std::process::id(), rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut child = Command::new("dbus-daemon").args(["--session", "--nofork", "--print-address=1", &format!("--address=unix:path={}/bus", root.display())])
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("dbus-daemon required for isolated native keyring tests");
        let mut address = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut address).unwrap();
        Self { child, root, address: address.trim().into() }
    }
}
impl Drop for Bus { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = fs::remove_dir_all(&self.root); } }

fn probe(mode: &'static str) -> (UnlockState, Vec<String>) {
    let bus = Bus::new();
    let client = Connection::new_address(&bus.address).unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let addr = bus.address.clone();
    let server_calls = calls.clone();
    let server_stop = stop.clone();
    let cancel = cancelled.clone();
    let server = thread::spawn(move || {
        let connection = Connection::new_address(&addr).unwrap();
        let intruder = Connection::new_address(&addr).unwrap();
        if mode != "stopped" { connection.request_name("org.freedesktop.secrets", false, true, false).unwrap(); }
        let mut locked = mode != "ready";
        let mut sender = String::new();
        connection.start_receive(MatchRule::new_method_call(), Box::new(move |msg, connection| {
            let method = msg.member().unwrap().to_string();
            server_calls.lock().unwrap().push(method.clone());
            let reply = match method.as_str() {
                "ReadAlias" => {
                    assert_eq!(msg.read1::<String>().unwrap(), "default");
                    msg.method_return().append1(Path::from(if mode == "no-default" { "/" } else { "/org/freedesktop/secrets/collection/test" }))
                },
                "Get" => {
                    assert_eq!(msg.read2::<String,String>().unwrap(), ("org.freedesktop.Secret.Collection".into(), "Locked".into()));
                    msg.method_return().append1(Variant(locked))
                },
                "Unlock" => {
                    let objects: Vec<Path<'static>> = msg.read1().unwrap();
                    assert_eq!(objects, vec![Path::from("/org/freedesktop/secrets/collection/test")]);
                    sender = msg.sender().unwrap().to_string();
                    if mode == "immediate" { locked = false; }
                    msg.method_return().append2(Vec::<Path<'static>>::new(), Path::from(if mode == "immediate" { "/" } else { "/org/freedesktop/secrets/prompt/test" }))
                },
                "Prompt" => {
                    assert_eq!(msg.sender().unwrap().to_string(), sender, "Prompt must keep Unlock's connection alive");
                    assert_eq!(msg.read1::<String>().unwrap(), "12345");
                    connection.send(msg.method_return()).unwrap();
                    if mode == "cancel" { cancel.store(true, Ordering::SeqCst); }
                    if mode == "complete" { locked = false; }
                    if !["cancel", "timeout"].contains(&mode) {
                        let signal = dbus::Message::new_signal("/org/freedesktop/secrets/prompt/test", "org.freedesktop.Secret.Prompt", "Completed").unwrap()
                            .append2(mode == "dismissed", Variant(Vec::<Path<'static>>::new()));
                        if mode == "spoof" { intruder.send(signal).unwrap(); }
                        else { connection.send(signal).unwrap(); }
                    }
                    return true;
                },
                "Dismiss" => msg.method_return(),
                _ => panic!("Unexpected method {method}, no credential reads are permitted"),
            };
            connection.send(reply).unwrap();
            true
        }));
        ready_tx.send(()).unwrap();
        while !server_stop.load(Ordering::SeqCst) { connection.process(Duration::from_millis(10)).unwrap(); }
    });
    ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let result = unlock_on(&client, "12345", &cancelled, Duration::from_millis(40));
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    let calls = calls.lock().unwrap().clone();
    (result.unwrap(), calls)
}

#[test]
fn keyring_unlock_private_bus_metadata_never_activates_or_reads_items() {
    for (mode, expected) in [("stopped", UnlockState::Stopped), ("no-default", UnlockState::NeedsSetup), ("ready", UnlockState::Ready)] {
        let (state, calls) = probe(mode);
        assert_eq!(state, expected);
        assert!(!calls.iter().any(|c| matches!(c.as_str(), "Unlock" | "Prompt")));
    }
}
#[test]
fn keyring_unlock_private_bus_prompt_connection_completion_and_lock_recheck() {
    for (mode, expected) in [("immediate", UnlockState::Ready), ("complete", UnlockState::Ready), ("dismissed", UnlockState::Cancelled), ("false-success", UnlockState::Locked)] {
        let (state, _) = probe(mode);
        assert_eq!(state, expected, "{mode}");
    }
}
#[test]
fn keyring_unlock_private_bus_cancellation_and_timeout_dismiss_the_prompt() {
    for (mode, expected) in [("cancel", UnlockState::Cancelled), ("timeout", UnlockState::TimedOut)] {
        let (state, calls) = probe(mode);
        assert_eq!(state, expected);
        assert!(calls.contains(&"Dismiss".into()));
    }
}
#[test]
fn keyring_unlock_private_bus_ignores_completion_from_another_owner() {
    let (state, calls) = probe("spoof");
    assert_eq!(state, UnlockState::TimedOut);
    assert!(calls.contains(&"Dismiss".into()));
}
