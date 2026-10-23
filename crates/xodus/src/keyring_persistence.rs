//! Optional durable-write barrier for KWallet's delayed disk writes.
//! Never stops a provider, reads credentials or changes wallet configuration.
use dbus::{blocking::{Connection, stdintf::org_freedesktop_dbus::Properties}, channel::Sender, message::MatchRule, Message, Path};
use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path as FsPath, process::{Command, Stdio}, sync::{Arc, Mutex}, thread, time::{Duration, Instant}};

const APP: &str = "Xodus Nexus";
const NATIVE: &str = "org.kde.KWallet";
const TIMEOUT: Duration = Duration::from_millis(750);
#[derive(Debug, PartialEq, Eq)]
enum SyncState { Synced, Skipped, Unavailable }

fn trusted_binary(path: &FsPath) -> bool {
    fs::metadata(path).is_ok_and(|s| s.is_file() && s.uid()==0 && s.mode() & 0o022==0 && s.mode() & 0o111!=0)
}
fn genuine_ksecret(pid:u32, uid:u32) -> bool {
    let root=format!("/proc/{pid}");
    pid>1 && fs::metadata(&root).is_ok_and(|s|s.uid()==uid)
        && fs::read_link(format!("{root}/exe")).is_ok_and(|p|p==FsPath::new("/usr/bin/ksecretd"))
        && trusted_binary(FsPath::new("/usr/bin/ksecretd"))
}
fn prompt_is_disabled() -> bool {
    let binary=FsPath::new("/usr/bin/kreadconfig6");
    if !trusted_binary(binary) { return false; }
    let mut cmd=Command::new(binary);
    cmd.env_clear().env("PATH","/usr/bin:/bin");
    for key in ["HOME","XDG_CONFIG_HOME","XDG_CONFIG_DIRS"] {
        if let Some(value)=std::env::var_os(key) { cmd.env(key,value); }
    }
    let Ok(mut child)=cmd.args(["--file","kwalletrc","--group","Wallet","--key","Prompt on Open","--default","false"])
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() else { return false; };
    let deadline=Instant::now()+Duration::from_millis(500);
    let status=loop {
        match child.try_wait() {
            Ok(Some(status))=>break Some(status),
            Ok(None) if Instant::now()<deadline=>thread::sleep(Duration::from_millis(5)),
            _=>{let _=child.kill();let _=child.wait();break None;}
        }
    };
    let mut text=Vec::new();
    if let Some(stdout)=child.stdout.take() { let _=stdout.take(129).read_to_end(&mut text); }
    status.is_some_and(|s|s.success()) && matches!(text.as_slice(), b"false\n" | b"0\n")
}

pub(crate) fn sync_after_write() {
    // Other Secret Service implementations and customized authorization policy
    // retain their existing behavior. This optional compatibility path must not
    // turn an otherwise successful login into a new provider-specific failure.
    let result=(|| {
        let uid=fs::metadata("/proc/self").ok()?.uid();
        let connection=Connection::new_session().ok()?;
        Some(sync_on(&connection,uid,genuine_ksecret,prompt_is_disabled,TIMEOUT).unwrap_or(SyncState::Unavailable))
    })();
    if result==Some(SyncState::Unavailable) {
        eprintln!("NEXUS_KEYRING_PERSISTENCE_V1 unavailable");
    }
}

fn sync_on(connection:&Connection, uid:u32, verify:impl FnOnce(u32,u32)->bool, no_prompt:impl FnOnce()->bool, timeout:Duration) -> Result<SyncState,dbus::Error> {
    let bus=connection.with_proxy("org.freedesktop.DBus","/org/freedesktop/DBus",timeout);
    let owner=match bus.method_call::<(String,),_,_,_>("org.freedesktop.DBus","GetNameOwner",("org.freedesktop.secrets",)) {
        Ok((owner,))=>owner,
        Err(e) if e.name()==Some("org.freedesktop.DBus.Error.NameHasNoOwner")=>return Ok(SyncState::Skipped),
        Err(e)=>return Err(e),
    };
    let (pid,):(u32,)=bus.method_call("org.freedesktop.DBus","GetConnectionUnixProcessID",(&owner,))?;
    let (owner_uid,):(u32,)=bus.method_call("org.freedesktop.DBus","GetConnectionUnixUser",(&owner,))?;
    if owner_uid!=uid || !verify(pid,uid) { return Ok(SyncState::Skipped); }
    let native=connection.with_proxy(owner.as_str(),"/ksecretd",timeout);
    // Newer KDE releases can remove this legacy interface. Probe only metadata,
    // never activate a second compatibility daemon or touch a different owner.
    let wallets=match native.method_call::<(Vec<String>,),_,_,_>(NATIVE,"wallets",()) {
        Ok((wallets,))=>wallets,
        Err(e) if matches!(e.name(),Some("org.freedesktop.DBus.Error.UnknownInterface"|"org.freedesktop.DBus.Error.UnknownMethod"|"org.freedesktop.DBus.Error.UnknownObject"))=>return Ok(SyncState::Skipped),
        Err(e)=>return Err(e),
    };
    let service=connection.with_proxy(owner.as_str(),"/org/freedesktop/secrets",timeout);
    let (collection,):(Path<'static>,)=service.method_call("org.freedesktop.Secret.Service","ReadAlias",("default",))?;
    if collection.to_string()=="/" { return Ok(SyncState::Skipped); }
    let props=connection.with_proxy(owner.as_str(),collection,timeout);
    let locked:bool=props.get("org.freedesktop.Secret.Collection","Locked")?;
    if locked { return Ok(SyncState::Skipped); }
    let label:String=props.get("org.freedesktop.Secret.Collection","Label")?;
    if label.is_empty() || label.len()>255 || !wallets.contains(&label) { return Ok(SyncState::Skipped); }
    let (open,):(bool,)=native.method_call(NATIVE,"isOpen",(&label,))?;
    if !open || !no_prompt() { return Ok(SyncState::Skipped); }
    let (current,):(String,)=bus.method_call("org.freedesktop.DBus","GetNameOwner",("org.freedesktop.secrets",))?;
    if current!=owner { return Ok(SyncState::Skipped); }
    let completions=Arc::new(Mutex::new(Vec::<(i32,i32)>::new()));
    let output=completions.clone();
    let token=connection.add_match(MatchRule::new_signal(NATIVE,"walletAsyncOpened").with_path("/ksecretd").with_sender(owner.clone()),move |value:(i32,i32),_,_|{
        let mut values=output.lock().unwrap();if values.len()<16 { values.push(value); } true
    })?;
    let result=(||{
        // Own application identity and a session-watched async request. A lock
        // race or missing reply cannot leave an orphan password dialog behind:
        // disconnecting this private connection cancels its pending request.
        let (transaction,):(i32,)=native.method_call(NATIVE,"openAsync",(&label,0i64,APP,true))?;
        if transaction<0 { return Ok(SyncState::Skipped); }
        let deadline=Instant::now()+timeout;
        let handle=loop {
            let value=completions.lock().unwrap().iter().find(|(id,_)|*id==transaction).map(|(_,h)|*h);
            if let Some(handle)=value { break handle; }
            if Instant::now()>=deadline { return Ok(SyncState::Unavailable); }
            connection.process(Duration::from_millis(10))?;
        };
        if handle<=0 { return Ok(SyncState::Skipped); }
        let sync_result=(||{
            let (current,):(String,)=bus.method_call("org.freedesktop.DBus","GetNameOwner",("org.freedesktop.secrets",))?;
            let locked:bool=props.get("org.freedesktop.Secret.Collection","Locked")?;
            if current!=owner || locked { return Ok(SyncState::Skipped); }
            let mut message=Message::new_method_call(owner.as_str(),"/ksecretd",NATIVE,"sync").unwrap().append2(handle,APP);
            message.set_no_reply(true);
            connection.send(message).map_err(|_|dbus::Error::new_failed("Keyring sync unavailable"))?;
            // Ordered call on the same connection is a completion barrier for
            // the no-reply sync slot, not an arbitrary persistence sleep.
            let (open,):(bool,)=native.method_call(NATIVE,"isOpen",(handle,))?;
            Ok(if open { SyncState::Synced } else { SyncState::Unavailable })
        })();
        let _:Result<(i32,),_>=native.method_call(NATIVE,"close",(handle,false,APP));
        sync_result
    })();
    let _=connection.remove_match(token);
    result
}

#[cfg(test)]
#[path="keyring_persistence_tests.rs"]
mod tests;
