use super::*;
use dbus::{arg::Variant, channel::MatchingReceiver};
use std::{io::{BufRead,BufReader},os::unix::fs::PermissionsExt,process::Child,sync::atomic::{AtomicBool,Ordering}};
struct Bus{child:Child,root:std::path::PathBuf,address:String}
impl Bus{fn new()->Self{
    let root=std::env::temp_dir().join(format!("nexus-sync-test-{}-{}",std::process::id(),rand::random::<u64>()));
    fs::create_dir(&root).unwrap();fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();
    let mut child=Command::new("dbus-daemon").args(["--session","--nofork","--print-address=1",&format!("--address=unix:path={}/bus",root.display())]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut address=String::new();BufReader::new(child.stdout.take().unwrap()).read_line(&mut address).unwrap();
    assert!(!address.trim().is_empty(),"Private Unix bus required");
    Self{child,root,address:address.trim().into()}
}}
impl Drop for Bus{fn drop(&mut self){let _=self.child.kill();let _=self.child.wait();let _=fs::remove_dir_all(&self.root);}}
fn probe(mode:&'static str)->(SyncState,Vec<String>){
    let bus=Bus::new();let client=Connection::new_address(&bus.address).unwrap();
    let stop=Arc::new(AtomicBool::new(false));let calls=Arc::new(Mutex::new(Vec::new()));
    let server_stop=stop.clone();let server_calls=calls.clone();let address=bus.address.clone();
    let (ready_tx,ready_rx)=std::sync::mpsc::channel();
    let server=thread::spawn(move||{
        let service=Connection::new_address(&address).unwrap();
        let other=Connection::new_address(&address).unwrap();
        if mode!="absent"{service.request_name("org.freedesktop.secrets",false,true,false).unwrap();}
        let mut checks=0;
        service.start_receive(MatchRule::new_method_call(),Box::new(move|msg,connection|{
            let method=msg.member().unwrap().to_string();server_calls.lock().unwrap().push(method.clone());
            let reply=match method.as_str(){
                "wallets"=>{
                    if mode=="new-kde"{
                        connection.send(msg.error(&"org.freedesktop.DBus.Error.UnknownInterface".into(),&std::ffi::CString::new("unsupported").unwrap())).unwrap();return true;
                    }
                    msg.method_return().append1(vec!["synthetic-wallet".to_string()])
                },
                "ReadAlias"=>{assert_eq!(msg.read1::<String>().unwrap(),"default");msg.method_return().append1(Path::from(if mode=="no-default"{"/"}else{"/collection/synthetic"}))},
                "Get"=>{
                    let (interface,property):(String,String)=msg.read2().unwrap();assert_eq!(interface,"org.freedesktop.Secret.Collection");
                    match property.as_str(){
                        "Locked"=>{checks+=1;msg.method_return().append1(Variant(mode=="locked"||(mode=="relocked"&&checks>1)))},
                        "Label"=>msg.method_return().append1(Variant(if mode=="unknown-wallet"{"missing"}else{"synthetic-wallet"})),
                        _=>panic!("Only metadata properties allowed"),
                    }
                },
                "isOpen"=>{
                    if let Ok(label)=msg.read1::<String>(){assert_eq!(label,"synthetic-wallet");}
                    else{assert_eq!(msg.read1::<i32>().unwrap(),42);}
                    msg.method_return().append1(mode!="not-open")
                },
                "openAsync"=>{
                    let (label,parent,appid,watched):(String,i64,String,bool)=msg.read4().unwrap();
                    assert_eq!((label,parent,appid,watched),("synthetic-wallet".into(),0,APP.into(),true));
                    connection.send(msg.method_return().append1(17i32)).unwrap();
                    if mode=="replaced"{connection.release_name("org.freedesktop.secrets").unwrap();other.request_name("org.freedesktop.secrets",false,true,false).unwrap();}
                    if mode!="timeout"{
                        let signal=Message::new_signal("/ksecretd",NATIVE,"walletAsyncOpened").unwrap().append2(17i32,if mode=="denied"{-1i32}else{42i32});
                        if mode=="spoof"{other.send(signal).unwrap();}else{connection.send(signal).unwrap();}
                    }
                    return true;
                },
                "sync"=>{
                    assert_eq!(msg.read2::<i32,String>().unwrap(),(42,APP.into()));assert!(msg.get_no_reply());return true;
                },
                "close"=>{assert_eq!(msg.read3::<i32,bool,String>().unwrap(),(42,false,APP.into()));msg.method_return().append1(1i32)},
                _=>panic!("No secret, unlock, lock, config, quit or credential APIs permitted: {method}"),
            };
            connection.send(reply).unwrap();true
        }));
        ready_tx.send(()).unwrap();while !server_stop.load(Ordering::SeqCst){service.process(Duration::from_millis(2)).unwrap();}
    });
    ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let uid=fs::metadata("/proc/self").unwrap().uid()+u32::from(mode=="foreign-uid");
    let state=sync_on(&client,uid,|_,_|mode!="foreign-provider",||mode!="prompt-enabled",Duration::from_millis(60)).unwrap_or(SyncState::Unavailable);
    stop.store(true,Ordering::SeqCst);server.join().unwrap();
    let calls=calls.lock().unwrap().clone();(state,calls)
}
#[test]
fn keyring_persistence_private_bus_only_own_session_sync_barrier_and_nonforced_close(){
    let (state,calls)=probe("complete");assert_eq!(state,SyncState::Synced);
    assert_eq!(calls,["wallets","ReadAlias","Get","Get","isOpen","openAsync","Get","sync","isOpen","close"]);
}
#[test]
fn keyring_persistence_private_bus_foreign_and_absent_provider_are_untouched(){
    for mode in ["absent","foreign-provider","foreign-uid"]{assert_eq!(probe(mode),(SyncState::Skipped,vec![]),"{mode}");}
    assert!(!genuine_ksecret(std::process::id(),fs::metadata("/proc/self").unwrap().uid()));
}
#[test]
fn keyring_persistence_private_bus_no_creation_unlock_or_extra_authorization(){
    for mode in ["locked","no-default","unknown-wallet","prompt-enabled","not-open","new-kde"]{
        let (state,calls)=probe(mode);assert_eq!(state,SyncState::Skipped,"{mode}");assert!(!calls.iter().any(|s|s=="openAsync"||s=="sync"));
    }
}
#[test]
fn keyring_persistence_private_bus_timeout_denial_and_foreign_signal_never_sync(){
    for mode in ["timeout","spoof","denied"]{
        let (state,calls)=probe(mode);assert_eq!(state,if mode=="denied"{SyncState::Skipped}else{SyncState::Unavailable});assert!(!calls.iter().any(|s|s=="sync"));
    }
}
#[test]
fn keyring_persistence_private_bus_replacement_or_lock_race_releases_only_own_handle(){
    for mode in ["replaced","relocked"]{
        let (state,calls)=probe(mode);assert_eq!(state,SyncState::Skipped,"{mode}");assert_eq!(calls.last().unwrap(),"close");assert!(!calls.iter().any(|s|s=="sync"));
    }
}
