pub static SERVICE_NAME: &str = "Xodus Service";

pub fn init_secrets() -> Result<(), keyring_core::Error> {
    #[cfg(feature = "key-chain-file")]
    {
        let store = keyring_core::sample::Store::new_with_backing(
            secrets_backing_file()
                .to_str()
                .expect("Invalid secrets backing path"),
        )?;
        keyring_core::set_default_store(store);
    }

    #[cfg(not(feature = "key-chain-file"))]
    {
        #[cfg(target_os = "linux")]
        {
            activate_desktop_keyring();
            keyring_core::set_default_store(dbus_secret_service_keyring_store::Store::new()?);
        }

        #[cfg(target_os = "macos")]
        {
            keyring_core::set_default_store(apple_native_keyring_store::keychain::Store::new()?);
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let store = keyring_core::sample::Store::new_with_configuration(
                &std::collections::HashMap::from([("persist", "true")]),
            )?;
            keyring_core::set_default_store(store);
        }
    }

    Ok(())
}

// Some KDE installations advertise ksecretd only under its compatibility
// activation name. Respect an existing/default Secret Service provider first.
// This starts a packaged user service, never installs or configures a keyring.
#[cfg(all(target_os = "linux", not(feature = "key-chain-file")))]
fn activate_desktop_keyring() {
    use dbus::blocking::Connection;
    use std::time::Duration;
    let Ok(connection) = Connection::new_session() else { return; };
    let bus = connection.with_proxy("org.freedesktop.DBus", "/org/freedesktop/DBus", Duration::from_secs(3));
    let Ok((owned,)): Result<(bool,), _> = bus.method_call("org.freedesktop.DBus", "NameHasOwner", ("org.freedesktop.secrets",)) else { return; };
    if owned { return; }
    let Ok((names,)): Result<(Vec<String>,), _> = bus.method_call("org.freedesktop.DBus", "ListActivatableNames", ()) else { return; };
    if names.iter().any(|name| name == "org.freedesktop.secrets") { return; }
    if names.iter().any(|name| name == "org.kde.secretservicecompat") {
        // On failure, Store::new below still returns the genuine keyring error.
        let _: Result<(u32,), _> = bus.method_call("org.freedesktop.DBus", "StartServiceByName", ("org.kde.secretservicecompat", 0u32));
    }
}

pub fn get_entry(user: &str) -> Result<keyring_core::Entry, keyring_core::Error> {
    keyring_core::Entry::new(SERVICE_NAME, user)
}

pub fn destroy_secrets() {
    keyring_core::unset_default_store();
}

#[cfg(feature = "key-chain-file")]
fn secrets_backing_file() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(".xodus-keyring.ron")
}
