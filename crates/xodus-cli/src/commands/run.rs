use std::collections::{HashMap, HashSet};
use std::os::fd::{AsFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::{FileExt, PermissionsExt, symlink};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use msixvc::layout::PAGE_SIZE;
use msixvc::xvd::{SegmentFile, XvdFile};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
#[cfg(target_os = "linux")]
use rustix::fs::{MemfdFlags, memfd_create};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
use tempfile::{Builder, TempDir};
#[cfg(not(target_os = "linux"))]
use tempfile::{tempdir, tempfile, tempfile_in};
use tokio::fs::{File, OpenOptions};
use tokio::process::Command;
use xodus::models::secrets::Token;
use xodus::tokens::TokenManager;

use crate::license::get_license;

const PLAYFAB_RELYING_PARTY: &str = "http://playfab.xboxlive.com/";

async fn playfab_auth_header(client: &reqwest::Client, tokens: &TokenManager) -> Option<String> {
    let Ok(Token::Legacy(dev_token)) = tokens.get_device_sts_token() else {
        return None;
    };
    let Ok(Token::Legacy(user_token)) = tokens.get_user_sts_token() else {
        return None;
    };

    let xsts = xodus::api::xbox::run(client, dev_token, user_token, PLAYFAB_RELYING_PARTY).await;
    Some(xodus::api::xbox::get_xsts_auth_header(xsts))
}

const LAUNCH_STUB_SUFFIX: &str = ".xodus-launch.exe";

fn select_launch_entry<'a>(
    fds: &[(&'a String, RawFd)],
    selected: Option<&str>,
) -> std::io::Result<(&'a String, RawFd)> {
    if let Some(selected) = selected {
        let selected_path = checked_relative_path(selected)?;
        let selected_path = selected_path.to_string_lossy();
        return fds.iter().copied().find(|(name, _)| {
            checked_relative_path(name).is_ok_and(|candidate| {
                candidate.to_string_lossy().eq_ignore_ascii_case(&selected_path)
            })
        }).ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("selected executable is not present in encrypted package metadata: {selected}"),
        ));
    }
    fds.first().copied().ok_or_else(|| std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no encrypted launch image was found",
    ))
}

fn wine_exit_code(status: std::process::ExitStatus) -> u8 {
    // A signal termination is not a successful game launch. Preserve the
    // conventional shell status (128 + signal) instead of reporting zero.
    status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(1)) as u8
}

fn checked_relative_path(name: &str) -> std::io::Result<PathBuf> {
    let mut relative = PathBuf::new();
    for component in name.split(['\\', '/']).filter(|component| !component.is_empty()) {
        if component == "." || component == ".." || component.contains(':') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsafe executable path: {name}"),
            ));
        }
        relative.push(component);
    }
    if relative.as_os_str().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "launch executable has no path components",
        ));
    }
    Ok(relative)
}

fn populate_launch_view(
    source_root: &Path,
    mirror_root: &Path,
    relative_directory: &Path,
    real_directories: &HashSet<PathBuf>,
    decrypted_files: &HashSet<PathBuf>,
) -> std::io::Result<()> {
    for item in std::fs::read_dir(source_root.join(relative_directory))? {
        let item = item?;
        let relative = relative_directory.join(item.file_name());
        let destination = mirror_root.join(&relative);
        if real_directories.contains(&relative) {
            if !item.metadata()?.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("expected a game directory: {}", relative.display()),
                ));
            }
            std::fs::create_dir(&destination)?;
            populate_launch_view(source_root, mirror_root, &relative, real_directories, decrypted_files)?;
        } else if decrypted_files.contains(&relative) {
            if !item.metadata()?.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("expected a game executable: {}", relative.display()),
                ));
            }
        } else {
            symlink(item.path(), destination)?;
        }
    }
    Ok(())
}

fn create_launch_chain_mirror(
    source_root: &Path,
    entry_suffix: &str,
    fds: &[(&String, RawFd)],
) -> std::io::Result<(TempDir, PathBuf, usize, u64)> {
    let entry_path = checked_relative_path(entry_suffix)?;
    let mut decrypted = HashMap::new();
    for (name, fd) in fds {
        if name.to_ascii_lowercase().ends_with(".exe") || checked_relative_path(name)? == entry_path {
            decrypted.insert(checked_relative_path(name)?, *fd);
        }
    }
    if !decrypted.contains_key(&entry_path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "selected executable is not present in encrypted package metadata",
        ));
    }
    let mut real_directories = HashSet::new();
    for relative in decrypted.keys() {
        let mut parent = relative.parent();
        while let Some(directory) = parent {
            if directory.as_os_str().is_empty() {
                break;
            }
            real_directories.insert(directory.to_path_buf());
            parent = directory.parent();
        }
    }
    let decrypted_files: HashSet<PathBuf> = decrypted.keys().cloned().collect();
    let parent = source_root.parent().unwrap_or_else(|| Path::new("/tmp"));
    let mirror = Builder::new()
        .prefix(".xodus-chain-")
        .tempdir_in(parent)
        .or_else(|_| Builder::new().prefix("xodus-chain-").tempdir())?;
    populate_launch_view(
        source_root,
        mirror.path(),
        Path::new(""),
        &real_directories,
        &decrypted_files,
    )?;
    let mut bytes = 0;
    for (relative, fd) in &decrypted {
        bytes += write_launch_stub(&mirror.path().join(relative), *fd, true)?;
    }
    let executable_count = decrypted.len();
    let entry = mirror.path().join(entry_path);
    Ok((mirror, entry, executable_count, bytes))
}

fn create_launch_mirror(
    source_root: &Path,
    entry_suffix: &str,
) -> std::io::Result<(TempDir, PathBuf)> {
    let parent = source_root.parent().unwrap_or_else(|| Path::new("/tmp"));
    let mirror = Builder::new()
        .prefix(".xodus-offline-")
        .tempdir_in(parent)
        .or_else(|_| Builder::new().prefix("xodus-offline-").tempdir())?;
    let components: Vec<&str> = entry_suffix
        .split(['\\', '/'])
        .filter(|component| !component.is_empty())
        .collect();
    if components.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "launch executable has no path components",
        ));
    }

    let mut source_directory = source_root.to_path_buf();
    let mut mirror_directory = mirror.path().to_path_buf();
    for (index, component) in components.iter().enumerate() {
        for item in std::fs::read_dir(&source_directory)? {
            let item = item?;
            if item.file_name() == std::ffi::OsStr::new(component) {
                continue;
            }
            symlink(item.path(), mirror_directory.join(item.file_name()))?;
        }

        source_directory.push(component);
        mirror_directory.push(component);
        if index + 1 < components.len() {
            std::fs::create_dir(&mirror_directory)?;
        }
    }

    Ok((mirror, mirror_directory))
}

fn write_launch_stub(stub_path: &Path, fd: RawFd, materialize: bool) -> std::io::Result<u64> {
    let invalid = |msg: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string());

    // Borrow the decrypted memfd without taking ownership; Wine still needs it.
    let image = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    let image_len = image.metadata()?.len();
    let mut head = vec![0u8; PAGE_SIZE];
    let read = image.read_at(&mut head, 0)?;
    head.truncate(read);

    if head.len() < 0x40 || head[..2] != *b"MZ" {
        return Err(invalid("decrypted image is not a PE file"));
    }
    let pe = u32::from_le_bytes(head[0x3c..0x40].try_into().unwrap()) as usize;
    let size_of_headers_at = pe + 24 + 60;
    if pe + 4 > head.len() || size_of_headers_at + 4 > head.len() {
        return Err(invalid("PE header lies outside the first page"));
    }
    if head[pe..pe + 4] != *b"PE\0\0" {
        return Err(invalid("missing PE signature"));
    }
    let size_of_headers = u32::from_le_bytes(
        head[size_of_headers_at..size_of_headers_at + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    if size_of_headers == 0 {
        return Err(invalid("PE reports a zero-length header"));
    }
    if size_of_headers > head.len() {
        head.resize(size_of_headers, 0);
        image.read_exact_at(&mut head, 0)?;
    }

    let stub = std::fs::File::create(stub_path)?;
    if materialize {
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut offset = 0u64;
        while offset < image_len {
            let bytes = (image_len - offset).min(buffer.len() as u64) as usize;
            image.read_exact_at(&mut buffer[..bytes], offset)?;
            stub.write_all_at(&buffer[..bytes], offset)?;
            offset += bytes as u64;
        }
    } else {
        stub.write_all_at(&head[..size_of_headers], 0)?;
        // A sparse tail lets Wine probe/map all PE sections without storing game code.
        stub.set_len(image_len.max(size_of_headers as u64))?;
    }
    stub.set_permissions(std::fs::Permissions::from_mode(0o755))?;
    Ok(image_len)
}

#[cfg(target_os = "linux")]
fn make_temp_file(_folder: &str) -> std::io::Result<std::fs::File> {
    let fd = memfd_create("xodus", MemfdFlags::CLOEXEC).map_err(std::io::Error::from)?;
    Ok(std::fs::File::from(fd))
}

#[cfg(not(target_os = "linux"))]
fn make_temp_file(folder: &str) -> std::io::Result<std::fs::File> {
    if folder.is_empty() {
        tempfile()
    } else {
        tempfile_in(folder)
    }
}

#[cfg(target_os = "macos")]
async fn prepare(lfiles: &HashMap<String, SegmentFile>) -> (impl AsyncFnOnce(), String) {
    let disk_size: u64 = lfiles
        .iter()
        .filter(|f| f.1.keep_encrypted)
        .map(|f| f.1.length + 4 * PAGE_SIZE as u64)
        .reduce(|o, s| o + s)
        .unwrap();

    let device_s = String::from_utf8(
        Command::new("/usr/bin/hdiutil")
            .arg("attach")
            .arg("-nomount")
            .arg(format!("ram://{}", disk_size.div_ceil(256)))
            .output()
            .await
            .unwrap()
            .stdout,
    )
    .unwrap();

    let device = device_s.trim();

    let vol = uuid::Uuid::new_v4().to_string();

    let fmt = Command::new("/sbin/newfs_hfs")
        .arg("-v")
        .arg(vol)
        .arg(device)
        .status()
        .await
        .unwrap();
    assert!(fmt.success());

    let mount_dir_obj = tempdir().unwrap();
    let mount_dir = mount_dir_obj.path().to_str().unwrap();

    let mnt = Command::new("/sbin/mount")
        .arg("-t")
        .arg("hfs")
        .arg("-o")
        .arg("nobrowse")
        .arg("-v")
        .arg(device)
        .arg(mount_dir)
        .status()
        .await
        .unwrap();
    assert!(mnt.success());
    let mount_dir_cl = mount_dir.to_string();
    let device_cl = device.to_string();
    (
        async move || {
            let mnt = Command::new("/sbin/umount")
                .arg("-f")
                .arg(mount_dir_cl)
                .status()
                .await
                .unwrap();
            assert!(mnt.success());

            let mnt = Command::new("/usr/bin/hdiutil")
                .arg("detach")
                .arg("-force")
                .arg(&device_cl)
                .status()
                .await
                .unwrap();
            assert!(mnt.success());
        },
        mount_dir.to_owned(),
    )
}

#[cfg(not(target_os = "macos"))]
async fn prepare(_lfiles: &HashMap<String, SegmentFile>) -> (impl AsyncFnOnce(), String) {
    (async || {}, "".to_owned())
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    wine: String,
    exe: Option<String>,
    materialize_exe: bool,
    materialize_chain: bool,
    market: Option<String>,
) -> ExitCode {
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let out: &Path = Path::new(&source);
    let out_absolute = std::fs::canonicalize(out).unwrap();
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .unwrap();

    let xvd = XvdFile::parse(&mut file).await.expect("no err");

    let files = xvd.parse_user_package_files(&mut file).await.expect("ok");
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = xvd.parse_segment_metadata(&mut file, v).await.expect("ok");
            lfiles = sfiles;
        }
    }

    // Classic files
    if lfiles.is_empty() {
        let sfiles = xvd
            .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
            .await
            .expect("ok");
        for (n, sfile) in &sfiles {
            if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
                println!("{}: {} {}", n, sfile.offset, sfile.length);
            }
        }
        lfiles.extend(sfiles);
    }

    let license = get_license(
        client,
        tokens,
        xvd.content_id().to_string(),
        market.unwrap_or("neutral".to_string()),
    )
    .await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    }
    let (key, game_splicense) = license.unwrap();
    if game_splicense.content_keys.len() != 1 {
        eprintln!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        );
        return ExitCode::FAILURE;
    }
    let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
        return ExitCode::FAILURE;
    };

    let full_key = content_key.unpack(&key).expect("failed to unpack");

    let mut fds = vec![];

    let (cleanup, mount_dir) = prepare(&lfiles).await;

    for file in &lfiles {
        if !file.1.keep_encrypted {
            continue;
        }
        let mut game_exe = File::from_std(make_temp_file(&mount_dir).unwrap());

        let source_path = out.join(file.0.replace("\\", "/"));

        let mut i = File::open(&source_path).await.unwrap();

        xvd.mount_mem_fd(&mut i, &mut game_exe, file.1, *full_key, |_, _| {})
            .await
            .unwrap();

        let stdf = game_exe.into_std().await;

        let mut flags = fcntl_getfd(stdf.as_fd()).unwrap();
        flags.remove(FdFlags::CLOEXEC);
        fcntl_setfd(stdf.as_fd(), flags).unwrap();

        fds.push((file.0, stdf.into_raw_fd()));
    }

    let nt_prefix = out_absolute.to_string_lossy().replace("/", "\\");
    let nt_prefix = nt_prefix.trim_end_matches('\\');
    let (entry_name, entry_fd) = match select_launch_entry(&fds, exe.as_deref()) {
        Ok(entry) => entry,
        Err(error) => {
            eprintln!("failed to select launch image: {error}");
            cleanup().await;
            return ExitCode::FAILURE;
        }
    };
    let entry_suffix = entry_name.trim_start_matches('\\');

    let (launch_mirror, stub_path, mirror_nt_prefix) = if materialize_chain {
        match create_launch_chain_mirror(&out_absolute, entry_suffix, &fds) {
            Ok((mirror, path, count, bytes)) => {
                eprintln!(
                    "created a temporary launch view with {} decrypted executables ({} bytes) at {}",
                    count,
                    bytes,
                    mirror.path().display()
                );
                let prefix = mirror.path().to_string_lossy().replace("/", "\\");
                (Some(mirror), path, Some(prefix))
            }
            Err(err) => {
                eprintln!("failed to create temporary launch chain: {}", err);
                cleanup().await;
                return ExitCode::FAILURE;
            }
        }
    } else if materialize_exe {
        match create_launch_mirror(&out_absolute, entry_suffix) {
            Ok((mirror, path)) => {
                let prefix = mirror.path().to_string_lossy().replace("/", "\\");
                (Some(mirror), path, Some(prefix))
            }
            Err(err) => {
                eprintln!("failed to create temporary launch view: {}", err);
                cleanup().await;
                return ExitCode::FAILURE;
            }
        }
    } else {
        let stub_suffix = format!("{}{}", entry_suffix, LAUNCH_STUB_SUFFIX);
        (
            None,
            out_absolute.join(stub_suffix.replace("\\", "/")),
            None,
        )
    };

    let mut mappings = Vec::new();
    for fd in &fds {
        let nt_suffix = fd.0.trim_start_matches('\\');
        mappings.push(format!("{}:\\??\\Z:{}\\{}", fd.1, nt_prefix, nt_suffix));
        if let Some(prefix) = &mirror_nt_prefix {
            mappings.push(format!("{}:\\??\\Z:{}\\{}", fd.1, prefix, nt_suffix));
        }
    }
    let mut env_value = mappings.join("|");

    // The wineserver-side exe map (wine PR#8) matches entries against the unix
    // name of the opened file, so these entries carry unix paths, unlike the
    // NT paths in WINE_DLL_FILE_MAP above.
    let mut exe_mappings = Vec::new();
    let mirror_unix_prefix = mirror_nt_prefix
        .as_ref()
        .map(|prefix| prefix.replace('\\', "/"));
    for fd in &fds {
        let unix_suffix = fd.0.trim_start_matches('\\').replace('\\', "/");
        exe_mappings.push(format!("{}:{}/{}", fd.1, out_absolute.display(), unix_suffix));
        if let Some(prefix) = &mirror_unix_prefix {
            exe_mappings.push(format!("{}:{}/{}", fd.1, prefix, unix_suffix));
        }
    }
    exe_mappings.push(format!("{}:{}", entry_fd, stub_path.display()));
    let exe_env_value = exe_mappings.join("|");

    let image_len = if materialize_chain {
        0
    } else {
        match write_launch_stub(&stub_path, entry_fd, materialize_exe) {
            Ok(image_len) => image_len,
            Err(err) => {
                eprintln!(
                    "failed to write launch image {}: {}",
                    stub_path.display(),
                    err
                );
                cleanup().await;
                return ExitCode::FAILURE;
            }
        }
    };
    if materialize_exe && !materialize_chain {
        eprintln!(
            "created a temporary offline view with {} decrypted bytes at {}",
            image_len,
            stub_path.display()
        );
    }

    env_value.push('|');
    let launch_nt_path = stub_path.to_string_lossy().replace("/", "\\");
    env_value.push_str(&format!("{}:\\??\\Z:{}", entry_fd, launch_nt_path));

    let mut command = Command::new(wine);
    command
        .arg(&stub_path)
        .env("WINE_DLL_FILE_MAP", env_value)
        .env("WINE_EXE_FILE_MAP", exe_env_value);
    match playfab_auth_header(client, tokens).await {
        Some(header) => {
            command.env("XODUS_XSTS_PLAYFAB", header);
        }
        None => eprintln!("could not authorise a PlayFab token; in-game sign-in may fail"),
    }

    let mut wn = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            eprintln!("failed to start Wine: {}", err);
            let _ = std::fs::remove_file(&stub_path);
            drop(launch_mirror);
            cleanup().await;
            return ExitCode::FAILURE;
        }
    };

    let pid = wn.id().unwrap();

    ctrlc::set_handler(move || {
        if pid > 0 {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGINT);
        }
    })
    .expect("failed to install Ctrl+C handler");

    let status = wn.wait().await.unwrap();

    let _ = std::fs::remove_file(&stub_path);
    drop(launch_mirror);
    cleanup().await;

    ExitCode::from(wine_exit_code(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    #[test]
    fn selected_image_matches_windows_case_and_path_separators() {
        let repair = String::from("Engine\\GamingRepair.exe");
        let shipping = String::from("Dungeons\\Binaries\\WinGDK\\Shipping.exe");
        let files = [(&repair, 10), (&shipping, 11)];
        assert_eq!(
            select_launch_entry(&files, Some("\\dungeons/binaries/wingdk/shipping.EXE")).unwrap().1,
            11,
        );
    }

    #[test]
    fn missing_selected_image_never_launches_an_unrelated_installer() {
        let repair = String::from("Engine\\GamingRepair.exe");
        let files = [(&repair, 10)];
        assert!(select_launch_entry(&files, Some("Game.exe")).is_err());
        assert!(select_launch_entry(&files, Some("..\\Game.exe")).is_err());
        assert!(select_launch_entry(&[], None).is_err());
    }

    #[test]
    fn signal_termination_is_reported_as_failure() {
        assert_eq!(wine_exit_code(std::process::ExitStatus::from_raw(9)), 137);
        assert_eq!(wine_exit_code(std::process::ExitStatus::from_raw(15)), 143);
        assert_eq!(wine_exit_code(std::process::ExitStatus::from_raw(0)), 0);
        assert_eq!(wine_exit_code(std::process::ExitStatus::from_raw(84 << 8)), 84);
    }

    fn fake_pe() -> Vec<u8> {
        let mut image = vec![0u8; 1024];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0xd4..0xd8].copy_from_slice(&0x200u32.to_le_bytes());
        image
    }

    #[test]
    fn launch_chain_materializes_nested_executables_without_changing_source() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("game");
        let nested = source.join("Dungeons/Binaries/WinGDK");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(source.join("Dungeons.exe"), b"encrypted launcher").unwrap();
        std::fs::write(nested.join("Shipping.exe"), b"encrypted child").unwrap();
        std::fs::write(source.join("MicrosoftGame.config"), b"metadata").unwrap();
        std::fs::write(nested.join("assets.bin"), b"assets").unwrap();

        let mut launcher = tempfile::tempfile().unwrap();
        let mut child = tempfile::tempfile().unwrap();
        launcher.write_all(&fake_pe()).unwrap();
        child.write_all(&fake_pe()).unwrap();
        let launcher_name = String::from("Dungeons.exe");
        let child_name = String::from("Dungeons\\Binaries\\WinGDK\\Shipping.exe");
        let files = vec![
            (&launcher_name, launcher.as_raw_fd()),
            (&child_name, child.as_raw_fd()),
        ];

        let (mirror, entry, count, bytes) =
            create_launch_chain_mirror(&source, &launcher_name, &files).unwrap();
        assert_eq!(entry, mirror.path().join("Dungeons.exe"));
        assert_eq!(count, 2);
        assert_eq!(bytes, 2048);
        assert_eq!(std::fs::read(&entry).unwrap(), fake_pe());
        assert_eq!(std::fs::read(mirror.path().join(&child_name.replace('\\', "/"))).unwrap(), fake_pe());
        assert!(std::fs::symlink_metadata(mirror.path().join("MicrosoftGame.config"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(std::fs::symlink_metadata(mirror.path().join("Dungeons/Binaries/WinGDK/assets.bin"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(source.join("Dungeons.exe")).unwrap(), b"encrypted launcher");
        assert_eq!(std::fs::read(nested.join("Shipping.exe")).unwrap(), b"encrypted child");
    }

    #[test]
    fn launch_chain_rejects_parent_path_components() {
        assert!(checked_relative_path("..\\outside.exe").is_err());
    }
}
