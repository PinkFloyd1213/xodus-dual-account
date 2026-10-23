use std::collections::HashMap;
use std::os::fd::{AsFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::{FileExt, PermissionsExt, symlink};
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
    let entry = exe
        .as_ref()
        .and_then(|selected| fds.iter().find(|fd| selected == fd.0))
        .or_else(|| fds.first());
    let Some((entry_name, entry_fd)) = entry else {
        eprintln!("Could not find .exe");
        return ExitCode::FAILURE;
    };
    let entry_suffix = entry_name.trim_start_matches('\\');
    let entry_fd = *entry_fd;

    let (launch_mirror, stub_path, mirror_nt_prefix) = if materialize_exe {
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

    let image_len = match write_launch_stub(&stub_path, entry_fd, materialize_exe) {
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
    };
    if materialize_exe {
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
    command.arg(&stub_path).env("WINE_DLL_FILE_MAP", env_value);
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

    ExitCode::from(status.code().map(|c| c as u8).unwrap_or(0))
}
