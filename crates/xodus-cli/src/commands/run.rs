use std::collections::{HashMap, HashSet};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, RawFd};
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

    let xsts = xodus::api::xbox::run(client, dev_token, user_token, PLAYFAB_RELYING_PARTY).await.ok()?;
    xodus::api::xbox::get_xsts_auth_header(xsts).ok()
}

const LAUNCH_STUB_SUFFIX: &str = ".xodus-launch.exe";

fn launch_image_error(name: &str, operation: &str, error: std::io::Error) -> std::io::Error {
    let shown: String = name.chars().take(240).collect();
    std::io::Error::new(error.kind(), format!("package image {shown:?}: {operation}: {error}"))
}

async fn open_launch_image(path: &Path, name: &str, content: &SegmentFile) -> std::io::Result<File> {
    let expected = content.stored_length().map_err(|e| launch_image_error(name, "invalid metadata", e))?;
    let file = File::open(path).await.map_err(|e| launch_image_error(name, "could not open local file", e))?;
    let metadata = file.metadata().await.map_err(|e| launch_image_error(name, "could not inspect local file", e))?;
    if !metadata.is_file() {
        return Err(launch_image_error(name, "invalid local file", std::io::Error::new(
            std::io::ErrorKind::InvalidData, "not a regular file")));
    }
    if metadata.len() < expected {
        return Err(launch_image_error(name, "incomplete local file", std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("expected at least {expected} bytes, found {}; retry installation to repair game files", metadata.len()))));
    }
    Ok(file)
}

fn inherit_launch_image(file: std::fs::File, name: &str) -> std::io::Result<std::fs::File> {
    let mut flags = fcntl_getfd(file.as_fd()).map_err(|e| launch_image_error(name, "could not read file descriptor flags", e.into()))?;
    flags.remove(FdFlags::CLOEXEC);
    fcntl_setfd(file.as_fd(), flags).map_err(|e| launch_image_error(name, "could not prepare file descriptor", e.into()))?;
    Ok(file)
}

fn select_launch_entry<'a>(
    fds: &[(&'a String, RawFd)],
    selected: Option<&str>,
) -> std::io::Result<(&'a String, RawFd)> {
    if let Some(selected) = selected {
        let selected_path = checked_relative_path(selected)?;
        let selected_path = selected_path.to_string_lossy();
        let matching: Vec<_> = fds.iter().copied().filter(|(name, _)| {
            checked_relative_path(name).is_ok_and(|candidate| {
                candidate.to_string_lossy().eq_ignore_ascii_case(&selected_path)
            })
        }).collect();
        let exact: Vec<_> = matching.iter().copied().filter(|(name, _)| {
            checked_relative_path(name).is_ok_and(|candidate| candidate.to_string_lossy() == selected_path)
        }).collect();
        let matching = if exact.is_empty() { matching } else { exact };
        return match matching.as_slice() {
            [entry] => Ok(*entry),
            [] => Err(std::io::Error::new(std::io::ErrorKind::NotFound,
                format!("selected executable is not present in package launch images: {selected}"))),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
                "selected executable has ambiguous package launch images")),
        };
    }
    fds.first().copied().ok_or_else(|| std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no encrypted launch image was found",
    ))
}

async fn prepare_plain_launch_entry(
    source: &Path,
    files: &HashMap<String, SegmentFile>,
    selected: Option<&str>,
) -> std::io::Result<Option<(String, std::fs::File)>> {
    let Some(selected) = selected else { return Ok(None); };
    let selected = checked_relative_path(selected)?;
    let selected = selected.to_string_lossy();
    let matching: Vec<_> = files.iter().filter(|(name, _)| {
        checked_relative_path(name).is_ok_and(|name| name.to_string_lossy().eq_ignore_ascii_case(&selected))
    }).collect();
    let exact: Vec<_> = matching.iter().copied().filter(|(name, _)| {
        checked_relative_path(name).is_ok_and(|name| name.to_string_lossy() == selected)
    }).collect();
    let matching = if exact.is_empty() { matching } else { exact };
    if matching.len() > 1 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "selected executable has ambiguous package metadata"));
    }
    let Some((name, content)) = matching.first() else { return Ok(None); };
    // Missing metadata or encrypted declarations never become an arbitrary
    // plaintext fallback. The license and encrypted-image paths remain intact.
    if content.keep_encrypted { return Ok(None); }
    let relative = resolve_package_file(source, name)?;
    let actual_name = relative.to_string_lossy().replace('/', "\\");
    let file = open_launch_image(&source.join(relative), &actual_name, content).await?.into_std().await;
    let mut signature = [0u8; 2];
    file.read_exact_at(&mut signature, 0).map_err(|e| launch_image_error(&actual_name, "could not read plain launch image", e))?;
    if signature != *b"MZ" {
        return Err(launch_image_error(&actual_name, "invalid plain launch image", std::io::Error::new(std::io::ErrorKind::InvalidData, "not a PE file")));
    }
    Ok(Some((actual_name.clone(), inherit_launch_image(file, &actual_name)?)))
}

fn wine_exit_code(status: std::process::ExitStatus) -> u8 {
    // A signal termination is not a successful game launch. Preserve the
    // conventional shell status (128 + signal) instead of reporting zero.
    status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(1)) as u8
}

// Real files in a full launch view must not be redirected back into memfds.
// Keep source mappings and encrypted DLL mappings; no title/EAC special case.
fn launch_file_maps(
    fds: &[(&String, RawFd)],
    source: &Path,
    mirror_nt_prefix: Option<&str>,
    entry_name: &str,
    entry_fd: RawFd,
    launch_image: &Path,
    materialize_chain: bool,
) -> (String, String) {
    let source_nt = source.to_string_lossy().replace('/', "\\");
    let source_nt = source_nt.trim_end_matches('\\');
    let mirror_unix = mirror_nt_prefix.map(|prefix| prefix.replace('\\', "/"));
    let mut dll_mappings = Vec::new();
    let mut exe_mappings = Vec::new();
    for (name, fd) in fds {
        let nt_suffix = name.trim_start_matches('\\');
        let unix_suffix = nt_suffix.replace('\\', "/");
        dll_mappings.push(format!("{fd}:\\??\\Z:{source_nt}\\{nt_suffix}"));
        exe_mappings.push(format!("{fd}:{}/{unix_suffix}", source.display()));
        let real_image = materialize_chain
            && (name.to_ascii_lowercase().ends_with(".exe") || name.as_str() == entry_name);
        if !real_image {
            if let Some(prefix) = mirror_nt_prefix {
                dll_mappings.push(format!("{fd}:\\??\\Z:{prefix}\\{nt_suffix}"));
            }
            if let Some(prefix) = &mirror_unix {
                exe_mappings.push(format!("{fd}:{prefix}/{unix_suffix}"));
            }
        }
    }
    if !materialize_chain {
        let launch_nt = launch_image.to_string_lossy().replace('/', "\\");
        dll_mappings.push(format!("{entry_fd}:\\??\\Z:{launch_nt}"));
        exe_mappings.push(format!("{entry_fd}:{}", launch_image.display()));
    }
    (dll_mappings.join("|"), exe_mappings.join("|"))
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

// Resolve physical Linux names independently from Windows package metadata.
// Preserve aliases inside the package, but never follow a path outside it.
fn resolve_package_file(root: &Path, name: &str) -> std::io::Result<PathBuf> {
    let relative = checked_relative_path(name)?;
    let base = root.canonicalize()?;
    let mut current = base.clone();
    for component in relative.components() {
        let component = component.as_os_str();
        let entries = std::fs::read_dir(&current)?.collect::<std::io::Result<Vec<_>>>()?;
        let exact = entries.iter().find(|entry| entry.file_name() == component);
        let matches: Vec<_> = if let Some(exact) = exact { vec![exact] } else {
            entries.iter().filter(|entry| {
                entry.file_name().to_str().zip(component.to_str())
                    .is_some_and(|(actual, requested)| actual.eq_ignore_ascii_case(requested))
            }).collect()
        };
        if matches.len() != 1 {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound,
                "package path is missing or has ambiguous letter casing"));
        }
        current.push(matches[0].file_name());
        if !current.canonicalize()?.starts_with(&base) {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied,
                "package path escapes the installation directory"));
        }
    }
    if !current.is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "package image is not a regular file"));
    }
    Ok(current.strip_prefix(&base).unwrap().to_path_buf())
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

fn probe_launch_view_links(directory: &Path) -> std::io::Result<()> {
    let probe = directory.join(".xodus-link-probe");
    symlink(".", &probe)?;
    std::fs::remove_file(probe)
}

fn launch_view_directory_with(
    source_root: &Path,
    fallback: &Path,
    prefix: &str,
    mut probe: impl FnMut(&Path) -> std::io::Result<()>,
) -> std::io::Result<TempDir> {
    let parent = source_root.parent().unwrap_or(fallback);
    if let Ok(directory) = Builder::new().prefix(prefix).tempdir_in(parent) {
        match probe(directory.path()) {
            Ok(()) => return Ok(directory),
            Err(error) if matches!(error.raw_os_error(), Some(nix::libc::EPERM | nix::libc::EOPNOTSUPP | nix::libc::ENOSYS)) => {
                // Some install filesystems allow directories but not symlinks.
                // Drop only this private empty view, then try the ordinary temp
                // directory once. Never change mount/security settings or copy
                // the whole game as a substitute for the links.
            }
            Err(error) => return Err(error),
        }
    }
    let directory = Builder::new().prefix(prefix.trim_start_matches('.')).tempdir_in(fallback)?;
    probe(directory.path())?;
    Ok(directory)
}

fn launch_view_directory(source_root: &Path, prefix: &str) -> std::io::Result<TempDir> {
    launch_view_directory_with(source_root, &std::env::temp_dir(), prefix, probe_launch_view_links)
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
            "selected executable is not present in package launch images",
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
    let mirror = launch_view_directory(source_root, ".xodus-chain-")?;
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
    let mirror = launch_view_directory(source_root, ".xodus-offline-")?;
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

    let mut opened_images = vec![];

    let (cleanup, mount_dir) = prepare(&lfiles).await;

    for file in &lfiles {
        if !file.1.keep_encrypted {
            continue;
        }
        let relative = match resolve_package_file(out, file.0) {
            Ok(relative) => relative,
            Err(error) => {
                eprintln!("failed to resolve package image {}: {}", file.0, error);
                cleanup().await;
                return ExitCode::FAILURE;
            }
        };
        let source_path = out.join(&relative);
        let name = relative.to_string_lossy().replace('/', "\\");
        let prepared = async {
            let mut input = open_launch_image(&source_path, &name, file.1).await?;
            let output = make_temp_file(&mount_dir).map_err(|e| launch_image_error(&name, "could not create temporary image", e))?;
            let mut output = File::from_std(output);
            xvd.mount_mem_fd(&mut input, &mut output, file.1, *full_key, |_, _| {})
                .await.map_err(|e| launch_image_error(&name, "decryption failed", std::io::Error::other(e.to_string())))?;
            inherit_launch_image(output.into_std().await, &name)
        }.await;
        match prepared {
            Ok(image) => opened_images.push((name, image)),
            Err(error) => {
                eprintln!("failed to prepare launch: {error}");
                cleanup().await;
                return ExitCode::FAILURE;
            }
        }
    }

    // All launch-view paths and file maps must use the resolved on-disk case,
    // not only the import readiness check or the selected executable name.
    // Keep ownership until launch finishes, including failure cleanup paths.
    match prepare_plain_launch_entry(out, &lfiles, exe.as_deref()).await {
        Ok(Some(image)) => opened_images.push(image),
        Ok(None) => (),
        Err(error) => {
            eprintln!("failed to prepare selected package executable: {error}");
            cleanup().await;
            return ExitCode::FAILURE;
        }
    }
    let fds: Vec<_> = opened_images.iter().map(|(name, file)| (name, file.as_raw_fd())).collect();

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

    let (env_value, exe_env_value) = launch_file_maps(
        &fds, &out_absolute, mirror_nt_prefix.as_deref(), entry_name, entry_fd,
        &stub_path, materialize_chain,
    );

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

    #[tokio::test]
    async fn launch_image_preflight_rejects_incomplete_ciphertext_with_file_and_size_without_writing() {
        for size in [0usize, 4095, 5000, 8191] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("Game.exe");
            let original = vec![7u8; size];
            std::fs::write(&path, &original).unwrap();
            let content = SegmentFile { offset: 0, length: 5000, keep_encrypted: true, data_hashs: vec![] };
            let error = open_launch_image(&path, "Bin\\Game.exe", &content).await.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
            let message = error.to_string();
            assert!(message.contains("Game.exe") && message.contains("expected at least 8192 bytes") && message.contains(&format!("found {size}")));
            assert!(message.contains("retry installation"));
            assert!(!message.contains(root.path().to_str().unwrap()));
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
    }

    #[tokio::test]
    async fn launch_image_preflight_accepts_valid_plain_and_padded_images_without_changes() {
        use tokio::io::AsyncReadExt;
        for (length, stored, encrypted) in [(0,0,true), (1,4096,true), (4096,4096,true), (5000,8192,true), (5000,5000,false)] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("Game.exe");
            let original = vec![9u8; stored];
            std::fs::write(&path, &original).unwrap();
            let content = SegmentFile { offset: 0, length, keep_encrypted: encrypted, data_hashs: vec![] };
            let mut input = open_launch_image(&path, "Game.exe", &content).await.unwrap();
            let mut read = vec![];
            input.read_to_end(&mut read).await.unwrap();
            assert_eq!(read, original);
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
    }

    #[tokio::test]
    async fn launch_image_errors_are_named_bounded_and_do_not_panic_on_missing_or_nonfile_input() {
        let root = tempfile::tempdir().unwrap();
        let content = SegmentFile { offset: 0, length: 4, keep_encrypted: true, data_hashs: vec![] };
        let error = open_launch_image(&root.path().join("missing"), "Missing.exe", &content).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(error.to_string().contains("Missing.exe"));
        assert!(open_launch_image(root.path(), "Folder", &content).await.is_err());
        let error = launch_image_error(&format!("Bad\n{}", "x".repeat(1000)), "decryption failed", std::io::Error::other("early eof"));
        assert!(!error.to_string().contains('\n'));
        assert!(error.to_string().len() < 400);
        assert!(error.to_string().contains("early eof"));
    }

    #[test]
    fn launch_images_keep_owned_descriptors_with_inheritance_enabled() {
        let file = tempfile::tempfile().unwrap();
        let raw = file.as_raw_fd();
        let image = inherit_launch_image(file, "Game.exe").unwrap();
        assert_eq!(raw, image.as_raw_fd());
        assert!(!fcntl_getfd(image.as_fd()).unwrap().contains(FdFlags::CLOEXEC));
    }

    #[test]
    fn full_launch_view_uses_real_executables_and_preserves_encrypted_dll_maps() {
        let entry = String::from("\\Launcher.exe");
        let child = String::from("\\Bin\\Child.ExE");
        let dll = String::from("\\Bin\\Encrypted.dll");
        let files = [(&entry, 10), (&child, 11), (&dll, 12)];
        let (nt, unix) = launch_file_maps(&files, Path::new("/package"), Some("\\view"),
            &entry, 10, Path::new("/view/Launcher.exe"), true);
        assert!(nt.contains("10:\\??\\Z:\\package\\Launcher.exe"));
        assert!(unix.contains("10:/package/Launcher.exe"));
        assert!(!nt.contains("\\view\\Launcher.exe"));
        assert!(!nt.contains("\\view\\Bin\\Child.ExE"));
        assert!(!unix.contains("/view/Launcher.exe"));
        assert!(!unix.contains("/view/Bin/Child.ExE"));
        assert!(nt.contains("12:\\??\\Z:\\view\\Bin\\Encrypted.dll"));
        assert!(unix.contains("12:/view/Bin/Encrypted.dll"));
    }

    #[test]
    fn materialized_selected_image_is_real_even_without_an_exe_suffix() {
        let entry = String::from("Entry.bin");
        let (nt, unix) = launch_file_maps(&[(&entry, 10)], Path::new("/package"),
            Some("\\view"), &entry, 10, Path::new("/view/Entry.bin"), true);
        assert!(!nt.contains("\\view\\Entry.bin"));
        assert!(!unix.contains("/view/Entry.bin"));
    }

    #[test]
    fn legacy_stub_launch_retains_both_file_maps() {
        let entry = String::from("Game.exe");
        let (nt, unix) = launch_file_maps(&[(&entry, 10)], Path::new("/package"), None,
            &entry, 10, Path::new("/package/Game.exe.xodus-launch.exe"), false);
        assert!(nt.contains("10:\\??\\Z:\\package\\Game.exe.xodus-launch.exe"));
        assert!(unix.contains("10:/package/Game.exe.xodus-launch.exe"));
    }

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

    #[tokio::test]
    async fn plain_launch_entry_uses_only_declared_package_images_and_preserves_sources() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("Bin")).unwrap();
        let original = fake_pe();
        std::fs::write(root.path().join("Bin/MINECRAFT.WINDOWS.EXE"), &original).unwrap();
        std::fs::write(root.path().join("MicrosoftGame.config"), b"metadata unchanged").unwrap();
        let metadata = HashMap::from([(String::from("Bin\\Minecraft.Windows.exe"), SegmentFile { offset: 0, length: original.len() as u64, data_hashs: vec![], keep_encrypted: false })]);
        let (name, file) = prepare_plain_launch_entry(root.path(), &metadata, Some("bin/Minecraft.Windows.exe")).await.unwrap().unwrap();
        assert_eq!(name, "Bin\\MINECRAFT.WINDOWS.EXE");
        assert!(!fcntl_getfd(file.as_fd()).unwrap().contains(FdFlags::CLOEXEC));
        let dll_name = String::from("Encrypted.dll");
        let mut dll = tempfile::tempfile().unwrap(); dll.write_all(b"synthetic decrypted library").unwrap();
        let images = [(&dll_name, dll.as_raw_fd()), (&name, file.as_raw_fd())];
        assert!(select_launch_entry(&images[..1], Some("bin/Minecraft.Windows.exe")).is_err());
        assert_eq!(select_launch_entry(&images, Some("bin/Minecraft.Windows.exe")).unwrap().1, file.as_raw_fd());
        let (mirror, entry, count, bytes) = create_launch_chain_mirror(root.path(), &name, &images).unwrap();
        assert_eq!(count, 1); assert_eq!(bytes, original.len() as u64);
        assert_eq!(std::fs::read(entry).unwrap(), original);
        let (nt, _) = launch_file_maps(&images, root.path(), Some("\\synthetic-view"), &name, file.as_raw_fd(), &mirror.path().join("Bin/MINECRAFT.WINDOWS.EXE"), true);
        assert!(nt.contains("synthetic-view\\Encrypted.dll"));
        assert!(!nt.contains("synthetic-view\\Bin\\MINECRAFT.WINDOWS.EXE"));
        assert_eq!(std::fs::read(root.path().join("Bin/MINECRAFT.WINDOWS.EXE")).unwrap(), original);
        assert_eq!(std::fs::read(root.path().join("MicrosoftGame.config")).unwrap(), b"metadata unchanged");
    }

    #[test]
    fn launch_entry_prefers_exact_case_and_refuses_ambiguous_case_fallbacks() {
        let names = [String::from("Game.exe"), String::from("GAME.EXE")];
        let images = [(&names[0], 42), (&names[1], 43)];
        assert_eq!(select_launch_entry(&images, Some("GAME.EXE")).unwrap().1, 43);
        assert_eq!(select_launch_entry(&images, Some("Game.exe")).unwrap().1, 42);
        assert!(select_launch_entry(&images, Some("game.exe")).is_err());
        assert!(select_launch_entry(&[(&names[0], 42), (&names[0], 43)], Some("Game.exe")).is_err());
        assert_eq!(select_launch_entry(&images, None).unwrap().1, 42);
    }

    #[tokio::test]
    async fn plain_launch_entry_never_treats_an_encrypted_or_undeclared_file_as_plaintext() {
        let root = tempfile::tempdir().unwrap(); let original = fake_pe();
        std::fs::write(root.path().join("Game.exe"), &original).unwrap();
        let mut metadata = HashMap::from([(String::from("Game.exe"), SegmentFile { offset: 0, length: original.len() as u64, data_hashs: vec![], keep_encrypted: true })]);
        assert!(prepare_plain_launch_entry(root.path(), &metadata, Some("Game.exe")).await.unwrap().is_none());
        assert!(prepare_plain_launch_entry(root.path(), &metadata, Some("Other.exe")).await.unwrap().is_none());
        assert!(prepare_plain_launch_entry(root.path(), &metadata, None).await.unwrap().is_none());
        assert!(prepare_plain_launch_entry(root.path(), &metadata, Some("../Game.exe")).await.is_err());
        metadata.get_mut("Game.exe").unwrap().keep_encrypted = false;
        metadata.get_mut("Game.exe").unwrap().length += 1;
        assert!(prepare_plain_launch_entry(root.path(), &metadata, Some("Game.exe")).await.is_err());
        metadata.get_mut("Game.exe").unwrap().length = original.len() as u64;
        std::fs::write(root.path().join("Game.exe"), vec![0; original.len()]).unwrap();
        assert!(prepare_plain_launch_entry(root.path(), &metadata, Some("Game.exe")).await.is_err());
        assert_eq!(std::fs::read(root.path().join("Game.exe")).unwrap(), vec![0; original.len()]);
    }

    #[tokio::test]
    async fn plain_launch_entry_rejects_ambiguous_metadata_and_outside_package_links() {
        let root = tempfile::tempdir().unwrap(); let outside = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("Game.exe"), fake_pe()).unwrap();
        let mut metadata = HashMap::new();
        for name in ["Game.exe", "GAME.EXE"] { metadata.insert(name.to_owned(), SegmentFile { offset: 0, length: 1024, data_hashs: vec![], keep_encrypted: false }); }
        assert!(prepare_plain_launch_entry(root.path(), &metadata, Some("Game.exe")).await.unwrap().is_some());
        assert!(prepare_plain_launch_entry(root.path(), &metadata, Some("game.exe")).await.is_err());
        std::fs::write(outside.path().join("Game.exe"), fake_pe()).unwrap();
        symlink(outside.path().join("Game.exe"), root.path().join("Outside.exe")).unwrap();
        metadata.insert("Outside.exe".to_owned(), SegmentFile { offset: 0, length: 1024, data_hashs: vec![], keep_encrypted: false });
        assert!(prepare_plain_launch_entry(root.path(), &metadata, Some("Outside.exe")).await.is_err());
    }

    #[test]
    fn launch_directory_falls_back_when_install_filesystem_cannot_create_links() {
        for code in [nix::libc::EPERM, nix::libc::EOPNOTSUPP, nix::libc::ENOSYS] {
            let root = tempfile::tempdir().unwrap();
            let parent = root.path().join("non-link-filesystem");
            let fallback = root.path().join("normal temporary filesystem");
            std::fs::create_dir_all(parent.join("game")).unwrap();
            std::fs::create_dir(&fallback).unwrap();
            std::fs::write(parent.join("game/original.bin"), b"unchanged").unwrap();
            let mut attempts = Vec::new();
            let result = launch_view_directory_with(&parent.join("game"), &fallback, ".xodus-chain-", |path| {
                attempts.push(path.to_owned());
                if path.parent() == Some(parent.as_path()) { return Err(std::io::Error::from_raw_os_error(code)); }
                probe_launch_view_links(path)
            }).unwrap();
            assert_eq!(attempts.len(), 2);
            assert_eq!(result.path().parent(), Some(fallback.as_path()));
            assert!(!attempts[0].exists());
            assert_eq!(std::fs::read(parent.join("game/original.bin")).unwrap(), b"unchanged");
            assert_eq!(std::fs::read_dir(result.path()).unwrap().count(), 0);
            let path = result.path().to_owned(); drop(result); assert!(!path.exists());
        }
    }

    #[test]
    fn launch_directory_keeps_supported_install_filesystem_and_cleans_probe() {
        let root = tempfile::tempdir().unwrap();
        let fallback = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("game")).unwrap();
        let directory = launch_view_directory_with(&root.path().join("game"), fallback.path(), ".xodus-chain-", probe_launch_view_links).unwrap();
        assert_eq!(directory.path().parent(), Some(root.path()));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(fallback.path()).unwrap().count(), 0);
    }

    #[test]
    fn launch_directory_does_not_hide_unrelated_io_failures_or_retry_forever() {
        let root = tempfile::tempdir().unwrap();
        let fallback = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("game")).unwrap();
        let mut calls = 0;
        let error = launch_view_directory_with(&root.path().join("game"), fallback.path(), ".xodus-chain-", |_| {
            calls += 1; Err(std::io::Error::from_raw_os_error(nix::libc::EIO))
        }).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(nix::libc::EIO));
        assert_eq!(calls, 1);
        assert_eq!(std::fs::read_dir(fallback.path()).unwrap().count(), 0);
        let mut calls = 0;
        let error = launch_view_directory_with(&root.path().join("game"), fallback.path(), ".xodus-chain-", |_| {
            calls += 1; Err(std::io::Error::from_raw_os_error(nix::libc::EPERM))
        }).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(nix::libc::EPERM));
        assert_eq!(calls, 2);
        assert_eq!(std::fs::read_dir(fallback.path()).unwrap().count(), 0);
    }

    #[test]
    fn case_resolved_launch_view_keeps_source_files_unchanged() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("bin/gaming.desktop.x64");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("WITCHER3.EXE"), b"encrypted source fixture").unwrap();
        let manifest = "bin\\Gaming.Desktop.x64\\witcher3.exe";
        let relative = resolve_package_file(root.path(), manifest).unwrap();
        assert_eq!(relative, Path::new("bin/gaming.desktop.x64/WITCHER3.EXE"));
        let name = relative.to_string_lossy().replace('/', "\\");
        let mut image = tempfile::tempfile().unwrap();
        image.write_all(&fake_pe()).unwrap();
        let files = [(&name, image.as_raw_fd())];
        assert_eq!(select_launch_entry(&files, Some(manifest)).unwrap().1, image.as_raw_fd());
        let (mirror, entry, count, _) = create_launch_chain_mirror(root.path(), &name, &files).unwrap();
        assert_eq!(entry, mirror.path().join(&relative));
        assert_eq!(std::fs::read(entry).unwrap(), fake_pe());
        assert_eq!(count, 1);
        assert_eq!(std::fs::read(nested.join("WITCHER3.EXE")).unwrap(), b"encrypted source fixture");
    }

    #[test]
    fn case_resolver_prefers_exact_paths_and_rejects_ambiguity_or_root_escape() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("Game.exe"), b"A").unwrap();
        std::fs::write(root.path().join("GAME.EXE"), b"B").unwrap();
        assert_eq!(resolve_package_file(root.path(), "Game.exe").unwrap(), Path::new("Game.exe"));
        assert!(resolve_package_file(root.path(), "game.exe").is_err());
        assert!(resolve_package_file(root.path(), "..\\Game.exe").is_err());
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("External.exe"), b"outside").unwrap();
        symlink(outside.path(), root.path().join("External")).unwrap();
        assert!(resolve_package_file(root.path(), "external/EXTERNAL.exe").is_err());
    }
}
