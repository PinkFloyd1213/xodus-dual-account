use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;
use std::vec;

use fs2::available_space;
use futures_util::{StreamExt, stream};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use msixvc::streaming;
use msixvc::xvd::{SegmentFile, XvdFile};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncRead;
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::Uuid;
use xodus::tokens::TokenManager;

use crate::license::get_license;
use crate::package::get_packages;

#[path = "streaming_progress.rs"]
mod progress;
#[path = "streaming_resume.rs"]
mod resume;
#[path = "streaming_failure.rs"]
mod failure;

#[cfg(test)]
#[path = "streaming_preflight_tests.rs"]
mod preflight_tests;

struct Job {
    name: String,
    content: SegmentFile,
}

fn pending_files<'a>(
    root: &Path,
    remote: &'a HashMap<String, SegmentFile>,
    local: &HashMap<String, SegmentFile>,
) -> std::io::Result<Vec<(&'a String, &'a SegmentFile)>> {
    let mut pending = Vec::new();
    for (name, file) in remote {
        let unchanged = local.get(name).is_some_and(|old| {
            !file.data_hashs.is_empty() && file.data_hashs == old.data_hashs
                && file.length == old.length && file.keep_encrypted == old.keep_encrypted
        });
        let needs_repair = if unchanged && file.keep_encrypted {
            // Matching package metadata alone does not prove that the on-disk
            // ciphertext still includes the full final page.
            let target = resume::target(root, name)?;
            match std::fs::metadata(target) {
                Ok(metadata) if metadata.is_file() => metadata.len() < file.stored_length()?,
                Ok(_) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "package image is not a regular file")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(error) => return Err(error),
            }
        } else { false };
        if !unchanged || needs_repair { pending.push((name, file)); }
    }
    Ok(pending)
}

enum ProgressEvent {
    Started { id: usize, name: String, total: u64 },
    Advanced { id: usize, delta: u64 },
    Finished { id: usize },
    UpdateRemaining { name: String, total: u64 },
    UpdateStatus { name: String },
    Paused { paused: bool },
    Completed { success: bool },
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    progress_json: bool,
    control_stdin: bool,
    selected_content_id: Option<String>,
) -> ExitCode {
    if selected_content_id.is_some() && (Uuid::try_parse(&source).is_ok() || source.contains("://")) {
        eprintln!("Package selection requires a Store product ID");
        return ExitCode::FAILURE;
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<ProgressEvent>(256);
    let pause = progress::controls(control_stdin, tx.clone());
    if source.starts_with("file://") {
        let fsrc = source.strip_prefix("file://").unwrap_or_default();
        let f = match File::open(fsrc).await {
            Ok(f) => f,
            Err(err) => {
                eprintln!("could not open {fsrc}: {err}");
                return ExitCode::FAILURE;
            }
        };
        let l = match f.metadata().await {
            Ok(metadata) => metadata.len(),
            Err(err) => {
                eprintln!("could not read metadata for {fsrc}: {err}");
                return ExitCode::FAILURE;
            }
        };
        return run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            f,
            l,
            &source,
            &tx,
            rx,
            progress_json,
            pause,
        )
        .await;
    } else {
        let vurl = if source.starts_with("http://") || source.starts_with("https://") {
            source
        } else {
            let content_id = if Uuid::try_parse(&source).is_err() {
                let region = market.clone().unwrap_or("US".into()).to_uppercase();
                let content_id_task = match crate::package_plan::resolve(client, &source.to_uppercase(), &region).await {
                    Ok(plan) => if selected_content_id.is_some() { plan.select(selected_content_id.as_deref()) }
                        else { plan.without_durable_selection().select(None) },
                    Err(error) => Err(error),
                };
                let Ok(content_id) = content_id_task else {
                    let Err(err) = content_id_task else {
                        eprintln!("Unknown Error");
                        return ExitCode::FAILURE;
                    };
                    eprintln!("{}", err);
                    return ExitCode::FAILURE;
                };
                content_id
            } else {
                source
            };
            let package_result = get_packages(client, tokens, content_id.clone()).await;
            let Ok(package) = package_result else {
                let Err(err) = package_result else {
                    eprintln!("Unknown Error");
                    return ExitCode::FAILURE;
                };
                eprintln!("{}", err);
                return ExitCode::FAILURE;
            };
            let Some(file) = package
                .package_files
                .iter()
                .find(|p| p.file_name.ends_with(".msixvc"))
            else {
                eprintln!("No .msixvc file found");
                return ExitCode::FAILURE;
            };
            let Some(root) = file.cdn_root_paths.first() else {
                eprintln!("Microsoft returned no package download location."); return ExitCode::FAILURE;
            };
            format!(
                "{}{}",
                root,
                file.relative_url
            )
        };
        let url = &vurl;
        let mut pos = 0;
        let http_file = match streaming::HttpRead::open(
            client.clone(),
            url,
            Some(|c, _| {
                if tx
                    .try_send(ProgressEvent::Advanced {
                        id: usize::MAX,
                        delta: c - pos,
                    })
                    .is_ok()
                {
                    pos = c;
                }
            }),
        )
        .await {
            Ok(file) => file,
            Err(error) => { failure::report(&error); return ExitCode::FAILURE; }
        };
        let l = http_file.len();

        return run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            http_file,
            l,
            url,
            &tx,
            rx,
            progress_json,
            pause,
        )
        .await;
    }
}

async fn run_cli_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    tx: &Sender<ProgressEvent>,
    mut rx: Receiver<ProgressEvent>,
    progress_json: bool,
    pause: tokio::sync::watch::Receiver<bool>,
) -> ExitCode
where
    Reader: AsyncRead + Unpin,
{
    let reporter = tokio::spawn(async move {
        if progress_json {
            progress::report(rx).await;
            return;
        }
        let multi_progress = MultiProgress::new();
        let total_progess = multi_progress.add(ProgressBar::new(l).with_style(
            ProgressStyle::with_template("{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%").unwrap()
            .progress_chars("#>-")
        ));

        total_progess.set_message("Initializing");
        let mut bars: HashMap<usize, ProgressBar> = HashMap::new();

        while let Some(event) = rx.recv().await {
            match event {
                ProgressEvent::Started { id, name, total } => {
                    let cur_progess = multi_progress.add(ProgressBar::new(total).with_style(
                        ProgressStyle::with_template("{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%").unwrap()
                        .progress_chars("#>-")
                    ));
                    cur_progess.set_message(name);
                    bars.insert(id, cur_progess);
                }
                ProgressEvent::Advanced { id, delta } => {
                    if let Some(bar) = bars.get(&id) {
                        bar.inc(delta);
                    }
                    total_progess.inc(delta);
                }
                ProgressEvent::Finished { id } => {
                    if let Some(bar) = bars.remove(&id) {
                        bar.finish_and_clear();
                    }
                }
                ProgressEvent::UpdateRemaining { name, total } => {
                    total_progess.set_message(name);
                    total_progess.set_length(total_progess.position() + total);
                }
                ProgressEvent::UpdateStatus { name } => {
                    total_progess.set_message(name);
                }
                ProgressEvent::Paused { .. } => {}
                ProgressEvent::Completed { .. } => break,
            }
        }

        total_progess.abandon();
    });
    let code = run_reader(
        client,
        tokens,
        destination,
        try_skip_ntfs,
        parallel,
        market,
        reader,
        l,
        url,
        tx,
        pause,
    )
    .await;
    tx.send(ProgressEvent::Completed {
        success: code == ExitCode::SUCCESS,
    })
    .await
    .ok();
    if reporter.await.is_err() {
        return ExitCode::FAILURE;
    }
    code
}

async fn run_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    tx: &Sender<ProgressEvent>,
    pause: tokio::sync::watch::Receiver<bool>,
) -> ExitCode
where
    Reader: AsyncRead + Unpin,
{
    let out: &Path = Path::new(&destination);

    if let Err(error) = std::fs::create_dir_all(out) {
        failure::report(&error); return ExitCode::FAILURE;
    }
    let _folder_lock = match resume::lock(out) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("Cannot start this download: {error}");
            return ExitCode::FAILURE;
        }
    };

    let cache_path = out.join(".xodus-streaming-tmp.msixvc");
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut remote_file = match streaming::PrefixCacheFile::new(reader, l, cache_path.clone()).await {
        Ok(file) => file,
        Err(error) => { failure::report(&error); return ExitCode::FAILURE; }
    };
    let remote_xvd = match XvdFile::parse(&mut remote_file).await {
        Ok(xvd) => xvd,
        Err(error) => { failure::report_metadata(error.as_ref()); return ExitCode::FAILURE; }
    };
    let mut rfiles: HashMap<String, SegmentFile> = HashMap::new();
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let files = match remote_xvd
        .parse_user_package_files(&mut remote_file)
        .await
    {
        Ok(files) => files,
        Err(error) => {
            failure::report_metadata(error.as_ref());
            return ExitCode::FAILURE;
        }
    };
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = match remote_xvd
                .parse_segment_metadata(&mut remote_file, v)
                .await {
                Ok(files) => files,
                Err(error) => { failure::report_metadata(error.as_ref()); return ExitCode::FAILURE; }
            };
            rfiles = sfiles;
        }
    }

    if !try_skip_ntfs || rfiles.is_empty() {
        tx.send(ProgressEvent::UpdateStatus {
            name: "Downloading ntfs...".to_owned(),
        })
        .await
        .ok();
        let sfiles = match remote_xvd
            .parse_ntfs_segment_metadata(&mut remote_file, !rfiles.is_empty())
            .await {
            Ok(files) => files,
            Err(error) => { failure::report_metadata(error.as_ref()); return ExitCode::FAILURE; }
        };
        rfiles.extend(sfiles);
    }

    let file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .ok();

    if let Some(mut file) = file {
        let xvd = match XvdFile::parse(&mut file).await {
            Ok(xvd) => xvd,
            Err(error) => { failure::report_metadata(error.as_ref()); return ExitCode::FAILURE; }
        };

        let files = match xvd.parse_user_package_files(&mut file).await {
            Ok(files) => files,
            Err(error) => {
                failure::report_metadata(error.as_ref());
                return ExitCode::FAILURE;
            }
        };
        for (k, v) in &files {
            if k == "SegmentMetadata.bin" {
                let sfiles = match xvd.parse_segment_metadata(&mut file, v).await {
                    Ok(files) => files,
                    Err(error) => { failure::report_metadata(error.as_ref()); return ExitCode::FAILURE; }
                };
                lfiles = sfiles;
            }
        }

        if let Ok(sfiles) = xvd
            .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
            .await
        {
            lfiles.extend(sfiles);
        }
    }

    let license = get_license(
        client,
        tokens,
        remote_xvd.content_id().to_string(),
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

    let full_key = match content_key.unpack(&key) {
        Ok(key) => key,
        Err(_) => { eprintln!("The content key could not be authenticated. Retry the installation or sign in again."); return ExitCode::FAILURE; }
    };

    let pending = match pending_files(out, &rfiles, &lfiles) {
        Ok(files) => files,
        Err(error) => { eprintln!("Unable to inspect installed package files: {error}"); return ExitCode::FAILURE; }
    };
    let total_size: u64 = pending
        .iter()
        .map(|(_, v)| v.length)
        .sum();

    let journal = match resume::Journal::open(out, &remote_xvd.resume_identity(), &rfiles) {
        Ok(journal) => std::sync::Arc::new(std::sync::Mutex::new(journal)),
        Err(error) => {
            eprintln!("Unable to prepare download checkpoints: {error}");
            return ExitCode::FAILURE;
        }
    };
    let saved: u64 = pending
        .iter()
        .map(|(name, file)| journal.lock().unwrap().offset(name, file.length))
        .sum();
    let required_free_space = total_size.saturating_sub(saved);
    let available_free_space = match available_space(out) {
        Ok(space) => space,
        Err(err) => {
            eprintln!(
                "failed to determine available space for {}: {}",
                out.display(),
                err
            );
            return ExitCode::FAILURE;
        }
    };

    if available_free_space < required_free_space {
        eprintln!(
            "not enough free disk space on {}: need {} bytes, have {} bytes (files: {})",
            out.display(),
            required_free_space,
            available_free_space,
            total_size
        );
        return ExitCode::FAILURE;
    }

    tx.send(ProgressEvent::UpdateRemaining {
        name: "Downloading".to_owned(),
        total: total_size,
    })
    .await
    .ok();

    let remote_xvd_ref = &remote_xvd;
    let (failed, failure_signal) = tokio::sync::watch::channel(false);
    stream::iter(
        pending
            .into_iter()
            .map(|(n, v)| Job {
                name: n.clone(),
                content: SegmentFile {
                    offset: v.offset,
                    length: v.length,
                    data_hashs: vec![],
                    keep_encrypted: v.keep_encrypted,
                },
            })
            .enumerate(),
    )
    .for_each_concurrent(parallel.unwrap_or(4).max(1), |(id, job)| {
        let tx = tx.clone();
        let client = client.clone();
        let mut pause = pause.clone();
        let journal = journal.clone();
        let failed = failed.clone();
        let failure_signal = failure_signal.clone();
        async move {
            if *failed.borrow() { return; }
            let prepared = async {
                pause.wait_for(|paused| !*paused).await.ok();
                Ok(())
            };
            if failure::run_or_cancel(failure_signal.clone(), prepared).await.is_err() { return; }
            let opened = async {
                let target_file = resume::target(out, &job.name)?;
                if let Some(folder) = target_file.parent() { std::fs::create_dir_all(folder)?; }
                Ok::<_,failure::Error>(OpenOptions::new().create(true).write(true).truncate(false).open(&target_file).await?)
            }.await;
            let mut fout = match opened {
                Ok(file) => file,
                Err(error) => { if !failed.send_replace(true) { failure::report(error.as_ref()); } return; }
            };
            let operation = async {
            let mut offset = journal
                .lock()
                .unwrap()
                .offset(&job.name, job.content.length);
            if url.starts_with("file://") && offset != job.content.length {
                offset = 0;
            }
            offset = resume::prepare_output(&mut fout, offset, &job.content).await?;
            let mut lp = offset;

            let progress = |pos, _| {
                if tx
                    .try_send(ProgressEvent::Advanced {
                        id,
                        delta: pos - lp,
                    })
                    .is_ok()
                {
                    lp = pos;
                }
            };
            let path = job.name.to_owned();
            let shown = if path.chars().count() > 30 {
                let tail: String = path.chars().rev().take(27).collect::<Vec<_>>().into_iter().rev().collect();
                format!("...{tail}")
            } else {
                path.clone()
            };
            tx.send(ProgressEvent::Started {
                id,
                name: shown,
                total: job.content.length,
            })
            .await
            .ok();

            tx.send(ProgressEvent::Advanced { id, delta: offset })
                .await
                .ok();
            if offset == job.content.length {
                return Ok::<(),failure::Error>(());
            }
            journal
                .lock()
                .unwrap()
                .checkpoint(&job.name, offset)?;

            if let Some(fpath) = url.strip_prefix("file://") {
                let mut i = File::open(&fpath).await?;
                remote_xvd_ref
                    .extract_file(&mut i, &mut fout, &job.content, *full_key, progress)
                    .await?;
            } else {
                remote_xvd_ref
                    .download_file_http(
                        &client,
                        url,
                        &mut fout,
                        &job.content,
                        *full_key,
                        progress,
                        Some(pause),
                        offset,
                        |position| journal.lock().unwrap().checkpoint(&job.name, position),
                    )
                    .await?;
            }
            Ok(())
            };
            let result = failure::run_or_cancel(failure_signal, operation).await;
            let result = failure::settle(&mut fout, result, || journal.lock().unwrap().checkpoint(&job.name,job.content.length)).await;
            match result {
                Ok(()) => { tx.send(ProgressEvent::Finished { id }).await.ok(); }
                Err(error) => { if !failed.send_replace(true) { failure::report(error.as_ref()); } }
            }
        }
    })
    .await;

    if *failed.borrow() { return ExitCode::FAILURE; }
    tx.send(ProgressEvent::UpdateStatus {
        name: "Finalizing".to_owned(),
    })
    .await
    .ok();
    if let Err(error) = failure::finalize(&cache_path, &final_path, false) {
        failure::report(&error);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
