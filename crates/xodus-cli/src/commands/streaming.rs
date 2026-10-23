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
use tokio::io::{AsyncRead, AsyncSeekExt};
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::Uuid;
use xodus::tokens::TokenManager;

use crate::license::get_license;
use crate::package::get_packages;

#[path = "streaming_progress.rs"]
mod progress;
#[path = "streaming_resume.rs"]
mod resume;

struct Job {
    name: String,
    content: SegmentFile,
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
                    Ok(plan) => plan.select(selected_content_id.as_deref()),
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
            format!(
                "{}{}",
                file.cdn_root_paths.first().unwrap(),
                file.relative_url
            )
        };
        let url = &vurl;
        let mut pos = 0;
        let http_file = streaming::HttpRead::open(
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
        .await
        .expect("ok");
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

    std::fs::create_dir_all(out).expect("ok");
    let _folder_lock = match resume::lock(out) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("Cannot start this download: {error}");
            return ExitCode::FAILURE;
        }
    };

    let cache_path = out.join(".xodus-streaming-tmp.msixvc");
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut remote_file = streaming::PrefixCacheFile::new(reader, l, cache_path.clone())
        .await
        .expect("no err");
    let remote_xvd = XvdFile::parse(&mut remote_file).await.expect("no err");
    let mut rfiles: HashMap<String, SegmentFile> = HashMap::new();
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let files = match remote_xvd
        .parse_user_package_files(&mut remote_file)
        .await
    {
        Ok(files) => files,
        Err(error) => {
            eprintln!("Cannot read package-file metadata: {error}");
            return ExitCode::FAILURE;
        }
    };
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = remote_xvd
                .parse_segment_metadata(&mut remote_file, v)
                .await
                .expect("ok");
            rfiles = sfiles;
        }
    }

    if !try_skip_ntfs || rfiles.is_empty() {
        tx.send(ProgressEvent::UpdateStatus {
            name: "Downloading ntfs...".to_owned(),
        })
        .await
        .ok();
        let sfiles = remote_xvd
            .parse_ntfs_segment_metadata(&mut remote_file, !rfiles.is_empty())
            .await
            .expect("ok");
        rfiles.extend(sfiles);
    }

    let file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .ok();

    if let Some(mut file) = file {
        let xvd = XvdFile::parse(&mut file).await.expect("no err");

        let files = match xvd.parse_user_package_files(&mut file).await {
            Ok(files) => files,
            Err(error) => {
                eprintln!("Cannot read cached package-file metadata: {error}");
                return ExitCode::FAILURE;
            }
        };
        for (k, v) in &files {
            if k == "SegmentMetadata.bin" {
                let sfiles = xvd.parse_segment_metadata(&mut file, v).await.expect("ok");
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

    let full_key = content_key.unpack(&key).expect("failed to unpack");

    let total_size: u64 = rfiles
        .iter()
        .filter(|(k, v1)| {
            if let Some(v2) = lfiles.get(*k) {
                v1.data_hashs != v2.data_hashs || v1.data_hashs.is_empty()
            } else {
                true
            }
        })
        .map(|(_, v)| v.length)
        .sum();

    let journal = match resume::Journal::open(out, &remote_xvd.resume_identity(), &rfiles) {
        Ok(journal) => std::sync::Arc::new(std::sync::Mutex::new(journal)),
        Err(error) => {
            eprintln!("Unable to prepare download checkpoints: {error}");
            return ExitCode::FAILURE;
        }
    };
    let saved: u64 = rfiles
        .iter()
        .filter(|(name, remote)| {
            lfiles.get(*name).is_none_or(|local| {
                remote.data_hashs != local.data_hashs || remote.data_hashs.is_empty()
            })
        })
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
    stream::iter(
        rfiles
            .iter()
            .filter(|(k, v1)| {
                if let Some(v2) = lfiles.get(*k) {
                    v1.data_hashs != v2.data_hashs || v1.data_hashs.is_empty()
                } else {
                    true
                }
            })
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
    .for_each_concurrent(parallel.unwrap_or(4), |(id, job)| {
        let tx = tx.clone();
        let client = client.clone();
        let mut pause = pause.clone();
        let journal = journal.clone();
        async move {
            pause.wait_for(|paused| !*paused).await.ok();
            let target_file = resume::target(out, &job.name).expect("safe download path");
            if let Some(folder) = target_file.parent() {
                std::fs::create_dir_all(folder).expect("ok");
            }
            let mut offset = journal
                .lock()
                .unwrap()
                .offset(&job.name, job.content.length);
            if url.starts_with("file://") && offset != job.content.length {
                offset = 0;
            }
            let mut fout = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&target_file)
                .await
                .expect("ok");
            if offset != job.content.length {
                fout.set_len(offset)
                    .await
                    .expect("truncate to durable checkpoint");
                fout.seek(std::io::SeekFrom::Start(offset))
                    .await
                    .expect("seek checkpoint");
            }
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
                tx.send(ProgressEvent::Finished { id }).await.ok();
                return;
            }
            journal
                .lock()
                .unwrap()
                .checkpoint(&job.name, offset)
                .expect("initial durable checkpoint");

            if let Some(fpath) = url.strip_prefix("file://") {
                let mut i = File::open(&fpath).await.unwrap();
                remote_xvd_ref
                    .extract_file(&mut i, &mut fout, &job.content, *full_key, progress)
                    .await
                    .expect("msg");
                use tokio::io::AsyncWriteExt;
                fout.flush().await.expect("flush extracted file");
                journal
                    .lock()
                    .unwrap()
                    .checkpoint(&job.name, job.content.length)
                    .expect("checkpoint extracted file");
                tx.send(ProgressEvent::Finished { id }).await.ok();
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
                    .await
                    .expect("msg");
                tx.send(ProgressEvent::Finished { id }).await.ok();
            }
        }
    })
    .await;

    tx.send(ProgressEvent::UpdateStatus {
        name: "Finalizing".to_owned(),
    })
    .await
    .ok();
    std::fs::remove_file(&final_path).ok();
    std::fs::rename(&cache_path, &final_path).expect("ok");
    ExitCode::SUCCESS
}
