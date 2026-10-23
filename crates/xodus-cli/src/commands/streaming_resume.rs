//! Durable checkpoints for the exact package layout, never CDN URLs/tokens.
use msixvc::streaming::resume_digest;
use msixvc::xvd::SegmentFile;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufRead, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

pub(super) struct Journal {
    root: PathBuf,
    identity: String,
    entries: serde_json::Map<String, serde_json::Value>,
}

/// Trim stale tails even when the complete new file has zero bytes.
pub(super) async fn prepare_output(file: &mut tokio::fs::File, offset: u64) -> io::Result<()> {
    use tokio::io::AsyncSeekExt;
    file.set_len(offset).await?;
    file.seek(SeekFrom::Start(offset)).await?;
    Ok(())
}

#[tokio::test]
async fn streaming_updated_file_is_trimmed_even_when_its_expected_length_is_zero_or_complete() {
    for offset in [0, 4] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("updated.bin");
        std::fs::write(&path, b"old-content").unwrap();
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .await
            .unwrap();
        prepare_output(&mut file, offset).await.unwrap();
        assert_eq!(
            std::fs::read(path).unwrap(),
            &b"old-content"[..offset as usize]
        );
    }
}

pub(super) fn lock(root: &Path) -> io::Result<File> {
    let path = target(root, ".nexus-streaming.lock")?;
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    fs2::FileExt::try_lock_exclusive(&file)
        .map_err(|_| io::Error::other("another download is using this folder"))?;
    Ok(file)
}

pub(super) fn target(root: &Path, name: &str) -> io::Result<PathBuf> {
    let relative = name.replace('\\', "/");
    let relative = Path::new(&relative);
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(io::Error::other("unsafe package filename"));
    }
    let mut path = root.to_owned();
    for component in relative.components() {
        path.push(component);
        if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(io::Error::other("symlink in package download path"));
        }
    }
    Ok(path)
}

impl Journal {
    pub(super) fn open(
        root: &Path,
        content: &str,
        files: &HashMap<String, SegmentFile>,
    ) -> io::Result<Self> {
        let mut layout: Vec<_> = files
            .iter()
            .map(|(name, f)| (name, f.offset, f.length, f.keep_encrypted, &f.data_hashs))
            .collect();
        layout.sort_by(|a, b| a.0.cmp(b.0));
        let identity = resume_digest(&serde_json::to_vec(&(content, layout))?);
        let path = target(root, ".nexus-streaming-v1.jsonl")?;
        let mut entries = serde_json::Map::new();
        if let Ok(file) = File::open(&path) {
            // A torn final append is ignored; previously synced records survive.
            for line in std::io::BufReader::new(file.take(64 * 1024 * 1024)).split(b'\n') {
                let Ok(line) = line else {
                    break;
                };
                if line.len() > 4096 {
                    continue;
                }
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&line) {
                    if value["schema"] == 1 && value["identity"].as_str() == Some(identity.as_str())
                    {
                        if let Some(name) = value["file"].as_str() {
                            entries.insert(name.to_owned(), value["checkpoint"].clone());
                        }
                    }
                }
            }
        }
        let journal = Self {
            root: root.to_owned(),
            identity,
            entries,
        };
        journal.compact()?;
        Ok(journal)
    }

    pub(super) fn offset(&self, name: &str, length: u64) -> u64 {
        let Some(entry) = self.entries.get(name) else {
            return 0;
        };
        let Some(offset) = entry["offset"]
            .as_u64()
            .filter(|v| *v <= length && (*v == length || *v % 4096 == 0))
        else {
            return 0;
        };
        let valid = target(&self.root, name)
            .and_then(|path| tail(&path, offset))
            .is_ok_and(|digest| entry["tailSha256"].as_str() == Some(digest.as_str()));
        if valid { offset } else { 0 }
    }

    pub(super) fn checkpoint(&mut self, name: &str, offset: u64) -> io::Result<()> {
        let file = target(&self.root, name)?;
        // File data reaches storage before the journal claims it can be resumed.
        File::open(&file)?.sync_data()?;
        let digest = tail(&file, offset)?;
        let entry = serde_json::json!({"offset": offset, "tailSha256": digest});
        let path = target(&self.root, ".nexus-streaming-v1.jsonl")?;
        let mut out = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(out, "{}", self.record(name, &entry))?;
        out.sync_all()?;
        self.entries.insert(name.to_owned(), entry);
        Ok(())
    }

    fn record(&self, name: &str, entry: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({"schema":1, "identity":self.identity, "file":name, "checkpoint":entry})
    }

    fn compact(&self) -> io::Result<()> {
        let path = self.root.join(".nexus-streaming-v1.jsonl");
        let temp = self
            .root
            .join(format!(".nexus-streaming-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut out = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            for (name, entry) in &self.entries {
                writeln!(out, "{}", self.record(name, entry))?;
            }
            out.sync_all()?;
            fs::rename(&temp, &path)?;
            File::open(&self.root)?.sync_all()
        })();
        if result.is_err() {
            fs::remove_file(&temp).ok();
        }
        result
    }
}

fn tail(path: &Path, offset: u64) -> io::Result<String> {
    let mut file = File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() < offset {
        return Err(io::Error::other("checkpoint file is incomplete"));
    }
    let start = offset.saturating_sub(65536);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = vec![0; (offset - start) as usize];
    file.read_exact(&mut bytes)?;
    Ok(resume_digest(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streaming_resume_reopens_checkpoint_and_rejects_changed_data_or_package() {
        let root = tempfile::tempdir().unwrap();
        let files = HashMap::from([(
            "game.bin".to_owned(),
            SegmentFile {
                offset: 0,
                length: 8192,
                keep_encrypted: false,
                data_hashs: vec![],
            },
        )]);
        fs::write(root.path().join("game.bin"), vec![7; 8192]).unwrap();
        let mut journal = Journal::open(root.path(), "package-A", &files).unwrap();
        journal.checkpoint("game.bin", 4096).unwrap();
        assert_eq!(
            Journal::open(root.path(), "package-A", &files)
                .unwrap()
                .offset("game.bin", 8192),
            4096
        );
        fs::write(root.path().join("game.bin"), vec![8; 8192]).unwrap();
        assert_eq!(journal.offset("game.bin", 8192), 0);
        assert_eq!(
            Journal::open(root.path(), "package-B", &files)
                .unwrap()
                .offset("game.bin", 8192),
            0
        );
        assert!(target(root.path(), "../outside").is_err());
        let _guard = lock(root.path()).unwrap();
        assert!(lock(root.path()).is_err());
    }
}
