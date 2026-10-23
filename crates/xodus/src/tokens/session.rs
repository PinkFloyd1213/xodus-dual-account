//! Freshness checks for network sessions, without changing raw credential reads.
use crate::models::secrets::Token;
use chrono::{DateTime, Duration, Utc};
#[cfg(unix)]
use std::time::Duration as WaitDuration;

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    Current,
    Expired,
    Invalid,
}

pub fn state(token: &Token, now: DateTime<Utc>) -> State {
    let Token::Legacy(token) = token else {
        return State::Invalid;
    };
    let (Ok(created), Ok(expires)) = (
        DateTime::parse_from_rfc3339(&token.lifetime.created),
        DateTime::parse_from_rfc3339(&token.lifetime.expires),
    ) else {
        return State::Invalid;
    };
    if expires <= created || created > now + Duration::minutes(5) {
        return State::Invalid;
    }
    if expires <= now {
        State::Expired
    } else {
        State::Current
    }
}

#[cfg(unix)]
pub(crate) async fn renewal_lock() -> std::io::Result<std::fs::File> {
    let uid = unsafe { libc::geteuid() };
    let root = std::env::temp_dir().join(format!("xodus-nexus-session-{uid}"));
    renewal_lock_at(&root, uid, WaitDuration::from_secs(15)).await
}
#[cfg(unix)]
async fn renewal_lock_at(
    root: &std::path::Path,
    uid: u32,
    wait: WaitDuration,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let dir = std::fs::symlink_metadata(&root)?;
    if !dir.is_dir() || dir.uid() != uid || dir.mode() & 0o077 != 0 {
        return Err(std::io::Error::other("Unsafe session lock directory"));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join("device.lock"))?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != uid || meta.nlink() != 1 || meta.mode() & 0o077 != 0 {
        return Err(std::io::Error::other("Unsafe session lock"));
    }
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(file),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(WaitDuration::from_millis(100)).await
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{secrets::LegacyToken, soap::Timestamp};
    fn token(created: &str, expires: &str) -> Token {
        Token::Legacy(LegacyToken {
            key_name: None,
            token: "fixture".into(),
            binary_secret: None,
            tpm_key: None,
            lifetime: Timestamp {
                id: None,
                created: created.into(),
                expires: expires.into(),
            },
        })
    }
    #[test]
    fn credential_session_lifetime_boundaries_and_offsets() {
        let now = DateTime::parse_from_rfc3339("2026-10-19T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            state(&token("2026-10-19T09:00:00Z", "2026-10-19T10:00:01Z"), now),
            State::Current
        );
        assert_eq!(
            state(&token("2026-10-19T09:00:00Z", "2026-10-19T10:00:00Z"), now),
            State::Expired
        );
        assert_eq!(
            state(
                &token("2026-10-19T11:00:00+02:00", "2026-10-19T13:00:00+02:00"),
                now
            ),
            State::Current
        );
        assert_eq!(
            state(&token("2000-01-01T00:00:00Z", "2001-01-01T00:00:00Z"), now),
            State::Expired
        );
        for (created, expires) in [
            ("bad", "2099-01-01T00:00:00Z"),
            ("2000-01-01T00:00:00Z", "bad"),
            ("2026-10-19T10:05:01Z", "2099-01-01T00:00:00Z"),
            ("2026-10-19T09:00:00Z", "2000-01-01T00:00:00Z"),
        ] {
            assert_eq!(state(&token(created, expires), now), State::Invalid);
        }
        assert_eq!(
            state(&Token::Compact("fixture".into()), now),
            State::Invalid
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn credential_session_renewal_lock_serializes_and_refuses_unsafe_paths() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = std::env::temp_dir().join(format!("xodus-session-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let root = dir.join("lock");
        let uid = unsafe { libc::geteuid() };
        let first = renewal_lock_at(&root, uid, WaitDuration::from_millis(5))
            .await
            .unwrap();
        assert!(
            renewal_lock_at(&root, uid, WaitDuration::from_millis(5))
                .await
                .is_err()
        );
        drop(first);
        drop(
            renewal_lock_at(&root, uid, WaitDuration::from_millis(5))
                .await
                .unwrap(),
        );
        let link = dir.join("link");
        symlink(&root, &link).unwrap();
        assert!(
            renewal_lock_at(&link, uid, WaitDuration::from_millis(5))
                .await
                .is_err()
        );
        let sentinel = dir.join("sentinel");
        std::fs::write(&sentinel, "unchanged").unwrap();
        std::fs::remove_file(root.join("device.lock")).unwrap();
        symlink(&sentinel, root.join("device.lock")).unwrap();
        assert!(
            renewal_lock_at(&root, uid, WaitDuration::from_millis(5))
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "unchanged");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            renewal_lock_at(&root, uid, WaitDuration::from_millis(5))
                .await
                .is_err()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
