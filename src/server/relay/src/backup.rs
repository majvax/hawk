//! Scheduled backups of the database: `HAWK_BACKUP_DIR`, every
//! `HAWK_BACKUP_INTERVAL` hours, the newest `HAWK_BACKUP_KEEP` kept.
//!
//! Each one is `VACUUM INTO` from a connection of its own, on the blocking
//! pool: a consistent snapshot (a read transaction, which in WAL mode
//! doesn't hold up writers) that's also compacted. It's written under a
//! temporary name, checked, synced, and only then renamed into place, so a
//! file with the final name is always a whole database.
//!
//! A backup holds everything the database does: password hashes, sealed
//! TOTP seeds, session hashes. Files and the folder are made readable by
//! the relay's user only (on Unix). The secret key isn't in them; it has
//! to be kept as well, apart.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use tracing::{error, info, warn};

use crate::metrics::{METRICS, Metrics};

pub const DEFAULT_INTERVAL_HOURS: u64 = 24;
pub const DEFAULT_KEEP: usize = 7;
/// After a failure, the next try comes sooner than a whole interval.
const RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

const PREFIX: &str = "hawk-";
const SUFFIX: &str = ".db";
/// `20261025T081500Z`.
const STAMP_LEN: usize = 16;
/// A backup being written. Starts with a dot, so nothing mistakes it for
/// a finished one.
const TEMP_PREFIX: &str = ".hawk-";
const TEMP_SUFFIX: &str = ".db.tmp";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupConfig {
    pub dir: PathBuf,
    pub interval: Duration,
    pub keep: usize,
}

impl BackupConfig {
    /// None when there's no directory: backups are off.
    pub fn parse(dir: Option<&str>, interval: Option<&str>, keep: Option<&str>) -> Result<Option<Self>, String> {
        let Some(dir) = dir.map(str::trim).filter(|dir| !dir.is_empty()) else { return Ok(None) };
        let given = |setting: Option<&str>| setting.map(str::trim).filter(|setting| !setting.is_empty()).map(str::to_owned);
        let hours = match given(interval) {
            None => DEFAULT_INTERVAL_HOURS,
            Some(hours) => match hours.parse::<u64>() {
                Ok(hours) if (1..=24 * 365).contains(&hours) => hours,
                _ => return Err(format!("HAWK_BACKUP_INTERVAL: \"{hours}\" isn't a number of hours (1 or more)")),
            },
        };
        let keep = match given(keep) {
            None => DEFAULT_KEEP,
            Some(keep) => match keep.parse::<usize>() {
                Ok(keep) if keep >= 1 => keep,
                _ => return Err(format!("HAWK_BACKUP_KEEP: \"{keep}\" isn't a number of backups (1 or more)")),
            },
        };
        Ok(Some(Self { dir: PathBuf::from(dir), interval: Duration::from_secs(hours * 60 * 60), keep }))
    }
}

/// `hawk-20261025T081500Z.db`.
fn file_name(at: OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    format!(
        "{PREFIX}{:04}{:02}{:02}T{:02}{:02}{:02}Z{SUFFIX}",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

/// When a backup's name says it was taken; None for anything else.
fn taken_at(name: &str) -> Option<OffsetDateTime> {
    let stamp = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
    // Digits everywhere but the T and the Z: a parse alone would also take
    // a sign ("+026"), and pruning must touch nothing it didn't name.
    let digits = stamp.bytes().enumerate().all(|(index, byte)| matches!(index, 8 | 15) || byte.is_ascii_digit());
    if stamp.len() != STAMP_LEN || !digits || &stamp[8..9] != "T" || &stamp[15..] != "Z" {
        return None;
    }
    let number = |range: std::ops::Range<usize>| stamp.get(range)?.parse::<u16>().ok();
    let month = Month::try_from(u8::try_from(number(4..6)?).ok()?).ok()?;
    let date = Date::from_calendar_date(i32::from(number(0..4)?), month, u8::try_from(number(6..8)?).ok()?).ok()?;
    let clock = Time::from_hms(
        u8::try_from(number(9..11)?).ok()?,
        u8::try_from(number(11..13)?).ok()?,
        u8::try_from(number(13..15)?).ok()?,
    )
    .ok()?;
    Some(PrimitiveDateTime::new(date, clock).assume_utc())
}

/// The finished backups in `dir`, oldest first (the names sort by time).
fn backups(dir: &Path) -> std::io::Result<Vec<(OffsetDateTime, PathBuf)>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(at) = name.to_str().and_then(taken_at) {
            found.push((at, entry.path()));
        }
    }
    found.sort();
    Ok(found)
}

/// Deletes the oldest backups beyond `keep`, and returns how many went.
fn prune(dir: &Path, keep: usize) -> std::io::Result<usize> {
    let found = backups(dir)?;
    let excess = found.len().saturating_sub(keep);
    for (_, path) in &found[..excess] {
        std::fs::remove_file(path)?;
    }
    Ok(excess)
}

/// The folder, made readable by its owner only if this creates it (one
/// that's already there, a mounted volume, keeps its permissions).
fn create_dir(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

/// An empty file only the owner can read or write, for VACUUM INTO to
/// fill (it takes an empty file as well as a missing one).
fn create_private(path: &Path) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path).map(drop)
}

/// Takes one backup of the database at `source` into `dir`, named for
/// `now`, then prunes to `keep`. Blocking: run it on the blocking pool.
pub fn run_once(source: &Path, dir: &Path, keep: usize, now: OffsetDateTime) -> Result<PathBuf, String> {
    create_dir(dir).map_err(|error| format!("creating {}: {error}", dir.display()))?;
    // Left by a backup the relay was stopped in the middle of.
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(TEMP_PREFIX) && name.ends_with(TEMP_SUFFIX) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    let name = file_name(now);
    let target = dir.join(&name);
    let temp = dir.join(format!(".{name}.tmp"));
    create_private(&temp).map_err(|error| format!("creating {}: {error}", temp.display()))?;
    let written = (|| {
        let into = temp.to_str().ok_or("the backup folder's path isn't valid UTF-8")?;
        // Never created here: a missing database is an error, not an empty backup.
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(source, flags)
            .map_err(|error| format!("opening {}: {error}", source.display()))?;
        conn.busy_timeout(Duration::from_secs(30)).map_err(|error| error.to_string())?;
        conn.execute("VACUUM INTO ?1", [into]).map_err(|error| format!("VACUUM INTO: {error}"))?;
        drop(conn);
        let copy = Connection::open(&temp).map_err(|error| format!("opening the copy: {error}"))?;
        let check: String = copy
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|error| format!("checking the copy: {error}"))?;
        if check != "ok" {
            return Err(format!("the copy failed its check: {check}"));
        }
        drop(copy);
        // Opened for writing: Windows won't flush a file opened to read.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&temp)
            .and_then(|file| file.sync_all())
            .map_err(|error| format!("syncing: {error}"))?;
        Ok::<_, String>(())
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    std::fs::rename(&temp, &target).map_err(|error| {
        let _ = std::fs::remove_file(&temp);
        format!("renaming into {}: {error}", target.display())
    })?;
    // The rename itself, on disk.
    #[cfg(unix)]
    if let Ok(dir) = std::fs::File::open(dir) {
        let _ = dir.sync_all();
    }
    match prune(dir, keep) {
        Ok(0) => {}
        Ok(pruned) => info!(pruned, keep, "backup: deleted the oldest"),
        Err(error) => warn!(%error, "backup: deleting old backups failed"),
    }
    Ok(target)
}

/// When the newest backup in `dir` was taken, by its name.
fn newest(dir: &Path) -> Option<OffsetDateTime> {
    backups(dir).ok().and_then(|found| found.last().map(|(at, _)| *at))
}

/// Turns the backup metrics on, with the last success taken from the
/// newest backup already there: an alert on its age doesn't go off just
/// because the relay restarted.
fn start_metrics(metrics: &Metrics, dir: &Path) {
    metrics.backups_enabled();
    if let Some(at) = newest(dir) {
        metrics.backup_seen(at.unix_timestamp());
    }
}

/// How long until the next backup is due: an interval after the newest
/// there is, or now. A relay that keeps restarting doesn't take a new one
/// each time and push the older ones out.
fn due_in(dir: &Path, interval: Duration, now: OffsetDateTime) -> Duration {
    let Some(newest) = newest(dir) else { return Duration::ZERO };
    let since = now - newest;
    if since.is_negative() {
        return interval; // a clock that went back: start the count again
    }
    interval.saturating_sub(since.unsigned_abs())
}

/// Takes a backup whenever one is due, for as long as the relay runs.
pub fn spawn(config: BackupConfig, source: PathBuf) {
    start_metrics(&METRICS, &config.dir);
    tokio::spawn(async move {
        let mut wait = due_in(&config.dir, config.interval, OffsetDateTime::now_utc());
        loop {
            tokio::time::sleep(wait).await;
            let (source, dir, keep) = (source.clone(), config.dir.clone(), config.keep);
            let now = OffsetDateTime::now_utc();
            let taken = tokio::task::spawn_blocking(move || run_once(&source, &dir, keep, now))
                .await
                .unwrap_or_else(|error| Err(format!("the backup task failed: {error}")));
            wait = match taken {
                Ok(path) => {
                    METRICS.backup_succeeded(now.unix_timestamp());
                    info!(path = %path.display(), "backup: written");
                    config.interval
                }
                Err(error) => {
                    METRICS.backup_failed();
                    error!(%error, "backup: failed");
                    RETRY_AFTER.min(config.interval)
                }
            };
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    /// A folder of its own under the system's temp, gone afterwards.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("hawk-backup-test-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    #[test]
    fn reads_its_settings() {
        assert_eq!(BackupConfig::parse(None, Some("3"), Some("2")), Ok(None));
        assert_eq!(BackupConfig::parse(Some(" "), None, None), Ok(None));
        let config = BackupConfig::parse(Some("/var/lib/hawk/backups"), None, None).unwrap().unwrap();
        assert_eq!(config.interval, Duration::from_secs(24 * 60 * 60));
        assert_eq!(config.keep, DEFAULT_KEEP);
        let config = BackupConfig::parse(Some("b"), Some(" 6 "), Some("30")).unwrap().unwrap();
        assert_eq!((config.interval, config.keep), (Duration::from_secs(6 * 60 * 60), 30));
        for (interval, keep) in [(Some("0"), None), (Some("1.5"), None), (Some("daily"), None), (None, Some("0"))] {
            assert!(BackupConfig::parse(Some("b"), interval, keep).is_err(), "{interval:?} {keep:?}");
        }
    }

    #[test]
    fn names_carry_the_time() {
        let when = at(1_793_000_000);
        let name = file_name(when);
        assert_eq!(name.len(), PREFIX.len() + STAMP_LEN + SUFFIX.len());
        assert_eq!(taken_at(&name), Some(when));
        for other in [
            "hawk.db",
            "hawk-.db",
            "hawk-20261325T000000Z.db",
            "hawk-20261025T081500Z.db.tmp",
            ".hawk-20261025T081500Z.db.tmp",
            "notes.txt",
            "hawk-+0261025T081500Z.db",
            "hawk-2026+025T081500Z.db",
            "hawk-20261025T+81500Z.db",
            "hawk-20261025t081500Z.db",
            "hawk-20261025T081500z.db",
            "hawk-20261025T081500Z.DB",
            "hawk-2026102éT08150Z.db",
        ] {
            assert_eq!(taken_at(other), None, "{other}");
        }
    }

    /// A backup is a whole, valid database with what the relay wrote, made
    /// from under a live connection; pruning keeps the newest few.
    #[tokio::test]
    async fn backs_up_and_keeps_the_newest() {
        let scratch = Scratch::new();
        let source = scratch.0.join("data").join("hawk.db");
        let db = Db::open(&source).unwrap();
        db.call(|conn| {
            conn.execute(
                "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES ('a@example.com', 'x', 1, 0)",
                [],
            )
        })
        .await
        .unwrap();
        let dir = scratch.0.join("backups");
        let base = 1_793_000_000;
        let mut written = Vec::new();
        for hour in 0..5 {
            let (source, dir) = (source.clone(), dir.clone());
            let path = tokio::task::spawn_blocking(move || run_once(&source, &dir, 3, at(base + hour * 3600)))
                .await
                .unwrap()
                .unwrap();
            written.push(path);
        }

        let mut left: Vec<String> =
            std::fs::read_dir(&dir).unwrap().map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
        left.sort();
        let newest: Vec<String> =
            written[2..].iter().map(|path| path.file_name().unwrap().to_str().unwrap().to_owned()).collect();
        assert_eq!(left, newest, "only the newest 3, and no temporary files");

        let copy = Connection::open(&written[4]).unwrap();
        let check: String = copy.query_row("PRAGMA integrity_check", [], |row| row.get(0)).unwrap();
        assert_eq!(check, "ok");
        let email: String = copy.query_row("SELECT email FROM users", [], |row| row.get(0)).unwrap();
        assert_eq!(email, "a@example.com");
        let version: i64 = copy.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert!(version > 0, "the schema version comes along");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in &written[2..] {
                assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
            }
            assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        }

        // A restarted relay reports the newest as its last success.
        let metrics = Metrics::new();
        start_metrics(&metrics, &dir);
        let (audit, _events) = crate::audit::AuditLog::new(1);
        let text = crate::metrics::render(&metrics, &crate::metrics::Live::default(), &audit, None);
        let line = format!("hawk_relay_backup_last_success_timestamp_seconds {}
", base + 4 * 3600);
        assert!(text.contains(&line), "{text}");
        assert!(text.contains("hawk_relay_backups_total 0
"), "none written by this relay yet");
        let empty = Metrics::new();
        start_metrics(&empty, &scratch.0.join("nowhere"));
        let text = crate::metrics::render(&empty, &crate::metrics::Live::default(), &audit, None);
        assert!(text.contains("hawk_relay_backup_last_success_timestamp_seconds 0
"));

        // The next one is due an interval after the newest.
        let interval = Duration::from_secs(24 * 3600);
        assert_eq!(due_in(&dir, interval, at(base + 4 * 3600 + 600)), interval - Duration::from_secs(600));
        assert_eq!(due_in(&dir, interval, at(base + 40 * 3600)), Duration::ZERO);
        assert_eq!(due_in(&scratch.0.join("nowhere"), interval, at(base)), Duration::ZERO);
    }

    /// Pruning deletes only its own backups, oldest first; anything else in
    /// the folder, look-alikes included, stays.
    #[test]
    fn pruning_touches_only_its_own_files() {
        let scratch = Scratch::new();
        let dir = &scratch.0;
        let ours = ["hawk-20200101T000000Z.db", "hawk-20210101T000000Z.db", "hawk-20220101T000000Z.db"];
        let others = ["hawk.db", "hawk-+0200101T000000Z.db", "hawk-20200101T000000Z.db-wal", "notes.txt", "secret.key"];
        for name in ours.iter().chain(&others) {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        std::fs::create_dir(dir.join("hawk-20190101T000000Z.db")).unwrap();
        assert!(prune(dir, 1).is_err(), "a folder named like a backup is never deleted");
        assert!(dir.join("hawk-20190101T000000Z.db").is_dir() && dir.join(ours[0]).exists());
        std::fs::remove_dir(dir.join("hawk-20190101T000000Z.db")).unwrap();

        assert_eq!(prune(dir, 1).unwrap(), 2);
        let mut left: Vec<String> =
            std::fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
        left.sort();
        let mut expected: Vec<String> = others.iter().chain(&ours[2..]).map(|name| (*name).to_owned()).collect();
        expected.sort();
        assert_eq!(left, expected);
    }

    /// A leftover temporary file goes; a source that isn't a database
    /// fails without leaving one, and without touching what's there.
    #[test]
    fn failures_leave_nothing_behind() {
        let scratch = Scratch::new();
        let dir = scratch.0.join("backups");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".hawk-20200101T000000Z.db.tmp"), b"half").unwrap();
        std::fs::write(dir.join("hawk-20200101T000000Z.db"), b"older").unwrap();
        let source = scratch.0.join("not-a-database");
        std::fs::write(&source, b"this is not SQLite, just some bytes that go on long enough").unwrap();
        assert!(run_once(&source, &dir, 1, at(1_793_000_000)).is_err());
        let left: Vec<String> =
            std::fs::read_dir(&dir).unwrap().map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
        assert_eq!(left, ["hawk-20200101T000000Z.db"]);
    }
}
