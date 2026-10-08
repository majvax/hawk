//! SQLite persistence: accounts, sessions and invites. Live connection state
//! stays in the registry; only what must survive a restart lives here.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};

/// Schema migrations, applied in order. `PRAGMA user_version` records how
/// many have run. Append new ones; never edit a released one.
const MIGRATIONS: &[&str] = &["
    CREATE TABLE users (
        id            INTEGER PRIMARY KEY,
        email         TEXT    NOT NULL UNIQUE,   -- stored lowercased
        password_hash TEXT    NOT NULL,          -- argon2id PHC string
        is_admin      INTEGER NOT NULL DEFAULT 0,
        disabled      INTEGER NOT NULL DEFAULT 0,
        created_at    INTEGER NOT NULL           -- unix seconds
    );
    CREATE TABLE sessions (
        id         INTEGER PRIMARY KEY,
        token_hash BLOB    NOT NULL UNIQUE,      -- SHA-256 of the cookie value
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    );
    CREATE TABLE invites (
        id           INTEGER PRIMARY KEY,
        token_hash   BLOB    NOT NULL UNIQUE,    -- SHA-256 of the invite token
        created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
        grants_admin INTEGER NOT NULL DEFAULT 0,
        created_at   INTEGER NOT NULL,
        expires_at   INTEGER NOT NULL,
        used_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
        used_at      INTEGER
    );
"];

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| format!("creating {}: {error}", parent.display()))?;
        }
        let conn = Connection::open(path).map_err(|error| format!("opening {}: {error}", path.display()))?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;")
            .map_err(|error| error.to_string())?;
        migrate(&conn).map_err(|error| format!("migrating {}: {error}", path.display()))?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    /// Runs `f` against the connection on the blocking pool, so queries never
    /// stall the async runtime.
    pub async fn call<F, R>(&self, f: F) -> rusqlite::Result<R>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            f(&conn)
        })
        .await
        .expect("database task panicked")
    }
}

fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let applied: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    for (version, migration) in (1_i64..).zip(MIGRATIONS).skip(usize::try_from(applied).unwrap_or(0)) {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(migration)?;
        tx.pragma_update(None, "user_version", version)?;
        tx.commit()?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub is_admin: bool,
}

pub struct UserWithPassword {
    pub user: User,
    pub password_hash: String,
    pub disabled: bool,
}

pub struct UserRow {
    pub user: User,
    pub disabled: bool,
    pub created_at: i64,
}

pub struct InviteRow {
    pub id: i64,
    pub grants_admin: bool,
    pub created_at: i64,
    pub expires_at: i64,
}

pub enum SignupError {
    InvalidInvite,
    EmailTaken,
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for SignupError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(error)
    }
}

pub fn user_count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
}

pub fn find_user_by_email(conn: &Connection, email: &str) -> rusqlite::Result<Option<UserWithPassword>> {
    conn.query_row(
        "SELECT id, email, is_admin, password_hash, disabled FROM users WHERE email = ?1",
        [email],
        |row| {
            Ok(UserWithPassword {
                user: User { id: row.get(0)?, email: row.get(1)?, is_admin: row.get(2)? },
                password_hash: row.get(3)?,
                disabled: row.get(4)?,
            })
        },
    )
    .optional()
}

pub fn list_users(conn: &Connection) -> rusqlite::Result<Vec<UserRow>> {
    let mut statement =
        conn.prepare("SELECT id, email, is_admin, disabled, created_at FROM users ORDER BY created_at, id")?;
    statement
        .query_map([], |row| {
            Ok(UserRow {
                user: User { id: row.get(0)?, email: row.get(1)?, is_admin: row.get(2)? },
                disabled: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?
        .collect()
}

/// Disabling also ends every session the user has. Returns false if there
/// is no such user.
pub fn set_user_disabled(conn: &Connection, user_id: i64, disabled: bool) -> rusqlite::Result<bool> {
    let tx = conn.unchecked_transaction()?;
    let changed = tx.execute("UPDATE users SET disabled = ?1 WHERE id = ?2", params![disabled, user_id])?;
    if disabled {
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?;
    }
    tx.commit()?;
    Ok(changed > 0)
}

pub fn create_session(
    conn: &Connection,
    token_hash: &[u8],
    user_id: i64,
    now: i64,
    expires_at: i64,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![token_hash, user_id, now, expires_at],
    )?;
    Ok(conn.last_insert_rowid())
}

/// The live session for this token: not expired, user not disabled.
pub fn find_session(conn: &Connection, token_hash: &[u8], now: i64) -> rusqlite::Result<Option<(i64, User)>> {
    conn.query_row(
        "SELECT s.id, u.id, u.email, u.is_admin
           FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND u.disabled = 0",
        params![token_hash, now],
        |row| Ok((row.get(0)?, User { id: row.get(1)?, email: row.get(2)?, is_admin: row.get(3)? })),
    )
    .optional()
}

pub fn delete_session(conn: &Connection, session_id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM sessions WHERE id = ?1", [session_id])?;
    Ok(())
}

pub fn create_invite(
    conn: &Connection,
    token_hash: &[u8],
    created_by: Option<i64>,
    grants_admin: bool,
    now: i64,
    expires_at: i64,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO invites (token_hash, created_by, grants_admin, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![token_hash, created_by, grants_admin, now, expires_at],
    )?;
    Ok(conn.last_insert_rowid())
}

/// An unused, unexpired invite.
pub fn find_invite(conn: &Connection, token_hash: &[u8], now: i64) -> rusqlite::Result<Option<InviteRow>> {
    conn.query_row(
        "SELECT id, grants_admin, created_at, expires_at FROM invites
          WHERE token_hash = ?1 AND used_by IS NULL AND expires_at > ?2",
        params![token_hash, now],
        invite_from_row,
    )
    .optional()
}

pub fn list_pending_invites(conn: &Connection, now: i64) -> rusqlite::Result<Vec<InviteRow>> {
    let mut statement = conn.prepare(
        "SELECT id, grants_admin, created_at, expires_at FROM invites
          WHERE used_by IS NULL AND expires_at > ?1 ORDER BY created_at DESC",
    )?;
    statement.query_map([now], invite_from_row)?.collect()
}

pub fn delete_pending_invite(conn: &Connection, invite_id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM invites WHERE id = ?1 AND used_by IS NULL", [invite_id])? > 0)
}

/// Removes unused admin invites, so only the newest bootstrap link works.
pub fn delete_pending_admin_invites(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM invites WHERE grants_admin = 1 AND used_by IS NULL", [])?;
    Ok(())
}

fn invite_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<InviteRow> {
    Ok(InviteRow { id: row.get(0)?, grants_admin: row.get(1)?, created_at: row.get(2)?, expires_at: row.get(3)? })
}

/// Consumes an invite and creates its account in one transaction, so an
/// invite can never produce two accounts.
pub fn redeem_invite(
    conn: &Connection,
    token_hash: &[u8],
    email: &str,
    password_hash: &str,
    now: i64,
) -> Result<User, SignupError> {
    let tx = conn.unchecked_transaction()?;
    let invite = find_invite(&tx, token_hash, now)?.ok_or(SignupError::InvalidInvite)?;
    let inserted = tx.execute(
        "INSERT INTO users (email, password_hash, is_admin, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![email, password_hash, invite.grants_admin, now],
    );
    match inserted {
        Err(rusqlite::Error::SqliteFailure(failure, _))
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            return Err(SignupError::EmailTaken);
        }
        other => {
            other?;
        }
    }
    let user_id = tx.last_insert_rowid();
    tx.execute("UPDATE invites SET used_by = ?1, used_at = ?2 WHERE id = ?3", params![user_id, now, invite.id])?;
    tx.commit()?;
    Ok(User { id: user_id, email: email.to_owned(), is_admin: invite.grants_admin })
}

pub fn purge_expired(conn: &Connection, now: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", [now])?;
    conn.execute("DELETE FROM invites WHERE used_by IS NULL AND expires_at <= ?1", [now])?;
    Ok(())
}
