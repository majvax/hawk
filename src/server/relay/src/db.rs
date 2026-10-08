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
", "
    CREATE TABLE machines (
        id              INTEGER PRIMARY KEY,
        public_id       TEXT    NOT NULL UNIQUE,   -- what dashboards and the API use
        owner_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name            TEXT    NOT NULL,          -- set by the owner; defaults to hostname
        hostname        TEXT    NOT NULL,          -- as last reported by the machine
        credential_hash BLOB    NOT NULL UNIQUE,   -- SHA-256 of the machine's credential
        created_at      INTEGER NOT NULL,
        last_seen_at    INTEGER
    );
    CREATE TABLE enrollment_codes (
        id         INTEGER PRIMARY KEY,
        code_hash  BLOB    NOT NULL UNIQUE,
        owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    );
    CREATE TABLE machine_shares (
        machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role       TEXT    NOT NULL CHECK (role IN ('view', 'control')),
        created_at INTEGER NOT NULL,
        PRIMARY KEY (machine_id, user_id)
    );
", "
    -- Machines authenticate with a key pair instead of a bearer credential.
    -- key_fingerprint is SHA-256(public_key); rows enrolled before this
    -- migration keep their old credential hash there, have no public_key,
    -- and can't connect until they're enrolled again.
    ALTER TABLE machines RENAME COLUMN credential_hash TO key_fingerprint;
    ALTER TABLE machines ADD COLUMN public_key BLOB;   -- uncompressed P-256 point, 65 bytes
    ALTER TABLE machines ADD COLUMN key_storage TEXT;  -- 'tpm' or 'software', as reported by the machine
", "
    -- Where a session signed in from, so its owner can tell them apart.
    -- NULL for sessions created before this migration.
    ALTER TABLE sessions ADD COLUMN user_agent TEXT;
    ALTER TABLE sessions ADD COLUMN ip TEXT;
", "
    -- Temporary shares. A share grants access only while
    -- starts_at <= now < expires_at (NULL: no bound); the relay deletes it
    -- once it expires. A single_view share is used up by one viewing.
    ALTER TABLE machine_shares ADD COLUMN starts_at INTEGER;
    ALTER TABLE machine_shares ADD COLUMN expires_at INTEGER;
    ALTER TABLE machine_shares ADD COLUMN single_view INTEGER NOT NULL DEFAULT 0;
    CREATE INDEX machine_shares_expires_at ON machine_shares (expires_at) WHERE expires_at IS NOT NULL;
    CREATE INDEX machine_shares_starts_at ON machine_shares (starts_at) WHERE starts_at IS NOT NULL;
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

/// Where a session was signed in from.
pub struct SessionOrigin {
    pub user_agent: Option<String>,
    pub ip: String,
}

pub fn create_session(
    conn: &Connection,
    token_hash: &[u8],
    user_id: i64,
    origin: &SessionOrigin,
    now: i64,
    expires_at: i64,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, user_agent, ip, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![token_hash, user_id, origin.user_agent, origin.ip, now, expires_at],
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

pub struct SessionRow {
    pub id: i64,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
}

/// The user's unexpired sessions, newest first.
pub fn list_sessions(conn: &Connection, user_id: i64, now: i64) -> rusqlite::Result<Vec<SessionRow>> {
    let mut statement = conn.prepare(
        "SELECT id, user_agent, ip, created_at, expires_at FROM sessions
          WHERE user_id = ?1 AND expires_at > ?2 ORDER BY created_at DESC, id DESC",
    )?;
    statement
        .query_map(params![user_id, now], |row| {
            Ok(SessionRow {
                id: row.get(0)?,
                user_agent: row.get(1)?,
                ip: row.get(2)?,
                created_at: row.get(3)?,
                expires_at: row.get(4)?,
            })
        })?
        .collect()
}

/// Returns false if `user_id` has no such session.
pub fn delete_user_session(conn: &Connection, user_id: i64, session_id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM sessions WHERE id = ?1 AND user_id = ?2", params![session_id, user_id])? > 0)
}

/// Ends every session the user has except `keep`.
pub fn delete_other_sessions(conn: &Connection, user_id: i64, keep: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM sessions WHERE user_id = ?1 AND id <> ?2", params![user_id, keep])?;
    Ok(())
}

pub fn password_hash(conn: &Connection, user_id: i64) -> rusqlite::Result<String> {
    conn.query_row("SELECT password_hash FROM users WHERE id = ?1", [user_id], |row| row.get(0))
}

/// Replaces the password hash and ends every other session, in one
/// transaction. Only replaces `old_hash`: returns false if the password
/// changed since it was read, so a concurrent change isn't silently undone.
pub fn change_password(
    conn: &Connection,
    user_id: i64,
    old_hash: &str,
    new_hash: &str,
    keep_session: i64,
) -> rusqlite::Result<bool> {
    let tx = conn.unchecked_transaction()?;
    let changed = tx.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2 AND password_hash = ?3",
        params![new_hash, user_id, old_hash],
    )?;
    if changed == 0 {
        return Ok(false);
    }
    delete_other_sessions(&tx, user_id, keep_session)?;
    tx.commit()?;
    Ok(true)
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
    conn.execute("DELETE FROM enrollment_codes WHERE expires_at <= ?1", [now])?;
    Ok(())
}

pub fn find_user_id_by_email(conn: &Connection, email: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row("SELECT id FROM users WHERE email = ?1", [email], |row| row.get(0)).optional()
}

// ---- machines -------------------------------------------------------------

/// What a user may do with a machine. Ordered: each role includes the ones
/// before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    View,
    Control,
    Owner,
}

impl Role {
    fn from_sql(text: &str) -> Self {
        match text {
            "owner" => Self::Owner,
            "control" => Self::Control,
            _ => Self::View,
        }
    }

    /// The value stored in machine_shares.role (never "owner").
    fn share_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Control | Self::Owner => "control",
        }
    }
}

/// A machine as one particular user sees it.
#[derive(Debug, Clone)]
pub struct MachineRow {
    pub public_id: String,
    pub owner_id: i64,
    pub owner_email: String,
    pub name: String,
    pub hostname: String,
    pub last_seen_at: Option<i64>,
    /// "tpm" or "software"; None for a machine that must be re-enrolled.
    pub key_storage: Option<String>,
    pub role: Role,
    /// When a temporary share ends; None for owners and open-ended shares.
    pub share_expires_at: Option<i64>,
    /// A share that one viewing uses up.
    pub single_view: bool,
}

/// The machine behind an authenticated device connection.
#[derive(Debug, Clone)]
pub struct MachineAuth {
    pub public_id: String,
    pub owner_id: i64,
}

/// What a connecting machine must prove it holds the private half of.
pub struct MachineKey {
    pub owner_id: i64,
    pub public_key: Vec<u8>,
}

pub struct ShareRow {
    pub user_id: i64,
    pub email: String,
    pub terms: ShareTerms,
}

/// What a share grants, and for how long.
#[derive(Debug, Clone, Copy)]
pub struct ShareTerms {
    pub role: Role,
    /// Access begins here; None: right away.
    pub starts_at: Option<i64>,
    /// Access ends here and the share is deleted; None: until revoked.
    pub expires_at: Option<i64>,
    /// Used up when the viewer's first viewing ends.
    pub single_view: bool,
}

/// A share as a (machine, user) pair, for mirroring into the registry.
pub struct ShareKey {
    pub public_id: String,
    pub user_id: i64,
}

pub fn create_enrollment_code(
    conn: &Connection,
    code_hash: &[u8],
    owner_id: i64,
    now: i64,
    expires_at: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO enrollment_codes (code_hash, owner_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![code_hash, owner_id, now, expires_at],
    )?;
    Ok(())
}

/// The owner of a usable enrollment code: unknown, used, expired codes and
/// disabled owners give None. Doesn't consume it.
pub fn enrollment_code_owner(conn: &Connection, code_hash: &[u8], now: i64) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT c.owner_id FROM enrollment_codes c JOIN users u ON u.id = c.owner_id
          WHERE c.code_hash = ?1 AND c.expires_at > ?2 AND u.disabled = 0",
        params![code_hash, now],
        |row| row.get(0),
    )
    .optional()
}

pub struct NewMachine<'a> {
    pub code_hash: &'a [u8],
    pub public_id: &'a str,
    pub hostname: &'a str,
    pub public_key: &'a [u8],
    pub key_storage: &'a str,
}

/// Consumes an enrollment code and registers the machine under the code's
/// owner, in one transaction, so a code can only ever enroll one machine.
/// None if the code is no longer usable.
pub fn enroll_machine(conn: &Connection, machine: &NewMachine<'_>, now: i64) -> rusqlite::Result<Option<MachineAuth>> {
    let tx = conn.unchecked_transaction()?;
    let Some(owner_id) = enrollment_code_owner(&tx, machine.code_hash, now)? else { return Ok(None) };
    tx.execute("DELETE FROM enrollment_codes WHERE code_hash = ?1", [machine.code_hash])?;
    let fingerprint = crate::auth::token_hash_bytes(machine.public_key);
    tx.execute(
        "INSERT INTO machines
             (public_id, owner_id, name, hostname, key_fingerprint, public_key, key_storage, created_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![machine.public_id, owner_id, machine.hostname, fingerprint, machine.public_key, machine.key_storage, now],
    )?;
    tx.commit()?;
    Ok(Some(MachineAuth { public_id: machine.public_id.to_owned(), owner_id }))
}

/// The public key a machine must prove it holds. None if the machine is
/// unknown, its owner is disabled, or it was enrolled before keys existed.
pub fn machine_key(conn: &Connection, public_id: &str) -> rusqlite::Result<Option<MachineKey>> {
    conn.query_row(
        "SELECT m.owner_id, m.public_key FROM machines m JOIN users u ON u.id = m.owner_id
          WHERE m.public_id = ?1 AND u.disabled = 0 AND m.public_key IS NOT NULL",
        [public_id],
        |row| Ok(MachineKey { owner_id: row.get(0)?, public_key: row.get(1)? }),
    )
    .optional()
}

/// Records a successful connection: current hostname, and seen now.
pub fn record_connect(conn: &Connection, public_id: &str, hostname: &str, now: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE machines SET hostname = ?1, last_seen_at = ?2 WHERE public_id = ?3",
        params![hostname, now, public_id],
    )?;
    Ok(())
}

pub fn touch_machine(conn: &Connection, public_id: &str, now: i64) -> rusqlite::Result<()> {
    conn.execute("UPDATE machines SET last_seen_at = ?1 WHERE public_id = ?2", params![now, public_id])?;
    Ok(())
}

fn machine_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MachineRow> {
    Ok(MachineRow {
        public_id: row.get(0)?,
        owner_id: row.get(1)?,
        owner_email: row.get(2)?,
        name: row.get(3)?,
        hostname: row.get(4)?,
        last_seen_at: row.get(5)?,
        key_storage: row.get(6)?,
        role: Role::from_sql(&row.get::<_, String>(7)?),
        share_expires_at: row.get(8)?,
        single_view: row.get(9)?,
    })
}

/// Every machine the user owns or has been shared, with their role on it.
/// Shares of a disabled owner's machines are left out, and so are shares
/// outside their time window at `now`.
pub fn accessible_machines(conn: &Connection, user_id: i64, now: i64) -> rusqlite::Result<Vec<MachineRow>> {
    let mut statement = conn.prepare(
        "SELECT m.public_id, m.owner_id, o.email, m.name, m.hostname, m.last_seen_at, m.key_storage, 'owner',
                NULL, 0
           FROM machines m JOIN users o ON o.id = m.owner_id
          WHERE m.owner_id = ?1
         UNION ALL
         SELECT m.public_id, m.owner_id, o.email, m.name, m.hostname, m.last_seen_at, m.key_storage, s.role,
                s.expires_at, s.single_view
           FROM machine_shares s
           JOIN machines m ON m.id = s.machine_id
           JOIN users o ON o.id = m.owner_id
          WHERE s.user_id = ?1 AND o.disabled = 0
            AND (s.starts_at IS NULL OR s.starts_at <= ?2)
            AND (s.expires_at IS NULL OR s.expires_at > ?2)
         ORDER BY 4",
    )?;
    statement.query_map(params![user_id, now], machine_from_row)?.collect()
}

/// One machine as `user_id` sees it at `now`, if they have any access to it.
pub fn machine_for_user(
    conn: &Connection,
    public_id: &str,
    user_id: i64,
    now: i64,
) -> rusqlite::Result<Option<MachineRow>> {
    Ok(accessible_machines(conn, user_id, now)?.into_iter().find(|machine| machine.public_id == public_id))
}

/// The machine's internal id, if `owner_id` owns it.
fn owned_machine_id(conn: &Connection, public_id: &str, owner_id: i64) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM machines WHERE public_id = ?1 AND owner_id = ?2",
        params![public_id, owner_id],
        |row| row.get(0),
    )
    .optional()
}

/// Users the machine is shared with (internal machine id).
fn shared_user_ids(conn: &Connection, machine_id: i64) -> rusqlite::Result<Vec<i64>> {
    conn.prepare("SELECT user_id FROM machine_shares WHERE machine_id = ?1")?
        .query_map([machine_id], |row| row.get(0))?
        .collect()
}

/// Renames an owned machine. Returns the users it's shared with (who need
/// the update too), or None if `owner_id` doesn't own it.
pub fn rename_machine(
    conn: &Connection,
    public_id: &str,
    owner_id: i64,
    name: &str,
) -> rusqlite::Result<Option<Vec<i64>>> {
    let Some(machine_id) = owned_machine_id(conn, public_id, owner_id)? else { return Ok(None) };
    conn.execute("UPDATE machines SET name = ?1 WHERE id = ?2", params![name, machine_id])?;
    shared_user_ids(conn, machine_id).map(Some)
}

/// Deletes an owned machine (its shares go by cascade). Returns false if
/// `owner_id` doesn't own it.
pub fn delete_machine(conn: &Connection, public_id: &str, owner_id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM machines WHERE public_id = ?1 AND owner_id = ?2", params![public_id, owner_id])? > 0)
}

/// Who an owned machine is shared with; None if `owner_id` doesn't own it.
pub fn list_shares(conn: &Connection, public_id: &str, owner_id: i64) -> rusqlite::Result<Option<Vec<ShareRow>>> {
    let Some(machine_id) = owned_machine_id(conn, public_id, owner_id)? else { return Ok(None) };
    let mut statement = conn.prepare(
        "SELECT u.id, u.email, s.role, s.starts_at, s.expires_at, s.single_view
           FROM machine_shares s JOIN users u ON u.id = s.user_id
          WHERE s.machine_id = ?1 ORDER BY u.email",
    )?;
    let shares = statement
        .query_map([machine_id], |row| {
            Ok(ShareRow {
                user_id: row.get(0)?,
                email: row.get(1)?,
                terms: ShareTerms {
                    role: Role::from_sql(&row.get::<_, String>(2)?),
                    starts_at: row.get(3)?,
                    expires_at: row.get(4)?,
                    single_view: row.get(5)?,
                },
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Some(shares))
}

pub enum ShareError {
    NotOwner,
    NoSuchUser,
    SelfShare,
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for ShareError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(error)
    }
}

/// Shares an owned machine with the account with `email`, or replaces the
/// terms of an existing share. Returns that account's user id.
pub fn upsert_share(
    conn: &Connection,
    public_id: &str,
    owner_id: i64,
    email: &str,
    terms: ShareTerms,
    now: i64,
) -> Result<i64, ShareError> {
    let machine_id = owned_machine_id(conn, public_id, owner_id)?.ok_or(ShareError::NotOwner)?;
    let user_id = find_user_id_by_email(conn, email)?.ok_or(ShareError::NoSuchUser)?;
    if user_id == owner_id {
        return Err(ShareError::SelfShare);
    }
    conn.execute(
        "INSERT INTO machine_shares (machine_id, user_id, role, created_at, starts_at, expires_at, single_view)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (machine_id, user_id) DO UPDATE SET
             role = excluded.role, starts_at = excluded.starts_at,
             expires_at = excluded.expires_at, single_view = excluded.single_view",
        params![
            machine_id,
            user_id,
            terms.role.share_str(),
            now,
            terms.starts_at,
            terms.expires_at,
            terms.single_view
        ],
    )?;
    Ok(user_id)
}

/// Deletes the user's share of the machine if it's a single-view one.
/// Returns whether it did.
pub fn delete_single_view_share(conn: &Connection, public_id: &str, user_id: i64) -> rusqlite::Result<bool> {
    let deleted = conn.execute(
        "DELETE FROM machine_shares
          WHERE user_id = ?2 AND single_view = 1
            AND machine_id = (SELECT id FROM machines WHERE public_id = ?1)",
        params![public_id, user_id],
    )?;
    Ok(deleted > 0)
}

/// Deletes every share that has expired by `now` and returns them.
pub fn take_expired_shares(conn: &Connection, now: i64) -> rusqlite::Result<Vec<ShareKey>> {
    let tx = conn.unchecked_transaction()?;
    let expired = tx
        .prepare(
            "SELECT m.public_id, s.user_id FROM machine_shares s JOIN machines m ON m.id = s.machine_id
              WHERE s.expires_at <= ?1",
        )?
        .query_map([now], |row| Ok(ShareKey { public_id: row.get(0)?, user_id: row.get(1)? }))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    tx.execute("DELETE FROM machine_shares WHERE expires_at <= ?1", [now])?;
    tx.commit()?;
    Ok(expired)
}

/// Shares whose start time is in `(after, now]` and that haven't expired:
/// the ones that began granting access since `after`.
pub fn shares_started_between(conn: &Connection, after: i64, now: i64) -> rusqlite::Result<Vec<ShareKey>> {
    conn.prepare(
        "SELECT m.public_id, s.user_id FROM machine_shares s JOIN machines m ON m.id = s.machine_id
          WHERE s.starts_at > ?1 AND s.starts_at <= ?2 AND (s.expires_at IS NULL OR s.expires_at > ?2)",
    )?
    .query_map(params![after, now], |row| Ok(ShareKey { public_id: row.get(0)?, user_id: row.get(1)? }))?
    .collect()
}

/// The next time after `now` a share starts or expires, if any will.
pub fn next_share_deadline(conn: &Connection, now: i64) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT MIN(t) FROM (
             SELECT MIN(expires_at) AS t FROM machine_shares WHERE expires_at IS NOT NULL
             UNION ALL
             SELECT MIN(starts_at) FROM machine_shares WHERE starts_at > ?1
         )",
        [now],
        |row| row.get(0),
    )
}

/// Returns false if `owner_id` doesn't own the machine or it wasn't shared
/// with `user_id`.
pub fn delete_share(conn: &Connection, public_id: &str, owner_id: i64, user_id: i64) -> rusqlite::Result<bool> {
    let Some(machine_id) = owned_machine_id(conn, public_id, owner_id)? else { return Ok(false) };
    let deleted =
        conn.execute("DELETE FROM machine_shares WHERE machine_id = ?1 AND user_id = ?2", params![machine_id, user_id])?;
    Ok(deleted > 0)
}
