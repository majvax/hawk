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
", "
    -- End-to-end encryption. Passwords never reach the relay any more: the
    -- browser derives an auth key from the password (that's what
    -- password_hash now hashes) and a wrapping key, under which it stores
    -- the user's identity key here. 'legacy' accounts still hash the
    -- password itself until their next login upgrades them.
    ALTER TABLE users ADD COLUMN kdf TEXT NOT NULL DEFAULT 'legacy';  -- 'legacy' or 'pbkdf2-sha256'
    ALTER TABLE users ADD COLUMN kdf_iterations INTEGER;
    ALTER TABLE users ADD COLUMN public_key BLOB;   -- identity key, uncompressed P-256 point
    ALTER TABLE users ADD COLUMN wrapped_key BLOB;  -- its private half, encrypted in the browser

    -- The owner's key, MACed with the enrollment code, which the relay never
    -- sees: the machine checks it to pin its owner. The machine answers with
    -- its own MACed key, which the owner's browser checks before endorsing it.
    ALTER TABLE enrollment_codes ADD COLUMN owner_binding BLOB;
    ALTER TABLE machines ADD COLUMN enroll_code_hash BLOB;
    ALTER TABLE machines ADD COLUMN enroll_binding BLOB;
    ALTER TABLE machines ADD COLUMN endorsement BLOB;  -- owner's signature over the machine's key

    -- What the owner signed for each share, which the machine checks itself.
    ALTER TABLE machine_shares ADD COLUMN grant_statement TEXT;
    ALTER TABLE machine_shares ADD COLUMN grant_signature BLOB;

    -- Signed by the owner when access is taken away; the machine is sent
    -- every one for it each time it connects.
    CREATE TABLE machine_revocations (
        id         INTEGER PRIMARY KEY,
        machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
        statement  TEXT    NOT NULL,
        signature  BLOB    NOT NULL,
        created_at INTEGER NOT NULL
    );
", "
    -- A third share role, dev: a shell (and files), no video. SQLite can't
    -- change a CHECK in place, so the table is rebuilt with the same rows.
    CREATE TABLE machine_shares_new (
        machine_id      INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
        user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role            TEXT    NOT NULL CHECK (role IN ('view', 'control', 'dev')),
        created_at      INTEGER NOT NULL,
        starts_at       INTEGER,
        expires_at      INTEGER,
        single_view     INTEGER NOT NULL DEFAULT 0,
        grant_statement TEXT,
        grant_signature BLOB,
        PRIMARY KEY (machine_id, user_id)
    );
    INSERT INTO machine_shares_new
        (machine_id, user_id, role, created_at, starts_at, expires_at, single_view, grant_statement, grant_signature)
        SELECT machine_id, user_id, role, created_at, starts_at, expires_at, single_view, grant_statement,
               grant_signature
        FROM machine_shares;
    DROP TABLE machine_shares;
    ALTER TABLE machine_shares_new RENAME TO machine_shares;
    CREATE INDEX machine_shares_expires_at ON machine_shares (expires_at) WHERE expires_at IS NOT NULL;
    CREATE INDEX machine_shares_starts_at ON machine_shares (starts_at) WHERE starts_at IS NOT NULL;
", "
    -- Second factors. A TOTP seed has to be readable to check a code, so
    -- it's encrypted under the relay's secret key rather than hashed.
    CREATE TABLE mfa_factors (
        id           INTEGER PRIMARY KEY,
        user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        kind         TEXT    NOT NULL CHECK (kind IN ('totp')),
        label        TEXT    NOT NULL,
        secret       BLOB    NOT NULL,             -- sealed with auth::SecretKey
        last_counter INTEGER NOT NULL DEFAULT -1,  -- last time step accepted: no replays
        created_at   INTEGER NOT NULL,
        last_used_at INTEGER
    );
    CREATE INDEX mfa_factors_user_id ON mfa_factors (user_id);
    -- Single-use codes for when every factor is lost. Only their SHA-256.
    CREATE TABLE recovery_codes (
        id        INTEGER PRIMARY KEY,
        user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash BLOB    NOT NULL,
        used_at   INTEGER
    );
    CREATE INDEX recovery_codes_user_id ON recovery_codes (user_id);
    -- When the session last proved a second factor; step-up actions need
    -- it to be recent.
    ALTER TABLE sessions ADD COLUMN step_up_at INTEGER;

    -- Email ownership. Accounts from before this are taken as verified.
    ALTER TABLE users ADD COLUMN email_verified_at INTEGER;
    UPDATE users SET email_verified_at = created_at;
    CREATE TABLE email_verifications (
        id         INTEGER PRIMARY KEY,
        token_hash BLOB    NOT NULL UNIQUE,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    );

    -- Instance-wide policy the admin sets, as key/value.
    CREATE TABLE settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
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

/// How the browser turns this account's password into its auth and
/// wrapping keys.
pub struct LoginParams {
    pub kdf: String,
    pub iterations: Option<i64>,
}

/// The account's identity key, as the browser stored it.
pub struct UserKey {
    pub public_key: Vec<u8>,
    pub wrapped_key: Vec<u8>,
}

/// An account's derived credentials: the hash of its auth key, and its
/// identity key.
pub struct NewCredentials<'a> {
    pub password_hash: &'a str,
    pub iterations: i64,
    pub public_key: &'a [u8],
    pub wrapped_key: &'a [u8],
}

pub struct UserRow {
    pub user: User,
    pub disabled: bool,
    pub created_at: i64,
    pub mfa: bool,
    pub email_verified: bool,
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

pub fn login_params(conn: &Connection, email: &str) -> rusqlite::Result<Option<LoginParams>> {
    conn.query_row("SELECT kdf, kdf_iterations FROM users WHERE email = ?1", [email], |row| {
        Ok(LoginParams { kdf: row.get(0)?, iterations: row.get(1)? })
    })
    .optional()
}

pub fn user_key(conn: &Connection, user_id: i64) -> rusqlite::Result<Option<UserKey>> {
    conn.query_row(
        "SELECT public_key, wrapped_key FROM users
          WHERE id = ?1 AND public_key IS NOT NULL AND wrapped_key IS NOT NULL",
        [user_id],
        |row| Ok(UserKey { public_key: row.get(0)?, wrapped_key: row.get(1)? }),
    )
    .optional()
}

/// The identity key of the account with `email`: (user id, public key).
/// The key is None for an account that hasn't set one up yet.
/// With `require_verified`, accounts that haven't proved they own their
/// email are left out, so no one is handed a machine under an address they
/// typed but don't own.
pub fn public_key_by_email(
    conn: &Connection,
    email: &str,
    require_verified: bool,
) -> rusqlite::Result<Option<(i64, Option<Vec<u8>>)>> {
    conn.query_row(
        "SELECT id, public_key FROM users WHERE email = ?1 AND (email_verified_at IS NOT NULL OR NOT ?2)",
        params![email, require_verified],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
}

/// The account, unless it's disabled or gone.
pub fn active_user(conn: &Connection, user_id: i64) -> rusqlite::Result<Option<User>> {
    conn.query_row("SELECT id, email, is_admin FROM users WHERE id = ?1 AND disabled = 0", [user_id], |row| {
        Ok(User { id: row.get(0)?, email: row.get(1)?, is_admin: row.get(2)? })
    })
    .optional()
}

/// Moves a legacy account to derived credentials and gives it its identity
/// key. Only replaces `old_hash` on a legacy account: returns false if it
/// changed or was upgraded since it was read.
pub fn upgrade_account(
    conn: &Connection,
    user_id: i64,
    old_hash: &str,
    credentials: &NewCredentials<'_>,
) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE users SET password_hash = ?1, kdf = 'pbkdf2-sha256', kdf_iterations = ?2,
                          public_key = ?3, wrapped_key = ?4
          WHERE id = ?5 AND password_hash = ?6 AND kdf = 'legacy'",
        params![
            credentials.password_hash,
            credentials.iterations,
            credentials.public_key,
            credentials.wrapped_key,
            user_id,
            old_hash
        ],
    )?;
    Ok(changed > 0)
}

pub fn list_users(conn: &Connection) -> rusqlite::Result<Vec<UserRow>> {
    let mut statement = conn.prepare(
        "SELECT u.id, u.email, u.is_admin, u.disabled, u.created_at,
                EXISTS (SELECT 1 FROM mfa_factors f WHERE f.user_id = u.id), u.email_verified_at IS NOT NULL
           FROM users u ORDER BY u.created_at, u.id",
    )?;
    statement
        .query_map([], |row| {
            Ok(UserRow {
                user: User { id: row.get(0)?, email: row.get(1)?, is_admin: row.get(2)? },
                disabled: row.get(3)?,
                created_at: row.get(4)?,
                mfa: row.get(5)?,
                email_verified: row.get(6)?,
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
    step_up_at: Option<i64>,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, user_agent, ip, created_at, expires_at, step_up_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![token_hash, user_id, origin.user_agent, origin.ip, now, expires_at, step_up_at],
    )?;
    Ok(conn.last_insert_rowid())
}

/// A live session and where its account stands on second factors and
/// email.
pub struct SessionInfo {
    pub id: i64,
    pub user: User,
    pub step_up_at: Option<i64>,
    pub account: AccountFlags,
}

/// What every request needs to know about the account besides who it is.
#[derive(Debug, Clone, Copy)]
pub struct AccountFlags {
    /// At least one second factor registered.
    pub mfa: bool,
    pub email_verified: bool,
    /// The admin requires a second factor on every account.
    pub mfa_required: bool,
}

const ACCOUNT_FLAGS_SQL: &str = "
    EXISTS (SELECT 1 FROM mfa_factors f WHERE f.user_id = u.id),
    u.email_verified_at IS NOT NULL,
    EXISTS (SELECT 1 FROM settings WHERE key = 'require_mfa' AND value = '1')";

fn account_flags_from(row: &rusqlite::Row<'_>, first: usize) -> rusqlite::Result<AccountFlags> {
    Ok(AccountFlags { mfa: row.get(first)?, email_verified: row.get(first + 1)?, mfa_required: row.get(first + 2)? })
}

/// The live session for this token: not expired, user not disabled.
pub fn find_session(conn: &Connection, token_hash: &[u8], now: i64) -> rusqlite::Result<Option<SessionInfo>> {
    conn.query_row(
        &format!(
            "SELECT s.id, u.id, u.email, u.is_admin, s.step_up_at, {ACCOUNT_FLAGS_SQL}
               FROM sessions s JOIN users u ON u.id = s.user_id
              WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND u.disabled = 0"
        ),
        params![token_hash, now],
        |row| {
            Ok(SessionInfo {
                id: row.get(0)?,
                user: User { id: row.get(1)?, email: row.get(2)?, is_admin: row.get(3)? },
                step_up_at: row.get(4)?,
                account: account_flags_from(row, 5)?,
            })
        },
    )
    .optional()
}

pub fn account_flags(conn: &Connection, user_id: i64) -> rusqlite::Result<AccountFlags> {
    conn.query_row(&format!("SELECT {ACCOUNT_FLAGS_SQL} FROM users u WHERE u.id = ?1"), [user_id], |row| {
        account_flags_from(row, 0)
    })
}

/// Records that the session just proved a second factor.
pub fn set_step_up(conn: &Connection, session_id: i64, now: i64) -> rusqlite::Result<()> {
    conn.execute("UPDATE sessions SET step_up_at = ?1 WHERE id = ?2", params![now, session_id])?;
    Ok(())
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
    wrapped_key: &[u8],
    keep_session: i64,
) -> rusqlite::Result<bool> {
    let tx = conn.unchecked_transaction()?;
    // The identity key is re-wrapped under the new password in the same
    // step, so the two never disagree.
    let changed = tx.execute(
        "UPDATE users SET password_hash = ?1, wrapped_key = ?2
          WHERE id = ?3 AND password_hash = ?4 AND kdf <> 'legacy' AND public_key IS NOT NULL",
        params![new_hash, wrapped_key, user_id, old_hash],
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
    credentials: &NewCredentials<'_>,
    email_verified: bool,
    now: i64,
) -> Result<User, SignupError> {
    let tx = conn.unchecked_transaction()?;
    let invite = find_invite(&tx, token_hash, now)?.ok_or(SignupError::InvalidInvite)?;
    let inserted = tx.execute(
        "INSERT INTO users (email, password_hash, is_admin, created_at, kdf, kdf_iterations, public_key, wrapped_key,
                            email_verified_at)
         VALUES (?1, ?2, ?3, ?4, 'pbkdf2-sha256', ?5, ?6, ?7, ?8)",
        params![
            email,
            credentials.password_hash,
            invite.grants_admin,
            now,
            credentials.iterations,
            credentials.public_key,
            credentials.wrapped_key,
            email_verified.then_some(now)
        ],
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
    conn.execute("DELETE FROM email_verifications WHERE expires_at <= ?1", [now])?;
    Ok(())
}

// ---- second factors, email verification, settings -------------------------

pub struct FactorRow {
    pub id: i64,
    pub label: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// A TOTP factor as needed to check a code against it.
pub struct TotpFactor {
    pub id: i64,
    pub secret: Vec<u8>,
}

pub fn list_factors(conn: &Connection, user_id: i64) -> rusqlite::Result<Vec<FactorRow>> {
    let mut statement = conn.prepare(
        "SELECT id, label, created_at, last_used_at FROM mfa_factors WHERE user_id = ?1 ORDER BY created_at, id",
    )?;
    statement
        .query_map([user_id], |row| {
            Ok(FactorRow { id: row.get(0)?, label: row.get(1)?, created_at: row.get(2)?, last_used_at: row.get(3)? })
        })?
        .collect()
}

pub fn totp_factors(conn: &Connection, user_id: i64) -> rusqlite::Result<Vec<TotpFactor>> {
    let mut statement =
        conn.prepare("SELECT id, secret FROM mfa_factors WHERE user_id = ?1 AND kind = 'totp'")?;
    statement
        .query_map([user_id], |row| Ok(TotpFactor { id: row.get(0)?, secret: row.get(1)? }))?
        .collect()
}

/// Moves the factor's counter up to `counter`, only if that's past the last
/// one accepted: false means the code was already used.
pub fn use_totp_counter(conn: &Connection, factor_id: i64, counter: i64, now: i64) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE mfa_factors SET last_counter = ?1, last_used_at = ?2 WHERE id = ?3 AND last_counter < ?1",
        params![counter, now, factor_id],
    )?;
    Ok(changed > 0)
}

/// A TOTP factor to add, its seed already sealed.
pub struct NewTotp<'a> {
    pub label: &'a str,
    pub secret: &'a [u8],
    /// The time step of the code that confirmed it, so that code can't be
    /// used again.
    pub counter: i64,
}

/// Adds a factor and ends every other session the user has, in one step.
/// With `recovery_hashes`, the account also gets that fresh set of codes.
pub fn add_totp_factor(
    conn: &Connection,
    user_id: i64,
    factor: &NewTotp<'_>,
    recovery_hashes: &[Vec<u8>],
    keep_session: i64,
    now: i64,
) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT INTO mfa_factors (user_id, kind, label, secret, last_counter, created_at, last_used_at)
         VALUES (?1, 'totp', ?2, ?3, ?4, ?5, ?5)",
        params![user_id, factor.label, factor.secret, factor.counter, now],
    )?;
    if !recovery_hashes.is_empty() {
        replace_recovery_codes(&tx, user_id, recovery_hashes)?;
    }
    delete_other_sessions(&tx, user_id, keep_session)?;
    tx.commit()
}

/// Removes one of the user's factors and ends their other sessions. The
/// last factor takes the recovery codes with it. Returns false if there's
/// no such factor.
pub fn delete_factor(conn: &Connection, user_id: i64, factor_id: i64, keep_session: i64) -> rusqlite::Result<bool> {
    let tx = conn.unchecked_transaction()?;
    let deleted = tx.execute("DELETE FROM mfa_factors WHERE id = ?1 AND user_id = ?2", params![factor_id, user_id])?;
    if deleted == 0 {
        return Ok(false);
    }
    let remaining: i64 =
        tx.query_row("SELECT COUNT(*) FROM mfa_factors WHERE user_id = ?1", [user_id], |row| row.get(0))?;
    if remaining == 0 {
        tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [user_id])?;
    }
    delete_other_sessions(&tx, user_id, keep_session)?;
    tx.commit()?;
    Ok(true)
}

/// The admin's rescue for a lost phone: every factor and recovery code
/// gone, and every session ended.
pub fn reset_mfa(conn: &Connection, user_id: i64) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM mfa_factors WHERE user_id = ?1", [user_id])?;
    tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [user_id])?;
    tx.execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?;
    tx.commit()
}

pub fn user_email(conn: &Connection, user_id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT email FROM users WHERE id = ?1", [user_id], |row| row.get(0)).optional()
}

pub fn replace_recovery_codes(conn: &Connection, user_id: i64, hashes: &[Vec<u8>]) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [user_id])?;
    let mut insert = conn.prepare("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?1, ?2)")?;
    for hash in hashes {
        insert.execute(params![user_id, hash])?;
    }
    Ok(())
}

/// Spends an unused recovery code: false if it isn't one, or was used.
pub fn use_recovery_code(conn: &Connection, user_id: i64, code_hash: &[u8], now: i64) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE recovery_codes SET used_at = ?1
          WHERE id = (SELECT id FROM recovery_codes
                       WHERE user_id = ?2 AND code_hash = ?3 AND used_at IS NULL LIMIT 1)",
        params![now, user_id, code_hash],
    )?;
    Ok(changed > 0)
}

pub fn unused_recovery_codes(conn: &Connection, user_id: i64) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL", [user_id], |row| {
        row.get(0)
    })
}

/// Replaces any verification link the user had with this one.
pub fn create_email_verification(
    conn: &Connection,
    user_id: i64,
    token_hash: &[u8],
    now: i64,
    expires_at: i64,
) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM email_verifications WHERE user_id = ?1", [user_id])?;
    tx.execute(
        "INSERT INTO email_verifications (token_hash, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![token_hash, user_id, now, expires_at],
    )?;
    tx.commit()
}

/// Marks the link's account verified and spends the link. Returns the
/// account, or None for an unknown or expired link.
pub fn redeem_email_verification(conn: &Connection, token_hash: &[u8], now: i64) -> rusqlite::Result<Option<i64>> {
    let tx = conn.unchecked_transaction()?;
    let user_id: Option<i64> = tx
        .query_row(
            "SELECT user_id FROM email_verifications WHERE token_hash = ?1 AND expires_at > ?2",
            params![token_hash, now],
            |row| row.get(0),
        )
        .optional()?;
    let Some(user_id) = user_id else { return Ok(None) };
    tx.execute(
        "UPDATE users SET email_verified_at = ?1 WHERE id = ?2 AND email_verified_at IS NULL",
        params![now, user_id],
    )?;
    tx.execute("DELETE FROM email_verifications WHERE user_id = ?1", [user_id])?;
    tx.commit()?;
    Ok(Some(user_id))
}

pub fn set_setting(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

// ---- machines -------------------------------------------------------------

/// What a user may do with a machine. Not a ladder: dev can do things view
/// can't (a shell, files) without control's video and input, so access is
/// always asked as a capability, never by comparing roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    View,
    Control,
    Dev,
    Owner,
}

impl Role {
    fn from_sql(text: &str) -> Self {
        match text {
            "owner" => Self::Owner,
            "control" => Self::Control,
            "dev" => Self::Dev,
            _ => Self::View,
        }
    }

    /// The value stored in machine_shares.role (never "owner").
    fn share_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Control | Self::Owner => "control",
            Self::Dev => "dev",
        }
    }

    /// Watches the screen.
    pub fn can_view(self) -> bool {
        matches!(self, Self::View | Self::Control | Self::Owner)
    }

    /// Sends the machine mouse and keyboard input.
    pub fn can_control(self) -> bool {
        matches!(self, Self::Control | Self::Owner)
    }

    /// Sends files to the machine's drop folder and downloads from it.
    pub fn can_files(self) -> bool {
        matches!(self, Self::Control | Self::Dev | Self::Owner)
    }

    /// Opens a shell on the machine.
    pub fn can_shell(self) -> bool {
        matches!(self, Self::Dev | Self::Owner)
    }
}

/// A statement and someone's signature over it (see crate::e2e).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub statement: String,
    pub signature: Vec<u8>,
}

fn signed_from(statement: Option<String>, signature: Option<Vec<u8>>) -> Option<Signed> {
    Some(Signed { statement: statement?, signature: signature? })
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
    /// The machine's key; None for a machine that must be re-enrolled.
    pub public_key: Option<Vec<u8>>,
    pub owner_public_key: Option<Vec<u8>>,
    /// The owner's signature over the machine's key, once they've checked it.
    pub endorsement: Option<Vec<u8>>,
    /// Owner only, until endorsed: which enrollment code the machine used
    /// and the key binding it answered with, for the browser to check.
    pub enroll_code_hash: Option<Vec<u8>>,
    pub enroll_binding: Option<Vec<u8>>,
    /// Shares only: what the owner signed for this user.
    pub grant: Option<Signed>,
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
    /// The recipient's identity key, if they have one yet.
    pub public_key: Option<Vec<u8>>,
    pub grant: Option<Signed>,
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
    owner_binding: &[u8],
    now: i64,
    expires_at: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO enrollment_codes (code_hash, owner_id, owner_binding, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![code_hash, owner_id, owner_binding, now, expires_at],
    )?;
    Ok(())
}

/// Who a usable enrollment code enrolls a machine for, and what the machine
/// needs to pin them.
#[derive(Debug, Clone)]
pub struct EnrollmentOwner {
    pub owner_id: i64,
    pub owner_public_key: Vec<u8>,
    pub owner_binding: Vec<u8>,
}

/// The owner of a usable enrollment code: unknown, used, expired codes,
/// disabled owners and codes made before keys existed give None. Doesn't
/// consume it.
pub fn enrollment_code_owner(
    conn: &Connection,
    code_hash: &[u8],
    now: i64,
) -> rusqlite::Result<Option<EnrollmentOwner>> {
    conn.query_row(
        "SELECT c.owner_id, u.public_key, c.owner_binding FROM enrollment_codes c JOIN users u ON u.id = c.owner_id
          WHERE c.code_hash = ?1 AND c.expires_at > ?2 AND u.disabled = 0
            AND u.public_key IS NOT NULL AND c.owner_binding IS NOT NULL",
        params![code_hash, now],
        |row| Ok(EnrollmentOwner { owner_id: row.get(0)?, owner_public_key: row.get(1)?, owner_binding: row.get(2)? }),
    )
    .optional()
}

pub struct NewMachine<'a> {
    pub code_hash: &'a [u8],
    pub public_id: &'a str,
    pub hostname: &'a str,
    pub public_key: &'a [u8],
    pub key_storage: &'a str,
    /// The machine's key, MACed with the enrollment code.
    pub binding: &'a [u8],
}

/// Consumes an enrollment code and registers the machine under the code's
/// owner, in one transaction, so a code can only ever enroll one machine.
/// None if the code is no longer usable.
pub fn enroll_machine(
    conn: &Connection,
    machine: &NewMachine<'_>,
    now: i64,
) -> rusqlite::Result<Option<(MachineAuth, EnrollmentOwner)>> {
    let tx = conn.unchecked_transaction()?;
    let Some(owner) = enrollment_code_owner(&tx, machine.code_hash, now)? else { return Ok(None) };
    tx.execute("DELETE FROM enrollment_codes WHERE code_hash = ?1", [machine.code_hash])?;
    let fingerprint = crate::auth::token_hash_bytes(machine.public_key);
    tx.execute(
        "INSERT INTO machines
             (public_id, owner_id, name, hostname, key_fingerprint, public_key, key_storage, created_at, last_seen_at,
              enroll_code_hash, enroll_binding)
         VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?9)",
        params![
            machine.public_id,
            owner.owner_id,
            machine.hostname,
            fingerprint,
            machine.public_key,
            machine.key_storage,
            now,
            machine.code_hash,
            machine.binding
        ],
    )?;
    tx.commit()?;
    Ok(Some((MachineAuth { public_id: machine.public_id.to_owned(), owner_id: owner.owner_id }, owner)))
}

/// The keys an endorsement of an owned machine is checked against:
/// (machine key, owner key). None if `owner_id` doesn't own it or either
/// key is missing.
pub fn endorsement_keys(
    conn: &Connection,
    public_id: &str,
    owner_id: i64,
) -> rusqlite::Result<Option<(Vec<u8>, Vec<u8>)>> {
    conn.query_row(
        "SELECT m.public_key, u.public_key FROM machines m JOIN users u ON u.id = m.owner_id
          WHERE m.public_id = ?1 AND m.owner_id = ?2 AND m.public_key IS NOT NULL AND u.public_key IS NOT NULL",
        params![public_id, owner_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
}

/// Stores the owner's endorsement of the machine's key. The enrollment
/// details it was checked with are no longer needed.
pub fn set_endorsement(conn: &Connection, public_id: &str, owner_id: i64, signature: &[u8]) -> rusqlite::Result<bool> {
    let changed = conn.execute(
        "UPDATE machines SET endorsement = ?1, enroll_code_hash = NULL, enroll_binding = NULL
          WHERE public_id = ?2 AND owner_id = ?3",
        params![signature, public_id, owner_id],
    )?;
    Ok(changed > 0)
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
        public_key: row.get(10)?,
        owner_public_key: row.get(11)?,
        endorsement: row.get(12)?,
        enroll_code_hash: row.get(13)?,
        enroll_binding: row.get(14)?,
        grant: signed_from(row.get(15)?, row.get(16)?),
    })
}

/// Every machine the user owns or has been shared, with their role on it.
/// Shares of a disabled owner's machines are left out, and so are shares
/// outside their time window at `now`.
pub fn accessible_machines(conn: &Connection, user_id: i64, now: i64) -> rusqlite::Result<Vec<MachineRow>> {
    let mut statement = conn.prepare(
        "SELECT m.public_id, m.owner_id, o.email, m.name, m.hostname, m.last_seen_at, m.key_storage, 'owner',
                NULL, 0, m.public_key, o.public_key, m.endorsement, m.enroll_code_hash, m.enroll_binding, NULL, NULL
           FROM machines m JOIN users o ON o.id = m.owner_id
          WHERE m.owner_id = ?1
         UNION ALL
         SELECT m.public_id, m.owner_id, o.email, m.name, m.hostname, m.last_seen_at, m.key_storage, s.role,
                s.expires_at, s.single_view, m.public_key, o.public_key, m.endorsement, NULL, NULL,
                s.grant_statement, s.grant_signature
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
        "SELECT u.id, u.email, s.role, s.starts_at, s.expires_at, s.single_view, u.public_key,
                s.grant_statement, s.grant_signature
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
                public_key: row.get(6)?,
                grant: signed_from(row.get(7)?, row.get(8)?),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Some(shares))
}

pub enum ShareError {
    NotOwner,
    SelfShare,
    Db(rusqlite::Error),
}

impl From<rusqlite::Error> for ShareError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(error)
    }
}

/// Shares an owned machine with `user_id`, or replaces the terms of an
/// existing share, along with the grant the owner signed for it.
pub fn upsert_share(
    conn: &Connection,
    public_id: &str,
    owner_id: i64,
    user_id: i64,
    terms: ShareTerms,
    grant: &Signed,
    now: i64,
) -> Result<(), ShareError> {
    let machine_id = owned_machine_id(conn, public_id, owner_id)?.ok_or(ShareError::NotOwner)?;
    if user_id == owner_id {
        return Err(ShareError::SelfShare);
    }
    conn.execute(
        "INSERT INTO machine_shares
             (machine_id, user_id, role, created_at, starts_at, expires_at, single_view, grant_statement, grant_signature)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT (machine_id, user_id) DO UPDATE SET
             role = excluded.role, starts_at = excluded.starts_at,
             expires_at = excluded.expires_at, single_view = excluded.single_view,
             grant_statement = excluded.grant_statement, grant_signature = excluded.grant_signature",
        params![
            machine_id,
            user_id,
            terms.role.share_str(),
            now,
            terms.starts_at,
            terms.expires_at,
            terms.single_view,
            grant.statement,
            grant.signature
        ],
    )?;
    Ok(())
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

/// Deletes a share and keeps the owner's signed revocation of it, in one
/// transaction. Returns false if `owner_id` doesn't own the machine or it
/// wasn't shared with `user_id`.
pub fn delete_share(
    conn: &Connection,
    public_id: &str,
    owner_id: i64,
    user_id: i64,
    revocation: Option<&Signed>,
    now: i64,
) -> rusqlite::Result<bool> {
    let tx = conn.unchecked_transaction()?;
    let Some(machine_id) = owned_machine_id(&tx, public_id, owner_id)? else { return Ok(false) };
    let deleted =
        tx.execute("DELETE FROM machine_shares WHERE machine_id = ?1 AND user_id = ?2", params![machine_id, user_id])?;
    if deleted == 0 {
        return Ok(false);
    }
    if let Some(revocation) = revocation {
        tx.execute(
            "INSERT INTO machine_revocations (machine_id, statement, signature, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![machine_id, revocation.statement, revocation.signature, now],
        )?;
    }
    tx.commit()?;
    Ok(true)
}

/// Every revocation the owner signed for the machine, oldest first.
pub fn revocations(conn: &Connection, public_id: &str) -> rusqlite::Result<Vec<Signed>> {
    conn.prepare(
        "SELECT r.statement, r.signature FROM machine_revocations r JOIN machines m ON m.id = r.machine_id
          WHERE m.public_id = ?1 ORDER BY r.id",
    )?
    .query_map([public_id], |row| Ok(Signed { statement: row.get(0)?, signature: row.get(1)? }))?
    .collect()
}

/// `user_id`'s share of an owned machine, if there is one.
pub fn share_for(conn: &Connection, public_id: &str, owner_id: i64, user_id: i64) -> rusqlite::Result<Option<ShareRow>> {
    Ok(list_shares(conn, public_id, owner_id)?.and_then(|shares| shares.into_iter().find(|s| s.user_id == user_id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rebuild that lets shares be dev keeps every share already there.
    #[test]
    fn dev_migration_keeps_shares() {
        let conn = Connection::open_in_memory().unwrap();
        // Only the shares table is under test: no users or machines to point at.
        conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        let before_dev = MIGRATIONS.len() - 1;
        for migration in &MIGRATIONS[..before_dev] {
            conn.execute_batch(migration).unwrap();
        }
        conn.pragma_update(None, "user_version", i64::try_from(before_dev).unwrap()).unwrap();
        conn.execute(
            "INSERT INTO machine_shares (machine_id, user_id, role, created_at, expires_at, single_view, grant_statement)
             VALUES (1, 2, 'control', 10, 20, 1, 'hawk-grant-v1')",
            [],
        )
        .unwrap();

        migrate(&conn).unwrap();
        let kept: (String, i64, i64, String) = conn
            .query_row(
                "SELECT role, expires_at, single_view, grant_statement FROM machine_shares WHERE user_id = 2",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(kept, ("control".to_owned(), 20, 1, "hawk-grant-v1".to_owned()));
        conn.execute("INSERT INTO machine_shares (machine_id, user_id, role, created_at) VALUES (1, 3, 'dev', 0)", [])
            .unwrap();
        assert!(
            conn.execute("INSERT INTO machine_shares (machine_id, user_id, role, created_at) VALUES (1, 4, 'root', 0)", [])
                .is_err()
        );
        assert_eq!(Role::from_sql("dev"), Role::Dev);
    }

    /// Accounts from before email verification stay verified, and a code
    /// can't be accepted twice.
    #[test]
    fn mfa_migration_and_replay() {
        let conn = Connection::open_in_memory().unwrap();
        let before = MIGRATIONS.len() - 1;
        for migration in &MIGRATIONS[..before] {
            conn.execute_batch(migration).unwrap();
        }
        conn.pragma_update(None, "user_version", i64::try_from(before).unwrap()).unwrap();
        conn.execute("INSERT INTO users (email, password_hash, created_at) VALUES ('a@example.com', 'x', 5)", [])
            .unwrap();

        migrate(&conn).unwrap();
        let flags = account_flags(&conn, 1).unwrap();
        assert!(flags.email_verified && !flags.mfa && !flags.mfa_required);

        let factor = NewTotp { label: "phone", secret: b"sealed", counter: 10 };
        add_totp_factor(&conn, 1, &factor, &[b"hash".to_vec()], 0, 100).unwrap();
        assert!(account_flags(&conn, 1).unwrap().mfa);
        let id = totp_factors(&conn, 1).unwrap()[0].id;
        assert!(!use_totp_counter(&conn, id, 10, 101).unwrap());
        assert!(use_totp_counter(&conn, id, 11, 101).unwrap());
        assert!(use_recovery_code(&conn, 1, b"hash", 102).unwrap());
        assert!(!use_recovery_code(&conn, 1, b"hash", 103).unwrap());

        set_setting(&conn, "require_mfa", "1").unwrap();
        assert!(account_flags(&conn, 1).unwrap().mfa_required);
        assert!(delete_factor(&conn, 1, id, 0).unwrap());
        assert_eq!(unused_recovery_codes(&conn, 1).unwrap(), 0);
    }
}
