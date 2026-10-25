//! Passkeys (WebAuthn) as a second factor beside authenticator apps:
//! security keys, platform authenticators (Windows Hello, Touch ID,
//! Android) and synced passkeys. Wherever a code is accepted (the second
//! step of a login, step-up), a passkey's answer is too. Not a way to sign
//! in without the password.
//!
//! A credential is bound to the relying party ID (a domain), and the
//! browser signs the page's origin into every answer, so a look-alike site
//! gets nothing it can replay here: what a TOTP code can never offer. Both
//! come from the relay's configuration ([`PasskeyConfig`]), since the
//! dashboard may be served by the relay or from somewhere else under the
//! same domain.
//!
//! Ceremonies are kept here, on the relay: a challenge is single-use, lives
//! two minutes, and belongs to one account and one session (adding a
//! passkey, stepping up) or one login ticket. So are the checks: a narrow
//! relying party, as much of WebAuthn as a factor on top of a password
//! needs. No attestation (the browser is asked for none, and only "none"
//! or an authenticator's self-attestation is taken), user verification
//! preferred (and required from then on of a passkey that did it once),
//! ES256, EdDSA and RS256 keys, signatures checked with ring.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{ConnectInfo, State};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tracing::{debug, warn};
use url::Url;

use crate::AppState;
use crate::api;
use crate::audit::{Client, Details, Event, Kind};
use crate::auth::{self, AllowedOrigins, SessionUser};
use crate::db::{self, FactorKind, NewPasskey, StoredPasskey};
use crate::error::ApiError;
use crate::mfa::{self, AddedFactor, MAX_FACTORS, MAX_LABEL_LEN, Proof};
use crate::totp;

/// How long a challenge can be answered, and what the browser is told to
/// give up after.
const CEREMONY_TTL: Duration = Duration::from_secs(2 * 60);

/// The COSE algorithms a passkey may sign with, in the order the browser is
/// asked for them.
const ES256: i64 = -7;
const EDDSA: i64 = -8;
const RS256: i64 = -257;
const ALGORITHMS: [i64; 3] = [ES256, EDDSA, RS256];

/// The longest credential id there can be (WebAuthn's own bound).
const MAX_CREDENTIAL_ID: usize = 1023;

/// The transports remembered from a registration, to hand back to the
/// browser so it knows where to look; anything else it says is dropped.
const TRANSPORTS: [&str; 6] = ["usb", "nfc", "ble", "smart-card", "hybrid", "internal"];

/// Where passkeys are valid: the relying party ID, and the origins the
/// dashboard may ask for them from. From `HAWK_WEBAUTHN_RP_ID` and
/// `HAWK_WEBAUTHN_ORIGINS`; by default the host of the relay's own address
/// (`PUBLIC_URL`), with that origin and every one in `HAWK_ALLOWED_ORIGINS`
/// that falls under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyConfig {
    pub rp_id: String,
    pub origins: Vec<Url>,
}

impl PasskeyConfig {
    /// None: passkeys are off, set so (`HAWK_WEBAUTHN_RP_ID=off`) or because
    /// the relay's address is an IP, which can't be a relying party ID.
    pub fn parse(
        base_url: &str,
        allowed_origins: &AllowedOrigins,
        rp_id: Option<&str>,
        origins: Option<&str>,
    ) -> Result<Option<Self>, String> {
        let base = Url::parse(base_url).map_err(|error| format!("the relay's address {base_url}: {error}"))?;
        let rp_id = match rp_id.map(str::trim).filter(|rp_id| !rp_id.is_empty()) {
            Some(off) if off.eq_ignore_ascii_case("off") => return Ok(None),
            Some(rp_id) => rp_id_from(rp_id).ok_or_else(|| {
                format!(
                    "HAWK_WEBAUTHN_RP_ID: \"{rp_id}\" isn't a domain name like example.com (no scheme, port, \
                     path or IP; a single label only for localhost)"
                )
            })?,
            // A relay reached by a name that can't be an RP ID (an IP, an
            // intranet name with no dot) just goes without passkeys.
            None => match base.domain().and_then(rp_id_from) {
                Some(domain) => domain,
                None => return Ok(None),
            },
        };

        let origins = match origins.map(str::trim).filter(|origins| !origins.is_empty()) {
            Some(list) => {
                let mut parsed = Vec::new();
                for origin in list.split(',').map(str::trim).filter(|origin| !origin.is_empty()) {
                    let url = parse_origin(origin)?;
                    if !within(&url, &rp_id) {
                        return Err(format!(
                            "HAWK_WEBAUTHN_ORIGINS: {origin} isn't on {rp_id} or a subdomain of it, so its pages \
                             can't use passkeys for that relying party ID"
                        ));
                    }
                    parsed.push(url);
                }
                parsed
            }
            None => {
                let own = base.origin().ascii_serialization();
                std::iter::once(&own)
                    .chain(allowed_origins.list())
                    .filter_map(|origin| parse_origin(origin).ok())
                    .filter(|origin| within(origin, &rp_id))
                    .collect()
            }
        };
        if origins.is_empty() {
            return Err(format!(
                "passkeys: no origin is on {rp_id}: set HAWK_WEBAUTHN_ORIGINS to where the dashboard is served"
            ));
        }
        Ok(Some(Self { rp_id, origins }))
    }
}

/// `text` as a relying party ID, lowercase ASCII (an internationalized name
/// in its xn-- form): a host name of dot-separated labels of letters,
/// digits and inner hyphens, with at least one dot unless it's localhost.
/// None for anything else, IP addresses included.
fn rp_id_from(text: &str) -> Option<String> {
    if text.is_empty() || text.contains(|c: char| c.is_whitespace() || "/:@?#[]*".contains(c)) {
        return None;
    }
    if text.parse::<IpAddr>().is_ok() {
        return None;
    }
    let url::Host::Domain(ascii) = url::Host::parse(text).ok()? else { return None };
    let ascii = ascii.to_ascii_lowercase();
    let label_valid = |label: &str| {
        (1..=63).contains(&label.len())
            && label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    let valid = ascii.len() <= 253
        && ascii.split('.').all(label_valid)
        && (ascii.contains('.') || ascii == "localhost")
        // The last label of a real domain isn't all digits.
        && !ascii.rsplit('.').next().is_some_and(|tld| tld.bytes().all(|byte| byte.is_ascii_digit()));
    valid.then_some(ascii)
}

/// An origin as the browser sends it: https, or http on localhost only
/// (where browsers allow WebAuthn too).
fn parse_origin(origin: &str) -> Result<Url, String> {
    let invalid = || format!("passkeys: \"{origin}\" isn't an origin like https://example.com");
    let url = Url::parse(origin).map_err(|_| invalid())?;
    let host = url.domain().ok_or_else(invalid)?;
    let local = host == "localhost" || host.ends_with(".localhost");
    let secure = url.scheme() == "https" || (url.scheme() == "http" && local);
    if !secure || url.path() != "/" || url.query().is_some() {
        return Err(format!("passkeys: {origin} has to be https (or http on localhost), with no path"));
    }
    Ok(url)
}

/// Whether pages on `origin` may use passkeys for `rp_id`: its host is the
/// RP ID or a subdomain of it.
fn within(origin: &Url, rp_id: &str) -> bool {
    origin
        .domain()
        .is_some_and(|host| host == rp_id || host.strip_suffix(rp_id).is_some_and(|rest| rest.ends_with('.')))
}

/// The configuration as the checks use it.
struct RelyingParty {
    id: String,
    /// SHA-256 of the ID, as authenticators put it in what they sign.
    id_hash: [u8; 32],
    /// As browsers write them into clientDataJSON: scheme://host[:port].
    origins: Vec<String>,
}

impl RelyingParty {
    fn new(config: &PasskeyConfig) -> Self {
        Self {
            id: config.rp_id.clone(),
            id_hash: sha256(config.rp_id.as_bytes()),
            origins: config.origins.iter().map(|origin| origin.origin().ascii_serialization()).collect(),
        }
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hash = [0; 32];
    hash.copy_from_slice(digest::digest(&digest::SHA256, data).as_ref());
    hash
}

/// Equal, in time that depends on the lengths only.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |diff, (x, y)| diff | (x ^ y)) == 0
}

/// Which ceremony a challenge belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Ceremony {
    /// Adding a passkey, from this session.
    Register(i64),
    /// Stepping this session up.
    StepUp(i64),
    /// The second step of a login, for the ticket with this hash.
    Login(Vec<u8>),
}

enum Started {
    Register { challenge: [u8; 32], password_confirmed: bool },
    /// `handle`: the account's user handle, which an answer may name.
    Authenticate { challenge: [u8; 32], handle: [u8; 16] },
}

struct Pending {
    user_id: i64,
    started: Instant,
    state: Started,
}

/// The relay's WebAuthn setup, and the ceremonies waiting for an answer.
pub struct Passkeys {
    rp: Option<RelyingParty>,
    pending: Mutex<HashMap<Ceremony, Pending>>,
}

impl Passkeys {
    pub fn new(config: Option<&PasskeyConfig>) -> Self {
        Self { rp: config.map(RelyingParty::new), pending: Mutex::new(HashMap::new()) }
    }

    /// The relying party ID, or None when passkeys are off.
    pub fn rp_id(&self) -> Option<&str> {
        self.rp.as_ref().map(|rp| rp.id.as_str())
    }

    fn relying_party(&self) -> Result<&RelyingParty, ApiError> {
        self.rp.as_ref().ok_or_else(|| ApiError::bad_request("passkeys aren't set up on this server"))
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<Ceremony, Pending>> {
        self.pending.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Replaces whatever the ceremony was waiting on: one challenge at a time.
    fn start(&self, ceremony: Ceremony, user_id: i64, state: Started) {
        let mut pending = self.map();
        pending.retain(|_, pending| pending.started.elapsed() < CEREMONY_TTL);
        pending.insert(ceremony, Pending { user_id, started: Instant::now(), state });
    }

    /// Takes the ceremony's challenge, whatever happens next: it's never
    /// answered twice. None when there's none for this account, or it's too
    /// old.
    fn take(&self, ceremony: &Ceremony, user_id: i64) -> Option<Started> {
        let pending = self.map().remove(ceremony)?;
        (pending.user_id == user_id && pending.started.elapsed() < CEREMONY_TTL).then_some(pending.state)
    }

    pub fn prune(&self) {
        self.map().retain(|_, pending| pending.started.elapsed() < CEREMONY_TTL);
    }

    /// Ages every waiting ceremony past its life.
    #[cfg(test)]
    fn expire_all(&self) {
        for pending in self.map().values_mut() {
            pending.started = Instant::now().checked_sub(CEREMONY_TTL).unwrap_or(pending.started);
        }
    }
}

// ---- the JSON the browser and the relay trade -----------------------------

/// Bytes as WebAuthn's JSON forms carry them: base64url, unpadded. Standard
/// base64, and padding, are taken too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base64Url(Vec<u8>);

impl Base64Url {
    fn decode(text: &str) -> Option<Vec<u8>> {
        let url_safe: String =
            text.trim_end_matches('=').chars().map(|c| match c { '+' => '-', '/' => '_', c => c }).collect();
        URL_SAFE_NO_PAD.decode(url_safe).ok()
    }
}

impl Serialize for Base64Url {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Url {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::decode(&text).map(Self).ok_or_else(|| D::Error::custom("not base64url"))
    }
}

/// What `navigator.credentials.create` is asked for (webauthn.ts turns it
/// into the browser's form).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreationOptions {
    public_key: CreationPublicKey,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreationPublicKey {
    rp: RpEntity,
    user: UserEntity,
    challenge: Base64Url,
    pub_key_cred_params: Vec<CredentialParameter>,
    timeout: u64,
    /// The account's passkeys: not the same authenticator twice.
    exclude_credentials: Vec<Descriptor>,
    authenticator_selection: AuthenticatorSelection,
    attestation: &'static str,
    extensions: CreationExtensions,
}

#[derive(Serialize)]
struct RpEntity {
    name: &'static str,
    id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserEntity {
    id: Base64Url,
    name: String,
    display_name: String,
}

#[derive(Serialize)]
struct CredentialParameter {
    #[serde(rename = "type")]
    kind: &'static str,
    alg: i64,
}

#[derive(Serialize)]
struct Descriptor {
    #[serde(rename = "type")]
    kind: &'static str,
    id: Base64Url,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    transports: Vec<String>,
}

impl Descriptor {
    fn of(stored: &StoredPasskey) -> Self {
        let transports = stored
            .transports
            .as_deref()
            .and_then(|transports| serde_json::from_str::<Vec<String>>(transports).ok())
            .map(known_transports)
            .unwrap_or_default();
        Self { kind: "public-key", id: Base64Url(stored.credential_id.clone()), transports }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorSelection {
    resident_key: &'static str,
    require_resident_key: bool,
    user_verification: &'static str,
}

/// credProtect: an authenticator that can verify its user (a PIN,
/// biometrics) won't use the passkey without; not enforced, as many
/// authenticators don't know the extension.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreationExtensions {
    cred_props: bool,
    credential_protection_policy: &'static str,
    enforce_credential_protection_policy: bool,
}

/// What `navigator.credentials.get` is asked for.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestOptions {
    public_key: RequestPublicKey,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestPublicKey {
    challenge: Base64Url,
    timeout: u64,
    rp_id: String,
    allow_credentials: Vec<Descriptor>,
    user_verification: &'static str,
}

/// What `navigator.credentials.create` made, as JSON (its toJSON, or
/// webauthn.ts's own): binary fields in base64url. Fields not read here
/// are ignored.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewCredential {
    id: String,
    raw_id: Base64Url,
    #[serde(rename = "type")]
    kind: String,
    response: AttestationResponse,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: Base64Url,
    attestation_object: Base64Url,
    #[serde(default)]
    transports: Vec<String>,
}

/// A passkey's answer to a challenge: what `navigator.credentials.get`
/// gave, as JSON.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Assertion {
    id: String,
    raw_id: Base64Url,
    #[serde(rename = "type")]
    kind: String,
    response: AssertionResponse,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: Base64Url,
    authenticator_data: Base64Url,
    signature: Base64Url,
    #[serde(default)]
    user_handle: Option<Base64Url>,
}

/// What the browser signs into every answer.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(default)]
    cross_origin: bool,
}

fn known_transports(transports: Vec<String>) -> Vec<String> {
    let mut known: Vec<String> = Vec::new();
    for transport in transports {
        if TRANSPORTS.contains(&transport.as_str()) && !known.contains(&transport) {
            known.push(transport);
        }
    }
    known
}

// ---- the checks -----------------------------------------------------------

/// Why an answer wasn't taken; logged, never told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    Malformed(&'static str),
    /// clientDataJSON's type isn't this ceremony's.
    Type,
    Challenge,
    Origin,
    /// Made in a frame of another site.
    CrossOrigin,
    /// Bound to another relying party.
    RpId,
    /// The user didn't touch the authenticator.
    NotPresent,
    /// The user wasn't verified, and was when the passkey was made.
    NotVerified,
    /// Backed up without being able to be, or changed its mind about it.
    Backup,
    Attestation,
    Algorithm,
    CredentialId,
    UserHandle,
    Signature,
    /// The sign counter didn't go up: a copy of the key may be in use.
    Counter,
}

impl From<cbor::Malformed> for Refused {
    fn from(_: cbor::Malformed) -> Self {
        Self::Malformed("CBOR")
    }
}

/// Authenticator data flags.
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;
const ED: u8 = 0x80;

/// The authenticator's part of what it signs.
struct AuthData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    counter: u32,
    /// The credential made, at registration.
    attested: Option<Attested<'a>>,
}

struct Attested<'a> {
    credential_id: &'a [u8],
    /// Its COSE_Key, as encoded.
    public_key: &'a [u8],
}

impl<'a> AuthData<'a> {
    /// The whole of it: nothing may follow the extensions, or the public
    /// key when there are none.
    fn parse(bytes: &'a [u8]) -> Result<Self, Refused> {
        let short = Refused::Malformed("authenticator data too short");
        let (rp_id_hash, rest) = bytes.split_at_checked(32).ok_or(short)?;
        let (head, mut rest) = rest.split_at_checked(5).ok_or(short)?;
        let flags = head[0];
        let counter = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
        let attested = if flags & AT != 0 {
            // The AAGUID, then the id's length and the id.
            let (head, after) = rest.split_at_checked(18).ok_or(short)?;
            let length = usize::from(u16::from_be_bytes([head[16], head[17]]));
            if length > MAX_CREDENTIAL_ID {
                return Err(Refused::CredentialId);
            }
            let (credential_id, after) = after.split_at_checked(length).ok_or(short)?;
            let (_, after_key) = cbor::read(after)?;
            let public_key = &after[..after.len() - after_key.len()];
            rest = after_key;
            Some(Attested { credential_id, public_key })
        } else {
            None
        };
        if flags & ED != 0 {
            let (extensions, after) = cbor::read(rest)?;
            if !matches!(extensions, cbor::Value::Map(_)) {
                return Err(Refused::Malformed("extensions"));
            }
            rest = after;
        }
        if !rest.is_empty() {
            return Err(Refused::Malformed("trailing bytes after the authenticator data"));
        }
        Ok(Self { rp_id_hash, flags, counter, attested })
    }

    /// What every answer has to show: this relying party, the user there.
    fn check(&self, rp: &RelyingParty) -> Result<(), Refused> {
        if !same(self.rp_id_hash, &rp.id_hash) {
            return Err(Refused::RpId);
        }
        if self.flags & UP == 0 {
            return Err(Refused::NotPresent);
        }
        if self.flags & BS != 0 && self.flags & BE == 0 {
            return Err(Refused::Backup);
        }
        Ok(())
    }
}

/// Checks what the browser says it asked: this ceremony, this challenge,
/// one of the dashboard's origins, not from inside another site's frame.
fn check_client_data(rp: &RelyingParty, kind: &str, challenge: &[u8; 32], json: &[u8]) -> Result<(), Refused> {
    let data: ClientData = serde_json::from_slice(json).map_err(|_| Refused::Malformed("clientDataJSON"))?;
    if data.kind != kind {
        return Err(Refused::Type);
    }
    let answered = Base64Url::decode(&data.challenge).ok_or(Refused::Challenge)?;
    if !same(&answered, challenge) {
        return Err(Refused::Challenge);
    }
    if !rp.origins.contains(&data.origin) {
        return Err(Refused::Origin);
    }
    if data.cross_origin {
        return Err(Refused::CrossOrigin);
    }
    Ok(())
}

/// What a signature covers: the authenticator data and the client data's
/// hash.
fn signed(auth_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
    [auth_data, &sha256(client_data_json)].concat()
}

/// A passkey's public key, from its COSE_Key, as ring checks with it.
#[derive(Debug)]
enum PublicKey {
    /// The uncompressed P-256 point.
    Es256(Vec<u8>),
    Ed25519(Vec<u8>),
    Rs256 { n: Vec<u8>, e: Vec<u8> },
}

impl PublicKey {
    fn from_cose(bytes: &[u8]) -> Result<Self, Refused> {
        let cbor::Value::Map(map) = cbor::read_all(bytes)? else {
            return Err(Refused::Malformed("public key"));
        };
        let int = |label| cbor::field(&map, &cbor::Value::Int(label)).and_then(cbor::Value::int);
        let bytes = |label| cbor::field(&map, &cbor::Value::Int(label)).and_then(cbor::Value::bytes);
        let malformed = Refused::Malformed("public key");
        // kty, alg; then crv and the key, labelled per kty.
        match (int(1), int(3)) {
            (Some(2), Some(ES256)) => {
                let (x, y) = (bytes(-2).ok_or(malformed)?, bytes(-3).ok_or(malformed)?);
                if int(-1) != Some(1) || x.len() != 32 || y.len() != 32 {
                    return Err(malformed);
                }
                Ok(Self::Es256([&[4], x, y].concat()))
            }
            (Some(1), Some(EDDSA)) => {
                let x = bytes(-2).ok_or(malformed)?;
                if int(-1) != Some(6) || x.len() != 32 {
                    return Err(malformed);
                }
                Ok(Self::Ed25519(x.to_vec()))
            }
            (Some(3), Some(RS256)) => {
                let strip = |bytes: &[u8]| bytes[bytes.iter().take_while(|&&byte| byte == 0).count()..].to_vec();
                let (n, e) = (strip(bytes(-1).ok_or(malformed)?), strip(bytes(-2).ok_or(malformed)?));
                // 2048 to 8192 bits, as ring takes them.
                if !(256..=1024).contains(&n.len()) || e.is_empty() || e.len() > 4 {
                    return Err(malformed);
                }
                Ok(Self::Rs256 { n, e })
            }
            (Some(_), Some(_)) => Err(Refused::Algorithm),
            _ => Err(malformed),
        }
    }

    fn alg(&self) -> i64 {
        match self {
            Self::Es256(_) => ES256,
            Self::Ed25519(_) => EDDSA,
            Self::Rs256 { .. } => RS256,
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Refused> {
        let checked = match self {
            Self::Es256(point) => {
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point).verify(message, signature)
            }
            Self::Ed25519(key) => UnparsedPublicKey::new(&signature::ED25519, key).verify(message, signature),
            Self::Rs256 { n, e } => {
                RsaPublicKeyComponents { n, e }.verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
            }
        };
        checked.map_err(|_| Refused::Signature)
    }
}

/// A passkey as kept in `mfa_factors.credential`, JSON: its public key and
/// what the authenticator said of it when it was made. The sign counter
/// and the transports have columns of their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredKey {
    /// The COSE algorithm: -7 ES256, -8 EdDSA, -257 RS256.
    alg: i64,
    /// The COSE_Key, as the authenticator encoded it.
    public_key: Base64Url,
    /// The user was verified (a PIN, biometrics) when it was made, so has
    /// to be every time.
    user_verified: bool,
    /// It may be synced (a password manager, a platform's passkeys)
    /// rather than bound to one device. Never changes.
    backup_eligible: bool,
}

/// A passkey made for a registration challenge, checked.
#[derive(Debug)]
struct Made {
    credential_id: Vec<u8>,
    key: StoredKey,
    counter: u32,
    transports: Vec<String>,
}

/// Checks a new passkey against the registration's challenge.
fn verify_registration(rp: &RelyingParty, challenge: &[u8; 32], made: &NewCredential) -> Result<Made, Refused> {
    if made.kind != "public-key" {
        return Err(Refused::Malformed("type"));
    }
    if Base64Url::decode(&made.id).as_deref() != Some(made.raw_id.0.as_slice()) {
        return Err(Refused::Malformed("id"));
    }
    let client_data_json = &made.response.client_data_json.0;
    check_client_data(rp, "webauthn.create", challenge, client_data_json)?;

    let cbor::Value::Map(attestation) = cbor::read_all(&made.response.attestation_object.0)? else {
        return Err(Refused::Malformed("attestation object"));
    };
    let field = |name| cbor::field(&attestation, &cbor::Value::Text(name));
    let malformed = Refused::Malformed("attestation object");
    let format = field("fmt").and_then(cbor::Value::text).ok_or(malformed)?;
    let Some(cbor::Value::Map(statement)) = field("attStmt") else { return Err(malformed) };
    let auth_data_bytes = field("authData").and_then(cbor::Value::bytes).ok_or(malformed)?;

    let auth_data = AuthData::parse(auth_data_bytes)?;
    auth_data.check(rp)?;
    let attested = auth_data.attested.as_ref().ok_or(Refused::Malformed("no credential made"))?;
    if attested.credential_id.is_empty() || attested.credential_id != made.raw_id.0.as_slice() {
        return Err(Refused::CredentialId);
    }
    let key = PublicKey::from_cose(attested.public_key)?;

    // The browser was asked for no attestation: it sends "none", or an
    // authenticator's self-attestation (signed with the new key itself,
    // which says nothing about who made it, so it's passed on as is).
    match format {
        "none" if statement.is_empty() => {}
        "packed" => {
            let statement_field = |name| cbor::field(statement, &cbor::Value::Text(name));
            let alg = statement_field("alg").and_then(cbor::Value::int);
            let sig = statement_field("sig").and_then(cbor::Value::bytes);
            let (Some(alg), Some(sig)) = (alg, sig) else { return Err(Refused::Attestation) };
            if statement.len() != 2 || alg != key.alg() {
                return Err(Refused::Attestation);
            }
            key.verify(&signed(auth_data_bytes, client_data_json), sig).map_err(|_| Refused::Attestation)?;
        }
        _ => return Err(Refused::Attestation),
    }

    Ok(Made {
        credential_id: attested.credential_id.to_vec(),
        key: StoredKey {
            alg: key.alg(),
            public_key: Base64Url(attested.public_key.to_vec()),
            user_verified: auth_data.flags & UV != 0,
            backup_eligible: auth_data.flags & BE != 0,
        },
        counter: auth_data.counter,
        transports: known_transports(made.response.transports.clone()),
    })
}

/// Checks a stored passkey's answer to an authentication challenge. Ok: its
/// sign counter now.
fn verify_assertion(
    rp: &RelyingParty,
    challenge: &[u8; 32],
    handle: &[u8; 16],
    key: &StoredKey,
    counter: u32,
    answer: &Assertion,
) -> Result<u32, Refused> {
    if answer.kind != "public-key" {
        return Err(Refused::Malformed("type"));
    }
    if Base64Url::decode(&answer.id).as_deref() != Some(answer.raw_id.0.as_slice()) {
        return Err(Refused::Malformed("id"));
    }
    let client_data_json = &answer.response.client_data_json.0;
    check_client_data(rp, "webauthn.get", challenge, client_data_json)?;

    let auth_data_bytes = &answer.response.authenticator_data.0;
    let auth_data = AuthData::parse(auth_data_bytes)?;
    if auth_data.attested.is_some() {
        return Err(Refused::Malformed("a credential in an answer"));
    }
    auth_data.check(rp)?;
    if key.user_verified && auth_data.flags & UV == 0 {
        return Err(Refused::NotVerified);
    }
    if (auth_data.flags & BE != 0) != key.backup_eligible {
        return Err(Refused::Backup);
    }
    if let Some(user_handle) = &answer.response.user_handle
        && user_handle.0 != handle
    {
        return Err(Refused::UserHandle);
    }

    let public_key = PublicKey::from_cose(&key.public_key.0)?;
    if public_key.alg() != key.alg {
        return Err(Refused::Algorithm);
    }
    public_key.verify(&signed(auth_data_bytes, client_data_json), &answer.response.signature.0)?;

    // A counter that doesn't go up: another copy of the key has signed
    // since. Synced passkeys count 0 throughout, and are let through.
    if (auth_data.counter != 0 || counter != 0) && auth_data.counter <= counter {
        return Err(Refused::Counter);
    }
    Ok(auth_data.counter)
}

// ---- the ceremonies -------------------------------------------------------

fn expired() -> ApiError {
    ApiError::bad_request("that passkey request has expired: try again")
}

fn timeout_ms() -> u64 {
    CEREMONY_TTL.as_secs() * 1000
}

/// The request for an answer from any of the account's passkeys, for
/// `ceremony` to check with [`check`].
async fn start_authentication(state: &AppState, user_id: i64, ceremony: Ceremony) -> Result<RequestOptions, ApiError> {
    let rp = state.passkeys.relying_party()?;
    let fresh = totp::random_bytes::<16>();
    // An account without a passkey is told so before it's given a handle.
    let found = state
        .db
        .call(move |conn| {
            let stored = db::passkeys(conn, user_id)?;
            if stored.is_empty() {
                return Ok(None);
            }
            Ok(Some((db::webauthn_handle(conn, user_id, fresh)?, stored)))
        })
        .await?;
    let Some((handle, stored)) = found else {
        return Err(ApiError::bad_request("this account has no passkey"));
    };
    let challenge = totp::random_bytes::<32>();
    let request = RequestOptions {
        public_key: RequestPublicKey {
            challenge: Base64Url(challenge.to_vec()),
            timeout: timeout_ms(),
            rp_id: rp.id.clone(),
            allow_credentials: stored.iter().map(Descriptor::of).collect(),
            user_verification: "preferred",
        },
    };
    state.passkeys.start(ceremony, user_id, Started::Authenticate { challenge, handle });
    Ok(request)
}

/// Checks a passkey's answer to the ceremony's challenge, spending the
/// challenge. Wrong answers count against the account like wrong codes
/// (see [`mfa::check_code`]). Ok(None): not a valid answer.
pub async fn check(
    state: &AppState,
    user_id: i64,
    ceremony: Ceremony,
    answer: &Assertion,
) -> Result<Option<Proof>, ApiError> {
    if state.mfa_limiter.is_blocked(user_id) {
        return Err(ApiError::TooManyRequests);
    }
    let rp = state.passkeys.relying_party()?;
    let Some(Started::Authenticate { challenge, handle }) = state.passkeys.take(&ceremony, user_id) else {
        return Err(expired());
    };

    // Only the account's own passkeys are looked up: another account's
    // never gets as far as a check.
    let credential_id = answer.raw_id.0.clone();
    let stored = if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID {
        None
    } else {
        state.db.call(move |conn| db::passkey(conn, user_id, &credential_id)).await?
    };
    let mut proof = None;
    match stored {
        None => debug!(user_id, "passkey answer refused: not one of the account's passkeys"),
        Some(stored) => {
            let key: StoredKey = serde_json::from_str(&stored.credential)
                .map_err(|error| ApiError::internal(format!("stored passkey {}: {error}", stored.id)))?;
            let counter = u32::try_from(stored.counter).unwrap_or(0);
            match verify_assertion(rp, &challenge, &handle, &key, counter, answer) {
                Ok(counter) => {
                    let (id, now) = (stored.id, auth::now());
                    state.db.call(move |conn| db::use_passkey(conn, id, i64::from(counter), now)).await?;
                    proof = Some(Proof::Passkey);
                }
                Err(Refused::Counter) => {
                    warn!(user_id, "a passkey's signature counter went backwards, so it may have been copied: refused");
                }
                Err(error) => debug!(user_id, ?error, "passkey answer refused"),
            }
        }
    }
    match proof {
        Some(_) => state.mfa_limiter.record_success(user_id),
        None => state.mfa_limiter.record_failure(user_id),
    }
    Ok(proof)
}

#[derive(Deserialize)]
pub struct TicketRequest {
    ticket: String,
}

/// A challenge for the second step of a login, for an account with a
/// passkey. The answer goes to `/api/login/mfa` in place of a code. Under
/// the same per-address limit as the rest of a login; asking doesn't use
/// up one of the ticket's tries, answering does.
pub async fn login_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<TicketRequest>,
) -> Result<Json<RequestOptions>, ApiError> {
    let ip = peer.ip();
    if state.limiter.is_blocked(ip) {
        return Err(ApiError::TooManyRequests);
    }
    let Some(user_id) = state.mfa_tickets.holder(&body.ticket) else {
        // A ticket that isn't one: a guess counts against the address.
        state.limiter.record_failure(ip);
        return Err(ApiError::bad_request("this sign-in has expired: enter your password again"));
    };
    let ceremony = Ceremony::Login(auth::token_hash(&body.ticket));
    Ok(Json(start_authentication(&state, user_id, ceremony).await?))
}

/// A challenge to step this session up with. The answer goes to
/// `/api/account/step-up` in place of a code.
pub async fn step_up_start(
    State(state): State<AppState>,
    SessionUser(current): SessionUser,
) -> Result<Json<RequestOptions>, ApiError> {
    let ceremony = Ceremony::StepUp(current.session_id);
    Ok(Json(start_authentication(&state, current.user.id, ceremony).await?))
}

#[derive(Deserialize)]
pub struct RegisterStart {
    /// The auth key derived from the password, for the first factor, which
    /// has no other factor to step up with.
    password: Option<String>,
}

/// A challenge to make a new passkey with. Like adding an authenticator
/// app, a step-up action, or with the password for the first factor.
pub async fn register_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    SessionUser(current): SessionUser,
    Json(body): Json<RegisterStart>,
) -> Result<Json<CreationOptions>, ApiError> {
    let rp = state.passkeys.relying_party()?;
    let first = !current.account.mfa;
    if first {
        let password = body.password.as_deref().ok_or_else(|| ApiError::bad_request("enter your password"))?;
        api::check_password(&state, peer, current.user.id, password).await?;
    } else if current.needs_step_up(auth::now()) {
        return Err(ApiError::StepUpRequired);
    }

    let user_id = current.user.id;
    let fresh = totp::random_bytes::<16>();
    let (count, handle, stored) = state
        .db
        .call(move |conn| {
            let count = db::list_factors(conn, user_id)?.len();
            Ok((count, db::webauthn_handle(conn, user_id, fresh)?, db::passkeys(conn, user_id)?))
        })
        .await?;
    if count >= MAX_FACTORS {
        return Err(too_many());
    }
    let challenge = totp::random_bytes::<32>();
    let email = &current.user.email;
    let options = CreationOptions {
        public_key: CreationPublicKey {
            rp: RpEntity { name: "Hawk", id: rp.id.clone() },
            user: UserEntity { id: Base64Url(handle.to_vec()), name: email.clone(), display_name: email.clone() },
            challenge: Base64Url(challenge.to_vec()),
            pub_key_cred_params: ALGORITHMS
                .iter()
                .map(|&alg| CredentialParameter { kind: "public-key", alg })
                .collect(),
            timeout: timeout_ms(),
            exclude_credentials: stored.iter().map(Descriptor::of).collect(),
            authenticator_selection: AuthenticatorSelection {
                resident_key: "discouraged",
                require_resident_key: false,
                user_verification: "preferred",
            },
            attestation: "none",
            extensions: CreationExtensions {
                cred_props: true,
                credential_protection_policy: "userVerificationRequired",
                enforce_credential_protection_policy: false,
            },
        },
    };
    let started = Started::Register { challenge, password_confirmed: first };
    state.passkeys.start(Ceremony::Register(current.session_id), user_id, started);
    Ok(Json(options))
}

fn too_many() -> ApiError {
    ApiError::Conflict(format!("an account can have at most {MAX_FACTORS} second factors"))
}

#[derive(Deserialize)]
pub struct RegisterFinish {
    /// What `navigator.credentials.create` made, as JSON.
    credential: Box<NewCredential>,
    label: String,
}

/// Registers the passkey the browser made for [`register_start`]'s
/// challenge. Every other session is ended, as for any new factor.
pub async fn register_finish(
    State(state): State<AppState>,
    client: Client,
    SessionUser(current): SessionUser,
    Json(body): Json<RegisterFinish>,
) -> Result<Json<AddedFactor>, ApiError> {
    let rp = state.passkeys.relying_party()?;
    let now = auth::now();
    let user_id = current.user.id;
    // Checked before the challenge is taken, so that the dashboard's retry
    // after stepping up (or fixing the name) still finds it.
    let first = !current.account.mfa;
    if !first && current.needs_step_up(now) {
        return Err(ApiError::StepUpRequired);
    }
    let label = body.label.trim().to_owned();
    if label.is_empty() || label.chars().count() > MAX_LABEL_LEN {
        return Err(ApiError::bad_request(format!("name it in 1 to {MAX_LABEL_LEN} characters")));
    }
    let Some(Started::Register { challenge, password_confirmed }) =
        state.passkeys.take(&Ceremony::Register(current.session_id), user_id)
    else {
        return Err(expired());
    };
    // The password was checked when the challenge was given; a challenge
    // given on a step-up, to an account that has since lost every factor,
    // won't do for a first one.
    if first && !password_confirmed {
        return Err(ApiError::bad_request("enter your password"));
    }
    let made = verify_registration(rp, &challenge, &body.credential).map_err(|error| {
        debug!(user_id, ?error, "passkey registration refused");
        ApiError::bad_request("that passkey couldn't be checked: try again")
    })?;

    let stored = serde_json::to_string(&made.key).map_err(|error| ApiError::internal(error.to_string()))?;
    let transports = (!made.transports.is_empty())
        .then(|| serde_json::to_string(&made.transports))
        .transpose()
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let counter = i64::from(made.counter);
    let credential_id = made.credential_id;
    let (recovery_codes, hashes) = mfa::first_recovery_codes(first);
    let keep = current.session_id;
    let details = Details::factor(FactorKind::Passkey, &label);
    let added = Event::new(Kind::MfaAdded).by(user_id).client(&client).details(details);
    let outcome = state
        .db
        .call(move |conn| {
            if db::list_factors(conn, user_id)?.len() >= MAX_FACTORS {
                return Ok(Err(too_many()));
            }
            let passkey = NewPasskey {
                label: &label,
                credential_id: &credential_id,
                credential: &stored,
                counter,
                transports: transports.as_deref(),
            };
            if !db::add_passkey_factor(conn, user_id, &passkey, &hashes, keep, now)? {
                return Ok(Err(ApiError::Conflict("that passkey is already registered".into())));
            }
            // Making it just proved it.
            db::set_step_up(conn, keep, now)?;
            Ok(Ok(()))
        })
        .await?;
    outcome?;

    state.registry.close_other_sessions(user_id, keep);
    state.registry.set_mfa(user_id, true);
    state.registry.note_step_up(keep, now);
    state.audit.record(added);
    mfa::notify(&state, &current.user.email, "A passkey was added to your account as a second factor.");
    Ok(Json(AddedFactor::new(recovery_codes)))
}

/// As much CBOR as WebAuthn uses, read strictly: definite lengths, no tags
/// or floats, no duplicate map keys, small collections, shallow nesting.
mod cbor {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Malformed;

    #[derive(Debug, PartialEq, Eq)]
    pub enum Value<'a> {
        Int(i64),
        Bytes(&'a [u8]),
        Text(&'a str),
        Array(Vec<Value<'a>>),
        Map(Vec<(Value<'a>, Value<'a>)>),
        Bool(bool),
        Null,
    }

    impl<'a> Value<'a> {
        pub fn int(&self) -> Option<i64> {
            if let Self::Int(value) = self { Some(*value) } else { None }
        }

        pub fn bytes(&self) -> Option<&'a [u8]> {
            if let Self::Bytes(bytes) = self { Some(bytes) } else { None }
        }

        pub fn text(&self) -> Option<&'a str> {
            if let Self::Text(text) = self { Some(text) } else { None }
        }
    }

    /// More entries than any COSE key, attestation statement or extension
    /// map has.
    const MAX_ITEMS: u64 = 32;
    const MAX_DEPTH: usize = 8;

    /// The value under `key` in a map's entries.
    pub fn field<'v, 'a>(map: &'v [(Value<'a>, Value<'a>)], key: &Value<'_>) -> Option<&'v Value<'a>> {
        map.iter().find(|(k, _)| k == key).map(|(_, value)| value)
    }

    /// One value from the front of `input`, and what follows it.
    pub fn read(input: &[u8]) -> Result<(Value<'_>, &[u8]), Malformed> {
        item(input, 0)
    }

    /// One value that is the whole of `input`.
    pub fn read_all(input: &[u8]) -> Result<Value<'_>, Malformed> {
        match read(input)? {
            (value, []) => Ok(value),
            _ => Err(Malformed),
        }
    }

    fn head(input: &[u8]) -> Result<(u8, u8, u64, &[u8]), Malformed> {
        let (&first, rest) = input.split_first().ok_or(Malformed)?;
        let (major, info) = (first >> 5, first & 0x1f);
        let size = match info {
            0..=23 => return Ok((major, info, u64::from(info), rest)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            // Reserved, or an indefinite length.
            _ => return Err(Malformed),
        };
        let (bytes, rest) = rest.split_at_checked(size).ok_or(Malformed)?;
        let argument = bytes.iter().fold(0, |value, &byte| (value << 8) | u64::from(byte));
        Ok((major, info, argument, rest))
    }

    fn item(input: &[u8], depth: usize) -> Result<(Value<'_>, &[u8]), Malformed> {
        if depth > MAX_DEPTH {
            return Err(Malformed);
        }
        let (major, info, argument, rest) = head(input)?;
        let length = || usize::try_from(argument).map_err(|_| Malformed);
        match major {
            0 => Ok((Value::Int(i64::try_from(argument).map_err(|_| Malformed)?), rest)),
            1 => Ok((Value::Int(-1 - i64::try_from(argument).map_err(|_| Malformed)?), rest)),
            2 => {
                let (bytes, rest) = rest.split_at_checked(length()?).ok_or(Malformed)?;
                Ok((Value::Bytes(bytes), rest))
            }
            3 => {
                let (bytes, rest) = rest.split_at_checked(length()?).ok_or(Malformed)?;
                Ok((Value::Text(std::str::from_utf8(bytes).map_err(|_| Malformed)?), rest))
            }
            4 if argument <= MAX_ITEMS => {
                let (mut items, mut rest) = (Vec::new(), rest);
                for _ in 0..argument {
                    let (value, after) = item(rest, depth + 1)?;
                    items.push(value);
                    rest = after;
                }
                Ok((Value::Array(items), rest))
            }
            5 if argument <= MAX_ITEMS => {
                let (mut entries, mut rest) = (Vec::<(Value<'_>, Value<'_>)>::new(), rest);
                for _ in 0..argument {
                    let (key, after) = item(rest, depth + 1)?;
                    let (value, after) = item(after, depth + 1)?;
                    if field(&entries, &key).is_some() {
                        return Err(Malformed);
                    }
                    entries.push((key, value));
                    rest = after;
                }
                Ok((Value::Map(entries), rest))
            }
            7 => match info {
                20 => Ok((Value::Bool(false), rest)),
                21 => Ok((Value::Bool(true), rest)),
                22 => Ok((Value::Null, rest)),
                _ => Err(Malformed),
            },
            _ => Err(Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::extract::FromRequestParts;
    use axum::http::{HeaderMap, Request};
    use axum_extra::extract::cookie::CookieJar;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair};
    use serde_json::json;
    use tokio::sync::{Notify, mpsc};

    use super::*;
    use crate::audit::AuditLog;
    use crate::auth::{AccountLimiter, CurrentUser, LoginLimiter, SteppedUp};
    use crate::db::Db;
    use crate::mfa::{Answer, LoginTickets};
    use crate::registry::Registry;
    use crate::totp::SecretKey;

    const ORIGIN: &str = "http://localhost:5173";
    const PEER: &str = "127.0.0.1:50000";

    // ---- a software authenticator, and CBOR to make its answers with ----

    fn head(out: &mut Vec<u8>, major: u8, argument: u64) {
        let major = major << 5;
        match argument {
            0..=23 => out.push(major | argument as u8),
            24..=0xff => out.extend([major | 24, argument as u8]),
            0x100..=0xffff => {
                out.push(major | 25);
                out.extend((argument as u16).to_be_bytes());
            }
            _ => {
                out.push(major | 26);
                out.extend((argument as u32).to_be_bytes());
            }
        }
    }

    fn int(out: &mut Vec<u8>, value: i64) {
        if value >= 0 { head(out, 0, value as u64) } else { head(out, 1, (-1 - value) as u64) }
    }

    fn bytes(out: &mut Vec<u8>, value: &[u8]) {
        head(out, 2, value.len() as u64);
        out.extend(value);
    }

    fn text(out: &mut Vec<u8>, value: &str) {
        head(out, 3, value.len() as u64);
        out.extend(value.as_bytes());
    }

    fn map(out: &mut Vec<u8>, entries: usize) {
        head(out, 5, entries as u64);
    }

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    enum Signer {
        Es256(EcdsaKeyPair),
        Ed25519(Ed25519KeyPair),
    }

    impl Signer {
        fn es256() -> Self {
            let rng = SystemRandom::new();
            let alg = &signature::ECDSA_P256_SHA256_ASN1_SIGNING;
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
            Self::Es256(EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap())
        }

        fn ed25519() -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            Self::Ed25519(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap())
        }

        fn cose(&self) -> Vec<u8> {
            let mut out = Vec::new();
            match self {
                Self::Es256(key) => {
                    let point = key.public_key().as_ref();
                    map(&mut out, 5);
                    for (label, value) in [(1, 2), (3, ES256), (-1, 1)] {
                        int(&mut out, label);
                        int(&mut out, value);
                    }
                    int(&mut out, -2);
                    bytes(&mut out, &point[1..33]);
                    int(&mut out, -3);
                    bytes(&mut out, &point[33..]);
                }
                Self::Ed25519(key) => {
                    map(&mut out, 4);
                    for (label, value) in [(1, 1), (3, EDDSA), (-1, 6)] {
                        int(&mut out, label);
                        int(&mut out, value);
                    }
                    int(&mut out, -2);
                    bytes(&mut out, key.public_key().as_ref());
                }
            }
            out
        }

        fn alg(&self) -> i64 {
            match self {
                Self::Es256(_) => ES256,
                Self::Ed25519(_) => EDDSA,
            }
        }

        fn sign(&self, message: &[u8]) -> Vec<u8> {
            match self {
                Self::Es256(key) => key.sign(&SystemRandom::new(), message).unwrap().as_ref().to_vec(),
                Self::Ed25519(key) => key.sign(message).as_ref().to_vec(),
            }
        }
    }

    fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        json!({ "type": kind, "challenge": b64(challenge), "origin": origin, "crossOrigin": false })
            .to_string()
            .into_bytes()
    }

    fn auth_data(rp_id: &str, flags: u8, counter: u32, attested: Option<(&[u8], &[u8])>) -> Vec<u8> {
        let mut out = sha256(rp_id.as_bytes()).to_vec();
        out.push(flags | if attested.is_some() { AT } else { 0 });
        out.extend(counter.to_be_bytes());
        if let Some((credential_id, public_key)) = attested {
            out.extend([0; 16]);
            out.extend((credential_id.len() as u16).to_be_bytes());
            out.extend(credential_id);
            out.extend(public_key);
        }
        out
    }

    fn attestation_object(format: &str, statement: &[u8], auth_data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        map(&mut out, 3);
        text(&mut out, "fmt");
        text(&mut out, format);
        text(&mut out, "attStmt");
        out.extend(statement);
        text(&mut out, "authData");
        bytes(&mut out, auth_data);
        out
    }

    fn new_credential(credential_id: &[u8], client_data: Vec<u8>, attestation_object: Vec<u8>) -> NewCredential {
        serde_json::from_value(json!({
            "id": b64(credential_id),
            "rawId": b64(credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(&client_data),
                "attestationObject": b64(&attestation_object),
                "transports": ["usb", "made-up", "usb"],
            },
            "clientExtensionResults": {},
        }))
        .unwrap()
    }

    fn assertion(credential_id: &[u8], client_data: Vec<u8>, auth_data: Vec<u8>, signature: Vec<u8>) -> Assertion {
        serde_json::from_value(json!({
            "id": b64(credential_id),
            "rawId": b64(credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(&client_data),
                "authenticatorData": b64(&auth_data),
                "signature": b64(&signature),
                "userHandle": null,
            },
            "clientExtensionResults": {},
        }))
        .unwrap()
    }

    /// A security key: makes a passkey for the relay's options, and answers
    /// its challenges, as a browser would hand them over.
    struct SoftKey {
        signer: Signer,
        credential_id: Vec<u8>,
        counter: u32,
    }

    impl SoftKey {
        fn new() -> Self {
            Self { signer: Signer::es256(), credential_id: totp::random_bytes::<16>().to_vec(), counter: 0 }
        }

        fn make(&mut self, options: &CreationOptions) -> NewCredential {
            let options = &options.public_key;
            let client_data = client_data("webauthn.create", &options.challenge.0, ORIGIN);
            let cose = self.signer.cose();
            let attested = Some((self.credential_id.as_slice(), cose.as_slice()));
            let auth_data = auth_data(&options.rp.id, UP | UV, self.counter, attested);
            let mut none = Vec::new();
            map(&mut none, 0);
            new_credential(&self.credential_id, client_data, attestation_object("none", &none, &auth_data))
        }

        fn answer(&mut self, options: &RequestOptions) -> Assertion {
            serde_json::from_value(self.answer_json(options)).unwrap()
        }

        /// The answer as the dashboard posts it.
        fn answer_json(&mut self, options: &RequestOptions) -> serde_json::Value {
            self.counter += 1;
            let options = &options.public_key;
            let client_data = client_data("webauthn.get", &options.challenge.0, ORIGIN);
            let auth_data = auth_data(&options.rp_id, UP | UV, self.counter, None);
            let signature = self.signer.sign(&signed(&auth_data, &client_data));
            json!({
                "id": b64(&self.credential_id),
                "rawId": b64(&self.credential_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": b64(&client_data),
                    "authenticatorData": b64(&auth_data),
                    "signature": b64(&signature),
                    "userHandle": null,
                },
                "clientExtensionResults": {},
            })
        }
    }

    // ---- the checks, one by one --------------------------------------------

    const RP_ID: &str = "example.com";
    const RP_ORIGIN: &str = "https://example.com";
    const CHALLENGE: [u8; 32] = [9; 32];
    const HANDLE: [u8; 16] = [3; 16];

    fn rp() -> RelyingParty {
        let config = PasskeyConfig::parse(RP_ORIGIN, &AllowedOrigins::default(), None, None).unwrap().unwrap();
        RelyingParty::new(&config)
    }

    /// The pieces of a registration, to change one at a time.
    struct Registration {
        kind: &'static str,
        challenge: Vec<u8>,
        origin: &'static str,
        cross_origin: bool,
        rp_id: &'static str,
        flags: u8,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        format: &'static str,
        statement: Option<Vec<u8>>,
        trailing: Vec<u8>,
    }

    impl Registration {
        fn of(signer: &Signer) -> Self {
            Self {
                kind: "webauthn.create",
                challenge: CHALLENGE.to_vec(),
                origin: RP_ORIGIN,
                cross_origin: false,
                rp_id: RP_ID,
                flags: UP | UV,
                credential_id: vec![1; 16],
                public_key: signer.cose(),
                format: "none",
                statement: None,
                trailing: Vec::new(),
            }
        }

        fn client_data(&self) -> Vec<u8> {
            json!({
                "type": self.kind,
                "challenge": b64(&self.challenge),
                "origin": self.origin,
                "crossOrigin": self.cross_origin,
            })
            .to_string()
            .into_bytes()
        }

        fn auth_data(&self) -> Vec<u8> {
            let attested = (self.credential_id.as_slice(), self.public_key.as_slice());
            let mut out = auth_data(self.rp_id, self.flags, 0, Some(attested));
            out.extend(&self.trailing);
            out
        }

        fn build(&self) -> NewCredential {
            let statement = self.statement.clone().unwrap_or_else(|| {
                let mut none = Vec::new();
                map(&mut none, 0);
                none
            });
            let object = attestation_object(self.format, &statement, &self.auth_data());
            new_credential(&self.credential_id, self.client_data(), object)
        }

        fn verify(&self) -> Result<Made, Refused> {
            verify_registration(&rp(), &CHALLENGE, &self.build())
        }
    }

    /// The pieces of an answer from a registered key.
    struct Answering<'a> {
        signer: &'a Signer,
        kind: &'static str,
        challenge: Vec<u8>,
        origin: &'static str,
        cross_origin: bool,
        rp_id: &'static str,
        flags: u8,
        counter: u32,
        user_handle: Option<Vec<u8>>,
        trailing: Vec<u8>,
    }

    impl<'a> Answering<'a> {
        fn of(signer: &'a Signer) -> Self {
            Self {
                signer,
                kind: "webauthn.get",
                challenge: CHALLENGE.to_vec(),
                origin: RP_ORIGIN,
                cross_origin: false,
                rp_id: RP_ID,
                flags: UP | UV,
                counter: 6,
                user_handle: Some(HANDLE.to_vec()),
                trailing: Vec::new(),
            }
        }

        fn build(&self) -> Assertion {
            let client_data = json!({
                "type": self.kind,
                "challenge": b64(&self.challenge),
                "origin": self.origin,
                "crossOrigin": self.cross_origin,
            })
            .to_string()
            .into_bytes();
            let mut auth_data = auth_data(self.rp_id, self.flags, self.counter, None);
            auth_data.extend(&self.trailing);
            let signature = self.signer.sign(&signed(&auth_data, &client_data));
            let mut answer = assertion(&[1; 16], client_data, auth_data, signature);
            answer.response.user_handle = self.user_handle.clone().map(Base64Url);
            answer
        }

        /// Against the key as registered, its counter at 5.
        fn verify(&self) -> Result<u32, Refused> {
            verify_assertion(&rp(), &CHALLENGE, &HANDLE, &stored(self.signer, true), 5, &self.build())
        }
    }

    fn stored(signer: &Signer, user_verified: bool) -> StoredKey {
        StoredKey { alg: signer.alg(), public_key: Base64Url(signer.cose()), user_verified, backup_eligible: false }
    }

    #[test]
    fn registration_of_es256_and_eddsa_keys() {
        for signer in [Signer::es256(), Signer::ed25519()] {
            let made = Registration::of(&signer).verify().unwrap();
            assert_eq!(made.credential_id, [1; 16]);
            assert_eq!(made.key, stored(&signer, true));
            assert_eq!(made.transports, ["usb"]);
            let parsed = PublicKey::from_cose(&made.key.public_key.0).unwrap();
            assert_eq!(parsed.alg(), signer.alg());

            // Without user verification: taken, and remembered as such.
            let registration = Registration { flags: UP, ..Registration::of(&signer) };
            assert!(!registration.verify().unwrap().key.user_verified);
        }
    }

    #[test]
    fn self_attestation_is_taken_and_checked() {
        let signer = Signer::es256();
        let registration = Registration { format: "packed", ..Registration::of(&signer) };
        let statement = |alg: i64, signature: &[u8], x5c: bool| {
            let mut out = Vec::new();
            map(&mut out, if x5c { 3 } else { 2 });
            text(&mut out, "alg");
            int(&mut out, alg);
            text(&mut out, "sig");
            bytes(&mut out, signature);
            if x5c {
                text(&mut out, "x5c");
                head(&mut out, 4, 0);
            }
            out
        };
        let good = signer.sign(&signed(&registration.auth_data(), &registration.client_data()));
        let with = |statement| Registration { statement: Some(statement), ..Registration::of(&signer) };
        let packed = |statement| Registration { format: "packed", ..with(statement) };
        assert!(packed(statement(ES256, &good, false)).verify().is_ok());
        assert_eq!(packed(statement(ES256, &[0; 70], false)).verify().unwrap_err(), Refused::Attestation);
        assert_eq!(packed(statement(EDDSA, &good, false)).verify().unwrap_err(), Refused::Attestation);
        // A certificate chain: real attestation, which was never asked for.
        assert_eq!(packed(statement(ES256, &good, true)).verify().unwrap_err(), Refused::Attestation);
        // "none" with a statement, or any other format.
        assert_eq!(with(statement(ES256, &good, false)).verify().unwrap_err(), Refused::Attestation);
        let tpm = Registration { format: "tpm", ..Registration::of(&signer) };
        assert_eq!(tpm.verify().unwrap_err(), Refused::Attestation);
    }

    #[test]
    fn registrations_that_are_refused() {
        let signer = Signer::es256();
        let base = || Registration::of(&signer);
        let refused = |registration: Registration| registration.verify().unwrap_err();

        assert_eq!(refused(Registration { origin: "https://evil.example.org", ..base() }), Refused::Origin);
        assert_eq!(refused(Registration { origin: "https://example.com:8443", ..base() }), Refused::Origin);
        assert_eq!(refused(Registration { challenge: vec![8; 32], ..base() }), Refused::Challenge);
        assert_eq!(refused(Registration { challenge: CHALLENGE[..31].to_vec(), ..base() }), Refused::Challenge);
        assert_eq!(refused(Registration { kind: "webauthn.get", ..base() }), Refused::Type);
        assert_eq!(refused(Registration { cross_origin: true, ..base() }), Refused::CrossOrigin);
        assert_eq!(refused(Registration { rp_id: "evil.com", ..base() }), Refused::RpId);
        assert_eq!(refused(Registration { flags: UV, ..base() }), Refused::NotPresent);
        assert_eq!(refused(Registration { flags: UP | BS, ..base() }), Refused::Backup);
        assert_eq!(refused(Registration { credential_id: vec![1; 1024], ..base() }), Refused::CredentialId);
        assert!(Registration { credential_id: vec![1; 1023], ..base() }.verify().is_ok());
        assert!(matches!(refused(Registration { trailing: vec![0], ..base() }), Refused::Malformed(_)));

        // A key in an algorithm that wasn't offered (ES384), or of no kind.
        let mut es384 = Vec::new();
        map(&mut es384, 5);
        for (label, value) in [(1, 2), (3, -35), (-1, 2)] {
            int(&mut es384, label);
            int(&mut es384, value);
        }
        for label in [-2, -3] {
            int(&mut es384, label);
            bytes(&mut es384, &[1; 48]);
        }
        assert_eq!(refused(Registration { public_key: es384, ..base() }), Refused::Algorithm);
        let mut empty = Vec::new();
        map(&mut empty, 0);
        assert!(matches!(refused(Registration { public_key: empty, ..base() }), Refused::Malformed(_)));

        // Something after the attestation object; an id that isn't the one made.
        let mut trailing = base().build();
        trailing.response.attestation_object.0.push(0);
        assert!(matches!(verify_registration(&rp(), &CHALLENGE, &trailing), Err(Refused::Malformed(_))));
        let mut other_id = base().build();
        other_id.raw_id = Base64Url(vec![2; 16]);
        other_id.id = b64(&[2; 16]);
        assert_eq!(verify_registration(&rp(), &CHALLENGE, &other_id).unwrap_err(), Refused::CredentialId);
    }

    #[test]
    fn answers_from_es256_and_eddsa_keys() {
        for signer in [Signer::es256(), Signer::ed25519()] {
            assert_eq!(Answering::of(&signer).verify(), Ok(6));
            // No user handle is fine; the user's own handle too, not another.
            assert_eq!(Answering { user_handle: None, ..Answering::of(&signer) }.verify(), Ok(6));
            let other = Answering { user_handle: Some(vec![4; 16]), ..Answering::of(&signer) };
            assert_eq!(other.verify(), Err(Refused::UserHandle));
        }
    }

    #[test]
    fn answers_that_are_refused() {
        let signer = Signer::es256();
        let base = || Answering::of(&signer);
        let refused = |answering: Answering<'_>| answering.verify().unwrap_err();

        assert_eq!(refused(Answering { origin: "https://evil.example.org", ..base() }), Refused::Origin);
        assert_eq!(refused(Answering { challenge: vec![8; 32], ..base() }), Refused::Challenge);
        assert_eq!(refused(Answering { kind: "webauthn.create", ..base() }), Refused::Type);
        assert_eq!(refused(Answering { cross_origin: true, ..base() }), Refused::CrossOrigin);
        assert_eq!(refused(Answering { rp_id: "evil.com", ..base() }), Refused::RpId);
        assert_eq!(refused(Answering { flags: UV, ..base() }), Refused::NotPresent);
        // Verified when made, so verified every time.
        assert_eq!(refused(Answering { flags: UP, ..base() }), Refused::NotVerified);
        assert_eq!(refused(Answering { flags: UP | UV | BE, ..base() }), Refused::Backup);
        assert!(matches!(refused(Answering { trailing: vec![0], ..base() }), Refused::Malformed(_)));
        // The counter has to go up: 5 was the last.
        assert_eq!(refused(Answering { counter: 5, ..base() }), Refused::Counter);
        assert_eq!(refused(Answering { counter: 4, ..base() }), Refused::Counter);
        assert_eq!(refused(Answering { counter: 0, ..base() }), Refused::Counter);

        // Signed by another key, or not quite what was signed.
        let other = Signer::es256();
        let mut forged = Answering { signer: &other, ..base() }.build();
        assert_eq!(
            verify_assertion(&rp(), &CHALLENGE, &HANDLE, &stored(&signer, true), 5, &forged),
            Err(Refused::Signature)
        );
        forged = base().build();
        forged.response.signature.0[10] ^= 1;
        assert_eq!(
            verify_assertion(&rp(), &CHALLENGE, &HANDLE, &stored(&signer, true), 5, &forged),
            Err(Refused::Signature)
        );
        // A stored key whose algorithm isn't its key's.
        let mismatched = StoredKey { alg: EDDSA, ..stored(&signer, true) };
        assert_eq!(
            verify_assertion(&rp(), &CHALLENGE, &HANDLE, &mismatched, 5, &base().build()),
            Err(Refused::Algorithm)
        );
    }

    #[test]
    fn counters_and_user_verification() {
        let signer = Signer::ed25519();
        // A synced passkey: 0 throughout.
        let answer = Answering { counter: 0, ..Answering::of(&signer) }.build();
        assert_eq!(verify_assertion(&rp(), &CHALLENGE, &HANDLE, &stored(&signer, true), 0, &answer), Ok(0));
        // A key that wasn't verified when made needn't be now.
        let answer = Answering { flags: UP, ..Answering::of(&signer) }.build();
        assert_eq!(verify_assertion(&rp(), &CHALLENGE, &HANDLE, &stored(&signer, false), 5, &answer), Ok(6));
        // Synced: backup eligible when made, and still.
        let synced = StoredKey { backup_eligible: true, ..stored(&signer, true) };
        let answer = Answering { flags: UP | UV | BE | BS, ..Answering::of(&signer) }.build();
        assert_eq!(verify_assertion(&rp(), &CHALLENGE, &HANDLE, &synced, 5, &answer), Ok(6));
        let answer = Answering::of(&signer).build();
        assert_eq!(verify_assertion(&rp(), &CHALLENGE, &HANDLE, &synced, 5, &answer), Err(Refused::Backup));
    }

    #[test]
    fn rsa_keys_are_read() {
        let key = |n: &[u8]| {
            let mut out = Vec::new();
            map(&mut out, 4);
            int(&mut out, 1);
            int(&mut out, 3);
            int(&mut out, 3);
            int(&mut out, RS256);
            int(&mut out, -1);
            bytes(&mut out, n);
            int(&mut out, -2);
            bytes(&mut out, &[1, 0, 1]);
            out
        };
        let mut n = vec![0];
        n.extend([0xc5; 256]);
        assert!(matches!(PublicKey::from_cose(&key(&n)), Ok(PublicKey::Rs256 { n, .. }) if n.len() == 256));
        // Under 2048 bits.
        assert!(PublicKey::from_cose(&key(&[0xc5; 128])).is_err());
    }

    #[test]
    fn cbor_is_read_strictly() {
        fn read(bytes: &[u8]) -> Result<cbor::Value<'_>, cbor::Malformed> {
            cbor::read_all(bytes)
        }
        assert_eq!(read(&[0x18, 100]), Ok(cbor::Value::Int(100)));
        assert_eq!(read(&[0x38, 99]), Ok(cbor::Value::Int(-100)));
        assert_eq!(read(&[0x43, 1, 2, 3]), Ok(cbor::Value::Bytes(&[1, 2, 3])));
        assert_eq!(read(&[0xa1, 0x01, 0xf5]), Ok(cbor::Value::Map(vec![(cbor::Value::Int(1), cbor::Value::Bool(true))])));
        // Trailing bytes, cut short, indefinite lengths, tags, floats.
        assert!(read(&[0x01, 0x00]).is_err());
        assert!(read(&[0x43, 1, 2]).is_err());
        assert!(read(&[0x5f, 0x41, 1, 0xff]).is_err());
        assert!(read(&[0xc2, 0x41, 1]).is_err());
        assert!(read(&[0xf9, 0x3c, 0x00]).is_err());
        // Duplicate keys; an integer past i64; text that isn't UTF-8.
        assert!(read(&[0xa2, 0x01, 0x01, 0x01, 0x02]).is_err());
        assert!(read(&[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(read(&[0x62, 0xff, 0xfe]).is_err());
        // Huge counts, deep nesting.
        assert!(read(&[0x9a, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(read(&[0x81; 12].iter().copied().chain([0x01]).collect::<Vec<_>>()).is_err());
    }

    // ---- whole ceremonies, through the handlers ----------------------------

    fn config() -> PasskeyConfig {
        PasskeyConfig::parse(ORIGIN, &AllowedOrigins::default(), None, None).unwrap().unwrap()
    }

    fn test_state() -> (AppState, mpsc::Receiver<Event>) {
        let (audit, events) = AuditLog::new(crate::audit::QUEUE_LEN);
        let audit = Arc::new(audit);
        let (view_ended, _) = mpsc::unbounded_channel();
        let state = AppState {
            registry: Arc::new(Registry::new(view_ended, audit.clone())),
            db: Db::open_in_memory(),
            limiter: Arc::new(LoginLimiter::default()),
            secure_cookies: false,
            relay_pin: None,
            shares_changed: Arc::new(Notify::new()),
            mfa_limiter: Arc::new(AccountLimiter::default()),
            mfa_tickets: Arc::new(LoginTickets::default()),
            secret_key: Arc::new(SecretKey::from_bytes(&[7; 32]).unwrap()),
            totp_issuer: "Hawk (test)".into(),
            mailer: None,
            allowed_origins: Arc::new(AllowedOrigins::default()),
            audit,
            passkeys: Arc::new(Passkeys::new(Some(&config()))),
        };
        (state, events)
    }

    /// A user (id `user_id`, password "auth-key") signed in on session
    /// `user_id`; plus one other session, which a new factor ends.
    async fn user(state: &AppState, user_id: i64) -> CurrentUser {
        let hash = tokio::task::spawn_blocking(|| auth::hash_password("auth-key").unwrap()).await.unwrap();
        state
            .db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, created_at) VALUES (?1, ?2, ?3, 0)",
                    rusqlite::params![user_id, format!("user{user_id}@example.com"), hash],
                )?;
                let origin = db::SessionOrigin { user_agent: None, ip: "127.0.0.1".into() };
                for token in [format!("token-{user_id}"), format!("other-{user_id}")] {
                    db::create_session(conn, &auth::token_hash(&token), user_id, &origin, 0, i64::MAX, None)?;
                }
                Ok(())
            })
            .await
            .unwrap();
        session(state, &format!("token-{user_id}")).await
    }

    /// The session behind a token, as the extractor sees it now.
    async fn session(state: &AppState, token: &str) -> CurrentUser {
        let mut parts = parts(token);
        SessionUser::from_request_parts(&mut parts, state).await.map(|SessionUser(current)| current).unwrap()
    }

    fn parts(token: &str) -> axum::http::request::Parts {
        Request::builder().header("cookie", format!("hawk_session={token}")).body(()).unwrap().into_parts().0
    }

    fn peer() -> ConnectInfo<SocketAddr> {
        ConnectInfo(PEER.parse().unwrap())
    }

    async fn register(
        state: &AppState,
        current: CurrentUser,
        authenticator: &mut SoftKey,
        password: Option<&str>,
    ) -> Result<AddedFactor, ApiError> {
        let token = format!("token-{}", current.user.id);
        let start = RegisterStart { password: password.map(str::to_owned) };
        let Json(options) = register_start(State(state.clone()), peer(), SessionUser(current), Json(start)).await?;
        let credential = authenticator.make(&options);
        let current = session(state, &token).await;
        let finish = RegisterFinish { credential: Box::new(credential), label: "Security key".into() };
        let finished = register_finish(State(state.clone()), Client::default(), SessionUser(current), Json(finish));
        finished.await.map(|Json(added)| added)
    }

    fn drain(events: &mut mpsc::Receiver<Event>) -> Vec<(Kind, Details)> {
        std::iter::from_fn(|| events.try_recv().ok()).map(|event| (event.kind, event.details)).collect()
    }

    /// The first passkey: confirmed with the password, it satisfies the
    /// admin's policy, comes with recovery codes and ends other sessions;
    /// then it steps the session up and signs in, and each is in the log.
    #[tokio::test]
    async fn register_step_up_and_sign_in() {
        let (state, mut events) = test_state();
        state.db.call(|conn| db::set_setting(conn, "require_mfa", "1")).await.unwrap();
        let current = user(&state, 1).await;
        assert!(current.must_set_up_mfa());
        let mut authenticator = SoftKey::new();

        // The first factor needs the password, not a step-up.
        assert!(matches!(
            register_start(State(state.clone()), peer(), SessionUser(current), Json(RegisterStart { password: None }))
                .await,
            Err(ApiError::BadRequest(_))
        ));
        let current = session(&state, "token-1").await;
        let added = register(&state, current, &mut authenticator, Some("auth-key")).await.unwrap();
        assert_eq!(added.recovery_codes().map(<[String]>::len), Some(totp::RECOVERY_CODES));

        let current = session(&state, "token-1").await;
        assert!(current.account.mfa && current.account.passkeys && !current.must_set_up_mfa());
        // Making it stepped the session up, and the other session is gone.
        assert!(!current.needs_step_up(auth::now()));
        let other = SessionUser::from_request_parts(&mut parts("other-1"), &state).await;
        assert!(matches!(other, Err(ApiError::Unauthorized)));
        let factors = state.db.call(|conn| db::list_factors(conn, 1)).await.unwrap();
        assert_eq!((factors.len(), factors[0].kind), (1, FactorKind::Passkey));
        let stored = state.db.call(|conn| db::passkeys(conn, 1)).await.unwrap();
        assert_eq!(stored[0].credential_id, authenticator.credential_id);
        assert_eq!(stored[0].transports.as_deref(), Some(r#"["usb"]"#));

        // Stepping up again, later, with the passkey; the options name it.
        state.db.call(|conn| conn.execute("UPDATE sessions SET step_up_at = 0", [])).await.unwrap();
        let current = session(&state, "token-1").await;
        assert!(current.needs_step_up(auth::now()));
        let Json(request) = step_up_start(State(state.clone()), SessionUser(current)).await.unwrap();
        let options = serde_json::to_value(&request).unwrap();
        assert_eq!(options["publicKey"]["rpId"], "localhost");
        assert_eq!(options["publicKey"]["allowCredentials"][0]["id"], b64(&authenticator.credential_id));
        assert_eq!(options["publicKey"]["allowCredentials"][0]["transports"], json!(["usb"]));
        let answer = authenticator.answer(&request);
        let current = session(&state, "token-1").await;
        let answer = Json(Answer::passkey(answer));
        let Json(_) = mfa::step_up(State(state.clone()), Client::default(), SessionUser(current), answer).await.unwrap();
        assert!(!session(&state, "token-1").await.needs_step_up(auth::now()));

        // Signing in: the password's ticket, then the passkey.
        let ticket = state.mfa_tickets.issue(1, db::SessionOrigin { user_agent: None, ip: "127.0.0.1".into() });
        let Json(request) =
            login_start(State(state.clone()), peer(), Json(TicketRequest { ticket: ticket.clone() })).await.unwrap();
        let answer = authenticator.answer(&request);
        let second = api::SecondStep::new(ticket, Answer::passkey(answer));
        let signed_in =
            api::login_mfa(State(state.clone()), peer(), HeaderMap::new(), CookieJar::new(), Json(second)).await;
        assert!(signed_in.is_ok());

        let logged = drain(&mut events);
        let passkey = Some(FactorKind::Passkey);
        assert!(logged.iter().any(|(kind, details)| *kind == Kind::MfaAdded && details.factor == passkey));
        assert!(logged.iter().any(|(kind, details)| *kind == Kind::StepUp && details.factor == passkey));
        assert!(logged.iter().any(|(kind, details)| *kind == Kind::SignIn && details.factor == passkey));
        let used = state.db.call(|conn| db::list_factors(conn, 1)).await.unwrap();
        assert!(used[0].last_used_at.is_some());
        let stored = state.db.call(|conn| db::passkeys(conn, 1)).await.unwrap();
        assert_eq!(stored[0].counter, 2);
    }

    /// What the dashboard is handed to make a passkey with.
    #[tokio::test]
    async fn creation_options_as_sent() {
        let (state, _events) = test_state();
        let current = user(&state, 1).await;
        let mut authenticator = SoftKey::new();
        register(&state, current, &mut authenticator, Some("auth-key")).await.unwrap();

        let current = session(&state, "token-1").await;
        let start = RegisterStart { password: None };
        let Json(options) = register_start(State(state.clone()), peer(), SessionUser(current), Json(start)).await.unwrap();
        let options = serde_json::to_value(&options).unwrap();
        let public_key = &options["publicKey"];
        assert_eq!(public_key["rp"], json!({ "name": "Hawk", "id": "localhost" }));
        assert_eq!(public_key["user"]["name"], "user1@example.com");
        assert_eq!(Base64Url::decode(public_key["user"]["id"].as_str().unwrap()).unwrap().len(), 16);
        assert_eq!(Base64Url::decode(public_key["challenge"].as_str().unwrap()).unwrap().len(), 32);
        let algs: Vec<_> = public_key["pubKeyCredParams"].as_array().unwrap().iter().map(|p| p["alg"].clone()).collect();
        assert_eq!(algs, [json!(-7), json!(-8), json!(-257)]);
        assert_eq!(public_key["attestation"], "none");
        assert_eq!(public_key["timeout"], 120_000);
        assert_eq!(public_key["authenticatorSelection"]["userVerification"], "preferred");
        assert_eq!(public_key["excludeCredentials"][0]["id"], b64(&authenticator.credential_id));

        // The same authenticator again is turned away at the end too.
        let current = session(&state, "token-1").await;
        let added = register(&state, current, &mut authenticator, None).await;
        assert!(matches!(added, Err(ApiError::Conflict(_))));
    }

    /// An answer is good for its own challenge once; a challenge is dead
    /// after two minutes, and on another account.
    #[tokio::test]
    async fn challenges_are_single_use_and_expire() {
        let (state, _events) = test_state();
        let current = user(&state, 1).await;
        let mut authenticator = SoftKey::new();
        register(&state, current, &mut authenticator, Some("auth-key")).await.unwrap();

        let current = session(&state, "token-1").await;
        let Json(request) = step_up_start(State(state.clone()), SessionUser(current)).await.unwrap();
        let answer = authenticator.answer(&request);
        let proof = check(&state, 1, Ceremony::StepUp(1), &answer).await.unwrap();
        assert_eq!(proof, Some(Proof::Passkey));
        assert!(matches!(check(&state, 1, Ceremony::StepUp(1), &answer).await, Err(ApiError::BadRequest(_))));

        // Too old.
        let current = session(&state, "token-1").await;
        let Json(request) = step_up_start(State(state.clone()), SessionUser(current)).await.unwrap();
        let answer = authenticator.answer(&request);
        state.passkeys.expire_all();
        assert!(matches!(check(&state, 1, Ceremony::StepUp(1), &answer).await, Err(ApiError::BadRequest(_))));

        // Another account's ceremony, or this account's answer to it.
        let current = session(&state, "token-1").await;
        let Json(request) = step_up_start(State(state.clone()), SessionUser(current)).await.unwrap();
        let answer = authenticator.answer(&request);
        assert!(matches!(check(&state, 2, Ceremony::StepUp(1), &answer).await, Err(ApiError::BadRequest(_))));
        assert!(matches!(check(&state, 1, Ceremony::StepUp(1), &answer).await, Err(ApiError::BadRequest(_))));

        // A registration that waited too long.
        let current = session(&state, "token-1").await;
        let start = RegisterStart { password: None };
        let Json(options) = register_start(State(state.clone()), peer(), SessionUser(current), Json(start)).await.unwrap();
        let credential = SoftKey::new().make(&options);
        state.passkeys.expire_all();
        let finish = RegisterFinish { credential: Box::new(credential), label: "Late".into() };
        let current = session(&state, "token-1").await;
        let late = register_finish(State(state.clone()), Client::default(), SessionUser(current), Json(finish)).await;
        assert!(matches!(late, Err(ApiError::BadRequest(_))));
    }

    /// Another account's passkey, signing this account's challenge, is
    /// refused, and counts as a wrong answer.
    #[tokio::test]
    async fn another_accounts_passkey_is_refused() {
        let (state, _events) = test_state();
        let mut mine = SoftKey::new();
        let mut theirs = SoftKey::new();
        let current = user(&state, 1).await;
        register(&state, current, &mut mine, Some("auth-key")).await.unwrap();
        let other = user(&state, 2).await;
        register(&state, other, &mut theirs, Some("auth-key")).await.unwrap();

        // Account 1's challenge, signed by account 2's passkey for a client
        // that wants it signed anyway.
        let current = session(&state, "token-1").await;
        let Json(request) = step_up_start(State(state.clone()), SessionUser(current)).await.unwrap();
        let answer = theirs.answer(&request);
        assert_eq!(check(&state, 1, Ceremony::StepUp(1), &answer).await.unwrap(), None);
    }

    /// A signature counter that goes backwards (a copied key) is refused.
    #[tokio::test]
    async fn counter_regression_is_refused() {
        let (state, _events) = test_state();
        let mut authenticator = SoftKey::new();
        let current = user(&state, 1).await;
        register(&state, current, &mut authenticator, Some("auth-key")).await.unwrap();
        // As if another copy of the key had signed a thousand times.
        state.db.call(|conn| conn.execute("UPDATE mfa_factors SET last_counter = 1000", [])).await.unwrap();
        let current = session(&state, "token-1").await;
        let Json(request) = step_up_start(State(state.clone()), SessionUser(current)).await.unwrap();
        let answer = authenticator.answer(&request);
        assert_eq!(check(&state, 1, Ceremony::StepUp(1), &answer).await.unwrap(), None);
    }

    /// Removing a passkey is a step-up action; a passkey's step-up does.
    #[tokio::test]
    async fn removing_a_passkey_needs_a_step_up() {
        let (state, mut events) = test_state();
        let mut authenticator = SoftKey::new();
        let current = user(&state, 1).await;
        register(&state, current, &mut authenticator, Some("auth-key")).await.unwrap();
        let id = state.db.call(|conn| db::list_factors(conn, 1)).await.unwrap()[0].id;

        state.db.call(|conn| conn.execute("UPDATE sessions SET step_up_at = 0", [])).await.unwrap();
        let refused = SteppedUp::from_request_parts(&mut parts("token-1"), &state).await;
        assert!(matches!(refused, Err(ApiError::StepUpRequired)));

        let current = session(&state, "token-1").await;
        let Json(request) = step_up_start(State(state.clone()), SessionUser(current)).await.unwrap();
        let answer = authenticator.answer(&request);
        let current = session(&state, "token-1").await;
        let answer = Json(Answer::passkey(answer));
        let Json(_) = mfa::step_up(State(state.clone()), Client::default(), SessionUser(current), answer).await.unwrap();
        let stepped_up = SteppedUp::from_request_parts(&mut parts("token-1"), &state).await.unwrap();
        mfa::remove_factor(State(state.clone()), Client::default(), stepped_up, axum::extract::Path(id))
            .await
            .unwrap();
        assert!(!session(&state, "token-1").await.account.mfa);
        let removed = drain(&mut events).into_iter().find(|(kind, _)| *kind == Kind::MfaRemoved).unwrap();
        assert_eq!(removed.1.factor, Some(FactorKind::Passkey));
    }

    /// Wrong answers count toward the same lockout as wrong codes.
    #[tokio::test]
    async fn the_code_lockout_covers_passkeys() {
        let (state, _events) = test_state();
        let mut authenticator = SoftKey::new();
        let current = user(&state, 1).await;
        register(&state, current, &mut authenticator, Some("auth-key")).await.unwrap();
        for _ in 0..10 {
            assert_eq!(mfa::check_code(&state, 1, "000000").await.unwrap(), None);
        }
        let current = session(&state, "token-1").await;
        let Json(request) = step_up_start(State(state.clone()), SessionUser(current)).await.unwrap();
        let answer = authenticator.answer(&request);
        assert!(matches!(check(&state, 1, Ceremony::StepUp(1), &answer).await, Err(ApiError::TooManyRequests)));
    }

    /// A tiny deterministic generator for the mutation tests.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// Whatever bytes come in, the CBOR reader and everything built on it
    /// answers with an error, never a panic: cut short anywhere, lengths
    /// far past the input or past usize, nesting at and past the limit,
    /// and a few thousand random corruptions of a real registration.
    #[test]
    fn cbor_and_authenticator_data_never_panic() {
        // Declared lengths of 2^64 - 1 (and 2^32 - 1) for every kind that has one.
        for major in [2u8, 3, 4, 5] {
            let mut huge = vec![(major << 5) | 27];
            huge.extend([0xff; 8]);
            assert!(cbor::read(&huge).is_err());
            let mut big = vec![(major << 5) | 26];
            big.extend([0xff; 4]);
            assert!(cbor::read(&big).is_err());
            // The head itself cut short.
            assert!(cbor::read(&huge[..5]).is_err());
        }
        // The most negative integer CBOR can say, and the most negative i64.
        assert!(cbor::read(&[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert_eq!(
            cbor::read_all(&[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Ok(cbor::Value::Int(i64::MIN))
        );
        // Nesting: eight levels are fine, nine aren't; maps as keys too.
        let nested = |levels: usize, open: u8| [open].repeat(levels).into_iter().chain([0x01]).collect::<Vec<_>>();
        assert!(cbor::read_all(&nested(8, 0x81)).is_ok());
        assert!(cbor::read_all(&nested(9, 0x81)).is_err());
        assert!(cbor::read(&nested(64, 0xa1)).is_err());
        assert!(cbor::read(&[0x81; 100_000]).is_err());
        assert!(cbor::read(&[]).is_err());

        // A real registration, cut short at every byte, and corrupted.
        let signer = Signer::es256();
        let registration = Registration::of(&signer);
        let made = registration.build();
        let object = made.response.attestation_object.0.clone();
        let auth_data = registration.auth_data();
        let cose = signer.cose();
        assert!(verify_registration(&rp(), &CHALLENGE, &made).is_ok());
        for cut in 0..object.len() {
            assert!(cbor::read_all(&object[..cut]).is_err());
        }
        for cut in 0..auth_data.len() {
            assert!(AuthData::parse(&auth_data[..cut]).is_err());
        }
        for cut in 0..cose.len() {
            assert!(PublicKey::from_cose(&cose[..cut]).is_err());
        }
        // Authenticator data that says its credential id is 65535 bytes long.
        let mut long_id = auth_data.clone();
        long_id[32 + 5 + 16] = 0xff;
        long_id[32 + 5 + 17] = 0xff;
        assert_eq!(AuthData::parse(&long_id).err(), Some(Refused::CredentialId));
        // Extensions flagged, but none there, or not a map.
        let mut flagged = auth_data.clone();
        flagged[32] |= ED;
        assert!(AuthData::parse(&flagged).is_err());
        flagged.push(0x01);
        assert!(AuthData::parse(&flagged).is_err());

        let mut random = XorShift(0x9e37_79b9_7f4a_7c15);
        for _ in 0..4000 {
            let mut corrupted = object.clone();
            for _ in 0..=(random.next() % 4) {
                let at = (random.next() as usize) % corrupted.len();
                corrupted[at] = random.next() as u8;
            }
            let _ = cbor::read_all(&corrupted);
            let mut credential = registration.build();
            credential.response.attestation_object = Base64Url(corrupted);
            let _ = verify_registration(&rp(), &CHALLENGE, &credential);

            let mut corrupted = auth_data.clone();
            let at = (random.next() as usize) % corrupted.len();
            corrupted[at] = random.next() as u8;
            let _ = AuthData::parse(&corrupted);
            let mut corrupted = cose.clone();
            let at = (random.next() as usize) % corrupted.len();
            corrupted[at] = random.next() as u8;
            let _ = PublicKey::from_cose(&corrupted);
        }
        // Random bytes, of random lengths.
        for _ in 0..4000 {
            let length = (random.next() % 96) as usize;
            let noise: Vec<u8> = (0..length).map(|_| random.next() as u8).collect();
            let _ = cbor::read(&noise);
            let _ = AuthData::parse(&noise);
            let _ = PublicKey::from_cose(&noise);
        }
    }

    /// RSA keys outside 2048 to 8192 bits, or with an exponent ring can't
    /// take, are refused when read.
    #[test]
    fn rsa_key_bounds() {
        let key = |n: &[u8], e: &[u8]| {
            let mut out = Vec::new();
            map(&mut out, 4);
            for (label, value) in [(1, 3), (3, RS256)] {
                int(&mut out, label);
                int(&mut out, value);
            }
            int(&mut out, -1);
            bytes(&mut out, n);
            int(&mut out, -2);
            bytes(&mut out, e);
            out
        };
        assert!(PublicKey::from_cose(&key(&[0xc5; 1024], &[1, 0, 1])).is_ok());
        assert!(PublicKey::from_cose(&key(&[0xc5; 1025], &[1, 0, 1])).is_err());
        assert!(PublicKey::from_cose(&key(&[0xc5; 255], &[1, 0, 1])).is_err());
        // Leading zeros don't make a short modulus long enough.
        assert!(PublicKey::from_cose(&key(&[[0; 10].as_slice(), &[0xc5; 250]].concat(), &[1, 0, 1])).is_err());
        assert!(PublicKey::from_cose(&key(&[0xc5; 256], &[])).is_err());
        assert!(PublicKey::from_cose(&key(&[0xc5; 256], &[0, 0])).is_err());
        assert!(PublicKey::from_cose(&key(&[0xc5; 256], &[1, 0, 0, 0, 1])).is_err());
        // A modulus that isn't a byte string.
        let mut text_n = Vec::new();
        map(&mut text_n, 4);
        for (label, value) in [(1, 3), (3, RS256)] {
            int(&mut text_n, label);
            int(&mut text_n, value);
        }
        int(&mut text_n, -1);
        text(&mut text_n, "n");
        int(&mut text_n, -2);
        bytes(&mut text_n, &[1, 0, 1]);
        assert!(PublicKey::from_cose(&text_n).is_err());
    }

    /// A challenge belongs to its ceremony: a step-up's can't be answered
    /// for a login or a registration's for a step-up, nor one session's
    /// from another session of the same account.
    #[tokio::test]
    async fn ceremonies_do_not_cross() {
        let (state, _events) = test_state();
        let mut authenticator = SoftKey::new();
        let current = user(&state, 1).await;
        register(&state, current, &mut authenticator, Some("auth-key")).await.unwrap();
        let expired = |outcome: Result<Option<Proof>, ApiError>| matches!(outcome, Err(ApiError::BadRequest(_)));

        // A step-up's challenge, answered for a login, or for another session.
        let current = session(&state, "token-1").await;
        let Json(request) = step_up_start(State(state.clone()), SessionUser(current)).await.unwrap();
        let answer = authenticator.answer(&request);
        assert!(expired(check(&state, 1, Ceremony::Login(auth::token_hash("any")), &answer).await));
        assert!(expired(check(&state, 1, Ceremony::StepUp(2), &answer).await));
        // ... still waiting for its own ceremony, and good there.
        assert_eq!(check(&state, 1, Ceremony::StepUp(1), &answer).await.unwrap(), Some(Proof::Passkey));

        // A login's challenge, answered for a step-up of a session of the
        // same account: that session has no challenge waiting.
        let ticket = state.mfa_tickets.issue(1, db::SessionOrigin { user_agent: None, ip: "127.0.0.1".into() });
        let Json(request) = login_start(State(state.clone()), peer(), Json(TicketRequest { ticket: ticket.clone() })).await.unwrap();
        let answer = authenticator.answer(&request);
        assert!(expired(check(&state, 1, Ceremony::StepUp(1), &answer).await));
        // A step-up started since: its challenge isn't the one signed.
        let current = session(&state, "token-1").await;
        let _ = step_up_start(State(state.clone()), SessionUser(current)).await.unwrap();
        assert_eq!(check(&state, 1, Ceremony::StepUp(1), &answer).await.unwrap(), None);

        // A registration's challenge isn't an authentication's.
        let current = session(&state, "token-1").await;
        let start = RegisterStart { password: None };
        let _ = register_start(State(state.clone()), peer(), SessionUser(current), Json(start)).await.unwrap();
        assert!(expired(check(&state, 1, Ceremony::Register(1), &answer).await));
    }

    /// The second step of a login as the dashboard posts it (a passkey's
    /// answer beside the ticket); one account's passkey can't finish
    /// another's login, and a failed answer costs one of the ticket's tries.
    #[tokio::test]
    async fn login_with_a_passkey_as_posted() {
        let (state, _events) = test_state();
        let mut mine = SoftKey::new();
        let mut theirs = SoftKey::new();
        let current = user(&state, 1).await;
        register(&state, current, &mut mine, Some("auth-key")).await.unwrap();
        let other = user(&state, 2).await;
        register(&state, other, &mut theirs, Some("auth-key")).await.unwrap();
        let origin = || db::SessionOrigin { user_agent: None, ip: "127.0.0.1".into() };
        let post = |state: &AppState, body: serde_json::Value| {
            let second: api::SecondStep = serde_json::from_value(body).unwrap();
            api::login_mfa(State(state.clone()), peer(), HeaderMap::new(), CookieJar::new(), Json(second))
        };

        // Account 2's login, answered by account 1's passkey.
        let ticket = state.mfa_tickets.issue(2, origin());
        let Json(request) = login_start(State(state.clone()), peer(), Json(TicketRequest { ticket: ticket.clone() })).await.unwrap();
        let passkey = mine.answer_json(&request);
        let refused = post(&state, json!({ "ticket": ticket, "passkey": passkey })).await;
        assert!(matches!(refused, Err(ApiError::BadRequest(_))));
        // The ticket is still live (with a try spent), and account 2's own
        // passkey finishes it.
        let Json(request) = login_start(State(state.clone()), peer(), Json(TicketRequest { ticket: ticket.clone() })).await.unwrap();
        let passkey = theirs.answer_json(&request);
        let (_, _, Json(user)) = post(&state, json!({ "ticket": ticket, "passkey": passkey })).await.unwrap();
        assert_eq!(serde_json::to_value(&user).unwrap()["id"], 2);
        // Spent: neither a challenge nor an answer for it any more.
        let spent = login_start(State(state.clone()), peer(), Json(TicketRequest { ticket: ticket.clone() })).await;
        assert!(matches!(spent, Err(ApiError::BadRequest(_))));

        // A ticket that has had its tries gets no challenge.
        let ticket = state.mfa_tickets.issue(1, origin());
        for _ in 0..5 {
            let _ = post(&state, json!({ "ticket": ticket, "code": "000000" })).await;
        }
        let spent = login_start(State(state.clone()), peer(), Json(TicketRequest { ticket: ticket.clone() })).await;
        assert!(matches!(spent, Err(ApiError::BadRequest(_))));
    }

    /// A factor id of another account is not found, passkey or not.
    #[tokio::test]
    async fn another_accounts_passkey_cannot_be_removed() {
        let (state, _events) = test_state();
        let current = user(&state, 1).await;
        register(&state, current, &mut SoftKey::new(), Some("auth-key")).await.unwrap();
        let other = user(&state, 2).await;
        register(&state, other, &mut SoftKey::new(), Some("auth-key")).await.unwrap();
        let theirs = state.db.call(|conn| db::list_factors(conn, 2)).await.unwrap()[0].id;

        let stepped_up = SteppedUp::from_request_parts(&mut parts("token-1"), &state).await.unwrap();
        let removed =
            mfa::remove_factor(State(state.clone()), Client::default(), stepped_up, axum::extract::Path(theirs)).await;
        assert!(matches!(removed, Err(ApiError::NotFound)));
        assert_eq!(state.db.call(|conn| db::passkeys(conn, 2)).await.unwrap().len(), 1);
    }

    /// A registration refused for want of a step-up keeps its challenge:
    /// the dashboard steps up and posts the same passkey again.
    #[tokio::test]
    async fn registration_survives_a_step_up_retry() {
        let (state, _events) = test_state();
        let current = user(&state, 1).await;
        register(&state, current, &mut SoftKey::new(), Some("auth-key")).await.unwrap();

        let current = session(&state, "token-1").await;
        let start = RegisterStart { password: None };
        let Json(options) = register_start(State(state.clone()), peer(), SessionUser(current), Json(start)).await.unwrap();
        let mut second = SoftKey::new();
        state.db.call(|conn| conn.execute("UPDATE sessions SET step_up_at = 0", [])).await.unwrap();
        let mut finish = || RegisterFinish { credential: Box::new(second.make(&options)), label: "Second".into() };
        let first_try = finish();
        let current = session(&state, "token-1").await;
        let refused = register_finish(State(state.clone()), Client::default(), SessionUser(current), Json(first_try));
        assert!(matches!(refused.await, Err(ApiError::StepUpRequired)));

        let now = auth::now();
        state.db.call(move |conn| db::set_step_up(conn, 1, now)).await.unwrap();
        let current = session(&state, "token-1").await;
        let retried = register_finish(State(state.clone()), Client::default(), SessionUser(current), Json(finish()));
        assert!(retried.await.is_ok());
        assert_eq!(state.db.call(|conn| db::passkeys(conn, 1)).await.unwrap().len(), 2);
    }

    /// Asking for a login challenge: refused for a made-up ticket (which
    /// counts against the address, until it's blocked), and for an account
    /// with no passkey, which isn't given a user handle for it.
    #[tokio::test]
    async fn login_challenges_are_limited() {
        let (state, _events) = test_state();
        user(&state, 1).await;
        let ticket = state.mfa_tickets.issue(1, db::SessionOrigin { user_agent: None, ip: "127.0.0.1".into() });
        let asked = login_start(State(state.clone()), peer(), Json(TicketRequest { ticket: ticket.clone() })).await;
        assert!(matches!(asked, Err(ApiError::BadRequest(_))));
        let handle: Option<Vec<u8>> = state
            .db
            .call(|conn| conn.query_row("SELECT webauthn_handle FROM users WHERE id = 1", [], |row| row.get(0)))
            .await
            .unwrap();
        assert_eq!(handle, None);
        // Asking didn't use up a try of the ticket.
        assert_eq!(state.mfa_tickets.holder(&ticket), Some(1));

        let mut blocked = false;
        for _ in 0..50 {
            let guess = TicketRequest { ticket: "made-up".into() };
            match login_start(State(state.clone()), peer(), Json(guess)).await {
                Err(ApiError::TooManyRequests) => {
                    blocked = true;
                    break;
                }
                outcome => assert!(matches!(outcome, Err(ApiError::BadRequest(_)))),
            }
        }
        assert!(blocked);
        let asked = login_start(State(state.clone()), peer(), Json(TicketRequest { ticket })).await;
        assert!(matches!(asked, Err(ApiError::TooManyRequests)));
    }

    #[test]
    fn rp_ids_are_host_names() {
        for good in ["example.com", "Example.COM", "a-b.example.co.uk", "localhost", "xn--bcher-kva.example"] {
            assert!(rp_id_from(good).is_some(), "{good}");
        }
        assert_eq!(rp_id_from("Bücher.example").as_deref(), Some("xn--bcher-kva.example"));
        for bad in [
            "",
            "example",
            "relay",
            "exa mple.com",
            "example.com:8443",
            "https://example.com",
            "example.com/path",
            "*.example.com",
            ".example.com",
            "example.com.",
            "a..example.com",
            "-a.example.com",
            "a-.example.com",
            "under_score.example.com",
            "192.0.2.1",
            "1.2.3",
            "[::1]",
            "::1",
            "user@example.com",
        ] {
            assert_eq!(rp_id_from(bad), None, "{bad}");
        }
        let allowed = AllowedOrigins::default();
        let refused = PasskeyConfig::parse("https://relay.example.com", &allowed, Some("exa mple.com"), None);
        assert!(refused.unwrap_err().contains("HAWK_WEBAUTHN_RP_ID"));
        assert!(PasskeyConfig::parse("https://relay.example.com", &allowed, Some("example"), None).is_err());
        // Derived from an intranet name: no passkeys, rather than no relay.
        assert_eq!(PasskeyConfig::parse("https://relay:8443", &allowed, None, None), Ok(None));
    }

    #[test]
    fn config_defaults_and_checks() {
        let allowed = AllowedOrigins::parse("https://dash.example.com, http://tauri.localhost, https://you.github.io")
            .unwrap();
        let config = PasskeyConfig::parse("https://relay.example.com:8443", &allowed, None, None).unwrap().unwrap();
        assert_eq!(config.rp_id, "relay.example.com");
        assert_eq!(config.origins, [Url::parse("https://relay.example.com:8443").unwrap()]);
        // As the browser writes it into what it signs.
        assert_eq!(RelyingParty::new(&config).origins, ["https://relay.example.com:8443"]);

        // A shared parent: the relay and a dashboard on its own subdomain.
        let config =
            PasskeyConfig::parse("https://relay.example.com", &allowed, Some("Example.com"), None).unwrap().unwrap();
        assert_eq!(config.rp_id, "example.com");
        let hosts: Vec<_> = config.origins.iter().map(|origin| origin.host_str().unwrap().to_owned()).collect();
        assert_eq!(hosts, ["relay.example.com", "dash.example.com"]);
        assert_eq!(RelyingParty::new(&config).id_hash, sha256(b"example.com"));

        let explicit =
            PasskeyConfig::parse("https://relay.example.com", &allowed, None, Some("https://relay.example.com/"))
                .unwrap()
                .unwrap();
        assert_eq!(explicit.origins.len(), 1);
        assert_eq!(RelyingParty::new(&explicit).origins, ["https://relay.example.com"]);

        // Off, by choice or for want of a domain.
        assert_eq!(PasskeyConfig::parse("https://relay.example.com", &allowed, Some("off"), None), Ok(None));
        assert_eq!(PasskeyConfig::parse("https://192.0.2.1:8443", &allowed, None, None), Ok(None));
        assert_eq!(PasskeyConfig::parse("http://127.0.0.1:8080", &allowed, None, None), Ok(None));
        // Development: the relay on an IP, the dashboard's dev server on localhost.
        let dev = PasskeyConfig::parse("https://127.0.0.1:8080", &allowed, Some("localhost"), Some(ORIGIN));
        assert_eq!(dev.unwrap().unwrap().origins, [Url::parse(ORIGIN).unwrap()]);
        let none = AllowedOrigins::default();
        assert!(PasskeyConfig::parse("https://127.0.0.1:8080", &none, Some("localhost"), None).is_err());

        // Mistakes are refused at start, not discovered in a browser.
        assert!(PasskeyConfig::parse("https://relay.example.com", &allowed, Some("192.0.2.1"), None).is_err());
        assert!(PasskeyConfig::parse("https://relay.example.com", &allowed, Some("https://example.com"), None).is_err());
        assert!(PasskeyConfig::parse("https://relay.example.com", &allowed, None, Some("https://you.github.io")).is_err());
        assert!(PasskeyConfig::parse("https://relay.example.com", &allowed, None, Some("http://relay.example.com")).is_err());
        assert!(PasskeyConfig::parse("https://relay.example.com", &allowed, Some("other.org"), None).is_err());
        assert!(!within(&Url::parse("https://badexample.com").unwrap(), "example.com"));
        assert!(within(&Url::parse("https://a.b.example.com").unwrap(), "example.com"));
    }
}
