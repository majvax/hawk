//! Time-based one-time codes (RFC 6238), the base32 authenticator apps read
//! seeds in, recovery codes, and the relay's secret key that seeds are
//! sealed under at rest.

use std::io::Write;
use std::path::Path;

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hmac;

/// Seconds per code, digits per code, and seed length: what every
/// authenticator app assumes when the URI doesn't say otherwise.
pub const STEP: i64 = 30;
const DIGITS: usize = 6;
pub const SECRET_LEN: usize = 20;

/// The code for one time step. SHA-1 is what RFC 6238 and every
/// authenticator app use; as an HMAC it's not the weak point.
fn code_at(secret: &[u8], counter: u64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let mac = hmac::sign(&key, &counter.to_be_bytes());
    let mac = mac.as_ref();
    let offset = usize::from(mac[mac.len() - 1] & 0x0f);
    let truncated = u32::from_be_bytes([mac[offset] & 0x7f, mac[offset + 1], mac[offset + 2], mac[offset + 3]]);
    format!("{:0width$}", truncated % 10u32.pow(DIGITS as u32), width = DIGITS)
}

/// The time step `code` belongs to, if it's one of the steps either side of
/// now (clocks drift, and people type slowly). Spaces are ignored.
pub fn matching_step(secret: &[u8], code: &str, now: i64) -> Option<i64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let current = now.div_euclid(STEP);
    (current - 1..=current + 1)
        .find(|&step| u64::try_from(step).is_ok_and(|counter| same_digits(&code_at(secret, counter), &code)))
}

/// Compares two codes of the same length without stopping at the first
/// difference.
fn same_digits(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0, |diff, (x, y)| diff | (x ^ y)) == 0
}

/// True when `code` looks like a TOTP code rather than a recovery code.
pub fn is_totp_code(code: &str) -> bool {
    let digits: Vec<char> = code.chars().filter(|c| !c.is_whitespace()).collect();
    digits.len() == DIGITS && digits.iter().all(char::is_ascii_digit)
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding, as authenticator apps expect seeds.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(BASE32[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// The inverse of [`base32`]; case, spaces and padding are forgiven.
pub fn from_base32(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let value = BASE32.iter().position(|&b| char::from(b) == c.to_ascii_uppercase())?;
        buffer = (buffer << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// What a QR code hands an authenticator app.
pub fn otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let issuer = percent_encode(issuer);
    format!(
        "otpauth://totp/{issuer}:{}?secret={}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP}",
        percent_encode(account),
        base32(secret)
    )
}

fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' => char::from(b).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("OS random number generator unavailable");
    bytes
}

/// How many recovery codes an account gets at a time.
pub const RECOVERY_CODES: usize = 10;

/// A recovery code as shown: 80 random bits, base32, in groups of four.
pub fn new_recovery_code() -> String {
    let raw = base32(&random_bytes::<10>());
    raw.as_bytes().chunks(4).map(|chunk| String::from_utf8_lossy(chunk).into_owned()).collect::<Vec<_>>().join("-")
}

/// What a recovery code is hashed as, however it was typed.
pub fn normalize_recovery_code(code: &str) -> String {
    code.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_uppercase()).collect()
}

/// The relay's own secret: seals what it must be able to read back (TOTP
/// seeds) so a copy of the database alone doesn't hand them over. It lives
/// beside the database and has to be backed up with it.
pub struct SecretKey {
    key: LessSafeKey,
}

const NONCE_LEN: usize = 12;

impl SecretKey {
    /// Reads the key at `path`, or creates it (readable by its owner only)
    /// when there's none yet.
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let bytes = random_bytes::<32>().to_vec();
                write_private(path, &bytes).map_err(|error| format!("creating {}: {error}", path.display()))?;
                bytes
            }
            Err(error) => return Err(format!("reading {}: {error}", path.display())),
        };
        Self::from_bytes(&bytes).ok_or_else(|| format!("{} is not a 32-byte key", path.display()))
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        UnboundKey::new(&aead::AES_256_GCM, bytes).ok().map(|key| Self { key: LessSafeKey::new(key) })
    }

    /// AES-256-GCM under a random nonce, bound to `context` so a sealed
    /// value can't be moved to another row: nonce, then ciphertext and tag.
    pub fn seal(&self, plaintext: &[u8], context: &[u8]) -> Vec<u8> {
        let nonce = random_bytes::<NONCE_LEN>();
        let mut sealed = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(context), &mut sealed)
            .expect("sealing a short value");
        [nonce.as_slice(), &sealed].concat()
    }

    pub fn open(&self, sealed: &[u8], context: &[u8]) -> Option<Vec<u8>> {
        let (nonce, ciphertext) = sealed.split_at_checked(NONCE_LEN)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut buffer = ciphertext.to_vec();
        let plaintext = self.key.open_in_place(nonce, Aad::from(context), &mut buffer).ok()?;
        Some(plaintext.to_vec())
    }
}

/// What a TOTP seed is bound to when sealed: its account.
pub fn seed_context(user_id: i64) -> Vec<u8> {
    format!("hawk-totp-v1\0{user_id}").into_bytes()
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B, SHA-1 column, cut to six digits.
    #[test]
    fn rfc6238_vectors() {
        let secret = b"12345678901234567890";
        for (time, expected) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(code_at(secret, (time / STEP) as u64), expected, "at {time}");
        }
    }

    #[test]
    fn accepts_one_step_either_side_only() {
        let secret = b"12345678901234567890";
        let now = 1_111_111_111;
        let step = now / STEP;
        let code = |offset: i64| code_at(secret, (step + offset) as u64);
        assert_eq!(matching_step(secret, &code(0), now), Some(step));
        assert_eq!(matching_step(secret, &code(-1), now), Some(step - 1));
        assert_eq!(matching_step(secret, &code(1), now), Some(step + 1));
        assert_eq!(matching_step(secret, &code(2), now), None);
        assert_eq!(matching_step(secret, &code(-2), now), None);
        let spaced = format!("{} {}", &code(0)[..3], &code(0)[3..]);
        assert_eq!(matching_step(secret, &spaced, now), Some(step));
        assert_eq!(matching_step(secret, "12345", now), None);
        assert_eq!(matching_step(secret, "abcdef", now), None);
    }

    #[test]
    fn base32_round_trip() {
        // RFC 4648 section 10.
        for (plain, encoded) in
            [("", ""), ("f", "MY"), ("fo", "MZXQ"), ("foo", "MZXW6"), ("foob", "MZXW6YQ"), ("fooba", "MZXW6YTB")]
        {
            assert_eq!(base32(plain.as_bytes()), encoded);
            assert_eq!(from_base32(encoded).unwrap(), plain.as_bytes());
        }
        let secret = random_bytes::<SECRET_LEN>();
        assert_eq!(from_base32(&base32(&secret).to_lowercase()).unwrap(), secret);
        assert!(from_base32("not base32!").is_none());
    }

    #[test]
    fn recovery_codes_normalize() {
        let code = new_recovery_code();
        assert_eq!(code.len(), 19);
        assert_eq!(normalize_recovery_code(&code.to_lowercase().replace('-', " ")), code.replace('-', ""));
        assert!(!is_totp_code(&code));
        assert!(is_totp_code("123 456"));
    }

    #[test]
    fn sealed_seeds_stay_with_their_account_and_key() {
        let key = SecretKey::from_bytes(&[7; 32]).unwrap();
        let sealed = key.seal(b"seed", &seed_context(1));
        assert_eq!(key.open(&sealed, &seed_context(1)).unwrap(), b"seed");
        assert!(key.open(&sealed, &seed_context(2)).is_none());
        let other = SecretKey::from_bytes(&[8; 32]).unwrap();
        assert!(other.open(&sealed, &seed_context(1)).is_none());
        assert!(key.open(&sealed[..5], &seed_context(1)).is_none());
    }

    #[test]
    fn otpauth_uri_escapes_names() {
        let uri = otpauth_uri("Hawk relay", "me+x@example.com", b"12345");
        assert_eq!(
            uri,
            "otpauth://totp/Hawk%20relay:me%2Bx@example.com?secret=GEZDGNBV&issuer=Hawk%20relay&algorithm=SHA1&digits=6&period=30"
        );
    }
}
