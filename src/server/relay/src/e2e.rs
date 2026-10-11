//! The signed statements end-to-end encryption rests on, as far as the relay
//! deals with them. The relay can't read the stream, so it can't be trusted
//! to decide who may: the owner's browser signs who may watch (grants and
//! revocations) and which key is really their machine's (endorsements),
//! and the machine and the viewers' browsers check those signatures
//! themselves. The relay only stores and passes them on. It also checks
//! them here, so a buggy dashboard can't store a share the machine would
//! refuse, but nothing depends on the relay doing so.
//!
//! A statement is UTF-8 text: a context line, then `key=value` lines, joined
//! with "\n". It's signed with ECDSA P-256 / SHA-256 (r || s), and whoever
//! checks it parses the signed text itself, so nothing is re-serialized.
//! The machine (src/service/e2e.cpp) and the dashboard
//! (frontend/src/e2e.ts) read the same formats.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

use crate::db::{Role, ShareTerms, Signed};

pub const GRANT_CONTEXT: &str = "hawk-grant-v1";
pub const REVOKE_CONTEXT: &str = "hawk-revoke-v1";
pub const MACHINE_CONTEXT: &str = "hawk-machine-v1";

/// An uncompressed P-256 point: 0x04 || X || Y.
pub const P256_PUBLIC_KEY_LEN: usize = 65;

pub fn is_public_key(key: &[u8]) -> bool {
    key.len() == P256_PUBLIC_KEY_LEN && key[0] == 0x04
}

/// Whether `signed` carries a valid signature by `public_key`.
pub fn verify(public_key: &[u8], signed: &Signed) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
        .verify(signed.statement.as_bytes(), &signed.signature)
        .is_ok()
}

/// The `key=value` lines of a statement with this context, or None if it
/// has another one, a malformed line, or a key twice.
pub fn fields<'a>(statement: &'a str, context: &str) -> Option<HashMap<&'a str, &'a str>> {
    let mut lines = statement.split('\n');
    if lines.next()? != context {
        return None;
    }
    let mut fields = HashMap::new();
    for line in lines {
        let (key, value) = line.split_once('=')?;
        if fields.insert(key, value).is_some() {
            return None;
        }
    }
    Some(fields)
}

/// What the owner signs to vouch for their machine's key.
pub fn machine_statement(machine_id: &str, machine_key: &[u8]) -> String {
    format!("{MACHINE_CONTEXT}\nmachine={machine_id}\nkey={}", BASE64.encode(machine_key))
}

fn optional_time(value: Option<i64>) -> String {
    value.map_or_else(|| "-".to_owned(), |time| time.to_string())
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::View => "view",
        Role::Control | Role::Owner => "control",
    }
}

/// Why a grant or revocation doesn't fit the share it came with.
#[derive(Debug, PartialEq, Eq)]
pub enum Mismatch {
    Signature,
    Malformed,
    Field(&'static str),
}

impl Mismatch {
    pub fn message(&self) -> String {
        match self {
            Self::Signature => "the signature doesn't match your key".to_owned(),
            Self::Malformed => "the signed statement is malformed".to_owned(),
            Self::Field(field) => format!("the signed {field} doesn't match the share"),
        }
    }
}

fn expect(fields: &HashMap<&str, &str>, key: &'static str, value: &str) -> Result<(), Mismatch> {
    if fields.get(key).copied() == Some(value) { Ok(()) } else { Err(Mismatch::Field(key)) }
}

fn issued(fields: &HashMap<&str, &str>) -> Result<i64, Mismatch> {
    fields.get("issued").and_then(|value| value.parse().ok()).ok_or(Mismatch::Field("issued"))
}

/// Checks that `grant` is the owner's signature over exactly these share
/// terms, for this machine and this viewer key.
pub fn check_grant(
    grant: &Signed,
    owner_key: &[u8],
    machine_id: &str,
    viewer_key: &[u8],
    terms: &ShareTerms,
) -> Result<(), Mismatch> {
    if !verify(owner_key, grant) {
        return Err(Mismatch::Signature);
    }
    let fields = fields(&grant.statement, GRANT_CONTEXT).ok_or(Mismatch::Malformed)?;
    expect(&fields, "machine", machine_id)?;
    expect(&fields, "viewer", &BASE64.encode(viewer_key))?;
    expect(&fields, "role", role_name(terms.role))?;
    expect(&fields, "not_before", &optional_time(terms.starts_at))?;
    expect(&fields, "not_after", &optional_time(terms.expires_at))?;
    expect(&fields, "single_view", if terms.single_view { "1" } else { "0" })?;
    issued(&fields)?;
    if fields.len() != 7 {
        return Err(Mismatch::Malformed);
    }
    Ok(())
}

/// Checks that `revocation` is the owner's signature taking this machine
/// away from this viewer key, issued after `grant` (if there was one).
pub fn check_revocation(
    revocation: &Signed,
    owner_key: &[u8],
    machine_id: &str,
    viewer_key: &[u8],
    grant: Option<&Signed>,
) -> Result<(), Mismatch> {
    if !verify(owner_key, revocation) {
        return Err(Mismatch::Signature);
    }
    let fields = fields(&revocation.statement, REVOKE_CONTEXT).ok_or(Mismatch::Malformed)?;
    expect(&fields, "machine", machine_id)?;
    expect(&fields, "viewer", &BASE64.encode(viewer_key))?;
    let revoked = issued(&fields)?;
    if fields.len() != 3 {
        return Err(Mismatch::Malformed);
    }
    let granted = grant
        .and_then(|grant| self::fields(&grant.statement, GRANT_CONTEXT))
        .and_then(|fields| issued(&fields).ok());
    if granted.is_some_and(|granted| revoked <= granted) {
        return Err(Mismatch::Field("issued"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    use super::*;

    fn key_pair() -> EcdsaKeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap()
    }

    fn sign(key: &EcdsaKeyPair, statement: &str) -> Signed {
        let signature = key.sign(&SystemRandom::new(), statement.as_bytes()).unwrap();
        Signed { statement: statement.to_owned(), signature: signature.as_ref().to_vec() }
    }

    const TERMS: ShareTerms = ShareTerms { role: Role::Control, starts_at: None, expires_at: Some(2000), single_view: true };

    fn grant_text(viewer: &[u8], issued: i64) -> String {
        format!(
            "hawk-grant-v1\nmachine=m1\nviewer={}\nrole=control\nnot_before=-\nnot_after=2000\nsingle_view=1\nissued={issued}",
            BASE64.encode(viewer)
        )
    }

    #[test]
    fn grant_must_match_terms_and_key() {
        let owner = key_pair();
        let viewer = key_pair();
        let viewer_key = viewer.public_key().as_ref();
        let owner_key = owner.public_key().as_ref();
        let grant = sign(&owner, &grant_text(viewer_key, 1));
        assert_eq!(check_grant(&grant, owner_key, "m1", viewer_key, &TERMS), Ok(()));

        let other_terms = ShareTerms { role: Role::View, ..TERMS };
        assert_eq!(check_grant(&grant, owner_key, "m1", viewer_key, &other_terms), Err(Mismatch::Field("role")));
        assert_eq!(check_grant(&grant, owner_key, "m2", viewer_key, &TERMS), Err(Mismatch::Field("machine")));
        let forged = sign(&viewer, &grant_text(viewer_key, 1));
        assert_eq!(check_grant(&forged, owner_key, "m1", viewer_key, &TERMS), Err(Mismatch::Signature));
        let extra = sign(&owner, &format!("{}\nextra=1", grant_text(viewer_key, 1)));
        assert_eq!(check_grant(&extra, owner_key, "m1", viewer_key, &TERMS), Err(Mismatch::Malformed));
    }

    #[test]
    fn revocation_must_come_after_the_grant() {
        let owner = key_pair();
        let viewer = key_pair();
        let viewer_key = viewer.public_key().as_ref();
        let owner_key = owner.public_key().as_ref();
        let grant = sign(&owner, &grant_text(viewer_key, 10));
        let revoke = |issued: i64| {
            sign(&owner, &format!("hawk-revoke-v1\nmachine=m1\nviewer={}\nissued={issued}", BASE64.encode(viewer_key)))
        };
        assert_eq!(check_revocation(&revoke(11), owner_key, "m1", viewer_key, Some(&grant)), Ok(()));
        assert_eq!(
            check_revocation(&revoke(10), owner_key, "m1", viewer_key, Some(&grant)),
            Err(Mismatch::Field("issued"))
        );
        assert_eq!(check_revocation(&revoke(1), owner_key, "m1", viewer_key, None), Ok(()));
    }

    #[test]
    fn fields_reject_duplicates_and_other_contexts() {
        assert!(fields("hawk-grant-v1\na=1\na=2", GRANT_CONTEXT).is_none());
        assert!(fields("hawk-revoke-v1\na=1", GRANT_CONTEXT).is_none());
        assert!(fields("hawk-grant-v1\nnoequals", GRANT_CONTEXT).is_none());
        assert_eq!(fields("hawk-grant-v1\na=b=c", GRANT_CONTEXT).unwrap()["a"], "b=c");
    }
}
