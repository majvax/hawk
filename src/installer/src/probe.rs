//! Reaches a relay before anything is installed: is it there, and is its
//! key the one the person was told to pin? The certificate isn't judged
//! here: with a pin, the pin is what the machine trusts (and what this
//! compares), and without one the service checks the chain itself.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

/// A relay address as a person types it, as the pieces the probe and the
/// service need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAddress {
    pub host: String,
    pub port: u16,
}

impl RelayAddress {
    /// "relay.example.com", "relay.example.com:8443", "https://…" or a
    /// pasted "wss://…/v1/ws" all work.
    pub fn parse(input: &str) -> Result<Self, String> {
        let text = input.trim();
        let rest = text.split_once("://").map_or(text, |(scheme, rest)| {
            if matches!(scheme, "https" | "wss") { rest } else { "" }
        });
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() {
            return Err(format!("\"{text}\" isn't a relay address like relay.example.com or https://relay.example.com"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.ends_with(']') || port.parse::<u16>().is_ok() => {
                (host, port.parse::<u16>().map_err(|_| format!("\"{port}\" isn't a port"))?)
            }
            _ => (authority, 443),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() || host.contains(char::is_whitespace) {
            return Err(format!("\"{text}\" isn't a relay address"));
        }
        Ok(Self { host: host.to_owned(), port })
    }

    /// What the service connects to.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn socket_url(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == 443 { format!("wss://{host}/v1/ws") } else { format!("wss://{host}:{}/v1/ws", self.port) }
    }

    pub fn display(&self) -> String {
        if self.port == 443 { self.host.clone() } else { format!("{}:{}", self.host, self.port) }
    }
}

/// Base64 SHA-256 of a certificate's SubjectPublicKeyInfo: what the relay
/// prints and machines pin (see spki_pin in the relay's main.rs).
pub fn spki_pin(certificate: &[u8]) -> Result<String, String> {
    let der = CertificateDer::from(certificate);
    let parsed =
        webpki::EndEntityCert::try_from(&der).map_err(|error| format!("unreadable certificate: {error}"))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(Sha256::digest(parsed.subject_public_key_info().as_ref())))
}

/// A pin as people paste it: 44 base64 characters ending in '='.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn valid_pin(pin: &str) -> bool {
    let pin = pin.trim();
    pin.len() == 44
        && pin.ends_with('=')
        && base64::engine::general_purpose::STANDARD.decode(pin).is_ok_and(|bytes| bytes.len() == 32)
}

#[derive(Debug)]
struct Recorder {
    leaf: Mutex<Option<Vec<u8>>>,
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.leaf.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(end_entity.to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// Connects, finishes a TLS handshake and returns the relay's key pin.
/// Nothing is sent but the handshake.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn relay_pin(address: &RelayAddress) -> Result<String, String> {
    connect(address).map(|(_, pin)| pin)
}

/// The HTTP status of `GET path` on a relay, over TLS whatever its
/// certificate: for checking a relay this machine just started.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn http_status(address: &RelayAddress, path: &str) -> Result<u16, String> {
    use std::io::{Read, Write};
    let (mut stream, _) = connect(address)?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", address.display());
    stream.write_all(request.as_bytes()).map_err(|error| error.to_string())?;
    let mut head = [0u8; 64];
    let read = stream.read(&mut head).map_err(|error| error.to_string())?;
    let line = String::from_utf8_lossy(&head[..read]);
    line.split_whitespace().nth(1).and_then(|code| code.parse().ok()).ok_or_else(|| "not an HTTP answer".into())
}

type TlsStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn connect(address: &RelayAddress) -> Result<(TlsStream, String), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let recorder = Arc::new(Recorder {
        leaf: Mutex::new(None),
        schemes: provider.signature_verification_algorithms.supported_schemes(),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(address.host.clone()).map_err(|error| format!("{}: {error}", address.host))?;
    let mut connection =
        rustls::ClientConnection::new(Arc::new(config), name).map_err(|error| error.to_string())?;

    let targets: Vec<_> = (address.host.as_str(), address.port)
        .to_socket_addrs()
        .map_err(|error| format!("can't find {}: {error}", address.display()))?
        .collect();
    // Every address in turn, as the service does: a name with an IPv6
    // address that drops packets mustn't hide a working IPv4 one.
    let mut failures = Vec::new();
    let mut socket = targets
        .iter()
        .find_map(|target| match TcpStream::connect_timeout(target, Duration::from_secs(5)) {
            Ok(socket) => Some(socket),
            Err(error) => {
                failures.push(format!("{}: {error}", target.ip()));
                None
            }
        })
        .ok_or_else(|| {
            if failures.is_empty() {
                format!("can't find {}", address.display())
            } else {
                format!("can't reach {} ({})", address.display(), failures.join("; "))
            }
        })?;
    socket.set_read_timeout(Some(Duration::from_secs(10))).map_err(|error| error.to_string())?;
    socket.set_write_timeout(Some(Duration::from_secs(10))).map_err(|error| error.to_string())?;
    while connection.is_handshaking() {
        connection
            .complete_io(&mut socket)
            .map_err(|error| format!("{} didn't complete a TLS handshake: {error}", address.display()))?;
    }
    let leaf = recorder.leaf.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
    let pin = spki_pin(&leaf.ok_or("the relay sent no certificate")?)?;
    Ok((rustls::StreamOwned::new(connection, socket), pin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_addresses() {
        let plain = RelayAddress::parse("relay.example.com").unwrap();
        assert_eq!(plain, RelayAddress { host: "relay.example.com".into(), port: 443 });
        assert_eq!(plain.socket_url(), "wss://relay.example.com/v1/ws");
        let port = RelayAddress::parse("https://10.0.0.5:8080/").unwrap();
        assert_eq!(port.socket_url(), "wss://10.0.0.5:8080/v1/ws");
        assert_eq!(RelayAddress::parse("wss://relay.example.com/v1/ws").unwrap().port, 443);
        assert_eq!(RelayAddress::parse("[::1]:8080").unwrap().socket_url(), "wss://[::1]:8080/v1/ws");
        assert!(RelayAddress::parse("http://relay.example.com").is_err());
        assert!(RelayAddress::parse("").is_err());
    }

    #[test]
    fn checks_pins() {
        assert!(valid_pin("wqsPIpg8z3m1sJ0xJHZfXQ3u8F2c0aY4hX2b7f9xW0A="));
        assert!(!valid_pin("wqsPIpg8"));
    }
}
