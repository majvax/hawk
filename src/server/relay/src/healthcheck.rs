//! `hawk-relay healthcheck`: asks the relay running beside it for
//! `/healthz`, for a container's HEALTHCHECK where there's no curl. Exits 0
//! when it answers 204, 1 otherwise.
//!
//! It reads the same environment as the relay, so it knows the port and
//! whether to speak TLS. The certificate isn't judged by a CA (it may well
//! be self-signed): the relay must present the key in its own
//! TLS_CERT_PATH, the same pin machines check.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

const TIMEOUT: Duration = Duration::from_secs(5);

/// Accepts the one key the relay is configured with, whatever signed it.
#[derive(Debug)]
struct OwnKey {
    pin: String,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for OwnKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match crate::spki_pin(end_entity) {
            Ok(pin) if pin == self.pin => Ok(ServerCertVerified::assertion()),
            _ => Err(rustls::Error::General("not the relay's own key".into())),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Where to reach the relay from inside its own host: loopback when it
/// listens on every interface.
fn target(listen: SocketAddr) -> SocketAddr {
    let ip = if listen.ip().is_unspecified() { IpAddr::V4(Ipv4Addr::LOCALHOST) } else { listen.ip() };
    SocketAddr::new(ip, listen.port())
}

/// The status line's code.
fn status(response: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(response).ok()?.lines().next()?;
    let mut parts = line.split_whitespace();
    parts.next().filter(|version| version.starts_with("HTTP/"))?;
    parts.next()?.parse().ok()
}

fn request(stream: &mut impl ReadWrite, host: SocketAddr) -> Result<u16, String> {
    let request = format!("GET /healthz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(|error| error.to_string())?;
    let mut head = [0u8; 64];
    let read = stream.read(&mut head).map_err(|error| error.to_string())?;
    status(&head[..read]).ok_or_else(|| "not an HTTP answer".to_owned())
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// One check: Ok when `/healthz` answered 204.
pub fn check(listen: SocketAddr, tls_cert: Option<&std::path::Path>) -> Result<(), String> {
    let address = target(listen);
    let socket = TcpStream::connect_timeout(&address, TIMEOUT).map_err(|error| format!("{address}: {error}"))?;
    socket.set_read_timeout(Some(TIMEOUT)).map_err(|error| error.to_string())?;
    socket.set_write_timeout(Some(TIMEOUT)).map_err(|error| error.to_string())?;
    let code = match tls_cert {
        None => request(&mut { socket }, address)?,
        Some(path) => {
            let cert = CertificateDer::from_pem_file(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let verifier = OwnKey { pin: crate::spki_pin(&cert)?, algorithms: provider.signature_verification_algorithms };
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|error| error.to_string())?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
            let name = ServerName::IpAddress(address.ip().into());
            let connection =
                rustls::ClientConnection::new(Arc::new(config), name).map_err(|error| error.to_string())?;
            request(&mut rustls::StreamOwned::new(connection, socket), address)?
        }
    };
    if code == 204 { Ok(()) } else { Err(format!("/healthz answered {code}")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_status_and_finds_the_relay() {
        assert_eq!(status(b"HTTP/1.1 204 No Content\r\n\r\n"), Some(204));
        assert_eq!(status(b"HTTP/1.1 503 Service Unavailable\r\n"), Some(503));
        assert_eq!(status(b"SSH-2.0-OpenSSH\r\n"), None);
        assert_eq!(status(b""), None);
        assert_eq!(target("0.0.0.0:8443".parse().unwrap()), "127.0.0.1:8443".parse().unwrap());
        assert_eq!(target("[::]:443".parse().unwrap()), "127.0.0.1:443".parse().unwrap());
        assert_eq!(target("10.0.0.5:80".parse().unwrap()), "10.0.0.5:80".parse().unwrap());
    }

    /// Against a plain HTTP listener answering like the relay does.
    #[test]
    fn checks_a_plain_relay() {
        for (answer, healthy) in [("HTTP/1.1 204 No Content\r\n\r\n", true), ("HTTP/1.1 503 Nope\r\n\r\n", false)] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 256];
                let read = stream.read(&mut request).unwrap();
                assert!(request[..read].starts_with(b"GET /healthz HTTP/1.1\r\n"));
                stream.write_all(answer.as_bytes()).unwrap();
            });
            assert_eq!(check(addr, None).is_ok(), healthy, "{answer}");
            server.join().unwrap();
        }
    }
}
