//! Shared TLS helpers for local admin RPC and peer-to-peer RPC.
//!
//! Local admin files:
//! - `server.pub`: PEM-encoded SubjectPublicKeyInfo (X.509) of the local
//!   daemon cert.
//! - `client.key`: PEM-encoded PKCS#8 Ed25519 private key of the local CLI
//!   client.
//!
//! Local admin TLS:
//! - The local server requires a client cert, then pins the expected client
//!   Ed25519 public key.
//! - The local client pins the server public key by comparing the end-entity
//!   cert's SPKI.
//!
//! Peer TLS:
//! - Peer servers require client certificates and derive peer identity from
//!   the presented Ed25519 public key.
//! - Peer clients pin the expected server onion hostname by validating the
//!   presented Ed25519 certificate against that hostname.

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, SignatureError};
use hyper_util::rt::TokioIo;
use keys::onion_hostname_from_public_key;
use pem::Pem;
// We manually encode a minimal PKCS#8 structure for the client key.
// pkcs8 crate not used directly; we encode minimal PKCS#8 v1 manually.
use rcgen::{
    Certificate, CertificateParams, DistinguishedName as RcDistinguishedName, DnType, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::version::TLS13;
use rustls::{ClientConfig, ServerConfig};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use std::fs;
use std::io;
#[cfg(unix)]
use std::io::Write;
use std::net::IpAddr;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

/// Install the shared Rustls crypto provider for this process once.
pub fn install_process_default_crypto_provider() {
    if CryptoProvider::get_default().is_some() {
        return;
    }

    let _ = crypto_provider().install_default();
}

/// Generate a fresh Ed25519 keypair.
pub fn generate_ed25519() -> Result<(PublicKey, SecretKey)> {
    let kp = Keypair::generate(&mut rand::rngs::OsRng);
    Ok((kp.public, kp.secret))
}

/// Write the local CLI pinning files expected by `bbd` and `bbcli`.
pub fn write_keys(
    dir: impl AsRef<Path>,
    server_pub: &PublicKey,
    client_priv: &SecretKey,
) -> Result<()> {
    let dir = dir.as_ref();
    ensure_owner_only_dir(dir).context("create cli-keys dir")?;
    // server.pub (SPKI)
    let spki_der = public_key_to_spki_der(server_pub)?;
    let spki_pem = Pem::new("PUBLIC KEY", spki_der);
    write_owner_only_file(&dir.join("server.pub"), pem::encode(&spki_pem).as_bytes())
        .context("write server.pub")?;
    // client.key (PKCS#8 minimal v1)
    let client_der = secret_to_pkcs8_der(client_priv);
    let client_pem = Pem::new("PRIVATE KEY", client_der);
    write_owner_only_file(&dir.join("client.key"), pem::encode(&client_pem).as_bytes())
        .context("write client.key")?;
    Ok(())
}

/// Read the local CLI pinning files written by [`write_keys`].
pub fn read_keys(dir: impl AsRef<Path>) -> Result<(PublicKey, SecretKey)> {
    let dir = dir.as_ref();
    if !dir.is_dir() {
        bail!("local CLI key directory {} does not exist", dir.display());
    }

    let server_pub_path = dir.join("server.pub");
    if !server_pub_path.is_file() {
        bail!(
            "expected local CLI server key file at {}",
            server_pub_path.display()
        );
    }

    let client_key_path = dir.join("client.key");
    if !client_key_path.is_file() {
        bail!(
            "expected local CLI client key file at {}",
            client_key_path.display()
        );
    }

    restrict_owner_only_file(&server_pub_path).context("tighten server.pub")?;
    restrict_owner_only_file(&client_key_path).context("tighten client.key")?;
    let spki_pem = fs::read_to_string(&server_pub_path).context("read server.pub")?;
    let spki = pem::parse(spki_pem).context("parse server.pub pem")?;
    if spki.tag() != "PUBLIC KEY" {
        return Err(anyhow!("invalid server.pub tag"));
    }
    let server_pub = spki_der_to_public_key(spki.contents())?;

    let client_pem = fs::read_to_string(&client_key_path).context("read client.key")?;
    let pem = pem::parse(client_pem).context("parse client.key pem")?;
    if pem.tag() != "PRIVATE KEY" {
        return Err(anyhow!("invalid client.key tag"));
    }
    let client_priv = secret_from_pkcs8_der(pem.contents())?;
    Ok((server_pub, client_priv))
}

/// Build a rustls server config for the local CLI daemon.
pub fn build_server_tls(
    expected_client_pub: &PublicKey,
    server_priv: &SecretKey,
) -> Result<ServerConfig> {
    let (server_cert, server_key) = self_signed_cert(server_priv, true)?;
    let verifier = Arc::new(PinClientPublicKeyVerifier {
        expected: expected_client_pub.to_bytes(),
        subjects: vec![],
    });
    let mut cfg = rustls::ServerConfig::builder_with_provider(crypto_provider().into())
        .with_protocol_versions(&[&TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server_cert], server_key)
        .map_err(|e| anyhow!("server cert: {e}"))?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

/// Build a rustls server config for peer-to-peer traffic.
pub fn build_peer_server_tls(server_priv: &SecretKey) -> Result<ServerConfig> {
    let (server_cert, server_key) = self_signed_cert(server_priv, true)?;
    let verifier = Arc::new(AcceptAnyEd25519ClientVerifier { subjects: vec![] });
    let mut cfg = rustls::ServerConfig::builder_with_provider(crypto_provider().into())
        .with_protocol_versions(&[&TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server_cert], server_key)
        .map_err(|e| anyhow!("server cert: {e}"))?;
    cfg.alpn_protocols = vec![transport::PEER_TRANSPORT_ALPN.to_vec()];
    Ok(cfg)
}

/// Build a rustls client config that pins the server public key.
pub fn build_client_tls(
    expected_server_pub: &PublicKey,
    client_priv: &SecretKey,
) -> Result<ClientConfig> {
    let (client_cert, client_key) = self_signed_cert(client_priv, false)?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(crypto_provider().into())
        .with_protocol_versions(&[&TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinServerKeyVerifier {
            expected: expected_server_pub.to_bytes(),
        }))
        .with_client_auth_cert(vec![client_cert], client_key)
        .map_err(|e| anyhow!("client cert: {e}"))?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

/// Build a rustls client config that pins a peer server by onion hostname.
pub fn build_peer_client_tls(
    expected_server_onion: &str,
    client_priv: &SecretKey,
) -> Result<ClientConfig> {
    let (client_cert, client_key) = self_signed_cert(client_priv, false)?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(crypto_provider().into())
        .with_protocol_versions(&[&TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinServerOnionVerifier {
            expected_onion: expected_server_onion.to_string(),
        }))
        .with_client_auth_cert(vec![client_cert], client_key)
        .map_err(|e| anyhow!("client cert: {e}"))?;
    cfg.alpn_protocols = vec![transport::PEER_TRANSPORT_ALPN.to_vec()];
    Ok(cfg)
}

/// Connect a tonic channel using the provided pinned rustls client config.
pub async fn connect_channel(addr: &str, tls: ClientConfig) -> Result<Channel> {
    // Tonic's endpoint URI must stay `http://` because TLS is terminated by the
    // custom connector below rather than by tonic's built-in client TLS stack.
    let endpoint_addr = addr
        .strip_prefix("https://")
        .map(|rest| format!("http://{rest}"))
        .unwrap_or_else(|| addr.to_string());
    let endpoint = Endpoint::from_shared(endpoint_addr)?;
    let uri = endpoint.uri().clone();
    let host = uri
        .host()
        .context("daemon address is missing a host")?
        .to_string();
    let port = uri.port_u16().unwrap_or(443);
    let socket_addr = format!("{host}:{port}");
    let server_name = build_server_name(&host)?;
    let connector = TlsConnector::from(Arc::new(tls));

    let channel = endpoint
        .connect_with_connector(service_fn(move |_| {
            let connector = connector.clone();
            let server_name = server_name.clone();
            let socket_addr = socket_addr.clone();

            async move {
                let tcp_stream = tokio::net::TcpStream::connect(&socket_addr).await?;
                let tls_stream = connector
                    .connect(server_name, tcp_stream)
                    .await
                    .map_err(io::Error::other)?;

                Ok::<_, io::Error>(TokioIo::new(tls_stream))
            }
        }))
        .await?;

    Ok(channel)
}

/// Build the pinned client config and open a tonic channel to the daemon.
pub async fn connect_pinned_channel(
    addr: &str,
    expected_server_pub: &PublicKey,
    client_priv: &SecretKey,
) -> Result<Channel> {
    let tls = build_client_tls(expected_server_pub, client_priv)?;
    connect_channel(addr, tls).await
}

/// Parse an Ed25519 public key from an X.509 certificate.
pub fn public_key_from_certificate_der(certificate_der: &[u8]) -> Result<PublicKey> {
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate_der)
        .map_err(|_| anyhow!("bad certificate"))?;
    let spki = parsed.tbs_certificate.subject_pki;
    if spki.algorithm.algorithm.to_id_string() != "1.3.101.112" {
        return Err(anyhow!("certificate key is not ed25519"));
    }

    PublicKey::from_bytes(spki.subject_public_key.data.as_ref())
        .map_err(|err: SignatureError| anyhow!("{err}"))
}

// No OpenSSL: we use rustls + rustls-post-quantum to enforce TLS 1.3 and the
// hybrid X25519MLKEM768 key exchange groups.

/// Build the rustls crypto provider used for all local and peer connections.
fn crypto_provider() -> CryptoProvider {
    let mut provider = rustls_post_quantum::provider();
    provider.kx_groups = vec![rustls_post_quantum::X25519MLKEM768];
    provider
}

/// Build a rustls server name from a hostname or IP literal.
fn build_server_name(host: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }

    ServerName::try_from(host.to_string())
        .map_err(|err| anyhow!("invalid server name {host:?}: {err}"))
}

/// PinClientPublicKeyVerifier authorizes exactly one Ed25519 client key.
#[derive(Debug)]
struct PinClientPublicKeyVerifier {
    expected: [u8; 32],
    subjects: Vec<DistinguishedName>,
}

impl ClientCertVerifier for PinClientPublicKeyVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let public_key = public_key_from_certificate_der(end_entity.as_ref())
            .map_err(|err| rustls::Error::General(err.to_string()))?;
        if public_key.to_bytes() != self.expected {
            return Err(rustls::Error::General("unauthorized client cert".into()));
        }

        Ok(ClientCertVerified::assertion())
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
        vec![SignatureScheme::ED25519]
    }
}

/// AcceptAnyEd25519ClientVerifier accepts any Ed25519 client certificate.
#[derive(Debug)]
struct AcceptAnyEd25519ClientVerifier {
    subjects: Vec<DistinguishedName>,
}

impl ClientCertVerifier for AcceptAnyEd25519ClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        public_key_from_certificate_der(end_entity.as_ref())
            .map_err(|err| rustls::Error::General(err.to_string()))?;
        Ok(ClientCertVerified::assertion())
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
        vec![SignatureScheme::ED25519]
    }
}

/// PinServerKeyVerifier pins a server certificate to an exact Ed25519 key.
#[derive(Debug)]
struct PinServerKeyVerifier {
    expected: [u8; 32],
}

impl ServerCertVerifier for PinServerKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let public_key = public_key_from_certificate_der(end_entity.as_ref())
            .map_err(|err| rustls::Error::General(err.to_string()))?;
        if public_key.to_bytes() != self.expected {
            return Err(rustls::Error::General("server public key mismatch".into()));
        }

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
        vec![SignatureScheme::ED25519]
    }
}

/// PinServerOnionVerifier pins a server certificate to a Tor onion hostname.
#[derive(Debug)]
struct PinServerOnionVerifier {
    expected_onion: String,
}

impl ServerCertVerifier for PinServerOnionVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let public_key = public_key_from_certificate_der(end_entity.as_ref())
            .map_err(|err| rustls::Error::General(err.to_string()))?;
        let onion = onion_hostname_from_public_key(&public_key);
        if onion != self.expected_onion {
            return Err(rustls::Error::General("server onion mismatch".into()));
        }

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
        vec![SignatureScheme::ED25519]
    }
}

fn self_signed_cert(
    private_key: &SecretKey,
    _server: bool,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let mut params = CertificateParams::new(vec!["localhost".into()]);
    params.distinguished_name = RcDistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "barterbackup-local");
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.alg = &rcgen::PKCS_ED25519;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.subject_alt_names = vec![SanType::DnsName("localhost".into())];
    // Reuse the supplied Ed25519 key so certificate pinning matches the
    // public/private key material written to disk.
    let key_der = secret_to_pkcs8_der(private_key);
    let kp = KeyPair::from_der(&key_der).context("rcgen keypair from pkcs8")?;
    params.key_pair = Some(kp);
    let cert = Certificate::from_params(params).context("rcgen cert")?;
    let der = cert.serialize_der().context("rcgen serialize")?;
    let private_key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(secret_to_pkcs8_der(private_key)));

    Ok((CertificateDer::from(der), private_key_der))
}

fn public_key_to_spki_der(pubkey: &PublicKey) -> Result<Vec<u8>> {
    // Build SPKI for Ed25519: Algorithm OID 1.3.101.112, no params
    // SubjectPublicKey is raw 32 bytes wrapped as BIT STRING (no zero padding for Ed25519)
    // Build SPKI directly:
    // Manual ASN.1 is verbose; instead, encode with simple builder.
    // Here we fall back to a small hardcoded DER for Ed25519 SPKI header + key bytes.
    // SEQ { ALG {1.3.101.112}, BIT STRING 0 unused bits, 32 bytes }
    let mut der = vec![
        0x30, 0x2a, // SEQUENCE, len 42
        0x30, 0x05, // SEQUENCE len 5
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
        0x03, 0x21, 0x00, // BIT STRING len 33, 0 unused bits
    ];
    der.extend_from_slice(pubkey.as_bytes());
    Ok(der)
}

fn spki_der_to_public_key(spki: &[u8]) -> Result<PublicKey> {
    // Expect exactly: SEQ(0x30 0x2a) ALG(0x30 0x05 0x06 0x03 2b 65 70) BITSTRING(0x03 0x21 0x00) + 32 bytes
    if spki.len() != 44 || spki[0..2] != [0x30, 0x2a] {
        return Err(anyhow!("unsupported SPKI format"));
    }
    if spki[2..9] != [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70] {
        return Err(anyhow!("SPKI not Ed25519"));
    }
    if spki[9..12] != [0x03, 0x21, 0x00] {
        return Err(anyhow!("invalid SPKI BIT STRING"));
    }
    PublicKey::from_bytes(&spki[12..44]).map_err(|e: SignatureError| anyhow!("{e}"))
}

/// Create `dir` if needed and tighten it to owner-only permissions.
fn ensure_owner_only_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        // Create any missing directories with private permissions from the
        // start, then repair an older existing directory if needed.
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)?;
    }

    Ok(())
}

/// Tighten one local admin TLS file to owner-only permissions.
fn restrict_owner_only_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

/// Write one local admin TLS file with owner-only permissions.
fn write_owner_only_file(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        // Create the file with private permissions immediately so there is no
        // window where another local user can open it before chmod lands.
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
    }
    restrict_owner_only_file(path)
}

// Minimal PKCS#8 v1 encode/decode for Ed25519 keys.
fn secret_to_pkcs8_der(secret: &SecretKey) -> Vec<u8> {
    // RFC 8410 stores the raw 32-byte seed inside an inner OCTET STRING that
    // becomes the payload of PrivateKeyInfo.privateKey.
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&[0x30, 0x2e]);
    der.extend_from_slice(&[0x02, 0x01, 0x00]);
    der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    der.extend_from_slice(&[0x04, 0x22, 0x04, 0x20]);
    der.extend_from_slice(secret.as_bytes());
    der
}

fn secret_from_pkcs8_der(der: &[u8]) -> Result<SecretKey> {
    if der.len() != 48 || der[0] != 0x30 || der[1] != 0x2e {
        return Err(anyhow!("unsupported PKCS#8 format"));
    }
    if der[2..5] != [0x02, 0x01, 0x00] {
        return Err(anyhow!("bad version"));
    }
    if der[5..12] != [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70] {
        return Err(anyhow!("bad algorithm"));
    }
    if der[12..16] != [0x04, 0x22, 0x04, 0x20] {
        return Err(anyhow!("bad private key"));
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&der[16..48]);
    SecretKey::from_bytes(&sk).map_err(|e| anyhow!("{e}"))
}

// Integration test: spin a TLS server and connect with pinned client.
#[cfg(test)]
mod tests {
    use super::*;

    use futures_util::StreamExt;
    use protos::clirpc::barter_backup_client_client::BarterBackupClientClient;
    use protos::clirpc::barter_backup_client_server::{
        BarterBackupClient, BarterBackupClientServer,
    };
    use protos::clirpc::StateRequest;
    use rustls::crypto::aws_lc_rs;
    use std::net::SocketAddr;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::server::TlsStream;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;
    use tonic::{Request, Status};

    #[derive(Default)]
    struct Hc;

    #[tonic::async_trait]
    impl BarterBackupClient for Hc {
        type TimerInterceptStream = std::pin::Pin<
            Box<
                dyn tokio_stream::Stream<
                        Item = std::result::Result<protos::clirpc::TimerInterceptEvent, Status>,
                    > + Send
                    + 'static,
            >,
        >;
        type GetFileStreamStream = std::pin::Pin<
            Box<
                dyn tokio_stream::Stream<
                        Item = std::result::Result<protos::clirpc::GetFileChunk, Status>,
                    > + Send
                    + 'static,
            >,
        >;
        async fn state(
            &self,
            _req: Request<StateRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::StateResponse>, Status> {
            Ok(tonic::Response::new(protos::clirpc::StateResponse {
                storage_initialized: false,
                server_onion: "".into(),
                uptime_seconds: 1,
                peer_runtime_state: protos::clirpc::PeerRuntimeState::Unknown as i32,
                peer_runtime_error: String::new(),
                self_peer_check_state: protos::clirpc::SelfPeerCheckState::Unknown as i32,
                self_peer_check_error: String::new(),
                local_summary: None,
            }))
        }
        async fn get_test_time(
            &self,
            _: Request<protos::clirpc::GetTestTimeRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::GetTestTimeResponse>, Status>
        {
            Err(Status::unimplemented(""))
        }
        async fn set_test_time(
            &self,
            _: Request<protos::clirpc::SetTestTimeRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::SetTestTimeResponse>, Status>
        {
            Err(Status::unimplemented(""))
        }
        async fn advance_test_time(
            &self,
            _: Request<protos::clirpc::AdvanceTestTimeRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::AdvanceTestTimeResponse>, Status>
        {
            Err(Status::unimplemented(""))
        }
        async fn timer_intercept(
            &self,
            _: Request<protos::clirpc::TimerInterceptRequest>,
        ) -> std::result::Result<tonic::Response<Self::TimerInterceptStream>, Status> {
            Err(Status::unimplemented(""))
        }
        type PublishToPeerStream = std::pin::Pin<
            Box<
                dyn tokio_stream::Stream<
                        Item = std::result::Result<protos::clirpc::PublishToPeerUpdate, Status>,
                    > + Send
                    + 'static,
            >,
        >;
        type VerifyPeerStorageStream = std::pin::Pin<
            Box<
                dyn tokio_stream::Stream<
                        Item = std::result::Result<protos::clirpc::VerifyPeerStorageUpdate, Status>,
                    > + Send
                    + 'static,
            >,
        >;
        async fn init(
            &self,
            _: Request<protos::clirpc::InitRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::InitResponse>, Status> {
            Err(Status::unimplemented(""))
        }
        async fn unlock(
            &self,
            _: Request<protos::clirpc::UnlockRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::UnlockResponse>, Status> {
            Err(Status::unimplemented(""))
        }
        async fn stop(
            &self,
            _: Request<protos::clirpc::StopRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::StopResponse>, Status> {
            Err(Status::unimplemented(""))
        }
        async fn connect_peer(
            &self,
            _: Request<protos::clirpc::ConnectPeerRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::ConnectPeerResponse>, Status>
        {
            Err(Status::unimplemented(""))
        }
        async fn peers(
            &self,
            _: Request<protos::clirpc::PeersRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::PeersResponse>, Status> {
            Err(Status::unimplemented(""))
        }
        async fn pin_peer(
            &self,
            _: Request<protos::clirpc::PinPeerRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::PinPeerResponse>, Status> {
            Err(Status::unimplemented(""))
        }
        async fn unpin_peer(
            &self,
            _: Request<protos::clirpc::UnpinPeerRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::UnpinPeerResponse>, Status>
        {
            Err(Status::unimplemented(""))
        }
        async fn export_built_in_peers(
            &self,
            _: Request<protos::clirpc::ExportBuiltInPeersRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::ExportBuiltInPeersResponse>, Status>
        {
            Err(Status::unimplemented(""))
        }
        async fn set_file_stream(
            &self,
            _: Request<tonic::Streaming<protos::clirpc::SetFileChunk>>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::SetFileResponse>, Status> {
            Err(Status::unimplemented(""))
        }
        async fn delete_file(
            &self,
            _: Request<protos::clirpc::DeleteFileRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::DeleteFileResponse>, Status>
        {
            Err(Status::unimplemented(""))
        }
        async fn get_file_stream(
            &self,
            _: Request<protos::clirpc::GetFileRequest>,
        ) -> std::result::Result<tonic::Response<Self::GetFileStreamStream>, Status> {
            Err(Status::unimplemented(""))
        }
        async fn list_files(
            &self,
            _: Request<protos::clirpc::ListFilesRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::ListFilesResponse>, Status>
        {
            Err(Status::unimplemented(""))
        }
        async fn set_storage_config(
            &self,
            _: Request<protos::clirpc::SetStorageConfigRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::SetStorageConfigResponse>, Status>
        {
            Err(Status::unimplemented(""))
        }
        async fn get_storage_config(
            &self,
            _: Request<protos::clirpc::GetStorageConfigRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::GetStorageConfigResponse>, Status>
        {
            Err(Status::unimplemented(""))
        }
        async fn get_peer_storage(
            &self,
            _: Request<protos::clirpc::GetPeerStorageRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::GetPeerStorageResponse>, Status>
        {
            Err(Status::unimplemented(""))
        }
        async fn publish_to_peer(
            &self,
            _: Request<protos::clirpc::PublishToPeerRequest>,
        ) -> std::result::Result<tonic::Response<Self::PublishToPeerStream>, Status> {
            Err(Status::unimplemented(""))
        }
        async fn verify_peer_storage(
            &self,
            _: Request<protos::clirpc::VerifyPeerStorageRequest>,
        ) -> std::result::Result<tonic::Response<Self::VerifyPeerStorageStream>, Status> {
            Err(Status::unimplemented(""))
        }
        async fn init_complete(
            &self,
            _: Request<protos::clirpc::InitCompleteRequest>,
        ) -> std::result::Result<tonic::Response<protos::clirpc::InitCompleteResponse>, Status>
        {
            Err(Status::unimplemented(""))
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn configs_build_and_keys_roundtrip() -> Result<()> {
        // Generate keys and configs
        let (server_pub, server_priv) = generate_ed25519()?;
        let (client_pub, client_priv) = generate_ed25519()?;
        let srv_cfg = build_server_tls(&client_pub, &server_priv)?;
        let cli_cfg = build_client_tls(&server_pub, &client_priv)?;
        assert!(srv_cfg.alpn_protocols.iter().any(|p| p == b"h2"));
        assert!(cli_cfg.alpn_protocols.iter().any(|p| p == b"h2"));

        // Write/read keys
        let dir = tempfile::tempdir()?;
        write_keys(dir.path(), &server_pub, &client_priv)?;
        let (sp, cp) = read_keys(dir.path())?;
        assert_eq!(sp, server_pub);
        assert_eq!(cp.to_bytes(), client_priv.to_bytes());
        #[cfg(unix)]
        {
            let dir_mode = std::fs::metadata(dir.path())?.permissions().mode() & 0o777;
            let server_mode = std::fs::metadata(dir.path().join("server.pub"))?
                .permissions()
                .mode()
                & 0o777;
            let client_mode = std::fs::metadata(dir.path().join("client.key"))?
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(server_mode, 0o600);
            assert_eq!(client_mode, 0o600);
        }
        Ok(())
    }

    #[test]
    fn read_keys_requires_existing_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let missing = temp_dir.path().join("missing-cli-keys");

        let error = read_keys(&missing).unwrap_err();
        assert!(error.to_string().contains("local CLI key directory"));
        assert!(!missing.exists());
    }

    // Helper: start a PQ-only TLS clirpc server on localhost and return address.
    async fn start_pq_server(
        expected_client_pub: PublicKey,
        server_priv: SecretKey,
    ) -> Result<(String, ServerHandle)> {
        let cfg = build_server_tls(&expected_client_pub, &server_priv)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let svc = BarterBackupClientServer::new(Hc);
        let incoming = TcpListenerStream::new(listener).filter_map(move |result| {
            let tls_acceptor = tls_acceptor.clone();

            async move {
                match result {
                    Ok(socket) => match tls_acceptor.accept(socket).await {
                        Ok(stream) => Some(Ok::<TlsStream<TcpStream>, std::io::Error>(stream)),
                        Err(err) => {
                            eprintln!("tls accept error: {err}");
                            None
                        }
                    },
                    Err(err) => {
                        eprintln!("tcp accept error: {err}");
                        None
                    }
                }
            }
        });

        let handle = tokio::spawn(async move {
            Server::builder()
                .add_service(svc)
                .serve_with_incoming(incoming)
                .await
        });
        Ok((format!("https://{}", addr), ServerHandle(handle)))
    }

    struct ServerHandle(tokio::task::JoinHandle<Result<(), tonic::transport::Error>>);

    impl Drop for ServerHandle {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    /// start_corrupting_proxy flips one byte in the first client TLS flight.
    async fn start_corrupting_proxy(target: SocketAddr) -> Result<ServerHandleWithAddr> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await?;
            let mut server = tokio::net::TcpStream::connect(target).await?;

            // The only configured TLS 1.3 key share is the hybrid
            // X25519MLKEM768 group, so corrupting a byte well inside the first
            // ClientHello payload should break the PQ-backed handshake.
            let mut first_flight = vec![0u8; 4096];
            let read_len = client.read(&mut first_flight).await?;
            if read_len == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "client closed before sending ClientHello",
                ));
            }
            let flip_index = if read_len > 128 { 128 } else { read_len - 1 };
            first_flight[flip_index] ^= 0x01;
            server.write_all(&first_flight[..read_len]).await?;

            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await?;
            Ok(())
        });

        Ok(ServerHandleWithAddr {
            addr: format!("https://{proxy_addr}"),
            handle,
        })
    }

    /// ServerHandleWithAddr keeps one background server task alive.
    struct ServerHandleWithAddr {
        /// addr is the externally reachable `https://` address.
        addr: String,
        /// handle owns the spawned task lifetime.
        handle: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    }

    impl Drop for ServerHandleWithAddr {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    // Client with classical X25519-only provider (no PQ).
    fn x25519_only_client_config(
        server_pub: &PublicKey,
        client_priv: &SecretKey,
    ) -> Result<rustls::ClientConfig> {
        let mut provider = aws_lc_rs::default_provider();
        provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];
        let (client_cert, client_key) = self_signed_cert(client_priv, false)?;
        let cfg = rustls::ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinServerKeyVerifier {
                expected: server_pub.to_bytes(),
            }))
            .with_client_auth_cert(vec![client_cert], client_key)
            .map_err(|e| anyhow!("client cert: {e}"))?;
        Ok(cfg)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pq_server_vs_x25519_client_fails() -> Result<()> {
        let (server_pub, server_priv) = generate_ed25519()?;
        let (client_pub, client_priv) = generate_ed25519()?;
        let (addr, _h) = start_pq_server(client_pub, server_priv).await?;

        let bad_cfg = x25519_only_client_config(&server_pub, &client_priv)?;
        let res = connect_channel(&addr, bad_cfg).await;
        assert!(
            res.is_err(),
            "X25519-only client must not connect to PQ-only server"
        );
        Ok(())
    }

    // Server with classical X25519-only provider.
    fn x25519_only_server_config(
        expected_client_pub: &PublicKey,
        _server_priv: &SecretKey,
    ) -> Result<rustls::ServerConfig> {
        let mut provider = aws_lc_rs::default_provider();
        provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];
        // Generate a self-signed cert for the server
        let (_pub, tmp_priv) = generate_ed25519()?;
        let (cert, key) = self_signed_cert(&tmp_priv, true)?;
        // Custom verifier pinning client pub
        #[derive(Debug)]
        struct PinClient {
            expected: [u8; 32],
            subjects: Vec<DistinguishedName>,
        }
        impl ClientCertVerifier for PinClient {
            fn offer_client_auth(&self) -> bool {
                true
            }
            fn client_auth_mandatory(&self) -> bool {
                true
            }
            fn root_hint_subjects(&self) -> &[DistinguishedName] {
                &self.subjects
            }
            fn verify_client_cert(
                &self,
                end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _now: UnixTime,
            ) -> Result<ClientCertVerified, rustls::Error> {
                let (_, parsed) = x509_parser::parse_x509_certificate(end_entity.as_ref())
                    .map_err(|_| rustls::Error::General("bad client cert".into()))?;
                let spki = parsed.tbs_certificate.subject_pki;
                if spki.algorithm.algorithm.to_id_string() != "1.3.101.112" {
                    return Err(rustls::Error::General("client cert not ed25519".into()));
                }
                if spki.subject_public_key.data.as_ref() != self.expected {
                    return Err(rustls::Error::General("unauthorized client cert".into()));
                }
                Ok(ClientCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _m: &[u8],
                _c: &CertificateDer<'_>,
                _d: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _m: &[u8],
                _c: &CertificateDer<'_>,
                _d: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![SignatureScheme::ED25519]
            }
        }
        let verifier = Arc::new(PinClient {
            expected: expected_client_pub.to_bytes(),
            subjects: vec![],
        });
        let cfg = rustls::ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)
            .map_err(|e| anyhow!("server cert: {e}"))?;
        Ok(cfg)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pq_client_vs_x25519_server_fails() -> Result<()> {
        let (server_pub, server_priv) = generate_ed25519()?;
        let (client_pub, client_priv) = generate_ed25519()?;

        // Start X25519-only server
        let srv_cfg = x25519_only_server_config(&client_pub, &server_priv)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv_cfg));
        let svc = BarterBackupClientServer::new(Hc);
        let incoming = TcpListenerStream::new(listener).filter_map(move |result| {
            let tls_acceptor = tls_acceptor.clone();

            async move {
                match result {
                    Ok(socket) => match tls_acceptor.accept(socket).await {
                        Ok(stream) => Some(Ok::<TlsStream<TcpStream>, std::io::Error>(stream)),
                        Err(err) => {
                            eprintln!("tls accept error: {err}");
                            None
                        }
                    },
                    Err(err) => {
                        eprintln!("tcp accept error: {err}");
                        None
                    }
                }
            }
        });
        let _h = tokio::spawn(async move {
            Server::builder()
                .add_service(svc)
                .serve_with_incoming(incoming)
                .await
        });

        // PQ-only client should fail to connect
        let good_cfg = build_client_tls(&server_pub, &client_priv)?;
        let res = connect_channel(&format!("https://{}", addr), good_cfg).await;
        assert!(
            res.is_err(),
            "PQ-only client must not connect to X25519-only server"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pq_client_and_server_succeed() -> Result<()> {
        let (server_pub, server_priv) = generate_ed25519()?;
        let (client_pub, client_priv) = generate_ed25519()?;
        let (addr, _h) = start_pq_server(client_pub, server_priv).await?;
        let good_cfg = build_client_tls(&server_pub, &client_priv)?;
        let channel = connect_channel(&addr, good_cfg).await?;
        let mut cli = BarterBackupClientClient::new(channel);
        let _ = cli.state(StateRequest {}).await; // Will likely fail due to dummy svc, but handshake succeeded.
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn corrupted_pq_client_hello_fails() -> Result<()> {
        let (server_pub, server_priv) = generate_ed25519()?;
        let (client_pub, client_priv) = generate_ed25519()?;
        let (server_addr, _server) = start_pq_server(client_pub, server_priv).await?;
        let target = server_addr
            .strip_prefix("https://")
            .context("strip server scheme")?
            .parse::<SocketAddr>()?;
        let proxy = start_corrupting_proxy(target).await?;

        let good_cfg = build_client_tls(&server_pub, &client_priv)?;
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            connect_channel(&proxy.addr, good_cfg),
        )
        .await;
        assert!(
            matches!(result, Ok(Err(_)) | Err(_)),
            "tampering with the PQ ClientHello flight must fail"
        );

        Ok(())
    }
}
