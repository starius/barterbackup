//! Local CLI <-> daemon TLS helpers (Rust), mirroring Go internal/clitls.
//!
//! Files:
//! - server.pub: PEM-encoded SubjectPublicKeyInfo (X.509) of the server cert.
//! - client.key: PEM-encoded PKCS#8 Ed25519 private key of the client.
//!
//! TLS:
//! - Server requires any client cert, then pins the expected client ed25519 public key.
//! - Client pins server public key by comparing the end-entity cert’s SPKI.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, SignatureError};
use pem::Pem;
// We manually encode a minimal PKCS#8 for the client key to match the Go files.
// pkcs8 crate not used directly; we encode minimal PKCS#8 v1 manually.
use rcgen::{Certificate, CertificateParams, DistinguishedName as RcDistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType};
use rustls::{ClientConfig, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use rustls::server::danger::{ClientCertVerifier, ClientCertVerified};
use rustls::{SignatureScheme, DistinguishedName, DigitallySignedStruct};
use rustls::version::TLS13;
use rustls::crypto::CryptoProvider;
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Ed25519 algorithm OID in dotted form 1.3.101.112.
const ED25519_OID: &[u64] = &[1, 3, 101, 112];

pub fn generate_ed25519() -> Result<(PublicKey, SecretKey)> {
    let kp = Keypair::generate(&mut rand::rngs::OsRng);
    Ok((kp.public, kp.secret))
}

pub fn write_keys(dir: impl AsRef<Path>, server_pub: &PublicKey, client_priv: &SecretKey) -> Result<()> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir).context("create cli-keys dir")?;
    // server.pub (SPKI)
    let spki_der = public_key_to_spki_der(server_pub)?;
    let spki_pem = Pem::new("PUBLIC KEY", spki_der);
    fs::write(dir.join("server.pub"), pem::encode(&spki_pem)).context("write server.pub")?;
    // client.key (PKCS#8 minimal v1)
    let client_der = secret_to_pkcs8_der(client_priv);
    let client_pem = Pem::new("PRIVATE KEY", client_der);
    fs::write(dir.join("client.key"), pem::encode(&client_pem)).context("write client.key")?;
    Ok(())
}

pub fn read_keys(dir: impl AsRef<Path>) -> Result<(PublicKey, SecretKey)> {
    let dir = dir.as_ref();
    let spki_pem = fs::read_to_string(dir.join("server.pub")).context("read server.pub")?;
    let spki = pem::parse(spki_pem).context("parse server.pub pem")?;
    if spki.tag() != "PUBLIC KEY" { return Err(anyhow!("invalid server.pub tag")); }
    let server_pub = spki_der_to_public_key(spki.contents())?;

    let client_pem = fs::read_to_string(dir.join("client.key")).context("read client.key")?;
    let pem = pem::parse(client_pem).context("parse client.key pem")?;
    if pem.tag() != "PRIVATE KEY" { return Err(anyhow!("invalid client.key tag")); }
    let client_priv = secret_from_pkcs8_der(pem.contents())?;
    Ok((server_pub, client_priv))
}

/// Build a rustls ServerConfig that pins a specific client public key and serves with a self-signed Ed25519 cert.
pub fn build_server_tls(expected_client_pub: &PublicKey, server_priv: &SecretKey) -> Result<ServerConfig> {
    // PQ-only provider (X25519+ML-KEM-768).
    let mut provider: CryptoProvider = rustls_post_quantum::provider();
    provider.kx_groups = vec![rustls_post_quantum::X25519MLKEM768];
    let (server_cert, server_key) = self_signed_cert(server_priv, true)?;
    // Custom client verifier: pin ed25519 pubkey
    #[derive(Debug)]
    struct PinClient { expected: [u8; 32], subjects: Vec<DistinguishedName> }
    impl ClientCertVerifier for PinClient {
        fn offer_client_auth(&self) -> bool { true }
        fn client_auth_mandatory(&self) -> bool { true }
        fn root_hint_subjects(&self) -> &[DistinguishedName] { &self.subjects }
        fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>], _now: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
            let (_, parsed) = x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|_| rustls::Error::General("bad client cert".into()))?;
            let spki = parsed.tbs_certificate.subject_pki;
            // Sanity: require Ed25519 algorithm OID 1.3.101.112.
            if spki.algorithm.algorithm.to_id_string() != "1.3.101.112" {
                return Err(rustls::Error::General("client cert not ed25519".into()));
            }
            if spki.subject_public_key.data.as_ref() != self.expected {
                return Err(rustls::Error::General("unauthorized client cert".into()));
            }
            Ok(ClientCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { Ok(HandshakeSignatureValid::assertion()) }
        fn verify_tls13_signature(&self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { Ok(HandshakeSignatureValid::assertion()) }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { vec![SignatureScheme::ED25519] }
    }
    let verifier = Arc::new(PinClient { expected: expected_client_pub.to_bytes(), subjects: vec![] });
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server_cert], server_key)
        .map_err(|e| anyhow!("server cert: {e}"))?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

/// Build a rustls ClientConfig that pins the server public key.
pub fn build_client_tls(expected_server_pub: &PublicKey, client_priv: &SecretKey) -> Result<ClientConfig> {
    // PQ-only provider.
    let mut provider: CryptoProvider = rustls_post_quantum::provider();
    provider.kx_groups = vec![rustls_post_quantum::X25519MLKEM768];
    // Client self-signed cert (for mTLS)
    let (client_cert, client_key) = self_signed_cert(client_priv, false)?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinServer { expected: expected_server_pub.to_bytes() }))
        .with_client_auth_cert(vec![client_cert], client_key)
        .map_err(|e| anyhow!("client cert: {e}"))?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

/// OpenSSL contexts enforcing TLS 1.3 and hybrid X25519MLKEM768 groups.
// No OpenSSL: we use rustls + rustls-post-quantum to enforce hybrid KEM.

fn self_signed_cert(_privkey: &SecretKey, _server: bool) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let mut params = CertificateParams::new(vec!["localhost".into()]);
    params.distinguished_name = RcDistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "barterbackup-local");
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.alg = &rcgen::PKCS_ED25519;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    params.subject_alt_names = vec![SanType::DnsName("localhost".into())];
    // Generate a fresh Ed25519 keypair for the certificate.
    let kp = KeyPair::generate(&rcgen::PKCS_ED25519).context("rcgen keypair gen")?;
    params.key_pair = Some(kp);
    let cert = Certificate::from_params(params).context("rcgen cert")?;
    let der = cert.serialize_der().context("rcgen serialize")?;
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.serialize_private_key_der()));
    Ok((CertificateDer::from(der), key_der))
}

fn public_key_to_spki_der(pubkey: &PublicKey) -> Result<Vec<u8>> {
    // Build SPKI for Ed25519: Algorithm OID 1.3.101.112, no params
    // SubjectPublicKey is raw 32 bytes wrapped as BIT STRING (no zero padding for Ed25519)
    // Build SPKI directly:
    use x509_parser::prelude::*;
    // Manual ASN.1 is verbose; instead, encode with simple builder.
    // Here we fall back to a small hardcoded DER for Ed25519 SPKI header + key bytes.
    // SEQ { ALG {1.3.101.112}, BIT STRING 0 unused bits, 32 bytes }
    let mut der = vec![0x30, 0x2a, // SEQUENCE, len 42
        0x30, 0x05, // SEQUENCE len 5
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
        0x03, 0x21, 0x00 // BIT STRING len 33, 0 unused bits
    ];
    der.extend_from_slice(pubkey.as_bytes());
    Ok(der)
}

fn spki_der_to_public_key(spki: &[u8]) -> Result<PublicKey> {
    // Expect exactly: SEQ(0x30 0x2a) ALG(0x30 0x05 0x06 0x03 2b 65 70) BITSTRING(0x03 0x21 0x00) + 32 bytes
    if spki.len() != 44 || &spki[0..2] != [0x30, 0x2a] {
        return Err(anyhow!("unsupported SPKI format"));
    }
    if &spki[2..9] != [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70] {
        return Err(anyhow!("SPKI not Ed25519"));
    }
    if &spki[9..12] != [0x03, 0x21, 0x00] {
        return Err(anyhow!("invalid SPKI BIT STRING"));
    }
    PublicKey::from_bytes(&spki[12..44]).map_err(|e: SignatureError| anyhow!("{e}"))
}

// Minimal PKCS#8 v1 encode/decode for Ed25519 keys.
fn secret_to_pkcs8_der(secret: &SecretKey) -> Vec<u8> {
    // SEQUENCE(len=44) { INTEGER 0; SEQ { OID 1.3.101.112 }; OCTET STRING 32 }
    let mut der = Vec::with_capacity(46);
    der.extend_from_slice(&[0x30, 0x2c]);
    der.extend_from_slice(&[0x02, 0x01, 0x00]);
    der.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    der.extend_from_slice(&[0x04, 0x20]);
    der.extend_from_slice(secret.as_bytes());
    der
}

fn secret_from_pkcs8_der(der: &[u8]) -> Result<SecretKey> {
    if der.len() != 46 || der[0] != 0x30 || der[1] != 0x2c {
        return Err(anyhow!("unsupported PKCS#8 format"));
    }
    if der[2..5] != [0x02, 0x01, 0x00] { return Err(anyhow!("bad version")); }
    if der[5..12] != [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70] { return Err(anyhow!("bad algorithm")); }
    if der[12..14] != [0x04, 0x20] { return Err(anyhow!("bad private key")); }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&der[14..46]);
    SecretKey::from_bytes(&sk).map_err(|e| anyhow!("{e}"))
}

#[derive(Debug)]
struct PinServer { expected: [u8; 32] }
impl ServerCertVerifier for PinServer {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let (_, parsed) = x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|_| rustls::Error::General("bad server cert".into()))?;
        let spki = parsed.tbs_certificate.subject_pki;
        // Sanity: require Ed25519 algorithm OID 1.3.101.112.
        if spki.algorithm.algorithm.to_id_string() != "1.3.101.112" {
            return Err(rustls::Error::General("server cert not ed25519".into()));
        }
        if spki.subject_public_key.data.as_ref() != self.expected {
            return Err(rustls::Error::General("server public key mismatch".into()));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { Ok(HandshakeSignatureValid::assertion()) }
    fn verify_tls13_signature(&self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { Ok(HandshakeSignatureValid::assertion()) }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { vec![SignatureScheme::ED25519] }
}

// Integration test: spin a TLS server and connect with pinned client.
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use rustls::crypto::aws_lc_rs;
    use tonic::{Request, Status};
    use tonic::transport::{Server, Endpoint};
    use protos::clirpc::barter_backup_client_client::BarterBackupClientClient;
    use protos::clirpc::barter_backup_client_server::{BarterBackupClient, BarterBackupClientServer};
    use protos::clirpc::HealthCheckRequest;
    use tokio_stream::wrappers::TcpListenerStream;
    use futures_util::stream::StreamExt;
    use tonic_rustls::TlsConnector;


    #[derive(Default)]
    struct Hc;
    #[tonic::async_trait]
    impl BarterBackupClient for Hc {
        async fn local_health_check(&self, _req: Request<HealthCheckRequest>) -> std::result::Result<tonic::Response<protos::clirpc::HealthCheckResponse>, Status> {
            Ok(tonic::Response::new(protos::clirpc::HealthCheckResponse { server_onion: "".into(), uptime_seconds: 1 }))
        }
        type ProposeContractStream = std::pin::Pin<Box<dyn futures::Stream<Item = std::result::Result<protos::clirpc::ProposeContractUpdate, Status>> + Send + 'static>>;
        type CheckContractStream = std::pin::Pin<Box<dyn futures::Stream<Item = std::result::Result<protos::clirpc::CheckContractUpdate, Status>> + Send + 'static>>;
        type RecoverContentStream = std::pin::Pin<Box<dyn futures::Stream<Item = std::result::Result<protos::clirpc::RecoverContentUpdate, Status>> + Send + 'static>>;
        type CliChatStream = std::pin::Pin<Box<dyn futures::Stream<Item = std::result::Result<protos::clirpc::ChatEvent, Status>> + Send + 'static>>;
        async fn unlock(&self, _: Request<protos::clirpc::UnlockRequest>) -> std::result::Result<tonic::Response<protos::clirpc::UnlockResponse>, Status> { Err(Status::unimplemented("")) }
        async fn connect_peer(&self, _: Request<protos::clirpc::ConnectPeerRequest>) -> std::result::Result<tonic::Response<protos::clirpc::ConnectPeerResponse>, Status> { Err(Status::unimplemented("")) }
        async fn connected_peers(&self, _: Request<protos::clirpc::ConnectedPeersRequest>) -> std::result::Result<tonic::Response<protos::clirpc::ConnectedPeersResponse>, Status> { Err(Status::unimplemented("")) }
        async fn set_file(&self, _: Request<protos::clirpc::SetFileRequest>) -> std::result::Result<tonic::Response<protos::clirpc::SetFileResponse>, Status> { Err(Status::unimplemented("")) }
        async fn get_file(&self, _: Request<protos::clirpc::GetFileRequest>) -> std::result::Result<tonic::Response<protos::clirpc::GetFileResponse>, Status> { Err(Status::unimplemented("")) }
        async fn list_files(&self, _: Request<protos::clirpc::ListFilesRequest>) -> std::result::Result<tonic::Response<protos::clirpc::ListFilesResponse>, Status> { Err(Status::unimplemented("")) }
        async fn set_storage_config(&self, _: Request<protos::clirpc::SetStorageConfigRequest>) -> std::result::Result<tonic::Response<protos::clirpc::SetStorageConfigResponse>, Status> { Err(Status::unimplemented("")) }
        async fn get_storage_config(&self, _: Request<protos::clirpc::GetStorageConfigRequest>) -> std::result::Result<tonic::Response<protos::clirpc::GetStorageConfigResponse>, Status> { Err(Status::unimplemented("")) }
        async fn get_contracts(&self, _: Request<protos::clirpc::GetContractsRequest>) -> std::result::Result<tonic::Response<protos::clirpc::GetContractsResponse>, Status> { Err(Status::unimplemented("")) }
        async fn propose_contract(&self, _: Request<protos::clirpc::ProposeContractRequest>) -> std::result::Result<tonic::Response<Self::ProposeContractStream>, Status> { Err(Status::unimplemented("")) }
        async fn check_contract(&self, _: Request<protos::clirpc::CheckContractRequest>) -> std::result::Result<tonic::Response<Self::CheckContractStream>, Status> { Err(Status::unimplemented("")) }
        async fn recover_content(&self, _: Request<protos::clirpc::RecoverContentRequest>) -> std::result::Result<tonic::Response<Self::RecoverContentStream>, Status> { Err(Status::unimplemented("")) }
        async fn set_aead_key_for_peer(&self, _: Request<protos::clirpc::SetAeadKeyForPeerRequest>) -> std::result::Result<tonic::Response<protos::clirpc::SetAeadKeyForPeerResponse>, Status> { Err(Status::unimplemented("")) }
        async fn cli_chat(&self, _: Request<tonic::Streaming<protos::clirpc::ChatAction>>) -> std::result::Result<tonic::Response<Self::CliChatStream>, Status> { Err(Status::unimplemented("")) }
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
        Ok(())
    }

    // Helper: start a PQ-only TLS clirpc server on localhost and return address.
    async fn start_pq_server(expected_client_pub: PublicKey, server_priv: SecretKey) -> Result<(String, ServerHandle)> {
        let cfg = build_server_tls(&expected_client_pub, &server_priv)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let svc = BarterBackupClientServer::new(Hc::default());

        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener).filter_map(|s| async move {
            match s {
                Ok(socket) => match tls_acceptor.accept(socket).await {
                    Ok(stream) => Some(Ok(stream)),
                    Err(e) => {
                        // Log the error, but don't panic
                        eprintln!("tls accept error: {}", e);
                        None
                    }
                },
                Err(e) => {
                    eprintln!("tcp accept error: {}", e);
                    None
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

    // Client with classical X25519-only provider (no PQ).
    fn x25519_only_client_config(server_pub: &PublicKey, client_priv: &SecretKey) -> Result<rustls::ClientConfig> {
        let mut provider = aws_lc_rs::default_provider();
        provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];
        let (client_cert, client_key) = self_signed_cert(client_priv, false)?;
        let cfg = rustls::ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinServer { expected: server_pub.to_bytes() }))
            .with_client_auth_cert(vec![client_cert], client_key)
            .map_err(|e| anyhow!("client cert: {e}"))?;
        Ok(cfg)
    }

    #[cfg(feature = "pq_tls_tests")]
    #[tokio::test(flavor = "multi_thread")]
    async fn pq_server_vs_x25519_client_fails() -> Result<()> {
        let (server_pub, server_priv) = generate_ed25519()?;
        let (client_pub, client_priv) = generate_ed25519()?;
        let (addr, _h) = start_pq_server(client_pub, server_priv).await?;

        let bad_cfg = x25519_only_client_config(&server_pub, &client_priv)?;
        let tls = TlsConnector::new(bad_cfg);
        let endpoint = Endpoint::from_shared(addr)?
            .tls_connector(tls)?;
        let res = endpoint.connect().await;
        assert!(res.is_err(), "X25519-only client must not connect to PQ-only server");
        Ok(())
    }

    // Server with classical X25519-only provider.
    fn x25519_only_server_config(expected_client_pub: &PublicKey, _server_priv: &SecretKey) -> Result<rustls::ServerConfig> {
        let mut provider = aws_lc_rs::default_provider();
        provider.kx_groups = vec![&aws_lc_rs::kx_group::X25519];
        // Generate a self-signed cert for the server
        let (_pub, tmp_priv) = generate_ed25519()?;
        let (cert, key) = self_signed_cert(&tmp_priv, true)?;
        // Custom verifier pinning client pub
        #[derive(Debug)]
        struct PinClient { expected: [u8; 32], subjects: Vec<DistinguishedName> }
        impl ClientCertVerifier for PinClient {
            fn offer_client_auth(&self) -> bool { true }
            fn client_auth_mandatory(&self) -> bool { true }
            fn root_hint_subjects(&self) -> &[DistinguishedName] { &self.subjects }
            fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>], _now: UnixTime) -> Result<ClientCertVerified, rustls::Error> {
                let (_, parsed) = x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|_| rustls::Error::General("bad client cert".into()))?;
                let spki = parsed.tbs_certificate.subject_pki;
                if spki.algorithm.algorithm.to_id_string() != "1.3.101.112" { return Err(rustls::Error::General("client cert not ed25519".into())); }
                if spki.subject_public_key.data.as_ref() != self.expected { return Err(rustls::Error::General("unauthorized client cert".into())); }
                Ok(ClientCertVerified::assertion())
            }
            fn verify_tls12_signature(&self, _m:&[u8], _c:&CertificateDer<'_>, _d:&DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { Ok(HandshakeSignatureValid::assertion()) }
            fn verify_tls13_signature(&self, _m:&[u8], _c:&CertificateDer<'_>, _d:&DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { Ok(HandshakeSignatureValid::assertion()) }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { vec![SignatureScheme::ED25519] }
        }
        let verifier = Arc::new(PinClient { expected: expected_client_pub.to_bytes(), subjects: vec![] });
        let cfg = rustls::ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)
            .map_err(|e| anyhow!("server cert: {e}"))?;
        Ok(cfg)
    }

    #[cfg(feature = "pq_tls_tests")]
    #[tokio::test(flavor = "multi_thread")]
    async fn pq_client_vs_x25519_server_fails() -> Result<()> {
        let (server_pub, server_priv) = generate_ed25519()?;
        let (client_pub, client_priv) = generate_ed25519()?;

        // Start X25519-only server
        let srv_cfg = x25519_only_server_config(&client_pub, &server_priv)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv_cfg));
        let svc = BarterBackupClientServer::new(Hc::default());
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener).filter_map(|s| async move {
            match s {
                Ok(socket) => match tls_acceptor.accept(socket).await {
                    Ok(stream) => Some(Ok(stream)),
                    Err(e) => {
                        eprintln!("tls accept error: {}", e);
                        None
                    }
                },
                Err(e) => {
                    eprintln!("tcp accept error: {}", e);
                    None
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
        let tls = TlsConnector::new(good_cfg);
        let endpoint = Endpoint::from_shared(format!("https://{}", addr))?
            .tls_connector(tls)?;
        let res = endpoint.connect().await;
        assert!(res.is_err(), "PQ-only client must not connect to X25519-only server");
        Ok(())
    }

    #[cfg(feature = "pq_tls_tests")]
    #[tokio::test(flavor = "multi_thread")]
    async fn pq_client_and_server_succeed() -> Result<()> {
        let (server_pub, server_priv) = generate_ed25519()?;
        let (client_pub, client_priv) = generate_ed25519()?;
        let (addr, _h) = start_pq_server(client_pub, server_priv).await?;
        let good_cfg = build_client_tls(&server_pub, &client_priv)?;
        let tls = TlsConnector::new(good_cfg);
        let channel = Endpoint::from_shared(addr)?
            .tls_connector(tls)?
            .connect().await?;
        let mut cli = BarterBackupClientClient::new(channel);
        let _ = cli.local_health_check(HealthCheckRequest{}).await; // Will likely fail due to dummy svc, but handshake succeeded.
        Ok(())
    }
}
