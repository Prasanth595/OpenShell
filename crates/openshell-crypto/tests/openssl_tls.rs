// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "openssl")]

use openshell_crypto::{CryptoContext, OpenSsl, ProtocolBackend, pki, tls};
use std::sync::{Arc, Once};

fn init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        #[cfg(feature = "aws-lc")]
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .unwrap();
        openshell_crypto::install_default_context(CryptoContext::new(Box::new(OpenSsl))).unwrap();
    });
}

fn handshake(
    client: rustls::ClientConfig,
    server: rustls::ServerConfig,
    host: &'static str,
) -> Result<(), rustls::Error> {
    let mut client =
        rustls::ClientConnection::new(Arc::new(client), host.try_into().unwrap()).unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server)).unwrap();
    for _ in 0..10 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut wire.as_slice()).unwrap();
        server.process_new_packets()?;
        wire.clear();
        server.write_tls(&mut wire).unwrap();
        client.read_tls(&mut wire.as_slice()).unwrap();
        client.process_new_packets()?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    Err(rustls::Error::General("handshake did not finish".into()))
}

fn leaf(
    ca: &pki::Certificate,
    ca_key: &pki::KeyPair,
    usage: rcgen::ExtendedKeyUsagePurpose,
) -> pki::CertifiedKey {
    let key_pair = pki::generate_keypair().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.extended_key_usages = vec![usage];
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let cert = pki::signed_by(params, &key_pair, ca, ca_key).unwrap();
    pki::CertifiedKey { cert, key_pair }
}

#[test]
fn tls12_and_tls13_enforce_server_and_client_authentication() {
    init();
    // An explicit empty protocol policy must not be replaced with defaults.
    assert!(tls::try_client_builder_with_protocol_versions(&[]).is_err());
    assert!(tls::try_server_builder_with_protocol_versions(&[]).is_err());
    assert!(std::ptr::eq(
        tls::configuration_provider().secure_random,
        OpenSsl.tls_provider().secure_random
    ));
    let ca_key = pki::generate_keypair().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca = pki::self_signed(params, &ca_key).unwrap();
    let server_key = leaf(&ca, &ca_key, rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let client_key = leaf(&ca, &ca_key, rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots.clone()),
            tls::configuration_provider(),
        )
        .build()
        .unwrap();
        let server = tls::try_server_builder_with_protocol_versions(&[version])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_key.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    server_key.key_pair.serialize_der().unwrap(),
                )
                .into(),
            )
            .unwrap();
        let client = tls::try_client_builder_with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(
                vec![client_key.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    client_key.key_pair.serialize_der().unwrap(),
                )
                .into(),
            )
            .unwrap();
        handshake(client.clone(), server.clone(), "localhost").unwrap();
        assert!(matches!(
            handshake(client, server.clone(), "wrong.example"),
            Err(rustls::Error::InvalidCertificate(_))
        ));
        let anonymous = tls::try_client_builder_with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        assert!(matches!(
            handshake(anonymous, server.clone(), "localhost"),
            Err(rustls::Error::NoCertificatesPresented)
        ));
        let untrusted = tls::try_client_builder_with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        assert!(matches!(
            handshake(untrusted, server.clone(), "localhost"),
            Err(rustls::Error::InvalidCertificate(_))
        ));
        let stranger = pki::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let unauthorized = tls::try_client_builder_with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(
                vec![stranger.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    stranger.key_pair.serialize_der().unwrap(),
                )
                .into(),
            )
            .unwrap();
        assert!(matches!(
            handshake(unauthorized, server, "localhost"),
            Err(rustls::Error::InvalidCertificate(_))
        ));
    }
}
