// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "openssl")]

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use openshell_crypto::{OpenSsl, ProtocolBackend};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
};

#[test]
fn jwt_rejects_invalid_rsa_public_components() {
    let provider = OpenSsl.jwt_provider();
    let valid = Rsa::generate(2048).unwrap();
    let mut oversized_exponent = BigNum::new().unwrap();
    oversized_exponent.set_bit(33).unwrap();
    oversized_exponent.add_word(1).unwrap();
    for exponent in [
        BigNum::from_u32(0).unwrap(),
        BigNum::from_u32(1).unwrap(),
        BigNum::from_u32(2).unwrap(),
        BigNum::from_u32(65536).unwrap(),
        oversized_exponent,
    ] {
        // Both JWK components and DER reach the adapter; parsing alone accepts
        // these values and must not be mistaken for RSA public-key validation.
        let key = Rsa::from_public_components(valid.n().to_owned().unwrap(), exponent).unwrap();
        let der = key.public_key_to_der_pkcs1().unwrap();
        let keys = [
            DecodingKey::from_rsa_raw_components(&key.n().to_vec(), &key.e().to_vec()),
            DecodingKey::from_rsa_der(&der),
        ];
        for algorithm in [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ] {
            for key in &keys {
                assert!(
                    (provider.verifier_factory)(&algorithm, key).is_err(),
                    "invalid RSA exponent accepted for {algorithm:?}"
                );
            }
        }
    }

    let mut even_modulus = valid.n().to_owned().unwrap();
    even_modulus.sub_word(1).unwrap();
    let invalid = DecodingKey::from_rsa_raw_components(&even_modulus.to_vec(), &valid.e().to_vec());
    for algorithm in [Algorithm::RS256, Algorithm::PS256] {
        assert!((provider.verifier_factory)(&algorithm, &invalid).is_err());
    }

    // Preserve non-FIPS compatibility, including the historically valid e=3.
    for exponent in [3, 65537] {
        let key = DecodingKey::from_rsa_raw_components(
            &valid.n().to_vec(),
            &BigNum::from_u32(exponent).unwrap().to_vec(),
        );
        for algorithm in [Algorithm::RS256, Algorithm::PS256] {
            assert!((provider.verifier_factory)(&algorithm, &key).is_ok());
        }
    }
}

#[test]
fn pki_and_jwt_reject_inconsistent_ec_private_keys() {
    let provider = OpenSsl.jwt_provider();
    for (curve, algorithm) in [
        (Nid::X9_62_PRIME256V1, Algorithm::ES256),
        (Nid::SECP384R1, Algorithm::ES384),
    ] {
        let group = EcGroup::from_curve_name(curve).unwrap();
        let valid = EcKey::generate(&group).unwrap();
        let other = EcKey::generate(&group).unwrap();
        let mut order = BigNum::new().unwrap();
        group
            .order(&mut order, &mut BigNumContext::new().unwrap())
            .unwrap();
        let invalid_keys = [
            EcKey::from_private_components(&group, valid.private_key(), other.public_key())
                .unwrap(),
            EcKey::from_private_components(
                &group,
                &BigNum::from_u32(0).unwrap(),
                valid.public_key(),
            )
            .unwrap(),
            EcKey::from_private_components(&group, &order, valid.public_key()).unwrap(),
        ];
        for ec in invalid_keys {
            assert!(ec.check_key().is_err());
            let sec1 = ec.private_key_to_der().unwrap();
            let key = PKey::from_ec_key(ec).unwrap();
            let pkcs8 = key.private_key_to_pkcs8().unwrap();
            let pem = String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap();
            // These are parseable encodings of invalid key material.
            assert!(PKey::private_key_from_pkcs8(&pkcs8).is_ok());
            assert!(OpenSsl.import_keypair_der(&pkcs8).is_err());
            assert!(OpenSsl.import_keypair_pem(&pem).is_err());
            assert!(
                (provider.signer_factory)(&algorithm, &EncodingKey::from_ec_der(&sec1)).is_err()
            );
            assert!(
                (provider.jwk_utils.extract_ec_public_key_coordinates)(&sec1, algorithm).is_err()
            );
        }

        let sec1 = valid.private_key_to_der().unwrap();
        let key = PKey::from_ec_key(valid).unwrap();
        assert!(
            OpenSsl
                .import_keypair_der(&key.private_key_to_pkcs8().unwrap())
                .is_ok()
        );
        assert!((provider.signer_factory)(&algorithm, &EncodingKey::from_ec_der(&sec1)).is_ok());
    }
}
