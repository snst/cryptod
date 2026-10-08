//! Tests for the native Rust cryptographic backend.

use crate::NativeProvider;
use crypto_api::{
    CreateKeyParams, CryptoError, CryptoProvider, HashAlgorithm, ImportKeyParams, KeyAlgorithm,
    KeyFormat, KeyMaterial, KeyUsage, MacAlgorithm,
};

// --------------------------------------------------------
// Hash Tests
// --------------------------------------------------------

#[test]
fn test_sha256_streaming() {
    let provider = NativeProvider::new();
    let mut ctx = provider.hash(HashAlgorithm::Sha256).unwrap();

    ctx.update(b"hello ").unwrap();
    ctx.update(b"world").unwrap();

    let digest = ctx.finish().unwrap();

    let expected =
        hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9").unwrap();

    assert_eq!(digest, expected);
}

#[test]
fn test_hash_output_size() {
    let provider = NativeProvider::new();

    let ctx256 = provider.hash(HashAlgorithm::Sha256).unwrap();
    assert_eq!(ctx256.output_size(), 32);

    let ctx384 = provider.hash(HashAlgorithm::Sha384).unwrap();
    assert_eq!(ctx384.output_size(), 48);
}

#[test]
fn test_unsupported_hash() {
    let provider = NativeProvider::new();
    let result = provider.hash(HashAlgorithm::Sha512);

    assert!(result.is_err());
    match result {
        Err(CryptoError::InvalidAlgorithm(_)) => {}
        _ => panic!("Expected InvalidAlgorithm error"),
    }
}

// --------------------------------------------------------
// HMAC Tests
// --------------------------------------------------------

#[test]
fn test_hmac_sha256_streaming() {
    let provider = NativeProvider::new();
    let key = provider
        .import_key(ImportKeyParams {
            label: "label1".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            format: KeyFormat::Raw,
            material: KeyMaterial::Plaintext(b"key"),
            usage: KeyUsage::ALL,
            extractable: true,
        })
        .unwrap();

    let mut ctx = provider
        .hmac(MacAlgorithm::Hmac(HashAlgorithm::Sha256), &key)
        .unwrap();

    ctx.update(b"The quick brown fox ").unwrap();
    ctx.update(b"jumps over the lazy dog").unwrap();

    let mac = ctx.finish().unwrap();

    // HMAC-SHA256("The quick brown fox jumps over the lazy dog", "key")
    let expected =
        hex::decode("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8").unwrap();

    assert_eq!(mac, expected);
}

#[test]
fn test_hmac_verify_success() {
    let provider = NativeProvider::new();
    let key = provider
        .import_key(ImportKeyParams {
            label: "label2".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            format: KeyFormat::Raw,
            material: KeyMaterial::Plaintext(b"key"),
            usage: KeyUsage::ALL,
            extractable: true,
        })
        .unwrap();

    let expected =
        hex::decode("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8").unwrap();

    let mut ctx = provider
        .hmac(MacAlgorithm::Hmac(HashAlgorithm::Sha256), &key)
        .unwrap();

    ctx.update(b"The quick brown fox jumps over the lazy dog")
        .unwrap();

    let result = ctx.verify(&expected).unwrap();
    assert!(result);
}

#[test]
fn test_hmac_verify_failure() {
    let provider = NativeProvider::new();
    let key = provider
        .import_key(ImportKeyParams {
            label: "label3".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            format: KeyFormat::Raw,
            material: KeyMaterial::Plaintext(b"key"),
            usage: KeyUsage::ALL,
            extractable: true,
        })
        .unwrap();

    let wrong_mac = vec![0u8; 32];

    let mut ctx = provider
        .hmac(MacAlgorithm::Hmac(HashAlgorithm::Sha256), &key)
        .unwrap();

    ctx.update(b"some message").unwrap();

    let result = ctx.verify(&wrong_mac);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn test_hmac_output_size() {
    let provider = NativeProvider::new();
    let key = provider
        .import_key(ImportKeyParams {
            label: "label4".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            format: KeyFormat::Raw,
            material: KeyMaterial::Plaintext(b"key"),
            usage: KeyUsage::ALL,
            extractable: true,
        })
        .unwrap();

    let ctx256 = provider
        .hmac(MacAlgorithm::Hmac(HashAlgorithm::Sha256), &key)
        .unwrap();
    assert_eq!(ctx256.output_size(), 32);

    let ctx384 = provider
        .hmac(MacAlgorithm::Hmac(HashAlgorithm::Sha384), &key)
        .unwrap();
    assert_eq!(ctx384.output_size(), 48);
}

// --------------------------------------------------------
// Random Tests
// --------------------------------------------------------

#[test]
fn test_random_fill() {
    let provider = NativeProvider::new();
    let mut rng = provider.random().unwrap();

    let mut buf = [0u8; 32];
    rng.fill(&mut buf).unwrap();

    // Verify it's not all zeros (extremely unlikely for 32 random bytes)
    assert_ne!(buf, [0u8; 32]);
}

#[test]
fn test_random_generate() {
    let provider = NativeProvider::new();
    let mut rng = provider.random().unwrap();

    let bytes = rng.generate(64).unwrap();
    assert_eq!(bytes.len(), 64);

    // Generate again and verify different
    let bytes2 = rng.generate(64).unwrap();
    assert_ne!(bytes, bytes2);
}

#[test]
fn test_random_u32() {
    let provider = NativeProvider::new();
    let mut rng = provider.random().unwrap();

    // Generate multiple values and check for variation
    let vals: Vec<u32> = (0..10).map(|_| rng.u32().unwrap()).collect();
    let unique: std::collections::HashSet<_> = vals.iter().collect();
    assert!(unique.len() > 1, "Random u32 should produce varied results");
}

#[test]
fn test_random_u64() {
    let provider = NativeProvider::new();
    let mut rng = provider.random().unwrap();

    let val1 = rng.u64().unwrap();
    let val2 = rng.u64().unwrap();

    // Very unlikely to be equal
    assert_ne!(val1, val2);
}

#[test]
fn test_random_u32_range() {
    let provider = NativeProvider::new();
    let mut rng = provider.random().unwrap();

    // Generate many values and ensure all are in range
    for _ in 0..100 {
        let val = rng.u32_range(10).unwrap();
        assert!(val < 10);
    }
}

#[test]
fn test_random_u32_range_zero_max() {
    let provider = NativeProvider::new();
    let mut rng = provider.random().unwrap();

    let result = rng.u32_range(0);
    assert!(result.is_err());
    match result {
        Err(CryptoError::InvalidInput(_)) => {}
        _ => panic!("Expected InvalidInput error"),
    }
}

// --------------------------------------------------------
// Key Management Tests
// --------------------------------------------------------

#[test]
fn test_export_key() {
    let provider = NativeProvider::new();

    let key = provider
        .create_key(
            //CreateKeyParams::symmetric_256()
            CreateKeyParams {
                label: "exportable-key".to_string(),
                algorithm: KeyAlgorithm::Symmetric,
                usage: KeyUsage::ALL,
                extractable: true,
                size_bits: Some(256),
            },
        )
        .unwrap();

    let exported = provider.export_key(&key, KeyFormat::Raw).unwrap();
    assert_eq!(exported.len(), 32);
}

#[test]
fn test_export_non_extractable_key() {
    let provider = NativeProvider::new();

    let key = provider
        .create_key(CreateKeyParams {
            label: "not-exportable-key".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: false,
            size_bits: Some(256),
        })
        .unwrap();

    let result = provider.export_key(&key, KeyFormat::Raw);
    assert!(result.is_err());
    match result {
        Err(CryptoError::UsageNotPermitted(_)) => {}
        _ => panic!("Expected UsageNotPermitted error"),
    }
}

#[test]
fn test_import_key() {
    let provider = NativeProvider::new();

    let material = b"Jefe";

    let key = provider
        .import_key(ImportKeyParams {
            label: "import-key1".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            format: KeyFormat::Raw,
            material: KeyMaterial::Plaintext(material),
            usage: KeyUsage::ALL,
            extractable: true,
        })
        .unwrap();

    // The same key can be used for different algorithms!
    let mut ctx = provider
        .hmac(MacAlgorithm::Hmac(HashAlgorithm::Sha256), &key)
        .unwrap();

    ctx.update(b"what do ya want for nothing?").unwrap();
    let mac = ctx.finish().unwrap();

    assert_eq!(mac.len(), 32);

    let expected =
        hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").unwrap();

    assert_eq!(mac, expected);
}

#[test]
fn test_find_key_by_label() {
    let provider = NativeProvider::new();

    // Create a key with a label
    let key1 = provider
        .create_key(CreateKeyParams {
            label: "encryption-key-1".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();

    // Create another key with a different label
    let _key2 = provider
        .create_key(CreateKeyParams {
            label: "signing-key".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();

    // Find by exact label
    let found = provider
        .find_key(crypto_api::KeyQuery::by_label("encryption-key-1"))
        .unwrap();

    assert!(found.is_some());
    assert_eq!(found.unwrap(), key1);
}

#[test]
fn test_delete_key() {
    let provider = NativeProvider::new();

    let key = provider
        .create_key(CreateKeyParams {
            label: "del-key".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();

    // Key should exist
    assert!(provider.key_info(&key).is_ok());

    // Delete the key
    provider.delete_key(&key).unwrap();

    // Key should no longer exist
    assert!(provider.key_info(&key).is_err());
}

// --------------------------------------------------------
// Provider Tests
// --------------------------------------------------------

#[test]
fn test_provider_name() {
    let provider = NativeProvider::new();
    assert_eq!(provider.name(), "native-rust");
}

#[test]
fn test_provider_capabilities() {
    let provider = NativeProvider::new();
    let caps = provider.capabilities();

    assert!(caps.hash_algorithms.contains(&HashAlgorithm::Sha256));
    assert!(caps.hash_algorithms.contains(&HashAlgorithm::Sha384));
}

#[test]
fn test_supports_algorithm() {
    let provider = NativeProvider::new();

    assert!(provider.supports_algorithm(&KeyAlgorithm::Symmetric));
    assert!(!provider.supports_algorithm(&KeyAlgorithm::Ed25519));
}

// --------------------------------------------------------
// AES-CBC Tests
// --------------------------------------------------------

#[test]
fn test_aes_cbc_128_encrypt_decrypt() {
    use crypto_api::CipherParams;

    let provider = NativeProvider::new();

    // Create a 128-bit key
    let key = provider
        .create_key(CreateKeyParams {
            label: "key128".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(128),
        })
        .unwrap();

    let plaintext = b"Hello, AES-CBC!!"; // 16 bytes = 1 block
    let iv = [0u8; 16];

    // Encrypt
    let mut ctx = provider
        .cipher_encrypt(CipherParams::aes_cbc(&iv), &key)
        .unwrap();
    let mut ciphertext = Vec::new();
    ctx.update(plaintext, &mut ciphertext).unwrap();
    ctx.finish(&mut ciphertext).unwrap();

    // Ciphertext should be 32 bytes (1 block data + 1 block padding)
    assert_eq!(ciphertext.len(), 32);

    // Decrypt
    let mut ctx = provider
        .cipher_decrypt(CipherParams::aes_cbc(&iv), &key)
        .unwrap();
    let mut decrypted = Vec::new();
    ctx.update(&ciphertext, &mut decrypted).unwrap();
    ctx.finish(&mut decrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_cbc_256_encrypt_decrypt() {
    use crypto_api::CipherParams;

    let provider = NativeProvider::new();

    // Create a 256-bit key
    let key = provider
        .create_key(CreateKeyParams {
            label: "key256".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();

    let plaintext = b"Hello, AES-256-CBC encryption test!";
    let iv = [0u8; 16];

    // Encrypt
    let mut ctx = provider
        .cipher_encrypt(CipherParams::aes_cbc(&iv), &key)
        .unwrap();
    let mut ciphertext = Vec::new();
    ctx.update(plaintext, &mut ciphertext).unwrap();
    ctx.finish(&mut ciphertext).unwrap();

    // Decrypt
    let mut ctx = provider
        .cipher_decrypt(CipherParams::aes_cbc(&iv), &key)
        .unwrap();
    let mut decrypted = Vec::new();
    ctx.update(&ciphertext, &mut decrypted).unwrap();
    ctx.finish(&mut decrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_cbc_streaming() {
    use crypto_api::CipherParams;

    let provider = NativeProvider::new();
    let key = provider
        .create_key(CreateKeyParams {
            label: "key256".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();
    let iv = [1u8; 16];

    // Encrypt in chunks
    let plaintext =
        b"This is a longer message that will be encrypted in multiple chunks for streaming test.";
    let mut ctx = provider
        .cipher_encrypt(CipherParams::aes_cbc(&iv), &key)
        .unwrap();
    let mut ciphertext = Vec::new();

    for chunk in plaintext.chunks(16) {
        ctx.update(chunk, &mut ciphertext).unwrap();
    }
    ctx.finish(&mut ciphertext).unwrap();

    // Decrypt in chunks
    let mut ctx = provider
        .cipher_decrypt(CipherParams::aes_cbc(&iv), &key)
        .unwrap();
    let mut decrypted = Vec::new();

    for chunk in ciphertext.chunks(16) {
        ctx.update(chunk, &mut decrypted).unwrap();
    }
    ctx.finish(&mut decrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes_cbc_empty_plaintext() {
    use crypto_api::CipherParams;

    let provider = NativeProvider::new();
    let key = provider
        .create_key(CreateKeyParams {
            label: "key256".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();
    let iv = [0u8; 16];

    // Encrypt empty plaintext
    let ctx = provider
        .cipher_encrypt(CipherParams::aes_cbc(&iv), &key)
        .unwrap();
    let mut ciphertext = Vec::new();
    ctx.finish(&mut ciphertext).unwrap();

    // Should have one block of padding
    assert_eq!(ciphertext.len(), 16);

    // Decrypt
    let mut ctx = provider
        .cipher_decrypt(CipherParams::aes_cbc(&iv), &key)
        .unwrap();
    let mut decrypted = Vec::new();
    ctx.update(&ciphertext, &mut decrypted).unwrap();
    ctx.finish(&mut decrypted).unwrap();

    assert!(decrypted.is_empty());
}

#[test]
fn test_aes_cbc_invalid_iv() {
    use crypto_api::CipherParams;

    let provider = NativeProvider::new();
    let key = provider
        .create_key(CreateKeyParams {
            label: "key256".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();
    let short_iv = [0u8; 8]; // Too short!

    let result = provider.cipher_encrypt(CipherParams::aes_cbc(&short_iv), &key);
    assert!(result.is_err());

    match result {
        Err(CryptoError::InvalidNonce {
            expected_len,
            actual_len,
        }) => {
            assert_eq!(expected_len, 16);
            assert_eq!(actual_len, 8);
        }
        _ => panic!("Expected InvalidNonce error"),
    }
}

#[test]
fn test_aes_cbc_known_vector() {
    use crypto_api::CipherParams;

    let provider = NativeProvider::new();

    // NIST test vector for AES-128-CBC
    let key_bytes = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let expected_ciphertext = hex::decode("7649abac8119b246cee98e9b12e9197d").unwrap();

    // Import the key
    let key = provider
        .import_key(ImportKeyParams {
            label: "imported-key".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            format: KeyFormat::Raw,
            material: KeyMaterial::Plaintext(&key_bytes),
            usage: KeyUsage::ALL,
            extractable: true,
        })
        .unwrap();

    // Encrypt
    let iv_arr: [u8; 16] = iv.as_slice().try_into().unwrap();
    let mut ctx = provider
        .cipher_encrypt(CipherParams::aes_cbc(&iv_arr), &key)
        .unwrap();
    let mut ciphertext = Vec::new();
    ctx.update(&plaintext, &mut ciphertext).unwrap();
    ctx.finish(&mut ciphertext).unwrap();

    // First block should match expected (ignore padding block)
    assert_eq!(&ciphertext[..16], expected_ciphertext.as_slice());
}

// --------------------------------------------------------
// TLS 1.2 PRF Tests
// --------------------------------------------------------

// #[test]
// fn test_tls12_prf_master_secret() {
//     use crypto_api::{HashAlgorithm, KdfAlgorithm, KdfParams, Tls12PrfLabel, Tls12PrfParams};

//     let provider = NativeProvider::new();

//     // Test vector derived from TLS 1.2 specification and verified against OpenSSL.
//     // PRF(secret, "master secret", ClientHello.random + ServerHello.random)
//     //
//     // Pre-master secret (48 bytes of 0x03)
//     let pre_master_secret = [0x03u8; 48];

//     // Client random (32 bytes)
//     let client_random = hex::decode(concat!(
//         "0001020304050607",
//         "08090a0b0c0d0e0f",
//         "1011121314151617",
//         "18191a1b1c1d1e1f"
//     ))
//     .unwrap();

//     // Server random (32 bytes)
//     let server_random = hex::decode(concat!(
//         "2021222324252627",
//         "28292a2b2c2d2e2f",
//         "3031323334353637",
//         "38393a3b3c3d3e3f"
//     ))
//     .unwrap();

//     // Seed = client_random + server_random
//     let mut seed = Vec::with_capacity(64);
//     seed.extend_from_slice(&client_random);
//     seed.extend_from_slice(&server_random);

//     let params = KdfParams {
//         algorithm: KdfAlgorithm::Tls12Prf(Tls12PrfParams {
//             hash: HashAlgorithm::Sha256,
//             label: Tls12PrfLabel::MasterSecret,
//         }),
//         ikm: &pre_master_secret,
//         salt: None,
//         info: Some(&seed),
//         output_len: 48, // Master secret is always 48 bytes
//     };

//     let master_secret = provider.derive_key(params).unwrap();
//     assert_eq!(master_secret.len(), 48);

//     // Expected master secret (computed using Python HMAC reference implementation)
//     let expected = hex::decode(concat!(
//         "f999ac25af645ede262f9d6775579fdc",
//         "3dbd8fb3a21e11776773ca011d06e223",
//         "1884dbaa87119abb63945be6393ef598"
//     ))
//     .unwrap();

//     assert_eq!(master_secret, expected);
// }

// #[test]
// fn test_tls12_prf_key_expansion() {
//     use crypto_api::{HashAlgorithm, KdfAlgorithm, KdfParams, Tls12PrfLabel, Tls12PrfParams};

//     let provider = NativeProvider::new();

//     // Use the master secret from previous test
//     let master_secret = hex::decode(concat!(
//         "f999ac25af645ede262f9d6775579fdc",
//         "3dbd8fb3a21e11776773ca011d06e223",
//         "1884dbaa87119abb63945be6393ef598"
//     ))
//     .unwrap();

//     // For key expansion, seed = server_random + client_random (note: reversed order!)
//     let server_random = hex::decode(concat!(
//         "2021222324252627",
//         "28292a2b2c2d2e2f",
//         "3031323334353637",
//         "38393a3b3c3d3e3f"
//     ))
//     .unwrap();

//     let client_random = hex::decode(concat!(
//         "0001020304050607",
//         "08090a0b0c0d0e0f",
//         "1011121314151617",
//         "18191a1b1c1d1e1f"
//     ))
//     .unwrap();

//     let mut seed = Vec::with_capacity(64);
//     seed.extend_from_slice(&server_random);
//     seed.extend_from_slice(&client_random);

//     // Derive key block (e.g., 72 bytes for AES-128-CBC with SHA256)
//     // client_write_MAC_key (32) + server_write_MAC_key (32) + client_write_key (16) + ...
//     let params = KdfParams {
//         algorithm: KdfAlgorithm::Tls12Prf(Tls12PrfParams {
//             hash: HashAlgorithm::Sha256,
//             label: Tls12PrfLabel::KeyExpansion,
//         }),
//         ikm: &master_secret,
//         salt: None,
//         info: Some(&seed),
//         output_len: 72,
//     };

//     let key_block = provider.derive_key(params).unwrap();
//     assert_eq!(key_block.len(), 72);

//     // Expected key block (computed using Python HMAC reference implementation)
//     let expected = hex::decode(concat!(
//         "f03e70e9289f53bf352f46640a8ff8ff",
//         "de6e9ac4117b66a7262fa27f2b4dcf67",
//         "d9ce32144bfbd8e4a583887e9bd79a08",
//         "31a672310594bb276bd12035101a7f47",
//         "516ae085dcef4ff4"
//     ))
//     .unwrap();

//     assert_eq!(key_block, expected);
// }

// #[test]
// fn test_tls12_prf_sha384() {
//     use crypto_api::{HashAlgorithm, KdfAlgorithm, KdfParams, Tls12PrfLabel, Tls12PrfParams};

//     let provider = NativeProvider::new();

//     // Test with SHA-384 (used in TLS_*_SHA384 cipher suites)
//     let secret = [0x0bu8; 48];
//     let seed = b"test label\x00\x01\x02\x03\x04\x05\x06\x07";

//     let params = KdfParams {
//         algorithm: KdfAlgorithm::Tls12Prf(Tls12PrfParams {
//             hash: HashAlgorithm::Sha384,
//             label: Tls12PrfLabel::MasterSecret,
//         }),
//         ikm: &secret,
//         salt: None,
//         info: Some(seed),
//         output_len: 48,
//     };

//     let result = provider.derive_key(params).unwrap();
//     assert_eq!(result.len(), 48);

//     // Expected output (computed using Python HMAC reference implementation with SHA-384)
//     let expected = hex::decode(concat!(
//         "94e5b8b366d6c35f4f0ceb82bfb5f31c",
//         "126a2c5a6aa06ac63fa2aed72c418477",
//         "0667a2279b5964e4b64520ab92f0c76c"
//     ))
//     .unwrap();

//     assert_eq!(result, expected);
// }

#[test]
fn test_tls12_prf_convenience_constructors() {
    use crypto_api::{HashAlgorithm, Tls12PrfLabel, Tls12PrfParams};

    // Test psk_master_secret() convenience constructor
    let params = Tls12PrfParams::psk_master_secret();
    assert_eq!(params.hash, HashAlgorithm::Sha256);
    assert_eq!(params.label, Tls12PrfLabel::MasterSecret);

    // Test key_expansion() convenience constructor
    let params = Tls12PrfParams::key_expansion();
    assert_eq!(params.hash, HashAlgorithm::Sha256);
    assert_eq!(params.label, Tls12PrfLabel::KeyExpansion);

    // Test with_hash() constructor
    let params = Tls12PrfParams::with_hash(HashAlgorithm::Sha384, Tls12PrfLabel::ClientFinished);
    assert_eq!(params.hash, HashAlgorithm::Sha384);
    assert_eq!(params.label, Tls12PrfLabel::ClientFinished);
}

#[test]
fn test_tls12_prf_label_strings() {
    use crypto_api::Tls12PrfLabel;

    assert_eq!(Tls12PrfLabel::MasterSecret.as_str(), "master secret");
    assert_eq!(Tls12PrfLabel::KeyExpansion.as_str(), "key expansion");
    assert_eq!(Tls12PrfLabel::ClientFinished.as_str(), "client finished");
    assert_eq!(Tls12PrfLabel::ServerFinished.as_str(), "server finished");

    assert_eq!(Tls12PrfLabel::MasterSecret.as_bytes(), b"master secret");
}

// --------------------------------------------------------
// Key Handle and Label Tests
// --------------------------------------------------------

#[test]
fn test_key_handle_always_numeric() {
    let provider = NativeProvider::new();

    // Create a key with a label
    let handle = provider
        .create_key(CreateKeyParams {
            label: "my-test-key".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();

    // The handle has a numeric ID
    assert!(handle.id() > 0);
}

#[test]
fn test_key_label_stored_in_key_info() {
    let provider = NativeProvider::new();

    // Create a key with a label
    let handle = provider
        .create_key(CreateKeyParams {
            label: "labeled-key".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();

    // Get key info and verify label is stored
    let info = provider.key_info(&handle).unwrap();
    assert_eq!(info.label, "labeled-key".to_string());
}

// #[test]
// fn test_key_without_label_has_none() {
//     let provider = NativeProvider::new();

//     // Create a key without a label
//     let handle = provider
//         .create_key(CreateKeyParams::symmetric_256())
//         .unwrap();

//     // Get key info and verify no label
//     let info = provider.key_info(&handle).unwrap();
//     assert_eq!(info.label, None);
// }

#[test]
fn test_duplicate_label_rejected() {
    let provider = NativeProvider::new();

    // Create first key with a label
    provider
        .create_key(CreateKeyParams {
            label: "unique-label".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();

    // Try to create second key with the same label
    let result = provider.create_key(CreateKeyParams {
        label: "unique-label".to_string(),
        algorithm: KeyAlgorithm::Symmetric,
        usage: KeyUsage::ALL,
        extractable: true,
        size_bits: Some(256),
    });

    assert!(result.is_err());
    match result {
        Err(CryptoError::InvalidInput(_)) => {} // Expected
        _ => panic!("Expected InvalidInput error for duplicate label"),
    }
}

#[test]
fn test_multiple_keys_unique_numeric_ids() {
    let provider = NativeProvider::new();

    // Create multiple keys
    let handle1 = provider
        .create_key(CreateKeyParams {
            label: "key1".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();
    let handle2 = provider
        .create_key(CreateKeyParams {
            label: "key2".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();
    let handle3 = provider
        .create_key(CreateKeyParams {
            label: "key3".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();

    // All IDs should be unique
    let id1 = handle1.id();
    let id2 = handle2.id();
    let id3 = handle3.id();

    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
    assert_ne!(id1, id3);
}

#[test]
fn test_import_key_with_label_findable() {
    use crypto_api::KeyQuery;

    let provider = NativeProvider::new();

    // Import a key with a label
    let handle = provider
        .import_key(ImportKeyParams {
            label: "imported-key".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            format: KeyFormat::Raw,
            material: KeyMaterial::Plaintext(b"secret-key-material-32-bytes!!"),
            usage: KeyUsage::ALL,
            extractable: true,
        })
        .unwrap();

    // Verify the label is stored
    let info = provider.key_info(&handle).unwrap();
    assert_eq!(info.label, "imported-key".to_string());

    // Find the key by label
    let query = KeyQuery::by_label("imported-key");
    let found = provider.find_key(query).unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().id(), handle.id());
}

#[test]
fn test_key_usable_via_handle_for_crypto() {
    let provider = NativeProvider::new();

    // Create a key with a label
    let handle = provider
        .create_key(CreateKeyParams {
            label: "hmac-crypto-key".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();

    // Use the key handle for HMAC operation
    let mut ctx = provider
        .hmac(MacAlgorithm::Hmac(HashAlgorithm::Sha256), &handle)
        .unwrap();

    ctx.update(b"test data").unwrap();
    let mac = ctx.finish().unwrap();

    // Verify we got a valid MAC
    assert_eq!(mac.len(), 32);
}

#[test]
fn test_find_key_after_delete_returns_none() {
    use crypto_api::KeyQuery;

    let provider = NativeProvider::new();

    // Create a key with a label
    let handle = provider
        .create_key(CreateKeyParams {
            label: "deleteme-key".to_string(),
            algorithm: KeyAlgorithm::Symmetric,
            usage: KeyUsage::ALL,
            extractable: true,
            size_bits: Some(256),
        })
        .unwrap();

    // Verify it can be found
    let query = KeyQuery::by_label("deleteme-key");
    assert!(provider.find_key(query.clone()).unwrap().is_some());

    // Delete the key
    provider.delete_key(&handle).unwrap();

    // Verify it can no longer be found
    assert!(provider.find_key(query).unwrap().is_none());
}
