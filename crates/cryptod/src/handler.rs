//! Request handler - dispatches protobuf requests to crypto operations.

use crypto_api::{
    CipherAlgorithm,
    //KeyFormat,
    CipherParams,
    //HashContext,
    CreateKeyParams,
    CryptoError,
    CryptoProvider,
    HashAlgorithm,
    ImportKeyParams,
    KdfAlgorithm,
    //    MacContext, CipherContext, RandomGenerator,
    KdfParams,
    KeyAlgorithm,
    KeyMaterial,
    KeyQuery,
    KeyUsage,
    Tls12PrfLabel,
    Tls12PrfParams,
};
use crypto_native::NativeProvider;
use std::sync::Arc;

use crate::context_store::ContextStore;
use crate::proto::*;

/// Request handler that processes crypto operations.
pub struct Handler {
    provider: Arc<NativeProvider>,
    contexts: ContextStore,
}

impl Handler {
    /// Create a new handler with the given provider and context store.
    pub fn new(provider: Arc<NativeProvider>, contexts: ContextStore) -> Self {
        Self { provider, contexts }
    }

    /// Handle a raw request and return the raw response.
    pub fn handle_request(&mut self, request_data: &[u8]) -> Vec<u8> {
        // Decode the request
        let request = match decode_request(request_data) {
            Ok(req) => req,
            Err(e) => {
                return encode_response(&error_response(0, e));
            }
        };

        let request_id = request.request_id;

        // Dispatch to appropriate handler
        let response = match request.request {
            Some(req) => self.dispatch(request_id, req),
            None => error_response(request_id, CryptoError::invalid_input("Empty request")),
        };

        encode_response(&response)
    }

    /// Dispatch a request to the appropriate handler method.
    fn dispatch(
        &mut self,
        request_id: u64,
        request: crypto::crypto_request::Request,
    ) -> CryptoResponse {
        use crypto::crypto_request::Request;

        match request {
            // Provider info
            Request::GetProviderInfo(_) => self.handle_get_provider_info(request_id),
            Request::GetCapabilities(_) => self.handle_get_capabilities(request_id),

            // Key management
            Request::CreateKey(req) => self.handle_create_key(request_id, req),
            Request::ImportKey(req) => self.handle_import_key(request_id, req),
            Request::ExportKey(req) => self.handle_export_key(request_id, req),
            Request::DeleteKey(req) => self.handle_delete_key(request_id, req),
            Request::GetKeyInfo(req) => self.handle_get_key_info(request_id, req),
            Request::FindKey(req) => self.handle_find_key(request_id, req),

            // Hash operations
            Request::HashCreate(req) => self.handle_hash_create(request_id, req),
            Request::HashUpdate(req) => self.handle_hash_update(request_id, req),
            Request::HashFinish(req) => self.handle_hash_finish(request_id, req),

            // MAC operations
            Request::MacCreate(req) => self.handle_mac_create(request_id, req),
            Request::MacUpdate(req) => self.handle_mac_update(request_id, req),
            Request::MacFinish(req) => self.handle_mac_finish(request_id, req),
            Request::MacVerify(req) => self.handle_mac_verify(request_id, req),

            // Cipher operations
            Request::CipherCreate(req) => self.handle_cipher_create(request_id, req),
            Request::CipherUpdate(req) => self.handle_cipher_update(request_id, req),
            Request::CipherFinish(req) => self.handle_cipher_finish(request_id, req),
            Request::CipherSetTag(req) => self.handle_cipher_set_tag(request_id, req),

            // Random
            Request::GenerateRandom(req) => self.handle_generate_random(request_id, req),

            // Key derivation
            Request::DeriveKey(req) => self.handle_derive_key(request_id, req),

            // Context management
            Request::DestroyContext(req) => self.handle_destroy_context(request_id, req),

            // Not yet implemented
            _ => error_response(
                request_id,
                CryptoError::unsupported("Operation not implemented"),
            ),
        }
    }

    // ========================================
    // Provider Info
    // ========================================

    fn handle_get_provider_info(&self, request_id: u64) -> CryptoResponse {
        success_response(
            request_id,
            crypto::crypto_response::Response::GetProviderInfo(crypto::GetProviderInfoResponse {
                name: self.provider.name().to_string(),
                version: "0.1.0".to_string(),
            }),
        )
    }

    fn handle_get_capabilities(&self, request_id: u64) -> CryptoResponse {
        let caps = self.provider.capabilities();

        success_response(
            request_id,
            crypto::crypto_response::Response::GetCapabilities(crypto::GetCapabilitiesResponse {
                key_algorithms: vec![], // TODO: convert algorithms
                hash_algorithms: caps
                    .hash_algorithms
                    .iter()
                    .map(|a| api_hash_to_proto(*a))
                    .collect(),
                cipher_modes: vec![crypto::CipherMode::Cbc as i32],
                signature_algorithms: vec![],
            }),
        )
    }

    // ========================================
    // Key Management
    // ========================================

    fn handle_create_key(
        &mut self,
        request_id: u64,
        req: crypto::CreateKeyRequest,
    ) -> CryptoResponse {
        let algorithm = match self.parse_key_algorithm(&req.algorithm) {
            Ok(a) => a,
            Err(e) => return error_response(request_id, e),
        };

        let usage = req
            .usage
            .as_ref()
            .map(KeyUsage::from)
            .unwrap_or(KeyUsage::ALL);

        let params = CreateKeyParams {
            label: req.label,
            algorithm,
            usage,
            extractable: req.extractable,
            size_bits: req.size_bits.map(|s| s as usize),
        };

        match self.provider.create_key(params) {
            Ok(handle) => success_response(
                request_id,
                crypto::crypto_response::Response::CreateKey(crypto::CreateKeyResponse {
                    handle: Some((&handle).into()),
                }),
            ),
            Err(e) => error_response(request_id, e),
        }
    }

    fn handle_import_key(
        &mut self,
        request_id: u64,
        req: crypto::ImportKeyRequest,
    ) -> CryptoResponse {
        let algorithm = match self.parse_key_algorithm(&req.algorithm) {
            Ok(a) => a,
            Err(e) => return error_response(request_id, e),
        };

        let format = match proto_key_format_to_api(req.format) {
            Ok(f) => f,
            Err(e) => return error_response(request_id, e),
        };

        let usage = req
            .usage
            .as_ref()
            .map(KeyUsage::from)
            .unwrap_or(KeyUsage::ALL);

        let params = ImportKeyParams {
            label: req.label,
            algorithm,
            format,
            material: KeyMaterial::Plaintext(&req.material),
            usage,
            extractable: req.extractable,
        };

        match self.provider.import_key(params) {
            Ok(handle) => success_response(
                request_id,
                crypto::crypto_response::Response::ImportKey(crypto::ImportKeyResponse {
                    handle: Some((&handle).into()),
                }),
            ),
            Err(e) => error_response(request_id, e),
        }
    }

    fn handle_export_key(&self, request_id: u64, req: crypto::ExportKeyRequest) -> CryptoResponse {
        let handle = match req.handle {
            Some(h) => (&h).into(),
            None => {
                return error_response(request_id, CryptoError::invalid_input("Missing key handle"))
            }
        };

        let format = match proto_key_format_to_api(req.format) {
            Ok(f) => f,
            Err(e) => return error_response(request_id, e),
        };

        match self.provider.export_key(&handle, format) {
            Ok(material) => success_response(
                request_id,
                crypto::crypto_response::Response::ExportKey(crypto::ExportKeyResponse {
                    material,
                }),
            ),
            Err(e) => error_response(request_id, e),
        }
    }

    fn handle_delete_key(
        &mut self,
        request_id: u64,
        req: crypto::DeleteKeyRequest,
    ) -> CryptoResponse {
        let handle = match req.handle {
            Some(h) => (&h).into(),
            None => {
                return error_response(request_id, CryptoError::invalid_input("Missing key handle"))
            }
        };

        match self.provider.delete_key(&handle) {
            Ok(()) => success_response(
                request_id,
                crypto::crypto_response::Response::DeleteKey(crypto::DeleteKeyResponse {}),
            ),
            Err(e) => error_response(request_id, e),
        }
    }

    fn handle_get_key_info(
        &self,
        request_id: u64,
        req: crypto::GetKeyInfoRequest,
    ) -> CryptoResponse {
        let handle = match req.handle {
            Some(h) => (&h).into(),
            None => {
                return error_response(request_id, CryptoError::invalid_input("Missing key handle"))
            }
        };

        match self.provider.key_info(&handle) {
            Ok(info) => {
                let proto_info = crypto::KeyInfo {
                    handle: Some((&handle).into()),
                    algorithm: None, // TODO: convert algorithm
                    usage: Some(info.usage.into()),
                    extractable: info.extractable,
                    backend: crypto::KeyBackendKind::Software as i32,
                    size_bits: info.size_bits.map(|s| s as u32),
                    label: info.label.clone(),
                };
                success_response(
                    request_id,
                    crypto::crypto_response::Response::GetKeyInfo(crypto::GetKeyInfoResponse {
                        info: Some(proto_info),
                    }),
                )
            }
            Err(e) => error_response(request_id, e),
        }
    }

    fn handle_find_key(&self, request_id: u64, req: crypto::FindKeyRequest) -> CryptoResponse {
        let query = self.build_key_query(&req.query);

        match self.provider.find_key(query) {
            Ok(Some(handle)) => success_response(
                request_id,
                crypto::crypto_response::Response::FindKey(crypto::FindKeyResponse {
                    handle: Some((&handle).into()),
                }),
            ),
            Ok(None) => success_response(
                request_id,
                crypto::crypto_response::Response::FindKey(crypto::FindKeyResponse {
                    handle: None,
                }),
            ),
            Err(e) => error_response(request_id, e),
        }
    }

    // ========================================
    // Hash Operations
    // ========================================

    fn handle_hash_create(
        &mut self,
        request_id: u64,
        req: crypto::HashCreateRequest,
    ) -> CryptoResponse {
        let algorithm = match proto_hash_to_api(req.algorithm) {
            Ok(a) => a,
            Err(e) => return error_response(request_id, e),
        };

        match self.provider.hash(algorithm) {
            Ok(ctx) => {
                let output_size = ctx.output_size();
                let handle = self.contexts.insert_hash(ctx);

                success_response(
                    request_id,
                    crypto::crypto_response::Response::HashCreate(crypto::HashCreateResponse {
                        context_handle: handle,
                        output_size: output_size as u32,
                    }),
                )
            }
            Err(e) => error_response(request_id, e),
        }
    }

    fn handle_hash_update(
        &mut self,
        request_id: u64,
        req: crypto::HashUpdateRequest,
    ) -> CryptoResponse {
        let ctx = match self.contexts.get_hash_mut(req.context_handle) {
            Some(c) => c,
            None => {
                return error_response(request_id, CryptoError::invalid_state("Context not found"))
            }
        };

        match ctx.update(&req.data) {
            Ok(()) => success_response(
                request_id,
                crypto::crypto_response::Response::HashUpdate(crypto::HashUpdateResponse {}),
            ),
            Err(e) => error_response(request_id, e),
        }
    }

    fn handle_hash_finish(
        &mut self,
        request_id: u64,
        req: crypto::HashFinishRequest,
    ) -> CryptoResponse {
        let ctx = match self.contexts.remove_hash(req.context_handle) {
            Some(c) => c,
            None => {
                return error_response(request_id, CryptoError::invalid_state("Context not found"))
            }
        };

        match ctx.finish() {
            Ok(digest) => success_response(
                request_id,
                crypto::crypto_response::Response::HashFinish(crypto::HashFinishResponse {
                    digest,
                }),
            ),
            Err(e) => error_response(request_id, e),
        }
    }

    // ========================================
    // MAC Operations
    // ========================================

    fn handle_mac_create(
        &mut self,
        request_id: u64,
        req: crypto::MacCreateRequest,
    ) -> CryptoResponse {
        let algorithm = match proto_mac_to_api(req.algorithm) {
            Ok(a) => a,
            Err(e) => return error_response(request_id, e),
        };

        let key_handle = match req.key {
            Some(h) => (&h).into(),
            None => {
                return error_response(request_id, CryptoError::invalid_input("Missing key handle"))
            }
        };

        match self.provider.hmac(algorithm, &key_handle) {
            Ok(ctx) => {
                let output_size = ctx.output_size();
                let handle = self.contexts.insert_mac(ctx);

                success_response(
                    request_id,
                    crypto::crypto_response::Response::MacCreate(crypto::MacCreateResponse {
                        context_handle: handle,
                        output_size: output_size as u32,
                    }),
                )
            }
            Err(e) => error_response(request_id, e),
        }
    }

    fn handle_mac_update(
        &mut self,
        request_id: u64,
        req: crypto::MacUpdateRequest,
    ) -> CryptoResponse {
        let ctx = match self.contexts.get_mac_mut(req.context_handle) {
            Some(c) => c,
            None => {
                return error_response(request_id, CryptoError::invalid_state("Context not found"))
            }
        };

        match ctx.update(&req.data) {
            Ok(()) => success_response(
                request_id,
                crypto::crypto_response::Response::MacUpdate(crypto::MacUpdateResponse {}),
            ),
            Err(e) => error_response(request_id, e),
        }
    }

    fn handle_mac_finish(
        &mut self,
        request_id: u64,
        req: crypto::MacFinishRequest,
    ) -> CryptoResponse {
        let ctx = match self.contexts.remove_mac(req.context_handle) {
            Some(c) => c,
            None => {
                return error_response(request_id, CryptoError::invalid_state("Context not found"))
            }
        };

        match ctx.finish() {
            Ok(tag) => success_response(
                request_id,
                crypto::crypto_response::Response::MacFinish(crypto::MacFinishResponse { tag }),
            ),
            Err(e) => error_response(request_id, e),
        }
    }

    fn handle_mac_verify(
        &mut self,
        request_id: u64,
        req: crypto::MacVerifyRequest,
    ) -> CryptoResponse {
        let ctx = match self.contexts.remove_mac(req.context_handle) {
            Some(c) => c,
            None => {
                return error_response(request_id, CryptoError::invalid_state("Context not found"))
            }
        };

        match ctx.verify(&req.expected_tag) {
            Ok(valid) => success_response(
                request_id,
                crypto::crypto_response::Response::MacVerify(crypto::MacVerifyResponse { valid }),
            ),
            Err(e) => error_response(request_id, e),
        }
    }

    // ========================================
    // Cipher Operations
    // ========================================

    fn handle_cipher_create(
        &mut self,
        request_id: u64,
        req: crypto::CipherCreateRequest,
    ) -> CryptoResponse {
        let params = match &req.params {
            Some(p) => p,
            None => {
                return error_response(
                    request_id,
                    CryptoError::invalid_input("Missing cipher params"),
                )
            }
        };

        let mode = match proto_cipher_mode_to_api(params.mode) {
            Ok(m) => m,
            Err(e) => return error_response(request_id, e),
        };

        let key_handle = match req.key {
            Some(h) => (&h).into(),
            None => {
                return error_response(request_id, CryptoError::invalid_input("Missing key handle"))
            }
        };

        let cipher_params = CipherParams {
            algorithm: CipherAlgorithm::Aes(mode),
            iv: params.iv.as_ref().map(|v| v.as_slice()),
            aad: params.aad.as_ref().map(|v| v.as_slice()),
            tag_len: params.tag_len.map(|t| t as usize),
        };

        let result = if req.encrypt {
            self.provider.cipher_encrypt(cipher_params, &key_handle)
        } else {
            self.provider.cipher_decrypt(cipher_params, &key_handle)
        };

        match result {
            Ok(ctx) => {
                let is_aead = ctx.is_aead();
                let handle = self.contexts.insert_cipher(ctx);

                success_response(
                    request_id,
                    crypto::crypto_response::Response::CipherCreate(crypto::CipherCreateResponse {
                        context_handle: handle,
                        is_aead,
                    }),
                )
            }
            Err(e) => error_response(request_id, e),
        }
    }

    fn handle_cipher_update(
        &mut self,
        request_id: u64,
        req: crypto::CipherUpdateRequest,
    ) -> CryptoResponse {
        let ctx = match self.contexts.get_cipher_mut(req.context_handle) {
            Some(c) => c,
            None => {
                return error_response(request_id, CryptoError::invalid_state("Context not found"))
            }
        };

        let mut output = Vec::new();
        match ctx.update(&req.input, &mut output) {
            Ok(()) => success_response(
                request_id,
                crypto::crypto_response::Response::CipherUpdate(crypto::CipherUpdateResponse {
                    output,
                }),
            ),
            Err(e) => error_response(request_id, e),
        }
    }

    fn handle_cipher_finish(
        &mut self,
        request_id: u64,
        req: crypto::CipherFinishRequest,
    ) -> CryptoResponse {
        let ctx = match self.contexts.remove_cipher(req.context_handle) {
            Some(c) => c,
            None => {
                return error_response(request_id, CryptoError::invalid_state("Context not found"))
            }
        };

        let mut output = Vec::new();
        match ctx.finish(&mut output) {
            Ok(tag) => success_response(
                request_id,
                crypto::crypto_response::Response::CipherFinish(crypto::CipherFinishResponse {
                    output,
                    tag,
                }),
            ),
            Err(e) => error_response(request_id, e),
        }
    }

    fn handle_cipher_set_tag(
        &mut self,
        request_id: u64,
        req: crypto::CipherSetTagRequest,
    ) -> CryptoResponse {
        let ctx = match self.contexts.get_cipher_mut(req.context_handle) {
            Some(c) => c,
            None => {
                return error_response(request_id, CryptoError::invalid_state("Context not found"))
            }
        };

        match ctx.set_tag(&req.tag) {
            Ok(()) => success_response(
                request_id,
                crypto::crypto_response::Response::CipherSetTag(crypto::CipherSetTagResponse {}),
            ),
            Err(e) => error_response(request_id, e),
        }
    }

    // ========================================
    // Random Generation
    // ========================================

    fn handle_generate_random(
        &mut self,
        request_id: u64,
        req: crypto::GenerateRandomRequest,
    ) -> CryptoResponse {
        match self.provider.random() {
            Ok(mut rng) => match rng.generate(req.length as usize) {
                Ok(data) => success_response(
                    request_id,
                    crypto::crypto_response::Response::GenerateRandom(
                        crypto::GenerateRandomResponse { data },
                    ),
                ),
                Err(e) => error_response(request_id, e),
            },
            Err(e) => error_response(request_id, e),
        }
    }

    // ========================================
    // Context Management
    // ========================================

    fn handle_destroy_context(
        &mut self,
        request_id: u64,
        req: crypto::DestroyContextRequest,
    ) -> CryptoResponse {
        self.contexts.remove(req.context_handle);
        success_response(
            request_id,
            crypto::crypto_response::Response::DestroyContext(crypto::DestroyContextResponse {}),
        )
    }

    // ========================================
    // Key Derivation
    // ========================================

    fn handle_derive_key(
        &mut self,
        request_id: u64,
        req: crypto::DeriveKeyRequest,
    ) -> CryptoResponse {
        // Parse the KDF algorithm
        let algorithm = match crypto::KdfAlgorithm::try_from(req.algorithm) {
            Ok(crypto::KdfAlgorithm::HkdfSha256) => KdfAlgorithm::Hkdf(HashAlgorithm::Sha256),
            Ok(crypto::KdfAlgorithm::HkdfSha384) => KdfAlgorithm::Hkdf(HashAlgorithm::Sha384),
            Ok(crypto::KdfAlgorithm::Tls12EmsPrfSha256) => KdfAlgorithm::Tls12Prf(Tls12PrfParams {
                hash: HashAlgorithm::Sha256,
                label: Tls12PrfLabel::ExtendedMasterSecret,
            }),
            Ok(crypto::KdfAlgorithm::Tls12EmsPrfSha384) => KdfAlgorithm::Tls12Prf(Tls12PrfParams {
                hash: HashAlgorithm::Sha384,
                label: Tls12PrfLabel::ExtendedMasterSecret,
            }),
            _ => {
                return error_response(
                    request_id,
                    CryptoError::invalid_algorithm("Unsupported KDF algorithm"),
                )
            }
        };

        let key_handle = match req.key.as_ref() {
            Some(h) => h.into(),
            None => {
                return error_response(request_id, CryptoError::invalid_input("Missing key handle"))
            }
        };

        let params = KdfParams {
            key_handle: key_handle,
            algorithm: algorithm,
            ikm: &[],
            salt: req.salt.as_deref(),
            info: req.info.as_deref(),
            output_len: req.output_len as usize,
        };

        match self.provider.derive_key(params) {
            Ok(derived_key) => {
                eprintln!(
                    "derive_key key_handle={:?} derived_key={:02x?}",
                    req.key, derived_key
                );
                success_response(
                    request_id,
                    crypto::crypto_response::Response::DeriveKey(crypto::DeriveKeyResponse {
                        derived_key,
                    }),
                )
            }
            Err(e) => error_response(request_id, e),
        }
    }

    // fn parse_tls12_prf_label(&self, label: &Option<String>) -> Result<Tls12PrfLabel, CryptoError> {
    //     let label_str = label.as_deref().unwrap_or("master secret");
    //     match label_str {
    //         "master secret" => Ok(Tls12PrfLabel::MasterSecret),
    //         "extended master secret" => Ok(Tls12PrfLabel::ExtendedMasterSecret),
    //         "key expansion" => Ok(Tls12PrfLabel::KeyExpansion),
    //         "client finished" => Ok(Tls12PrfLabel::ClientFinished),
    //         "server finished" => Ok(Tls12PrfLabel::ServerFinished),
    //         _ => Err(CryptoError::invalid_input(format!("Unknown TLS PRF label: {}", label_str))),
    //     }
    // }

    // ========================================
    // Helper Methods
    // ========================================

    fn parse_key_algorithm(
        &self,
        proto: &Option<crypto::KeyAlgorithm>,
    ) -> Result<KeyAlgorithm, CryptoError> {
        let alg = proto
            .as_ref()
            .ok_or_else(|| CryptoError::invalid_input("Missing algorithm"))?;

        match &alg.algorithm {
            Some(crypto::key_algorithm::Algorithm::Symmetric(_)) => Ok(KeyAlgorithm::Symmetric),
            Some(crypto::key_algorithm::Algorithm::Aes(size)) => {
                let size = match crypto::SymmetricKeySize::try_from(*size) {
                    Ok(crypto::SymmetricKeySize::SymmetricKeySize128) => {
                        crypto_api::SymmetricKeySize::Bits128
                    }
                    Ok(crypto::SymmetricKeySize::SymmetricKeySize192) => {
                        crypto_api::SymmetricKeySize::Bits192
                    }
                    Ok(crypto::SymmetricKeySize::SymmetricKeySize256) => {
                        crypto_api::SymmetricKeySize::Bits256
                    }
                    _ => return Err(CryptoError::invalid_algorithm("Invalid AES key size")),
                };
                Ok(KeyAlgorithm::Aes(size))
            }
            Some(crypto::key_algorithm::Algorithm::Hmac(hash)) => {
                let hash = proto_hash_to_api(*hash)?;
                Ok(KeyAlgorithm::Hmac(hash))
            }
            Some(crypto::key_algorithm::Algorithm::Cmac(_)) => Ok(KeyAlgorithm::Cmac),
            _ => Err(CryptoError::invalid_algorithm("Unsupported algorithm")),
        }
    }

    fn build_key_query(&self, proto: &Option<crypto::KeyQuery>) -> KeyQuery {
        // let label = proto
        //     .as_ref()
        //     .and_then(|q| q.label.clone());
        let label = proto.as_ref().map(|q| q.label.clone()).unwrap_or_default();
        KeyQuery { label }
    }
}
