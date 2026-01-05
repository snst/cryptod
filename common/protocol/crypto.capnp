# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

@0xbf53880479532599; # Unique file ID (generate yours with 'capnp id')

interface CryptoService {
  
  enum HashMode {
    sha256 @0;
    sha384 @1;
    sha512 @2;
  }

  interface HmacSession {
    # A stateful session representing a specific HMAC calculation.
    
    update @0 (data :Data) -> stream;
    # Append a chunk of bytes to the current HMAC context.
    
    final @1 () -> (hmac :Data);
    # Finalize the calculation and return the resulting digest.
    # Note: Calling this usually destroys the session or resets it.
  }

  initHmac @0 (keyId :Int32, mode :HashMode) -> (session :HmacSession);
  # Starts a new HMAC operation on the server.
  # Returns a capability (handle) to the stateful session.
}