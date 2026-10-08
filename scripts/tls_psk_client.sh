#!/bin/bash
# Start a TLS-PSK client for testing. Use -p to use the cryptod provider interface.


set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BASE_DIR="$SCRIPT_DIR/.."

USE_PROVIDER=0
if [[ "$1" == "-p" ]]; then
  USE_PROVIDER=1
fi

KEY="aabbccddeeff"

# 41424344 is key label "ABCD"

if [[ "$USE_PROVIDER" == "1" ]]; then
  $BASE_DIR/openssl/apps/openssl s_client -tls1_2 \
    -psk 41424344 \
    -psk_identity "Client_identity" \
    -cipher "PSK-AES256-CBC-SHA" \
    -connect localhost:4433 \
    -provider-path "$BASE_DIR/client/build/ossl_provider/" \
    -provider libcryptod_provider \
    -provider default \
    -propquery '?provider=libcryptod_provider' \
    -debug -msg
else
  $BASE_DIR/openssl/apps/openssl s_client -tls1_2 \
    -psk $KEY \
    -psk_identity "Client_identity" \
    -cipher "PSK-AES256-CBC-SHA" \
    -connect localhost:4433 \
    -debug -msg
fi
