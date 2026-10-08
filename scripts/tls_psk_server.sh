#!/bin/bash
# Start a TLS-PSK server for testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

$SCRIPT_DIR/../openssl/apps/openssl s_server -tls1_2 \
  -psk aabbccddeeff \
  -psk_hint "MyServerHint" \
  -accept 4433 \
  -nocert \
  -debug -msg