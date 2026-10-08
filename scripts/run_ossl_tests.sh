#!/bin/bash
# Run all tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_SOCKET="/tmp/cryptod.sock"


echo ""
echo "Running C++ tests..."
if [ -d "$PROJECT_ROOT/client/build/test" ]; then
    cd "$PROJECT_ROOT/client/build/test"
    export OPENSSL_MODULES=$PROJECT_ROOT/client/build/ossl_provider
    ./cryptod_client_tests --gtest_filter=*OsslMacTest*

fi

echo ""
echo "All tests completed!"
