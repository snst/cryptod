#!/bin/bash
# Run all tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_SOCKET="/tmp/cryptod.sock"
DAEMON_PID=""

cleanup() {
    if [ -n "$DAEMON_PID" ]; then
        echo "Stopping daemon (PID $DAEMON_PID)..."
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -f "$TEST_SOCKET"
}

trap cleanup EXIT

echo "Running Rust tests..."
cd "$PROJECT_ROOT"
cargo test --workspace

echo ""
echo "Building daemon..."
cargo build --release -p cryptod

echo ""
echo "Starting daemon for C++ tests..."
rm -f "$TEST_SOCKET"
"$PROJECT_ROOT/target/release/cryptod" --socket "$TEST_SOCKET" &
DAEMON_PID=$!
sleep 0.5  # Give daemon time to start

# Verify daemon is running
if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "ERROR: Daemon failed to start"
    exit 1
fi
echo "Daemon started (PID $DAEMON_PID)"

echo ""
echo "Running C++ tests..."
if [ -d "$PROJECT_ROOT/client/cpp/build" ]; then
    cd "$PROJECT_ROOT/client/cpp/build"
    ctest --output-on-failure
else
    echo "C++ build directory not found. Build with:"
    echo "  cd client/cpp && mkdir build && cd build && cmake .. && make"
fi

echo ""
echo "All tests completed!"
