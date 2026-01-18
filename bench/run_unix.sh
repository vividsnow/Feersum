#!/bin/bash
# Feersum Unix socket benchmark runner

cd "$(dirname "$0")/.."

DURATION=${1:-10}
CONCURRENCY=${2:-50}
SOCKET_PATH="/tmp/feersum_bench.sock"

echo "========================================"
echo "Feersum Unix Socket Benchmark"
echo "Duration: ${DURATION}s, Concurrency: $CONCURRENCY"
echo "========================================"
echo

# Build first
make -s || exit 1

# Function to run benchmark
run_bench() {
    local name=$1
    local server_cmd=$2
    local keepalive=$3

    echo "--- $name ---"

    # Kill any existing server using the socket
    if [ -S "$SOCKET_PATH" ]; then
        fuser -k "$SOCKET_PATH" 2>/dev/null
        rm -f "$SOCKET_PATH"
    fi
    sleep 0.3

    # Start server in background
    $server_cmd &
    local pid=$!
    sleep 0.5

    # Check if server started
    if ! kill -0 $pid 2>/dev/null; then
        echo "Failed to start server"
        return 1
    fi

    # Check if socket exists
    if [ ! -S "$SOCKET_PATH" ]; then
        echo "Socket not created"
        kill $pid 2>/dev/null
        return 1
    fi

    # Run benchmark
    if [ "$keepalive" = "1" ]; then
        perl bench/unix_bench_client.pl --socket "$SOCKET_PATH" --duration $DURATION --concurrency $CONCURRENCY --keepalive
    else
        perl bench/unix_bench_client.pl --socket "$SOCKET_PATH" --duration $DURATION --concurrency $CONCURRENCY --no-keepalive
    fi

    # Stop server
    kill $pid 2>/dev/null
    wait $pid 2>/dev/null
    rm -f "$SOCKET_PATH"
    sleep 0.3

    echo
}

# Native benchmarks
run_bench "Native (keepalive)" \
    "perl -Mblib bench/native_unix.pl --socket $SOCKET_PATH --keepalive" 1

run_bench "Native (no keepalive)" \
    "perl -Mblib bench/native_unix.pl --socket $SOCKET_PATH --no-keepalive" 0

# PSGI benchmarks
run_bench "PSGI (keepalive)" \
    "perl -Mblib bench/psgi_server_unix.pl --socket $SOCKET_PATH --keepalive" 1

run_bench "PSGI (no keepalive)" \
    "perl -Mblib bench/psgi_server_unix.pl --socket $SOCKET_PATH --no-keepalive" 0

echo "========================================"
echo "Unix Socket Benchmark complete"
echo "========================================"
