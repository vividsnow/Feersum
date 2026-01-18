#!/bin/bash
# Feersum benchmark runner

cd "$(dirname "$0")/.."

DURATION=${1:-10}
CONNECTIONS=${2:-100}
THREADS=${3:-4}

echo "========================================"
echo "Feersum Benchmark"
echo "Duration: ${DURATION}s, Connections: $CONNECTIONS, Threads: $THREADS"
echo "========================================"
echo

# Build first
make -s || exit 1

# Create Lua script for no-keepalive test
cat > /tmp/no_keepalive.lua << 'EOF'
wrk.headers["Connection"] = "close"
EOF

# Function to run benchmark
run_bench() {
    local name=$1
    local port=$2
    local cmd=$3
    local keepalive=${4:-1}

    echo "--- $name ---"

    # Kill any existing process on the port
    fuser -k $port/tcp 2>/dev/null
    sleep 0.5

    # Start server in background
    $cmd &
    local pid=$!
    sleep 1

    # Check if server started
    if ! kill -0 $pid 2>/dev/null; then
        echo "Failed to start server"
        return 1
    fi

    # Run wrk (with or without keepalive)
    if [ "$keepalive" = "1" ]; then
        wrk -t$THREADS -c$CONNECTIONS -d${DURATION}s "http://127.0.0.1:$port/" 2>&1
    else
        wrk -t$THREADS -c$CONNECTIONS -d${DURATION}s -s /tmp/no_keepalive.lua "http://127.0.0.1:$port/" 2>&1
    fi

    # Stop server
    kill $pid 2>/dev/null
    wait $pid 2>/dev/null
    sleep 0.5

    echo
}

# Benchmark PSGI app (with keep-alive)
run_bench "PSGI App (keep-alive)" 5000 "perl -Mblib bench/psgi_server.pl --port 5000 --keepalive" 1

# Benchmark PSGI app (no keep-alive)
run_bench "PSGI App (no keep-alive)" 5000 "perl -Mblib bench/psgi_server.pl --port 5000" 0

# Benchmark PSGI app with prefork
run_bench "PSGI App (prefork=3)" 5000 "perl -Mblib bench/psgi_server_prefork.pl --port 5000 --workers 3 --keepalive" 1

# Benchmark Native app (with keep-alive)
run_bench "Native App (keep-alive)" 5002 "perl bench/native.pl 5002" 1

# Benchmark Native app (no keep-alive)
run_bench "Native App (no keep-alive)" 5002 "perl bench/native.pl 5002" 0

# Benchmark Native app with prefork
run_bench "Native App (prefork=3)" 5002 "perl bench/native_prefork.pl 5002 3" 1

echo "========================================"
echo "Benchmark complete"
echo "========================================"
