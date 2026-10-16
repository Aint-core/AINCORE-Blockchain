# Build Stage. B351: a pinned toolchain (the one the release is tested with)
# and the lock file's dependency versions (`--locked`): `rust:latest` and an
# unlocked build made each image a different build of the node.
FROM rust:1.95-bookworm AS builder

WORKDIR /usr/src/aincore

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev protobuf-compiler clang && rm -rf /var/lib/apt/lists/*

# Copy entire workspace
COPY . .

# B351: the stdlib bytecode is the repository's, the one genesis.json pins
# (`stdlib_hash`); it is not compiled again here (a compiler that emitted
# other bytes made the node refuse the genesis).

# Build the node and the indexer (release mode)
RUN cargo build --release --locked --bin node --bin indexer

# Runtime Stage
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

# B351: the node runs as an unprivileged user, not root. A mounted data
# directory must be writable by it: `sudo chown -R 10001 <host dir>`.
RUN useradd --uid 10001 --create-home --home-dir /home/aincore aincore
WORKDIR /home/aincore/.aincore

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/aincore/target/release/node /usr/local/bin/node
COPY --from=builder /usr/src/aincore/target/release/indexer /usr/local/bin/indexer

# The Move stdlib bytecode genesis pins, where the node looks for it
# (`vm_move/stdlib/bytecode` under its working directory).
COPY --from=builder --chown=aincore:aincore /usr/src/aincore/core/vm_move/stdlib/bytecode /home/aincore/.aincore/vm_move/stdlib/bytecode
RUN mkdir -p /home/aincore/.aincore/data && chown -R aincore:aincore /home/aincore
USER aincore

# No genesis is baked in: the repository's genesis.json predates the current
# format and is refused (no stdlib_hash, a treasury reserve, no pinned
# intervals). Mount the genesis.json of the chain the node joins (the compose
# files take it from AINCORE_GENESIS_FILE); without one the node stops with
# "genesis.json not found".

# Expose libp2p (base port 9002 + 100), API, and Indexer ports
EXPOSE 9102 8002 3001

# B269: the RPC listens on the container's interfaces (the node binds
# 127.0.0.1 unless told otherwise, which inside a container no published port
# or other container reaches). B303: behind a proxy, give the proxy its own
# listener (AINCORE_RPC_PROXY_PORT, bound at AINCORE_RPC_PROXY_BIND, published
# to the proxy alone) and set AINCORE_RPC_TRUSTED_PROXIES and
# AINCORE_RPC_CLIENT_IP_HEADER: the header counts on that listener only.
ENV AINCORE_RPC_BIND=0.0.0.0

# Default command
CMD ["node", "--port", "9002"]
