# Build Stage
FROM rust:latest as builder

WORKDIR /usr/src/aincore

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev protobuf-compiler clang && rm -rf /var/lib/apt/lists/*

# Copy entire workspace
COPY . .

# Compile Move Stdlib
RUN cargo run --release --bin move_compiler_tool -- --sources core/vm_move/stdlib/sources/*.move --output core/vm_move/stdlib/bytecode

# Build the node binary (release mode)
RUN cargo build --release --bin node
# Build the indexer binary
RUN cargo build --release --bin indexer

# Runtime Stage
FROM debian:trixie-slim

WORKDIR /root/.aincore

# Install runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/aincore/target/release/node /usr/local/bin/node
COPY --from=builder /usr/src/aincore/target/release/indexer /usr/local/bin/indexer

# Copy the compiled Move Stdlib bytecode
RUN mkdir -p /root/.aincore/vm_move/stdlib/bytecode
COPY --from=builder /usr/src/aincore/core/vm_move/stdlib/bytecode /root/.aincore/vm_move/stdlib/bytecode

# Expose P2P, API, and Indexer ports
EXPOSE 9002 8002 3001

# Default command
CMD ["node", "--port", "9002"]
