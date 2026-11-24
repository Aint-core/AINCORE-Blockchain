#!/usr/bin/env bash
# Run only inside a disposable, resource-limited NAS builder container.
set -euo pipefail
umask 022

test "$(uname -m)" = x86_64
test -d /src/.git || test -f /src/.git
test -d /cache/registry
test -d /out
stage=toolchain
finish() {
    rc=$?
    trap - EXIT
    printf 'stage=%s\nexit_code=%s\n' "$stage" "$rc" > /out/result.txt
    exit "$rc"
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

export DEBIAN_FRONTEND=noninteractive
dpkg --add-architecture arm64
apt-get update
apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
    libc6-dev-arm64-cross libclang-dev libssl-dev:arm64 pkg-config
rustup target add aarch64-unknown-linux-gnu
rustc -Vv > /out/toolchain.txt
dpkg-query -W > /out/packages.txt

stage=cache-copy
export CARGO_HOME=/out/cargo-home
mkdir -p "$CARGO_HOME"
cp -a /cache/registry "$CARGO_HOME/"
cp -a /cache/git "$CARGO_HOME/"
export CARGO_TARGET_DIR=/out/target
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_LIBDIR=/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig
export OPENSSL_LIB_DIR=/usr/lib/aarch64-linux-gnu
export OPENSSL_INCLUDE_DIR=/usr/include
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu='--sysroot=/usr/aarch64-linux-gnu'
cd /src
stage=compile
cargo build --locked --offline --release --target aarch64-unknown-linux-gnu -p node --bin node
stage=inspect
binary=/out/target/aarch64-unknown-linux-gnu/release/node
aarch64-linux-gnu-readelf -h "$binary" > /out/elf-header.txt
grep -q 'Machine:.*AArch64' /out/elf-header.txt
aarch64-linux-gnu-readelf -d "$binary" > /out/elf-dynamic.txt
sha256sum "$binary" > /out/SHA256SUMS
stage=complete
