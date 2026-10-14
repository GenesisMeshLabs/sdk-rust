#!/bin/sh
# Build genesis-mesh-edge (1.7.0, beta) as it is released: a static Linux
# binary (musl), with the toolchain, profile and path remapping of
# scripts/build_verifier.sh. CI (edge.yml) builds the release binaries with
# this script (docs/edge.md).
#
#   scripts/build_edge.sh <target> [<out-dir>] [<cargo args>...]
#
#   <target>   x86_64-unknown-linux-musl or aarch64-unknown-linux-musl
#   <out-dir>  where the binary and its .sha256 go (default: dist)
#
# Pinned: the Rust toolchain (RUST_TOOLCHAIN below; rustup installs it), every
# crate (Cargo.lock, --locked), the build time (SOURCE_DATE_EPOCH, the commit's
# time) and the paths the binary records (--remap-path-prefix: the checkout is
# /build, the Cargo home /cargo, the target directory /target). The release
# profile is set here, not in Cargo.toml: one codegen unit, LTO, symbols
# stripped. Whatever directory you build in, the same commit gives the same
# bytes.
#
# GM_EDGE_ANY_TOOLCHAIN=1 builds with whatever toolchain is active, for a
# local check only: its digest is not the release's. SQLite (rusqlite's
# bundled C code) is compiled for the target too: musl-gcc or a cross
# compiler must be on the path (CC_<target>).
set -eu

# The verifier's pinned toolchain: one toolchain for every release binary.
RUST_TOOLCHAIN="$(sed -n 's/^RUST_TOOLCHAIN=//p' "$(dirname "$0")/build_verifier.sh")"

usage="usage: scripts/build_edge.sh <target> [<out-dir>] [<cargo args>...]"
target="${1:?$usage}"
shift
out="dist"
if [ $# -gt 0 ]; then
    out="$1"
    shift
fi

root="$(cd "$(dirname "$0")/.." && pwd -P)"
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/edge/Cargo.toml" | head -n 1)"

if [ "${GM_EDGE_ANY_TOOLCHAIN:-0}" != 1 ]; then
    export RUSTUP_TOOLCHAIN="$RUST_TOOLCHAIN"
    actual="$(rustc --version | cut -d ' ' -f 2)"
    if [ "$actual" != "$RUST_TOOLCHAIN" ]; then
        echo "error: rustc $actual is not the pinned $RUST_TOOLCHAIN (rustup toolchain install $RUST_TOOLCHAIN --target $target)" >&2
        exit 1
    fi
fi

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
cargo_home="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
mkdir -p "$target_dir"
target_dir="$(cd "$target_dir" && pwd -P)"
export CARGO_TARGET_DIR="$target_dir"

# Paths: Rust and C code record source paths (panic locations, debug info);
# each is mapped to the same name wherever the build runs.
export RUSTFLAGS="--remap-path-prefix=$root=/build --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$target_dir=/target"
export CFLAGS="-ffile-prefix-map=$root=/build -ffile-prefix-map=$cargo_home=/cargo -ffile-prefix-map=$target_dir=/target"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_STRIP=symbols
export CARGO_PROFILE_RELEASE_DEBUG=false
export CARGO_PROFILE_RELEASE_INCREMENTAL=false
export CARGO_INCREMENTAL=0

cargo build --locked --release --target "$target" -p genesis-mesh-edge "$@"

mkdir -p "$out"
name="genesis-mesh-edge-$version-$target"
cp "$target_dir/$target/release/genesis-mesh-edge" "$out/$name"
(cd "$out" && sha256sum "$name" > "$name.sha256")

# What built it: a rebuild that differs starts by comparing these.
{
    echo "binary: $name"
    echo "sha256: $(cut -d ' ' -f 1 "$out/$name.sha256")"
    echo "commit: $(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "source_date_epoch: $SOURCE_DATE_EPOCH"
    echo "rustc: $(rustc --version --verbose | tr '\n' ' ')"
    echo "cargo: $(cargo --version)"
    echo "cc: $(cc --version 2>/dev/null | head -n 1)"
    echo "ld: $(ld --version 2>/dev/null | head -n 1)"
    echo "os: $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") $(uname -m)"
} > "$out/$name.buildinfo"
cat "$out/$name.sha256"
