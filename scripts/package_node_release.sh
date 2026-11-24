#!/usr/bin/env bash
# Package only the selected binary and its required public runtime files.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# == 2 ]] || { echo "Usage: $0 <node-binary> <output.tar.gz>" >&2; exit 2; }
BINARY=$1
OUT=$2
[[ -f "$BINARY" && -x "$BINARY" && ! -L "$BINARY" ]] || { echo "ERROR: expected an executable binary" >&2; exit 3; }
[[ ! -e "$OUT" && ! -L "$OUT" && ! -e "$OUT.sha256" && ! -L "$OUT.sha256" ]] \
  || { echo "ERROR: refusing to overwrite release evidence" >&2; exit 3; }
if command -v sha256sum >/dev/null 2>&1; then
  SHA=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  SHA=(shasum -a 256)
else
  echo "ERROR: need sha256sum or shasum" >&2
  exit 3
fi
STAGE="$(mktemp -d)"
PARTIAL="$(mktemp "${OUT}.partial.XXXXXX")"
cleanup() { rm -rf "$STAGE"; rm -f "$PARTIAL"; }
trap cleanup EXIT
mkdir -p "$STAGE/core/vm_move/stdlib/bytecode"
cp "$BINARY" "$STAGE/node"
chmod 755 "$STAGE/node"
cp "$ROOT/LICENSE" "$STAGE/LICENSE"
cp "$ROOT/docs/RELEASE_PACKAGE.md" "$STAGE/README.md"
COUNT=0
for module in "$ROOT"/core/vm_move/stdlib/bytecode/*.mv; do
  [[ -f "$module" && ! -L "$module" ]] || { echo "ERROR: missing or symlinked stdlib module: $module" >&2; exit 3; }
  cp "$module" "$STAGE/core/vm_move/stdlib/bytecode/"
  COUNT=$((COUNT + 1))
done
[[ "$COUNT" -gt 0 ]] || { echo "ERROR: no stdlib modules" >&2; exit 3; }
(
  cd "$STAGE"
  "${SHA[@]}" node LICENSE README.md core/vm_move/stdlib/bytecode/*.mv > SHA256SUMS
)
tar czf "$PARTIAL" -C "$STAGE" node LICENSE README.md SHA256SUMS core
# Same-directory hard link publishes the complete archive without clobbering
# an existing one, including a concurrent publisher's artifact.
ln "$PARTIAL" "$OUT"
HASH="$("${SHA[@]}" "$OUT" | awk '{print $1}')"
( set -o noclobber; printf '%s  %s\n' "$HASH" "$(basename "$OUT")" > "$OUT.sha256" )
printf 'Packaged %s with %s stdlib modules; checksum: %s.sha256\n' "$OUT" "$COUNT" "$OUT"
