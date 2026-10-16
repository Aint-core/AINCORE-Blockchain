#!/bin/bash
# B385: the two keys below are PUBLIC test keys: they are committed to this
# repository, so anyone can sign with them. Never use them on a network that
# holds value. Before, this script wrote them over any existing node.key, so a
# real validator identity could be replaced by a public one. Now it refuses
# (exit 1) when either target node.key already exists, and writes nothing.
set -euo pipefail
set -o noclobber

EXISTING=0
for t in testnet_data_node1/node.key testnet_data_node2/node.key; do
  if [[ -e "$t" || -L "$t" ]]; then
    echo "ERROR: $t already exists; refusing to overwrite it." >&2
    EXISTING=1
  fi
done
if [[ "$EXISTING" == 1 ]]; then
  echo "       This script writes PUBLIC test keys (committed to this repository," >&2
  echo "       anyone can sign with them). Move the existing key away yourself if" >&2
  echo "       you really want a public test key in its place." >&2
  exit 1
fi

mkdir -p testnet_data_node1 testnet_data_node2

# Key 1 (matches 9b472159b3555c77f5dc43512862ae21 in genesis)
echo "8721d8bf414f27cac0e11e92ebac68bb64aa4ccdbae68b145318e69cdb7822c0" | xxd -r -p > testnet_data_node1/node.key

# Key 2 (matches e1d895a946252a40acb29b6d05c41f8f in genesis)
echo "fa26110d3a14e793f07fbf15b2ba85b90a219535f52cbfd61e188dbf0b8f6797" | xxd -r -p > testnet_data_node2/node.key

echo "✅ Validator keys injected for Node 1 and Node 2."
echo "   These are PUBLIC test keys: never use them on a network that holds value."
