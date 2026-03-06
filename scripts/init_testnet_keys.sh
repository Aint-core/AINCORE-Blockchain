#!/bin/bash
mkdir -p testnet_data_node1 testnet_data_node2

# Key 1 (matches 9b472159b3555c77f5dc43512862ae21 in genesis)
echo "8721d8bf414f27cac0e11e92ebac68bb64aa4ccdbae68b145318e69cdb7822c0" | xxd -r -p > testnet_data_node1/node.key

# Key 2 (matches e1d895a946252a40acb29b6d05c41f8f in genesis)
echo "fa26110d3a14e793f07fbf15b2ba85b90a219535f52cbfd61e188dbf0b8f6797" | xxd -r -p > testnet_data_node2/node.key

echo "✅ Validator keys injected for Node 1 and Node 2."
