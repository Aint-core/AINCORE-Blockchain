# Writes da/vectors/da_vectors.json from the independent reference
# (da_ref.py). The Rust verifier (da/src/tests.rs) and the SDK verifier
# (aincore-js/test_da_sample.ts) both check every vector.
# Run from the repository root: python3 da/reference/da_vectors.py
import json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from da_ref import pattern, sample

valid, invalid = [], []
for length in [0, 1, 1000, 5000]:
    k = min(max(-(-length // 512), 1), 128)
    for index in sorted({0, k - 1, k, 2 * k - 1, (7 * length) % (2 * k)}):
        root, s = sample(pattern(length), index)
        valid.append({"da_root": root, "sample": s})

root, good = sample(pattern(5000), 13)
_, other = sample(pattern(5000), 12)
def bad(name, error, **changes):
    s = dict(good); s.update(changes)
    invalid.append({"name": name, "da_root": changes.pop("_root", root), "sample": s, "error": error})
flipped = bytearray(bytes.fromhex(good["shard"])); flipped[0] ^= 1
bad("a flipped shard byte", "RootMismatch", shard=flipped.hex())
bad("another index's shard and proof", "RootMismatch", shard=other["shard"], proof=other["proof"])
bad("a proof one sibling short", "BadProof", proof=good["proof"][:-1])
bad("a proof one sibling long", "BadProof", proof=good["proof"] + ["00" * 32])
bad("a proof of nine siblings", "BadProof", proof=["00" * 32] * 9)
bad("another body length", "RootMismatch", body_len=4999)
bad("an index past the last shard", "IndexOutOfRange", index=20)
bad("a shard of the wrong size", "BadShard", shard=good["shard"][:-2])
bad("a shard that is not hex", "BadShard", shard="zz" + good["shard"][2:])
bad("a body length of 2^64 - 1", "BadShard", body_len=2**64 - 1)
invalid.append({"name": "another body's root", "da_root": sample(pattern(5001), 0)[0], "sample": good, "error": "RootMismatch"})
invalid.append({"name": "a root that is not hex", "da_root": "g" * 64, "sample": good, "error": "BadRoot"})

out = {"description": "B1 DA sample vectors from da/reference/da_vectors.py. Bodies are pattern(len): byte i is (31 i + 7) mod 256.",
       "valid": valid, "invalid": invalid}
with open(os.path.join(os.path.dirname(__file__), "..", "vectors", "da_vectors.json"), "w") as f:
    json.dump(out, f, indent=1)
    f.write("\n")
print(len(valid), "valid,", len(invalid), "invalid")
