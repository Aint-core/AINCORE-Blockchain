#!/usr/bin/env bash
# P_ANCHOR_HEIGHT — the invariant whose violation WAS the live B4b block fork.
#
#   anchor_round -> block_height must be INJECTIVE on each node,
#   and IDENTICAL across every node.
#
# The live fork looked like this: one node built height 50 from round 52, another
# from round 53. Identical DAG, different height<->round mapping. Nothing in the
# node alarms on it by itself, because each node's own chain looks perfectly
# consistent -- the divergence is only visible by COMPARING nodes. That is what
# this does.
#
# LEG 0 exists because this script LIED on 2026-09-21. It printed
# "P_ANCHOR_HEIGHT: HOLDS" against a cluster that had been halted since
# 2026-09-12. Agreement is not health: four nodes frozen at the same height
# agree perfectly. Every run now proves the chain is MOVING before it says
# anything about whether the nodes agree.
#
# Reads only. Safe to run against a production cluster at any time.
#
# The detection logic is VERIFIED, not assumed. Against synthetic input it reports:
#   leg 1  "round 210 maps to heights 105 and 106"          (injectivity broken)
#   leg 2  "height 105: r1=round 210, ... r4=round 211"      (the live fork shape)
# and stays silent on an agreeing control set. A checker that has never been shown
# to detect anything is not evidence.
#
#   ./check-anchor-height-map.sh [N_BLOCKS] [SLEEP_SECS] [STALE_SECS]
#       N_BLOCKS    window compared across nodes            (default 400)
#       SLEEP_SECS  gap between the two liveness samples    (default 20)
#       STALE_SECS  tip older than this means HALTED        (default 120)
set -uo pipefail
N=${1:-400}
SLEEP_SECS=${2:-20}
STALE_SECS=${3:-120}
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

# host:api_port:label — API port is the p2p port minus 1000.
NODES=(
  "aincore-nas:8201:r1"
  "aincore-nas:8205:r2"
  "aincore-pi:8203:r3"
  "aincore-pi:8206:r4"
)

cat > "$OUT/dump.sh" <<'INNER'
curl -s -m 30 -X POST "http://127.0.0.1:$1/rpc" -H 'Content-Type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"aincore_getBlocks\",\"params\":[$2]}"
INNER

echo "Collecting the last $N blocks from ${#NODES[@]} nodes..."
for spec in "${NODES[@]}"; do
  host=${spec%%:*}; rest=${spec#*:}; port=${rest%%:*}; label=${rest#*:}
  ssh -o ConnectTimeout=10 -o BatchMode=yes "$host" "bash -s $port $N" \
      < "$OUT/dump.sh" > "$OUT/$label.json" 2>/dev/null
  sz=$(wc -c < "$OUT/$label.json" | tr -d ' ')
  printf "  %-3s %-14s port %-5s %8s bytes\n" "$label" "$host" "$port" "$sz"
done

# Second liveness sample. Only the tip is needed, so this is one block per node.
echo "Waiting ${SLEEP_SECS}s for the second liveness sample..."
sleep "$SLEEP_SECS"
SAMPLE_GAP_START=$(date -u +%s)
for spec in "${NODES[@]}"; do
  host=${spec%%:*}; rest=${spec#*:}; port=${rest%%:*}; label=${rest#*:}
  ssh -o ConnectTimeout=10 -o BatchMode=yes "$host" "bash -s $port 1" \
      < "$OUT/dump.sh" > "$OUT/$label.tip.json" 2>/dev/null
done
NOW=$(date -u +%s)
: "$SAMPLE_GAP_START"

python3 - "$OUT" "$NOW" "$STALE_SECS" "$SLEEP_SECS" "${NODES[@]}" <<'PY'
import json, sys, os
out = sys.argv[1]
now, stale_secs, sleep_secs = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
labels = [s.split(":")[2] for s in sys.argv[5:]]

def tip_of(path):
    """(height, round, timestamp) of the newest block in a getBlocks reply."""
    res = json.load(open(path))["result"]
    b = max(res, key=lambda b: b["header"]["height"])["header"]
    return b["height"], b.get("round"), b.get("timestamp", 0)

maps, hdrs = {}, {}
for n in labels:
    path = os.path.join(out, f"{n}.json")
    try:
        res = json.load(open(path))["result"]
    except Exception as e:
        print(f"  {n}: UNREADABLE ({e}) — node down, or the API is bound to localhost only")
        continue
    maps[n] = {b["header"]["height"]: b["header"].get("round") for b in res}
    hdrs[n] = {b["header"]["height"]: b["header"]["hash"] for b in res}

if len(maps) < 2:
    print("\nFATAL: need at least 2 readable nodes to compare. Nothing checked.")
    sys.exit(2)
if len(maps) < len(labels):
    print(f"\nWARNING: only {len(maps)}/{len(labels)} nodes answered. A node that is "
          f"DOWN cannot disagree, so a PASS below covers only the nodes listed.")

fail = 0
halted = 0

# LEG 0 — the chain is ALIVE. Runs first: if it is not moving, the agreement
# legs below are measuring four copies of a frozen snapshot, and "HOLDS" would
# be an answer to a question nobody asked.
print("\nLEG 0 — liveness (the chain is producing blocks)")
advanced = []
for n in labels:
    try:
        h1, _, ts = tip_of(os.path.join(out, f"{n}.json"))
        h2, _, _ = tip_of(os.path.join(out, f"{n}.tip.json"))
    except Exception as e:
        print(f"  {n}: UNREADABLE ({e}) — cannot vouch for liveness on this node")
        continue
    age = now - ts if ts else None
    moved = h2 > h1
    advanced.append(moved)
    age_txt = "tip timestamp missing" if age is None else (
        f"tip is {age}s old" if age <= stale_secs else
        f"tip is {age}s old ({age/86400:.1f} DAYS) — STALE, threshold {stale_secs}s")
    if not moved:
        halted = 1
        print(f"  {n}: NOT ADVANCING — height {h1} unchanged over {sleep_secs}s; {age_txt}")
    elif age is not None and age > stale_secs:
        halted = 1
        print(f"  {n}: height {h1}->{h2} but {age_txt}")
    else:
        print(f"  {n}: ok — height {h1}->{h2} (+{h2-h1} in {sleep_secs}s), {age_txt}")

if advanced and not any(advanced):
    print("  ==> EVERY readable node is frozen. This is a HALT, not a slow chain.")

print("\nLEG 1 — anchor_round -> height injective on each node")
for n, m in maps.items():
    seen, dup = {}, []
    for h in sorted(m):
        r = m[h]
        if r in seen:
            dup.append((r, seen[r], h))
        seen[r] = h
    if dup:
        fail = 1
        print(f"  {n}: VIOLATED — round {dup[0][0]} maps to heights {dup[0][1]} and {dup[0][2]}"
              f" ({len(dup)} total)")
    else:
        print(f"  {n}: ok ({len(m)} blocks, heights {min(m)}..{max(m)})")

print("\nLEG 2 — the map is identical across nodes")
common = sorted(set.intersection(*[set(m) for m in maps.values()]))
if not common:
    fail = 1
    print("  VIOLATED — no shared heights at all; the nodes are on different chains")
else:
    bad = [h for h in common
           if len({maps[n][h] for n in maps}) > 1 or len({hdrs[n][h] for n in maps}) > 1]
    if bad:
        fail = 1
        print(f"  VIOLATED at {len(bad)} of {len(common)} shared heights. First 5:")
        for h in bad[:5]:
            print(f"    height {h}: " + ", ".join(f"{n}=round {maps[n][h]}" for n in maps))
    else:
        print(f"  ok — {len(common)} shared heights, identical round AND header hash on every node")

print("\nLIVENESS:        " + ("HALTED / STALLED — see LEG 0" if halted else "chain is advancing"))
print("P_ANCHOR_HEIGHT: " + ("VIOLATED — this is the B4b signature" if fail
                             else "holds over the window sampled"))
if halted:
    print("\n*** Agreement across FROZEN nodes is not health. Four nodes stopped at the")
    print("*** same height agree perfectly. Fix liveness before reading the legs above.")
print("\nNOTE: a window of blocks, not a proof. B4b needs a sync-vs-local race to fire;")
print("a quiet LAN may simply never produce one. Re-run after any restart or partition.")
sys.exit(1 if (fail or halted) else 0)
PY
