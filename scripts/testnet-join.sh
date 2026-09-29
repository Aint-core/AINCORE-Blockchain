#!/usr/bin/env bash
#
# testnet-join.sh: DISABLED on G3 chains (G3 SN-5).
#
# It installed a downloaded database tarball as this node's state. On a G3
# chain that tarball carries everything the boot checks compare against (the
# state tree, the stored quorum certificate and the committee that signed
# it), so a forged snapshot passed them all. Nothing in it was verified.
#
# Join instead by syncing from genesis off a seed that keeps every block
# (AINCORE_STORAGE_MODE=archive; full nodes keep only the last 100,000), or,
# once G3 S6 lands, by verified
# snapshot restore: every chunk proven against a state root that a quorum of
# the trusted committee signed. The old script is in git history (before G3
# S7) for the pre-G3 testnet only.
set -euo pipefail

cat >&2 <<'MSG'
testnet-join.sh is disabled (G3 SN-5): it installed an unverified database
snapshot, and on a G3 chain a forged snapshot passes every boot check.

Join by syncing from genesis, off a seed that keeps every block
(AINCORE_STORAGE_MODE=archive; full nodes keep only the last 100,000):
  AINCORE_P2P_LISTEN=0 ./node --port <p2p> --rpc-port <rpc> \
    --datadir <dir> --bootnodes <archive seed multiaddr>

Verified snapshot restore is G3 S6.
MSG
exit 1
