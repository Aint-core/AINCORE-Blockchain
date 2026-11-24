# AINCORE node runtime package

This package contains the node executable, matching Move bytecode, license,
instructions and file checksums. Keep the bytecode directory with the binary.
A node-only copy cannot initialize a fresh database.

The package does not contain a genesis, data directory or signing key. Obtain
the intended network's reviewed genesis and its trusted hash separately. Do not
use an example or newly generated genesis to join an existing network.

## Verify before running

The tagged release workflow builds and smoke-tests Linux x86-64, Linux ARM64 and macOS ARM64 archives. Before extraction, obtain the repository name, release tag and full source commit from your approved release record. Set the four shell variables below to those values and the downloaded archive for your platform. Use a GitHub CLI with the flags shown in `gh attestation verify --help`.

```bash
repo='OWNER/REPOSITORY'
tag='RELEASE_TAG'
commit='FULL_APPROVED_COMMIT_SHA'
archive='aincore-node-aarch64-unknown-linux-gnu.tar.gz'

verify_archive() {
  gh attestation verify "$archive" --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/release.yml" \
    --source-ref "refs/tags/$tag" --source-digest "$commit" \
    --deny-self-hosted-runners "$@"
}
verify_archive
```

A successful check verifies the digest of the archive against the signed build provenance for the approved source, tag, workflow and GitHub-hosted runner. For an offline installation, fetch the bundle from the expected repository on a connected machine and obtain fresh trusted roots through the CLI.

```bash
gh attestation download "$archive" --repo "$repo"
gh attestation trusted-root > trusted_root.jsonl
```

Copy the archive, its checksum sidecar, the CLI, the downloaded bundle and the trusted roots to the offline machine by your approved transfer procedure. Keep the expected repository, tag and source commit from the same approved release record. Define the variables and function above, then use the bundle filename printed by the download command.

```bash
bundle='sha256:ARCHIVE_DIGEST.jsonl'
verify_archive --bundle "$bundle" --custom-trusted-root trusted_root.jsonl
```

Continue only after verification succeeds. In the archive directory, run `sha256sum -c "$archive.sha256"`. Extract into a fresh directory and run `sha256sum -c SHA256SUMS` there. On macOS, use `shasum -a 256 -c` for both checks. The outer checksum covers the archive and the inner manifest covers the extracted files. [GitHub artifact verification](https://cli.github.com/manual/gh_attestation_verify) · [GitHub offline trust procedure](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline)

## Start from this directory

Run the node with this directory as the working directory so it can locate
`core/vm_move/stdlib/bytecode`. With a separately verified genesis:

```sh
AINCORE_GENESIS_PATH=/absolute/path/to/verified-genesis.json \
  ./node --datadir /absolute/path/to/new-observer-data --port 9001 \
  --bootnodes /ip4/VERIFIED_PEER_IP/tcp/VERIFIED_BASE_PORT
```

Replace the paths and peer with the network operator's verified values before
running. The peer multiaddress uses the node's base port. Do not put credentials
in it. Default RPC binding is loopback; preserve that until access controls and
rate limits are configured and tested. A new key is generated only inside the
selected data directory; this command does not enroll a validator.

For a service manager, set `WorkingDirectory` to this extracted directory and
use absolute binary, data and genesis paths. Do not run a live validator key on
a restored old database. Stop and fence an old signer before any approved
validator migration; follow the reviewed network-specific recovery runbook.

Successful unpacking or startup is not mainnet clearance. Fresh join, consensus,
transactions, recovery, operational load and independent review need their own
recorded evidence for the specific release and network.
