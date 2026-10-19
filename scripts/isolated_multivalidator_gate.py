#!/usr/bin/env python3
"""Four-process local failure gate. Only creates and removes its own Docker resources.

No published ports, host networking, live keys, or existing databases are used.
This is not an independent-operator soak or an independent QC verifier.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import time
import traceback


def command(*args, timeout=90):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0:3]}: {result.stderr[-2000:]} {result.stdout[-1000:]}")
    return result.stdout.strip()


def certified_identity(reply, chain):
    if reply.get("available") is not True or reply.get("verified") is not True:
        raise ValueError("certificate unavailable or not verified by node RPC")
    cert = reply["quorum_certificate"]
    if cert["chain_id"] != chain or int(cert["block_height"]) != int(reply["height"]):
        raise ValueError("certificate chain/height mismatch")
    signed, total = int(cert["signed_stake"]), int(cert["total_stake"])
    if total <= 0 or signed > total or signed * 3 <= total * 2:
        raise ValueError("certificate lacks strict two-thirds stake")
    values = tuple(cert[k] for k in ("block_hash", "state_root", "receipts_root", "finality_digest"))
    if any(not isinstance(v, str) or not v for v in values):
        raise ValueError("empty certified commitment")
    return int(reply["height"]), values


class Gate:
    def __init__(self, args):
        self.args = args
        self.root = args.output.resolve()
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.tag = "aincore-chaos-" + secrets.token_hex(6)
        self.chain = self.tag.upper()
        self.names = [f"{self.tag}-{i}" for i in range(4)]
        self.created = []
        self.ips = []
        self.observed = {}
        self.stage = "setup"
        self.report = {"passed": False, "phases": [], "chain_id": self.chain,
                       "scope": "single-host four-process Docker network; RPC QC verification"}

    def event(self, **data):
        record = {"time": time.time(), "stage": self.stage, **data}
        with (self.root / "events.jsonl").open("a") as file:
            file.write(json.dumps(record) + "\n")
        print(json.dumps(record), flush=True)

    def docker(self, *args, **kwargs):
        return command("docker", *map(str, args), **kwargs)

    def rpc(self, i, method, params=None):
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []})
        code = ("import urllib.request,sys; "
                "r=urllib.request.Request('http://127.0.0.1:8002/rpc',"
                "data=sys.argv[1].encode(),headers={'Content-Type':'application/json'}); "
                "print(urllib.request.urlopen(r,timeout=8).read().decode())")
        response = json.loads(self.docker("exec", self.names[i], "python3", "-c", code, payload, timeout=15))
        if response.get("error"):
            raise RuntimeError(str(response["error"]))
        return response["result"]

    def heights(self, indices):
        return [int(self.rpc(i, "aincore_getStatus")["latest_height"]) for i in indices]

    def wait_progress(self, indices, minimum, timeout=600):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            # Exited/OOM containers are failures, not transient RPC delays.
            for i in indices:
                state = json.loads(self.docker("inspect", self.names[i]))[0]["State"]
                if not state["Running"]:
                    raise RuntimeError(f"node {i} exited: {state}")
            try:
                heights = self.heights(indices)
            except (RuntimeError, ValueError, KeyError) as error:
                self.event(waiting=str(error)[-300:])
            else:
                self.event(nodes=list(indices), heights=heights, target=minimum)
                if min(heights) >= minimum:
                    self.check_certificates(indices)
                    return heights
            time.sleep(5)
        raise TimeoutError(f"{self.stage}: no progress to {minimum}")

    def check_certificates(self, indices):
        latest = [self.rpc(i, "aincore_getQuorumCert") for i in indices]
        common = min(certified_identity(reply, self.chain)[0] for reply in latest)
        if common < 1:
            raise ValueError("no certified blocks")
        for i in indices:
            # Compare every available common height, including pre-crash history.
            for height in range(1, common + 1):
                actual, identity = certified_identity(self.rpc(i, "aincore_getQuorumCert", [height]), self.chain)
                if actual != height:
                    raise ValueError("RPC returned a different height")
                previous = self.observed.setdefault(height, identity)
                if previous != identity:
                    raise ValueError(f"CONFLICT at certified height {height} on node {i}")
        self.event(certified_common_height=common, checked_nodes=list(indices))
        return common

    def setup(self):
        source = self.args.source.resolve()
        binary = self.args.binaries.resolve()
        self.report["commit"] = command("git", "-C", str(source), "rev-parse", "HEAD")
        if command("git", "-C", str(source), "status", "--porcelain"):
            raise ValueError("source must be clean")
        self.image = self.docker("image", "inspect", self.args.image, "--format", "{{.Id}}")
        self.report["image"] = self.image
        self.report["binary_sha256"] = {name: hashlib.sha256((binary / name).read_bytes()).hexdigest()
                                        for name in ("node", "genesis-tool")}
        specs = []
        for i in range(4):
            directory = self.root / f"node-{i}"
            directory.mkdir(mode=0o700)
            seed = secrets.token_bytes(32)
            key = directory / "node.key"
            key.write_bytes(seed)
            key.chmod(0o600)
            specs.append(seed.hex() + ":1000000")
        seeds = self.root / "test-seeds.txt"
        seeds.write_text("\n".join(specs))
        seeds.chmod(0o600)
        self.mounts = ["-v", f"{source}:/src:ro", "-v", f"{binary}:/b:ro"]
        # Timing constants are synthetic test inputs, not a production measurement.
        self.docker("run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                    *self.mounts, "-v", f"{self.root}:/work", "-w", "/src",
                    "--entrypoint", "/b/genesis-tool", self.image, "gen-multi",
                    "--seeds-file", "/work/test-seeds.txt", "--chain-id", self.chain,
                    "--block-time-ms", "3000", "--clock-cap-secs", "9", "--out", "/work/genesis.json")
        self.docker("network", "create", "--internal", "--label", f"aincore.gate={self.tag}", self.tag)
        self.network_created = True
        for i, name in enumerate(self.names):
            self.docker("create", "--name", name, "--label", f"aincore.gate={self.tag}",
                        "--network", self.tag, "--memory", "512m", "--memory-swap", "768m",
                        "--cpus", "0.5", "--pids-limit", "256", "--read-only",
                        "--tmpfs", "/tmp:rw,size=64m", "--user", f"{os.getuid()}:{os.getgid()}",
                        *self.mounts, "-v", f"{self.root / f'node-{i}'}:/data",
                        "-v", f"{self.root / 'genesis.json'}:/genesis.json:ro", "-w", "/src",
                        "-e", "AINCORE_GENESIS_PATH=/genesis.json", "-e", f"AINCORE_CHAIN_ID={self.chain}",
                        "-e", "TOKIO_WORKER_THREADS=2", "-e", "RAYON_NUM_THREADS=1",
                        "--entrypoint", "/bin/sh", self.image, "-c",
                        "while [ ! -f /data/start.sh ]; do sleep 1; done; exec /bin/sh /data/start.sh")
            self.created.append(name)
            self.docker("start", name)
            details = json.loads(self.docker("inspect", name))[0]
            self.ips.append(details["NetworkSettings"]["Networks"][self.tag]["IPAddress"])
        for i in range(4):
            peers = ",".join(f"/ip4/{ip}/tcp/9002" for j, ip in enumerate(self.ips) if i != j)
            script = self.root / f"node-{i}" / "start.sh"
            temp = script.with_suffix(".tmp")
            temp.write_text(
                "if [ ! -f /data/gate-first-boot ]; then\n"
                "  export AINCORE_GUARD_ORIGIN_INIT=1\n"
                "  touch /data/gate-first-boot\n"
                "fi\n"
                f"exec /b/node --port 9002 --datadir /data --bootnodes {peers}\n")
            temp.replace(script)
        self.event(containers=self.names, network=self.tag)

    def run(self):
        try:
            self.setup()
            self.stage = "healthy-four-validators"
            heights = self.wait_progress(range(4), 5)
            self.report["phases"].append({"name": self.stage, "passed": True, "heights": heights})
            self.stage = "one-validator-crash"
            self.docker("kill", "--signal", "KILL", self.names[3])
            heights = self.wait_progress(range(3), max(heights) + 3)
            self.report["phases"].append({"name": self.stage, "passed": True, "heights": heights})
            self.stage = "restart-and-catch-up"
            self.docker("start", self.names[3])
            heights = self.wait_progress(range(4), max(heights) + 2)
            self.report["phases"].append({"name": self.stage, "passed": True, "heights": heights})
            self.stage = "partition-without-quorum-2-plus-1-plus-1"
            for i in (2, 3):
                self.docker("network", "disconnect", self.tag, self.names[i])
            time.sleep(30)  # Let already-in-flight certified work settle.
            before = [certified_identity(self.rpc(i, "aincore_getQuorumCert"), self.chain)[0] for i in range(4)]
            time.sleep(45)
            after = [certified_identity(self.rpc(i, "aincore_getQuorumCert"), self.chain)[0] for i in range(4)]
            if before != after:
                raise ValueError(f"certified height moved without quorum: {before} -> {after}")
            self.check_certificates(range(4))
            self.report["phases"].append({"name": self.stage, "passed": True, "heights": after})
            self.stage = "partition-healed"
            for i in (2, 3):
                self.docker("network", "connect", "--ip", self.ips[i], self.tag, self.names[i])
            heights = self.wait_progress(range(4), max(heights + after) + 3)
            self.report["phases"].append({"name": self.stage, "passed": True, "heights": heights})
            self.report["passed"] = True
            self.stage = "complete"
        except BaseException as error:
            self.report["error"] = str(error)
            self.report["traceback"] = traceback.format_exc()
        finally:
            self.report["stage"] = self.stage
            self.report["checked_certified_heights"] = len(self.observed)
            errors = []
            for name in self.created:
                try:
                    (self.root / f"{name}.inspect.json").write_text(self.docker("inspect", name))
                    logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True, timeout=30)
                    (self.root / f"{name}.log").write_text(logs.stdout + logs.stderr)
                    self.docker("rm", "-f", name)
                except Exception as error:
                    errors.append(f"{name}: {error}")
            if getattr(self, "network_created", False):
                try:
                    self.docker("network", "rm", self.tag)
                except Exception as error:
                    errors.append(str(error))
            if errors:
                self.report["passed"] = False
                self.report["cleanup_errors"] = errors
            (self.root / "result.json").write_text(json.dumps(self.report, indent=2))
            print(json.dumps(self.report, indent=2), flush=True)
        return 0 if self.report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default="rust:latest")
    args = parser.parse_args()
    def interrupted(signum, _frame):
        raise RuntimeError(f"interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(Gate(args).run())
