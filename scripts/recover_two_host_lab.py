#!/usr/bin/env python3
"""Explicit recovery of the disposable October 20 lab, never of live services."""
import shlex
import subprocess

CHAIN = "AINCORE-LAB-646F5C8B4FEBB6A2"
UNIT_PREFIX = "aincore-lab-exitfix-20261022"
GENESIS_SHA = "fb8479b39650654f608b6b159821764e9de31d9da7a1340afddfd26282cde61d"
BINARY_SHA = {
    "alpha@192.168.18.202": "8ac0c2112432f819d3c3dd1735184edc47ebf5e90edd3a3a62e9cc6704f5e893",
    "pi@192.168.18.66": "6882bbd71cc21c8db20c8fdb3825d6e81d335025bf5e46e4495d80778bf890b4",
}
NODES = [
    ("alpha@192.168.18.202", "/home/alpha", "192.168.18.202", 9501,
     "/home/alpha/aincore-exit-fix-20261022/target/exit-followup/node-x86_64"),
    ("alpha@192.168.18.202", "/home/alpha", "192.168.18.202", 9502,
     "/home/alpha/aincore-exit-fix-20261022/target/exit-followup/node-x86_64"),
    ("pi@192.168.18.66", "/home/pi", "192.168.18.66", 9503,
     "/home/pi/aincore-exit-probe-20261022/node"),
    ("pi@192.168.18.66", "/home/pi", "192.168.18.66", 9504,
     "/home/pi/aincore-exit-probe-20261022/node"),
]


def launch_args(index):
    _, home, _, port, binary = NODES[index]
    root = home + "/aincore-lab-20261020"
    peers = ",".join(f"/ip4/{n[2]}/tcp/{n[3]}"
                     for i, n in enumerate(NODES) if i != index)
    return [
        "systemd-run", "--user", f"--unit={UNIT_PREFIX}-{index}",
        "--property=RemainAfterExit=yes",
        f"--property=WorkingDirectory={root}",
        "--property=CPUQuota=50%", "--property=TasksMax=128",
        "--property=MemoryMax=512M", "--property=MemorySwapMax=256M",
        "--property=RuntimeMaxSec=30min", "--property=TimeoutStopSec=120",
        f"--setenv=AINCORE_GENESIS_PATH={root}/genesis.json",
        f"--setenv=AINCORE_CHAIN_ID={CHAIN}",
        "--setenv=AINCORE_GUARD_ORIGIN_INIT=0",
        "--setenv=TOKIO_WORKER_THREADS=2", "--setenv=RAYON_NUM_THREADS=1",
        binary, "--port", str(port), "--datadir", f"{root}/data-{index}",
        "--bootnodes", peers,
    ]


def ssh(host, command):
    return subprocess.check_output(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, command],
        text=True, timeout=30).strip()


def require_memory_controller(controllers):
    if "memory" not in controllers.split():
        raise RuntimeError("memory controller unavailable; refusing unbounded lab launch")


def main():
    # Preflight every host before starting any process. Never create/reset a DB.
    for i, (host, home, _, port, binary) in enumerate(NODES):
        root = home + "/aincore-lab-20261020"
        check = (
            f"test -s {root}/data-{i}/node.key && "
            f"test -s {root}/genesis.json && "
            f"test \"$(systemctl --user is-active aincore-lab-20261020-{i} || true)\" != active"
        )
        ssh(host, check)
        actual = ssh(host, shlex.join(["sha256sum", binary, root + "/genesis.json"]))
        if [line.split()[0] for line in actual.splitlines()] != [BINARY_SHA[host], GENESIS_SHA]:
            raise RuntimeError("candidate binary or genesis does not match the pinned lab")
        # Refuse a port already owned by any service, including earlier lab runs.
        code = ("import socket,sys\nfor port in sys.argv[1:]:\n with socket.socket() as s:\n"
                "  s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
                "  s.bind(('0.0.0.0',int(port)))")
        ssh(host, shlex.join(["python3", "-c", code, str(port - 1000), str(port), str(port + 100)]))
    for host in dict.fromkeys(n[0] for n in NODES):
        controllers = ssh(host, "cat /sys/fs/cgroup/cgroup.controllers")
        require_memory_controller(controllers)
    for i, node in enumerate(NODES):
        print(ssh(node[0], shlex.join(launch_args(i))), flush=True)


if __name__ == "__main__":
    main()
