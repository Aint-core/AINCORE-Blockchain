#!/usr/bin/env python3
"""NAS-only transaction gate, restricted to the disposable lab and its test key."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import subprocess
import threading
import time
import urllib.request

ROOT = Path("/home/alpha/aincore-lab-20261020")
RPC = "http://127.0.0.1:8501/rpc"
CHAIN = "AINCORE-LAB-646F5C8B4FEBB6A2"

def rejection(reply, reasons):
    error = reply.get("error") or {}
    message = error.get("message", "").lower()
    if error.get("code") != -32010 or not any(reason in message for reason in reasons):
        raise RuntimeError(f"not the expected admission rejection: {reply}")
    return error


def call(method, params):
    request = urllib.request.Request(RPC, data=json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def result(method, params):
    reply = call(method, params)
    if reply.get("error"):
        raise RuntimeError(reply["error"])
    return reply["result"]


def main():
    report = {"passed": False, "scope": "NAS admission/execution; lab tokens only"}
    output = ROOT / ("transaction-gate-" + str(time.time_ns()) + ".json")
    try:
        if json.loads((ROOT / "manifest.json").read_text())["chain_id"] != CHAIN:
            raise RuntimeError("wrong lab identity")
        captured = []

        class Capture(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path != "/get_network_info":
                    self.send_error(404)
                    return
                with urllib.request.urlopen(
                        "http://127.0.0.1:8501/get_network_info", timeout=10) as response:
                    body = response.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if payload["method"] == "aincore_sendTransaction":
                    captured.append(payload["params"][0])
                    reply = {"jsonrpc": "2.0", "id": payload["id"],
                             "result": {"status": "captured-not-broadcast"}}
                else:
                    reply = call(payload["method"], payload["params"])
                    reply["id"] = payload["id"]
                body = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        recipient = hashlib.sha256(("lab-recipient-" + str(time.time_ns())).encode()).hexdigest()
        server = HTTPServer(("127.0.0.1", 0), Capture)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            subprocess.run([
                "/home/alpha/aincore-hardening-20261016/target/release/aincore-cli",
                "--rpc", f"http://127.0.0.1:{server.server_port}/rpc",
                "--keyfile", str(ROOT / "data-0/node.key"), "--chain-id", CHAIN,
                "--assume-yes", "transfer", recipient, "1",
            ], check=True, timeout=60, capture_output=True, text=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        if len(captured) != 1:
            raise RuntimeError("expected one captured signed transaction")
        tx = json.loads(captured[0]) if isinstance(captured[0], str) else captured[0]
        if tx["chain_id"] != CHAIN:
            raise RuntimeError("wrong signed chain")
        before = int(result("aincore_getBalance", [recipient])["move_balance"])
        forged = dict(tx)
        forged["signature"] = ("0" if tx["signature"][0] != "0" else "1") + tx["signature"][1:]
        denial = call("aincore_sendTransaction", [forged])
        report["forged_signature"] = rejection(denial, ("invalid signature",))
        accepted = result("aincore_sendTransaction", [tx])
        tx_hash = accepted["tx_hash"]
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            receipt = result("aincore_getTransactionReceipt", [tx_hash])
            execution = receipt.get("execution_receipt") or {}
            if execution.get("status") == "success" and receipt.get("block_height"):
                break
            time.sleep(3)
        else:
            raise RuntimeError(f"no successful indexed execution: {receipt}")
        balance = int(result("aincore_getBalance", [recipient])["move_balance"])
        if balance - before != 10**18:
            raise RuntimeError(f"incorrect recipient delta {balance - before}")
        nonce = result("aincore_getAccountNonce", [tx["sender"]])["sequence_number"]
        replay = call("aincore_sendTransaction", [tx])
        replay_error = rejection(replay, ("duplicate transaction", "nonce", "sequence"))
        report.update(valid_receipt=receipt, replay_rejection=replay_error,
                      recipient_delta=str(balance-before))
        height = int(result("aincore_getStatus", [])["latest_height"])
        deadline = time.monotonic() + 90
        while int(result("aincore_getStatus", [])["latest_height"]) < height + 3:
            if time.monotonic() > deadline:
                raise RuntimeError("no post-replay progress")
            time.sleep(3)
        if int(result("aincore_getBalance", [recipient])["move_balance"]) != balance:
            raise RuntimeError("recipient balance changed after replay")
        if result("aincore_getAccountNonce", [tx["sender"]])["sequence_number"] != nonce:
            raise RuntimeError("nonce changed after replay")
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            report["cli_stderr"] = error.stderr
            report["cli_stdout"] = error.stdout
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(output), **report}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
