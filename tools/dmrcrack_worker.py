#!/usr/bin/env python3
"""
dmrcrack_worker.py - Multi-GPU distributed worker for FSP.DMRCrack
==================================================================
Connects to a coordinator, receives key range chunks, launches
dmrcrack.exe in CLI mode on each chunk, reports best candidate back.

Usage (worker machine):
    python dmrcrack_worker.py --coordinator 192.168.1.100:9999 --bin payloads.bin

Usage (coordinator):
    python dmrcrack_worker.py --coordinator-mode --port 9999 \
        --start 0000000000 --end FFFFFFFFFF --bin payloads.bin
"""
import argparse
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

CHUNK_SIZE = 0x4000000  # 64M keys per chunk (~8 seconds at 8M keys/s)
COORDINATOR_TIMEOUT = 30  # seconds


# ---------------------------------------------------------------------------
# Coordinator
# ---------------------------------------------------------------------------

class Coordinator:
    def __init__(self, port: int, start: int, end: int, bin_path: str):
        self.port      = port
        self.start     = start
        self.end       = end
        self.bin_path  = bin_path
        self.lock      = threading.Lock()
        self.next_key  = start
        self.best_score = -1e38
        self.best_key  = None
        self.workers   = []
        self.done      = False

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.port))
        srv.listen(32)
        print(f"[coordinator] listening on port {self.port}")
        print(f"[coordinator] keyspace: {self.start:010X} – {self.end:010X}")
        total = self.end - self.start
        try:
            while not self.done:
                srv.settimeout(1.0)
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                t = threading.Thread(target=self._handle_worker,
                                     args=(conn, addr), daemon=True)
                t.start()
                self.workers.append(t)
        except KeyboardInterrupt:
            pass
        finally:
            srv.close()

        if self.best_key is not None:
            print(f"\n[coordinator] BEST KEY: {self.best_key}  score={self.best_score:.2f}")
        else:
            print("\n[coordinator] no key found")

    def _handle_worker(self, conn, addr):
        print(f"[coordinator] worker connected: {addr}")
        try:
            conn.sendall(json.dumps({"bin": self.bin_path}).encode() + b"\n")
            while True:
                with self.lock:
                    if self.next_key >= self.end:
                        conn.sendall(json.dumps({"done": True}).encode() + b"\n")
                        break
                    chunk_start = self.next_key
                    chunk_end   = min(self.next_key + CHUNK_SIZE, self.end)
                    self.next_key = chunk_end
                    progress = (chunk_start - self.start) / max(1, self.end - self.start)

                msg = json.dumps({
                    "start": f"{chunk_start:010X}",
                    "end":   f"{chunk_end:010X}",
                }).encode() + b"\n"
                conn.sendall(msg)
                print(f"[coordinator] → {addr} chunk {chunk_start:010X}–{chunk_end:010X} "
                      f"({progress*100:.1f}%)")

                # Wait for result from this chunk
                data = b""
                while b"\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                result = json.loads(data.split(b"\n")[0])

                if result.get("found"):
                    with self.lock:
                        if result["score"] > self.best_score:
                            self.best_score = result["score"]
                            self.best_key   = result["key"]
                            print(f"[coordinator] *** CANDIDATE from {addr}: "
                                  f"key={self.best_key} score={self.best_score:.2f}")
        except Exception as e:
            print(f"[coordinator] worker {addr} error: {e}")
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

class Worker:
    def __init__(self, coordinator_host: str, coordinator_port: int,
                 exe_path: str):
        self.host    = coordinator_host
        self.port    = coordinator_port
        self.exe     = exe_path

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        sock.settimeout(COORDINATOR_TIMEOUT)
        print(f"[worker] connected to {self.host}:{self.port}")

        # Receive config
        data = b""
        while b"\n" not in data:
            data += sock.recv(4096)
        config = json.loads(data.split(b"\n")[0])
        bin_path = config["bin"]
        print(f"[worker] payload file: {bin_path}")

        try:
            while True:
                # Receive chunk assignment
                data = b""
                while b"\n" not in data:
                    chunk = sock.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                msg = json.loads(data.split(b"\n")[0])

                if msg.get("done"):
                    print("[worker] all chunks processed, disconnecting")
                    break

                start = msg["start"]
                end   = msg["end"]
                print(f"[worker] processing {start} – {end}")

                result = self._run_chunk(bin_path, start, end)
                sock.sendall(json.dumps(result).encode() + b"\n")

        except KeyboardInterrupt:
            pass
        finally:
            sock.close()

    def _run_chunk(self, bin_path: str, start: str, end: str) -> dict:
        """Run dmrcrack.exe CLI on a single chunk, parse best result."""
        cmd = [
            self.exe,
            "--cli",
            "--bin", bin_path,
            "--start", start,
            "--end", end,
        ]
        try:
            t0 = time.time()
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            elapsed = time.time() - t0

            # Parse output: expect line "RESULT key=XXXXXXXXXX score=XX.X"
            best_key   = None
            best_score = -1e38
            for line in proc.stdout.splitlines():
                if line.startswith("RESULT"):
                    parts = dict(p.split("=") for p in line.split()[1:])
                    score = float(parts.get("score", "-1e38"))
                    if score > best_score:
                        best_score = score
                        best_key   = parts.get("key")

            if best_key and best_score > 0:
                print(f"[worker] chunk done in {elapsed:.1f}s — candidate: "
                      f"{best_key} score={best_score:.2f}")
                return {"found": True, "key": best_key, "score": best_score}
            else:
                print(f"[worker] chunk done in {elapsed:.1f}s — no candidate")
                return {"found": False}

        except subprocess.TimeoutExpired:
            print("[worker] chunk timed out")
            return {"found": False}
        except Exception as e:
            print(f"[worker] error: {e}")
            return {"found": False}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--coordinator-mode", action="store_true",
                    help="Run as coordinator (divides keyspace)")
    ap.add_argument("--coordinator", default="127.0.0.1:9999",
                    help="coordinator host:port (worker mode)")
    ap.add_argument("--port", type=int, default=9999,
                    help="Listen port (coordinator mode)")
    ap.add_argument("--start", default="0000000000",
                    help="Start key hex (coordinator mode)")
    ap.add_argument("--end", default="FFFFFFFFFF",
                    help="End key hex (coordinator mode)")
    ap.add_argument("--bin", required=True,
                    help="Path to .bin payload file")
    ap.add_argument("--exe", default="bin/dmrcrack.exe",
                    help="Path to dmrcrack.exe (worker mode)")
    args = ap.parse_args()

    if args.coordinator_mode:
        c = Coordinator(
            port      = args.port,
            start     = int(args.start, 16),
            end       = int(args.end,   16),
            bin_path  = args.bin,
        )
        c.run()
    else:
        host, port = args.coordinator.rsplit(":", 1)
        w = Worker(
            coordinator_host = host,
            coordinator_port = int(port),
            exe_path         = args.exe,
        )
        w.run()


if __name__ == "__main__":
    main()
