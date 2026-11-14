"""Separate-process TCP read smoke test for the compatibility-only C++ examples."""

import argparse
import os
import re
import socket
import subprocess
import threading
import time
from pathlib import Path


class Peer:
    def __init__(self, executable, port, exit_command):
        self.exit_command = exit_command
        self.lines = []
        self.condition = threading.Condition()
        self.process = subprocess.Popen(
            [str(executable), "--port", str(port)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.process.stdout:
            with self.condition:
                self.lines.append(line.rstrip())
                self.condition.notify_all()

    def send(self, command):
        with self.condition:
            cursor = len(self.lines)
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        return cursor

    def wait(self, pattern, cursor=0, timeout=12):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                if any(re.search(pattern, line) for line in self.lines[cursor:]):
                    return
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self.process.poll() is not None:
                    raise AssertionError(
                        f"Missing {pattern!r}; exit={self.process.poll()}\n"
                        + "\n".join(self.lines[-30:])
                    )
                self.condition.wait(min(remaining, 0.2))

    def close(self):
        if self.process.poll() is None:
            try:
                self.send(self.exit_command)
            except (OSError, ValueError):
                pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.reader.join(timeout=2)


def free_tcp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(master_exe, outstation_exe):
    port = free_tcp_port()
    outstation = Peer(outstation_exe, port, "quit")
    master = None
    try:
        outstation.wait("EXAMPLE ONLY: SA DISABLED")
        for kind, value in (
            ("binary", "on"),
            ("double", "intermediate"),
            ("analog", "12.5"),
            ("bos", "on"),
            ("aos", "-3.5"),
        ):
            cursor = outstation.send(f"set {kind} 0 {value} suppress")
            outstation.wait(rf"Update submitted: {kind}\[0\]={re.escape(value)}", cursor)

        master = Peer(master_exe, port, "x")
        master.wait(r"channel state change: OPEN$")
        outstation.wait(r"channel state change: OPEN$")
        for request, expected in (
            ("s 1 1 6", r"\[0\] : 1 :"),
            ("s 3 2 6", r"\[0\] : INTERMEDIATE :"),
            ("s 30 5 0 0 0", r"\[0\] : 12\.5 :"),
            ("s 30 5 1 0 0", r"\[0\] : 12\.5 :"),
            ("s 30 5 6", r"\[0\] : 12\.5 :"),
            ("s 10 2 6", r"\[0\] : 1 :"),
            ("s 40 3 6", r"\[0\] : -3\.5 :"),
        ):
            cursor = master.send(request)
            master.wait("READ queued", cursor)
            master.wait(expected, cursor)

        cursor = master.send("s 30 5 0 9 0")
        master.wait("Invalid range for Q00/Q01", cursor)
        cursor = outstation.send("set analog 10 1")
        outstation.wait("Invalid set syntax or index", cursor)
        print("EXAMPLE TCP PASS: native Master/Outstation readback and invalid inputs")
    finally:
        if master is not None:
            master.close()
        outstation.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--master", type=Path, required=True)
    parser.add_argument("--outstation", type=Path, required=True)
    args = parser.parse_args()
    if not args.master.is_file() or not args.outstation.is_file():
        parser.error("Build master-demo and outstation-demo first")
    run(args.master, args.outstation)


if __name__ == "__main__":
    main()
