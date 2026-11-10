"""Bounded CLI process checks with native outcomes and a small F01 wire oracle.

All children are hidden, owned, bounded, and stopped before credential cleanup.
"""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import threading
import time
import uuid


class Peer:
    def __init__(self, exe, role, options):
        self.lines = []
        self.cv = threading.Condition()
        self.process = subprocess.Popen(
            [str(exe), role, *options], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)

        def receive():
            for line in self.process.stdout:
                with self.cv:
                    self.lines.append(line.rstrip())
                    self.cv.notify_all()
        self.reader = threading.Thread(target=receive, daemon=True)
        self.reader.start()

    def send(self, command):
        with self.cv:
            cursor = len(self.lines)
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        return cursor

    def wait(self, pattern, cursor=0, timeout=20):
        until = time.monotonic() + timeout
        with self.cv:
            while True:
                for line in self.lines[cursor:]:
                    if re.search(pattern, line):
                        return line
                remaining = until - time.monotonic()
                if remaining <= 0 or self.process.poll() is not None:
                    raise AssertionError(f"Missing {pattern!r}; exit={self.process.poll()}\n" + "\n".join(self.lines[-35:]))
                self.cv.wait(min(remaining, 0.25))

    def task(self, command, success=True, timeout=25):
        cursor = self.send(command)
        label = command.split()[0]
        if label in ("crob", "analog"):
            self.wait(r"\[RESULT\].*task=", cursor, timeout)
            if success:
                self.wait(r"state=SUCCESS status=SUCCESS", cursor, timeout)
            else:
                assert not any("state=SUCCESS status=SUCCESS" in line for line in self.lines[cursor:]), self.lines[cursor:]
        else:
            result = self.wait(r"\[TASK\] " + label + r" (?!START)[A-Z_]+", cursor, timeout)
            assert (result.endswith(" SUCCESS")) == success, "\n".join(self.lines[max(0, cursor - 20):])
        return cursor

    def noack(self, command, timeout=25):
        cursor = self.send(command)
        completion = self.wait(
            r"\[FC6\] local transmission complete; remote execution unknown$", cursor, timeout)
        self.wait(r"FC6 locally accepted; remote execution unknown\)$", cursor, timeout)
        assert not any("[RESULT]" in line or "status=SUCCESS" in line
                       for line in self.lines[cursor:]), self.lines[cursor:]
        return completion

    def executed(self, expected):
        cursor = self.send("status")
        self.wait(r"channel=.* executed=" + str(expected) + r"$", cursor)

    def close(self):
        if self.process.poll() is None:
            try:
                self.send("quit")
            except BrokenPipeError:
                pass
        try:
            code = self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
            raise AssertionError("CLI failed to shut down cleanly")
        self.reader.join(timeout=2)
        assert code == 0, (code, self.lines[-20:])


def stop(*peers):
    with ExitStack() as stack:
        for peer in peers:
            if peer:
                stack.callback(peer.close)


def run(exe, *args, success=True):
    result = subprocess.run([str(exe), *args], capture_output=True, text=True, timeout=60,
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    assert result.returncode == (0 if success else 1), (args, result.returncode, result.stdout[-2000:], result.stderr[-2000:])
    return result


def loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return ["--port", str(listener.getsockname()[1])]


def connected(exe, options, master_options=(), out_options=()):
    if "--port" not in options:
        options = [*options, *loopback_port()]
    out = Peer(exe, "outstation", [*options, *out_options])
    master = Peer(exe, "master", [*options, *master_options])
    try:
        master.wait(r"\[LINK\] OPEN$")
        out.wait(r"\[LINK\] OPEN$")
        return master, out
    except BaseException:
        stop(out, master)
        raise


def ft3_crc(data):
    crc = 0
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA6BC if crc & 1 else 0)
    return struct.pack("<H", crc ^ 0xFFFF)


def f01_link_frame(apdu, transport_seq):
    return f01_ft3_frame(0xC4, 10, 1, bytes([0xC0 | transport_seq]) + apdu)


def f01_ft3_frame(control, destination, source, user_data=b""):
    header = struct.pack("<2sBBHH", b"\x05\x64", len(user_data) + 5, control, destination, source)
    blocks = [user_data[i:i + 16] for i in range(0, len(user_data), 16)]
    return header + ft3_crc(header) + b"".join(block + ft3_crc(block) for block in blocks)


def f01_receive_frame(peer):
    # One absolute deadline also bounds a peer sending one byte at a time.
    deadline = time.monotonic() + 5

    def exact(size):
        data = bytearray()
        while len(data) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("incomplete F01 FT3 frame")
            peer.settimeout(remaining)
            chunk = peer.recv(size - len(data))
            assert chunk, "unexpected EOF in F01 FT3 frame"
            data.extend(chunk)
        return bytes(data)

    header = exact(10)
    assert header[:2] == b"\x05\x64" and header[8:] == ft3_crc(header[:8]), header.hex()
    assert header[4:8] == bytes.fromhex("01 00 0A 00"), header.hex()
    remaining = header[2] - 5
    assert 0 <= remaining <= 250, header.hex()
    data = bytearray()
    while remaining:
        size = min(remaining, 16)
        block = exact(size + 2)
        assert block[-2:] == ft3_crc(block[:-2]), block.hex()
        data.extend(block[:-2])
        remaining -= size
    return header[3], bytes(data)


def f01_receive_apdu(peer):
    control, data = f01_receive_frame(peer)
    assert control == 0x44 and len(data) >= 3, (control, data.hex())
    assert data[0] & 0xC0 == 0xC0, data.hex()
    return data[0] & 0x3F, data[1:]


def f01_publish_double_events(out, count, offset=0):
    for n in range(offset, offset + count):
        value = "on" if n % 2 == 0 else "off"
        index = n % 10
        cursor = out.send(f"set double {index} {value} force")
        out.wait(rf"\[UPDATE\].*double {index} {value} force", cursor)
    cursor = out.send("show")
    out.wait(r"Input values are this application", cursor)  # Executor barrier.


def f01_double_events(lines):
    events = [re.search(r"EVENT DoubleBit\[(\d+)\]=(DETERMINED_ON|DETERMINED_OFF)", line) for line in lines]
    return [(int(event[1]), event[2]) for event in events if event]


def f01_expected_double_events(start, end):
    return [(n % 10, "DETERMINED_ON" if n % 2 == 0 else "DETERMINED_OFF") for n in range(start, end)]


def f01_solicited_fragments(exe):
    options = ["--auth", "compat", *loopback_port()]
    out = Peer(exe, "outstation", [*options, "--tx-fragment-bytes", "250", "--sol-confirm-ms", "1000"])
    master = None
    try:
        out.wait(r"\[HELP\]")
        port = int(options[-1])

        def check_events(apdu, control, start, count):
            assert apdu[:2] == bytes([control, 0x81]), apdu.hex()
            assert apdu[2] & 0x02 == (0x02 if count == 26 else 0), apdu.hex()
            assert apdu[3:9] == bytes([0, 4, 2, 0x28, count, 0]), apdu.hex()
            assert len(apdu) == 9 + 9 * count, apdu.hex()
            for offset in range(count):
                index, flags = struct.unpack_from("<HB", apdu, 9 + offset * 9)
                n = start + offset
                assert index == n % 10 and flags == (0x81 if n % 2 == 0 else 0x41), apdu.hex()

        f01_publish_double_events(out, 28)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            out.wait(r"\[LINK\] OPEN$")
            # 249 APDU + TPDU byte makes a full 292-octet FT3 frame. Its
            # final, incomplete object header must give PARAMETER_ERROR.
            malformed = bytes.fromhex("C0 01") + bytes.fromhex("3C 02 06") * 82 + b"\x01"
            full = f01_link_frame(malformed, 0)
            assert len(full) == 292
            corrupt = full[:-1] + bytes([full[-1] ^ 0x80])
            raw.sendall(bytes.fromhex("05 64 01") + corrupt + full[:70])
            raw.sendall(full[70:])
            tp_seq, apdu = f01_receive_apdu(raw)
            assert apdu[:2] == bytes.fromhex("C0 81") and apdu[3:] == b"\x04", apdu.hex()

            raw.sendall(f01_link_frame(bytes.fromhex("CF 01 3C 02 06"), 1))
            first_seq, first = f01_receive_apdu(raw)
            assert first_seq == (tp_seq + 1) % 64
            check_events(first, 0xAF, 0, 26)

            time.sleep(1.2)  # Lose the first CONFIRM, then send it after the configured timer.
            raw.sendall(f01_link_frame(bytes.fromhex("CF 00"), 2)
                        + f01_link_frame(bytes.fromhex("CE 01 3C 02 06"), 3))
            retry_seq, retry = f01_receive_apdu(raw)
            assert retry_seq == (first_seq + 1) % 64
            assert retry[1:] == first[1:], retry.hex()
            check_events(retry, 0xAE, 0, 26)

            raw.sendall(f01_link_frame(bytes.fromhex("CE 00"), 4))
            final_seq, final = f01_receive_apdu(raw)
            assert final_seq == (retry_seq + 1) % 64
            check_events(final, 0x6F, 26, 2)
            # Disconnect without confirming the final two events.

        f01_publish_double_events(out, 28, 28)
        master = Peer(exe, "master", options)
        master.wait(r"\[LINK\] OPEN$")
        master.task("scan class1", timeout=20)  # Complete startup and the first scan.
        with master.cv:
            actual = f01_double_events(master.lines)
            assert actual == f01_expected_double_events(26, 56), actual
        cursor = master.task("scan class1", timeout=20)  # Check for redelivery.
        with master.cv:
            assert not f01_double_events(master.lines[cursor:]), master.lines[cursor:]
    finally:
        stop(out, master)


def f01_confirmed_link(exe):
    ack = f01_ft3_frame(0x80, 10, 1)
    reset = (0x40, b"")
    for mode in ("never", "always", "multi-frame"):
        options = ["--auth", "compat", *loopback_port()]
        out = Peer(exe, "outstation", [*options, "--link-confirm", mode, "--link-timeout-ms", "1000"])
        try:
            out.wait(r"\[HELP\]")
            port = int(options[-1])
            # A legal-looking but incomplete FT3 frame ends at TCP EOF. The next connection starts clean.
            with socket.create_connection(("127.0.0.1", port), timeout=5) as stale:
                out.wait(r"\[LINK\] OPEN$")
                stale.sendall(f01_link_frame(bytes.fromhex("C9 18"), 0)[:11])
            f01_publish_double_events(out, 28)

            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                raw.sendall(f01_link_frame(bytes.fromhex("C0 18"), 0))
                if mode == "always":
                    assert f01_receive_frame(raw) == reset
                    raw.sendall(f01_ft3_frame(0x80, 10, 2))  # Foreign source cannot ACK reset.
                    raw.settimeout(0.15)
                    try:
                        assert not raw.recv(1), "foreign source advanced the link transaction"
                        raise AssertionError("link closed on a foreign ACK")
                    except socket.timeout:
                        pass
                    raw.sendall(ack)
                control, single = f01_receive_frame(raw)
                assert control == (0x73 if mode == "always" else 0x44), (mode, control)
                assert single[0] & 0xC0 == 0xC0 and single[1:3] == b"\xC0\x81", single.hex()

                if mode == "always":
                    raw.sendall(f01_ft3_frame(0x81, 10, 1))  # NACK, DFC=0: one reset recovery.
                    assert f01_receive_frame(raw) == reset
                    raw.sendall(ack)
                    assert f01_receive_frame(raw) == (0x73, single)
                    raw.sendall(f01_ft3_frame(0x91, 10, 1))  # NACK, DFC=1: fail and close.
                    raw.settimeout(5)
                    try:
                        assert raw.recv(1) == b"", "DFC=1 unexpectedly retransmitted"
                    except ConnectionResetError:
                        pass
                    # A new TCP connection will need a fresh reset handshake.

            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                raw.sendall(f01_link_frame(bytes.fromhex("C1 01 3C 02 06"), 0))
                if mode != "never":
                    assert f01_receive_frame(raw) == reset
                    raw.sendall(ack)
                control, first = f01_receive_frame(raw)
                assert control == (0x44 if mode == "never" else 0x73), (mode, control)
                assert len(first) == 250 and first[0] & 0xC0 == 0x40, first.hex()
                if mode != "never":
                    raw.sendall(ack)
                control, last = f01_receive_frame(raw)
                assert control == (0x44 if mode == "never" else 0x53), (mode, control)
                assert len(last) == 13 and last[0] & 0xC0 == 0x80, last.hex()
                assert last[0] & 0x3F == ((first[0] + 1) & 0x3F)
                apdu = first[1:] + last[1:]
                assert apdu[:2] == b"\xE1\x81" and apdu[4:9] == b"\x04\x02\x28\x1C\x00", apdu.hex()
                if mode != "never":
                    raw.sendall(ack)
                raw.sendall(f01_link_frame(bytes.fromhex("C1 00"), 1))
        finally:
            stop(out)


def f01_required_fragments(exe):
    profile = "f01-" + uuid.uuid4().hex[:12]
    args = ["--test-only", "--profile", profile, "--auth", "method4"]
    run(exe, "test-provision", *args)
    master = out = None
    try:
        master, out = connected(exe, [*args, "--trust-system-time", "--reply-ms", "5000", "--trace"],
                                out_options=["--tx-fragment-bytes", "250"])
        master.task("read 1 2 0 0", timeout=25)  # Startup and authentication barrier.
        f01_publish_double_events(out, 28)
        cursor = master.task("scan class1", timeout=25)
        with master.cv:
            lines = master.lines[cursor:]
            assert f01_double_events(lines) == f01_expected_double_events(0, 28), lines
            assert sum("Response fragment" in line for line in lines) == 2, lines
        cursor = master.task("scan class1", timeout=25)
        with master.cv:
            assert not f01_double_events(master.lines[cursor:]), master.lines[cursor:]
    finally:
        try:
            stop(out, master)
        finally:
            run(exe, "test-cleanup", *args)


def compatibility(exe):
    master, out = connected(exe, ["--auth", "compat"], out_options=["--unsolicited", "--command-events"])
    try:
        master.task("scan integrity")
        out.send("set analog 3 12.5 force")
        out.wait(r"\[UPDATE\].*analog 3 12.5")
        cursor = master.task("read 30 5 3 3")
        master.wait(r"Analog\[3\]=12.5", cursor)
        cursor = master.task("scan class2")
        master.wait(r"EVENT Analog\[3\]=12.5.*time=[1-9]", cursor)
        out.send("set double 6 on force")
        out.wait(r"\[UPDATE\].*double 6 on")
        cursor = master.task("read 3 2 6 6")
        master.wait(r"STATIC DoubleBit\[6\]=DETERMINED_ON", cursor)
        cursor = master.task("scan class1")
        master.wait(r"EVENT DoubleBit\[6\]=DETERMINED_ON.*time=[1-9]", cursor)
        out.send("set counter 5 123 force")
        out.wait(r"\[UPDATE\].*counter 5 123")
        cursor = master.task("read 20 1 5 5")
        master.wait(r"STATIC Counter\[5\]=123", cursor)
        cursor = master.task("scan class3")
        master.wait(r"EVENT Counter\[5\]=123", cursor)
        master.task("scan class0")
        master.task("crob 3 on")
        master.task("crob 3 off direct")
        master.task("analog 1 2 42")
        master.task("analog 2 2 -12 direct")
        master.task("analog 3 2 4.25")
        master.task("analog 4 2 8.5 direct")
        master.noack("crob 4 on noack")
        out.executed(7)
        master.noack("analog 1 4 77 noack")
        out.executed(8)
        for variation, index, value, expected_count in (
                (2, 5, "-23", 9),
                (3, 6, "6.75", 10),
                (4, 7, "9.125", 11)):
            master.noack(f"analog {variation} {index} {value} noack")
            out.executed(expected_count)
            cursor = master.task(f"read 40 {variation} {index} {index}")
            master.wait(rf"AnalogOutput\[{index}\]={re.escape(value)}", cursor)
        master.noack("analog 2 10 17 noack")
        out.executed(11)
        cursor = master.task("read 13 0")
        master.wait(r"Group13Var2.*BinaryCommandEvent\[3\]=ON.*SUCCESS", cursor)
        master.wait(r"Group13Var2.*BinaryCommandEvent\[3\]=OFF.*SUCCESS", cursor)
        cursor = master.task("read 43 0")
        for variation, value in ((3, "42"), (4, "-12"), (7, "4.25"), (8, "8.5")):
            master.wait(rf"Group43Var{variation}.*AnalogCommandEvent\[2\]={re.escape(value)}.*SUCCESS", cursor)
        cursor = master.task("read 10 2 3 3")
        master.wait(r"BinaryOutput\[3\]=OFF", cursor)
        cursor = master.task("read 40 3 2 2")
        master.wait(r"AnalogOutput\[2\]=8.5", cursor)
        cursor = master.task("read 10 2 4 4")
        master.wait(r"BinaryOutput\[4\]=ON", cursor)
        cursor = master.task("read 40 1 4 4")
        master.wait(r"AnalogOutput\[4\]=77", cursor)
        cursor = master.task("attr 210")
        master.wait(r"\[ATTR\].*Group0Var210.*value=0$", cursor)
        cursor = master.task("attr 254")
        master.wait(r"\[ATTR\].*Group0Var210.*value=0$", cursor)
        cursor = master.task("attr 255")
        master.wait(r"\[ATTR\] variation=210 properties=0$", cursor)
        cursor = master.send("attr 209")
        master.wait(r"IIN=.* REQUEST_ERROR", cursor)
        master.wait(r"\[TASK\] attr (?!START)[A-Z_]+", cursor)
        cursor = master.task("time")
        master.wait(r"Absolute time=[1-9]", cursor)
        master.task("assign 30 1 3 3")
        master.task("unsol on")
        out.send("set binary 7 on force")
        out.wait(r"\[UPDATE\].*binary 7 on")
        master.wait(r"Binary\[7\]=ON")
    finally:
        stop(out, master)
    print("PASS compatibility: real READ/events/classes/attributes/controls/command events/output readback", flush=True)


def secure(exe, method):
    profile = "pc-" + uuid.uuid4().hex[:12]
    args = ["--test-only", "--profile", profile, "--auth", method]
    run(exe, "test-provision", *args)
    options = [*args, *loopback_port(), "--trust-system-time", "--reply-ms", "5000", "--trace"]
    master = out = None
    try:
        master, out = connected(exe, options)
        master.task("read 1 2 0 0")
        master.task("crob 0 on")
        out.executed(1)
        out.wait(r"\[SA-OBJECT\] TX G120V1$")
        master.wait(r"\[SA-OBJECT\] TX G120V2$")
        cursor = master.task("attr 210")
        master.wait(r"\[ATTR\].*Group0Var210.*value=18$", cursor)
        cursor = master.send("auth")
        master.wait(r"\[SESSION\] user=2 ready=1", cursor)
        master.task("ruk change operator 1 1 1")
        for variation in (10, 11, 13, 14 if method == "method68" else 15):
            master.wait(r"\[SA-OBJECT\] TX G120V" + str(variation) + r"$")
        out.wait(r"\[SA-OBJECT\] TX G120V12$")
        out.wait(r"\[SA-OBJECT\] TX G120V15$")
        master.task("crob 0 off direct")
        out.executed(2)
        cursor = master.task("stats")
        master.wait(r"\[STAT\].*index=15 association=0 value=1\b", cursor)
        master.task("events")
        master.wait(r"\[STAT\].*Group122Var[12].*index=15 association=0 value=1\b")
        master.task("ruk change operator 2 0 1")
        master.task("crob 1 on", success=False)
        out.executed(2)
        master.task("ruk change operator 3 1 1")
        master.task("ruk add guest 0 1 1")
        master.send("user 4")
        master.task("crob 1 on")
        out.executed(3)
        master.task("ruk delete guest 1 1 1")
        master.task("crob 1 off", success=False)
        out.executed(3)
        master.send("user 2")
        master.task("ruk verify operator")
        cursor = master.send("reconnect")
        master.wait(r"\[LINK\] OPEN$", cursor)
        master.task("read 30 5 0 0")
        master.task("crob 2 on")
        out.executed(4)
        # Selected authenticated FC6 forms, with independent execution evidence.
        for command, count in (("crob 0 off noack", 5), ("analog 1 0 7 noack", 6),
                               ("analog 2 0 -23 noack", 7), ("analog 3 0 6.75 noack", 8)):
            master.noack(command)
            master.task("read 1 2 0 0") # Receiver barrier; local completion alone proves no execution.
            out.executed(count)
        # Recreate each process using its independently persisted credentials.
        master.close(); master = None
        out.close(); out = None
        master, out = connected(exe, [*options, "--aggressive"])
        master.task("ruk verify operator")
        master.task("read 30 5 0 0")
        master.task("crob 3 on")
        out.executed(1)
        master.wait(r"\[SA-OBJECT\] TX G120V3$")
        cursor = master.send("auth")
        master.wait(r"\[LOCAL-STAT\] index=5 value=[1-9]", cursor)
        master.send("user 99")
        master.task("crob 4 on", success=False)
        out.executed(1)
        master.send("user 2")
        master.noack("crob 3 off noack") # Genuine prior exchange seeded Aggressive history.
        master.task("read 1 2 0 0")
        out.executed(2)
    finally:
        try:
            stop(out, master)
        finally:
            run(exe, "test-cleanup", *args)
    print("PASS " + method + ": session/C-R/RUK/ADD/CHANGE/DELETE/role denial/stats/reconnect/restart/aggressive", flush=True)


def renewal(exe):
    profile = "renewal-" + uuid.uuid4().hex[:12]
    provision = ["--test-only", "--profile", profile, "--auth", "method4"]

    def snapshot(peer, limit):
        deadline = time.monotonic() + 20
        while True:
            cursor = peer.send("auth")
            users = {}
            for user in (1, 2):
                line = peer.wait(r"\[SESSION\] user=" + str(user)
                                 + r" ready=[01] exchanging=[01] remaining=\d+$",
                                 cursor, max(0, deadline - time.monotonic()))
                match = re.search(r"ready=([01]) exchanging=([01]) remaining=(\d+)$", line)
                users[user] = tuple(map(int, match.groups()))
            line = peer.wait(r"\[LOCAL-STAT\] index=13 value=\d+$", cursor,
                             max(0, deadline - time.monotonic()))
            changes = int(re.search(r"value=(\d+)$", line).group(1))
            peer.wait(r"\[LOCAL-STAT\] index=17 value=\d+$", cursor,
                      max(0, deadline - time.monotonic()))
            if all(ready and not exchanging for ready, exchanging, _ in users.values()):
                assert changes >= 2, (profile, changes, users)
                assert all(0 < remaining <= limit for _, _, remaining in users.values()), users
                return {user: value[2] for user, value in users.items()}
            remaining = deadline - time.monotonic()
            assert remaining > 0, ("SA users did not become ready", profile, users, changes)
            with peer.cv:
                peer.cv.wait(min(0.05, remaining))

    try:
        run(exe, "test-provision", *provision)
        # Verify the CLI's existing restrictions, not a restriction on the generic
        # SessionKeys count-only capability. Provision valid credentials so failure
        # cannot be explained by a missing profile or clock.
        invalid = (
            ("--renewal-ms", "0", "Zero port/user/timeout/count is unsupported"),
            ("--renewal-ms", "7200001", "Numeric option out of range"),
            ("--message-count", "0", "Zero port/user/timeout/count is unsupported"),
            ("--message-count", "-1", "Invalid numeric option"),
            ("--message-count", "2147483648", "SA credentials or policy unavailable"),
            ("--message-count", "4294967296", "Numeric option out of range"),
        )
        for role in ("master", "outstation"):
            for option, value, reason in invalid:
                result = run(exe, role, *provision, *loopback_port(), "--trust-system-time",
                             option, value, success=False)
                assert "ERROR: " + reason in result.stdout + result.stderr, (role, option, value, result)

        # Two pairs cover both interval endpoints and default/configured counts.
        # Omit --message-count in the first case to exercise the actual CLI default.
        for interval, explicit_count in ((900000, None), (7200000, 2000)):
            limit = 1000 if explicit_count is None else explicit_count
            options = [*provision, *loopback_port(), "--trust-system-time", "--reply-ms", "5000",
                       "--renewal-ms", str(interval)]
            if explicit_count is not None:
                options += ["--message-count", str(explicit_count)]
            master = out = None
            try:
                master, out = connected(exe, options)
                before = [snapshot(peer, limit) for peer in (master, out)]
                # Startup tasks use Common/user 1. No explicit user-2 command has
                # run yet, so its unused budget identifies the configured limit.
                assert all(value[2] == limit for value in before), (interval, before)
                out.executed(0)
                master.task("read 1 2 0 0")
                after_read = [snapshot(peer, limit) for peer in (master, out)]
                assert all(after[2] < initial[2] for initial, after in zip(before, after_read)), (before, after_read)
                out.executed(0)
                master.task("crob 0 on")
                out.executed(1)
                after_control = [snapshot(peer, limit) for peer in (master, out)]
                assert all(after[2] < initial[2] for initial, after in zip(after_read, after_control)), (after_read, after_control)
                # No equality between peer counters or one-ASDU-per-command assumption.
            finally:
                stop(out, master)
            print(f"PASS renewal configuration: interval={interval} count={limit} "
                  f"budgets={before}->{after_read}->{after_control}", flush=True)
    finally:
        run(exe, "test-cleanup", *provision)


def reply_timeouts(exe):
    profile = "reply-" + uuid.uuid4().hex[:12]
    provision = ["--test-only", "--profile", profile, "--auth", "method4"]

    def status(peer):
        cursor = peer.send("auth")
        users = {}
        for user in (1, 2):
            line = peer.wait(r"\[SESSION\] user=" + str(user)
                             + r" ready=[01] exchanging=[01] remaining=\d+$", cursor, timeout=5)
            users[user] = tuple(map(int, re.search(
                r"ready=([01]) exchanging=([01]) remaining=(\d+)$", line).groups()))
        line = peer.wait(r"\[LOCAL-STAT\] index=13 value=\d+$", cursor, timeout=5)
        changes = int(re.search(r"value=(\d+)$", line).group(1))
        peer.wait(r"\[LOCAL-STAT\] index=17 value=\d+$", cursor, timeout=5)
        return users, changes

    def unready(peer):
        users, changes = status(peer)
        assert changes == 0, ("Zero-duration exchange installed keys", users, changes)
        assert all(not ready and remaining == 0 for ready, _, remaining in users.values()), users

    try:
        run(exe, "test-provision", *provision)
        invalid = (
            ("--reply-ms", "-1", "Invalid numeric option"),
            ("--reply-ms", "1", "SA credentials or policy unavailable"),
            ("--reply-ms", "101", "SA credentials or policy unavailable"),
            ("--reply-ms", "120001", "Numeric option out of range"),
            ("--reply-ms", "4294967296", "Numeric option out of range"),
            ("--response-ms", "0", "Zero port/user/timeout/count is unsupported"),
        )
        for role in ("master", "outstation"):
            for option, value, reason in invalid:
                extra = ["--reply-ms", "0"] if option == "--response-ms" else []
                result = run(exe, role, *provision, *loopback_port(), "--trust-system-time",
                             *extra, option, value, success=False)
                assert "ERROR: " + reason in result.stdout + result.stderr, (role, option, value, result)
            # Acceptance of the nonzero endpoints is independent of whether a
            # 100 ms timer can complete an exchange under a particular host load.
            for value in (100, 120000):
                peer = Peer(exe, role, [*provision, *loopback_port(), "--trust-system-time",
                                       "--reply-ms", str(value)])
                try:
                    unready(peer)  # No peer is connected; valid configuration, no fabricated keys.
                finally:
                    stop(peer)

        # None omits the option. Verify default/default really authenticates;
        # then isolate zero in each role, and finally configure both roles zero.
        for master_ms, out_ms in ((None, None), (0, None), (None, 0), (0, 0)):
            options = [*provision, *loopback_port(), "--trust-system-time", "--response-ms", "1000"]
            master_options = [] if master_ms is None else ["--reply-ms", str(master_ms)]
            out_options = [] if out_ms is None else ["--reply-ms", str(out_ms)]
            master = out = None
            try:
                master, out = connected(exe, options, master_options, out_options)
                out.executed(0)
                if master_ms is None and out_ms is None:
                    deadline = time.monotonic() + 20
                    while True:
                        snapshots = [status(peer) for peer in (master, out)]
                        if all(changes >= 2 and all(ready and not exchanging and remaining > 0
                               for ready, exchanging, remaining in users.values())
                               for users, changes in snapshots):
                            break
                        remaining = deadline - time.monotonic()
                        assert remaining > 0, ("Default Reply Timer did not authenticate", snapshots)
                        with master.cv:
                            master.cv.wait(min(0.05, remaining))
                    master.task("crob 0 on")
                    out.executed(1)
                else:
                    # Configuration acceptance must not be confused with ready
                    # keys: zero expires before a fresh exchange can complete.
                    unready(master)
                    unready(out)
                    master.task("crob 0 on", success=False, timeout=25)
                    out.executed(0)
                    unready(master)
                    unready(out)
            finally:
                stop(out, master)
            print(f"PASS Reply Timer configuration: master={master_ms} outstation={out_ms}", flush=True)
    finally:
        run(exe, "test-cleanup", *provision)


def invalid_credentials(exe):
    profiles = ["bad-" + uuid.uuid4().hex[:10] for _ in range(2)]
    for profile in profiles:
        run(exe, "test-provision", "--test-only", "--profile", profile, "--auth", "method4")
    options = ["--auth", "method4", "--test-only", *loopback_port(), "--trust-system-time",
               "--response-ms", "1000", "--reply-ms", "1000"]
    out = Peer(exe, "outstation", [*options, "--profile", profiles[0], "--deny-controls"])
    master = Peer(exe, "master", [*options, "--profile", profiles[1]])
    try:
        master.wait(r"\[LINK\] OPEN$")
        master.task("crob 0 on", success=False, timeout=30)
        out.executed(0)
        master.close()
        master = Peer(exe, "master", [*options, "--profile", profiles[0]])
        master.wait(r"\[LINK\] OPEN$")
        master.task("read 1 2 0 0")
        master.task("crob 0 on", success=False)
        out.wait(r"\[DENIED\] association=7 user=2$")
        out.executed(0)
        blocked = run(exe, "test-cleanup", "--test-only", "--profile", profiles[0].upper(), success=False)
        assert "namespace already in use" in blocked.stderr
        master.close()
        master = None
        missing_clock = run(exe, "master", "--auth", "method4", "--profile", profiles[0], "--test-only", success=False)
        assert "requires an explicitly trusted clock" in missing_clock.stderr
        wrong_association = run(exe, "master", *options, "--profile", profiles[0], "--association", "8", success=False)
        assert "Missing explicitly provisioned TEST profile" in wrong_association.stderr
        missing_keys = run(exe, "master", *options, "--profile", profiles[0], "--auth", "method68", success=False)
        assert "Method68 requires Method68 TEST provisioning" in missing_keys.stderr
    finally:
        try:
            stop(out, master)
        finally:
            for profile in profiles:
                run(exe, "test-cleanup", "--test-only", "--profile", profile)
    print("PASS wrong keys/association, policy denial, missing clock/Method68 material and guarded cleanup: no command execution", flush=True)


def tls(exe, root):
    owned = root.resolve() / ("pc-tls-" + uuid.uuid4().hex[:10])
    owned.mkdir(parents=True)
    try:
        tls_cases(exe, owned)
    finally:
        (owned / "bundle.pem").unlink(missing_ok=True)
        for name in ("normal", "untrusted", "expired", "anchor2", "anchor3", "anchor4"):
            directory = owned / name
            if directory.is_dir():
                for filename in ("ca.pem", "server.pem", "server-key.pem", "client.pem", "client-key.pem"):
                    (directory / filename).unlink(missing_ok=True)
                directory.rmdir()
        owned.rmdir()


def tls_cases(exe, root):
    material, wrong, expired = (root / name for name in ("normal", "untrusted", "expired"))
    for directory in (material, wrong, expired):
        run(exe, "test-tls", "--test-only", "--directory", str(directory),
            *(["--expired-test-certificate"] if directory == expired else []))

    def peer_options(role, directory=material, trust=material):
        return ["--ca", str(trust / "ca.pem"), "--cert", str(directory / ("client.pem" if role == "master" else "server.pem")),
                "--key", str(directory / ("client-key.pem" if role == "master" else "server-key.pem")),
                "--peer-name", "outstation.test" if role == "master" else "master.test"]

    for version in ("1.2", "1.3"):
        common = ["--auth", "compat", "--tls", "--tls-version", version]
        common += ["--ciphers", "ECDHE-RSA-AES128-GCM-SHA256"] if version == "1.2" else ["--suites", "TLS_AES_128_GCM_SHA256"]
        client = peer_options("master")
        if version == "1.2":
            client[-1] = "127.0.0.1"  # Exercise IP SAN as well as DNS SAN.
        master, out = connected(exe, common, client, peer_options("outstation"))
        try:
            master.task("read 1 2 0 0")
            master.task("crob 0 on")
            out.executed(1)
            cursor = master.send("reconnect")
            master.wait(r"\[LINK\] OPEN$", cursor)
            master.task("read 30 5 0 0")
        finally:
            stop(out, master)
    # Exercise each independent trust anchor in both TLS roles with the same
    # CA bundle. Different client/server issuers rule out a shared-anchor shortcut.
    anchors = [material, *(root / name for name in ("anchor2", "anchor3", "anchor4"))]
    for directory in anchors[1:]:
        run(exe, "test-tls", "--test-only", "--directory", str(directory))
    bundle = root / "bundle.pem"
    bundle.write_bytes(b"\n".join((directory / "ca.pem").read_bytes() for directory in anchors))
    for index, server in enumerate(anchors):
        client_options = peer_options("master", anchors[(index + 1) % len(anchors)])
        server_options = peer_options("outstation", server)
        client_options[1] = server_options[1] = str(bundle)
        master, out = connected(exe, ["--auth", "compat", "--tls"], client_options, server_options)
        try:
            master.task("read 1 2 0 0")
            master.task("crob 0 on")
            out.executed(1)
        finally:
            stop(out, master)
    print("PASS four independent CA anchors in both mutual TLS roles", flush=True)
    profile = "tls-sa-" + uuid.uuid4().hex[:10]
    auth = ["--test-only", "--profile", profile, "--auth", "method4"]
    run(exe, "test-provision", *auth)
    master = out = None
    try:
        master, out = connected(exe, [*auth, "--trust-system-time", "--tls", "--tls-version", "1.3"],
                                peer_options("master"), peer_options("outstation"))
        master.task("ruk verify operator")
        master.task("crob 0 on")
        out.executed(1)
        cursor = master.send("auth")
        master.wait(r"\[SESSION\] user=2 ready=1", cursor)
    finally:
        try:
            stop(out, master)
        finally:
            run(exe, "test-cleanup", *auth)
    # The same stack must reject every invalid peer before command dispatch.
    for fault in ("wrong-name", "untrusted-server", "untrusted-client", "expired-server"):
        common = ["--auth", "compat", "--tls", *loopback_port(), "--response-ms", "1000"]
        trust = expired if fault == "expired-server" else material
        mo = peer_options("master", wrong if fault == "untrusted-client" else material, trust)
        oo = peer_options("outstation", wrong if fault == "untrusted-server" else expired if fault == "expired-server" else material, trust)
        if fault == "wrong-name": mo[-1] = "untrusted.test"
        out = Peer(exe, "outstation", [*common, *oo])
        master = Peer(exe, "master", [*common, *mo])
        try:
            master.task("crob 0 on", success=False, timeout=30)
            out.executed(0)
            if fault == "expired-server":
                master.wait(r"certificate has expired")
            elif fault == "wrong-name":
                master.wait(r"hostname mismatch")
            elif fault == "untrusted-client":
                out.wait(r"TLS handshake failed:.*certificate")
            else:
                master.wait(r"unable to get local issuer certificate")
        finally:
            stop(out, master)
    for option, value in (("--ciphers", "INVALID-CIPHER"), ("--suites", "INVALID-CIPHER")):
        run(exe, "master", "--tls", *peer_options("master"), option, value, success=False)
    run(exe, "master", "--tls", "--ca", str(material / "ca.pem"), success=False)
    print("PASS TLS1.2/1.3 mTLS/identity/validity/reconnect and invalid certificate/cipher/key-material rejection", flush=True)


def asio_fixtures(exe, asio, root):
    # Keep the original Catch TLS tests and their filenames. Generate fresh
    # credentials in this run's own working directory rather than commit keys.
    owned = root.resolve() / ("pc-asio-" + uuid.uuid4().hex[:10])
    certificates = owned / "certs"
    certificates.mkdir(parents=True)
    try:
        for case in ("self_signed", "ca_chain"):
            directory = certificates / case
            run(exe, "test-tls", "--test-only", "--directory", str(directory),
                *(["--self-signed-test-certificate"] if case == "self_signed" else []))
            for source, target in (("client.pem", "entity1_cert.pem"), ("client-key.pem", "entity1_key.pem"),
                                   ("server.pem", "entity2_cert.pem"), ("server-key.pem", "entity2_key.pem"), ("ca.pem", "ca_cert.pem")):
                (directory / source).rename(directory / target)
        result = subprocess.run([str(asio), "-r", "compact"], cwd=owned, timeout=60)
        assert result.returncode == 0, result.returncode
    finally:
        for case in ("self_signed", "ca_chain"):
            directory = certificates / case
            if directory.is_dir():
                for filename in ("ca.pem", "server.pem", "server-key.pem", "client.pem", "client-key.pem", "ca_cert.pem",
                                 "entity1_cert.pem", "entity1_key.pem", "entity2_cert.pem", "entity2_key.pem"):
                    (directory / filename).unlink(missing_ok=True)
                directory.rmdir()
        certificates.rmdir()
        owned.rmdir()


def acceptance_counter_profile(exe):
    """Two fresh native TCP pairs, with and without the RTU profile."""
    def observed(name, actual, expected):
        print("DNP3-ACCEPTANCE " + json.dumps({"check": name, "value": actual}), flush=True)
        assert actual == expected, (name, expected, actual)

    def read_counter(peer):
        cursor = peer.send("read 20 1 5 5")
        peer.wait(r"\[TASK\] read (?!START)[A-Z_]+", cursor)
        with peer.cv:
            return [match for line in peer.lines[cursor:]
                    if (match := re.search(r"Group20Var1 STATIC Counter\[5\]=([0-9]+)\b", line))]

    master, out = connected(exe, ["--auth", "compat"])
    try:
        master.task("scan integrity")
        cursor = out.send("set counter 5 123 force")
        out.wait(r"\[UPDATE\].*counter 5 123", cursor)
        values = read_counter(master)
        observed("compat_static_count", len(values), 1)
        observed("compat_counter_value", int(values[0][1]), 123)
        cursor = master.task("scan class3")
        line = master.wait(r"Group22Var[0-9]+ EVENT Counter\[5\]=([0-9]+)\b", cursor)
        observed("compat_event_value", int(re.search(r"Counter\[5\]=([0-9]+)", line)[1]), 123)
    finally:
        stop(out, master)

    master, out = connected(exe, ["--auth", "compat", "--rtu-io-profile"])
    try:
        master.task("scan integrity")
        cursor = out.send("set counter 5 123 force")
        out.wait(r"\[ERROR\] Invalid point type/value", cursor)
        with out.cv:
            rejected = sum("[ERROR] Invalid point type/value" in line for line in out.lines[cursor:])
        observed("rtu_update_rejected", rejected, 1)
        observed("rtu_static_count", len(read_counter(master)), 0)
        cursor = master.task("scan class3")
        with master.cv:
            count = sum("EVENT Counter[" in line for line in master.lines[cursor:])
        observed("rtu_event_count", count, 0)
    finally:
        stop(out, master)


def profile_analog_event(exe):
    """Check selected RTU G32V5 and unchanged generic G32V7 over real TCP."""
    for rtu, variation in ((False, 7), (True, 5)):
        options = ["--auth", "compat"] + (["--rtu-io-profile"] if rtu else [])
        master, out = connected(exe, options)
        try:
            master.task("scan integrity")
            cursor = out.send("set analog 3 12.5 force")
            out.wait(r"\[UPDATE\].*analog 3 12\.5", cursor)
            cursor = master.task("scan class2")
            line = master.wait(rf"Group32Var{variation} EVENT Analog\[3\]=12\.5\b", cursor)
            if rtu:
                assert "time=" not in line, line
                master.task("analog 3 2 4.25 direct")
                out.executed(1)
                cursor = master.task("analog 4 2 4.25 sbo", success=False)
                master.wait(r"status=NOT_SUPPORTED", cursor)
                out.executed(1)
                cursor = master.task("analog 4 2 4.25 direct", success=False)
                master.wait(r"status=NOT_SUPPORTED", cursor)
                out.executed(1)
                master.noack("analog 4 2 4.25 noack")
                out.executed(1)
            else:
                assert "time=" in line, line
        finally:
            stop(out, master)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--asio", type=Path)
    parser.add_argument("--only", choices=("compat", "method4", "method68", "negative", "renewal", "reply-timeout", "tls", "asio", "f01-fragments", "f01-link", "f01-required-fragments", "profile-analog", "all"), default="all")
    parser.add_argument("--scenario", choices=("AT-CFG-13-COMPAT",))
    parser.add_argument("--vector", choices=("V1",))
    parser.add_argument("--seed", type=int, default=1741815)
    args = parser.parse_args()
    assert args.exe.is_file(), args.exe
    if args.scenario:
        if args.vector != "V1" or args.only != "all":
            parser.error("an acceptance scenario requires --vector V1 and no smoke-suite filter")
        acceptance_counter_profile(args.exe)
        return
    if args.vector:
        parser.error("--vector requires an acceptance scenario")
    if args.only == "asio":
        assert args.asio and args.asio.is_file(), args.asio
        asio_fixtures(args.exe, args.asio, args.work_dir)
        return
    if args.only in ("f01-fragments", "all"): f01_solicited_fragments(args.exe)
    if args.only in ("f01-link", "all"): f01_confirmed_link(args.exe)
    if args.only in ("f01-required-fragments", "all"): f01_required_fragments(args.exe)
    if args.only in ("profile-analog", "all"): profile_analog_event(args.exe)
    if args.only in ("compat", "all"): compatibility(args.exe)
    if args.only in ("method4", "all"): secure(args.exe, "method4")
    if args.only in ("method68", "all"): secure(args.exe, "method68")
    if args.only in ("negative", "all"): invalid_credentials(args.exe)
    if args.only in ("renewal", "all"): renewal(args.exe)
    if args.only in ("reply-timeout", "all"): reply_timeouts(args.exe)
    if args.only in ("tls", "all"): tls(args.exe, args.work_dir)
    print("CLI PROCESS ACCEPTANCE PASS; native callbacks/readbacks, clean peer shutdowns and expected failure exits checked.", flush=True)


if __name__ == "__main__":
    main()
