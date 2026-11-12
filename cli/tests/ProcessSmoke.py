"""Bounded CLI process checks with native outcomes and a small F01 wire oracle.

All children are hidden, owned, bounded, and stopped before credential cleanup.
"""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import select
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
        assert not any("[RESULT]" in line or "status=SUCCESS" in line
                       for line in self.lines[cursor:]), self.lines[cursor:]
        return completion

    def executed(self, expected):
        cursor = self.send("status")
        return self.wait(r"channel=.* executed=" + str(expected) + r"$", cursor)

    def close(self):
        if self.process.poll() is None:
            try:
                self.send("quit")
            except OSError:
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


def f01_solicited_fragments(exe, observe=False):
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
            remaining = f01_double_events(master.lines[cursor:])
            assert not remaining, master.lines[cursor:]
        if observe:
            for name, actual_value in (("delivered_after_reconnect", len(actual)), ("redelivered_after_confirm", len(remaining))):
                print("DNP3-ACCEPTANCE " + json.dumps({"check": name, "value": actual_value}), flush=True)
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
        cursor = master.send("attr 209")
        master.wait(r"IIN=.* REQUEST_ERROR", cursor)
        master.wait(r"\[TASK\] attr (?!START)[A-Z_]+", cursor)
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


def acceptance_fragment_options(exe, role):
    accepted = rejected = 0
    for tested, other in (("rx", "tx"), ("tx", "rx")):
        option = f"--{tested}-fragment-bytes"
        fixed = f"--{other}-fragment-bytes"
        for value in ("250", "2048", "2049", "65535"):
            peer = Peer(exe, role, ["--auth", "compat", *loopback_port(), option, value, fixed, "300"])
            try:
                peer.wait(r"\[HELP\]")
                accepted += 1
            finally:
                stop(peer)
        for value in ("249", "65536", "", "-1", "invalid"):
            result = run(exe, role, "--auth", "compat", option, value, fixed, "300", success=False)
            assert "ERROR:" in result.stderr and "[HELP]" not in result.stdout, result
            rejected += 1
    for check, value in (("valid_configurations", accepted), ("invalid_configurations", rejected)):
        print("DNP3-ACCEPTANCE " + json.dumps({"check": check, "value": value}), flush=True)


SA_CONTROL_SCENARIO = re.compile(r"AT-CFG-08-(M4|M68)-(CHALLENGE|AGGRESSIVE)-(G12V1|G41V[123])-(SBO|DO|NR)")


def acceptance_sa_control(exe, match, narrow):
    method, mode, object_type, operation = match.groups()
    aggressive = mode == "AGGRESSIVE"
    profile = "cfg08-" + uuid.uuid4().hex[:12]
    provision = ["--test-only", "--profile", profile, "--auth", {"M4": "method4", "M68": "method68"}[method]]
    options = [*provision, "--trust-system-time", "--rtu-io-profile", "--link-confirm", "never",
               "--reply-ms", "5000", "--response-ms", "15000"]
    if aggressive:
        options.append("--aggressive")
    actions = {"SBO": ("sbo", (3, 4)), "DO": ("direct", (5,)), "NR": ("noack", (6,))}
    action, functions = actions[operation]
    if object_type == "G12V1":
        group, variation, index = 12, 1, 3
        command = f"crob 3 on {action}"
        readback = "read 10 2 3 3"
        old, new = r"BinaryOutput\[3\]=OFF\b", r"BinaryOutput\[3\]=ON\b"
        value = struct.pack("<BBII", 0x41, 1, 100, 0)
    else:
        group, variation = 41, int(object_type[-1])
        index, number, fmt = {1: (2, 1234, "i"), 2: (3, -123, "h"), 3: (4, 4.25, "f")}[variation]
        command = f"analog {variation} {index} {number} {action}"
        readback = f"read 40 {variation} {index} {index}"
        old = rf"AnalogOutput\[{index}\]=0\b"
        new = rf"AnalogOutput\[{index}\]={re.escape(str(number))}\b"
        value = struct.pack("<" + fmt, number)
    prefix = bytes([group, variation, 0x17, 1, index]) if narrow else bytes([group, variation, 0x28, 1, 0, index, 0])
    body = prefix + value + b"\0"

    master = out = None
    captured, errors = [], []
    stopped, held, release = threading.Event(), threading.Event(), threading.Event()
    run(exe, "test-provision", *provision)
    try:
        with ExitStack() as sockets:
            listener = sockets.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)
            out_port = loopback_port()
            out = Peer(exe, "outstation", [*options, *out_port, "--rtu-crob-latch", "3", "--rtu-crob-latch", "5"])
            out.wait(r"\[HELP\]")
            out_link = sockets.enter_context(socket.create_connection(("127.0.0.1", int(out_port[1])), timeout=5))
            master_options = [*options, "--port", str(listener.getsockname()[1])]
            if narrow:
                master_options.append("--control-q17")
            master = Peer(exe, "master", master_options)
            master_link, _ = listener.accept()
            sockets.enter_context(master_link)

            def relay():
                try:
                    while not stopped.is_set():
                        ready, _, _ = select.select((master_link, out_link), (), (), 0.25)
                        for source in ready:
                            wire, apdu = read_control_frame(source)
                            if stopped.is_set():
                                return
                            from_master = source is master_link
                            if apdu:
                                captured.append((from_master, apdu))
                            if from_master and apdu and apdu[1] == 4 and not held.is_set():
                                held.set()
                                if not release.wait(10):
                                    raise TimeoutError("OPERATE gate expired")
                                if stopped.is_set():
                                    return
                            (out_link if from_master else master_link).sendall(wire)
                except Exception as error:
                    if not stopped.is_set():
                        errors.append(error)
                finally:
                    held.set()

            worker = threading.Thread(target=relay, daemon=True)
            worker.start()
            try:
                master.wait(r"\[LINK\] OPEN$")
                out.wait(r"\[LINK\] OPEN$")
                for point in (3, 5):
                    cursor = out.send(f"crob-interlock {point} allow")
                    out.wait(rf"\[INTERLOCK\] CROB\[{point}\] allow$", cursor)
                executions = 0
                if aggressive:
                    # Prime a different point using the genuine Challenge/Reply path.
                    master.task("crob 5 on direct")
                    executions = 1
                out.executed(executions)
                cursor = master.task(readback)
                master.wait(old, cursor)
                start = len(captured)
                if operation == "SBO":
                    cursor = master.send(command)
                    assert held.wait(15) and not errors, errors
                    assert any(sent and apdu[1] == 4 for sent, apdu in captured[start:])
                    out.executed(executions)
                    release.set()
                    master.wait(r"state=SUCCESS status=SUCCESS", cursor)
                elif operation == "NR":
                    master.noack(command)
                else:
                    master.task(command)

                # The readback is a remote barrier for FC6 and independently verifies the output.
                cursor = master.task(readback)
                observation = master.wait(new, cursor)
                state = out.executed(executions + 1)
                actual_actuations = int(state.rsplit("=", 1)[1]) - executions
                exchanges = captured[start:]
                requests = [apdu for sent, apdu in exchanges if sent and apdu[1] in (3, 4, 5, 6)]
                assert tuple(request[1] for request in requests) == functions, [request[:2].hex() for request in requests]
                command_responses = 0
                for request in requests:
                    seq = request[0] & 15
                    if aggressive:
                        assert aggressive_control_objects(request, 2, 2) == body
                    else:
                        assert request[2:] == body
                        assert any(not sent and apdu[1] == 0x83 and apdu[0] & 15 == seq
                                   and apdu[4:6] == bytes.fromhex("78 01") for sent, apdu in exchanges)
                        assert any(sent and apdu[1] == 0x20 and apdu[0] & 15 == seq
                                   and apdu[2:4] == bytes.fromhex("78 02") for sent, apdu in exchanges)
                    echoes = [apdu for sent, apdu in exchanges if not sent and apdu[1] == 0x81 and apdu[0] & 15 == seq]
                    if request[1] == 6:
                        assert not echoes, [apdu[:4].hex() for apdu in echoes]
                    else:
                        assert len(echoes) == 1
                        echo = echoes[0]
                        objects = aggressive_control_objects(echo, 4, 1) if echo[4:6] == b"\x78\x03" else echo[4:]
                        assert objects == body, objects.hex(" ")
                        command_responses += 1
                assert not errors, errors
                for name, actual in (("authenticated_requests", len(requests)), ("command_responses", command_responses),
                                     ("outstation_actuations", actual_actuations), ("receiver_readback", int(bool(observation)))):
                    print("DNP3-ACCEPTANCE " + json.dumps({"check": name, "value": actual}), flush=True)
            finally:
                stopped.set()
                release.set()
                worker.join(6)
                assert not worker.is_alive()
    finally:
        try:
            stop(out, master)
        finally:
            run(exe, "test-cleanup", *provision)


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


def acceptance_rtu_counters(exe, scenario):
    options = ["--auth", "compat", "--rtu-io-profile", "--link-confirm", "never"]
    counter_value = re.compile(r"(?:Counter|FrozenCounter)\[\d+\]=")

    def exchange(peer, sequence, function_and_objects):
        control = 0xC0 | sequence
        peer.sendall(f01_link_frame(bytes([control]) + bytes.fromhex(function_and_objects), sequence))
        _, response = f01_receive_apdu(peer)
        assert response[:2] == bytes([control, 0x81]), response.hex(" ")
        return response[4:]

    def scan_without_counters(master, command):
        cursor = master.task(command)
        with master.cv:
            lines = master.lines[cursor:]
            values = [line for line in lines if counter_value.search(line)]
        assert not values, values
        return lines

    if scenario == "EVENT":
        master, out = connected(exe, [*options, "--trace"], out_options=["--unsolicited"])
        try:
            master.task("unsol on")
            with master.cv:
                cursor = len(master.lines)
            with out.cv:
                confirmation = len(out.lines)
            updated = out.send("set binary 0 on force")
            out.wait(r"\[UPDATE\].*binary 0 on force", updated)
            event = master.wait(r"Group2Var2 EVENT Binary\[0\]=ON\b", cursor)
            out.wait(r"FUNC: CONFIRM", confirmation)
            scans = 0
            for command in ("scan class1", "scan class2", "scan class3", "read 22 0", "read 23 0"):
                lines = scan_without_counters(master, command)
                assert not any(" EVENT Binary[0]=" in line for line in lines), lines
                scans += 1
            observations = {"ordinary_unsolicited": int(bool(event)), "empty_counter_scans": scans}
        finally:
            stop(out, master)
    elif scenario == "STATIC":
        master, out = connected(exe, options)
        try:
            changed = out.send("set binary 0 on suppress")
            out.wait(r"\[UPDATE\].*binary 0 on suppress", changed)
            lines = scan_without_counters(master, "scan integrity")
            assert any(re.search(r"STATIC Binary\[0\]=ON\b", line) for line in lines), lines
            ordinary = 1
        finally:
            stop(out, master)

        port = loopback_port()
        out = Peer(exe, "outstation", [*options, *port])
        try:
            out.wait(r"\[HELP\]")
            changed = out.send("set binary 0 on suppress")
            out.wait(r"\[UPDATE\].*binary 0 on suppress", changed)
            direct = 0
            with socket.create_connection(("127.0.0.1", int(port[1])), timeout=5) as raw:
                out.wait(r"\[LINK\] OPEN$")
                for sequence, selector in enumerate(("14 00 06", "14 00 00 00 09", "14 00 01 00 00 09 00",
                                                    "15 00 06", "15 00 00 00 09", "15 00 01 00 00 09 00")):
                    assert exchange(raw, sequence, "01 " + selector) == b""
                    direct += 1
                mixed = exchange(raw, 6, "01 14 00 06 01 02 00 00 00 15 00 06")
                assert mixed == bytes.fromhex("01 02 00 00 00 81"), mixed.hex(" ")
            observations = {"empty_direct_selectors": direct, "class0_binary_marker": ordinary,
                            "mixed_binary_marker": int(bool(mixed))}
        finally:
            stop(out)
    else:
        rejected = freeze_checks = recovered = 0
        for process in range(2):
            port = loopback_port()
            out = Peer(exe, "outstation", [*options, *port])
            try:
                out.wait(r"\[HELP\]")
                updated = out.send("set counter 5 123 force")
                out.wait(r"\[ERROR\] Invalid point type/value", updated)
                rejected += 1
                for connection in range(2 if process == 0 else 1):
                    with socket.create_connection(("127.0.0.1", int(port[1])), timeout=5) as raw:
                        out.wait(r"\[LINK\] OPEN$")
                        if process == 0 and connection == 0:
                            for sequence, function in enumerate((7, 9)):
                                assert exchange(raw, sequence, f"{function:02X} 14 00 06") == b""
                                freeze_checks += 1
                            for sequence, function in enumerate((8, 10), start=2):
                                raw.sendall(f01_link_frame(bytes([0xC0 | sequence, function, 20, 0, 6]), sequence))
                                freeze_checks += 1
                        # The solicited read also rejects any spurious ordinary response to FC8/10.
                        assert exchange(raw, 4, "01 14 00 06 15 00 06 16 00 06 17 00 06") == b""
                        recovered += 1
            finally:
                stop(out)
        observations = {"rejected_updates": rejected, "freeze_checks": freeze_checks,
                        "empty_reads_after_reconnect_or_restart": recovered}

    for name, actual in observations.items():
        print("DNP3-ACCEPTANCE " + json.dumps({"check": name, "value": actual}), flush=True)


def profile_analog_event(exe):
    """Selected RTU analog event and output control checks over real TCP."""
    configurations = (
        (False, 7, False),
        (True, 5, False),
        (True, 5, True),
    )

    for rtu, event_variation, use_q17 in configurations:
        common = ["--auth", "compat"]
        if rtu:
            common.append("--rtu-io-profile")

        master, out = connected(
            exe,
            common,
            master_options=["--control-q17"] if use_q17 else [],
            out_options=["--event-q17"] if use_q17 else [],
        )

        try:
            master.task("scan integrity")

            cursor = out.send("set analog 3 12.5 force")
            out.wait(r"\[UPDATE\].*analog 3 12\.5", cursor)

            cursor = master.task("scan class2")
            line = master.wait(
                rf"Group32Var{event_variation} EVENT Analog\[3\]=12\.5\b",
                cursor,
            )

            assert "flags=0x01" in line, line

            if not rtu:
                assert "time=" in line, line
                continue

            assert "time=" not in line, line

            cursor = master.task("scan class2")
            with master.cv:
                assert not any(
                    "Group32Var5 EVENT Analog[3]" in item
                    for item in master.lines[cursor:]
                ), master.lines[cursor:]

            executions = 0

            # G41V1, G41V2 and G41V3: FC3/4, FC5 and FC6.
            for variation, index, value in (
                (1, 1, "42"),
                (2, 2, "-12"),
                (3, 3, "4.25"),
            ):
                for mode in ("sbo", "direct", "noack"):
                    command = f"analog {variation} {index} {value} {mode}"

                    if mode == "noack":
                        master.noack(command)
                    else:
                        master.task(command)

                    executions += 1
                    out.executed(executions)

                cursor = master.task(
                    f"read 40 {variation} {index} {index}"
                )
                master.wait(
                    rf"AnalogOutput\[{index}\]={re.escape(value)}\b",
                    cursor,
                )

            # G41V4 is not selected for the RTU profile.
            for mode in ("sbo", "direct"):
                cursor = master.task(
                    f"analog 4 4 4.25 {mode}",
                    success=False,
                )
                master.wait(r"status=NOT_SUPPORTED", cursor)
                out.executed(executions)

            master.noack("analog 4 4 4.25 noack")
            out.executed(executions)

            # Invalid point indices must not actuate outputs.
            for variation in (1, 2, 3):
                cursor = master.task(
                    f"analog {variation} 10 1 direct",
                    success=False,
                )
                master.wait(r"status=OUT_OF_RANGE", cursor)
                out.executed(executions)

            # Selected signed integer encoding limits.
            for variation, index, values in (
                (1, 1, ("-2147483648", "2147483647")),
                (2, 2, ("-32768", "32767")),
            ):
                for value in values:
                    master.task(
                        f"analog {variation} {index} {value} direct"
                    )
                    executions += 1
                    out.executed(executions)

            # Reject invalid numeric input before transmission.
            invalid_commands = (
                ("analog 1 1 2147483648 direct",
                 "Integer command out of range"),
                ("analog 1 1 -2147483649 direct",
                 "Integer command out of range"),
                ("analog 2 2 32768 direct",
                 "Integer command out of range"),
                ("analog 2 2 -32769 direct",
                 "Integer command out of range"),
                ("analog 3 3 nan direct",
                 "Invalid analog command"),
                ("analog 3 3 inf direct",
                 "Invalid analog command"),
                ("analog 3 3 1e39 direct",
                 "Float overflow"),
            )

            for command, error in invalid_commands:
                cursor = master.send(command)
                master.wait(
                    r"\[ERROR\] " + re.escape(error),
                    cursor,
                )
                out.executed(executions)
        finally:
            stop(out, master)

    print(
        "PASS RTU G32/G41 TCP smoke checks in both qualifier configurations",
        flush=True,
    )


def profile_binary_wire(exe):
    """Exercise the selected binary READ/ASSIGN_CLASS forms over FT3/TCP."""
    options = ["--auth", "compat", "--rtu-io-profile", *loopback_port()]
    out = Peer(exe, "outstation", options)
    try:
        out.wait(r"\[HELP\]")
        for index, state in enumerate(("on", "off", "on", "off", "on", "on", "off", "on", "on", "off")):
            cursor = out.send(f"set binary {index} {state} suppress")
            out.wait(rf"\[UPDATE\].*binary {index} {state} suppress", cursor)
        for index, state in enumerate(("intermediate", "off", "on", "indeterminate")):
            cursor = out.send(f"set double {index} {state} suppress")
            out.wait(rf"\[UPDATE\].*double {index} {state} suppress", cursor)

        with socket.create_connection(("127.0.0.1", int(options[-1])), timeout=5) as raw:
            out.wait(r"\[LINK\] OPEN$")
            exchanges = (
                ("01 01 00 00 00 08", "00 01 02 00 00 08 81 01 81 01 81 81 01 81 81"),
                ("01 01 00 01 00 00 08 00", "00 01 02 00 00 08 81 01 81 01 81 81 01 81 81"),
                ("01 01 00 06", "00 01 02 00 00 09 81 01 81 01 81 81 01 81 81 01"),
                ("01 01 01 00 00 08", "00 01 01 00 00 08 B5 01"),
                ("01 01 01 01 00 00 08 00", "00 01 01 00 00 08 B5 01"),
                ("01 01 01 06", "00 01 01 00 00 09 B5 01"),
                ("01 01 02 00 00 01", "00 01 02 00 00 01 81 01"),
                ("01 01 01 00 08 00", "04"),
                ("16 3C 03 06 01 00 06", "00"),
                ("16 3C 02 06 01 00 01 01 00 02 00", "00"),
                ("01 00 D2 00 00 00", "00 00 D2 00 00 00 02 01 00"),
                ("01 00 D1 00 00 00", "02"),
                ("01 03 00 00 00 03", "00 03 02 00 00 03 01 41 81 C1"),
                ("01 03 02 01 00 00 03 00", "00 03 02 00 00 03 01 41 81 C1"),
                ("16 3C 03 06 03 00 00 01 02", "00"),
            )
            for seq, (request, expected) in enumerate(exchanges):
                control = 0xC0 | seq
                raw.sendall(f01_link_frame(bytes([control]) + bytes.fromhex(request), seq))
                _, response = f01_receive_apdu(raw)
                # The diagnostic clock is unsynchronized and restart has not been cleared.
                assert response == bytes([control, 0x81, 0x90]) + bytes.fromhex(expected), (
                    request, expected, response.hex(" "),
                )
            out.wait(r"\[CLASS\].*class-mask=4 range=0\.\.9$")
            out.wait(r"\[CLASS\].*class-mask=2 range=1\.\.2$")
    finally:
        stop(out)
    print("PASS binary profile: real TCP READ, ASSIGN_CLASS and G0 attributes", flush=True)
    profile_binary_event_wire(exe)
    profile_iin_write_wire(exe)


def profile_iin_write_wire(exe):
    """Check the RTU's G80V1 write policy over FT3/TCP."""
    for rtu_profile in (True, False):
        options = ["--auth", "compat", *loopback_port()]
        port = int(options[-1])
        if rtu_profile:
            options.append("--rtu-io-profile")
        out = Peer(exe, "outstation", options)
        try:
            out.wait(r"\[HELP\]")
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                exchanges = (
                    ("02 50 01 00 04 04 00", "90 01" if rtu_profile else "80 00"),
                    ("02 50 01 01 07 00 07 00 00", "90 04" if rtu_profile else "80 04"),
                    ("01 50 01 00 07 07", ("90" if rtu_profile else "80") + " 00 50 01 00 07 07 01"),
                    ("02 50 01 00 07 07 00", "10 00" if rtu_profile else "00 00"),
                )
                for seq, (request, expected) in enumerate(exchanges):
                    control = 0xC0 | seq
                    raw.sendall(f01_link_frame(bytes([control]) + bytes.fromhex(request), seq))
                    _, response = f01_receive_apdu(raw)
                    assert response == bytes([control, 0x81]) + bytes.fromhex(expected), (request, response.hex(" "))
        finally:
            stop(out)
    print("PASS G80V1 WRITE qualifier and selected index policy over real TCP", flush=True)


def profile_binary_event_wire(exe):
    """Check native G2/G4 events against an independent raw TCP peer."""
    import select

    for narrow, timed_default in ((False, 2), (True, 3)):
        options = ["--auth", "compat", "--rtu-io-profile", "--unsolicited",
                   "--unsol-confirm-ms", "500", *loopback_port()]
        port = int(options[-1])
        if narrow:
            options += ["--event-q17", "--binary-event-time", "relative"]
        out = Peer(exe, "outstation", options)
        try:
            out.wait(r"\[HELP\]")
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                transport_seq = 0
                seq = 0

                def send(control, body):
                    nonlocal transport_seq
                    raw.sendall(f01_link_frame(bytes([control]) + bytes.fromhex(body), transport_seq))
                    transport_seq = (transport_seq + 1) & 63

                def event(apdu, group, variation, index, flags):
                    payload = apdu[4:]
                    if variation == 3:
                        assert payload[:4] == bytes.fromhex("33 02 07 01"), apdu.hex()
                        assert len(payload[4:10]) == 6, apdu.hex()
                        payload = payload[10:]
                    qualifier = 0x17 if narrow else 0x28
                    expected = bytes([group, variation, qualifier, 1])
                    if not narrow:
                        expected += bytes([0])
                    expected += index.to_bytes(1 if narrow else 2, "little") + bytes([flags])
                    assert payload.startswith(expected), apdu.hex()
                    time_bytes = payload[len(expected):]
                    assert len(time_bytes) == {1: 0, 2: 6, 3: 2}[variation], apdu.hex()
                    if variation == 3:
                        assert time_bytes == bytes(2), apdu.hex()

                def force(group, index):
                    kind = "binary" if group == 2 else "double"
                    cursor = out.send(f"set {kind} {index} on force")
                    out.wait(rf"\[UPDATE\].*{kind} {index} on force", cursor)

                _, startup = f01_receive_apdu(raw)
                assert startup[:2] == bytes.fromhex("F0 82") and len(startup) == 4, startup.hex()
                send(0xD0, "00")
                for group in (2, 4):
                    for variation, count in ((0, "06"), (1, "07 01"), (2, "08 01 00"), (3, "06")):
                        force(group, 7)
                        request = f"01 {group:02X} {variation:02X} {count}"
                        send(0xC0 | seq, request)
                        _, reply = f01_receive_apdu(raw)
                        assert reply[:2] == bytes([0xE0 | seq, 0x81]), reply.hex()
                        wire_variation = variation or (timed_default if group == 2 else 2)
                        event(reply, group, wire_variation, 7, 0x81)
                        if variation == 1:
                            send(0xC0 | ((seq + 1) & 15), "00")
                            send(0xC0 | seq, request)
                            assert f01_receive_apdu(raw)[1] == reply
                        send(0xC0 | seq, "00")
                        seq += 1

                send(0xC0 | seq, "01 02 00 06 04 00 06")
                _, empty = f01_receive_apdu(raw)
                assert empty[:2] == bytes([0xC0 | seq, 0x81]) and len(empty) == 4, empty.hex()
                seq += 1
                force(2, 8)
                assert not select.select([raw], [], [], 0.05)[0], "events sent before ENABLE_UNSOLICITED"
                send(0xC0 | seq, "14 3C 02 06")
                _, enabled = f01_receive_apdu(raw)
                assert enabled[:2] == bytes([0xC0 | seq, 0x81]) and enabled[3] == 0, enabled.hex()
                _, unsolicited = f01_receive_apdu(raw)
                assert unsolicited[:2] == bytes.fromhex("F1 82"), unsolicited.hex()
                event(unsolicited, 2, timed_default, 8, 0x81)
                send(0xC1, "00")  # Same sequence with the wrong UNS bit.
                assert f01_receive_apdu(raw)[1] == unsolicited
                send(0xD1, "00")
                seq += 1
                send(0xC0 | seq, "01 02 00 06")
                _, empty = f01_receive_apdu(raw)
                assert empty[:2] == bytes([0xC0 | seq, 0x81]) and len(empty) == 4, empty.hex()
        finally:
            stop(out)
    print("PASS binary events: real TCP G2/G4 variation, time, and confirmation", flush=True)


def profile_class_restart(exe):
    """Route events through FC22, a link reconnect, and an Outstation process restart."""
    options = ["--auth", "compat", "--rtu-io-profile", *loopback_port()]
    port = int(options[-1])
    assign = "16 3C 04 06 03 00 06 1E 00 06"
    malformed = "16 3C 04 06 03 00 06 1E 00"
    double_event = bytes.fromhex("04 02 28 01 00 07 00 81")
    analog_event = bytes.fromhex("20 05 28 01 00 08 00 01 00 00 20 41")

    def connect():
        return socket.create_connection(("127.0.0.1", port), timeout=5)

    def force(out):
        for command in ("set double 7 on force", "set analog 8 10 force"):
            cursor = out.send(command)
            out.wait(r"\[UPDATE\].*" + re.escape(command[4:]) + "$", cursor)

    def exchange(raw, seq, request):
        raw.sendall(f01_link_frame(bytes([0xC0 | seq]) + bytes.fromhex(request), seq * 2))
        _, reply = f01_receive_apdu(raw)
        assert reply[1] == 0x81 and reply[0] & 0x0F == seq, (request, reply.hex())
        return reply

    def poll(raw, seq, event_class, expected):
        reply = exchange(raw, seq, f"01 3C {event_class + 1:02X} 06")
        payload = reply[4:]
        assert reply[3] == 0 and bool(reply[0] & 0x20) == bool(expected), reply.hex()
        for event in expected:
            assert payload.startswith(event), reply.hex()
            payload = payload[len(event) + (6 if event == double_event else 0):]
        assert not payload, reply.hex()
        if expected:
            raw.sendall(f01_link_frame(bytes([0xC0 | seq, 0]), seq * 2 + 1))

    out = Peer(exe, "outstation", options)
    try:
        out.wait(r"\[HELP\]")
        with connect() as raw:
            # A truncated second target must not apply even the complete first target.
            assert exchange(raw, 0, malformed) == bytes.fromhex("C0 81 90 04")
            force(out)
            poll(raw, 1, 3, ())
            assert exchange(raw, 2, assign) == bytes.fromhex("C2 81 96 00")
            # Events already queued retain their original classes.
            poll(raw, 3, 1, (double_event,))
            poll(raw, 4, 2, (analog_event,))
            force(out)
            poll(raw, 5, 1, ())
            poll(raw, 6, 2, ())
            poll(raw, 7, 3, (double_event, analog_event))
        with connect() as raw:
            force(out)
            poll(raw, 0, 3, (double_event, analog_event))
    finally:
        stop(out)

    out = Peer(exe, "outstation", options)
    try:
        out.wait(r"\[HELP\]")
        with connect() as raw:
            # A new process is a device restart for the volatile Host configuration.
            assert exchange(raw, 0, "01")[2] & 0x80
            assert exchange(raw, 1, malformed) == bytes.fromhex("C1 81 90 04")
            force(out)
            poll(raw, 2, 3, ())
            poll(raw, 3, 1, (double_event,))
            poll(raw, 4, 2, (analog_event,))
            poll(raw, 5, 1, ())
            poll(raw, 6, 2, ())
    finally:
        stop(out)
    print("PASS FC22 class routing across TCP reconnect and Outstation process restart", flush=True)


def profile_time_wire(exe):
    """Exercise time WRITE/readback and FC23 no-retry link behavior on TCP."""
    for confirm_mode in ("never", "always"):
        options = ["--auth", "compat", "--rtu-io-profile", "--link-confirm", confirm_mode, *loopback_port()]
        out = Peer(exe, "outstation", options)
        try:
            out.wait(r"\[HELP\]")
            with socket.create_connection(("127.0.0.1", int(options[-1])), timeout=5) as raw:
                delay = bytes.fromhex("C0 17")
                raw.sendall(f01_link_frame(delay, 0))
                # f01_receive_apdu checks FC4/UNCONFIRMED_USER_DATA even with link-confirm always.
                assert f01_receive_apdu(raw)[1] == bytes.fromhex("C0 81 90 00 34 02 07 01 00 00")
                raw.sendall(f01_link_frame(delay, 1))
                raw.settimeout(0.1)
                try:
                    assert not raw.recv(1), "Outstation retried a stale delay result"
                except socket.timeout:
                    pass
                raw.sendall(f01_link_frame(bytes.fromhex("C1 17"), 2))
                assert f01_receive_apdu(raw)[1] == bytes.fromhex("C1 81 90 00 34 02 07 01 00 00")
                if confirm_mode == "never":
                    stamp = 0x010203040506
                    payload = bytes.fromhex("C2 02 32 01 07 01") + stamp.to_bytes(6, "little")
                    raw.sendall(f01_link_frame(payload, 3))
                    assert f01_receive_apdu(raw)[1] == bytes.fromhex("C2 81 80 00")
                    raw.sendall(f01_link_frame(bytes.fromhex("C3 01 32 01 07 01"), 4))
                    reply = f01_receive_apdu(raw)[1]
                    assert reply[:8] == bytes.fromhex("C3 81 80 00 32 01 07 01"), reply.hex()
                    assert len(reply) == 14 and stamp <= int.from_bytes(reply[8:], "little") < stamp + 5000
        finally:
            stop(out)
    print("PASS time WRITE readback and unconfirmed FC23 with no stale response retry", flush=True)


def profile_analog_wire(exe):
    """Verify G32V5 request and response bytes over real TCP."""
    for request_qualifier, count_bytes in (
        (0x06, b""),
        (0x07, b"\x01"),
        (0x08, b"\x01\x00"),
    ):
        for use_q17 in (False, True):
            options = [
                "--auth", "compat",
                "--rtu-io-profile",
                *loopback_port(),
            ]
            out_options = ["--event-q17"] if use_q17 else []
            out = Peer(exe, "outstation", [*options, *out_options])

            try:
                out.wait(r"\[HELP\]")
                port = int(options[-1])

                cursor = out.send("set analog 3 12.5 force")
                out.wait(
                    r"\[UPDATE\].*analog 3 12\.5 force",
                    cursor,
                )

                cursor = out.send("show")
                out.wait(
                    r"Input values are this application",
                    cursor,
                )

                with socket.create_connection(
                    ("127.0.0.1", port), timeout=5
                ) as raw:
                    out.wait(r"\[LINK\] OPEN$")

                    request = bytes((
                        0xC0, 0x01,
                        0x20, 0x05,
                        request_qualifier,
                    )) + count_bytes

                    raw.sendall(f01_link_frame(request, 0))
                    _, response = f01_receive_apdu(raw)

                    assert response[1] == 0x81, response.hex()
                    assert response[0] & 0xC0 == 0xC0, response.hex()
                    assert response[0] & 0x0F == 0, response.hex()

                    value = struct.pack("<f", 12.5)

                    if use_q17:
                        expected = bytes.fromhex(
                            "20 05 17 01 03 01"
                        ) + value
                    else:
                        expected = bytes.fromhex(
                            "20 05 28 01 00 03 00 01"
                        ) + value

                    assert response[4:] == expected, (
                        f"request Q{request_qualifier:02X}, "
                        f"response Q{'17' if use_q17 else '28'}: "
                        f"expected={expected.hex()} "
                        f"actual={response[4:].hex()}"
                    )
            finally:
                stop(out)

    print(
        "PASS G32V5 FC1 Q06/Q07/Q08 and response Q17/Q28 wire bytes",
        flush=True,
    )


def profile_analog_unsolicited(exe):
    """Verify RTU G32V5 unsolicited delivery and buffered events."""
    master, out = connected(
        exe,
        ["--auth", "compat", "--rtu-io-profile"],
        out_options=["--unsolicited"],
    )
    try:
        master.task("scan integrity")
        master.task("unsol off")

        cursor = out.send("set analog 3 12.5 force")
        out.wait(r"\[UPDATE\].*analog 3 12\.5 force", cursor)

        cursor = out.send("show")
        out.wait(r"Input values are this application", cursor)

        with master.cv:
            before = len(master.lines)

        time.sleep(0.3)
        with master.cv:
            assert not any(
                "Group32Var5 EVENT Analog[3]" in line
                for line in master.lines[before:]
            ), master.lines[before:]

        cursor = master.send("unsol on")
        master.wait(r"\[TASK\] unsol SUCCESS", cursor)

        line = master.wait(
            r"Group32Var5 EVENT Analog\[3\]=12\.5\b",
            cursor,
        )
        assert "flags=0x01" in line, line
        assert "time=" not in line, line

        with master.cv:
            assert any(
                "Unsolicited response fragment" in item
                for item in master.lines[cursor:]
            ), master.lines[cursor:]

        cursor = master.task("scan class2")
        with master.cv:
            assert not any(
                "Group32Var5 EVENT Analog[3]" in item
                for item in master.lines[cursor:]
            ), master.lines[cursor:]

        master.task("unsol off")

        cursor = out.send("set analog 3 13.5 force")
        out.wait(r"\[UPDATE\].*analog 3 13\.5 force", cursor)

        cursor = out.send("show")
        out.wait(r"Input values are this application", cursor)

        with master.cv:
            before = len(master.lines)

        time.sleep(0.3)
        with master.cv:
            assert not any(
                "Group32Var5 EVENT Analog[3]=13.5" in item
                for item in master.lines[before:]
            ), master.lines[before:]

        cursor = master.task("scan class2")
        line = master.wait(
            r"Group32Var5 EVENT Analog\[3\]=13\.5\b",
            cursor,
        )
        assert "time=" not in line, line

    finally:
        stop(out, master)

    print("PASS G32V5 unsolicited delivery and buffering", flush=True)


def profile_analog_confirm_wire(exe):
    """Verify G32V5 count limit, lost CONFIRM and confirmed removal."""
    for use_q17 in (False, True):
        options = [
            "--auth", "compat", "--rtu-io-profile",
            *loopback_port(),
        ]
        out_options = ["--sol-confirm-ms", "1000"]
        if use_q17:
            out_options.append("--event-q17")

        out = Peer(exe, "outstation", [*options, *out_options])

        try:
            out.wait(r"\[HELP\]")

            for index, value in ((3, "12.5"), (4, "13.5")):
                cursor = out.send(
                    f"set analog {index} {value} force"
                )
                out.wait(
                    rf"\[UPDATE\].*analog {index} "
                    + re.escape(value) + r" force",
                    cursor,
                )

            cursor = out.send("show")
            out.wait(r"Input values are this application", cursor)

            def event_bytes(index, value):
                if use_q17:
                    header = bytes((32, 5, 0x17, 1, index, 1))
                else:
                    header = bytes((32, 5, 0x28, 1, 0, index, 0, 1))
                return header + struct.pack("<f", value)

            with socket.create_connection(
                ("127.0.0.1", int(options[-1])), timeout=5
            ) as raw:
                out.wait(r"\[LINK\] OPEN$")

                def read(seq, transport_seq, count_one=True):
                    qualifier = b"\x07\x01" if count_one else b"\x06"
                    apdu = bytes((0xC0 | seq, 0x01, 32, 5)) + qualifier
                    raw.sendall(f01_link_frame(apdu, transport_seq))
                    _, response = f01_receive_apdu(raw)
                    assert response[1] == 0x81, response.hex()
                    return response

                first = read(0, 0)
                assert first[0] == 0xE0, first.hex()
                assert first[4:] == event_bytes(3, 12.5), first.hex()

                # No CONFIRM: let the configured 1000 ms timer expire.
                time.sleep(1.3)

                # A new READ must recover the unconfirmed first event.
                recovered = read(1, 1)
                assert recovered[0] == 0xE1, recovered.hex()
                assert recovered[4:] == first[4:], recovered.hex()

                # Confirm the recovered event.
                raw.sendall(f01_link_frame(b"\xC1\x00", 2))

                # Count=1 must now return only the second event.
                second = read(2, 3)
                assert second[0] == 0xE2, second.hex()
                assert second[4:] == event_bytes(4, 13.5), second.hex()

                raw.sendall(f01_link_frame(b"\xC2\x00", 4))

                # Both confirmed events must be absent from later READs.
                empty = read(3, 5, count_one=False)
                assert empty[0] == 0xC3, empty.hex()
                assert empty[4:] == b"", empty.hex()

        finally:
            stop(out)

    print("PASS G32V5 lost CONFIRM and count-limited READ", flush=True)


def profile_g41_wire(exe):
    """Verify selected RTU G41 controls over raw TCP/FT3."""
    commands = (
        (1, 2, struct.pack("<i", 123456789)),
        (2, 3, struct.pack("<h", -12345)),
        (3, 4, struct.pack("<f", 4.25)),
    )

    for variation, index, encoded_value in commands:
        for qualifier in (0x17, 0x28):
            options = [
                "--auth", "compat", "--rtu-io-profile",
                *loopback_port(),
            ]
            out = Peer(exe, "outstation", options)

            try:
                out.wait(r"\[HELP\]")

                if qualifier == 0x17:
                    prefix = bytes((1, index))
                else:
                    prefix = struct.pack("<HH", 1, index)

                objects = (
                    bytes((41, variation, qualifier))
                    + prefix
                    + encoded_value
                    + b"\x00"
                )

                with socket.create_connection(
                    ("127.0.0.1", int(options[-1])),
                    timeout=5,
                ) as raw:
                    out.wait(r"\[LINK\] OPEN$")

                    def send_control(seq, function, expect_response):
                        request = bytes((0xC0 | seq, function)) + objects
                        raw.sendall(f01_link_frame(request, seq))

                        if not expect_response:
                            return

                        _, response = f01_receive_apdu(raw)

                        assert response[:2] == bytes(
                            (0xC0 | seq, 0x81)
                        ), response.hex()

                        assert response[4:] == objects, (
                            f"G41V{variation} Q{qualifier:02X} "
                            f"FC{function}: {response.hex()}"
                        )

                    # FC3: SELECT must not execute an output.
                    send_control(0, 3, True)
                    out.executed(0)

                    # FC4: matching OPERATE executes once.
                    send_control(1, 4, True)
                    out.executed(1)

                    # FC5: direct operation executes independently.
                    send_control(2, 5, True)
                    out.executed(2)

                    # FC6: execution without application response.
                    send_control(3, 6, False)
                    raw.sendall(f01_link_frame(b"\xC4\x01\x20\x05\x07\x00", 4))
                    _, barrier = f01_receive_apdu(raw)
                    assert barrier[:2] == b"\xC4\x81" and barrier[4:] == b"", barrier.hex()
                    out.executed(3)

                    raw.settimeout(0.2)
                    try:
                        unexpected = raw.recv(1)
                    except socket.timeout:
                        pass
                    else:
                        raise AssertionError(
                            "FC6 generated a response or closed "
                            f"the connection: {unexpected.hex()}"
                        )

            finally:
                stop(out)

    print(
        "PASS RTU G41V1/V2/V3 FC3/4/5/6 Q17/Q28 wire checks",
        flush=True,
    )


def profile_g41_negative_wire(exe):
    """Negative RTU G41 control and duplicate tests over FT3/TCP."""
    cases = (
        (1, 2, struct.pack("<i", 1234)),
        (2, 3, struct.pack("<h", -123)),
        (3, 4, struct.pack("<f", 4.25)),
    )

    for variation, index, value in cases:
        for qualifier in (0x17, 0x28):
            options = [
                "--auth", "compat", "--rtu-io-profile",
                *loopback_port(),
            ]
            out = Peer(exe, "outstation", options)

            try:
                out.wait(r"\[HELP\]")

                def command(point, encoded):
                    prefix = (
                        bytes((1, point))
                        if qualifier == 0x17
                        else struct.pack("<HH", 1, point)
                    )
                    return (
                        bytes((41, variation, qualifier))
                        + prefix + encoded + b"\x00"
                    )

                original = command(index, value)
                changed_value = value[:-1] + bytes((value[-1] ^ 1,))
                changed = command(index, changed_value)
                invalid_point = command(10, value)
                unsupported = (
                    bytes((41, 4, qualifier))
                    + (
                        bytes((1, 4))
                        if qualifier == 0x17
                        else struct.pack("<HH", 1, 4)
                    )
                    + struct.pack("<d", 4.25)
                    + b"\x00"
                )

                with socket.create_connection(
                    ("127.0.0.1", int(options[-1])), timeout=5
                ) as raw:
                    out.wait(r"\[LINK\] OPEN$")

                    transport = 0

                    def exchange(seq, fc, objects, status):
                        nonlocal transport
                        raw.sendall(f01_link_frame(
                            bytes((0xC0 | seq, fc)) + objects,
                            transport,
                        ))
                        transport += 1

                        _, response = f01_receive_apdu(raw)
                        assert response[:2] == bytes(
                            (0xC0 | seq, 0x81)
                        ), response.hex()

                        expected = objects[:-1] + bytes((status,))
                        assert response[4:] == expected, (
                            f"G41V{variation} Q{qualifier:02X} "
                            f"FC{fc}: {response.hex()}"
                        )
                        return response

                    def noack(seq, objects):
                        nonlocal transport
                        raw.sendall(f01_link_frame(
                            bytes((0xC0 | seq, 6)) + objects,
                            transport,
                        ))
                        transport += 1

                    # OPERATE without SELECT: NO_SELECT = 2.
                    exchange(0, 4, original, 2)
                    out.executed(0)

                    # SELECT succeeds without output execution.
                    exchange(1, 3, original, 0)
                    out.executed(0)

                    # Different OPERATE value cannot use the selection.
                    exchange(2, 4, changed, 2)
                    out.executed(0)

                    # Consumed selection cannot be reused.
                    exchange(3, 4, original, 2)
                    out.executed(0)

                    exchange(4, 3, original, 0)
                    out.executed(0)

                    result = exchange(5, 4, original, 0)
                    out.executed(1)

                    # Identical retry returns the previous response.
                    duplicate = exchange(5, 4, original, 0)
                    assert duplicate == result
                    out.executed(1)

                    # Out-of-range point: OUT_OF_RANGE = 12.
                    exchange(6, 5, invalid_point, 12)
                    out.executed(1)

                    # Unselected G41V4: NOT_SUPPORTED = 4.
                    exchange(7, 3, unsupported, 4)
                    out.executed(1)

                    exchange(8, 5, unsupported, 4)
                    out.executed(1)

                    noack(9, unsupported)

                    # Verify rejected FC6 is processed before checking execution count.
                    raw.sendall(f01_link_frame(
                        b"\xC9\x01\x20\x05\x07\x00", transport
                    ))
                    transport += 1
                    _, barrier = f01_receive_apdu(raw)
                    assert barrier[:2] == b"\xC9\x81" and barrier[4:] == b"", barrier.hex()
                    out.executed(1)

                    # Keep the identical FC6 requests adjacent for replay detection.
                    noack(10, original)
                    noack(10, original)

                    # READ is ordered after both FC6 requests on the same TCP connection.
                    raw.sendall(f01_link_frame(
                        b"\xCB\x01\x20\x05\x07\x00", transport
                    ))
                    transport += 1
                    _, barrier = f01_receive_apdu(raw)
                    assert barrier[:2] == b"\xCB\x81" and barrier[4:] == b"", barrier.hex()
                    out.executed(2)

                    raw.settimeout(0.2)
                    try:
                        data = raw.recv(1)
                    except socket.timeout:
                        pass
                    else:
                        raise AssertionError(
                            f"Unexpected FC6 data/EOF: {data.hex()}"
                        )

            finally:
                stop(out)

    print("PASS G41 negative, duplicate and FC6 replay tests", flush=True)


def profile_g41_timeout_wire(exe):
    """Verify expired SELECT cannot authorize G41 OPERATE."""
    cases = (
        (1, 2, struct.pack("<i", 1234)),
        (2, 3, struct.pack("<h", -123)),
        (3, 4, struct.pack("<f", 4.25)),
    )

    for variation, index, value in cases:
        for qualifier in (0x17, 0x28):
            options = [
                "--auth", "compat", "--rtu-io-profile",
                *loopback_port(),
            ]
            out = Peer(exe, "outstation", options)

            try:
                out.wait(r"\[HELP\]")

                prefix = (
                    bytes((1, index))
                    if qualifier == 0x17
                    else struct.pack("<HH", 1, index)
                )
                objects = (
                    bytes((41, variation, qualifier))
                    + prefix + value + b"\x00"
                )

                with socket.create_connection(
                    ("127.0.0.1", int(options[-1])),
                    timeout=5,
                ) as raw:
                    out.wait(r"\[LINK\] OPEN$")

                    raw.sendall(f01_link_frame(
                        b"\xC0\x03" + objects, 0
                    ))
                    _, selected = f01_receive_apdu(raw)

                    assert selected[:2] == b"\xC0\x81", selected.hex()
                    assert selected[4:] == objects, selected.hex()
                    out.executed(0)

                    # OutstationParams::selectTimeout defaults to 10 seconds.
                    time.sleep(10.25)

                    raw.sendall(f01_link_frame(
                        b"\xC1\x04" + objects, 1
                    ))
                    _, expired = f01_receive_apdu(raw)

                    assert expired[:2] == b"\xC1\x81", expired.hex()
                    assert expired[4:] == (
                        objects[:-1] + b"\x01"
                    ), expired.hex()
                    out.executed(0)

            finally:
                stop(out)

    print("PASS G41 expired SELECT wire tests", flush=True)


def profile_g41_sa(exe, method):
    """Same-implementation SA v5 G41 control and policy acceptance."""
    cases = ((1, 2, "1234"), (2, 3, "-123"), (3, 4, "4.25"))

    for q17 in (False, True):
        profile = "g41sa-" + uuid.uuid4().hex[:12]
        provision = ["--test-only", "--profile", profile, "--auth", method]
        run(exe, "test-provision", *provision)
        options = [*provision, *loopback_port(), "--trust-system-time",
                   "--reply-ms", "5000", "--rtu-io-profile", "--trace"]
        master_options = ["--control-q17"] if q17 else []

        try:
            for denied in (False, True):
                master = out = None
                try:
                    master, out = connected(
                        exe, options, master_options=master_options,
                        out_options=["--deny-controls"] if denied else [],
                    )
                    master.task("read 1 2 0 0")
                    executions = 0

                    for variation, index, value in cases:
                        for mode in ("sbo", "direct"):
                            command = f"analog {variation} {index} {value} {mode}"
                            if denied:
                                with out.cv:
                                    start = len(out.lines)
                                master.task(command, success=False)
                                out.wait(r"\[DENIED\] association=7 user=2$", start)
                            else:
                                master.task(command)
                                executions += 1
                            out.executed(executions)

                        command = f"analog {variation} {index} {value} noack"
                        if denied:
                            with out.cv:
                                start = len(out.lines)
                            master.send(command)
                            out.wait(r"\[DENIED\] association=7 user=2$", start)
                        else:
                            master.noack(command)

                        # Receiver-side barrier for FC6 processing.
                        master.task("read 1 2 0 0")
                        if not denied:
                            executions += 1
                        out.executed(executions)

                    if not denied:
                        cursor = master.send("auth")
                        master.wait(r"\[SESSION\] user=2 ready=1", cursor)
                        cursor = out.send("auth")
                        out.wait(r"\[SESSION\] user=2 ready=1", cursor)
                        out.wait(r"\[SA-OBJECT\] TX G120V1$")
                        master.wait(r"\[SA-OBJECT\] TX G120V2$")
                finally:
                    stop(out, master)
        finally:
            run(exe, "test-cleanup", *provision)

    print("PASS G41 SA " + method +
          ": FC3/4/5/6, Q17/Q28, authorization", flush=True)


def profile_g41_bounds_wire(exe):
    """Selected RTU G41 numeric boundaries and non-finite rejection."""
    valid = (
        (1, 2, struct.pack("<i", -2147483648)),
        (1, 2, struct.pack("<i", 2147483647)),
        (2, 3, struct.pack("<h", -32768)),
        (2, 3, struct.pack("<h", 32767)),
        (3, 4, struct.pack("<I", 0x7F7FFFFF)),
        (3, 4, struct.pack("<I", 0xFF7FFFFF)),
        (3, 4, struct.pack("<I", 0x00000000)),
        (3, 4, struct.pack("<I", 0x80000000)),
        (3, 4, struct.pack("<I", 0x00000001)),
        (3, 4, struct.pack("<I", 0x80000001)),
        (3, 4, struct.pack("<I", 0x007FFFFF)),
        (3, 4, struct.pack("<I", 0x807FFFFF)),
    )

    invalid = (
        struct.pack("<I", 0x7F800000),
        struct.pack("<I", 0xFF800000),
        struct.pack("<I", 0x7FC00000),
        struct.pack("<I", 0x7FC01234),
        struct.pack("<I", 0xFFC01234),
    )

    for qualifier in (0x17, 0x28):
        options = [
            "--auth", "compat", "--rtu-io-profile",
            *loopback_port(),
        ]
        out = Peer(exe, "outstation", options)

        try:
            out.wait(r"\[HELP\]")

            with socket.create_connection(
                ("127.0.0.1", int(options[-1])),
                timeout=5,
            ) as raw:
                out.wait(r"\[LINK\] OPEN$")

                app_seq = 0
                transport_seq = 0
                executions = 0

                def objects(variation, index, value):
                    prefix = (
                        bytes((1, index))
                        if qualifier == 0x17
                        else struct.pack("<HH", 1, index)
                    )
                    return (
                        bytes((41, variation, qualifier))
                        + prefix + value + b"\x00"
                    )

                def send(fc, body, expect_response=True):
                    nonlocal app_seq, transport_seq

                    control = 0xC0 | app_seq
                    raw.sendall(f01_link_frame(
                        bytes((control, fc)) + body,
                        transport_seq,
                    ))

                    app_seq = (app_seq + 1) & 0x0F
                    transport_seq = (transport_seq + 1) & 0x3F

                    if not expect_response:
                        return None

                    _, response = f01_receive_apdu(raw)
                    assert response[:2] == bytes(
                        (control, 0x81)
                    ), response.hex()
                    return response

                def exchange(fc, body, status):
                    response = send(fc, body)
                    expected = body[:-1] + bytes((status,))
                    assert response[4:] == expected, (
                        qualifier, fc, body.hex(), response.hex()
                    )

                def barrier():
                    # Valid all-objects READ of an empty analog
                    # input event buffer. It also detects an
                    # unexpected application response to FC6.
                    response = send(1, b"\x20\x05\x06")
                    assert response[4:] == b"", response.hex()

                for variation, index, value in valid:
                    body = objects(variation, index, value)

                    exchange(3, body, 0)
                    out.executed(executions)

                    exchange(4, body, 0)
                    executions += 1
                    out.executed(executions)

                    exchange(5, body, 0)
                    executions += 1
                    out.executed(executions)

                    send(6, body, expect_response=False)
                    barrier()
                    executions += 1
                    out.executed(executions)

                for value in invalid:
                    body = objects(3, 4, value)

                    # Reject non-finite SELECT and leave
                    # no valid selection for OPERATE.
                    exchange(3, body, 12)
                    out.executed(executions)

                    exchange(4, body, 2)
                    out.executed(executions)

                    exchange(5, body, 12)
                    out.executed(executions)

                    send(6, body, expect_response=False)
                    barrier()
                    out.executed(executions)

        finally:
            stop(out)

    print("PASS RTU G41 numeric boundaries and non-finite rejection",
          flush=True)


def profile_crob_latch(exe):
    """Exercise explicit interlocked Complementary Latches over authenticated TCP."""

    rejected = run(
        exe, "outstation", "--rtu-io-profile", "--test-only",
        "--auth", "compat", "--rtu-crob-latch", "3",
        success=False,
    )
    assert "RTU CROB models require an RTU outstation, --test-only and SA" in rejected.stderr, rejected.stderr

    duplicate = run(
        exe, "outstation", "--rtu-io-profile", "--test-only",
        "--auth", "method4", "--rtu-crob-latch", "3",
        "--rtu-crob-latch", "3", success=False,
    )
    assert "Duplicate --rtu-crob-latch index" in duplicate.stderr

    master, out = connected(
        exe, ["--auth", "compat", "--rtu-io-profile"]
    )
    try:
        cursor = master.task("crob 3 on sbo", success=False)
        master.wait(r"status=NOT_SUPPORTED", cursor)
        out.executed(0)
    finally:
        stop(out, master)

    profile = "pc-" + uuid.uuid4().hex[:12]
    args = ["--test-only", "--profile", profile, "--auth", "method4"]

    run(exe, "test-provision", *args)
    try:
        options = [
            *args, "--trust-system-time", "--reply-ms", "5000",
            "--trace", "--rtu-io-profile",
        ]

        for q17 in (False, True):
            master, out = connected(
                exe, options,
                master_options=["--control-q17"] if q17 else [],
                out_options=[
                    "--rtu-crob-latch", "3",
                    "--rtu-crob-latch", "5",
                ],
            )
            try:
                cursor = master.task("crob 3 on sbo", success=False)
                master.wait(
                    r"state=SELECT_FAIL status=AUTOMATION_INHIBIT",
                    cursor,
                )
                out.wait(r"\[SA-OBJECT\] TX G120V1$")
                master.wait(r"\[SA-OBJECT\] TX G120V2$")
                out.executed(0)

                cursor = master.task("crob 4 on sbo", success=False)
                master.wait(r"status=NOT_SUPPORTED", cursor)
                out.executed(0)

                cursor = out.send("crob-interlock 3 allow")
                out.wait(r"\[INTERLOCK\] CROB\[3\] allow$", cursor)

                cursor = master.task("crob 5 on sbo", success=False)
                master.wait(
                    r"state=SELECT_FAIL status=AUTOMATION_INHIBIT",
                    cursor,
                )
                out.executed(0)

                master.task("crob 3 on sbo")
                out.executed(1)

                cursor = master.task("read 10 2 3 3")
                master.wait(r"BinaryOutput\[3\]=ON\b", cursor)

                master.task("crob 3 off direct")
                out.executed(2)

                cursor = master.task("read 10 2 3 3")
                master.wait(r"BinaryOutput\[3\]=OFF\b", cursor)

                master.noack("crob 3 on noack")

                cursor = master.task("read 10 2 3 3")
                master.wait(r"BinaryOutput\[3\]=ON\b", cursor)
                out.executed(3)

                cursor = out.send("crob-interlock 3 block")
                out.wait(r"\[INTERLOCK\] CROB\[3\] block$", cursor)

                cursor = master.task("crob 3 off direct", success=False)
                master.wait(r"status=AUTOMATION_INHIBIT", cursor)

                master.noack("crob 3 off noack")

                cursor = master.task("read 10 2 3 3")
                master.wait(r"BinaryOutput\[3\]=ON\b", cursor)
                out.executed(3)
            finally:
                stop(out, master)
    finally:
        run(exe, "test-cleanup", *args)


def read_control_frame(peer):
    deadline = time.monotonic() + 5

    def exact(size):
        data = bytearray()
        while len(data) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Incomplete control FT3 frame")
            peer.settimeout(remaining)
            chunk = peer.recv(size - len(data))
            assert chunk, "Unexpected EOF in control FT3 frame"
            data.extend(chunk)
        return bytes(data)

    header = exact(10)
    assert header[:2] == b"\x05\x64"
    assert header[8:] == ft3_crc(header[:8])
    size = header[2] - 5
    assert 0 <= size <= 250

    wire = bytearray(header)
    payload = bytearray()
    while size:
        count = min(size, 16)
        block = exact(count + 2)
        assert block[-2:] == ft3_crc(block[:-2])
        wire.extend(block)
        payload.extend(block[:-2])
        size -= count

    apdu = (bytes(payload[1:]) if len(payload) >= 3
            and (payload[0] & 0xC0) == 0xC0 else b"")
    return bytes(wire), apdu

def aggressive_control_objects(apdu, header_size, user):
    assert len(apdu) >= header_size + 10 + 22
    assert apdu[header_size:header_size + 4] == b"\x78\x03\x07\x01"
    assert int.from_bytes(
        apdu[header_size + 8:header_size + 10], "little"
    ) == user
    assert apdu[-22:-16] == b"\x78\x09\x5b\x01\x10\x00"
    return apdu[header_size + 10:-22]

def profile_crob_interlock_transition(exe):
    """Hold authenticated FC4 while the CLI interlock changes."""
    profile = "pc-" + uuid.uuid4().hex[:12]
    args = ["--test-only", "--profile", profile, "--auth", "method4"]
    options = [*args, "--trust-system-time", "--rtu-io-profile",
               "--aggressive", "--user", "2", "--link-confirm", "never",
               "--response-ms", "15000", "--reply-ms", "5000"]

    def run_case(q17):
        master = out = None
        captured = {}
        errors = []
        held = threading.Event()
        release = threading.Event()
        stopping = threading.Event()
        out_send_lock = threading.Lock()
        qualifier = 0x17 if q17 else 0x28

        try:
            with ExitStack() as sockets:
                listener = sockets.enter_context(
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                )
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(10)
                master_port = str(listener.getsockname()[1])

                out_port_args = loopback_port()
                out = Peer(
                    exe, "outstation",
                    [*options, *out_port_args, "--rtu-crob-latch", "3"]
                )
                out.wait(r"Listening on:")

                out_link = sockets.enter_context(
                    socket.create_connection(
                        ("127.0.0.1", int(out_port_args[1])), timeout=5
                    )
                )

                master_options = [*options, "--port", master_port]
                if q17:
                    master_options.append("--control-q17")

                master = Peer(exe, "master", master_options)
                master_link, _ = listener.accept()
                sockets.enter_context(master_link)
                master_link.settimeout(5)

                def send_to_out(wire):
                    with out_send_lock:
                        out_link.sendall(wire)

                def relay():
                    try:
                        while not stopping.is_set():
                            ready, _, _ = select.select(
                                (master_link, out_link), (), (), 0.25
                            )
                            for source in ready:
                                wire, apdu = read_control_frame(source)
                                fc = apdu[1] if apdu else None

                                if source is master_link:
                                    if fc == 3:
                                        captured.setdefault("select", apdu)
                                    elif fc == 4 and "operate" not in captured:
                                        captured["operate"] = (wire, apdu)
                                        held.set()
                                        if not release.wait(6):
                                            raise TimeoutError(
                                                "D-07 OPERATE gate expired"
                                            )
                                        if stopping.is_set():
                                            return
                                    send_to_out(wire)
                                else:
                                    if fc == 0x81 and "select" in captured:
                                        if "operate" not in captured:
                                            if ((apdu[0] & 0x0F) ==
                                                    (captured["select"][0] & 0x0F)):
                                                captured.setdefault(
                                                    "select_response", apdu
                                                )
                                        elif ((apdu[0] & 0x0F) ==
                                              (captured["operate"][1][0] & 0x0F)):
                                            captured.setdefault(
                                                "operate_response", apdu
                                            )
                                    master_link.sendall(wire)
                    except Exception as error:
                        if not stopping.is_set():
                            errors.append(error)
                    finally:
                        held.set()

                def interlock(state, timeout=5):
                    cursor = out.send(f"crob-interlock 3 {state}")
                    out.wait(
                        rf"\[INTERLOCK\] CROB\[3\] {state}$",
                        cursor, timeout
                    )

                def readback(state):
                    cursor = master.task("read 10 2 3 3")
                    master.wait(
                        rf"BinaryOutput\[3\]={state}\b", cursor
                    )

                def authentication_failures():
                    cursor = out.send("auth")
                    line = out.wait(
                        r"\[LOCAL-STAT\] index=2 value=\d+$", cursor
                    )
                    return int(line.rsplit("=", 1)[1])

                worker = threading.Thread(target=relay, daemon=True)
                worker.start()

                try:
                    master.wait(r"\[LINK\] OPEN$")
                    out.wait(r"\[LINK\] OPEN$")
                    master.task("read 10 2 3 3")

                    for peer in (master, out):
                        cursor = peer.send("auth")
                        peer.wait(
                            r"\[SESSION\] user=2 ready=1\b", cursor
                        )

                    interlock("allow")
                    master.task("crob 3 off direct")
                    out.executed(1)
                    readback("OFF")

                    cursor = master.send("crob 3 on sbo")
                    assert held.wait(20) and "operate" in captured, errors
                    assert not errors, errors
                    assert "select" in captured
                    assert "select_response" in captured

                    select_apdu = captured["select"]
                    select_response = captured["select_response"]
                    operate_wire, operate_apdu = captured["operate"]

                    assert operate_wire[3] == 0xC4

                    prefix = (
                        bytes.fromhex("0C 01 17 01 03") if q17
                        else bytes.fromhex("0C 01 28 01 00 03 00")
                    )
                    body = prefix + struct.pack(
                        "<BBIIB", 0x41, 1, 100, 0, 0
                    )

                    select_seq = select_apdu[0] & 0x0F
                    operate_seq = (select_seq + 1) & 0x0F

                    assert aggressive_control_objects(select_apdu, 2, 2) == body
                    assert aggressive_control_objects(
                        select_response, 4, 1
                    ) == body
                    assert (operate_apdu[0] & 0x0F) == operate_seq
                    assert aggressive_control_objects(
                        operate_apdu, 2, 2
                    ) == body

                    status = out.send("status")
                    out.wait(
                        r"channel=.* executed=1$", status, timeout=2
                    )

                    interlock("block", timeout=2)
                    release.set()

                    master.wait(
                        r"\[RX\] crob\[3\] state=SUCCESS "
                        r"status=AUTOMATION_INHIBIT\b",
                        cursor
                    )
                    master.wait(r"\[RESULT\] crob task=", cursor)

                    response = captured["operate_response"]
                    assert (response[0] & 0x0F) == operate_seq
                    assert aggressive_control_objects(
                        response, 4, 1
                    ) == body[:-1] + b"\x0a"

                    out.executed(1)
                    readback("OFF")

                    interlock("allow")
                    failures = authentication_failures()

                    send_to_out(operate_wire)
                    readback("OFF")

                    assert authentication_failures() == failures + 1
                    out.executed(1)

                    master.task("crob 3 on sbo")
                    out.executed(2)
                    readback("ON")

                    assert not errors, errors
                    print(
                        f"D-07 Q{qualifier:02X} "
                        "interlock transition and replay checked",
                        flush=True
                    )
                finally:
                    stopping.set()
                    release.set()
                    for peer_link in (master_link, out_link):
                        try:
                            peer_link.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                    worker.join(timeout=6)
                    assert not worker.is_alive(), (
                        "D-07 relay failed to stop"
                    )
        finally:
            stop(out, master)

    run(exe, "test-provision", *args)
    try:
        for q17 in (False, True):
            run_case(q17)
    finally:
        run(exe, "test-cleanup", *args)


def profile_crob_two_output(exe):
    """Test deterministic authenticated Complementary Two-output CROB pulses."""
    profile = "pc-" + uuid.uuid4().hex[:12]
    provision = ["--test-only", "--profile", profile, "--auth", "method4"]
    out_config = ["--rtu-io-profile", "--rtu-crob-two-output", "3:10000"]

    invalid_options = (
        (["--rtu-crob-two-output", "3:0"], "Timeout must be"),
        (["--rtu-crob-two-output", "3:"], "Invalid numeric option"),
        (["--rtu-crob-two-output", "3"], "Expected --rtu-crob-two-output"),
        (["--rtu-crob-two-output", "x:1"],
         "Invalid --rtu-crob-two-output index or pulse duration"),
        (["--rtu-crob-two-output", "3:abc"],
         "Invalid --rtu-crob-two-output index or pulse duration"),
        (["--rtu-crob-two-output", "10:1"], "Numeric option out of range"),
        (["--rtu-crob-two-output", "3:120001"], "Numeric option out of range"),
        (["--rtu-crob-two-output", "3:4294967296"], "Numeric option out of range"),
        (["--rtu-crob-two-output", "3:-1"], "Invalid numeric option"),
        (["--rtu-crob-two-output", "3:1",
          "--rtu-crob-two-output", "3:2"], "Duplicate --rtu-crob-two-output"),
        (["--rtu-crob-latch", "3",
          "--rtu-crob-two-output", "3:1"], "Conflicting CROB models"),
    )
    for extra, message in invalid_options:
        result = run(
            exe, "outstation", *provision, "--rtu-io-profile",
            *extra, success=False
        )
        assert message in result.stderr, (extra, result.stderr)

    wrong_role = run(
        exe, "master", *provision, "--rtu-io-profile",
        "--rtu-crob-two-output", "3:1", success=False
    )
    assert "RTU CROB models require an RTU outstation" in wrong_role.stderr
    no_test_mode = run(
        exe, "outstation", "--auth", "method4", "--rtu-io-profile",
        "--rtu-crob-two-output", "3:1", success=False
    )
    assert "require an RTU outstation, --test-only and SA" in no_test_mode.stderr
    compat_mode = run(
        exe, "outstation", "--test-only", "--auth", "compat",
        "--rtu-io-profile", "--rtu-crob-two-output", "3:1",
        success=False
    )
    assert "require an RTU outstation, --test-only and SA" in compat_mode.stderr

    def read_frame(peer):
        deadline = time.monotonic() + 5

        def exact(size):
            data = bytearray()
            while len(data) < size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Incomplete two-output FT3 frame")
                peer.settimeout(remaining)
                chunk = peer.recv(size - len(data))
                assert chunk, "Unexpected EOF in two-output FT3 frame"
                data.extend(chunk)
            return bytes(data)

        header = exact(10)
        assert header[:2] == b"\x05\x64"
        assert header[8:] == ft3_crc(header[:8])
        remaining = header[2] - 5
        assert 0 <= remaining <= 250

        wire = bytearray(header)
        payload = bytearray()
        while remaining:
            count = min(remaining, 16)
            block = exact(count + 2)
            assert block[-2:] == ft3_crc(block[:-2])
            wire.extend(block)
            payload.extend(block[:-2])
            remaining -= count

        apdu = (bytes(payload[1:]) if len(payload) >= 3
                and (payload[0] & 0xC0) == 0xC0 else b"")
        return bytes(wire), apdu

    def authenticated_objects(apdu, header_size, user):
        assert len(apdu) >= header_size + 32
        assert apdu[header_size:header_size + 4] == b"\x78\x03\x07\x01"
        assert int.from_bytes(
            apdu[header_size + 8:header_size + 10], "little"
        ) == user
        assert apdu[-22:-16] == b"\x78\x09\x5b\x01\x10\x00"
        return apdu[header_size + 10:-22]

    run(exe, "test-provision", *provision)
    try:
        base = [
            *provision, "--trust-system-time", "--rtu-io-profile",
            "--aggressive", "--user", "2", "--response-ms", "15000",
            "--reply-ms", "5000", "--link-confirm", "never",
        ]

        # A policy-denied control must not start a pulse.
        denied_master, denied_out = connected(
            exe, base,
            out_options=[*out_config, "--deny-controls"],
        )
        try:
            cursor = denied_out.send("crob-interlock 3 allow")
            denied_out.wait(r"\[INTERLOCK\] CROB\[3\] allow$", cursor)
            with denied_out.cv:
                denied_cursor = len(denied_out.lines)
            denied_master.task(
                "crob 3 on direct", success=False
            )
            denied_out.wait(
                r"\[DENIED\] association=7 user=2$", denied_cursor
            )
            denied_out.executed(0)
            cursor = denied_out.send("status")
            denied_out.wait(
                r"\[CROB-STATE\] point=3 model=complementary-two-output "
                r"interlock=allowed close=inactive trip=inactive executed=0$",
                cursor
            )
        finally:
            stop(denied_out, denied_master)

        def run_case(q17):
            master = out = None
            captured = {
                "requests": {},
                "responses": {},
                "gate_used": False,
            }
            errors = []
            held = threading.Event()
            release = threading.Event()
            stopping = threading.Event()
            out_send_lock = threading.Lock()
            fc6_forwarded = threading.Event()

            def send_to_out(wire):
                with out_send_lock:
                    out_link.sendall(wire)

            try:
                with ExitStack() as sockets:
                    listener = sockets.enter_context(
                        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    )
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(1)
                    listener.settimeout(10)

                    out_port = loopback_port()
                    out = Peer(
                        exe, "outstation",
                        [*base, *out_port, *out_config]
                    )
                    out.wait(
                        r"Listening on:"
                    )
                    out.wait(
                        r"\[CROB-CONFIG\] point=3 "
                        r"model=complementary-two-output pulse-ms=10000 "
                        r"close=inactive trip=inactive$"
                    )
                    out_link = sockets.enter_context(
                        socket.create_connection(
                            ("127.0.0.1", int(out_port[1])), timeout=5
                        )
                    )

                    master_options = [
                        *base, "--port", str(listener.getsockname()[1])
                    ]
                    if q17:
                        master_options.append("--control-q17")
                    master = Peer(exe, "master", master_options)
                    master_link, _ = listener.accept()
                    sockets.enter_context(master_link)
                    master_link.settimeout(5)

                    def relay():
                        try:
                            while not stopping.is_set():
                                ready, _, _ = select.select(
                                    (master_link, out_link), (), (), 0.25
                                )
                                for source in ready:
                                    wire, apdu = read_frame(source)
                                    function = apdu[1] if apdu else None
                                    sequence = apdu[0] & 0x0F if apdu else None

                                    if source is master_link:
                                        if function in (3, 4, 5, 6):
                                            captured["requests"][sequence] = (
                                                function, apdu, wire
                                            )
                                        if function == 4 and not captured["gate_used"]:
                                            captured["gate_used"] = True
                                            captured["held_operate"] = (
                                                sequence, apdu, wire
                                            )
                                            held.set()
                                            if not release.wait(20):
                                                raise TimeoutError(
                                                    "Two-output FC4 gate expired"
                                                )
                                            if stopping.is_set():
                                                return
                                        send_to_out(wire)
                                        if function == 6:
                                            fc6_forwarded.set()
                                    else:
                                        if function == 0x81 and apdu:
                                            captured["responses"][sequence] = apdu
                                        master_link.sendall(wire)
                        except Exception as error:
                            if not stopping.is_set():
                                errors.append(error)
                        finally:
                            held.set()

                    worker = threading.Thread(target=relay, daemon=True)
                    worker.start()

                    def interlock(state):
                        cursor = out.send(f"crob-interlock 3 {state}")
                        out.wait(rf"\[INTERLOCK\] CROB\[3\] {state}$", cursor)

                    def state(close, trip, execution_count):
                        cursor = out.send("status")
                        return out.wait(
                            rf"\[CROB-STATE\] point=3 "
                            rf"model=complementary-two-output "
                            rf"interlock=(?:allowed|blocked) "
                            rf"close={close} trip={trip} "
                            rf"executed={execution_count}$",
                            cursor
                        )

                    def readback(value):
                        cursor = master.task("read 10 2 3 3")
                        master.wait(
                            rf"BinaryOutput\[3\]={value}\b", cursor
                        )

                    def echo(function, variation, qualifier, index,
                             code, status):
                        entries = [
                            (seq, request)
                            for seq, request in captured["requests"].items()
                            if request[0] == function
                        ]
                        assert entries, (function, captured["requests"])
                        sequence, (_, apdu, _) = entries[-1]
                        response = captured["responses"].get(sequence)
                        assert response is not None, (function, sequence)
                        assert response[1] == 0x81
                        prefix = (
                            bytes((12, variation, qualifier, 1, index))
                            if qualifier == 0x17 else
                            bytes((12, variation, qualifier, 1, 0,
                                   index, 0))
                        )
                        expected = prefix + struct.pack(
                            "<BBIIB", code, 1, 100, 0, status
                        )
                        assert authenticated_objects(apdu, 2, 2) == (expected[:-1] + b"\x00")
                        assert authenticated_objects(response, 4, 1) == expected
                        return sequence, expected

                    def advance(milliseconds, total):
                        cursor = out.send(
                            f"crob-pulse advance {milliseconds}"
                        )
                        out.wait(
                            rf"\[CROB-CLOCK\] advanced-ms={milliseconds} "
                            rf"total-ms={total}$", cursor
                        )

                    def auth_failures():
                        cursor = out.send("auth")
                        line = out.wait(
                            r"\[LOCAL-STAT\] index=2 value=\d+$", cursor
                        )
                        return int(line.rsplit("=", 1)[1])

                    try:
                        master.wait(r"\[LINK\] OPEN$")
                        out.wait(r"\[LINK\] OPEN$")
                        master.task("read 10 2 3 3")

                        for peer in (master, out):
                            cursor = peer.send("auth")
                            peer.wait(
                                r"\[SESSION\] user=2 ready=1\b", cursor
                            )

                        state("inactive", "inactive", 0)
                        readback("OFF")

                        cursor = master.task(
                            "crob 3 on sbo", success=False
                        )
                        master.wait(
                            r"\[RX\] crob\[3\] state=SELECT_FAIL "
                            r"status=AUTOMATION_INHIBIT\b",
                            cursor
                        )
                        echo(3, 1, 0x17 if q17 else 0x28,
                             3, 0x41, 10)
                        state("inactive", "inactive", 0)

                        interlock("allow")
                        cursor = master.send("crob 3 on sbo")
                        assert held.wait(20), errors
                        assert not errors, errors
                        assert "held_operate" in captured
                        state("inactive", "inactive", 0)

                        selected = [
                            (seq, request)
                            for seq, request in captured["requests"].items()
                            if request[0] == 3
                        ][-1]
                        select_sequence = selected[0]
                        select_response = captured["responses"].get(
                            select_sequence
                        )
                        assert select_response is not None
                        qualifier = 0x17 if q17 else 0x28
                        prefix = (
                            bytes((12, 1, qualifier, 1, 3))
                            if q17 else bytes((12, 1, qualifier, 1, 0, 3, 0))
                        )
                        close_body = prefix + struct.pack(
                            "<BBIIB", 0x41, 1, 100, 0, 0
                        )
                        assert authenticated_objects(
                            selected[1][1], 2, 2
                        ) == close_body
                        assert authenticated_objects(
                            select_response, 4, 1
                        ) == close_body
                        assert select_response[1] == 0x81

                        held_sequence, held_apdu, held_wire = (
                            captured["held_operate"]
                        )
                        assert held_wire[3] == 0xC4
                        assert (held_sequence
                                == ((select_sequence + 1) & 0x0F))
                        assert authenticated_objects(
                            held_apdu, 2, 2
                        ) == close_body

                        release.set()
                        master.wait(r"\[RESULT\] crob task=", cursor)
                        master.wait(
                            r"\[RX\] crob\[3\] state=SUCCESS "
                            r"status=SUCCESS\b",
                            cursor
                        )
                        out.wait(
                            r"\[CROB-PULSE\] started point=3 drive=close "
                            r"configured-ms=10000 request-on-ms=100 "
                            r"request-off-ms=0 executed=1$"
                        )
                        echo(4, 1, qualifier, 3, 0x41, 0)
                        out.executed(1)
                        state("active", "inactive", 1)

                        cursor = master.task(
                            "crob 3 on sbo", success=False
                        )
                        master.wait(
                            r"\[RX\] crob\[3\] state=SELECT_FAIL "
                            r"status=ALREADY_ACTIVE\b",
                            cursor
                        )
                        echo(3, 1, qualifier, 3, 0x41, 5)

                        cursor = master.task(
                            "crob 3 off direct", success=False
                        )
                        master.wait(
                            r"\[RX\] crob\[3\] state=SUCCESS "
                            r"status=ALREADY_ACTIVE\b",
                            cursor
                        )
                        echo(5, 1, qualifier, 3, 0x81, 5)

                        responses_before_fc6 = len(captured["responses"])
                        fc6_forwarded.clear()
                        master.noack("crob 3 off noack")
                        assert fc6_forwarded.wait(5), ("FC6 not forwarded", errors)
                        fc6_sequence = [
                            seq for seq, request in
                            captured["requests"].items()
                            if request[0] == 6
                        ][-1]
                        assert fc6_sequence not in captured["responses"]
                        assert len(captured["responses"]) == responses_before_fc6
                        out.executed(1)
                        state("active", "inactive", 1)

                        advance(101, 101)
                        state("active", "inactive", 1)
                        advance(9898, 9999)
                        state("active", "inactive", 1)
                        advance(1, 10000)
                        out.wait(
                            r"\[CROB-PULSE\] expired point=3 drive=close$"
                        )
                        state("inactive", "inactive", 1)
                        readback("OFF")

                        failures = auth_failures()
                        send_to_out(held_wire)
                        deadline = time.monotonic() + 5
                        while True:
                            current = auth_failures()
                            if current > failures:
                                break
                            remaining = deadline - time.monotonic()
                            assert remaining > 0, (
                                "Replayed Aggressive OPERATE was not rejected"
                            )
                            with out.cv:
                                out.cv.wait(min(0.05, remaining))
                        out.executed(1)
                        state("inactive", "inactive", 1)

                        cursor = master.task("crob 3 off direct")
                        master.wait(
                            r"\[RX\] crob\[3\] state=SUCCESS "
                            r"status=SUCCESS\b",
                            cursor
                        )
                        echo(5, 1, qualifier, 3, 0x81, 0)
                        out.wait(
                            r"\[CROB-PULSE\] started point=3 drive=trip "
                            r"configured-ms=10000 request-on-ms=100 "
                            r"request-off-ms=0 executed=2$"
                        )
                        out.executed(2)
                        state("inactive", "active", 2)
                        readback("OFF")

                        advance(10000, 20000)
                        out.wait(
                            r"\[CROB-PULSE\] expired point=3 drive=trip$"
                        )
                        state("inactive", "inactive", 2)

                        responses_before_fc6 = len(captured["responses"])
                        fc6_forwarded.clear()
                        master.noack("crob 3 on noack")
                        assert fc6_forwarded.wait(5), ("FC6 not forwarded", errors)
                        fc6_sequence = [
                            seq for seq, request in
                            captured["requests"].items()
                            if request[0] == 6
                        ][-1]
                        fc6_apdu = captured["requests"][fc6_sequence][1]
                        assert authenticated_objects(
                            fc6_apdu, 2, 2
                        ) == close_body
                        assert fc6_sequence not in captured["responses"]
                        assert len(captured["responses"]) == responses_before_fc6
                        # Forwarding and Master TX completion precede receiver actuation.
                        out.wait(
                            r"\[CROB-PULSE\] started point=3 drive=close "
                            r"configured-ms=10000 request-on-ms=100 "
                            r"request-off-ms=0 executed=3$"
                        )
                        out.executed(3)
                        state("active", "inactive", 3)
                        readback("OFF")

                        stopping.set()
                        release.set()
                        worker.join(timeout=6)
                        assert not worker.is_alive(), (
                            "Two-output relay failed to stop"
                        )
                        cursor = out.send("quit")
                        out.wait(
                            r"\[CROB-PULSE\] shutdown=inactive "
                            r"point=3 drive=close$",
                            cursor
                        )
                    finally:
                        stopping.set()
                        release.set()
                        if worker.is_alive():
                            worker.join(timeout=6)
                        assert not errors, errors
            finally:
                stop(out, master)

        for q17 in (False, True):
            run_case(q17)
    finally:
        run(exe, "test-cleanup", *provision)


def profile_crob_activation(exe):
    """Exercise explicit Activation pulses through both SA methods and control qualifiers."""
    for args, error in (
        (["--rtu-crob-activation", "3:0"], "Timeout must be"),
        (["--rtu-crob-activation", "3:120001"], "Numeric option out of range"),
        (["--rtu-crob-latch", "3", "--rtu-crob-activation", "3:1"], "Conflicting CROB models"),
    ):
        rejected = run(exe, "outstation", "--test-only", "--auth", "method4", "--rtu-io-profile",
                       *args, success=False)
        assert error in rejected.stderr, (args, rejected.stderr)
    for method in ("method4", "method68"):
        profile = "pc-" + uuid.uuid4().hex[:12]
        provision = ["--test-only", "--profile", profile, "--auth", method]
        run(exe, "test-provision", *provision)
        try:
            for narrow in (False, True):
                master, out = connected(
                    exe, [*provision, "--trust-system-time", "--rtu-io-profile", "--trace"],
                    master_options=["--control-q17"] if narrow else [],
                    out_options=["--rtu-crob-activation", "3:250", "--rtu-crob-activation", "5:250",
                                 "--rtu-crob-latch", "4", "--rtu-crob-two-output", "6:250"],
                )
                try:
                    for point, action, status in (
                        (3, "pulse", "AUTOMATION_INHIBIT"),
                        (5, "pulse", "AUTOMATION_INHIBIT"),
                        (4, "pulse", "NOT_SUPPORTED"),
                        (6, "pulse", "NOT_SUPPORTED"),
                        (7, "pulse", "NOT_SUPPORTED"),
                        (3, "on", "NOT_SUPPORTED"),
                    ):
                        cursor = master.task(f"crob {point} {action} direct", success=False)
                        master.wait(rf"status={status}\b", cursor)
                    out.executed(0)
                    cursor = out.send("crob-interlock 3 allow")
                    out.wait(r"\[INTERLOCK\] CROB\[3\] allow$", cursor)
                    cursor = out.send("crob-interlock 4 allow")
                    out.wait(r"\[INTERLOCK\] CROB\[4\] allow$", cursor)
                    for point, code, repeat in (
                        (3, 0x01, 0), (3, 0x01, 2), (3, 0x01, 255),
                        (3, 0x02, 1), (3, 0x03, 1), (3, 0x04, 1),
                        (3, 0x11, 1), (3, 0x21, 1), (3, 0xC1, 1), (3, 0xFF, 1),
                        (4, 0x41, 0), (4, 0x81, 2), (4, 0x41, 255),
                        (4, 0x51, 1), (4, 0x91, 1), (4, 0x61, 1), (4, 0xA1, 1),
                    ):
                        for mode in ("sbo", "direct", "noack"):
                            command = f"crob {point} raw {mode} {code} {repeat}"
                            if mode == "noack":
                                master.noack(command)
                            else:
                                cursor = master.task(command, success=False)
                                master.wait(r"status=NOT_SUPPORTED\b", cursor)
                    cursor = master.task("read 10 2 3 4")
                    master.wait(r"BinaryOutput\[3\]=OFF\b", cursor)
                    master.wait(r"BinaryOutput\[4\]=OFF\b", cursor)
                    out.executed(0)
                    for count, (mode, requested) in enumerate((("sbo", 1), ("direct", 2000), ("noack", 999)), 1):
                        with out.cv:
                            cursor = len(out.lines)
                        command = f"crob 3 pulse {mode} {requested}"
                        if mode == "noack":
                            master.noack(command)
                        else:
                            master.task(command)
                        out.wait(
                            rf"\[CROB-PULSE\] started point=3 drive=activation configured-ms=250 "
                            rf"request-on-ms={requested} request-off-ms=0 executed={count}$", cursor,
                        )
                        cursor = out.send("crob-pulse advance 249")
                        out.wait(r"\[CROB-CLOCK\] advanced-ms=249 ", cursor)
                        cursor = out.send("status")
                        out.wait(rf"point=3 model=activation interlock=allowed activation=active executed={count}$", cursor)
                        cursor = out.send("crob-pulse advance 1")
                        out.wait(r"\[CROB-PULSE\] expired point=3 drive=activation$", cursor)
                    out.executed(3)
                finally:
                    stop(out, master)
        finally:
            run(exe, "test-cleanup", *provision)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--asio", type=Path)
    parser.add_argument("--only", choices=("compat", "method4", "method68", "negative", "renewal", "reply-timeout", "tls", "asio", "f01-fragments", "f01-link", "f01-required-fragments", "profile-binary-wire", "profile-class-restart", "profile-time-wire", "profile-analog", "profile-analog-wire", "profile-analog-unsol", "profile-analog-confirm", "profile-g41-wire", "profile-g41-negative", "profile-g41-timeout", "profile-g41-sa4", "profile-g41-sa68", "profile-g41-bounds", "profile-crob-latch", "profile-crob-interlock-transition", "profile-crob-two-output", "profile-crob-activation", "all"), default="all")
    parser.add_argument("--scenario")
    parser.add_argument("--vector", choices=("V1", "V2"))
    parser.add_argument("--seed", type=int, default=1741815)
    args = parser.parse_args()
    assert args.exe.is_file(), args.exe
    if args.scenario:
        if not args.vector or args.only != "all":
            parser.error("an acceptance scenario requires --vector and no smoke-suite filter")
        control = SA_CONTROL_SCENARIO.fullmatch(args.scenario)
        if control and (args.vector == "V1" or control[4] == "DO"):
            acceptance_sa_control(args.exe, control, args.vector == "V1")
        elif args.vector == "V1" and args.scenario == "AT-CFG-14-TCP":
            f01_solicited_fragments(args.exe, observe=True)
        elif args.vector == "V1" and args.scenario == "AT-CFG-13-COMPAT":
            acceptance_counter_profile(args.exe)
        elif args.vector == "V1" and args.scenario in ("AT-CFG-13-STATIC", "AT-CFG-13-EVENT", "AT-CFG-13-NEG"):
            acceptance_rtu_counters(args.exe, args.scenario.removeprefix("AT-CFG-13-"))
        elif args.vector == "V1" and args.scenario in ("AT-CFG-03-MASTER-CLI", "AT-CFG-03-OUTSTATION-CLI"):
            role = args.scenario.split("-")[3].lower()
            acceptance_fragment_options(args.exe, role)
        else:
            parser.error("unknown acceptance scenario or vector")
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
    if args.only in ("profile-binary-wire", "all"): profile_binary_wire(args.exe)
    if args.only in ("profile-class-restart", "all"): profile_class_restart(args.exe)
    if args.only in ("profile-time-wire", "all"): profile_time_wire(args.exe)
    if args.only in ("profile-analog", "all"): profile_analog_event(args.exe)
    if args.only in ("profile-crob-latch", "all"):
        profile_crob_latch(args.exe)
    if args.only in ("profile-analog-wire", "all"): profile_analog_wire(args.exe)
    if args.only in ("profile-analog-unsol", "all"): profile_analog_unsolicited(args.exe)
    if args.only in ("profile-analog-confirm", "all"): profile_analog_confirm_wire(args.exe)
    if args.only in ("profile-g41-wire", "all"): profile_g41_wire(args.exe)
    if args.only in ("profile-g41-negative", "all"): profile_g41_negative_wire(args.exe)
    if args.only in ("profile-g41-timeout", "all"): profile_g41_timeout_wire(args.exe)
    if args.only in ("profile-g41-sa4", "all"): profile_g41_sa(args.exe, "method4")
    if args.only in ("profile-g41-sa68", "all"): profile_g41_sa(args.exe, "method68")
    if args.only in ("profile-g41-bounds", "all"): profile_g41_bounds_wire(args.exe)
    if args.only in ("profile-crob-interlock-transition", "all"):
        profile_crob_interlock_transition(args.exe)
    if args.only in ("profile-crob-two-output", "all"):
        profile_crob_two_output(args.exe)
    if args.only in ("profile-crob-activation", "all"):
        profile_crob_activation(args.exe)
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
