"""Run owned children without persisting raw output."""

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import os
import signal
import subprocess
import sys
import threading


CHILD_GATE = """
import os
import subprocess
import sys

if sys.stdin.buffer.read(1) != b"G":
    sys.exit(125)
code = subprocess.call(sys.argv[1:], stdin=subprocess.DEVNULL)
if os.name == "nt":
    import ctypes
    exit_process = ctypes.WinDLL("kernel32").ExitProcess
    exit_process.argtypes = [ctypes.c_uint32]
    exit_process.restype = None
    exit_process(code)
sys.exit(128 - code if code < 0 else code)
"""
MAX_LINE = 8192


@dataclass
class ProcessResult:
    exit_code: int
    timed_out: bool
    stdout_bytes: int
    stderr_bytes: int


class WindowsJob:
    """Assign the gated launcher before allowing it to spawn descendants."""

    def __init__(self, pid):
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": (wintypes.HANDLE, [wintypes.LPVOID, wintypes.LPCWSTR]),
            "OpenProcess": (wintypes.HANDLE, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]),
            "AssignProcessToJobObject": (wintypes.BOOL, [wintypes.HANDLE, wintypes.HANDLE]),
            "TerminateJobObject": (wintypes.BOOL, [wintypes.HANDLE, wintypes.UINT]),
            "CloseHandle": (wintypes.BOOL, [wintypes.HANDLE]),
        }
        for name, (result, args) in signatures.items():
            function = getattr(self.api, name)
            function.restype, function.argtypes = result, args
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        process = self.api.OpenProcess(0x0101, False, pid)  # SET_QUOTA | TERMINATE
        try:
            if not process or not self.api.AssignProcessToJobObject(self.handle, process):
                raise ctypes.WinError(ctypes.get_last_error())
        except OSError:
            self.api.CloseHandle(self.handle)
            raise
        finally:
            if process:
                self.api.CloseHandle(process)

    def close(self):
        try:
            if not self.api.TerminateJobObject(self.handle, 125):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.api.CloseHandle(self.handle)


def run_child(argv, *, cwd, env, timeout, on_stdout=None):
    """Only bounded, complete stdout lines reach the caller. Stderr is counted."""
    windows = os.name == "nt"
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", CHILD_GATE, *map(str, argv)],
        cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=not windows,
    )
    job = None
    readers = []
    sizes = [0, 0]
    errors = []
    timed_out = False

    def drain(stream, index):
        fragmented = False
        try:
            with stream:
                while chunk := stream.readline(MAX_LINE + 1):
                    sizes[index] += len(chunk)
                    complete = chunk.endswith(b"\n")
                    if index == 0 and on_stdout and not fragmented and (complete or len(chunk) > MAX_LINE):
                        on_stdout(chunk.rstrip(b"\r\n"))
                    fragmented = not complete
        except Exception as exc:
            errors.append(type(exc).__name__)

    try:
        if windows:
            job = WindowsJob(proc.pid)
        for index, stream in enumerate((proc.stdout, proc.stderr)):
            reader = threading.Thread(target=drain, args=(stream, index), daemon=True)
            reader.start()
            readers.append(reader)
        proc.stdin.write(b"G")
        proc.stdin.close()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
    finally:
        if not proc.stdin.closed:
            proc.stdin.close()
        try:
            if job:
                job.close()
            elif windows:
                if proc.poll() is None:
                    proc.kill()
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        finally:
            proc.wait(timeout=5)
            for reader in readers:
                reader.join(timeout=5)
            if not readers:
                proc.stdout.close()
                proc.stderr.close()
    if errors or any(reader.is_alive() for reader in readers):
        raise OSError("child output drain failed")
    return ProcessResult(proc.returncode, timed_out, *sizes)
