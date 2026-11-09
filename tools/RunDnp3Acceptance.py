"""DNP3 acceptance catalog, runner, and evidence writer. Invoke through PowerShell."""

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from xml.etree import ElementTree as ET

sys.dont_write_bytecode = True
from acceptance_process import run_child


REPO = Path(__file__).resolve().parents[1]
CATALOG = REPO / "opendnp3/cpp/tests/acceptance"
MATRIX = CATALOG / "DNP3-54-TEST-MATRIX.csv"
REGISTRY = CATALOG / "phase0.json"
REQUIREMENTS = (
    *(f"PROFILE-{n:03}" for n in (*range(3, 19), *range(20, 47), 63, 64, 65)),
    "SEC-T1-07", "SEC-T1-14", *(f"CFG-{n:02}" for n in (3, 5, 8, 9, 13, 14)),
)
SCENARIO_ID = re.compile(r"AT-(?:PROFILE-\d{3}|SEC-T1-\d{2}|CFG-\d{2})-[A-Z0-9-]+")
CHECK_ID = re.compile(r"[a-z][a-z0-9_]{0,63}")
SHA = re.compile(r"[a-f0-9]{40}")
EVENT = b"DNP3-ACCEPTANCE "
CATEGORIES = {"PARSER", "SERIALIZER", "TRANSPORT", "LINK", "STATE", "TIMEOUT",
              "CONFIG", "AUTH", "COMMAND", "EVENT", "TEST_INFRA"}
LEVELS = {"UNIT_WIRE", "TCP", "PROCESS_TCP", "POLICY", "RTU_HARDWARE", "INDEPENDENT_PEER"}
GATES = {"HOST", "HOST_MASTER_RX", "EXTERNAL_POLICY", "EXTERNAL_HARDWARE", "EXTERNAL_PEER"}
STATES = ("PASS", "FAIL", "BLOCKED", "NOT_RUN", "INCONCLUSIVE")
BINARIES = {
    "unit": "cpp/tests/unit/{configuration}/unittests.exe",
    "integration": "cpp/tests/integration/{configuration}/integrationtests.exe",
    "process": "cli/{configuration}/dnp3-cli.exe",
}
BUILD_TARGETS = ("unittests", "integrationtests", "dnp3-cli")
CONFIGS = ("Debug", "Release", "RelWithDebInfo", "MinSizeRel")


class InfraError(Exception):
    """Error code chosen by this runner. Never use subprocess text as its value."""


def require(condition, code):
    if not condition:
        raise InfraError(code)


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def write_text(path, text):
    with path.open("x", encoding="utf-8", newline="\n") as file:
        file.write(text)


def write_json(path, value):
    write_text(path, json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n")


def parse_json(data):
    def unique(pairs):
        values = dict(pairs)
        require(len(values) == len(pairs), "DUPLICATE_JSON_KEY")
        return values

    return json.loads(data, object_pairs_hook=unique)


def read_json(path):
    return parse_json(path.read_text(encoding="utf-8-sig"))


def load_catalog():
    required = {"scenario_id", "requirement_id", "selected_subcase", "expected_wire",
                "expected_receiver_state", "proposed_case", "priority", "evidence_level", "gate", "planning_status"}
    with MATRIX.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        fields = reader.fieldnames or []
        require(required <= set(fields) and len(fields) == len(set(fields)), "INVALID_MATRIX_HEADER")
        rows = list(reader)
    by_id = {}
    for row in rows:
        sid, rid = row["scenario_id"], row["requirement_id"]
        require(None not in row and all(row[key] for key in required) and
                SCENARIO_ID.fullmatch(sid) and sid.startswith(f"AT-{rid}-") and sid not in by_id and
                row["proposed_case"] == sid and row["evidence_level"] in LEVELS and row["gate"] in GATES and
                row["priority"] in {"P0", "P1", "P2", "P3"} and row["planning_status"] == "NOT_RUN",
                "INVALID_MATRIX_ROW")
        by_id[sid] = row
    require(len(by_id) == 448 and {r["requirement_id"] for r in rows} == set(REQUIREMENTS),
            "UNEXPECTED_MATRIX_SCOPE")
    registry = read_json(REGISTRY)
    require(isinstance(registry, dict) and set(registry) == {"schema_version", "fixtures", "bindings"} and
            registry["schema_version"] == 1 and all(isinstance(registry[k], dict) for k in ("fixtures", "bindings")),
            "INVALID_REGISTRY")
    fixtures = {}
    for address, fixture in registry["fixtures"].items():
        sid, _, vector = address.partition("/")
        require(sid in by_id and re.fullmatch(r"V[1-9][0-9]*", vector) and
                isinstance(fixture, dict) and isinstance(fixture.get("checks"), list) and fixture["checks"] and
                set(fixture) <= {"checks", "reference", "description", "input_hex", "association"} and
                all(isinstance(fixture.get(k), str) and fixture[k] for k in ("reference", "description")) and
                ("input_hex" not in fixture or isinstance(fixture["input_hex"], str)
                 and re.fullmatch(r"[0-9A-F]{2}(?: [0-9A-F]{2})*", fixture["input_hex"])),
                "INVALID_FIXTURE")
        if "association" in fixture:
            association = fixture["association"]
            require(isinstance(association, dict) and bool(association) and
                    set(association) <= {"master_link", "outstation_link", "sa_association"} and
                    all(type(v) is int and 0 <= v <= 65535 for v in association.values()),
                    "INVALID_FIXTURE_ASSOCIATION")
        checks = set()
        expanded = []
        for spec in fixture["checks"]:
            if isinstance(spec, list) and len(spec) == 5 and spec[1] == "frame":
                name, _, category, role, hex_bytes = spec
                require(isinstance(name, str) and CHECK_ID.fullmatch(name) and
                        isinstance(hex_bytes, str) and len(hex_bytes) <= 4096 and
                        re.fullmatch(r"(?:[0-9A-F]{2}(?: [0-9A-F]{2})*)?", hex_bytes),
                        "INVALID_GOLDEN_FRAME")
                frame = bytes.fromhex(hex_bytes)
                expanded.append([name + "_length", "wire", category, role, len(frame), 0, 65535])
                for offset in range(0, len(frame), 6):
                    chunk = frame[offset:offset+6]
                    expanded.append([f"{name}_bytes_{offset}", "wire", category, role,
                                     int.from_bytes(chunk, "big"), 0, (1 << (8 * len(chunk))) - 1])
            else:
                expanded.append(spec)
        fixture["checks"] = expanded
        for spec in expanded:
            require(isinstance(spec, list) and len(spec) == 7, "INVALID_CHECK")
            check, stream, category, role, expected, low, high = spec
            require(isinstance(check, str) and CHECK_ID.fullmatch(check) and check not in checks and
                    stream in ("wire", "receiver", "state") and category in CATEGORIES and
                    role in ("MASTER", "OUTSTATION", "RUNNER") and
                    all(type(n) is int for n in (expected, low, high)) and
                    -(1 << 63) <= low <= expected <= high < (1 << 64),
                    "INVALID_CHECK")
            checks.add(check)
        fixtures.setdefault(sid, {})[vector] = fixture
    bindings = registry["bindings"]
    for sid, binding in bindings.items():
        require(sid in by_id and by_id[sid]["gate"].startswith("HOST") and isinstance(binding, dict) and
                set(binding) == {"kind", "vectors"} and binding["kind"] in BINARIES and
                isinstance(binding["vectors"], list) and binding["vectors"] and
                all(isinstance(v, str) for v in binding["vectors"]) and
                set(binding["vectors"]) == set(fixtures.get(sid, {})) and
                len(set(binding["vectors"])) == len(binding["vectors"]) and
                binding["kind"] == {"UNIT_WIRE": "unit", "TCP": "integration",
                                    "PROCESS_TCP": "process"}.get(by_id[sid]["evidence_level"]),
                "INVALID_BINDING")
    return by_id, fixtures, bindings


def external(path):
    path = Path(path).expanduser().resolve()
    require(path != REPO and REPO not in path.parents, "PATH_INSIDE_REPOSITORY")
    return path


def default_root():
    return REPO.parent / "DNP3-EXTRA-TEST-EVIDENCE"


def config(path):
    values = {
        "schema_version": 1, "configuration": "Release", "generator": "Visual Studio 17 2022",
        "architecture": "x64", "build_timeout_seconds": 1200, "unit_timeout_seconds": 30,
        "integration_timeout_seconds": 60, "process_timeout_seconds": 240,
        "cmake": None, "toolchain": None,
    }
    if path:
        data = read_json(Path(path))
        require(isinstance(data, dict) and set(data) <= set(values), "INVALID_CONFIG_FIELDS")
        values.update(data)
    require(type(values["schema_version"]) is int and values["schema_version"] == 1 and
            values["configuration"] in CONFIGS and
            values["architecture"] in ("x64", "Win32", "ARM64") and
            isinstance(values["generator"], str) and re.fullmatch(r"Visual Studio [0-9]{2} [0-9]{4}", values["generator"]),
            "INVALID_BUILD_CONFIG")
    for key in values:
        if key.endswith("_seconds"):
            require(type(values[key]) is int and 1 <= values[key] <= 86400, "INVALID_TIMEOUT")
    for key in ("cmake", "toolchain"):
        value = values[key]
        if value is not None:
            require(isinstance(value, str) and Path(value).is_absolute() and Path(value).is_file(),
                    "INVALID_TOOL_PATH")
    return values


def git(*args):
    result = subprocess.run(["git", "-C", str(REPO), *args], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=30, check=False)
    require(result.returncode == 0, "GIT_QUERY_FAILED")
    return result.stdout


def source_identity():
    commit = git("rev-parse", "HEAD").decode("ascii").strip()
    require(SHA.fullmatch(commit), "INVALID_HEAD")
    tree = hashlib.sha256()
    entries = git("ls-files", "-z", "--cached", "--others", "--exclude-standard", "--",
                  "opendnp3", "apps", "cli", "tools", "CMakeLists.txt")
    for entry in sorted(set(entries.split(b"\0")) - {b""}):
        path = REPO / os.fsdecode(entry)
        if path.is_symlink():
            digest = b"link:" + os.fsencode(os.readlink(path))
        elif path.is_file():
            digest = sha256(path).encode("ascii")
        else:
            digest = b"absent"
        tree.update(entry + b"\0" + digest + b"\0")
    return {"commit_sha": commit, "source_sha256": tree.hexdigest()}


def quote_ps(value):
    return "'" + str(value).replace("'", "''") + "'"


def reproduction(args, sid, vector, root, receipt):
    parts = ["&", quote_ps(REPO / "tools/run-acceptance.ps1"), "-Scenario", quote_ps(sid),
             "-Vector", quote_ps(vector), "-Seed", str(args.seed), "-ArtifactRoot", quote_ps(root),
             "-Python", quote_ps(sys.executable)]
    for flag, value in (("-Config", args.config), ("-BuildReceipt", receipt)):
        if value:
            parts.extend((flag, quote_ps(Path(value).resolve())))
    return " ".join(parts)


def redacted_counts(folder, result, prefix=""):
    for stream in ("stdout", "stderr"):
        count = getattr(result, stream + "_bytes") if result else None
        write_text(folder / f"{prefix}{stream}.log",
                   f"Raw child output withheld. Byte count: {count if count is not None else 'unavailable'}.\n")


class Evidence:
    """Keep only catalogued numeric observations and runner-owned fields."""

    def __init__(self, folder, context, fixture):
        self.folder = folder
        self.context = context
        self.checks = fixture["checks"] if fixture else []
        self.next_check = 0
        self.first = None
        self.invalid = False
        self.counter = 0

    def event(self, event_type, **fields):
        self.counter += 1
        record = dict(self.context, event_id=self.counter, cause_id=self.counter - 1 or None,
                      event_type=event_type, utc=utc(),
                      mono_ns=time.monotonic_ns(), clock_id="runner", **fields)
        streams = ["timeline.jsonl"]
        if fields.get("stream") == "wire":
            streams.append("public-wire.jsonl")
        elif fields.get("stream") == "receiver":
            streams.append("receiver.jsonl")
        for name in streams:
            with (self.folder / name).open("a", encoding="utf-8", newline="\n") as file:
                file.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
        return record

    def observe(self, line):
        if not line.startswith(EVENT) or self.invalid:
            return
        try:
            require(len(line) <= 1024, "OVERSIZE_EVENT")
            data = parse_json(line[len(EVENT):])
            require(isinstance(data, dict) and set(data) == {"check", "value"} and
                    self.next_check < len(self.checks), "UNEXPECTED_EVENT")
            check, stream, category, role, expected, low, high = self.checks[self.next_check]
            value = data["value"]
            require(data["check"] == check and type(value) is int and low <= value <= high,
                    "INVALID_OBSERVATION")
        except (InfraError, ValueError, RecursionError):
            self.invalid = True
            self.event("invalid_observation", mismatch_category="TEST_INFRA")
            return
        self.next_check += 1
        public_hex = {}
        if stream == "wire" and "_bytes_" in check:
            width = (high.bit_length() + 7) // 8
            public_hex = {"expected_hex": expected.to_bytes(width, "big").hex(" "),
                          "observed_hex": value.to_bytes(width, "big").hex(" ")}
        record = self.event("check", check=check, stream=stream, endpoint=role, expected=expected, observed=value,
                            assertion=f"{check} equals golden value",
                            mismatch_category=None if expected == value else category, **public_hex)
        if expected != value and self.first is None:
            keys = ("event_id", "cause_id", "check", "assertion", "endpoint", "expected", "observed",
                    "expected_hex", "observed_hex", "mismatch_category")
            self.first = {key: record[key] for key in keys if key in record}

    def result(self, process):
        if process.timed_out:
            return "INCONCLUSIVE", "CHILD_TIMEOUT", "TIMEOUT"
        if self.invalid:
            return "INCONCLUSIVE", "INVALID_OBSERVATION", "TEST_INFRA"
        if process.exit_code in (0, 1) and self.first:
            return "FAIL", "ASSERTION", self.first["mismatch_category"]
        if process.exit_code:
            return "INCONCLUSIVE", "CHILD_EXIT_WITHOUT_MATCHING_ASSERTION", "TEST_INFRA"
        if not self.checks or self.next_check != len(self.checks):
            return "INCONCLUSIVE", "MISSING_OBSERVATIONS", "TEST_INFRA"
        return "PASS", "ALL_CHECKS_MATCH", None


def receipt_data(path, identity, settings):
    path = external(path)
    receipt = read_json(path)
    require(isinstance(receipt, dict) and receipt.get("schema_version") == 1 and
            receipt.get("identity") == identity and receipt.get("configuration") == settings["configuration"] and
            isinstance(receipt.get("build_dir"), str) and isinstance(receipt.get("binaries"), dict) and
            set(receipt["binaries"]) == set(BINARIES), "BUILD_RECEIPT_MISMATCH")
    build = external(receipt["build_dir"])
    require(path.name == "build-receipt.json" and build.name == path.parent.name, "INVALID_BUILD_PATH")
    files = {}
    for kind, relative in BINARIES.items():
        binary = external(build / relative.format(configuration=settings["configuration"]))
        require(build in binary.parents and binary.is_file() and sha256(binary) == receipt["binaries"][kind],
                "BINARY_HASH_MISMATCH")
        files[kind] = binary
    return files


def build_native(run, identity, settings, env):
    require(os.name == "nt", "WINDOWS_BUILD_REQUIRED")
    cmake = settings["cmake"] or shutil.which("cmake")
    require(cmake, "CMAKE_NOT_FOUND")
    build = external(run.parent / "builds" / run.name)
    build.mkdir(parents=True)
    configure = [
        cmake, "-S", REPO / "opendnp3", "-B", build, "-G", settings["generator"], "-A", settings["architecture"],
        "-DDNP3_DIAGNOSTIC_CLI=ON", "-DDNP3_SA_CRYPTO=ON", "-DDNP3_TLS=ON", "-DDNP3_TESTS=ON",
        f"-DPython3_EXECUTABLE={sys.executable}",
    ]
    toolchain = settings["toolchain"]
    if toolchain is None and os.environ.get("VCPKG_ROOT"):
        candidate = Path(os.environ["VCPKG_ROOT"]) / "scripts/buildsystems/vcpkg.cmake"
        if candidate.is_file():
            toolchain = candidate
    if toolchain:
        configure.append(f"-DCMAKE_TOOLCHAIN_FILE={toolchain}")
    compile_targets = [cmake, "--build", build, "--config", settings["configuration"], "--target", *BUILD_TARGETS]
    for name, argv in (("configure", configure), ("compile", compile_targets)):
        result = None
        started = utc()
        try:
            result = run_child(argv, cwd=build, env=env, timeout=settings["build_timeout_seconds"])
        finally:
            redacted_counts(run, result, f"{name}.")
            write_json(run / f"{name}.json", {"started_utc": started, "finished_utc": utc(),
                       "command": list(map(str, argv)), "result": vars(result) if result else None})
        require(not result.timed_out and result.exit_code == 0, f"CMAKE_{name.upper()}_FAILED")
    require(source_identity() == identity, "SOURCE_CHANGED_DURING_BUILD")
    binaries = {kind: sha256(build / pattern.format(configuration=settings["configuration"]))
                for kind, pattern in BINARIES.items()}
    path = run / "build-receipt.json"
    write_json(path, {"schema_version": 1, "identity": identity, "configuration": settings["configuration"],
                      "build_dir": str(build), "binaries": binaries})
    return path


def execute_vector(row, vector, fixture, binding, *, args, run, root, identity, receipt, binaries, binary_hashes, settings, env):
    sid = row["scenario_id"]
    folder = run / "scenarios" / sid / vector
    folder.mkdir(parents=True)
    for name in ("timeline.jsonl", "public-wire.jsonl", "receiver.jsonl"):
        write_text(folder / name, "")
    context = dict(identity, run_id=run.name, scenario_id=sid, vector_id=vector,
                   requirement_id=row["requirement_id"], seed=args.seed, schema_version=1,
                   direction=row.get("direction"), association=fixture.get("association") if fixture else None,
                   tested_executable_sha256=binary_hashes.get(binding["kind"]) if binding else None)
    evidence = Evidence(folder, context, fixture)
    repro = reproduction(args, sid, vector, root, receipt)
    evidence.event("start")
    result = None
    status, reason, category = "NOT_RUN", "NO_EXECUTABLE_BINDING", None
    interrupted = False
    try:
        if not row["gate"].startswith("HOST"):
            status, reason = "BLOCKED", row["gate"]
        elif binding:
            require(binaries is not None, "MATCHING_BUILD_RECEIPT_REQUIRED")
            kind = binding["kind"]
            child_env = dict(env, DNP3_ACCEPTANCE_SCENARIO=sid, DNP3_ACCEPTANCE_VECTOR=vector,
                             DNP3_ACCEPTANCE_SEED=str(args.seed))
            # Children never run in the evidence directory. A temporary directory
            # outside the source and evidence trees owns their incidental files.
            scratch_root = external(run.parent / "scratch")
            scratch_root.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=run.name + "-", dir=scratch_root) as temp:
                scratch = Path(temp)
                child_env.update(TEMP=temp, TMP=temp, TMPDIR=temp)
                if kind in ("unit", "integration"):
                    # Catch v2 may return the number of selected names.
                    names = []
                    def count_name(line):
                        if len(names) < 2 and line.strip():
                            names.append(line.strip() == sid.encode("ascii"))

                    probe = run_child([binaries[kind], sid, "--list-test-names-only"], cwd=scratch,
                                      env=child_env, timeout=settings[f"{kind}_timeout_seconds"],
                                      on_stdout=count_name)
                    redacted_counts(folder, probe, "discovery.")
                    require(not probe.timed_out and probe.exit_code in (0, 1) and names == [True],
                            "CATCH_CASE_DISCOVERY_FAILED")
                    command = [binaries[kind], sid]
                else:
                    command = [sys.executable, "-B", REPO / "cli/tests/ProcessSmoke.py",
                               "--exe", binaries[kind], "--work-dir", scratch,
                               "--scenario", sid, "--vector", vector, "--seed", str(args.seed)]
                result = run_child(command, cwd=scratch, env=child_env,
                                   timeout=settings[f"{kind}_timeout_seconds"], on_stdout=evidence.observe)
            status, reason, category = evidence.result(result)
    except KeyboardInterrupt:
        status, reason, category = "INCONCLUSIVE", "INTERRUPTED", "TEST_INFRA"
        interrupted = True
    except (InfraError, OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError) as exc:
        status, reason, category = "INCONCLUSIVE", error_code(exc), "TEST_INFRA"
    redacted_counts(folder, result)
    if status == "INCONCLUSIVE" and evidence.first is None:
        pending = evidence.checks[evidence.next_check] if evidence.next_check < len(evidence.checks) else None
        delta = evidence.event("missing_evidence", mismatch_category=category,
                               check=pending[0] if pending else "process_completion",
                               expected=pending[4] if pending else 0,
                               observed=None if pending or not result or result.timed_out else result.exit_code)
        evidence.first = {key: delta[key] for key in ("event_id", "check", "expected", "observed", "mismatch_category")}
    observation = dict(context, status=status, reason=reason, mismatch_category=category,
                       failure_kind={"FAIL": "ASSERTION", "BLOCKED": "UNSUPPORTED_BLOCKED",
                                     "INCONCLUSIVE": "INFRA_CONFIG"}.get(status),
                       first_divergence=evidence.first, reproduction=repro,
                       process=vars(result) if result else None, expected_fixture=fixture,
                       expected_plan={k: row.get(k) for k in (
                           "expected_wire", "expected_receiver_state", "request_fc", "request_q_hex",
                           "response_fc_and_q", "object_group_variation", "ieee_reference", "pdf_source",
                           "initial_conditions", "stimulus")})
    evidence.event("outcome", status=status, reason=reason, mismatch_category=category,
                   first_divergence_id=evidence.first["event_id"] if evidence.first else None)
    write_json(folder / "scenario.json", observation)
    write_junit(folder / "result.xml", [(f"{sid}/{vector}", status, reason)])
    if status != "PASS":
        divergence = json.dumps(evidence.first, ensure_ascii=False)
        write_text(folder / "failure.md", f"# {sid}/{vector}\n\n{status} · {reason}\n\n"
                   f"First divergence: `{divergence}`\n\n"
                   f"Source to investigate: {row.get('production_anchor', 'unavailable')}\n\n"
                   "See `timeline.jsonl`, `public-wire.jsonl`, and `receiver.jsonl`.\n\n"
                   f"```powershell\n{repro}\n```\n")
    return {"vector_id": vector, "status": status, "reason": reason, "interrupted": interrupted,
            "artifact": (folder / "scenario.json").relative_to(run).as_posix()}


def write_junit(path, records):
    suite = ET.Element("testsuite", name="DNP3 acceptance", tests=str(len(records)),
                       failures=str(sum(row[1] == "FAIL" for row in records)),
                       errors=str(sum(row[1] == "INCONCLUSIVE" for row in records)),
                       skipped=str(sum(row[1] in ("NOT_RUN", "BLOCKED") for row in records)))
    for name, status, reason in records:
        case = ET.SubElement(suite, "testcase", name=name, classname="DNP3.Acceptance")
        node = {"FAIL": "failure", "INCONCLUSIVE": "error", "BLOCKED": "skipped", "NOT_RUN": "skipped"}.get(status)
        if node:
            ET.SubElement(case, node, message=f"{status}: {reason}")
    with path.open("xb") as file:
        ET.ElementTree(suite).write(file, encoding="utf-8", xml_declaration=True)


def aggregate(states):
    for status in ("FAIL", "INCONCLUSIVE", "BLOCKED", "NOT_RUN", "PASS"):
        if status in states:
            return status
    return "NOT_RUN"


def finalize(run, records, meta):
    by_requirement = {rid: [] for rid in REQUIREMENTS}
    for record in records:
        by_requirement[record["requirement_id"]].append(record)
    with (run / "requirements.csv").open("x", encoding="utf-8-sig", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["requirement_id", "campaign_status", "commit_sha", "source_sha256",
                         "catalog_complete", "planned_scenarios", *STATES])
        for rid, cases in by_requirement.items():
            counts = Counter(case["status"] for case in cases)
            status = aggregate(counts)
            if not meta["catalog_complete"]:
                status = "INCONCLUSIVE"
            writer.writerow([rid, status, meta.get("commit_sha"), meta.get("source_sha256"),
                             meta["catalog_complete"], len(cases) if meta["catalog_complete"] else "",
                             *(counts[s] if meta["catalog_complete"] else "" for s in STATES)])
    with (run / "scenarios.csv").open("x", encoding="utf-8-sig", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["requirement_id", "scenario_id", "status", "reason", "planned_vectors", "result_directory"])
        for row in records:
            relative = Path("scenarios") / row["scenario_id"]
            folder = run / relative
            folder.mkdir(parents=True, exist_ok=True)
            write_json(folder / "result.json", row)
            writer.writerow([row["requirement_id"], row["scenario_id"], row["status"], row["reason"],
                             len(row["planned_vectors"]), relative.as_posix()])
    totals = Counter(row["status"] for row in records)
    lines = [f"# Acceptance run {run.name}", "",
             f"- Campaign result: {meta['status']} ({meta['reason']})",
             f"- Source commit: {meta.get('commit_sha', 'unavailable')}",
             f"- Exit code: {meta['exit_code']}",
             f"- Selected: {len(meta['selected_scenarios'])} of {len(records)} discovered", "",
             "| Outcome | Scenarios |", "| --- | ---: |",
             *(f"| {state} | {totals[state]} |" for state in STATES), "",
             "[Requirements](requirements.csv) · [Scenarios](scenarios.csv) · [JUnit](junit.xml)", ""]
    if meta.get("setup_error"):
        lines += ["Campaign setup/provenance failed. See [failure details](failure.md).", ""]
    for row in records:
        if row["status"] in ("FAIL", "INCONCLUSIVE"):
            lines.append(f"- {row['status']} [{row['scenario_id']}](scenarios/{row['scenario_id']}/result.json) · {row['reason']}")
    write_text(run / "summary.md", "\n".join(lines) + "\n")
    write_json(run / "requirement-evidence.json", by_requirement)
    write_json(run / "discovery.json", {"catalog_complete": meta["catalog_complete"],
               "selected_scenarios": meta["selected_scenarios"],
               "discovered_scenarios": len(records), "bound_scenarios": meta.get("bound_scenarios")})
    junit = [(r["scenario_id"], r["status"], r["reason"]) for r in records]
    if meta.get("setup_error"):
        junit.append(("CAMPAIGN", "INCONCLUSIVE", meta["setup_error"]))
    write_junit(run / "junit.xml", junit)
    with (run / "diagnostics.jsonl").open("x", encoding="utf-8", newline="\n") as file:
        for record in records:
            for vector in record["vectors"]:
                timeline = (run / vector["artifact"]).with_name("timeline.jsonl")
                with timeline.open(encoding="utf-8") as events:
                    shutil.copyfileobj(events, file)
        file.write(json.dumps({"event_type": "campaign_outcome", "run_id": run.name, "utc": utc(),
                               "mono_ns": time.monotonic_ns(), "clock_id": "runner",
                               "commit_sha": meta.get("commit_sha"), "seed": meta["seed"],
                               "status": meta["status"], "reason": meta["reason"]}) + "\n")
    if meta["status"] != "PASS":
        write_text(run / "failure.md", f"# Campaign {run.name}\n\n{meta['status']} · {meta['reason']}\n\n"
                   "See `requirements.csv`, `requirement-evidence.json` and `diagnostics.jsonl`.\n\n"
                   f"```powershell\n{meta['reproduction']}\n```\n")
    write_json(run / "run.json", meta)
    hashes = {path.relative_to(run).as_posix(): sha256(path) for path in sorted(run.rglob("*")) if path.is_file()}
    write_json(run / "sealed.json", {"schema_version": 1, "sealed_utc": utc(), "sha256": hashes})


def choose(rows, fixtures, args):
    require(not args.requirement or set(args.requirement) <= set(REQUIREMENTS), "UNKNOWN_REQUIREMENT")
    require(not args.scenario or args.scenario in rows, "UNKNOWN_SCENARIO")
    if args.vector:
        require(args.scenario and args.vector in vector_ids(fixtures, args.scenario), "UNKNOWN_VECTOR")
    if args.scenario:
        return {args.scenario}
    if args.requirement:
        return {sid for sid, row in rows.items() if row["requirement_id"] in args.requirement}
    return set(rows) if args.all or args.list else set()


def vector_ids(fixtures, sid):
    return sorted(fixtures.get(sid, {"V1": None}), key=lambda vector: int(vector[1:]))


def error_code(error):
    if isinstance(error, InfraError):
        return str(error)
    return type(error).__name__.upper()


def options():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--list", action="store_true")
    filters = parser.add_mutually_exclusive_group()
    filters.add_argument("--all", action="store_true")
    filters.add_argument("--requirement", action="append")
    filters.add_argument("--scenario")
    parser.add_argument("--vector")
    parser.add_argument("--continue-on-failure", action="store_true")
    parser.add_argument("--seed", type=int, default=1741815)
    for flag in ("--config", "--artifact-root", "--build-receipt"):
        parser.add_argument(flag, type=Path)
    args = parser.parse_args()
    if not any((args.build, args.list, args.all, args.requirement, args.scenario)):
        args.list = True
    if not 0 <= args.seed <= 0xFFFFFFFF or args.vector and not args.scenario:
        parser.error("use a uint32 seed; --vector requires --scenario")
    if args.build and (args.list or args.build_receipt):
        parser.error("--build cannot be combined with --list or --build-receipt")
    return args


def campaign_reproduction(args, root, receipt=None):
    command = ["&", quote_ps(REPO / "tools/run-acceptance.ps1"), "-Seed", str(args.seed),
               "-ArtifactRoot", quote_ps(root), "-Python", quote_ps(sys.executable)]
    if args.build and receipt is None:
        command.append("-Build")
    if args.all:
        command.append("-All")
    if args.requirement and set(args.requirement) <= set(REQUIREMENTS):
        command.extend(("-Requirement", ",".join(map(quote_ps, args.requirement))))
    scenario = args.scenario if args.scenario and SCENARIO_ID.fullmatch(args.scenario) else None
    vector = args.vector if scenario and args.vector and re.fullmatch(r"V[1-9][0-9]*", args.vector) else None
    for flag, value in (("-Scenario", scenario), ("-Vector", vector),
                        ("-Config", args.config), ("-BuildReceipt", receipt)):
        if value:
            command.extend((flag, quote_ps(Path(value).resolve() if isinstance(value, Path) else value)))
    if args.continue_on_failure:
        command.append("-ContinueOnFailure")
    return " ".join(command)


def main():
    args = options()
    if args.list:
        try:
            rows, fixtures, bindings = load_catalog()
            selected = choose(rows, fixtures, args)
        except (InfraError, OSError, ValueError, TypeError, RecursionError) as exc:
            print(f"Discovery failed: {error_code(exc)}", file=sys.stderr)
            return 2
        for sid in sorted(selected):
            state = "REGISTERED" if sid in bindings else "NOT_RUN"
            for vector in ([args.vector] if args.vector else vector_ids(fixtures, sid)):
                has_fixture = vector in fixtures.get(sid, {})
                print(f"{sid}/{vector}\t{state}\t{rows[sid]['gate']}\t{'golden' if has_fixture else 'planned'}")
        print(f"{len(selected)} selected scenarios; {len(rows)} total; {len(bindings)} bound.")
        return 0

    started = utc()
    reason = None
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex
    try:
        root = external(args.artifact_root or default_root())
        run = root / run_id
        run.mkdir(parents=True)
    except (InfraError, OSError) as exc:
        reason = error_code(exc)
        try:
            root = external(default_root())
            run = root / run_id
            run.mkdir(parents=True)
        except (InfraError, OSError):
            print("Cannot allocate an external evidence directory.", file=sys.stderr)
            return 2
    print(f"Evidence: {run}", flush=True)
    records = []
    selected = set()
    identity = {}
    meta = {"schema_version": 1, "run_id": run.name, "started_utc": started, "seed": args.seed,
            "catalog_complete": False, "python_version": sys.version.split()[0]}
    rows, fixtures, bindings = {}, {}, {}
    receipt = args.build_receipt
    env = {key: value for key, value in os.environ.items() if not key.startswith("DNP3_ACCEPTANCE_")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    stop = False
    try:
        rows, fixtures, bindings = load_catalog()
        meta.update(catalog_complete=True, matrix_sha256=sha256(MATRIX), registry_sha256=sha256(REGISTRY),
                    bound_scenarios=len(bindings))
        selected = choose(rows, fixtures, args)
        require(reason is None, reason)
        identity = source_identity()
        meta.update(identity)
        settings = config(args.config)
        meta["configuration"] = settings["configuration"]
        if args.config:
            meta["config_sha256"] = sha256(args.config)
        if args.build or (receipt is None and any(sid in bindings for sid in selected)):
            receipt = build_native(run, identity, settings, env)
        binaries = None
        if receipt:
            binaries = receipt_data(receipt, identity, settings)
            meta["build_receipt_sha256"] = sha256(receipt)
            meta["binary_sha256"] = {kind: sha256(file) for kind, file in binaries.items()}
        for sid in sorted(selected, key=lambda item: (rows[item]["priority"], item)):
            row = rows[sid]
            vectors = []
            ids = [args.vector] if args.vector else vector_ids(fixtures, sid)
            for vector in ids:
                item = execute_vector(row, vector, fixtures.get(sid, {}).get(vector), bindings.get(sid),
                                      args=args, run=run, root=root, identity=identity, receipt=receipt,
                                      binaries=binaries, binary_hashes=meta.get("binary_sha256", {}),
                                      settings=settings, env=env)
                vectors.append(item)
                if item["interrupted"] or item["status"] in ("FAIL", "INCONCLUSIVE") and not args.continue_on_failure:
                    stop = True
                    break
            status = aggregate([item["status"] for item in vectors] +
                               (["NOT_RUN"] if len(vectors) != len(vector_ids(fixtures, sid)) else []))
            why = next((item["reason"] for item in vectors if item["status"] == status), "VECTORS_NOT_RUN")
            records.append({"scenario_id": sid, "requirement_id": row["requirement_id"], "status": status,
                            "reason": why, "vectors": vectors, "planned_vectors": vector_ids(fixtures, sid)})
            if stop:
                break
        if binaries and source_identity() != identity:
            reason = "SOURCE_CHANGED_DURING_CAMPAIGN"
            for record in records:
                if record["status"] in ("PASS", "FAIL"):
                    record.update(status="INCONCLUSIVE", reason=reason)
    except KeyboardInterrupt:
        reason = "INTERRUPTED"
    except (InfraError, OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError) as exc:
        reason = error_code(exc)

    seen = {r["scenario_id"] for r in records}
    for sid, row in rows.items():
        if sid not in seen:
            blocked = sid in selected and not row["gate"].startswith("HOST")
            skip = row["gate"] if blocked else (
                ("FAIL_FAST" if stop else "CAMPAIGN_SETUP_FAILED") if sid in selected else "NOT_SELECTED")
            records.append({"scenario_id": sid, "requirement_id": row["requirement_id"],
                            "status": "BLOCKED" if blocked else "NOT_RUN",
                            "reason": skip, "vectors": [], "planned_vectors": vector_ids(fixtures, sid)})
    selected_records = [r for r in records if r["scenario_id"] in selected]
    counts = Counter(r["status"] for r in selected_records)
    if reason:
        code, status = 2, "INCONCLUSIVE"
    elif counts["FAIL"]:
        code, status = 1, "FAIL"
    elif counts["INCONCLUSIVE"]:
        code, status = 2, "INCONCLUSIVE"
    elif counts["NOT_RUN"] or counts["BLOCKED"] and (not args.all or not counts["PASS"]):
        code, status = 3, "NOT_RUN" if counts["NOT_RUN"] else "BLOCKED"
    elif selected_records or args.build:
        code, status = 0, "PASS" if selected_records else "BUILD_ONLY"
    else:
        code, status = 3, "NOT_RUN"
    meta.update(finished_utc=utc(), status=status, reason=reason or status, setup_error=reason,
                exit_code=code, counts=dict(counts),
                selected_scenarios=sorted(selected),
                reproduction=campaign_reproduction(args, root, receipt))
    finalize(run, records, meta)
    print(f"{status}: {len(selected)} selected. Summary: {run / 'summary.md'}")
    return code


if __name__ == "__main__":
    sys.exit(main())
