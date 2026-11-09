"""Infrastructure contract checks only; no native tests or network required."""

import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

from RunDnp3Acceptance import Evidence, REQUIREMENTS, aggregate, load_catalog, vector_ids
from acceptance_process import ProcessResult, run_child


class CatalogTests(unittest.TestCase):
    def test_catalog_has_exact_scope_and_expected_execution_routes(self):
        rows, fixtures, bindings = load_catalog()
        self.assertEqual(len(rows), 448)
        self.assertEqual({row["requirement_id"] for row in rows.values()}, set(REQUIREMENTS))
        self.assertEqual(bindings["AT-PROFILE-003-RD00"], {"kind": "unit", "vectors": ["V1", "V2"]})
        self.assertEqual(bindings["AT-CFG-13-COMPAT"], {"kind": "process", "vectors": ["V1"]})
        self.assertNotIn("AT-PROFILE-003-AS00", bindings)
        self.assertNotIn("AT-CFG-09-PULSE-ON", bindings)
        self.assertEqual(vector_ids(fixtures, "AT-PROFILE-038-EDGE"), ["V1", "V2"])

    def test_not_run_campaign_is_sealed_and_keeps_all_requirements(self):
        with tempfile.TemporaryDirectory(prefix="dnp3-acceptance-infra-") as folder:
            root = Path(folder) / "runs with spaces"
            args = [sys.executable, "-B", str(TOOLS / "RunDnp3Acceptance.py"), "--scenario",
                    "AT-PROFILE-003-AS00", "--seed", "9", "--artifact-root", str(root)]
            for _ in range(2):
                result = subprocess.run(args, timeout=30, capture_output=True, check=False)
                self.assertEqual(result.returncode, 3, result.stderr.decode(errors="replace"))
            runs = list(root.iterdir())
            self.assertEqual(len(runs), 2)
            for run in runs:
                with (run / "requirements.csv").open(encoding="utf-8-sig", newline="") as file:
                    summary = list(csv.DictReader(file))
                self.assertEqual(len(summary), 54)
                with (run / "scenarios.csv").open(encoding="utf-8-sig", newline="") as file:
                    self.assertEqual(len(list(csv.DictReader(file))), 448)
                self.assertTrue((run / "summary.md").is_file())
                self.assertTrue(all(row["campaign_status"] == "NOT_RUN" for row in summary))
                report = json.loads((run / "scenarios/AT-PROFILE-003-AS00/V1/scenario.json").read_text(encoding="utf-8"))
                self.assertEqual(report["status"], "NOT_RUN")
                self.assertIn("-Seed 9", report["reproduction"])
                seal = json.loads((run / "sealed.json").read_text(encoding="utf-8"))
                self.assertIn("requirements.csv", seal["sha256"])

    def test_external_gate_is_blocked_without_binding_or_pass(self):
        with tempfile.TemporaryDirectory(prefix="dnp3-acceptance-infra-") as folder:
            root = Path(folder) / "runs"
            result = subprocess.run([sys.executable, "-B", str(TOOLS / "RunDnp3Acceptance.py"),
                                     "--scenario", "AT-CFG-09-PULSE-ON", "--artifact-root", str(root)],
                                    timeout=30, capture_output=True, check=False)
            self.assertEqual(result.returncode, 3)
            run, = root.iterdir()
            path = run / "scenarios/AT-CFG-09-PULSE-ON/V1/scenario.json"
            row = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual((row["status"], row["reason"]), ("BLOCKED", "EXTERNAL_POLICY"))

    def test_aggregate_preserves_pending_vectors_and_failure_precedence(self):
        self.assertEqual(aggregate(["PASS", "NOT_RUN"]), "NOT_RUN")
        self.assertEqual(aggregate(["PASS", "BLOCKED"]), "BLOCKED")
        self.assertEqual(aggregate(["INCONCLUSIVE", "FAIL"]), "FAIL")

    def test_bad_config_seals_a_full_summary(self):
        with tempfile.TemporaryDirectory(prefix="dnp3-acceptance-infra-") as folder:
            root = Path(folder) / "runs"
            bad = Path(folder) / "bad.json"
            bad.write_text('{"bogus":"TEST_SECRET_MARKER"}', encoding="utf-8")
            result = subprocess.run([sys.executable, "-B", str(TOOLS / "RunDnp3Acceptance.py"),
                                     "--all", "--artifact-root", str(root), "--config", str(bad)],
                                    timeout=30, capture_output=True, check=False)
            self.assertEqual(result.returncode, 2)
            run, = root.iterdir()
            run_data = (run / "run.json").read_text(encoding="utf-8")
            self.assertIn("INVALID_CONFIG_FIELDS", run_data)
            self.assertNotIn("TEST_SECRET_MARKER", run_data)
            with (run / "requirements.csv").open(encoding="utf-8-sig", newline="") as file:
                self.assertEqual(len(list(csv.DictReader(file))), 54)


class EvidenceTests(unittest.TestCase):
    def evidence(self, folder):
        return Evidence(Path(folder), {"scenario_id": "synthetic"},
                        {"checks": [["field", "wire", "PARSER", "OUTSTATION", 7, 0, 255]]})

    def test_checked_projection_pass_and_first_divergence(self):
        for value, expected in ((7, "PASS"), (8, "FAIL")):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as folder:
                journal = self.evidence(folder)
                journal.observe(b'ignored raw password: TEST_SECRET_MARKER')
                journal.observe(b'DNP3-ACCEPTANCE ' + json.dumps({"check": "field", "value": value}).encode())
                self.assertEqual(journal.result(ProcessResult(0, False, 0, 0))[0], expected)
                wire = (Path(folder) / "public-wire.jsonl").read_text(encoding="utf-8")
                self.assertNotIn("TEST_SECRET_MARKER", wire)
                if expected == "FAIL":
                    self.assertEqual(journal.first["observed"], 8)
                    self.assertEqual(journal.first["expected"], 7)

    def test_secret_fields_and_duplicate_json_keys_are_never_persisted(self):
        for line in (
            b'DNP3-ACCEPTANCE {"check":"field","value":7,"secret":"TEST_SECRET_MARKER"}',
            b'DNP3-ACCEPTANCE {"check":"field","value":"TEST_SECRET_MARKER","value":7}',
        ):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as folder:
                journal = self.evidence(folder)
                journal.observe(line)
                self.assertEqual(journal.result(ProcessResult(0, False, 0, 0))[0], "INCONCLUSIVE")
                output = (Path(folder) / "timeline.jsonl").read_text(encoding="utf-8")
                self.assertNotIn("TEST_SECRET_MARKER", output)
                self.assertIn("invalid_observation", output)

    def test_zero_exit_without_observations_never_passes(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(self.evidence(folder).result(ProcessResult(0, False, 0, 0))[0], "INCONCLUSIVE")

    def test_timeout_and_abnormal_exit_keep_prior_observations(self):
        for tail, timeout, timed_out in (("time.sleep(60)", 3, True), ("os._exit(125)", 10, False)):
            with self.subTest(tail=tail), tempfile.TemporaryDirectory() as folder:
                journal = self.evidence(folder)
                code = ("import os,time,sys;"
                        "print('DNP3-ACCEPTANCE {\"check\":\"field\",\"value\":7}',flush=True);"
                        "print('TEST_SECRET_MARKER',file=sys.stderr,flush=True);" + tail)
                result = run_child([sys.executable, "-c", code], cwd=folder, env=os.environ.copy(),
                                   timeout=timeout, on_stdout=journal.observe)
                self.assertEqual(result.timed_out, timed_out)
                self.assertEqual(journal.result(result)[0], "INCONCLUSIVE")
                self.assertGreater(result.stderr_bytes, 0)
                self.assertEqual(journal.next_check, 1)
                output = (Path(folder) / "timeline.jsonl").read_text(encoding="utf-8")
                self.assertNotIn("TEST_SECRET_MARKER", output)
