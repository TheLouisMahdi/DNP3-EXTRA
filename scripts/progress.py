"""Build the private repository's requirements dashboard from the audit matrices."""

import argparse
from collections import Counter
import csv
from datetime import date
from html import escape
import json
from pathlib import Path
import re
import subprocess
import sys
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "DNP3_PDD_PLAN"
SOURCE_PATHS = ("opendnp3", "apps", "cli", "CMakeLists.txt", ":(exclude,glob)**/*.md")
STATUSES = {
    "VERIFIED": ("Verified", "#52d39b"),
    "IMPLEMENTED_NOT_VERIFIED": ("Implemented, unverified", "#55c9ee"),
    "PARTIAL": ("Partial", "#ffc465"),
    "NOT_IMPLEMENTED": ("Missing", "#f38d91"),
    "NOT_AUDITED": ("Not audited", "#8191a8"),
    "NOT_APPLICABLE": ("Not applicable", "#b9bfd1"),
    "BLOCKED": ("Blocked", "#cc9af2"),
}
COMPLETE = {"VERIFIED", "IMPLEMENTED_NOT_VERIFIED"}
CLASSIFICATIONS = {"MANDATORY", "RECOMMENDED", "OPTIONAL", "UNRESOLVED"}
ROLES = ("outstation_status", "master_status")
COMMON = set("requirement_id classification applicability master_status outstation_status "
             "evidence execution_evidence open_issues last_verified_revision".split())
PROFILE = set("profile_pdf_page group_decimal variation_decimal description "
              "request_function_codes_decimal request_qualifiers_hex response_function_codes_decimal "
              "response_qualifiers_hex family notes local_code_status".split())
START, END = "<!-- progress:start -->", "<!-- progress:end -->"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def link(value):
    path = Path(value)
    require(not path.is_absolute() and ".." not in path.parts
            and (ROOT / path).resolve().is_relative_to(ROOT)
            and (ROOT / path).is_file() and path.suffix.lower() != ".pdf",
            f"Invalid repository evidence link: {value}")


def load_rows(filename, fields, prefix, outcome, issues):
    with (PLAN / filename).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames and len(reader.fieldnames) == len(fields)
                and set(reader.fieldnames) == fields, f"{filename}: unexpected schema")
        rows = list(reader)
    ids = set()
    for row in rows:
        key = row["requirement_id"]
        require(re.fullmatch(prefix + r"-[A-Z0-9-]+", key) and key not in ids,
                f"{filename}: invalid or repeated ID {key}")
        ids.add(key)
        require(None not in row and None not in row.values(), f"{key}: malformed CSV row")
        require(row["classification"] in CLASSIFICATIONS and row["applicability"],
                f"{key}: missing classification/applicability")
        require(all(row[role] in STATUSES for role in ROLES)
                and row[outcome] == row["outstation_status"], f"{key}: inconsistent status")
        if any(row[role] == "NOT_APPLICABLE" for role in ROLES):
            require("excluded because" in row["applicability"], f"{key}: missing exclusion rationale")
        for value in row["evidence"].split("|"):
            link(value)
        for value in filter(None, row["open_issues"].split("|")):
            require(value in issues, f"{key}: undocumented issue {value}")
        if any(row[role] == "VERIFIED" for role in ROLES):
            require(row["execution_evidence"] and re.fullmatch(r"[0-9a-f]{40}", row["last_verified_revision"]),
                    f"{key}: VERIFIED requires executed evidence and tested SHA")
            link(row["execution_evidence"])
    return rows


def counts(rows, role):
    return Counter(row[role] for row in rows)


def mandatory(rows, role):
    return [row for row in rows if row["classification"] == "MANDATORY"
            and row[role] != "NOT_APPLICABLE"]


def metric(numerator, denominator):
    if denominator == 0:
        return "No applicable rows"
    # Integer hundredths of a percent, rounded half up.
    hundredths = (20000 * numerator + denominator) // (2 * denominator)
    return f"{hundredths // 100}.{hundredths % 100:02}% ({numerator}/{denominator})"


def metrics(rows, role):
    selected = mandatory(rows, role)
    tally = counts(selected, role)
    return (metric(tally["VERIFIED"], len(selected)),
            metric(sum(tally[key] for key in COMPLETE), len(selected)))


def issue_count(rows):
    return len({issue for row in rows for issue in row["open_issues"].split("|") if issue})


def svg(title, rows, evidence, ieee):
    width = 700
    selected = rows if ieee else mandatory(rows, ROLES[0])
    tally = counts(selected, ROLES[0])
    if ieee:
        primary = "AUDIT IN PROGRESS"
        secondary = f"{len(rows)} provisional work packages | Level 4 obligations still being enumerated"
    else:
        verified, implemented = metrics(rows, ROLES[0])
        primary = f"Verified {verified}"
        secondary = f"Implementation coverage {implemented}"
    context = f"Evidence {evidence['tested_revision'][:12]} | {issue_count(rows)} open issue IDs"
    desc = f"{primary}. {secondary}. {context}. " + ", ".join(
        f"{label}: {tally[key]}" for key, (label, _) in STATUSES.items())
    result = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} 165" role="img" aria-labelledby="title desc">',
        f'<title id="title">{escape(title)}</title>',
        f'<desc id="desc">{escape(desc)}</desc>',
        '<rect width="700" height="165" rx="14" fill="#101b2d"/>',
        '<g font-family="system-ui, sans-serif" fill="#f1f6ff">',
        f'<text x="22" y="30" font-size="22" font-weight="700">{escape(title)}</text>',
        f'<text x="22" y="63" font-size="25" font-weight="700">{escape(primary)}</text>',
        f'<text x="22" y="91" font-size="17">{escape(secondary)}</text>',
        f'<text x="22" y="150" font-size="16" fill="#bdcce2">{escape(context)}</text>',
        '</g>',
        '<rect x="22" y="106" width="656" height="22" rx="5" fill="#34425a"/>',
    ]
    if not ieee and selected:
        cumulative = 0
        for key, (_, color) in STATUSES.items():
            start = 22 + 656 * cumulative // len(selected)
            cumulative += tally[key]
            end = 22 + 656 * cumulative // len(selected)
            if end > start:
                result.append(f'<rect x="{start}" y="106" width="{end-start}" height="22" fill="{color}"/>')
    result.append("</svg>")
    output = "\n".join(result) + "\n"
    ElementTree.fromstring(output)
    return output


def dashboard(scopes, evidence, latest, fresh, tested_current):
    lines = []
    for slug, title, rows in scopes:
        ieee = slug == "ieee"
        verified, implemented = metrics(rows, ROLES[0])
        alt = "Audit in progress" if ieee else f"Verified {verified}, implementation coverage {implemented}"
        lines.append(f"![{title}. {alt}.](DNP3_PDD_PLAN/progress-{slug}.svg)")
        lines.append("")
    lines += [
        "| Scope | Verified | Implemented, unverified | Partial | Missing | Not audited | Not applicable | Blocked |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for slug, title, rows in scopes:
        for role in ROLES:
            label = f"{title} / {role.split('_')[0].title()}"
            tally = counts(rows, role)
            lines.append(f"| {label} | " + " | ".join(str(tally[key]) for key in STATUSES) + " |")
    lines += ["", "| Role and scope | Strict verified | Implementation coverage | Open issue IDs |",
              "| --- | --- | --- | ---: |"]
    for slug, title, rows in scopes:
        for role in ROLES:
            verified, implemented = metrics(rows, role)
            if slug == "ieee":
                verified = implemented = "AUDIT IN PROGRESS"
            excluded = counts(rows, role)["NOT_APPLICABLE"]
            label = f"{title} / {role.split('_')[0].title()}"
            if excluded:
                label += f" ({excluded} not applicable)"
            lines.append(f"| {label} | {verified} | {implemented} | {issue_count(rows)} |")
    profile_sa = [row for row in scopes[1][2] if row["group_decimal"] == "120"]
    for role in ROLES:
        verified, implemented = metrics(profile_sa, role)
        lines.append(f"| Profile G120 / {role.split('_')[0].title()} | {verified} | {implemented} | {issue_count(profile_sa)} |")
    security = scopes[2][2]
    for kind in ("RECOMMENDED", "OPTIONAL", "UNRESOLVED"):
        tally = counts([row for row in security if row["classification"] == kind], ROLES[0])
        details = ", ".join(f"{tally[key]} {label.lower()}" for key, (label, _) in STATUSES.items() if tally[key])
        lines.append(f"| Security {kind.lower()} rows | {details or '0 rows'} | Excluded from mandatory metrics | — |")
    lines += [
        "",
        "Bar order: verified (green), implemented without verification (cyan), partial (amber), missing (red), not audited (slate), blocked (violet).",
        "",
        f"Latest tracked source commit **{latest}**. Audit revision **{evidence['audit_revision']}**.",
        f"Last tested revision **{evidence['tested_revision']}** on {evidence['date']} ({evidence['platform']}).",
        f"Unit **{evidence['unit'][0]} cases / {evidence['unit'][1]:,} assertions**. "
        f"Integration **{evidence['integration'][0]} cases / {evidence['integration'][1]:,} assertions**, including SA TCP. "
        f"[Execution evidence]({evidence['report']})",
        f"Historical SA TCP baseline **{evidence['sa_tcp_baseline']['cases']} cases / "
        f"{evidence['sa_tcp_baseline']['assertions']} assertions** at "
        f"`{evidence['sa_tcp_baseline']['revision']}`.",
        "",
        ("Windows execution evidence applies to the tracked source revision." if tested_current else
         "**Historical Windows test results.** The current source differs from the tested revision."),
    ]
    if not fresh:
        lines.append("**Audit refresh required.** Positive and partial assessments await review on this source revision.")
    lines += ["", "Outstation items awaiting audit:"]
    for _, title, rows in scopes:
        pending = [row["requirement_id"] for row in rows if row[ROLES[0]] == "NOT_AUDITED"]
        if len(pending) > 12:
            details = f"{len(pending)} rows or work packages. See the source matrices."
        else:
            details = ", ".join(f"`{key}`" for key in pending) if pending else "None within the listed rows"
        lines.append(f"- **{title}** — {details}")
    lines += ["", "[Formulas, evidence scope and open decisions](DNP3_PDD_PLAN/PROGRESS.md)"]
    return "\n".join(lines)


def generate():
    issues = set(re.findall(r"^\| ([A-Z0-9-]+) \|", (PLAN / "PROGRESS.md").read_text(encoding="utf-8"), re.M))
    ieee = load_rows("IEEE_TRACEABILITY.csv", COMMON | {"clause", "behavior", "outcome"},
                     "IEEE", "outcome", issues)
    require(ieee and all(row["clause"] and row["behavior"] for row in ieee), "Incomplete IEEE traceability")
    profile = load_rows("02_PROFILE_MATRIX.csv", COMMON | PROFILE, "PROFILE", "local_code_status", issues)
    require({row["requirement_id"] for row in profile} == {f"PROFILE-{n:03}" for n in range(1, 70)}
            and all(re.fullmatch(r"(?:[4-9]|1[0-2])(?:\|(?:[4-9]|1[0-2]))?", row["profile_pdf_page"])
                    and row["description"] for row in profile), "Profile must trace all 69 supplied rows")
    security = load_rows("SECURITY_PROGRESS.csv", COMMON | {"source_location", "outcome"},
                         "SEC", "outcome", issues)
    ids = re.findall(r"^\| (SEC-T[123]-\d\d) \|", (PLAN / "03_SECURITY_MATRIX.md").read_text(encoding="utf-8"), re.M)
    require(len(ids) == len(set(ids)) == 36 and set(ids) == {row["requirement_id"] for row in security}
            and all(row["source_location"] for row in security), "Security audit must match the three source tables")
    scopes = [("ieee", "IEEE 1815-2012", ieee), ("profile", "RTU Device Profile", profile),
              ("security", "RTU Security Requirements", security)]
    evidence = json.loads((PLAN / "PROGRESS_EVIDENCE.json").read_text(encoding="utf-8"))
    date.fromisoformat(evidence["date"])
    link(evidence["report"])
    for suite in ("unit", "integration"):
        totals = evidence[suite]
        require(isinstance(totals, list) and len(totals) == 2
                and all(type(value) is int and value > 0 for value in totals), f"Invalid {suite} totals")
    latest = git("log", "-1", "--format=%H", "--", *SOURCE_PATHS)
    dirty = bool(git("status", "--porcelain", "--untracked-files=normal", "--", *SOURCE_PATHS))
    for key in ("audit_revision", "tested_revision"):
        require(re.fullmatch(r"[0-9a-f]{40}", evidence[key]), f"Invalid {key}")
        git("merge-base", "--is-ancestor", evidence[key], "HEAD")
    fresh = not dirty and not git("diff", "--name-only", evidence["audit_revision"], "HEAD", "--", *SOURCE_PATHS)
    tested_current = not dirty and not git("diff", "--name-only", evidence["tested_revision"], "HEAD", "--", *SOURCE_PATHS)
    for _, _, rows in scopes:
        for row in rows:
            for role in ROLES:
                if not fresh and row[role] in COMPLETE | {"PARTIAL"}:
                    row[role] = "NOT_AUDITED"
                elif row[role] == "VERIFIED" and (
                    not tested_current or row["last_verified_revision"] != evidence["tested_revision"]
                ):
                    row[role] = "IMPLEMENTED_NOT_VERIFIED"
    readme = ROOT / "README.md"
    before = readme.read_text(encoding="utf-8")
    require(before.count(START) == before.count(END) == 1 and before.index(START) < before.index(END),
            "README must contain one ordered managed dashboard block")
    section = dashboard(scopes, evidence, latest + (" + local edits" if dirty else ""), fresh, tested_current)
    outputs = {readme: before.split(START, 1)[0] + START + "\n\n" + section + "\n\n" + END + before.split(END, 1)[1]}
    outputs.update({PLAN / f"progress-{slug}.svg": svg(title, rows, evidence, slug == "ieee")
                    for slug, title, rows in scopes})
    return outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Report drift without writing files")
    args = parser.parse_args()
    try:
        outputs = generate()
        stale = [path for path, content in outputs.items()
                 if not path.exists() or path.read_text(encoding="utf-8") != content]
        if args.check:
            require(not stale, "Generated output drift: " + ", ".join(str(path.relative_to(ROOT)) for path in stale))
        else:
            for path in stale:
                path.write_bytes(outputs[path].encode("utf-8"))
        print(f"Validated {len(outputs)} dashboard outputs; {len(stale)} changed.")
        return 0
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print(f"Dashboard error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
