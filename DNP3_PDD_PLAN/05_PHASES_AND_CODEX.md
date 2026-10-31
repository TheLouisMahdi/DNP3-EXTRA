# PDD development phases and narrow Codex handoff

**No code is authorized by this document.** Each numbered step is a future change request, not permission to execute all phases at once.

## Workflow for a single approved feature

`SPEC -> EXISTING CODE AUDIT -> MINIMAL OUTSTATION DIFF -> MINIMAL MASTER DIFF -> REQUESTED LOCAL VERIFICATION -> RECORD RESULT -> STOP`

- **SPEC:** Exact Group, Variation, function codes, qualifiers, index, type, error semantics, source PDF page(s).
- **AUDIT:** Check existing C++ implementation first: public model, generated object metadata, parser/writer, Outstation handler/database, Master parser/callback. Identify all reused functions and only the directly affected files.
- **OUTSTATION:** Localized change only; never create a second serializer, parser or database.
- **MASTER:** Only after Outstation behavior is established; reuse the same existing facilities.
- **VERIFY:** Execute only the specific verification requested for that implementation slice, including localhost connectivity where approved. No test frameworks, fixtures, mocks or scripts unless explicitly authorized.
- **RECORD:** Update status, source references, actual changed files, observed result, Windows-only vs portable code classification.
- **STOP:** No adjacent cleanup or speculative implementation.

## Phased backlog

| Phase | Narrow goal | Prerequisite / exit |
|---|---|---|
| P0 | Audit available *local* OpenDNP3 + existing STM32 integration, no code edit | Commit/revision, exact impacted paths, reuse map and API availability |
| P1.1 | **G0V209** Outstation READ at set index 0 | Actual supported SA version established; minimal diff scoped |
| P1.2 | **G0V209** Master explicit READ and decode | Only missing Master behavior; same slice's localhost verification |
| P1.3 | G0V254 / G0V255 discovery support as required for implemented Group 0 attributes | Explicit new approval; IEEE 5.5.2 compatibility gate |
| P2 | G0V210, then G121 and G122 when actual stats exist | Require real statistic data model, not fabricated values |
| P3 | Measurement and events from PROFILE matrix (G1/2/3/4/10/30/32/40) | For each entry first classify `already available` vs `missing`; implement only gaps |
| P4 | Control, time, classes and IIN (G12/41/50/51/52/60/80 and function-only operations) | Preserve existing application callbacks / interlocks, protocol semantics |
| P5 | SA v5 (G120V1-V15) and auth state machine | IEEE clause 7 + exact SEC parameters; independent per-message and stateful role review |
| P6 | TLS/credentials/platform-specific security and hardening | Exact SEC requirements and resolved TLS naming; Windows vs STM32 adapter separation |
| P7 | Optional Level 4 delta only if user authorizes its scope | Separate standard conformance assessment; not automatically included in supplied Level 3 PROFILE |

**Order exception:** G0V209 is prioritized for learning and narrow protocol support, but its *true SA-v5 reported value* cannot be finalized before SA v5 exists. That is an explicit dependency, not a reason to fake capability.

### Per-object task status (do not auto-advance)

`UNREVIEWED -> SOURCE_MAPPED -> CODE_AUDITED -> OUTSTATION_DONE -> MASTER_DONE -> VERIFIED -> CLOSED`

If a requirement is unsupported or unclear, use `BLOCKED` with a reason; if code already supports it, use `ALREADY_SUPPORTED` after audit. These are planning labels only.

## Read/class grouping rules

- A Class 0 READ (`G60V1`) selects eligible static point values from configured types; Class 1/2/3 (`G60V2/V3/V4`) read eligible queued events by class. They do **not** merge unrelated devices/attributes simply because several groups are present in the codebase.
- Explicit object READ can carry multiple request headers in one APDU using the existing header writer. Whether a particular object may be requested this way must be checked against its own function/qualifier rules.
- G0 attributes use attribute-set index semantics and special discovery variations. Do not register G0V209 in an ordinary measurement Class 0 scan.
- G120 authentication objects use security-specific procedures; do not process them via ordinary measurement SOE callbacks merely because they share the DNP3 object library.

## Portable-code rule

`C++ shared protocol behavior` is reusable; `Windows ASIO manager/sockets/threads` are not assumed MCU-portable. OpenDNP3 3.x hides ASIO from the public API but uses it in its runtime. Do not promise literal copy/paste of the complete Windows runtime to FreeRTOS without checking executor, time and I/O seams. Keep board dependencies outside shared protocol changes.

## One short Codex prompt for the *future* P0 audit

> Inspect the existing local OpenDNP3 C++ sources and any already-present STM32 adaptation. **Do not edit any file or run tests.** Identify exact revision, whether G0V209 READ is already supported, and the current source functions/files for: GroupVariation metadata and generation, attribute serialization/deserialization, Outstation READ dispatch, Master attribute decoding, and qualifier 0x00/0x17 support. Report only verified paths, reused functions, missing behavior, and obstacles. Follow `DNP3_PDD_PLAN/04_G0V209_CONTRACT.md`. Do not refactor, generate code, tests, or documentation.

**Why P0 matters:** The supplied ZIP has three PDFs, not the local C++ tree. Any attempt to specify exact edit locations before P0 would be guesswork.
