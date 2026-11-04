# DNP3-EXTRA project rules

## 1. Existing project rules (preserved)

- Preserve the OpenDNP3 architecture.
- Reuse existing implementations before extending them.
- Minimize unnecessary changes and never modify unrelated files.
- Keep support for both Master and Outstation.
- Use permanent tests; do not use temporary application main.cpp changes as test harnesses.
- Review Git diffs before staging and stage only relevant, safe files.
- Commit completed, verified changes with descriptive messages and push to origin/develop after every source-changing task.
- Do not push failed changes to main. Preserve failed work locally or on an explicitly labeled WIP branch.
- Never commit secrets, compiled binaries, or unauthorized documents.
- Never force-push or rewrite history.
- Report commit SHA, branch, test results, and push status in the final report.
- Verify the remote branch before reporting a successful push.
- Preserve local commits and report PUSH_FAILED if authentication or networking fails.
- Read-only tasks must not create empty commits.

**Instruction precedence:** An explicit instruction in the current task, such as `do not commit or push`, `review only`, or `wait for approval`, overrides the default commit/push workflow above. Never claim that static review is equivalent to a successful build or runtime test.

## 2. Mandatory start of every task

1. Read this `AGENTS.md` before investigation, editing, or implementation. Also follow any more-specific `AGENTS.md` applying to the files in scope.
2. Read `REPO_MAP.md`. Navigate directly to the relevant components rather than performing unnecessary repository-wide scans.
3. Check the actual Git root, current branch, HEAD, and staged/unstaged/untracked changes. The workspace root is the Git repository. `opendnp3/` is the library subtree. Never overwrite another task's changes.
4. Identify the requested scope and whether it is read-only, implementation, review, or Git-only. Do not expand scope silently.
5. Before implementing a DNP3 feature, locate the actual applicable IEEE 1815 requirements and inspect the corresponding native OpenDNP3 implementation path.

## 3. Standards authority and development order

**IEEE 1815 defines the protocol. OpenDNP3 defines the project's native software architecture.** Third-party implementations are secondary evidence for resolving ambiguities, not replacements for IEEE requirements.

For each assigned feature, object group, variation, security procedure, or command:

1. **IEEE first:** Read the relevant clauses, annexes, tables, formal object definitions, state diagrams, qualifiers, function codes, field encodings, sequence rules, timeouts, error handling, and role-specific requirements from the available `IEEE 1815/` PDFs. Record precise section/table references and printed page numbers where available.
2. **Applicability:** Distinguish mandatory, conditional, optional, obsolete, and not-applicable requirements. Cross-check the project's Device Profile and security requirements. Do not assume an optional IEEE feature is mandatory unless the selected profile or project scope requires it.
3. **Existing code:** Trace the specific feature through Scala generator definitions, generated objects/enums, application parsing and serialization, Master/Outstation dispatch, state machines, configuration, and tests. Classify support as implemented, partial, missing, or not applicable from source evidence.
4. **Native extension:** Reuse correct existing components. Extend an incomplete component, or create a missing component in the corresponding OpenDNP3 layer. Add the necessary types, classes, state, APIs, and tests when IEEE behavior requires them; do not stop merely because the upstream project does not implement a feature.
5. **Related IEEE clauses:** Read all relevant cross-references before resolving conflicting wording. Document a provisional decision and its supporting clauses if ambiguity remains. Verify interpretation later with independent implementations and the Triangle MicroWorks DNP3 Test Harness.
6. **Validation:** Add focused permanent protocol tests now. Execute builds, tests, and independent interoperability checks only in the explicitly authorized validation phase (currently P10).

Reference matrices and planning documents are navigation aids, **not proof that a feature is implemented or conformant**.

## 4. Implement a complete object family in native OpenDNP3 style

Inspect a comparable existing group/variation before adding a new family. Follow its established end-to-end implementation path as applicable:

- **Scala source of truth:** `opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/groups/` contains object-family and variation models (for example `Group120.scala`). Inspect generator registrations, shared field definitions, object categories, and naming conventions.
- **Generated C++:** `opendnp3/cpp/lib/src/gen/objects/` and `opendnp3/cpp/lib/include/opendnp3/gen/` contain generated artifacts. Do not treat manually edited generated code as the source of truth. Update the Scala model and use the established generation workflow so source and outputs stay synchronized. If generation is unavailable, state this limitation precisely; do not claim regenerated files were verified.
- **Shared APDU code:** `opendnp3/cpp/lib/src/app/` and `app/parsing/` own object headers, qualifiers, parsing, serialization, response writing, validation, and dispatch. Reuse these facilities instead of introducing a parallel parser/serializer.
- **Master:** `opendnp3/cpp/lib/src/master/` owns Master task scheduling, requests, replies, timeouts, and Master-specific state transitions.
- **Outstation:** `opendnp3/cpp/lib/src/outstation/` owns request processing, command authorization, responses, data selection, security-statistic/event publication, and Outstation-specific state transitions.
- **Shared authentication:** `opendnp3/cpp/lib/src/auth/` owns reusable SA v5 exchanges, session keys, replay protections, ownership/correlation, and common security procedures.
- **Cryptography:** `opendnp3/cpp/lib/src/crypto/` owns MAC, key wrap, and cryptographic provider behavior. Do not duplicate cryptographic primitives elsewhere.
- **Public API:** `opendnp3/cpp/lib/include/opendnp3/` contains supported configuration and interfaces. Change only when functionality requires it, preserving source/API compatibility where feasible.
- **Tests:** `opendnp3/cpp/tests/unit/`, `integration/`, and existing mocks provide permanent tests. Include wire encoding/decoding, success, denial, malformed inputs, timeouts, replay, and lifecycle cases as applicable.

A feature is **not complete** just because a group codec, enum, handler branch, or context method exists. Implement the required end-to-end vertical slice for the applicable Master and Outstation roles. Conversely, do not force unrelated features into both roles when IEEE makes a behavior role-specific.

Avoid placing all logic for an entire family inside `MasterContext` or `OutstationContext` when existing dedicated modules should own it. Context classes should orchestrate the relevant components, not replace the native family architecture.

Keep OpenDNP3 namespace, header/source separation, naming, license headers, C++ conventions, error handling, buffer ownership, and bounded-memory practices. Keep common code portable for later STM32H743/FreeRTOS use. Avoid unrelated refactors, speculative abstractions, duplicate state machines, and new dependencies without a concrete need.

## 5. Secure Authentication v5 safety and correctness

- Preserve separation among authentication, authorization, MAC-algorithm negotiation, and key management. Never map unrelated security failures to the same wire error code.
- Validate actual association, user, CSQ/KSQ, pending exchange, deadlines, key readiness, MAC, and replay state. Do not invent exchange identifiers or silently reuse invalid keys.
- Reject unauthenticated or unauthorized critical operations. No fallback may bypass security or execute an unverified command.
- Preserve independently owned exchanges, in-flight transmission buffers, application CONFIRMs, retries, disconnect handling, and key erasure.
- Implement and enforce IEEE-defined security error suppression and rate/quantity limits.
- For the current provisional P4 interpretation, follow Annex A.45.7.2.2: G120V7 Code 5 = MAC Algorithm Not Supported; Code 7 = Authorization Failed. Track the conflict with IEEE 1815-2012 section 7.5.5.7 as `P4-OPEN-01`. Keep the issue open until an authoritative correction or independent SA v5 interoperability test resolves it. Do not misrepresent this as an official IEEE erratum.

## 6. Tests, changes, and Git workflow

- Make the smallest complete, maintainable change that satisfies the assigned IEEE requirement. Do not alter unrelated files or weaken existing behavior to satisfy a test.
- Add permanent focused tests with realistic wire messages and negative cases. Do not modify application `main.cpp` files as temporary test drivers.
- Until authorized P10, do not run builds, test executables, broad formatting, or full test suites. A necessary generator run is separate from a C++ build and must be reported accurately.
- Perform a scoped static review, inspect the complete diff, and run `git diff --check` for changed files. Clearly label test code as written but **NOT RUN**.
- Respect the existing commit/push rule in section 1 for completed and sufficiently reviewed work, unless the current task instructs otherwise. Never commit unfinished, known-broken, or unrelated work. Before committing, stage only task-specific files and inspect the staged diff. Push to `origin/develop` only when permitted and verify the remote result.
- Do not commit local IEEE reference PDFs, credentials, secrets, compiled artifacts, or unauthorized documents. Never force-push, rewrite history, or silently modify Git exclusion settings.

## 7. Required final report

Keep the report concise and evidence-based. Include:

1. The implemented requirement, relevant IEEE sections/tables, and Device Profile applicability.
2. Master and Outstation responsibilities, existing modules reused, and missing modules added.
3. Exact modified paths and any generated-source/output synchronization.
4. Permanent test cases written, static-review findings, and remaining limitations or unresolved standards ambiguities.
5. `git diff --check` result and explicit `NOT BUILT / NOT TESTED` status until P10.
6. Git root, branch, HEAD/commit SHA, staged/commit/push status, and remote verification or `PUSH_FAILED` when applicable.

Never assert full IEEE 1815, Level 4, SA v5, or Test Harness conformance without the corresponding completed validation evidence.
