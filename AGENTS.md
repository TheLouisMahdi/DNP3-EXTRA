# DNP3-EXTRA engineering rules

## Objective and authority
Implement the applicable selections in the supplied RTU Device Profile and minimum security addendum. Use `DNP3_PDD_PLAN/DNP3_IEEE1815_IMPLEMENTATION_REFERENCE.xlsx` as the canonical source for requirements, decisions, implementation status and verification evidence. Filter `IMPLEMENTATION_INDEX` by ID, then read its linked `WIRE_PROCEDURES` and `OPEN_DECISIONS`. Open only the cited PDF pages needed to resolve a source question. The target is Level 3 Outstation with explicit extensions, runtime settings and SA v5. IEEE 1815-2012 governs correct protocol behavior. General Level 4 expansion requires explicit authorization.

## Start and navigation
Read this file and `REPO_MAP.md`. Check Git root, branch, HEAD and local changes once. The workspace root owns Git, and `opendnp3/` is the library subtree. Preserve unrelated work. Navigate directly to relevant files. Batch tool discovery once, reuse installed tools and project-pinned dependencies, and keep output concise.

## Implementation
- Preserve native OpenDNP3 architecture and existing Master/Outstation functionality. Map exact selected PDF functions, qualifiers, role obligations and applicable IEEE clauses before editing.
- Keep optional Master issuance separate unless required for selected functionality or explicitly requested.
- Reuse public APIs, generators, shared parsers/serializers, database/event infrastructure and dedicated state machines. Contexts orchestrate components.
- Scala models are the source of truth for generated objects/enums. Regenerate corresponding outputs and report any synchronization limitation.
- Keep portable protocol code independent of Windows and STM32 hardware adapters. Avoid unrelated refactors and dependencies.
- Fail closed for unauthenticated or unauthorized critical operations. Validate association, user, sequence, ownership, deadlines, keys, MAC and replay state. Preserve pending exchanges, borrowed transmit buffers and key erasure.
- Preserve provisional G120V7 Code 5/7 interpretation and unresolved P4-OPEN-01. Never advertise unverified SA capability.

## Verification and delivery
- Add permanent positive, negative, boundary and appropriate wire-level tests for each new behavior. Reuse existing unit/integration fixtures and process tests. Never alter application main files as temporary tests.
- Build and execute tests only when authorized by the current task. Use the smallest relevant targets first. See README.md and cli/README.md for commands. Do not retry failures without diagnosis.
- Inspect the complete scoped diff and run `git -c core.whitespace=cr-at-eol diff --check`. Record implementation and evidence status only in the workbook, including tested SHA, exact commands and wire/receiver observations. Static review and codec tests cannot establish runtime or independent-peer conformance. Keep STM32H743/FreeRTOS acceptance deferred until target integration.
- For completed, verified source changes, stage only reviewed task files, commit clearly and push to origin/develop when authorized. Verify the remote tip. Preserve local commits and report PUSH_FAILED if needed.
- Explicit task restrictions override this workflow. Never commit secrets, reference PDFs, binaries or temporary outputs. Never force push or destructively reset/clean the workspace.
