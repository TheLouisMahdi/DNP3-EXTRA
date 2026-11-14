# DNP3-EXTRA - Engineering Agent Contract and Completion Plan

> Consolidated from the repository's existing `AGENTS.md` and the extended Host-only security/configuration roadmap. Applies to the portable C++ Master and Outstation development in `TheLouisMahdi/DNP3-EXTRA`. This is a development policy and plan, not proof of implemented features or conformance. Verify the actual current `develop` revision before every task; never assume a recorded baseline SHA is still current.

## Existing repository rules: preserved and consolidated

The following directives preserve the substance and navigation structure of the existing `AGENTS.md` at the repository root, fetched from GitHub `develop` (Git blob `e675ec7963494f890551ca0e823f398521779e3d`). The extended sections below refine these directives without replacing the repository architecture. If two provisions appear inconsistent, resolve against the authoritative requirement sources and record an open decision; do not silently discard an existing constraint.

### Objective and authority

Implement the applicable selections in the supplied RTU Device Profile and minimum security addendum. Use `DNP3_PDD_PLAN/DNP3_IEEE1815_IMPLEMENTATION_REFERENCE.xlsx` as the canonical source for requirements, decisions, implementation status and verification evidence. Filter `IMPLEMENTATION_INDEX` by ID, then read its linked `WIRE_PROCEDURES` and `OPEN_DECISIONS`. Open only the cited PDF pages needed to resolve a source question. The contractual target is the Level 3 Outstation selections with explicit extensions, runtime settings and SA v5. IEEE 1815-2012 governs correct protocol behavior. General Level 4 expansion requires explicit authorization.

### Start and navigation

Read this file and `REPO_MAP.md`. Check Git root, branch, HEAD and local changes once. The workspace root owns Git, and `opendnp3/` is the library subtree. Preserve unrelated work. Navigate directly to relevant files. Batch tool discovery once, reuse installed tools and project-pinned dependencies, and keep output concise.

### Implementation

- Preserve native OpenDNP3 architecture and existing Master/Outstation functionality. Map exact selected PDF functions, qualifiers, role obligations and applicable IEEE clauses before editing.
- Keep optional Master issuance separate unless required for selected functionality or explicitly requested.
- Reuse public APIs, generators, shared parsers/serializers, database/event infrastructure and dedicated state machines. Contexts orchestrate components.
- Scala models are the source of truth for generated objects/enums. Regenerate corresponding outputs and report any synchronization limitation.
- Keep portable protocol code independent of Windows-specific adapters and implementation details. Avoid unrelated refactors and dependencies.
- Fail closed for unauthenticated or unauthorized critical operations. Validate association, user, sequence, ownership, deadlines, keys, MAC and replay state. Preserve pending exchanges, borrowed transmit buffers and key erasure.
- Preserve provisional G120V7 Code 5/7 interpretation and unresolved P4-OPEN-01. Never advertise unverified SA capability.

### Verification and delivery

- Add permanent positive, negative, boundary and appropriate wire-level tests for each new behavior. Reuse existing unit/integration fixtures and process tests. Never alter application main files as temporary tests.
- Build and execute tests only when authorized by the current task. Use the smallest relevant targets first. See `README.md` and `cli/README.md` for commands. Do not retry failures without diagnosis.
- Inspect the complete scoped diff and run `git -c core.whitespace=cr-at-eol diff --check`. Record implementation and evidence status only in the workbook, including tested SHA, exact commands and wire/receiver observations. Static review and codec tests cannot establish runtime or independent-peer conformance. The final deliverable and acceptance scope is the portable C++ Host implementation.
- For completed, verified source changes, stage only reviewed task files, commit clearly and push to `origin/develop` when authorized. Verify the remote tip. Preserve local commits and report `PUSH_FAILED` if needed.
- Explicit task restrictions override this workflow. Never commit secrets, reference PDFs, binaries or temporary outputs. Never force push or destructively reset/clean the workspace.

## 1. Mission and non-negotiable boundaries

Extend **OpenDNP3 3.1.2** into a reliable, portable, production-oriented C++ Master and Outstation library, implementing the *applicable, selected* functions in the supplied RTU Device Profile and minimum-security addendum, interpreted according to **IEEE 1815-2012**.

- Track **119 contractual requirements**, and only these: `PROFILE-001..069` (69), `SEC-T1/T2/T3` (36), and `CFG-01..14` (14). Preserve identifiers, roles, qualifiers, functions, subcases, and source citations.
- The **RTU Outstation** is the principal contractual acceptance target. Preserve the Master and implement Master behavior needed for tested/selected requirements. Do not silently expand into general DNP3 Level 4 compliance.
- Current implementation/acceptance environment: portable C++, Windows Host, real TCP, unit, integration, wire, negative, boundary, and separate-process testing. Preserve Linux portability.
- **Scope ends at the Host library and its verification.** Hardware integration, firmware delivery and device deployment are not development phases. Device-only requirements remain traceable in the workbook and cannot be marked VERIFIED by Host testing.
- Distinguish compiled code, synthetic codec vectors, local successful unit tests, real TCP/process tests, and independent-peer interoperability. None alone proves complete contractual acceptance.
- Preserve OpenDNP3 architecture, public API compatibility where feasible, old operating functionality, and minimal reviewable diffs. No needless redesign, cross-platform dependencies, or broad search/refactor.

## 2. Sources, priority, and revision discipline

Use **these in order** for each requirement:

1. Supplied **12-page RTU Device Profile** (selected function/object/qualifier combinations).
2. Supplied **6-page minimum-security addendum** (requirements vs recommendations; fixed vs configurable values).
3. **IEEE 1815-2012**, relevant normative clauses and object encoding; use Annex F for *informative* SA version-upgrade guidance. Do not treat informative guidance as mandatory language.
4. Current repository **`DNP3_PDD_PLAN/DNP3_IEEE1815_IMPLEMENTATION_REFERENCE.xlsx`**: `IMPLEMENTATION_INDEX`, `WIRE_PROCEDURES`, `OPEN_DECISIONS`, `SOURCES`; record requirements, decisions, source links, tests and execution evidence here.
5. Repository `REPO_MAP.md`, `README.md`, engineering tests and implementation. Historical `PDF_SCOPE.md`, `PROFILE_MATRIX.csv`, `SECURITY_MATRIX.csv`, `OPEN_ISSUES.md`, `ENGINEERING_EVIDENCE.md`, and the 119-dependency roadmap are historical/reference materials where available, **not automatic overrides of the current workbook**.
6. Upstream **`dnp3/opendnp3` tag `3.1.2`** to preserve its event-driven stack model and separate `MasterParams`, `OutstationParams`, `TLSConfig`, link, transport, database, and application APIs. Compare upstream paths starting `cpp/` with this repository's `opendnp3/cpp/` subtree; do not assume the layouts are identical.

The 712-row IEEE inventory is **reference material, not 712 new contractual requirements**. Where document selections or numeric ranges are absent, record an open product decision. Never fabricate vendor/device metadata, default variations, wire semantics, or a normative erratum. Distinguish GitHub HEAD from a Google Drive copy or a dirty local working tree.

At the start of **every new technical slice**, read `AGENTS.md`, `REPO_MAP.md`, the relevant workbook ID rows and open decisions; verify repo root/branch/HEAD, status, relevant production files, and existing permanent tests. If using Drive, fetch the latest relevant actual files and compare their revision against Git where possible. Inspect authoritative Scala models plus generated C++ when touching generated groups/enums. Ignore caches, builds, binaries, `_deps`, logs and test outputs.

## 3. Product architecture and application-level configurability

### 3.1 Required layering

`Applications / CLI -> public DNP3Manager, channel and stack APIs -> Master/Outstation contexts -> shared parser, serializers, link/transport -> crypto, credentials and platform adapters`.

- **Public configuration** selects *policy and supported behavior*; the app should not have to edit protocol internals to choose a supported security profile.
- **Contexts** orchestrate; existing parsing, frame serialization, authentication state machines, event buffers and providers implement behavior. Do not add a duplicate DNP3 stack or global mutable security singleton.
- Use one immutable **effective security configuration per stack/association** after validation and start. Changes to identity, SA version, roles, keys, MAC allowlist, transport security or trust roots require an explicit controlled reprovision/restart/reconnect transition. Do not hot-swap a live exchange silently.
- Keep user, association, owner, pending challenge, CSQ, MAC, nonce, key-expiry and replay state isolated. Fail closed when policy, keys, crypto, time, authorization or enrollment fails.
- Reuse `AuthenticationConfig`, `MasterParams`, `OutstationParams`, `TLSConfig`, `IAuthenticationCredentials`, `IAuthenticationAuthorization`, `IUpdateKeyTrust`, `IUserCertificatePolicy`, `SessionKeys`, `MasterResponder`, `OutstationChallenger`, `RemoteUpdateKeys` and the existing channel/credential providers. Add the smallest compatible public option rather than introducing a parallel API.

### 3.2 Secure Authentication version selection: explicit design target

The current project has `AuthenticationConfig::Mode { REQUIRED, COMPATIBILITY }`; **this controls enforcement, not the protocol version**. The inspected current header has **no application-selected SA version field**. The 12-page Device Profile and security addendum specify **SA Version 5**, not an arbitrary-version requirement. IEEE 1815-2012 Annex F says SAv2 and SAv5 are incompatible and recommends explicit configuration when an implementation genuinely supports multiple versions.

Introduce a **strongly typed version selector on the existing public authentication configuration**, subject to normal design review. Proposed behavior contract:

| Concept | Application-visible semantics | Production policy |
| --- | --- | --- |
| SA protocol version | `SA_V5` as the supported contractual target; reserve an explicit future `SA_V2` only when a complete, independently tested v2 implementation and its normative specification are authorized | Selecting unimplemented v2, unknown numeric values, or a disallowed policy is a **configuration error**, never silent fallback to v5 or unauthenticated traffic |
| Authentication enforcement | Preserve `REQUIRED` default; `COMPATIBILITY` remains explicit, isolated legacy/test mode | In deployed RTU profile, SA required and enabled by default. Test-only disable requires explicit authorization and must not satisfy security acceptance |
| Capability vs readiness | Version support means the outstation implements the protocol version; user/session readiness is separately observable | Do not conflate an expired user session with protocol incompatibility, and do not advertise a version never implemented or enabled |
| Negotiation | Master and Outstation must be explicitly aligned to an approved version; no opportunistic downgrade | No automatic v5-to-v2, v5-to-plaintext, or TLS downgrade on handshake/authentication failure |
| Configuration scope | At least per configured stack/association and its endpoint; validate multi-association consistency with the actual wire/profile semantics | No mid-exchange version switch; reset relevant exchanges and keys on an approved transition |

**Do not implement SAv2 merely by changing a numeric version field.** It requires its *own normative behavior*, distinct state/codec/key handling and independent interoperability testing. IEEE 1815-2010 or other approved SAv2 authority must be obtained first; such optional scope must be tracked **outside the contractual 119** until approved. An API may initially allow only v5 and reject other selections to guarantee honest behavior.

### 3.3 G0V209: remove artificial blockage, not truthful-capability checks

**Observed at the source revision reviewed for this plan:** `src/outstation/DeviceAttributeSelection.cpp` has a hard-coded `supported[]` without **209** and returns `IINBit::OBJECT_UNKNOWN`; `TestDeviceAttributes.cpp` already verifies Master parsing and standalone writer encoding for G0V209. `PROFILE-001` remains blocked in the historical roadmap.

Implement the missing *Outstation selection/response/discovery plumbing* in a small scoped change, using native `DeviceAttributeSelection`/`Database`/`HeaderWriter`, not a fabricated constant. Define and test the actual capability predicate. The eventual production-enabled answer must:

1. Encode **G0V209** as the IEEE device-attribute **unsigned value** with the selected SA version (for this contract, **5**), including correct set/qualifier/type/length and fragment behavior.
2. Derive the value from a **validated effective supported/configured version**, never an unvalidated GUI choice, hard-coded marketing claim, or unauthenticated fallback.
3. Include 209 in `G0V254`/`G0V255` discovery **iff** the same condition permits its direct read. Preserve `G0V210` and existing discovery behavior and all unrelated attributes.
4. In unsupported/unprovisioned or explicitly compatibility-only configurations, return the appropriate existing unsupported behavior rather than advertising a working SA v5 path; define the precise availability predicate against source and normative guidance, not speculation.
5. Respect any application-authentication/authorization rules governing READ; a version attribute never grants authentication privileges.
6. Have permanent positive, negative, direct-read, discovery, wire, Master delivery, per-association, malformed, fragment, and configuration-transition tests.

**Rollout gates are separate:** coding and testing the response early is encouraged; enabling it in the contractual profile requires verified matching SA v5 behavior. Do not demand every unrelated product feature to serialize G0V209 in an isolated test, but never remove a security/capability gate just to produce a misleading production response. A conditional, tested implementation is preferable to unconditional `OBJECT_UNKNOWN` or unconditional `5`.

### 3.4 Handling every partially implemented feature

For each `PARTIAL`, `IMPLEMENTED_UNVERIFIED`, `BLOCKED`, or missing behavior: identify the exact code guard and its origin, then classify it:

- **Contractual selection**: retain and make configurable only if the Device Profile explicitly allows it.
- **Normative/security requirement**: do **not** remove; implement the prerequisite, validation and rejection path.
- **Unnecessary internal limitation**: remove the restriction with minimal code and prove the formerly blocked behavior using wire and receiver-side tests.
- **Unresolved customer input**: hold a tracked decision; do not substitute an invented numeric default or certificate/profile format.
- **Implementation incomplete**: implement the missing Host path (parser, serializer, state transition, Master delivery, Outstation issue or configuration) and permanent tests; never unlock an incomplete branch by bypassing a check.
- **Build-time optional**: provide a clear compile-time capability check plus runtime rejection if unavailable. Build flags alone do not make a feature implementable at runtime.

No feature may be labeled VERIFIED solely because a synthetic writer/codec can produce bytes. No advertised G0, G120, G121/G122 or TLS capability without corresponding working runtime behavior and verified scope.

## 4. Security options: full application configuration audit

All user-selectable fields must have: a validated type/range, an approved default, owner/association scope, lifecycle rules, defensive error behavior, a documented API/CLI example, and permanent positive/negative/boundary tests. Prefer grouping existing fields over adding duplicate knobs.

### 4.1 SA protocol, user and role controls

| Security addendum | Runtime controls / current code entry points | Required design and remaining checks |
| --- | --- | --- |
| `SEC-T1-01`, `SEC-T2-01`, `SEC-T2-09` | SA v5 selection + existing `AuthenticationConfig::mode` | v5 as contractual version; REQUIRED default, compatibility only by explicit test/legacy authorization; no fallback |
| `SEC-T1-02`, `SEC-T2-10` | `users`, `userCapacity`, `IAuthenticationCredentials`, `IAuthenticationAuthorization` | At least **2 users**; provision admin/operator roles with least privilege; validate configured users against true runtime capacity; no implicit allow |
| `SEC-T1-03` | `replyTimeoutMs` | Configurable **0..120 seconds**; `TIMEOUT-ZERO` semantics remain open: don't silently force an interpretation. For other values test expiration, boundary and monotonic clock failures |
| `SEC-T1-04/05/06`, `SEC-T2-01` | `aggressiveReceive`, `aggressiveTransmit`, challenger/responder | Support mandated receive/issue behaviors; **Challenge-Response required**, Aggressive Mode usage discouraged; keep controls separately selectable but never bypass auth |
| `SEC-T1-07/08` | `renewalIntervalMs`, `renewalMessageCount` | 15..120 minutes; configurable key-change message count, supplied default 1000; cover renewal, failed rekey, reconnect and expiry |
| `SEC-T1-09` | `macAlgorithm`, `tagLength`, `permittedMACAlgorithms` | Explicit approved allowlist: SHA-256 8/16 octets and/or AES-GMAC only as authorized. **MAC-SELECTION unresolved**; do not default to unapproved SHA-1 or silently reduce tag length |
| `SEC-T1-10`, `SEC-T2-03/05/06` | `keyWrapAlgorithm`, credential provider, key/session storage | AES-256 key wrap mandatory per addendum; AES-128 discouraged. Check 128/256-bit minimums for relevant keys, required randomness, destruction and expiry; fail closed |
| `SEC-T1-17`, `SEC-T2-08`, `SEC-T3-03/05/06` | credential lifetime, enrolled user provider, secure storage | Expiring/revoked credentials and disabled users; no hardcoded production credentials; use a secure Host credential provider and hash human passwords with an approved password-hashing scheme, **not** reversible encryption masquerading as hashing |
| `SEC-T2-07/11`, `SEC-T3-04` | application configuration/password/authorization adapters | Password-protected Host application configuration, strong human passwords, authorized role controls for security changes; no unauthenticated runtime policy mutation. Record device-specific applicability separately |

### 4.2 Remote update keys, certificates, authorization

- `SEC-T1-16`, `PROFILE-055`, `PROFILE-057..062`, `SEC-T2-04`: expose **approved** RUK enable/disable, Method 4 vs Method 68, symmetric/asymmetric method where implemented, update-key retry limits, trust source, certificate validation and expiry. Existing fields include `remoteUpdateKeys`, `allowMethod68`, `maxUpdateKeyRetries`, `updateKeyTrust`, `userCertificatePolicy`, `userCertificateRecheckIntervalMs`, `outstationName`. Do not assume these imply full G120V8 runtime verification.
- For symmetric RUK, select only approved AES-256 wrap with SHA-256-HMAC or AES-GMAC, subject to product decision and actual implementation. For asymmetric methods, require the exact selected RSAES-OAEP/DSA/signature/profile trust behavior and independent tests before enabling.
- Bind every operation to the authenticated user, association, owner, CSQ, nonces, role, credentials, remote identity and deadline. Validate signature, chain, key strength, authorization and revocation; discard/erase on failure. No silent cross-user reuse, replay acceptance or fallback to weaker methods.
- Separate **key update**, **session key renewal**, **certificate validation**, **user enrollment**, and **role permissions**. Do not make them a single boolean feature switch.
- Never infer that a user certificate is trusted merely because a supported G120V8 parser accepts its bytes.

### 4.3 TLS / channel policy

| Requirement | Configuration or implementation work |
| --- | --- |
| `SEC-T1-11`, `SEC-T2-02` | Application-selectable **TLS 1.2 / TLS 1.3** at `TLSConfig`/channel level; explicit, compatible cipher-suite allowlists; validate against OpenSSL and **separate TLS 1.3 ciphersuite naming**. The addendum mixes TLS 1.2-style names under TLS 1.3: track `SEC-T1-11` as unresolved, never claim the listed strings are valid TLS 1.3 suite identifiers |
| `SEC-T1-12` | Port **19999** for DNP over TLS in the selected RTU profile; keep channel endpoint configuration and verify actual listener/connect behavior |
| `SEC-T1-13` | Configurable **1..60-second cipher-change request timeout** once its exact protocol/application semantics are established; do not equate it silently to existing handshake/response/CRL timers |
| `SEC-T1-14` | Provision and validate at least **4 certificate authorities**, trust-chain isolation, replacement and revocation; test all four actual authorities, not just a container capacity |
| `SEC-T1-15` | Configurable certificate revocation-check interval and fail-closed policy; actual value and update behavior require customer decision. Current `TLSConfig::crlCheckIntervalHours` is only an API field until checked against runtime enforcement |
| `SEC-T3-02` | Test actual Host listener/port configuration and network service allowlist as far as the Host application controls them. Device deployment hardening is outside the deliverable; do not claim it is verified |

Transport encryption (TLS) is **independent of application-layer SA**. TLS success does not satisfy SA challenge-response, role authorization, replay protection or G120 lifecycle. No TLS v1.0/1.1 in the deployed security profile even if legacy API fields exist. Never log keys, secrets, passphrases or complete private credential payloads.

### 4.4 Security statistics and operational hardening

- `PROFILE-002`, `PROFILE-063..066`, `SEC-T1-01`: verify **G0V210**, all **18 G121** per-association statistics, G122 variation/quality/time selection, event confirm/overflow, correct reset and non-reset behavior, persistence, and absence of false counters.
- `SEC-T3-01..06`: validate Host-controlled network listeners, unnecessary user accounts, strong human passwords, externalized secrets and approved password hashing. Preserve device-only subcases as explicitly not Host-verified; do not schedule hardware implementation.
- `SEC-T3-07/08`: firmware signature/update protections are **recommended**, not mandatory under the supplied addendum. Preserve their original status and applicability in the workbook, but do not create a firmware implementation phase or claim Host verification.
- `P4-OPEN-01` is unresolved: preserve provisional **G120V7 Code 5 = MAC Algorithm Not Supported; Code 7 = Authorization Failed**. Do not invent a published IEEE erratum.

## 5. Implementation phases and exactly 119 requirement assignments

**Use the current workbook to determine status and precise subcases.** These fixed-ID workstreams assign each of the 119 selected IDs exactly once; they are an execution order/dependency grouping, not new requirements or a claim of completion. Workstreams can run in parallel where dependencies permit.

| Workstream | IDs | Dependency and acceptance gate |
| --- | --- | --- |
| **F00 decisions / baseline** | Cross-cutting, **no new ID** | Reconcile current workbook, specific product blanks, actual HEAD, and open decisions; baseline acceptance tool/fixtures |
| **F01 link/transport** | `CFG-01`, `CFG-02`, `CFG-03`, `CFG-04`, `CFG-05`, `CFG-07`, `CFG-14`, `PROFILE-067` | Real frame boundaries (292-byte RX), CRC, link confirm, retry/reconnect, transport fragment deadlines, multi-fragment ownership and safe ACK semantics. Preserve unresolved stale-ACK limits unless actually solved |
| **F02 static/database** | `CFG-13`, `PROFILE-003`, `PROFILE-004`, `PROFILE-005`, `PROFILE-010`, `PROFILE-011`, `PROFILE-012`, `PROFILE-017`, `PROFILE-018`, `PROFILE-020`, `PROFILE-021`, `PROFILE-022`, `PROFILE-023`, `PROFILE-024`, `PROFILE-025`, `PROFILE-031`, `PROFILE-032`, `PROFILE-033`, `PROFILE-034` | Exact static variations, request/response qualifiers, sparse indices, packed bits, flags, value bounds, negative Master delivery and Outstation response |
| **F03 time/restart/IIN** | `PROFILE-038`, `PROFILE-039`, `PROFILE-040`, `PROFILE-041`, `PROFILE-042`, `PROFILE-047`, `PROFILE-068`, `PROFILE-069` | Time semantics, CTO, clock quality, IIN, restart hooks and negative/boundary behavior |
| **F04 events/classes/unsolicited** | `CFG-06`, `CFG-10`, `CFG-11`, `CFG-12`, `PROFILE-006`, `PROFILE-007`, `PROFILE-008`, `PROFILE-009`, `PROFILE-013`, `PROFILE-014`, `PROFILE-015`, `PROFILE-016`, `PROFILE-026`, `PROFILE-027`, `PROFILE-028`, `PROFILE-029`, `PROFILE-030`, `PROFILE-043`, `PROFILE-044`, `PROFILE-045`, `PROFILE-046` | Event variation/qualifier and count, class scans, default variations, confirmation, retry, reconnect and event retention. Resolve CFG-12 customer selection |
| **F05 credential/role/policy** | `SEC-T2-07`, `SEC-T2-09`, `SEC-T2-10`, `SEC-T2-11`, `SEC-T3-01`, `SEC-T3-02`, `SEC-T3-03`, `SEC-T3-04`, `SEC-T3-05`, `SEC-T3-06`, `SEC-T3-07`, `SEC-T3-08` | Host user/role/configuration security, credential provisioning/storage and controllable network hardening; track device-only subcases without adding non-Host development |
| **F06 core SA v5** | `PROFILE-048`, `PROFILE-049`, `PROFILE-051`, `PROFILE-052`, `PROFILE-053`, `PROFILE-054`, `SEC-T1-02`, `SEC-T1-03`, `SEC-T1-06`, `SEC-T1-07`, `SEC-T1-08`, `SEC-T2-01`, `SEC-T2-05` | G120 challenge/reply/status/change/error, user/owner isolation, CSQ, MAC, timeouts, session renewal and protected transactions |
| **F07 aggressive/MAC** | `PROFILE-050`, `PROFILE-056`, `SEC-T1-04`, `SEC-T1-05`, `SEC-T1-09` | G120V3/V9, approved MAC selection, aggressive prevention/issuance, replay and invalid-protected-operation rejection |
| **F08 controls** | `CFG-08`, `CFG-09`, `PROFILE-019`, `PROFILE-035`, `PROFILE-036`, `PROFILE-037` | G12/G41 FC3/4/5/6 with SA role authorization, exact wire, rejected prohibited operations, duplicate prevention, receiver-side TCP effects |
| **F09 certificate/RUK** | `PROFILE-055`, `PROFILE-057`, `PROFILE-058`, `PROFILE-059`, `PROFILE-060`, `PROFILE-061`, `PROFILE-062`, `SEC-T1-10`, `SEC-T1-16`, `SEC-T1-17`, `SEC-T2-03`, `SEC-T2-04`, `SEC-T2-06`, `SEC-T2-08` | G120V8 and remote-key methods, chain/expiry/ownership, selected wrap/signature methods, rollback and interruption recovery |
| **F10 TLS/CA** | `SEC-T1-11`, `SEC-T1-12`, `SEC-T1-13`, `SEC-T1-14`, `SEC-T1-15`, `SEC-T2-02` | TLS 1.2/1.3, suite policy, port 19999, 4 CAs, rotation/revocation, timeout decision, separate-process tests |
| **F11 statistics/attributes** | `PROFILE-001`, `PROFILE-002`, `PROFILE-063`, `PROFILE-064`, `PROFILE-065`, `PROFILE-066`, `SEC-T1-01` | G0V209 truthful conditional advertisement, G0V210, G121/G122 integrity, persistence and lifecycle; final deployed enablement only with matching SA v5 evidence |

**Execution priorities**:

1. **F00**: current HEAD, workbook/open-decisions, failures, upstream feature diff. Resolve product decisions that block correct behavior; keep open items visible.
2. **Runtime configuration contract (cross-cutting)**: audit current auth/TLS/credential/user/MAC/RUK fields; add explicit SA version semantics with **v5 only until another version is real**; introduce validation and negative configuration tests. This must not break existing Master/Outstation call sites.
3. **G0V209 narrow implementation**: remove the unconditional internal `OBJECT_UNKNOWN` path *under an evidence-based capability predicate*. Test direct G0V209, discovery, Master decode, disabled/not-ready cases and real TCP. Keep shipping enablement gated by matching protocol readiness.
4. Close **F01-F04** protocol gaps with minimal patches and selected wire/receiver tests. Do not spend effort on already passing code unless coverage reveals a defect.
5. Advance **F05 and F10 in parallel**, then **F06/F07** authentication correctness, **F09** key/cert management, **F08** authenticated controls; rerun focused regressions at integration boundaries.
6. Complete **F11** statistics lifecycle and apply the final truthful capability-advertisement gate.
7. Run selected Windows Host unit, integration, wire, negative, boundary, real TCP, separate-process and TLS/SA regressions; perform independent-peer interoperability separately, preserving BLOCKED where unavailable.

## 5.1 First implementation slices: exact code touchpoints and acceptance

These are **planned candidate files**, not permission to modify all of them at once. Reinspect current HEAD and select only necessary files; each slice is independently reviewable. There is no new contractual ID count.

| Slice | Scope and initial production/test touchpoints | Required passing evidence |
| --- | --- | --- |
| **S00 - audit** | `AGENTS.md`, `REPO_MAP.md`, workbook, current `AuthenticationConfig.h`, `TLSConfig.h`, `DeviceAttributeSelection.cpp`, tests | Signed-off list of actual fields, missing controls, business-vs-security guards, unresolved decisions, and compatibility constraints; **no source mutation** |
| **S01 - version API** | `api/auth/AuthenticationConfig.h`, `src/auth/AuthenticationSession.cpp`, Master/Outstation stack initialization and `TestAuthenticationConfig.cpp` | Application can explicitly select *implemented* SA v5; default remains v5 REQUIRED; unknown/v2/unbuilt SA and conflicting options reject before network operation; no Master or Outstation regression |
| **S02 - G0V209** | `src/outstation/DeviceAttributeSelection.{h,cpp}`, `Database.{h,cpp}`, effective configuration injection from outstation context as needed, `TestDeviceAttributes.cpp` | Direct READ returns accurate uint 5 where allowed; G0V254/V255 discovery agrees; compatibility/unsupported config does not falsely advertise; Master callback decodes; malformed/fragmented/range and exact bytes covered |
| **S03 - user and roles** | `AuthenticationConfig.h`, credential/authorization provider implementations, `AuthenticationSession.cpp`, `TestAuthenticationConfig.cpp`, `TestAuthenticationRuntime.cpp` | >=2 users; admin/operator authorization, disabled/expired users and reject-by-default; no credentials or cross-user state leak; no hard-coded deployed secrets |
| **S04 - algorithms and rekey** | `auth/SessionKeys.*`, `auth/AuthenticationMAC.*`, `auth/AggressiveMode.*`, `master/MasterResponder.*`, `outstation/OutstationChallenger.*` | Approved SHA-256 tag/AES-GMAC and AES-256 wrap choices only; timers/count, nonce, CSQ, replay, ownership, rekey failure, algorithm rejection without downgrade |
| **S05 - remote key/cert** | `auth/RemoteUpdateKeys.*`, `master/UpdateKeyTask.*`, crypto/trust providers, Group120 Scala and generated outputs when changed | Methods 4/68 selected by verified policy; G120V8 certificate trust, status/key-change sequence, negative signatures/revocation, restart and interrupted rollover |
| **S06 - TLS** | `api/channel/TLSConfig.h`, `src/channel/tls/*`, `cli/TestTLS.cpp`, permanent TLS/process tests | Version- and suite-specific allowlist, 4 CA chains, revocation cadence, client/server identity, 19999, invalid/expired credentials and fail-closed reconnect; preserve open decisions |
| **S07 - protected functions and stats** | `outstation/OutstationContext.cpp`, control handlers, `auth/AuthenticationStatistics.cpp`, `outstation/SecurityStatEventPublisher.cpp`, selected tests | Authenticated FC3/4/5/6 receiver effects and denials, G121/122 count/event lifecycle, no duplicate executions or forged stats |
| **S08 - final Host acceptance** | Current workbook evidence, unit/integration/TCP/wire/process/negative regressions | Every applicable selected Host subcase matched to tested SHA; G0V209 enablement justified; independent-peer results separately evidenced; no device-only requirement claimed VERIFIED |

For S01/S02, first compare the existing test `DeviceAttributes - actual count per association and no fabricated SA version` and the native G0V209 writer test. Update only assertions whose expected *runtime* behavior is deliberately changed and proven; preserve Master parsing and G0V210 independent behavior. The original `dnp3/opendnp3` 3.1.2 public surface can guide API compatibility but is not evidence that a later SA revision is supported. Do not create a user-visible `SA_V2` success path without the approved v2 specification and complete implementation.

## 6. Work packet, implementation and verification contract

For every change, use this sequence:

1. Identify exact **requirement ID(s), PDF page/table, IEEE clause, role, FC/object/variation/qualifier and acceptance subcase**. Define expected positive and negative wire behavior.
2. Verify HEAD, branch, dirty files; read current source *and permanent tests*, not previous ZIPs or model summaries. Use `REPO_MAP.md` to navigate directly. For generated code inspect Scala originals and C++ outputs.
3. Classify the gap: missing Host production behavior, unused API, false internal block, missing configuration validation, parser/writer defect, security policy, missing test, non-Host applicability, or unresolved product decision.
4. Propose the **smallest correct scoped patch**: file/function and exact anchor, compatibility impact, security/lifetime effects and acceptance. Do not expand unrelated capabilities or refactor just to simplify a test.
5. Make the change on an isolated reviewable slice; permanent focused **positive, negative, malformed, boundary, timeout, ownership, replay, state and wire** tests as applicable. Prove Master and Outstation behavior relevant to the requirement.
6. For changes involving G120/G121/G122, public enum or object layout, edit authoritative Scala model and regenerated C++ outputs consistently. Confirm generated artifacts and test vectors match.
7. **Codex implementation tasks normally do not build/test unless explicitly authorized**. The user runs Windows PowerShell validation: diff check -> focused build/tests -> nearby regressions -> full applicable Host suite -> wire/TCP/process when applicable. Check external exit codes; never report success without log output.
8. Review diff and ownership, then log tested HEAD, command, binary flags, test counts, receiver observations and limitations in the **workbook**. Use `VERIFIED` only if the relevant complete subcase has matching passing evidence. Otherwise use `IMPLEMENTED_UNVERIFIED`, `PARTIAL`, `MISSING`, `BLOCKED`, `NOT_APPLICABLE` as appropriate to workbook conventions.
9. If a test fails, isolate root cause; do not weaken normative assertion, change expected bytes to hide a defect, or retry a failed command blindly. A failing test may be a wrong fixture: investigate both.
10. **Never stage, commit, push, reset, clean, overwrite unrelated files, or apply a third-party ZIP without explicit authorization.** When explicitly authorized, stage only reviewed approved paths, verify tracked remote `develop`, push without force, verify remote HEAD. Preserve stashes, existing work and backups.

### Isolated ZIP handoff to a coding agent

- Input ZIP: just `AGENTS.md`, relevant `REPO_MAP.md` excerpts, exact requirement IDs/workbook evidence or bounded worksheet export, and all *necessary* source/test/helper files. Include `TASK.md` with whitelist of allowed modified paths, source SHA, acceptance and prohibited actions. Avoid entire-repo dumps.
- Output ZIP: **only** the modified allowlisted files plus `RESULT.md` specifying paths, rationale, unanswered questions, build/test **NOT RUN** if applicable, and any uncovered limitation.
- Review output hashes, unexpected paths, source revision, byte/diff changes, normative encoding, public compatibility and independent expectations before applying. Never trust a model's success claim as execution evidence.
- Maintain one work packet and one bounded context per feature. Do not let assistants roam the full repository or silently rewrite the requirements.

## 7. Open decisions and invariant security behavior

These are **not** permission to fabricate a missing setting or bypass validation:

- `P4-OPEN-01`: provisional G120V7 Code 5/7 as documented above; still unresolved.
- `TIMEOUT-ZERO`: SEC-T1-03 zero response timeout meaning; select only after normative/product decision.
- `MAC-SELECTION`: checked/approved SHA-256-8/16 and/or AES-GMAC policy and downgrade constraints.
- `SEC-T1-11`: malformed/conflicting TLS 1.3 suite names in supplied addendum; clarify approved TLS 1.3 profile.
- `SEC-T1-13`: cipher-change timeout meaning, enforcement point and testable transitions.
- `SEC-T1-15`: CRL interval, expiry, failure and refresh behavior in deployed product.
- `G120V8`, `RUK-OPEN-01`, `RUK-OPEN-02`: user certificate trust/encoding, symmetric/asymmetric remote update key method choices and lifecycle.
- `PHASE2-SA-V5`, `STAT-RETENTION`, `G122-UNTIMED`: actual G0V209 enabling evidence and statistics persistence, time and quality semantics.
- `CFG-02/03/07/09/10/12`: missing/conditional device product defaults, frame/fragment sizes, timer ranges, Trip/Close mapping, variations and startup unsolicited selection.
- `INDEPENDENT-PEER`, `RTU-HARDWARE`, `RTU-FIRMWARE`, `RTU-NETWORK`, `RTU-PROVISIONING`, `ROLE-PROVISIONING`: preserve traceability and scope classification; independent-peer Host interoperability is a separate verification gate, and device-only obligations are not part of the implementation plan.
- **SAv2 extension**: outside the present 119 and not available simply by setting a number. Requires separately supplied normative specification, explicit product decision, separate implementation and interop matrix; never count as current SAv5 compliance.

Safety invariants: fail closed; no unauthenticated protected controls; no plaintext/TLS/SA downgrade; no fake G0V209/G121/G122 advertisements; no user/association state leakage; no replay or deadline bypass; no hardcoded deployment keys; do not log secrets; no unsupported conformance certificate or “Level 4 compliant” claim.

## 8. Definition of done

**For a feature slice:** complete selected source behavior and relevant permanent passing Host evidence at the same identifiable revision; workbook updated with exact applicable subcases and unresolved limitations.

**For the final Host deliverable:** every applicable selected Host requirement/subcase has working code and matching unit/integration/wire/boundary/negative/TCP/process evidence; relevant security failure cases and policy combinations pass; open product decisions are resolved or explicitly BLOCKED; Master regression preserved. Independent-peer interoperability remains separately identified until executed. Device-only obligations remain traceable but do not expand the deliverable. Never claim full IEEE Level 4 compliance or certification from Host tests alone.
