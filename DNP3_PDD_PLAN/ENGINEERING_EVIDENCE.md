# Historical engineering evidence

Preserved records with original tested revisions and limitations. Statements below are historical and may conflict. Current scope is PDF_SCOPE.md and current issues are OPEN_ISSUES.md. Historical phase labels confer no implementation authorization. The unverified local acceptance runner supplies no accepted evidence.

<a id="record-01"></a>

## Record 01 — ENGINEERING_EVIDENCE.md#record-01

# Source index and engineering partition

## Input integrity and scope

| ID | Original file | PDF pages | What it governs |
|---|---|---:|---|
| IEEE | `IEEE 1815-2012.pdf` | 821 | Normative formats, functions, object semantics and layer behavior |
| PROFILE | `4812449245627490050_724147149003390.pdf` | 12 | Supplied RTU profile, selection boxes and implementation-table requirements |
| SEC | `الزامت حداقل مورد نیاز.pdf` | 6 | Amended security requirements, constraints and hardening |

The PROFILE is **a 12-page excerpt** showing its original document page numbering **41 to 52 of 78**. It identifies the outstation role and Level 3 request/response support. Do not assume absent pages of the full 78-page document are available.

The SEC introduction (PDF p2) describes modified security tables relating to a larger requirements document. The other pages/rows of that parent document have **not** been supplied. Do not claim complete contract coverage based solely on this excerpt.

## Source partitions: IEEE (PDF page, 1-based)

| Logical module | IEEE sections | Starting PDF page | Engineering use |
|---|---|---:|---|
| Object terminology and static/event/class | 4.1 | 55 | Point models; class semantics |
| APDU headers, fragments, function handling | 4.2-4.5 | 61-123 | Reuse existing request/response paths; IIN |
| READ/WRITE/device attributes | 5.5.1-5.5.8 | 190-195 | Required for G0V209 and other Group 0 values |
| Attribute data types | 5.5.4.3 / Table 5-16 | 192 | Code 2 for UINT; byte length |
| Security behavior | Clause 7 | 213 | SA v5 protocol and roles |
| Security messages, procedures | 7.5.1-7.5.5 | 228-281 | Stateful authentication, not just serialization |
| Transport | Clause 8 | 309 | Protected existing infrastructure |
| Data link | Clause 9 | 316 | Protected existing infrastructure |
| Object library definitions | Clause 11 | 349 | Generic wire shapes |
| Subset-level parsing tables | Clause 12.1 | 393 | Check obligations by level |
| Special object parsing guidance | Clause 12.2 | 404 | Qualifier/function compatibility |
| Device Attributes G0 | Annex A.1 | 480 | Attribute variations |
| G0V209 | A.1.1 | 480 (printed p438) | First requested object |
| G0V210 | A.1.2 | 481 (printed p439) | Second attribute candidate |
| G0V254 and G0V255 | A.1.43 and A.1.44 | 527, 528 | Group 0 discovery/all attributes behavior |
| SA message objects G120 | A.45 | 761 | G120V1-V15 |
| Security statistics G121 | A.46 | 800 | G121V1 |
| Security event G122 | A.47 | 802 | G122V1-V2 |

For other Groups, look up their *specific* Annex A entry and the corresponding Clause 12 table **when that variation is selected**; do not paste all 821 pages into Codex context.

## Profile partitions

| PDF page(s) | Portion | Implementation concern |
|---|---|---|
| 1-2 | Device profile declaration and notable objects | Level 3 outstation; extras G0/G120/G121/G122 |
| 2-4 | Link, fragmentation, retries, control modes, events and unsolicited options | Runtime configuration and behavior; several numeric fields are blank |
| 4 | G0V209/V210, G1V0/V1 | Device attributes and binary inputs |
| 5 | G1V2, G2, G3, G4V0 | Binary and double-bit static/event |
| 6 | G4V1-V3, G10, G12, G30V0/V1 | Control and analog start |
| 7 | G30, G32, G40V0 | Analog and events |
| 8 | G40, G41, G50V1 | Analog output and time |
| 9 | G50-V52, G60V1-V3 | Time, Class 0-2 |
| 10 | G60V4, G80V1, G120V1-V4 | Class 3, internal indications, SA |
| 11 | G120V5-V14 | SA messages |
| 12 | G120V15, G121V1, G122, no-object functions | Security counters/events and function-only support |

The complete **identified Group/Variation rows** appear in `PROFILE_MATRIX.csv`; entries record **what the profile shows**, not proof of code support. The column `qualifier_status` flags cases where response echoes the request or the table is function-specific.

## Security partitions

| PDF page(s) | Portion | File |
|---|---|---|
| 1-2 | Title, revision, relationship to amended RTU rules | `ENGINEERING_EVIDENCE.md#record-02` |
| 3-4 | Table 1, parameters 1-17 | `ENGINEERING_EVIDENCE.md#record-02` |
| 5 | Table 2, requirements 1-11 | `ENGINEERING_EVIDENCE.md#record-02` |
| 6 | Table 3, hardening 1-8 | `ENGINEERING_EVIDENCE.md#record-02` |

## Items intentionally not inferred

- Source tree, OpenDNP3 commit/tag, existing STM32 adaptations, and generated-code workflow are unknown until the local C++ project is available.
- Vendor name and device name fields are blank in PROFILE PDF p1; application fragmentation sizes are also left blank on p2.
- The PROFILE states **No Counters Reported** (p4). Do not treat all standard counter objects as product requirements solely because OpenDNP3 implements them.
- Device Profile Level 3 is explicit. A separate, complete Level 4 target requires a distinct approved gap assessment; it does not follow automatically from the supplied profile.


<a id="record-02"></a>

## Record 02 — ENGINEERING_EVIDENCE.md#record-02

# Security requirements ledger (SEC)

**Source:** `الزامت حداقل مورد نیاز.pdf` (6 PDF pages), final-revision date displayed on cover: 1405/06/22. This document *amends* security tables in a larger RTU requirements document. It is not itself the entire parent specification.

## Table 1 - DNP3 security parameters (SEC PDF pp3-4)

| ID | Parameter | Source requirement | Status for implementation |
|---|---|---|---|
| SEC-T1-01 | Secure Authentication | Fixed: Version 5 | Mandatory, no false reporting |
| SEC-T1-02 | Maximum users | Configurable, at least 2 | Mandatory |
| SEC-T1-03 | Security response timeout | Configurable, 0-120 s | Mandatory range; legal zero semantics to verify in IEEE |
| SEC-T1-04 | Aggressive receive | Yes, not recommended | Capability required; usage policy separate |
| SEC-T1-05 | Aggressive issue | Yes, not recommended | Capability required; usage policy separate |
| SEC-T1-06 | Challenge-response | Mandatory | Mandatory |
| SEC-T1-07 | Session key change interval | Configurable, 15-120 min | Mandatory |
| SEC-T1-08 | Session key change count | Configurable, default 1000 messages | Mandatory |
| SEC-T1-09 | Requested MAC | Selectable SHA-256 (16/8 octets), AES-GMAC | Final required *selection set* not filled by checkboxes; track separately |
| SEC-T1-10 | Session key wrapping | AES-256 mandatory; AES-128 not recommended | Mandatory AES-256 |
| SEC-T1-11 | TLS cipher suites | TLS 1.2 and TLS 1.3 lists | Conflicting TLS 1.3 naming; clarify before coding |
| SEC-T1-12 | DNP TCP port using TLS | Fixed: 19999 | Mandatory when using TLS |
| SEC-T1-13 | Cipher-change request timeout | Configurable, 1-60 s | Mandatory |
| SEC-T1-14 | Supported CAs | At least 4 | Mandatory |
| SEC-T1-15 | Certificate revocation check time | Configurable; numeric value blank | OPEN: no default/range supplied |
| SEC-T1-16 | Remote update-key changes | Configurable, symmetric/asymmetric algorithm options | Must distinguish alternatives vs minimum mandatory options |
| SEC-T1-17 | User-credential expiry | Yes | Mandatory |

**Caution:** The security table uses checkboxes for some algorithms and modes. A checkbox not selected in the source does not establish that every listed algorithm is simultaneously mandatory. Preserve the exact list and requirement category until a compliant algorithm selection is approved. Do not silently commit to an algorithm based on a sample.

### TLS inconsistency

SEC p3 presents names of the `TLS_ECDHE_*_WITH_*` form under TLS 1.3. Those are TLS 1.2-style cipher-suite identifiers; TLS 1.3 has different cipher suite naming and cipher-suite negotiation. This is a **source inconsistency**, not permission to weaken TLS. Resolve using RFC 8446 and requirement-owner approval before implementation. Note that the table also repeats some entries.

Windows diagnostic evidence: mutual TLS 1.2 and 1.3 on port 19999, expected
DNS/IP SAN and trust-chain enforcement, reconnect, rejected peer identities,
untrusted client/server, expired certificates and invalid cipher settings are
locally verified (see `cli/README.md`, `pc-tls`). TLS 1.2 and TLS 1.3 settings
are separate; this does not resolve SEC-T1-11's product naming conflict.
Multiple-CA capacity, automated revocation/rotation and cipher-change timing
remain outside this verified diagnostic slice.

## Table 2 - RTU security requirements (SEC PDF p5)

| ID | Subject | Level or statement |
|---|---|---|
| SEC-T2-01 | Protocol authentication | Challenge-response; Aggressive Mode not recommended |
| SEC-T2-02 | Protected communications | TLS 1.2 and TLS 1.3 |
| SEC-T2-03 | Session-key encryption and exchange | Key wrap |
| SEC-T2-04 | Update-key protection | Symmetric and asymmetric approaches indicated; must agree on operative choice |
| SEC-T2-05 | Session key length | 128-bit acceptable; 256-bit recommended |
| SEC-T2-06 | Update key length | 128-bit acceptable; 256-bit recommended |
| SEC-T2-07 | Local RTU configuration password | Mandatory |
| SEC-T2-08 | Random generation for security keys | Mandatory |
| SEC-T2-09 | Authentication enabled by default | Mandatory; disabling for protocol configuration accepted (as described) |
| SEC-T2-10 | Minimum user roles | Administrator for security settings, ordinary user for technical settings; both may perform ordinary tasks |
| SEC-T2-11 | Security parameter configurability | Mandatory for all protocol/configuration security parameters |

This table distinguishes *acceptable minimum* from *recommendation*: do not reclassify the suggested 256-bit length as strictly required where the document accepts 128-bit.

## Table 3 - Hardening (SEC PDF p6)

| ID | Requirement | Level |
|---|---|---|
| SEC-T3-01 | Close unused hardware ports | Mandatory |
| SEC-T3-02 | Close unused network ports | Mandatory |
| SEC-T3-03 | Disable unnecessary users | Mandatory |
| SEC-T3-04 | Least privilege for users | Mandatory |
| SEC-T3-05 | Do not hardcode credentials | Mandatory |
| SEC-T3-06 | Hash stored credentials | Mandatory |
| SEC-T3-07 | Secure firmware update with digital-signature verification | Recommended |
| SEC-T3-08 | Check digital signature during firmware update | Recommended |

## Dependencies and boundary

- **G0V209 (first slice):** reports actual negotiated/implemented SA version capability; its return value must not advertise unimplemented SAv5. Status PARTIAL: the Master decodes an external device's real UINTn value; the Outstation returns OBJECT_UNKNOWN and omits the attribute from discovery because no complete SA v5 version is supported (`ENGINEERING_EVIDENCE.md#record-09`).
- **G0V210, G121, G122:** represent actual supported security-statistic points and events; these cannot be replaced by made-up counters. Status IMPLEMENTED from real per-association statistics: G0V210 with mandatory V254/V255 discovery (`ENGINEERING_EVIDENCE.md#record-09`), G121 READ/Class 0 and G122V1/V2 publication (`ENGINEERING_EVIDENCE.md#record-08`), Master typed decode and delivery (`ENGINEERING_EVIDENCE.md#record-07`).
- **G120V1-V15:** are protocol structures that participate in a security state machine; merely serializing them is insufficient. Status: V1/V2 challenge-reply, V3/V9 aggressive, V4/V5/V6 session-key and V7 error objects participate in the implemented exchanges; V11-V15 update-key objects remain codec-only with no operational procedure.
- **TLS:** a separate secure transport feature; not a substitute for DNP3 SAv5.
- **Platform:** key storage, RNG, time and TLS configuration require Windows vs STM32 adapters later; no new platform interface is prescribed in this planning phase.

**Completion rule:** no security requirement is marked fulfilled until the actual implementation and its configured behavior have been inspected and a user-authorized verification step has completed. This ledger contains no implementation and no test code.

## P4-OPEN-01 - IEEE Authentication Error Code Ambiguity

**Status: OPEN - deferred independent verification in P10.**

- IEEE 1815-2012 §7.5.5.7 refers to Code 5 for Authorization Failed.
- Annex A.45.7.2.2 defines Code 7 for Authorization Failed and Code 5 for MAC Algorithm Not Supported.
- Current implementation deliberately follows the Annex wire-format assignment: authenticated authorization denial uses G120V7 Code 7; Code 5 remains MAC Algorithm Not Supported.
- This is a provisional interoperability decision, not a confirmed official IEEE erratum.
- Verify against official IEEE corrections and Triangle MicroWorks SA v5 Test Harness during P10.
- Do not close this issue without independent interoperability evidence.

Implementation verification remains static only (NOT BUILT / NOT TESTED). Error suppression follows §7.5.2.4 and Table 7-6: explicit suppression and unavailable/busy transmission paths may suppress an Error; the send threshold is reopened only after successful Session Key change. No UTC timestamp is fabricated when the application time source is invalid.

## P6a security-statistics implementation gate

**Status: PARTIAL. Compile-ready P6a source/test changes are committed and user-validated; P6-OPEN-03 and indexes 15/16 remain open.**

Normative sources: IEEE 1815-2012 sections 7.5.2.1-7.5.2.2, Table 7-6
(printed pp206-207), Table 7-8 (pp215-222), Table 7-13 (pp231-233),
7.6.1.4.2 and Table 7-15 (pp242-243), and 11.9.10/Table 11-19 (pp349-350).
The Device Profile lists G121V1/G122V1/V2 on PDF p12; their wire publication,
READ/event handling and G0V210 remain outside P6a.

### P6-OPEN-01 - Reporting threshold boundary

- Section 7.6.1.4.2 generates an event when the statistic has increased by the
  configured threshold amount; 11.9.10.2 instead says the difference exceeds it.
- User-approved provisional decision: use the Clause 7 `>=` reporting boundary.
- Keep reporting baselines separate from the five protocol Max values. Table
  7-8 retains its explicit `>`/`<=` rules and specified Max-reset events.
- Verify independently during P10; this is not an official IEEE correction.

### P6-OPEN-02 - Critical Messages Sent accounting boundary

- Table 7-6 describes index 7 as incrementing on receiving a Challenge, whereas
  7.5.3.2 says to increment upon responding to that Challenge.
- User-approved provisional decision: increment exactly once when the valid
  response to an owned Challenge begins actual transmission. This includes the
  Master's mandatory Aggressive CONFIRM (G120V3/G120V9), without counting it a
  second time as both a Challenge response and an Aggressive transmission.
- Other Aggressive transmissions follow 7.5.3.3. Rejected, invalid, stale or
  unrelated Challenges and responses that never start TX do not increment 7.
- Total Messages Sent (5) and Critical Messages Received (8) remain independent.
- Verify independently during P10; this is not an official IEEE correction.

### P6-OPEN-03 - Authentication-failure threshold user ownership

**Only ownership-dependent recovery remains BLOCKED; this does not block independent statistics.**

- Section 7.5.2.1 (printed p203) describes per-user authentication states and only
  one non-idle user. Table 7-8 rows 10/12 require a failure-driven key-status
  exchange or setting current Key Status to AUTH_FAIL after Max Authentication
  Failures is exceeded. Unlike rows 8/9 for communication failure, these rows do
  not explicitly say that the event affects all users.
- `OutstationChallenger::Challenge()` emits Control Direction USR=0. The pending
  critical APDU does not establish its selected user's identity; `Reply()` later
  looks up the Reply's user, and can return INVALID_USER without finding one.
- `OContext::RouteAuthentication()` uses that selected user to find per-user
  SessionKeys; common-user monitoring and another user's key exchange have
  independent ownership in the current implementation.
- User decision: USR=0 and an unverified Reply USR establish no authenticated
  user. Count the failed owned Reply at association index 2 and discard its
  pending ASDU at index 9 (Table 7-8 row 6). An unsolicited/late Reply with no
  pending Challenge is unexpected/discarded at indexes 0/9, not a second failed
  owned authentication (rows 5/6, Security Idle).
- Retain the association failure total and exceeded Max. Do not select user 1/2,
  invalidate all users, set unrelated SessionKeys to AUTH_FAIL, or increment
  index 4 without a real failure-driven recovery exchange. Valid independent
  users and pending Monitoring/key exchanges remain usable.
- The Master's own Monitoring Challenge explicitly selects user 1, establishing
  a legitimate recovery subject independently of the received Reply's USR.
  Recovery reuses SessionKeys; index 4 increments only at the first actual owned
  V4/V6 transmission. Index 13 increments separately on successful installation.
- The missing case remains Table 7-8 rows 10/12 for an Outstation Control
  Challenge with USR=0 and an invalid/unknown-user Reply causing the failure Max
  to be exceeded. No standards-backed user-specific AUTH_FAIL/rekey target has
  been established. Resolve this case before claiming full P6a compliance.
- Unambiguous association reactions remain implemented: Reply Timeout Max
  handling affects all users as expressly required by rows 8/9; row 11 requests
  native TCP closure when both failure/rekey limits are exceeded. Neither action
  treats a received unverified USR as identity. Protected data is never released
  because a failure, Error, timeout or threshold crossing occurred.

### Retained P6a runtime and exact event hooks

`AuthenticationSession` owns one `AuthenticationStatistics` runtime per configured
SA association. SessionKeys message-renewal budgets remain separate from these
cumulative statistics. Reporting uses P6-OPEN-01; the five protocol maxima use
strict `>` and their state-table reset events. Totals wrap modulo 32 bits and
have no clear/freeze API. Link reconnect preserves totals and reporting baselines;
pending recovery ownership is cancelled rather than carried into a new connection.

I = IMPLEMENTED at the listed sources; P = PARTIAL; D = DEFERRED. These statuses
describe static implementation coverage, not executed verification or conformance.

| Index | Statistic | Status | Actual source hook | Default threshold |
|---:|---|:---:|---|---:|
| 0 | Unexpected Messages | P | Challenger Idle Reply; Context authentication/parser/response rejection; SessionKeys unexpected input | 3 |
| 1 | Authorization Failures | I | OContext::SendAuthorizationError, only after verified policy denial in C/R or Aggressive Mode | 5 |
| 2 | Authentication Failures | I/P | Challenger::Reply/RejectReply; Context failed Aggressive verification; invalid SessionKeys status authentication. Accounting implemented; unowned recovery is P6-OPEN-03 | 5 |
| 3 | Reply Timeouts | I | Challenger::Tick/expired Reply; Master SessionKeys::Tick. Local responder retention expiry is not a peer Reply timeout | 3 |
| 4 | Authentication Rekeys | P | SessionKeys::OnExchangeTransmit for an owned failure-driven recovery; Outstation unowned recovery blocked | 3 |
| 5 | Total Messages Sent | I | MContext::Transmit/OContext::BeginTx, once per lower-layer-accepted application fragment | 100 |
| 6 | Total Messages Received | I | MContext::OnReceive/OContext::ProcessMessage after association address validation, including malformed fragments | 100 |
| 7 | Critical Messages Sent | I | Actual V2 or Aggressive V3 transmission, including mandatory CONFIRM; P6-OPEN-02 | 100 |
| 8 | Critical Messages Received | I | Actual V1 TX, parsed Aggressive RX, plus specified critical-request discard/invalid-key state-table cases | 100 |
| 9 | Discarded Messages | P | Challenger pending-ASDU disposal; Context authentication/header/response rejection. Failed owned Reply consumes the pending-ASDU increment once | 10 |
| 10 | Error Messages Sent | I | Actual Error-fragment TX; existing authorization Error producer consults the moving Max | 2 |
| 11 | Error Messages Received | I | Valid standalone V7 handlers; validated native V7 event objects in authenticated mixed responses, without standalone recovery | 10 |
| 12 | Successful Authentications | I | Challenger verified Reply and successful Aggressive verification, once before authorization; not Reply generation or key-status MAC processing | 100 |
| 13 | Session Key Changes | I | SessionKeys::Process returning INSTALLED on each role, never credential loading or codec serialization | 10 |
| 14 | Failed Session Key Changes | P | Correlated Outstation V6 unwrap/validation/confirmation-generation failure; Master terminal retry/Reply-Max failure and disconnect of a pending key transaction | 5 |
| 15 | Update Key Changes | D | Methods 4/68 real mutual-proof/durable-install boundaries; Outstation counts actual final TX; verification-only and retries do not duplicate | 1 |
| 16 | Failed Update Key Changes | D | Methods 4/68 terminal transmitted-exchange failure; bounded retry exhaustion/disconnect; never codec construction or untransmitted attempts | 1 |
| 17 | Rekeys Due to Restarts | I | MContext::OnReceive rising RESPONSE/UNSOLICITED_RESPONSE restart IIN; existing bounded restarted-peer Key Status bootstrap avoids double counting; moving throttle/rearm; always zero in Outstations | 3 |

Indexes 0/9 cover the confirmed authentication and Context response-discard paths;
this patch does not claim exhaustive instrumentation of every ordinary DNP3 state
handler. Index 14 does not invent failed transactions for uncorrelated key traffic.
Table 7-13 row 10's inappropriate noncritical-response exit is not supplied by
the present policy, which protects all normal responses; no unsafe unprotected
dispatch was introduced to manufacture that event. These coverage limitations
are separate from the implemented event hooks.

Table 7-13 row 2 now retains an authentic non-OK confirmation, including its
original deadline/candidate, and increments only Unexpected Messages. Row 12
retains an owned status request on another user's V5; from confirmation it
returns to Wait for Key Status without extending the Reply Timer. Sent-V6
recovery proof is retained. The Context authenticates foreign-user status using
that user's retained status proof before deciding whether to increment index 2;
an unverified USR never becomes a recovery owner or resets the foreign session.

Table 7-8 rows 28/29 discard a rising restart-IIN response, additionally discard
an owned pending monitoring ASDU only when recovery is allowed, and retain it
when the restart Max is exceeded. The Master queries status while retaining old
Monitoring proof: a restart bit alone does not erase the only MAC evidence for
a live peer. A subsequently accepted NOT_INIT/no-MAC restart bootstrap cannot
double-count the same recovery. Table 7-6's index-17 trigger is applied in both
Challenger states; row 28's Wait-for-Reply column omits the increment explicitly
shown in its Security-Idle column. Independently verify that textual omission
during P10; this implementation does not assert an official IEEE correction.

Native V7 event accounting reuses APDUParser after message authentication. Historical
Error events, including events about another association, do not invoke standalone
Error cancellation or Code 1 recovery. Ordinary task/SOE dispatch is unchanged.

Necessary private lifecycle state is bounded: one known recovery user, one pending
all-user timeout notification with its aborted transaction owner, and SessionKeys
flags for unsent failure-driven recovery and capped renewal backoff, plus the
observed restart-IIN edge and pending restart-recovery marker. They prevent
duplicate index-4 accounting, stale recovery after disconnect, retry acceleration,
and resetting the restart Max on reconnect. No second authentication engine exists.

### Remaining runtime and later-phase dependencies

- Table 11-19 requires modulo-32-bit rollover, no freezing/clearing, and durable
  retention across device restarts. Link reconnect must not reset totals. A RAM
  array or retained Context object alone does not meet device-restart retention;
  `IAuthenticationStatisticsStore` now provides the portable, association/role-isolated
  contract. No platform NVM backend is supplied. `Retained()` is false without a
  working backend; failed loads cannot overwrite unread retained totals. Threshold
  configuration persistence remains the configuration owner's responsibility.
- Table 7-8 row 11 uses native IOHandler::CloseForSecurity through the stack owner.
  Closure is posted off the receive/parser callback, checks the original connection
  identity, reuses native Reset/reconnect, and leaves serial/UDP untouched. Active
  authentication APDU arrays are not overwritten by threshold servicing. Actual
  TCP/TLS cancellation/reconnect remains unexecuted until P10.
- Indexes 15/16 now have operational Method 4/68 producers in `RemoteUpdateKeys`.
  Native G121/G122/CONFIRM publication is tested. Credential loading and G120
  serialization remain uncounted. See the remote-update report for validation.
- P6b consumes real reporting-threshold state for G121/G122 publication and G0V210, including retention/discontinuity quality and event snapshots; that wire support is implemented and user-validated (`ENGINEERING_EVIDENCE.md#record-08`, `ENGINEERING_EVIDENCE.md#record-07`, `ENGINEERING_EVIDENCE.md#record-09`). No full SA compliance is advertised by the runtime index enum, and G0V209 remains unavailable on the Outstation.
- Permanent tests: TestAuthenticationStatistics, TestSessionKeys and
  TestProductionAuthentication cover defaults/indexes, reporting versus Max
  boundaries, rollover/retention failures, real C/R/Aggressive accounting, native
  Error events, unknown users, suppression, replay, timeout, reconnect, restart
  throttling/rising IIN in both states, live-peer MAC-history retention, non-OK
  confirmations, foreign-user status transitions, pending-TX ownership and
  independent users. Tests are NOT RUN. Existing controlled FIX-01 (no successful
  authentication on OUTPUT_TOO_SMALL), FIX-02 (BUSY = 8/0/9, original pending
  exchange retained), and FIX-03 (unowned Outstation Error = 11/0/9) are preserved.
  Master unowned Error reception now has the same 11/0/9 boundary.

Historical P6a static-subset disposition remains recorded above. Current index
15/16 production is supplied by the opt-in remote Method 4/68 lifecycle. P6-OPEN-03
remains open; this does not claim full SA conformance.

## Remote Update Keys: Windows Methods 4/68 (2026-11-03)

`ENGINEERING_EVIDENCE.md#record-10` records source boundaries, normative references,
validation and OPEN decisions. SEC-T1-02 is implemented with configurable 2..16
users. SEC-T1-16 and SEC-T2-04 have locally verified configurable Methods 4/68:
Method 4 is independent; Method 68 requires explicit `allowMethod68`, provisioned
RSA-OAEP2048/SHA256 keys and DSA2048/256 keys. This verifies the implemented
operative choices, not every optional Table 7-16 method. RUK-OPEN-01/02 and
independent interoperability remain OPEN. SEC-T2-10 remains configuration
dependent: the standard SECADM role does not grant monitoring; an explicitly
provisioned private role and application policy are required for the requested
combined administrative/ordinary capabilities. No permissive default is added.
G0V209 and existing P4/P6/NEED_TIME limitations remain unchanged.


<a id="record-03"></a>

## Record 03 — ENGINEERING_EVIDENCE.md#record-03

# First implementation slice: G0V209

P6c status: Master parsing and typed delivery are implemented for received G0V209 UINTn. The current Outstation still has no complete supported SA version to advertise, so G0V209 READ returns OBJECT_UNKNOWN and V255 omits it. No version 0 or 5 is fabricated. P6c separately supplies G0V210 and the IEEE-required V254/V255 discovery dependency; see `ENGINEERING_EVIDENCE.md#record-09` for current validation status. The original first-slice scope below is retained as historical contract context.

**Decision:** Start with **Object Group 0 / Variation 209** (decimal), named **Secure Authentication Version**. This is a device attribute, **not** Group 209 and **not** an SA v5 authentication exchange.

## Normative traceability

| Source | Location | Finding |
|---|---|---|
| PROFILE | PDF p1 | Named as an additional supported object |
| PROFILE | PDF p4, Group 0 / Variation 209 row | READ 1, request qualifier `0x00`, RESPONSE 129, response qualifiers `0x00` / `0x17` |
| IEEE | 5.5.1-5.5.5, PDF pp190-192 | Standard attributes use index **0** and have a type/length/value payload |
| IEEE | Table 5-16, PDF p192 (printed p150) | `UINT` attribute type code = `2` (`0x02`) |
| IEEE | Annex A.1.1, PDF p480 (printed p438) | The variation represents the supported SA version, encoded as UINTn |
| IEEE | 5.5.2, PDF p191 (printed p149) | Attribute-capable outstations **shall include** G0V254 and G0V255 discovery behavior (dependency, not part of this small initial slice) |
| SEC | Table 1 row 1, PDF p3 | Product target is SA Version 5 |

## Interface/behavior contract: only as supported by source

| Aspect | Required behavior |
|---|---|
| Addressing | Read attribute **set index 0**, the standard device attribute set |
| Master request | Function `READ = 1 (0x01)`, object header `Group=0x00`, `Variation=0xD1` (209), qualifier `0x00` (8-bit start/stop), start=0, stop=0 |
| Outstation response | `RESPONSE = 129 (0x81)`, Group 0 / Variation 209; use only permitted qualifiers `0x00` or `0x17` as per supplied profile |
| Value | Type `UINT = 0x02`; one byte specifying value length; value is UINTn in little-endian order if multi-byte |
| Minimal representation for value 5 | Attribute value bytes **`02 01 05`** (`UINT`, length=1, value=5) **only when SA v5 is genuinely supported** |
| Role | Outstation returns the real supported version; Master reads and presents/consumes the attribute |
| READ grouping | Explicit Group 0 attribute read; **not** automatically returned by Class 0 scan (G60V1) |
| Unsupported attribute/error | Preserve baseline OpenDNP3 IIN/error semantics after inspecting current parser/handler; do not invent a second error-handling path |
| Concurrent/mixed reads | Existing APDU object-header parser and writer must remain the single mechanism |

**Reference request object header only**, excluding application control, function byte, link-layer, and fragment framing: `00 D1 00 00 00`. Do not treat this header as a complete DNP3 packet or the `02 01 05` example as validation of live SA support.

**Caution:** The format permits `UINTn` rather than an invented fixed-size C++ integer wire format; the reported **version number and response behavior must be correct**, independently of host byte order. Do not assert a constant `5` while the SA-v5 implementation is absent.

## Functions-first inspection checklist (future Codex task, no code yet)

1. Determine the exact local OpenDNP3 revision and whether G0 support already exists (object enum/metadata, Attribute decoder, generic writer, Outstation READ dispatch, Master result handler). Record actual file names, not guessed paths.
2. Locate existing reusable UINT write/read primitives and qualifier `0x00`/`0x17` handling. Do not modify Link/Transport/CRC/TLS.
3. Identify the **single** source of truth for the runtime SA version; if none exists, mark this functional dependency OPEN. Do not insert an invented hardcoded constant.
4. Outstation: add only missing behavior needed to answer the specific READ. Master: reuse existing explicit READ construction and response parser; add only missing support if proven absent.
5. After those two roles are implemented, perform the *user-requested* local Outstation -> Master check for exact bytes, index, data type and value. No tests or harnesses are created by this planning document.
6. Record status as *slice verified* if the narrow transaction passes. Record **Group 0 overall conformance as pending** until G0V254/G0V255 and other applicable obligations are completed.

## Explicit exclusions from first slice

- No G0V210, G0V254, G0V255 implementation within this slice without separate authorization.
- No G120 authentication messages, keys, challenge-response, MAC, session management or TLS.
- No generalized attribute framework until the existing code proves one is strictly necessary. Reuse existing structure first.
- No changes to STM32 board code, Windows UI, Class 0 configuration, other objects, or source tree structure.

**Acceptance gate:** A plan is ready; the actual patch is **blocked on the local source audit**. If true SA v5 support is not yet present, an honest G0V209 implementation must not advertise it. Decide correct unsupported capability behavior from IEEE/local implementation before committing a value.


<a id="record-04"></a>

## Record 04 — ENGINEERING_EVIDENCE.md#record-04

# Windows protocol issue register

Scope checked against `OPEN_ISSUES.md`, the IEEE and security traceability matrices, P4/P6 and remote-key reports, and relevant Master, Outstation, TLS and event TODOs. The private GitHub issue list was empty when queried. This is a rolling issue register. Local uncommitted candidates are identified explicitly. The implementation slice resolves G50 qualifiers, dangling class selectors and the G80 NEED_TIME acknowledgment. It also verifies four-anchor mutual TLS.

Baseline `60436c6ab62f6bd851aa1875797d010a5ac33836`. Published source anchors below refer to the source slice `275300426ed5e210fef69703c99475b11af15408`. Independent interoperability was not executed. The [IEEE 1815-2012 listing](https://standards.ieee.org/ieee/1815/5414/) was checked. No applicable official correction was established for the cited SA ambiguities. Original IEEE and product documents are available locally through [the source index](ENGINEERING_EVIDENCE.md#record-01).

First source slice validation used the existing Windows Release CMake configuration. Targets: dnp3-cli, unittests, integrationtests and asiotests. Build exit 0. Focused time/class/parser filter exit 0, 15 cases and 79 assertions. CTest exit 0, 8/8 targets, including 719 unit cases and 59,074 assertions, 12 integration cases and 241 assertions, and 7 ASIO cases and 105 assertions. Real CLI TCP profiles covered compatibility, SA Methods 4 and 68, negative security paths, and mutual TLS. The corresponding build and CTest logs are issue-release-build.log and issue-release-ctest.log in the local build directory.

The provisional SA policies below predate this slice. Their named evidence is existing Windows evidence. The source slice retains those policies. Newly unresolved rows do not claim a new issue-specific passing test.

The first source commit changed these paths:

- `cli/main.cpp`
- `cli/tests/ProcessSmoke.py`
- `opendnp3/cpp/lib/include/opendnp3/outstation/DefaultOutstationApplication.h`
- `opendnp3/cpp/lib/include/opendnp3/outstation/IOutstationApplication.h`
- `opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp`
- `opendnp3/cpp/lib/src/app/parsing/CountParser.cpp`
- `opendnp3/cpp/lib/src/outstation/AssignClassHandler.h`
- `opendnp3/cpp/lib/src/outstation/DefaultOutstationApplication.cpp`
- `opendnp3/cpp/lib/src/outstation/OutstationContext.cpp`
- `opendnp3/cpp/lib/src/outstation/WriteHandler.cpp`
- `opendnp3/cpp/tests/dnp3mocks/include/dnp3mocks/MockOutstationApplication.h`
- `opendnp3/cpp/tests/unit/TestMeasurementHandler.cpp`
- `opendnp3/cpp/tests/unit/TestProfileClasses.cpp`
- `opendnp3/cpp/tests/unit/TestProfileTime.cpp`

### TIME-QUALIFIERS - Absolute-time qualifiers

**Source**

IEEE Table 12-23 (p. 360), Device Profile pp. 8–9, PROFILE-038. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

G50V1 accepted an out-of-profile 16-bit count WRITE and handled indexed READ inconsistently.

**Affected implementation**

Shared. [opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp:121](../opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp#L121) · `Absolute time uses qualifier` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Require qualifier 07 before dispatch. Require one object in header-only READ. Preserve Master delivery of multiple values in qualifier-07 responses and Outstation WRITE cardinality checks. A global single-value gate broke the existing Master response case.

**Implementation**

[opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp:115](../opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp#L115) · `APDUParser::ParseQualifier` enforces qualifier 07 before object delivery. [opendnp3/cpp/lib/src/app/parsing/CountParser.cpp:53](../opendnp3/cpp/lib/src/app/parsing/CountParser.cpp#L53) · `CountParser::ParseHeader` rejects a header-only count other than one. The existing Outstation WRITE single-value check and Master response decoding are reused.

**Validation**

TestProfileTime.cpp · malformed G50V1 count rejects a mixed WRITE before application callbacks and existing positive READ/WRITE cases. TestMeasurementHandler.cpp · MeasurementHandlerTestSuite - parses g50v1 correctly and MeasurementHandlerTestSuite - rejects g50v1 with a 16-bit count before delivery. Asserts no callback for invalid qualifier, zero/count-two READ rejection, valid recovery, and two-value Master response compatibility. Release build and CTest exit 0 at `275300426ed5e210fef69703c99475b11af15408`. No independent peer exercised.

**Status**

VERIFIED_LOCAL

**Remaining dependency**

Independent peer comparison. NEED_TIME acknowledgment is tracked separately under IIN-WRITE-SCOPE.

### CLASS-EDGE - Trailing class selector

**Source**

IEEE Table 12-24 (p. 360), Device Profile pp. 9–10, PROFILE-043–046. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

A dangling G60 header returned success without an assignment.

**Affected implementation**

Outstation. [opendnp3/cpp/lib/src/outstation/OutstationContext.cpp:1035](../opendnp3/cpp/lib/src/outstation/OutstationContext.cpp#L1035) · `IINField OContext::HandleAssignClass` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Report PARAM_ERROR when the native handler finishes with a pending selector. Keep completed pairs and the native application callback contract. Rolling back completed pairs would require a separate transactional semantic change.

**Implementation**

[opendnp3/cpp/lib/src/outstation/AssignClassHandler.h:40](../opendnp3/cpp/lib/src/outstation/AssignClassHandler.h#L40) · `AssignClassHandler::HasPendingAssignment` exposes the pending selector to [opendnp3/cpp/lib/src/outstation/OutstationContext.cpp:1035](../opendnp3/cpp/lib/src/outstation/OutstationContext.cpp#L1035) · `OContext::HandleAssignClass`. The response sets PARAM_ERROR for a dangling selector and leaves earlier complete assignments applied.

**Validation**

TestProfileClasses.cpp · ProfileClasses - ASSIGN_CLASS reports an incomplete trailing pair. Asserts isolated dangling header, one completed pair before a dangling selector, and a later valid request. Release build and CTest exit 0 at `275300426ed5e210fef69703c99475b11af15408`. No independent peer exercised.

**Status**

VERIFIED_LOCAL

**Remaining dependency**

Audit unsupported qualifier diagnostics separately.

### CA-CAPACITY - Four trusted authorities

**Source**

Security amendment p. 4, Table 1 row 14. TLS trust-store capacity is a product requirement. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Four simultaneous anchors lacked execution evidence.

**Affected implementation**

Shared TLS. [opendnp3/cpp/lib/src/channel/tls/SSLContext.cpp:114](../opendnp3/cpp/lib/src/channel/tls/SSLContext.cpp#L114) · `value.load_verify_file` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Use the native OpenSSL PEM trust bundle. A second trust store is unnecessary. Exercise four independent issuers in each endpoint role, with different peer issuers in each session.

**Implementation**

Production uses the existing CA loader. [cli/tests/ProcessSmoke.py:289](../cli/tests/ProcessSmoke.py#L289) · `tls_cases` loads one bundle in both peers and rotates the four issuers across client and server roles.

**Validation**

cli/tests/ProcessSmoke.py · tls_cases, pc-tls. Four-anchor trust bundle, real READ and control, and exact operation counts. Existing untrusted peer, wrong identity and expiry cases reject dispatch. Release build and CTest exit 0 at `275300426ed5e210fef69703c99475b11af15408`. No independent peer exercised.

**Status**

VERIFIED_LOCAL

**Remaining dependency**

Certificate rotation and revocation scheduling remain separate.

### P4-OPEN-01 - Authorization Error code

**Source**

IEEE §7.5.5.7 (p. 241) versus Annex A.45.7.2.2. Device Profile p. 11 G120V7. Security amendment p. 5 authorization. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

The clause and annex disagree on Code 5 versus Code 7.

**Affected implementation**

Outstation. [opendnp3/cpp/lib/src/outstation/OutstationContext.cpp:1239](../opendnp3/cpp/lib/src/outstation/OutstationContext.cpp#L1239) · `void OContext::SendAuthorizationError` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Retain provisional Annex codes 5 for unsupported MAC and 7 for denied authorization. Mapping both conditions to one code could trigger incorrect key recovery.

**Implementation**

Existing provisional runtime behavior retained in this slice.

**Validation**

TestProductionAuthentication.cpp · authorization Error suppression reopens only on successful key change. pc-negative exercises authenticated application denial with unchanged invocation count. Existing test evidence is local. Independent validation remains open.

**Status**

IMPLEMENTED_PROVISIONAL

**Remaining dependency**

Independent peer must exercise unsupported-MAC and denied-authorization paths and inspect G120V7.

### P6-OPEN-01 - Reporting threshold equality

**Source**

IEEE §7.6.1.4.2 (pp. 242–243) versus §11.9.10.2 (pp. 349–350). Device Profile p. 12. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

The cited provisions disagree at equality.

**Affected implementation**

Shared. [opendnp3/cpp/lib/src/auth/AuthenticationStatistics.cpp:61](../opendnp3/cpp/lib/src/auth/AuthenticationStatistics.cpp#L61) · `>= reportingThresholds[n]` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Retain provisional >= for reporting. Keep the independent protocol Max comparisons from Table 7-8. Using a single comparison for both changes recovery limits.

**Implementation**

Existing provisional runtime behavior retained in this slice.

**Validation**

TestAuthenticationStatistics.cpp, Security statistics - reporting equality and five independent moving maxima. TestSecurityStatEvents.cpp covers local event delivery. The unfiltered Windows suite passed. Independent validation remains open.

**Status**

IMPLEMENTED_PROVISIONAL

**Remaining dependency**

Independent threshold tests at T−1, T and T+1.

### P6-OPEN-02 - Critical messages sent

**Source**

IEEE Table 7-6 (pp. 206–207), §7.5.3.2 and §7.5.3.3. Device Profile p. 12. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Table language counts receipt while the procedure counts response.

**Affected implementation**

Master and Outstation transmit accounting. [opendnp3/cpp/lib/src/outstation/OutstationContext.cpp:414](../opendnp3/cpp/lib/src/outstation/OutstationContext.cpp#L414) · `OContext transmit accounting` and [opendnp3/cpp/lib/src/master/MasterContext.cpp:609](../opendnp3/cpp/lib/src/master/MasterContext.cpp#L609) · `MContext transmit accounting` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Retain accounting at actual owned transmit and avoid double-counting Aggressive CONFIRM. Receipt counting would include replies that never transmit.

**Implementation**

Existing provisional runtime behavior retained in this slice.

**Validation**

TestProductionAuthentication.cpp and TestAuthenticationStatistics.cpp cover authentication transmission accounting. Existing test evidence is local. Independent validation remains open.

**Status**

IMPLEMENTED_PROVISIONAL

**Remaining dependency**

Independent ordinary Reply and mandatory Aggressive CONFIRM counter comparison.

### P6-OPEN-03 - Failure threshold ownership

**Source**

IEEE §7.5.2.1 (p. 203), Table 7-8 rows 5/6/10/12 (pp. 215–222). Device Profile pp. 10–12. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Control Challenge USR=0 and unverified Reply USR do not authenticate a recovery subject.

**Affected implementation**

Shared. [opendnp3/cpp/lib/src/auth/AuthenticationStatistics.cpp:82](../opendnp3/cpp/lib/src/auth/AuthenticationStatistics.cpp#L82) · `void AuthenticationStatistics::AuthenticationFailed` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Retain association accounting and the existing authenticated-owner recovery paths. Guessing a configured user or resetting all users can let a hostile packet evict unrelated sessions.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

TestAuthenticationStatistics.cpp, Security statistics - unknown failures never invent recovery ownership or key changes. The unfiltered Windows suite passed. Automatic recovery when no user is attributable remains unverified.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Independent multilateral ownership evidence or authoritative per-user rule for unattributable failures.

### RUK-OPEN-01 - SCS wrap

**Source**

IEEE §7.5.5.5 (pp. 239–240) versus Annex A.45.10. Device Profile p. 11, Security amendment p. 4 row 16. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Annex wrap conflicts with strict sequence monotonicity.

**Affected implementation**

Outstation. [opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.cpp:671](../opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.cpp#L671) · `status.seqNum <= users[index].statusSequence` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Retain fail-closed provisional monotonicity and named tombstones across methods and authority changes. Reset on method change permits replay of old certification.

**Implementation**

Existing provisional runtime behavior retained in this slice.

**Validation**

TestRemoteUpdateKeys.cpp · SCS wrap remains rejected across authority-key changes and SCS and tombstones cannot be reset by changing certification methods. Existing test evidence is local. Independent validation remains open.

**Status**

IMPLEMENTED_PROVISIONAL

**Remaining dependency**

Independent wrap-boundary exchange and approved administrative trust reset procedure.

### RUK-OPEN-02 - DSA signature representation

**Source**

IEEE Annex A.45.10/A.45.14 and Table 7-16 (p. 245). Device Profile p. 11, Security amendment p. 4 row 16. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

IEEE does not settle the r/s representation used by independent peers.

**Affected implementation**

Shared. [opendnp3/cpp/lib/src/crypto/OpenSSLCryptoProvider.cpp:251](../opendnp3/cpp/lib/src/crypto/OpenSSLCryptoProvider.cpp#L251) · `Result DSASHA256Verify` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Retain provisional strict DER per RFC 5758 §3.1 and RFC 3279 §2.2.2. Accepting arbitrary alternate encodings would enlarge the verification surface.

**Implementation**

Existing provisional runtime behavior retained in this slice.

**Validation**

TestRemoteUpdateKeys.cpp DSA positive/negative checks and pc-method68 runtime change. Local mutual success leaves the wire representation provisional. Existing test evidence is local. Independent validation remains open.

**Status**

IMPLEMENTED_PROVISIONAL

**Remaining dependency**

Independent Method 68 authority and endpoint V10/V14 tests using known signatures.

### G120V8 - Runtime User Certificate

**Source**

IEEE Annex A.45.8, Device Profile p. 11, Security amendment p. 4 row 16. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Codec exists without an authenticated runtime certificate lifecycle.

**Affected implementation**

Shared. [opendnp3/cpp/lib/src/app/parsing/FreeFormatParser.cpp:127](../opendnp3/cpp/lib/src/app/parsing/FreeFormatParser.cpp#L127) · `IsValidAuthObject(const Group120Var8` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep V8 inactive until the chain trust, certificate profile, user binding and activation lifecycle are defined. Parsing a nonempty blob cannot grant trust.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

Specify the trust profile and implement verification, expiry, replay and negative chain tests.

### G0V209 - SA capability advertisement

**Source**

IEEE §5.5 (pp. 148–154), Annex A.1.1 (p. 438), Device Profile p. 4. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Master can decode an external version. Outstation capability is omitted.

**Affected implementation**

Outstation. [opendnp3/cpp/lib/src/outstation/DeviceAttributeSelection.cpp:7](../opendnp3/cpp/lib/src/outstation/DeviceAttributeSelection.cpp#L7) · `DeviceAttributeSelection::Select` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep OBJECT_UNKNOWN and omit discovery entry until the advertised SA version is defensible. Advertising 5 based on local Method 4/68 tests would overstate coverage.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

Resolve runtime SA capability gaps and test discovery plus explicit read.

### STAT-RETENTION - Durable security statistics

**Source**

IEEE §11.9.10/Table 11-19 (pp. 349–350). Device Profile p. 12. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

A storage interface exists. Production restart retention and per-point discontinuity rearming remain incomplete.

**Affected implementation**

Shared. [opendnp3/cpp/lib/src/auth/AuthenticationStatistics.cpp:16](../opendnp3/cpp/lib/src/auth/AuthenticationStatistics.cpp#L16) · `AuthenticationStatistics::AuthenticationStatistics` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Preserve explicit discontinuity when a continuity record is unavailable. Clearing quality on startup would falsely imply continuity.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

Implement Windows storage, rollback/corruption handling and restart assertions.

### G122-UNTIMED - Historical untimed events

**Source**

IEEE Annex A.47 and §11.9.10. Device Profile p. 12 G122V1/V2. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

An event recorded without usable UTC cannot satisfy an explicitly timed V2 request.

**Affected implementation**

Outstation. [opendnp3/cpp/lib/src/outstation/SecurityStatEventPublisher.cpp:23](../opendnp3/cpp/lib/src/outstation/SecurityStatEventPublisher.cpp#L23) · `bool SecurityStatEventPublisher::Report` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Retain the event for untimed/class selection. Fabricating an occurrence timestamp or discarding the historical event loses evidence.

**Implementation**

Existing provisional runtime behavior retained in this slice.

**Validation**

TestSecurityStatEvents.cpp covers unavailable/restored clock, V1 fallback and retained untimed events. Existing test evidence is local. Independent validation remains open.

**Status**

IMPLEMENTED_PROVISIONAL

**Remaining dependency**

Independent peer behavior for V2-only polls and untimed backlog.

### FC6-MASTER - Typed no-response control

IEEE 1815-2012 section 4.4.5 and Table 14-5. The typed Master API now sends
FC6 in Compatibility mode and reports local transmit completion. The B3a
tests in `a1d3ddcc096f329bdcc7f07da167a596eb0cb2e6` cover sequence wrap and the local
Master/Outstation control boundary. See [ENGINEERING_EVIDENCE.md#record-06](ENGINEERING_EVIDENCE.md#record-06).

The Compatibility-mode subset is verified. REQUIRED mode rejects FC6.
Authenticated FC6 and independent-peer interoperability remain open.

### IIN-WRITE-SCOPE - NEED_TIME clear and rearm

**Source**

IEEE §4.5.5 (p. 83), Table 12-26 (p. 361). Device Profile p. 10 G80V1. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

The Outstation rejected a zero written to NEED_TIME. Clearing its internal IIN alone would leave the application-owned indication asserted.

**Affected implementation**

Outstation. [opendnp3/cpp/lib/src/outstation/WriteHandler.cpp:33](../opendnp3/cpp/lib/src/outstation/WriteHandler.cpp#L33) · `WriteHandler::ProcessHeader` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Delegate a valid acknowledgment to the application. Use a monotonic hold interval and preserve timestamp quality. An internal IIN override would discard application policy. Treating acknowledgment as a time write would report synchronization without a clock update.

**Implementation**

[opendnp3/cpp/lib/src/outstation/WriteHandler.cpp:56](../opendnp3/cpp/lib/src/outstation/WriteHandler.cpp#L56) · `WriteHandler::ProcessHeader` accepts one zero at index 4 with qualifier 00. [opendnp3/cpp/lib/include/opendnp3/outstation/IOutstationApplication.h:64](../opendnp3/cpp/lib/include/opendnp3/outstation/IOutstationApplication.h#L64) · `IOutstationApplication::ClearNeedTime` defaults to unsupported. [opendnp3/cpp/lib/src/outstation/DefaultOutstationApplication.cpp:48](../opendnp3/cpp/lib/src/outstation/DefaultOutstationApplication.cpp#L48) · `DefaultOutstationApplication::ClearNeedTime` temporarily suppresses the request for half the configured refresh interval and rearms when still due. A valid absolute time write clears that hold. The [cli/main.cpp:611](../cli/main.cpp#L611) · `OutstationApplication::ClearNeedTime` override uses the existing application mutex. Existing binary consumers of the virtual interface require rebuilding.

**Validation**

TestProfileTime.cpp, ProfileTime - NEED_TIME clear delegates to the application without writing time, and ProfileTime - default NEED_TIME acknowledgment preserves clock quality and rearms. The native wire fixture checks unsupported app, invalid one and qualifier 01, accepted zero, subsequent IIN and zero time writes. The application fixture checks unchanged UNSYNCHRONIZED quality and immediate rearm with zero interval. Release build, focused tests and CTest exit 0 at `275300426ed5e210fef69703c99475b11af15408`.

**Status**

VERIFIED_LOCAL

**Remaining dependency**

The G80V1 exchange was checked in a native wire fixture. Independent peer or dedicated TCP acknowledgment coverage remains open. No new typed Master acknowledgment API was introduced.

### RESTART-APP - Cold restart application behavior

**Source**

IEEE §4.4 restart functions, Table 12-23 (p. 360). Device Profile p. 12. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Native hook exists. Default simulated application does not restart the device.

**Affected implementation**

Outstation. [opendnp3/cpp/lib/src/outstation/OutstationContext.cpp:1001](../opendnp3/cpp/lib/src/outstation/OutstationContext.cpp#L1001) · `IINField OContext::HandleRestart` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep explicit application policy instead of exiting or resetting before the restart response transmits.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

Design deferred restart after response ownership and test durable credential reload.

### AGGRESSIVE-SCOPE - Aggressive function matrix

**Source**

IEEE §7.5.3.3 and Annex A.45.3/A.45.9. Device Profile pp. 10–11, Security amendment p. 3 rows 4–5. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Local control and selected read/confirmation paths work. Full selected function matrix needs review.

**Affected implementation**

Shared. [opendnp3/cpp/lib/src/auth/AggressiveMode.cpp:13](../opendnp3/cpp/lib/src/auth/AggressiveMode.cpp#L13) · `namespace opendnp3` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Preserve exact G120 envelope and MAC coverage. Do not infer arbitrary function support from a passing control.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

Enumerate functions and test replay and authorization per direction.

### TIMEOUT-ZERO - Zero security timeout

**Source**

IEEE §7.5 response lifecycle and Table 7-14. Security amendment p. 3 row 3. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Native configuration accepts 100–120000 ms in 100 ms steps. Product range includes zero.

**Affected implementation**

Shared. [opendnp3/cpp/lib/src/auth/SessionKeys.cpp:103](../opendnp3/cpp/lib/src/auth/SessionKeys.cpp#L103) · `bool SessionKeys::ValidConfig` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep rejection of zero while semantics are unsettled. Treating zero as infinite would remove a security deadline.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Determine authorized zero behavior and test boundary configuration and expiry.

### MAC-SELECTION - MAC choice

**Source**

IEEE Clause 7 algorithm selection. Security amendment p. 3 row 9. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Product MAC boxes do not establish the required selection.

**Affected implementation**

Shared. [opendnp3/cpp/lib/src/auth/AuthenticationSession.cpp:48](../opendnp3/cpp/lib/src/auth/AuthenticationSession.cpp#L48) · `settings.replyTimeoutMs` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Retain implemented SHA choices and fail closed on unsupported algorithms. Silent fallback changes authentication policy.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Obtain selected MAC set and verify any added provider.

### METHOD-SELECTION - Additional remote methods

**Source**

IEEE Table 7-16 (p. 245), Security amendment p. 4 row 16 and p. 5 row 4. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Method 4/68 operate locally. Additional choices are unresolved.

**Affected implementation**

Shared. [opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.cpp:80](../opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.cpp#L80) · `bool RemoteUpdateKeys::` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Retain explicit method choice and no algorithm substitution.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Product selection of additional methods and independent interop.

### SEC-T1-11 - TLS cipher list

**Source**

Security amendment pp. 3–4 row 11. TLS 1.3 names are defined by RFC 8446. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Product table places TLS 1.2-style names in the TLS 1.3 list.

**Affected implementation**

Shared TLS. [opendnp3/cpp/lib/src/channel/tls/SSLContext.cpp:88](../opendnp3/cpp/lib/src/channel/tls/SSLContext.cpp#L88) · `SSL_CTX_set_ciphersuites` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep separate native cipher namespaces and reject invalid settings. Reinterpreting names would change the requirement.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

pc-tls proves actual TLS versions and rejects invalid settings.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Obtain corrected product cipher list.

### SEC-T1-13 - Cipher-change timeout

**Source**

Security amendment p. 4 row 13. No DNP wire mapping established. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Product requests 1–60 s without establishing which TLS operation is timed.

**Affected implementation**

Shared TLS. [opendnp3/cpp/lib/src/channel/tls/SSLContext.cpp:41](../opendnp3/cpp/lib/src/channel/tls/SSLContext.cpp#L41) · `SSLContext::ApplyConfig` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Do not map cipher-change timeout to an unrelated response or handshake timer.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Define the required event, protocol versions and completion semantics.

### SEC-T1-15 - Revocation checking

**Source**

Security amendment p. 4 row 15. Certificate policy is external to IEEE DNP application objects. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Chain, SAN and expiry are verified. Revocation policy and scheduling are absent.

**Affected implementation**

Shared TLS. [opendnp3/cpp/lib/src/channel/tls/SSLContext.cpp:114](../opendnp3/cpp/lib/src/channel/tls/SSLContext.cpp#L114) · `value.load_verify_file` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Retain existing verification. A CRL/OCSP policy needs explicit fail-closed outage and refresh behavior.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

Specify trusted revocation sources and interval. Implement the Windows checks and revoked-peer tests.

### LOCAL-PASSWORD - Local configuration access

**Source**

Security amendment p. 5 row 7. Local access policy is outside IEEE wire semantics. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Diagnostic CLI has no local RTU password gate.

**Affected implementation**

CLI. [cli/Security.cpp:283](../cli/Security.cpp#L283) · `Options ParseOptions` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Use a separately specified Windows administrative authentication contract. Do not repurpose SA keys as console passwords.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Define protected configuration operations, account recovery and authentication policy.

### RTU-SA-DEFAULT - Startup policy

**Source**

Security amendment p. 5 row 9. IEEE Clause 7. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Library requires authentication by default. The diagnostic CLI exposes explicit compatibility behavior.

**Affected implementation**

CLI. [cli/Security.cpp:337](../cli/Security.cpp#L337) · `AuthenticationConfig Authentication` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep diagnostic and deployed RTU policy separate. A CLI test mode cannot establish deployed security policy.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Specify RTU packaging and confirm production startup policy.

### ROLE-PROVISIONING - Production roles

**Source**

IEEE Table 7-12 (p. 228), Security amendment p. 5 row 10 and p. 6 row 4. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Native application policy and certified roles exist. Production authority and combined-role policy are unprovisioned.

**Affected implementation**

Shared. [opendnp3/cpp/lib/src/auth/AuthenticationSession.cpp:144](../opendnp3/cpp/lib/src/auth/AuthenticationSession.cpp#L144) · `bool AuthenticationSession::Authorize` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Retain fail-closed role and application checks. Avoid broadening standard roles to satisfy a convenience CLI scenario.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Provision and test actual administrator and ordinary role policies.

### SEC-CONFIG - Security parameter coverage

**Source**

Security amendment p. 5 row 11 and Table 1 pp. 3–4. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Some timeouts, users and methods are configurable. The complete product configuration is incomplete.

**Affected implementation**

CLI. [cli/Security.cpp:283](../cli/Security.cpp#L283) · `Options ParseOptions` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Extend existing typed options only for defined parameters. Generic numeric knobs can silently change security semantics.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

Resolve dependent MAC, TLS and credential configuration decisions.

### RTU-HARDWARE - Unused hardware ports

**Source**

Security amendment p. 6 row 1. No applicable IEEE DNP wire behavior established. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

No physical RTU port audit exists.

**Affected implementation**

RTU deployment. [cli/main.cpp:707](../cli/main.cpp#L707) · `int main` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep the Windows boundary. A localhost result cannot substitute for deployed evidence.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Inspect the production device and disable unused interfaces.

### RTU-NETWORK - Unused network services

**Source**

Security amendment p. 6 row 2. No applicable IEEE DNP wire behavior established. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

A Windows diagnostic listener cannot establish RTU service inventory.

**Affected implementation**

RTU deployment. [cli/main.cpp:424](../cli/main.cpp#L424) · `MakeChannel` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep the Windows boundary. A localhost result cannot substitute for deployed evidence.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Audit the deployed service and firewall configuration.

### RTU-HARDENING - Unnecessary users

**Source**

Security amendment p. 6 rows 3–4. No applicable IEEE DNP wire behavior established. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Native DELETE revokes a user. Production inventory and least privilege remain unverified.

**Affected implementation**

RTU deployment. [opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.cpp:671](../opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.cpp#L671) · `status.seqNum <=` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep the Windows boundary. A localhost result cannot substitute for deployed evidence.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Audit actual identities and verify disablement in the deployed profile.

### RTU-PROVISIONING - Production credential provisioning

**Source**

Security amendment p. 6 row 5. No applicable IEEE DNP wire behavior established. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Test-only credential provisioning is separate from production trust.

**Affected implementation**

RTU deployment. [cli/Security.cpp:413](../cli/Security.cpp#L413) · `int AuthorityWorker` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep the Windows boundary. A localhost result cannot substitute for deployed evidence.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Supply the production credential authority and secret lifecycle.

### RTU-CREDENTIAL-HASH - RTU credential storage

**Source**

Security amendment p. 6 row 6. No applicable IEEE DNP wire behavior established. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Windows Credential Manager stores usable protocol keys. RTU password storage policy is unverified.

**Affected implementation**

RTU deployment. [cli/Security.cpp:9](../cli/Security.cpp#L9) · `WindowsAuthenticationCredentials` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep the Windows boundary. A localhost result cannot substitute for deployed evidence.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Specify password hashing separately from protocol key storage.

### RTU-FIRMWARE - Firmware signature verification

**Source**

Security amendment p. 6 rows 7–8. No applicable IEEE DNP wire behavior established. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Firmware signing and loading are outside Windows diagnostic scope.

**Affected implementation**

RTU deployment. [cli/main.cpp:707](../cli/main.cpp#L707) · `int main` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep the Windows boundary. A localhost result cannot substitute for deployed evidence.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

BLOCKED_EXTERNAL

**Remaining dependency**

Validate the production update and boot chain.

### IEEE-ENUMERATION - Level 4 obligation audit

**Source**

IEEE §12.1.1 and parsing tables (pp. 351 onward). Supplied Device Profile excerpt pp. 1–2 selects Level 3 plus listed features. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Traceability is a provisional set of work packages.

**Affected implementation**

Shared. [opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp:115](../opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp#L115) · `ParseResult APDUParser::ParseQualifier` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Enumerate mandatory/conditional obligations by function, object, qualifier and role. Counting objects alone would miss lifecycle requirements.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

Complete the normative enumeration and validate applicable Windows behaviors.

### CLASS-QUALIFIER-DIAGNOSTICS - Unsupported class header errors

**Source**

IEEE Table 12-24 (p. 360), Device Profile pp. 9–10. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Different class functions return different IIN for count headers.

**Affected implementation**

Outstation. [opendnp3/cpp/lib/src/outstation/AssignClassHandler.h:42](../opendnp3/cpp/lib/src/outstation/AssignClassHandler.h#L42) · `bool IsAllowed` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Preserve rejection. Changing diagnostic IIN requires exact function-specific error evidence, independently of the trailing-header fix.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

Confirm response codes per function and add independent malformed qualifier fixtures.

### MASTER-UNEXPECTED-IIN - Unexpected response IIN TODO

**Source**

IEEE §4.2–4.5 application response ownership. Device Profile p. 10. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Source TODO leaves IIN handling for unexpected responses open.

**Affected implementation**

Master. [opendnp3/cpp/lib/src/master/MasterContext.cpp:449](../opendnp3/cpp/lib/src/master/MasterContext.cpp#L449) · `should we process IIN bits for unexpected responses` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Review IIN processing after authentication and correlation. Ignoring every unsolicited IIN could lose legitimate recovery signals.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

Reproduce wrong-sequence IIN impact and verify authenticated restart and time-sync behavior.

### TLS-ACCEPT-RETRY - TLS listen retry TODO

**Source**

Security amendment p. 5 row 2. Listener recovery is transport policy. Original tracking: OPEN_ISSUES.md, engineering reports or the source marker at the cited anchor.

**Problem**

Native source asks whether to retry a failed listen start.

**Affected implementation**

Shared TLS. [opendnp3/cpp/lib/src/channel/tls/TLSServerIOHandler.cpp:83](../opendnp3/cpp/lib/src/channel/tls/TLSServerIOHandler.cpp#L83) · `should we retry` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Preserve existing failure signaling until transient versus permanent errors can be distinguished.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

Reproduce a transient bind/retry failure without masking a configuration error.

### EVENT-DEFAULT-VARIATION - Class reselect after an explicit variation

**Source**

IEEE 1815-2012 §4.1.5.3 (p. 17), §5.1.5 and Table 5-3 (p. 107), and Table 12-24 (p. 360) for class and variation selection. §4.2.2.4.3–5 (pp. 22–23) for CON, UNS and SEQ. Device Profile PDF p. 7, PROFILE-026–030, covers G32V0 default selection and G32V1/V2/V4 event encodings. Original tracking in the EventSelection.cpp default-variation TODO.

**Problem**

An explicit G32V2 READ set the buffered event's selectedVariation. On the next READ after confirmation timeout, EventStorage::Unselect reset the selection state of an ordinary analog event and left that variation in place. SelectByClass selected the event without choosing a new variation, so a class poll could return G32V2 for an event configured with G32V1.

**Affected implementation**

Outstation [opendnp3/cpp/lib/src/outstation/event/EventSelection.cpp:26–44](../opendnp3/cpp/lib/src/outstation/event/EventSelection.cpp#L26) (EventSelection::SelectByClass). Related [EventSelection.h:54–78](../opendnp3/cpp/lib/src/outstation/event/EventSelection.h#L54) (SelectByTypeGeneric), [EventStorage.cpp:196–204](../opendnp3/cpp/lib/src/outstation/event/EventStorage.cpp#L196) (Unselect), and [EventTypeImpl.h:46–50](../opendnp3/cpp/lib/src/outstation/event/EventTypeImpl.h#L46) (SelectDefaultVariation). Tested source 87964278f6579ce37f88053fee415b0518ad40e1.

**Engineering decision**

A Class 1, 2 or 3 READ selects a class without specifying a reporting variation for each event. Table 5-3 uses the configured default for that case. Restore the default when the class selection claims the unselected record. This mirrors the typed default path. Setting it during serialization could override a valid explicit READ.

**Implementation**

SelectByClass uses the existing IEventType::SelectDefaultVariation operation for each eligible unselected record. The operation copies the stored default into selectedVariation. The same event snapshot, class, selection counters and confirmation ownership are used.

**Validation**

[opendnp3/cpp/tests/unit/TestOutstationEventResponses.cpp:117–159](../opendnp3/cpp/tests/unit/TestOutstationEventResponses.cpp#L117), OutstationEventResponsesTestSuite - Class poll uses the default variation after an explicit event response times out. The original regression reproduced G32V2 instead of G32V1 before the fix. The final test runs both G32V1 and timestamped G32V4 defaults. It verifies an explicit G32V2 response at SEQ 0, completion of transmission, confirmation timeout, and re-selection at SEQ 1 with the original index, value, flags and timestamp where encoded. Late SEQ 0 confirmations in Idle and during the new wait cannot retire the event. The correct SEQ 1 confirmation reports zero remaining events in each class once. A duplicate confirmation produces no second callback, and a subsequent class poll is empty.

Windows MSVC Release build exited 0. Focused event, security-event, class and measurement filters passed 72 cases and 534 assertions with exit 0. Two complete Release CTest runs each passed 8/8 targets with exit 0. Each run covered 721 unit cases and 59,186 assertions, 12 integration cases and 241 assertions, 7 ASIO cases and 105 assertions, and the PC compatibility, Method 4, Method 68, negative security and mutual TLS scenarios. Logs in build-p6b-o1/native include event-default-release-build.log and event-default-ctest-1.log / event-default-ctest-2.log.

**Status**

VERIFIED_LOCAL

**Remaining dependency**

The expiry and re-selection sequence was verified with the native wire fixture. Dedicated TCP coverage of that sequence and independent-peer interoperability validation remain open.

### METHOD68-RESTART-TIMEOUT - Intermittent post-restart READ timeout

**Source**

IEEE 1815-2012 §7.5.1.3, §7.5.2.3.5 and Table 7-8 for Challenge/Reply and state ownership, §7.5.5.5–7 and §7.6.1.4.9/Table 7-16 for remote key change, and Annex A.45.10–15/Tables A-10–13 for Method 68. Security amendment p. 4 row 16. DSA representation remains tracked under RUK-OPEN-02.

**Problem**

The historical Method 68 run timed out on an authenticated READ after both peers restarted. Its original diagnostics are insufficient to identify the cause. In this investigation the original fixed-port fixture failed before reaching that point. Three trials saw the Master open while its own Outstation did not open. One lost communications during Update Key verification before reconnect. A separate local CLI pair was present. The shared default TCP endpoint was independently shown to be a fixture failure mechanism by deliberately occupying it.

**Affected implementation**

[ProcessSmoke.py:102–115](../cli/tests/ProcessSmoke.py#L102) (loopback_port and connected), [177–241](../cli/tests/ProcessSmoke.py#L177) (secure) and [245–278](../cli/tests/ProcessSmoke.py#L245) (invalid_credentials), with TLS rejection peers allocated at [364](../cli/tests/ProcessSmoke.py#L364). Method 68 uses [RemoteUpdateKeys.cpp:85](../opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.cpp#L85) (Load), [294](../opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.cpp#L294) (Install), [549–598](../opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.cpp#L549) (VerifyCertification and ReadAsymmetricChange), and [616](../opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.cpp#L616) (Request). [OpenSSLCryptoProvider.cpp:251](../opendnp3/cpp/lib/src/crypto/OpenSSLCryptoProvider.cpp#L251) checks strict DER and DSA-SHA256. [WindowsAuthenticationCredentials.cpp:137–190](../opendnp3/cpp/lib/src/auth/WindowsAuthenticationCredentials.cpp#L137) loads the committed record by marker, generation and digest and writes the alternate record before publishing its marker. [AuthenticationSession.cpp:64–82](../opendnp3/cpp/lib/src/auth/AuthenticationSession.cpp#L64) clears live sessions before loading durable credentials. Tested revision e1a1ebbe5b82dab5ffa9f1bd6e7184ea807e8ddc.

**Engineering decision**

Method 68 could reach the previous stale timestamp mechanism because both methods use the same verified Control dispatch and Monitoring response paths. The relevant paths are [OutstationContext.cpp:347](../opendnp3/cpp/lib/src/outstation/OutstationContext.cpp#L347) (BeginTx), [1102](../opendnp3/cpp/lib/src/outstation/OutstationContext.cpp#L1102) (CountControlAuthentication), [MasterResponder.cpp:184](../opendnp3/cpp/lib/src/master/MasterResponder.cpp#L184) (Respond), [OutstationChallenger.cpp:283](../opendnp3/cpp/lib/src/outstation/OutstationChallenger.cpp#L283) (Reply) and [AggressiveMode.cpp:356](../opendnp3/cpp/lib/src/auth/AggressiveMode.cpp#L356) (Verify). This shared path establishes reachability before the clock fix. It does not establish the cause of the historical Method 68 failure. Isolate the demonstrated fixture collision through an OS-selected loopback port and retain the selected endpoint across a scenario's reconnect and process restart. The socket allocation has a brief handoff window before the CLI binds.

**Implementation**

The PC fixture supplies its loopback endpoint to both peers. Production authentication, wire encoding, credential storage and timeout values are untouched. [TestRemoteUpdateKeys.cpp:1131](../opendnp3/cpp/tests/unit/TestRemoteUpdateKeys.cpp#L1131), RemoteUpdateKeys - restart loads only verified active credentials and preserves pending recovery, now exercises both methods after a lost V15. It checks common-user readiness and KSQ on the live peers, rejects a replayed old key change on a recreated Outstation without a journal write or KSQ advance, then completes fresh V15 recovery at increasing monotonic times. Only the owning user consumes a new Outstation KSQ. Neither recreated peer treats an Update Key proof as an installed Session Key. The original response-dispatch regression and Aggressive replay cases in TestProductionAuthentication.cpp also ran.

**Validation**

The baseline shared-port batch recorded 6 passes and 4 failures, aggregate exit 1. Secret-redacted timelines for both peers are in build-p6b-o1/native/method68-restart-2.log through method68-restart-5.log. The occupied-port control failed with the fixed endpoint and passed with the private endpoint against the same reserved default listener. Control logs are method68-port-control.log and method68-occupied-default-before-1.log / method68-occupied-default-after-1.log. This control establishes a fixture defect and does not attribute all earlier failures to it.

All 10 private-port Method 68 scenarios completed with recorded exit 0, and the batch process exited 0. Every fresh profile exercised normal authentication, repeated key changes, reconnect, both peer process restarts, persisted credential verification, READ and CROB, Aggressive Mode, and rejection without additional command execution. Each trace recorded 13 G120V6 and four G120V14 transmissions, a reconnect, and four clean peer exits. See method68-private-independent.log and method68-private-1.log through method68-private-10.log. The Windows Release build exited 0. Focused SA passed 78 cases and 36,576 assertions with exit 0. Two serial full CTest runs passed all 8 targets with exit 0. Each covered 721 unit cases and 59,271 assertions, 12 integration cases and 241 assertions, 7 ASIO cases and 105 assertions, and all five PC scenarios. The first parallel run exited 8 after concurrent ASIO and integration fixtures overlapped on fixed ports beginning at 20000. The second parallel run passed 8/8, and pc-method68 passed in both. See method68-full-ctest-1.log / method68-full-ctest-2.log and method68-serial-ctest-1.log / method68-serial-ctest-2.log.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

The current Windows Method 68 lifecycle is verified locally at the revision above. The historical post-restart timeout remains open because it was neither reproduced nor causally attributed. If it recurs, capture the owning peer, authentication sequence, monotonic timestamps and task completion before changing production behavior. Independent interoperability and RUK-OPEN-02 remain separate.

### SA-TCP-INTERMITTENT - Outstation session reset during authenticated response dispatch

**Source**

IEEE §7.5.1.3 (PDF p. 234), §7.5.2.3.5 and Table 7-8 (PDF pp. 256–257 and following), and §7.6.1.4.4–5 (printed p. 243). Security amendment p. 4 row 16. Original observations in issue-event-ctest.log and issue-event-ctest-serial.log.

**Problem**

Outstation RouteAuthentication captured an arrival time before processing an authenticated request. Processing could enter BeginTx, which observed a later time on the common session while preparing a native or Aggressive monitoring response. The outer control-message accounting then fed the earlier timestamp into SessionKeys::Observe. That anti-rollback check reset an otherwise valid session. The next owned monitoring Challenge, CONFIRM or READ could no longer use the matching common session. Windows scheduling determined whether the calls crossed a millisecond boundary.

**Affected implementation**

Outstation [OutstationContext.cpp:347–397](../opendnp3/cpp/lib/src/outstation/OutstationContext.cpp#L347) (BeginTx), [1102–1129](../opendnp3/cpp/lib/src/outstation/OutstationContext.cpp#L1102) (CountControlAuthentication), [1657–1669](../opendnp3/cpp/lib/src/outstation/OutstationContext.cpp#L1657) (G120V2 verified dispatch) and [1734–1745](../opendnp3/cpp/lib/src/outstation/OutstationContext.cpp#L1734) (Aggressive dispatch). Shared [SessionKeys.cpp:168–179](../opendnp3/cpp/lib/src/auth/SessionKeys.cpp#L168) (Observe) and [342–349](../opendnp3/cpp/lib/src/auth/SessionKeys.cpp#L342) (CountAuthentication). Tested source 174facf1bfb4b6c344fd5ebd83ae96ae7cdd8367.

**Engineering decision**

Sample the monotonic executor clock when charging verified incoming control traffic after response dispatch. Preserve the rollback guard, deadline and key-count rules, association and KSQ ownership, MAC verification, replay checks and authorization. Clamping timestamps inside SessionKeys would mask a real clock regression. Increasing response timeouts would leave the invalidated session unusable.

**Implementation**

OutstationContext.h:166 and OutstationContext.cpp:1102–1129 remove the receive-time argument from CountControlAuthentication. Both authenticated dispatch callers use the fresh timestamp. TestProductionAuthentication.cpp:328–364 adds “ProductionAuthentication - response dispatch can advance the clock before control accounting”. The static G30 regression advances time by one millisecond during authorization and checks real key negotiation, Challenge/Reply and Aggressive cases, unchanged KSQ and successful Master completion. Temporary metadata tracing was removed from production sources.

**Validation**

Before the fix, the deterministic test failed both generated scenarios at session readiness (exit 2). Isolated Method 4 runs failed 3 of 4. Three unfiltered Release CTest runs exited 8, 8 and 0. The first failed pc-method4 after pc-method68. The second started with a passing pc-method4 and failed native integration. CLI PC tests use RUN_SERIAL. The two peers shut down with exit 0 and each trial used a unique test credential profile. The metadata-only trace reproduced the reset in method4-diag-2.log:542–563. Outstation received Aggressive READ SEQ 4 at 1687997 ms, transmitted its response at the next millisecond, then accounted at 1687997 ms and reset common KSQ 2 to 0 with 993 messages still available. Subsequent G120V1/V2 and READ traffic preceded the Master timeout. Outstation user 1 reported not ready while independent users remained ready. This demonstrates a production lifetime defect independent of event selection and of CTest ordering.

After the fix, a Release build of dnp3-cli, unittests, integrationtests and asiotests exited 0 with the pre-existing event candidate excluded. The focused [sa-dispatch-clock],[production-sa] run exited 0 with 43 cases and 32,758 assertions. Six isolated Method 4 runs exited successfully. Three complete CTest runs using -C Release -V -j 2 --timeout 180 each exited 0 with 8/8 targets, including 720 unit cases and 59,158 assertions, 12 integration cases and 241 assertions, 7 ASIO cases and 105 assertions, and the Method 4, Method 68, negative and TLS process scenarios. Logs in build-p6b-o1/native include method4-fix-build.log, method4-fixed-1.log through method4-fixed-6.log and method4-fixed-full-1.log through method4-fixed-full-3.log.

**Status**

VERIFIED_LOCAL

**Remaining dependency**

No Method 4 or native TCP failure recurred in the six isolated and three full post-fix runs. Earlier native TCP failures had no equivalent per-peer capture, so their historical cause is not established independently. The earlier Method 68 observation remains separately open. Independent interoperability was not exercised.

### NATIVE-PORT-COLLISION - Windows TCP/TLS test isolation

**Problem**

Native ASIO and integration fixtures shared fixed TCP ports,
including 20000. Concurrent tests and external listeners could
interfere with otherwise valid test execution. The ASIO TCP mock
also ignored the server's effective bound port.

**Implementation**

TCPServer.cpp:85-95 and TLSServer.cpp:79-85 capture the actual
listener endpoint after binding.

TCPServerIOHandler.cpp:52 and TLSServerIOHandler.cpp:54
propagate the assigned port.

DNP3ManagerImpl.cpp:93-108 and 204-222 expose the effective
server port through the channel.

IChannel.h and IListener.h expose GetBoundPort, returning zero
when no bound listener port is available.

Native ASIO and integration fixtures use isolated dynamic
loopback ports. Restart scenarios preserve their selected port.

**Validation**

Windows Release build passed.

Focused TCP/TLS tests: 3 passed.
Integration tests: 12 passed.
ASIO tests: 7 passed.

Complete CTest: 5 successful runs at each of -j 1, -j 2,
and -j 4, totaling 15 successful full runs.

Each completed run passed 8/8 targets.
An occupied-port-20000 parallel run also passed.
Final serial verification exited 0.
git diff --check exited 0.

Evidence logs are retained in the local build directory.

**Status**

VERIFIED_LOCAL

**Remaining dependency**

Independent CI validation remains outstanding.
Adding public virtual interface methods requires rebuilding
binary consumers of the library.


<a id="record-05"></a>

## Record 05 — ENGINEERING_EVIDENCE.md#record-05

# Device Profile measurement/event and control coverage

Baseline: `develop`, `39e175da7716bb14745e62773107181a1a00dd41`. Scope: 31 rows for G1/G2/G3/G4/G10/G30/G32/G40. IMPLEMENTED; focused manual validation and final review PASS. Builds/tests were executed by the user, not the agent. All 31 rows retain IMPLEMENTED status; no complete per-row VERIFIED claim. Existing AGENTS.md and Catch edits are excluded. No push.

## Coverage

All 31 selected matrix rows are IMPLEMENTED, not VERIFIED. Source inspection establishes the native paths below. Existing tests or a focused CTO run do not prove every function/qualifier/variation at runtime. Other matrix rows are unchanged. Extra existing variations do not enlarge the selected product requirements.

| Profile rows | Selected variations and encoding | Native paths reused | Status |
| --- | --- | --- | --- |
| 003-005: G1 | V0 default/assignment; V1 packed 1-bit state; V2 state/flags octet | BinarySpec Database selection, StaticWriters, RangeParser, Binary callback, AssignClassHandler | IMPLEMENTED |
| 006-009: G2 | V0 default; V1 state/flags; V2 plus UINT48 time; V3 plus UINT16 offset/CTO | EventBuffer Binary selection, ASDUEventWriteHandler/EventWriters, CountIndexParser, Binary callback, MeasurementHandler CTO | IMPLEMENTED; malformed CTO dependency fixed |
| 010-012: G3 | V0 default/assignment; V1 packed 2-bit states; V2 state/flags octet | DoubleBitBinarySpec Database selection, DoubleBitfieldRangeWriteIterator/StaticWriters, RangeParser, DoubleBitBinary callback, AssignClassHandler | IMPLEMENTED |
| 013-016: G4 | V0 default; V1 state/flags; V2 plus UINT48 time; V3 plus UINT16 offset/CTO | EventBuffer DoubleBitBinary selection, ASDUEventWriteHandler/EventWriters, CountIndexParser, DoubleBitBinary callback, MeasurementHandler CTO | IMPLEMENTED; malformed CTO dependency fixed |
| 017-018: G10 | V0 default; V2 output status/flags octet | BinaryOutputStatusSpec Database selection, StaticWriters, RangeParser, BinaryOutputStatus callback | IMPLEMENTED |
| 020-025: G30 | V0 default/assignment; V1 flags+INT32; V2 flags+INT16; V3 INT32; V4 INT16; V5 flags+FLT32 | AnalogSpec Database selection, StaticWriters/WriteConversions, RangeParser, Analog callback, AssignClassHandler | IMPLEMENTED |
| 026-030: G32 | V0 default; V1 flags+INT32; V2 flags+INT16; V4 flags+INT16+UINT48 time; V5 flags+FLT32 | EventBuffer Analog selection, ASDUEventWriteHandler/EventWriters, CountIndexParser, Analog callback | IMPLEMENTED |
| 031-034: G40 | V0 default; V1 flags+INT32; V2 flags+INT16; V3 flags+FLT32 | AnalogOutputStatusSpec Database selection, StaticWriters/WriteConversions, RangeParser, AnalogOutputStatus callback | IMPLEMENTED |

Exact source prefix: `opendnp3/cpp/lib/src/`:

- Static READ: `outstation/ReadHandler.cpp`, `outstation/Database.cpp::SelectAll/SelectRange`, `outstation/StaticDataMap.h::select_all/select`, `outstation/StaticWriters.cpp`.
- Event READ/publication: `outstation/event/EventBuffer.cpp::SelectMaxCount`, `EventSelection.h::SelectByTypeGeneric`, `ASDUEventWriteHandler.cpp`, `EventWriters.h` in that directory. Bounded occurrence snapshots and overflow use `EventUpdate.h`, `EventStorage.cpp`, `EventWriting.cpp`; native `outstation/ResponseContext.cpp` and response states own fragmentation/confirmation/removal. These modules are unchanged.
- Master decode: `app/parsing/RangeParser.{h,cpp}`, `CountIndexParser.{h,cpp}`, `app/MeasurementFactory.h`, `app/MeasurementTypes.cpp`, `master/MeasurementHandler.{h,cpp}` and public `opendnp3/master/ISOEHandler.h`.
- Class assignment: `outstation/AssignClassHandler.cpp`, `Database.cpp::AssignClassToAll/AssignClassToRange`, `StaticDataMap.h::assign_class`; application RecordClassAssignment remains native. No new persistence guarantee.
- Models/codecs: `opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/groups/Group{1,2,3,4,10,30,32,40}.scala` and `gen/objects/Group{1,2,3,4,10,30,32,40}.{h,cpp}`. All 16 codec files match existing official P6c generator output after whitespace normalization. No regeneration/generated edits.

## Functions, qualifiers and behavior

Static READ function 1: 00/01/06; RESPONSE 129: 00/01. Selected G1V0/G3V0/G30V0 also support ASSIGN_CLASS 22 with 00/01/06 and native class-header sequencing. G10/G40 rows describe status, not control commands.

Event READ function 1: 06/07/08 for V0 and selected explicit variations; native count selection bounds quantity. RESPONSE 129 and UNSOLICITED_RESPONSE 130: 17/28. Outstation writes 28; Master parses both widths. Scheduling, retries, confirmations and event removal remain native/configuration dependent. No duplicate-delivery policy changes.

V0 selects configured variations and is not a response body. Numeric encodings are little-endian; packed states are low-bit first with zero padding. `outstation/StaticDataMap.cpp::check_for_promotion` already preserves abnormal quality by promoting G1V1 to V2, G3V1 to V2, and G30V3/V4 to V1/V2. Flagless receive values assume online. Existing WriteConversions/DownSampling provide narrowing/overrange behavior. Raw point indexes and typed callbacks are retained.

G2V3/G4V3 use the preceding CTO in the same fragment. CTO V1/V2 conveys synchronized/unsynchronized quality; Outstation EventWriters starts another CTO/header on backward time, oversized UINT16 offset or quality change. Event occurrence values remain independent of later database updates.

## IEEE/profile references and confirmed gap

Device Profile PDF pp4-8 and matrix rows above. IEEE 1815-2012 Tables 12-2/3/4/5/6/14/16/19 (printed pp352-358); A.2 (pp488-489), A.3 (pp490-492), A.4 (pp493-494), A.5 (pp495-497), A.6.2 (p500), A.14.1-5 (pp565-569), A.16.1/2/4/5 (pp581-582,585-587), A.19.1-3 (pp610-612). Related types/flags/float: 11.9.1/2/4/6/8, 11.6, 11.3.5. Product-selected objects apply even when beyond Level 3 minimums; no full Level 4 claim.

Confirmed gap: IEEE Table 12-23 (printed p360) requires CTO qualifier 07, quantity 1; A.3.3/A.5.3 and A.24 (pp654-657) define the preceding reference. Baseline parser accepted multi-value/08 CTO headers and all-objects 06 markers. MeasurementHandler ignored multi-value CTOs, retaining an earlier reference; malformed input could deliver relative events with stale timestamps.

Fix: APDUParser rejects response G51 qualifiers other than 07; CountParser rejects CTO quantities other than 1 on the first validation pass. This necessary G51 dependency is the only protocol change. No partial callbacks or unsolicited confirmation on malformed fragments. Valid CTO paths, no-contents READs and ordinary event limited counts remain unchanged. G120/G121/G122, SA state machines, TLS and G0V209 are untouched.

## Tests and validation

`opendnp3/cpp/tests/unit/TestProfileMeasurements.cpp`, `[profile-measurements]`: 8 permanent cases, manually executed by the user: PASS, 160 assertions, exit code 0. Covers valid G2V3/G4V3 with both prefix widths/CTO qualities; next CTO replacement; malformed quantities/08/06 with preceding measurement/reference; zero/truncated CTOs; ordinary event limited READs; malformed native unsolicited no-delivery/no-CONFIRM; valid native solicited fragment CONFIRMs.

Manual validation supplied by the user in this chat:

| Check | Result |
| --- | --- |
| MSVC Release `unittests` build, including dependencies | PASS; exit code 0 |
| `[profile-measurements] -r compact` | PASS; 8 cases / 160 assertions; exit code 0 |
| `*APDUParsing*,*MeasurementHandler*,*ReadGrp2Var3* -r compact` | PASS; 46 cases / 193 assertions; exit code 0 |
| Focused final review and scoped/staged whitespace checks | PASS; no additional confirmed defect |

The build emitted dependency FetchContent deprecation warnings; it completed successfully. Later shell errors came from pasted prompt/output text after the successful focused run, not from the executable. No agent build/test execution. Existing tests outside the exact filters above were not rerun; prior-phase results are not substituted for this task's validation.

Successful manual validation and final review satisfy the authorization for one local commit containing only the seven paths below; the commit hash is recorded in the final chat response. Existing AGENTS.md and Catch edits remain excluded. No push. Full per-row protocol/interoperability verification remains outstanding, so all selected coverage stays IMPLEMENTED rather than VERIFIED.

## Measurement/event changed paths (previous commit)

```
DNP3_PDD_PLAN/PROFILE_MATRIX.csv
DNP3_PDD_PLAN/ENGINEERING_EVIDENCE.md#record-05
REPO_MAP.md
opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp
opendnp3/cpp/lib/src/app/parsing/CountParser.cpp
opendnp3/cpp/tests/unit/CMakeLists.txt
opendnp3/cpp/tests/unit/TestProfileMeasurements.cpp
```

## Control command completion

Current baseline: `develop`, `77980d5a68a1e58e854ed9e6787585a2a75774cb`. This extension adds profile rows 019 and 035-037 to the coverage above. Status: IMPLEMENTED, committed at that baseline and validated by the focused tests below. Earlier measurement/event test results above are historical and are not control validation. Not VERIFIED: no interoperability, Test Harness, embedded or full profile/IEEE conformance run.

| Profile row | Applicable behavior and native evidence | Status |
| --- | --- | --- |
| 019, G12V1 CROB | code/count UINT8, on/off UINT32, status UINT8; Master CommandSet/CommandTask/TypedCommandHeader; Outstation CommandResponseHandler/CommandActionAdapter/ICommandHandler | IMPLEMENTED |
| 035, G41V1 | INT32 followed by UINT8 command status; same native command machinery and typed AnalogOutputInt32 callbacks | IMPLEMENTED |
| 036, G41V2 | INT16 followed by UINT8 command status; typed AnalogOutputInt16 callbacks | IMPLEMENTED |
| 037, G41V3 | IEEE FLT32 followed by UINT8 command status; typed AnalogOutputFloat32 callbacks | IMPLEMENTED |

Native source prefix: `opendnp3/cpp/lib/src/`. Models are `opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/groups/Group12.scala` and `Group41.scala`; generated codecs in `gen/objects/Group12.{h,cpp}` and `Group41.{h,cpp}` match existing official P6c generator evidence after whitespace normalization. No generator/model/codec change or regeneration. `app/parsing/CountIndexParser` supplies two-pass indexed command parsing; `master/CommandSet.cpp`, `CommandSetOps.cpp`, `TypedCommandHeader.h`, `CommandTask.cpp` and `outstation/CommandResponseHandler`, `CommandActionAdapter`, `OutstationContext` supply the existing vertical path. Existing permanent MasterCommandRequests, MasterMultiCommandRequests, TypedCommandHeader and OutstationCommandResponses tests are retained.

Both request qualifier widths 17/28 are reused, with corresponding echoed response headers/indexes. Outstation SELECT/OPERATE/DIRECT_OPERATE/DIRECT_OPERATE_NR functions 3/4/5/6 are parsed and dispatched through the native command interface. Function 6 sends no command response. Master typed SELECT/OPERATE (3/4) and DIRECT_OPERATE (5) remain supported. The supplied profile targets an Outstation; Master function 6 issuance is optional. The user explicitly chose to preserve the native Master API: no typed function 6 API or authenticated no-response task lifecycle is added. Generic PerformFunction is not advertised as a correct no-response command API because it awaits a response.

IEEE 1815-2012: 4.4.4/4.4.4.1-3, Rules 1-9 and Tables 4-9/4-10 (printed pp48-54); 4.4.5 (pp54-55); Table 12-8 (p354), Table 12-20 (p358); A.8.1 (pp505-510, including Table A-1/A-2 and the obsolete QU rule), A.20.1-3 (pp615-617). Device Profile PDF pp3,6,8. Hardware-specific point models, pulse timing, zero-count behavior, interlocks, allowed analog ranges and actual physical execution remain application ICommandHandler responsibilities; this task does not invent a hardware model or treat a successful wire response as proof of physical movement.

### Confirmed gaps and minimal fixes

- Partial SELECT acceptance: objects rejected as TOO_MANY_OPS were not counted, making AllCommandsSuccessful true after a partially rejected batch. Count every request object, including rejected objects; a failed SELECT cannot arm OPERATE.
- Selection lifecycle: intervening requests did not cancel a selection; a successful OPERATE did not consume it; failed new SELECTs and link loss could leave stale state. Apply Table 4-9 after authentication admission, cancel/consume native selection as appropriate, and clear on disconnect. A changed same-sequence SELECT is discarded; an exact retry uses the cached response without restarting the timer. Native timeout remains exclusive at the configured boundary. Existing maxRx/maxTx checks and command limits remain in force; empty control requests now return PARAM_ERROR (or no response for function 6) without callbacks.
- Exact identity: ControlState and RequestHistory used only length plus CRC-16. Distinct, valid same-length commands with a CRC collision could substitute for selected output values or be mistaken for retries. Replace fingerprint-only identity with owned byte snapshots. Both buffers are allocated once per Outstation using the existing configured maxRxFragSize; total additional payload storage is twice that limit (4096 bytes at default 2048). Normal parsing/retry requests do not allocate new buffers. Oversize command bodies are rejected before callbacks.
- Master SELECT guard: typed value comparisons did not enforce the complete wire echo, so raw CROB differences, float signed-zero changes or extra objects could permit OPERATE. CommandTask retains the successfully formatted SELECT body (bounded by its existing TX buffer) and refuses OPERATE unless response bytes match and IIN2.0/2.1/2.2/2.4 are clear. Existing per-point failure callbacks remain native. TypedCommandHeader compares raw CROB and floating-point fields on both response legs, while CommandSetOps observes handler errors for SELECT and OPERATE/direct responses. This snapshot allocates once for a SELECT task, not per response.
- ALREADY_ACTIVE status 5 lacked IIN2.4; set ALREADY_EXECUTING as required by Table 4-10. Existing NOT_SUPPORTED/PARAM_ERROR handling is retained; local-control IIN still comes from the application.

Same-sequence authenticated SELECT retries/discards must not transfer ownership. The two existing validated-user binding sites (challenge/reply and aggressive request release) now retain the original selectUser whenever native ControlState identifies that SELECT sequence. Policy authorization, MAC verification, replay checking, key state and the OPERATE user comparison remain unchanged and precede native dispatch. No unauthenticated fast path, alternate execution path or authentication state machine is added. No changes to G120/G121/G122 codecs, statistics, event publication, TLS or G0V209.

### Focused permanent tests and current validation

`opendnp3/cpp/tests/unit/TestProfileControls.cpp`, `[profile-controls]`: 21 permanent cases, PASS (user-run): 21 cases / 588 assertions, exit code 0. Covers all four selected variations and both index widths; functions 3/4/5/6 on the Outstation; Master SBO; command limits; failed/intervening/new selections; exact retry timer boundary; duplicate execution prevention; CRC-collision substitution and retry identity; reconnect; command statuses/IIN; malformed/truncated/empty requests with no partial callbacks; Master error IIN, extra/truncated echo, raw CROB and signed-zero mismatch; failed SELECT statuses; no automatic control retries on timeout; bounded snapshot ownership/sequence wrap.

Existing authenticated operation/policy/ownership tests were selected narrowly for command regression (50 cases / 235 assertions); no broad SA suite was run. The new bounded-selection unit case is not a new MAC/SA integration result. Existing historical authentication baseline failures remain historical; do not infer a new pass/fail from them. All four rows stay IMPLEMENTED, not VERIFIED; targeted tests do not establish physical operation, full profile/IEEE conformance or independent interoperability.

Current manual build/test: PASS. Static review and `git diff --check`: PASS.

| Check | Result |
| --- | --- |
| MSVC Release `unittests` build, including dependencies | PASS |
| `[profile-controls] -r compact` | PASS; 21 cases / 588 assertions; exit code 0 |
| Command regression selection | PASS; 50 cases / 235 assertions; exit code 0 |
| Combined validated total | PASS; 71 cases / 823 assertions |

The control implementation, its permanent test file and the test registration are committed at `77980d5a68a1e58e854ed9e6787585a2a75774cb`; no control code is left in the working tree. Remote synchronization is recorded in the final chat response. Independent AGENTS.md and Catch edits remain excluded.

## Control command changed paths (commit `77980d5`)

```
DNP3_PDD_PLAN/PROFILE_MATRIX.csv
DNP3_PDD_PLAN/ENGINEERING_EVIDENCE.md#record-05
REPO_MAP.md
opendnp3/cpp/lib/src/master/CommandSetOps.cpp
opendnp3/cpp/lib/src/master/CommandTask.cpp
opendnp3/cpp/lib/src/master/CommandTask.h
opendnp3/cpp/lib/src/master/TypedCommandHeader.h
opendnp3/cpp/lib/src/outstation/CommandResponseHandler.h
opendnp3/cpp/lib/src/outstation/ControlState.h
opendnp3/cpp/lib/src/outstation/OutstationContext.cpp
opendnp3/cpp/lib/src/outstation/RequestHistory.cpp
opendnp3/cpp/lib/src/outstation/RequestHistory.h
opendnp3/cpp/tests/unit/CMakeLists.txt
opendnp3/cpp/tests/unit/TestProfileControls.cpp
```


<a id="record-06"></a>

## Record 06 — ENGINEERING_EVIDENCE.md#record-06

# FC6-B3 evidence and traceability audit

## Scope and assessment

This audit covers IEEE 1815-2012 §4.4.5 no-application-response behavior and
the selected command obligations in Table 14-5: `IEEE-CONTROLS`,
`L4-BINARY-CONTROL`, `L4-ANALOG-CONTROL`, the eight G12V1/G41V1-3 FC6 wire
rows, and Device Profile rows `PROFILE-019` and `PROFILE-035` through
`PROFILE-037`.

The eight detailed FC6 rows now record `VERIFIED_SUBSET` for Master and
Outstation, with aggregate outcome `PARTIAL`. The subset is the tested typed
FC6 request and no-response path in Compatibility mode, not full control or
product conformance. The broader IEEE control rows remain partial or
implemented-but-unverified. The Profile rows likewise retain their existing
partial or implemented-but-unverified assessment; FC6 coverage does not
complete their FC3/FC4/FC5 requirements or the whole profile row. `PROFILE-019`
now has `local_code_status=PARTIAL`, matching its Outstation status. No coverage
percentage is increased by this audit.

## Evidence by role

**Master transmission and completion.** The command task selects FC6 and uses
the shared typed command writer. The focused `[fc6-master]` tests cover CROB
and G41V1/V2/V3 payloads with 8-bit and 16-bit index qualifiers, exactly one
FC6 application request, local completion only after `OnTxReady()`, and
`CommandStatus::UNDEFINED` rather than a remote success status. Seventeen
sequential requests establish application sequence progression modulo 16.
The subsequent ordinary SELECT/OPERATE request verifies sequence continuity
and unchanged normal command behavior.
Advancing the mock timer after each locally completed request confirms no
application retry. Separate focused cases cover transmit timeout, disconnect
before transmit completion, and rejection when authentication is REQUIRED.
The permanent unit coverage is in
[TestProfileControls.cpp](../opendnp3/cpp/tests/unit/TestProfileControls.cpp);
the process scenarios are in
[ProcessSmoke.py](../cli/tests/ProcessSmoke.py).

**Outstation parsing and execution.** Unit fixture assertions exercise FC6
parsing and the CROB/analog command handlers for both index qualifier widths.
The `pc-compat` real TCP process scenario uses the project's own Master and
Outstation: it observes one simulated execution and subsequent output readback
for CROB and G41V1 through G41V4. The G41V4 process check is outside the eight
detailed G41V1-3 wire rows. It also sends a valid FC6 command to unsupported
output index 10; local transmission completes, while the
Outstation execution count does not increase. This is same-project process
coverage, not independent-peer interoperability evidence.

There is no solicited application response for FC6. A successful local
transmission is not proof of remote execution; the CLI and tests do not treat
it as a successful remote command acknowledgment.

## Recorded execution

The final tested repository HEAD before committing the B3a tests was
`0b8026098e2c5564eb95eaa7641daf3b3425a52c`. The B3a test commit is
`a1d3ddcc096f329bdcc7f07da167a596eb0cb2e6`; it is on `develop` and contained
in `origin/develop`. Matrix `last_verified_revision` values point to the
reported tested HEAD, which contains the FC6 implementation exercised by the
tests.

The reported FC6-B3a Release build passed. The focused `[fc6-master]` run
passed 5 cases / 392 assertions. Final Windows Release CTest passed 8/8 in
110.00 seconds. The `pc-compat`, `pc-method4`, `pc-method68`, `pc-negative`
and `pc-tls` process scenarios passed. Test logs were supplied externally;
they are not committed repository artifacts. No full-suite assertion total is
claimed here.

Reproduction commands (with local build paths substituted):

```powershell
.\unittests.exe "[fc6-master]"
ctest.exe --test-dir <release-build-directory> -C Release --output-on-failure
python .\cli\tests\ProcessSmoke.py --exe <path-to-dnp3-cli.exe> --work-dir <writable-test-directory> --only compat
python .\cli\tests\ProcessSmoke.py --exe <path-to-dnp3-cli.exe> --work-dir <writable-test-directory> --only method4
python .\cli\tests\ProcessSmoke.py --exe <path-to-dnp3-cli.exe> --work-dir <writable-test-directory> --only method68
python .\cli\tests\ProcessSmoke.py --exe <path-to-dnp3-cli.exe> --work-dir <writable-test-directory> --only negative
python .\cli\tests\ProcessSmoke.py --exe <path-to-dnp3-cli.exe> --work-dir <writable-test-directory> --only tls
```

## Remaining boundaries

- FC6 is rejected in REQUIRED mode. Authenticated FC6's special
  challenge/aggressive handling under §7.5.2.3.2(i) is not implemented.
- No independent-peer interoperability test has been performed.
- Class-assignment wire auditing and broader FC3/FC4/FC5 control coverage
  remain open; the aggregate rows and Profile assessments were not promoted.
- The same-project TCP checks prove simulated Outstation invocation and
  readback in those scenarios only; they do not prove execution by a remote
  production device.


<a id="record-07"></a>

## Record 07 — ENGINEERING_EVIDENCE.md#record-07

# P6b-M1 implementation and manual-validation report

Status: IMPLEMENTED and manually validated. Focused final review and `git diff --check`: PASS. Builds and executable tests were run by the user, not the agent. The authorized local commit is created after this report is finalized; its hash is recorded in the final chat response. No push is authorized or performed.

## Baseline and normative scope

Branch `develop`, baseline `0b030c425e540276119e5321cf352d3ce0e36659` (completed O2). Existing AGENTS.md and TestProductionAuthentication.cpp/Catch edits are excluded and preserved.

IEEE 1815-2012 references: 7.5.2.2 (printed pp204-207; own/cross-association identity and raw indexes), A.46.1 (pp758-759; G121V1 flags/UINT16 Association ID/UINT32 count), A.47.1/A.47.2 (pp760-763; G122V1/V2 and UINT48 occurrence time), Table 12-63 (p374; G121 response qualifiers 00/01/17/28 and G122 response qualifiers 17/28), 4.5.5 (p83) and 10.3 (pp298-299; absence of synchronization need not inhibit functions). The supplied Device Profile p12 lists these objects; M1 supplies the Master parsing/delivery counterpart to the completed Outstation publication.

## Implementation

- Reuse the unchanged generated Group121/Group122 ReadTarget codecs and SecurityStat model. No Scala/generated artifacts changed; no regeneration needed.
- Register G121V1 with RangeParser and G121V1/G122V1/G122V2 with CountIndexParser. Existing required-size checks and two-pass APDU validation reject incomplete fragments before application callbacks.
- Extend IAPDUHandler's native typed range/prefix dispatch and MeasurementHandler's response handling. A Master-only whitelist enforces the supported response qualifiers and rejects variation-zero response headers.
- Append an optional default no-op ISOEHandler::Process(HeaderInfo, ICollection<Indexed<SecurityStat>>) overload. Existing handlers remain source-compatible; binary clients must rebuild for the expanded C++ virtual interface. Callback collection lifetime/ownership remains the native synchronous SOE contract.
- Preserve every raw UINT16 point index, received Association ID (including zero), UINT32 value, flag byte, header metadata and occurrence-time value. Do not remap indexes modulo 18, merge associations, accumulate counters, or write received values into local authentication statistics. Association ID zero is relative to the receiving Master stack/its handler.
- Untimed G121V1/G122V1 deliver INVALID time quality. G122V2 carries no synchronization-quality bit, so the Master preserves its absolute occurrence value but conservatively delivers TimestampQuality::UNSYNCHRONIZED (accuracy unknown) in both SecurityStat.time and HeaderInfo. No current IIN/CTO/local clock is used to invent historical accuracy or change occurrence time.
- Solicited PollTaskBase and unsolicited MContext already share MeasurementHandler. Existing fragmentation, confirmation and retransmission policies are reused. The current native unsolicited path delivers repeated responses again; M1 preserves that policy and adds no deduplication state.
- Shared parser recognition would otherwise permit invalid mixed WRITEs to reach earlier handlers before an unsupported security object was rejected. A narrow WriteHandler whitelist guard preserves the existing first-pass rejection and PARAM_ERROR, including zero side effects from preceding time writes. No Outstation READ/event behavior, authentication state transition or cryptography changed.

## Permanent tests

TestMasterSecurityStatistics.cpp covers all four G121 qualifiers and both G122 prefixes/variations; raw flag and association/index preservation; maximum indexes/count/time values; mixed-object order and fragment callbacks; no association merging; every truncated-byte prefix of representative messages; malformed qualifiers/count/ranges; source compatibility through the unchanged PrintingSOEHandler; native solicited fragments/CONFIRMs; unsolicited delivery and isolated Master stacks; malformed unsolicited rejection; and unchanged Outstation mixed-WRITE rejection before side effects.

The user manually ran all 13 new cases: PASS, 587 assertions, exit code 0. The existing parser/measurement and G121/G122 Outstation regression selection also passed: 78 cases, 1351 assertions, exit code 0, as shown in the user's supplied output. Historical O2 results are not presented as M1 execution.

## Exact M1 paths

```
DNP3_PDD_PLAN/ENGINEERING_EVIDENCE.md#record-07
REPO_MAP.md
opendnp3/cpp/lib/include/opendnp3/master/ISOEHandler.h
opendnp3/cpp/lib/src/app/parsing/CountIndexParser.cpp
opendnp3/cpp/lib/src/app/parsing/IAPDUHandler.cpp
opendnp3/cpp/lib/src/app/parsing/IAPDUHandler.h
opendnp3/cpp/lib/src/app/parsing/RangeParser.cpp
opendnp3/cpp/lib/src/master/MeasurementHandler.cpp
opendnp3/cpp/lib/src/master/MeasurementHandler.h
opendnp3/cpp/lib/src/outstation/WriteHandler.h
opendnp3/cpp/tests/dnp3mocks/include/dnp3mocks/MockSOEHandler.h
opendnp3/cpp/tests/unit/CMakeLists.txt
opendnp3/cpp/tests/unit/TestMasterSecurityStatistics.cpp
```

## Validation and disposition

Verified existing build directory: `C:/Users/poimu/Desktop/DNP3-EXTRA/build-p6b-o1/native`, Visual Studio 17 2022/x64, SA crypto and tests enabled. Target `unittests` builds its opendnp3 dependency. Verified CMake executable: `C:/Program Files/CMake/bin/cmake.exe`. Verified existing test executable path: `C:/Users/poimu/Desktop/DNP3-EXTRA/build-p6b-o1/native/cpp/tests/unit/Release/unittests.exe`; the user rebuilt this executable for M1 and supplied the successful build/test output.

Manual validation recorded in this chat:

| Check | Result |
| --- | --- |
| MSVC x64 Release `unittests` build, including opendnp3/dnp3mocks dependencies | PASS; user supplied output and exit code 0 |
| `[master-security-statistics] -r compact` | PASS; 13 cases, 587 assertions; user supplied output and exit code 0 |
| `*APDUParsing*,*MeasurementHandler*,[security-stat-read],[security-stat-events] -r compact` | PASS; 78 cases, 1351 assertions; user supplied output and exit code 0 |
| Focused final code review | PASS; no additional defect found |
| `git diff --check` and scoped staged review | PASS before local commit |
| Generator/model synchronization | Existing codecs/model reused unchanged; no regeneration necessary |

No build, compiler, unit/integration executable or suite was run by the agent for M1. Existing authentication failures (historically 11 cases / 60 assertions matching the pre-O2 baseline) were not rerun in this M1 validation step; no new authentication-regression result is claimed. No interoperability/Test Harness or embedded validation was performed. Existing native unsolicited repeat-delivery policy and the public C++ virtual-interface rebuild requirement remain as documented above.

The original M1 instruction explicitly authorizes one local commit after successful manual validation and focused review. Only the 13 manifest paths belong in it; independent AGENTS.md and Catch edits stay outside it. Do not push or start another phase.

G0V210, Outstation functionality changes, authentication-state changes, platform persistence, and subsequent phases remain excluded. Existing NEED_TIME/continuity/P6a ambiguities remain unchanged. No full IEEE/SA v5/Level 4 or interoperability conformance is claimed.


<a id="record-08"></a>

## Record 08 — ENGINEERING_EVIDENCE.md#record-08

# P6b-O2 implementation and validation report

Status: **COMPLETE for the assigned native P6b-O2 implementation**, including the timestamp-blocker correction. Lack of synchronization does not inhibit events. A usable absolute occurrence time supports V2; no usable time produces an immutable V1 event for ordinary reporting. An explicit V2 request cannot convert an untimed historical event; its retention behavior is documented below. This is not an IEEE, SA v5, Level 4, or interoperability conformance claim.

## Initial baseline and change control

- Git root reported by Git: `D:/C drive/User/Desktop/DNP3-EXTRA` (the `C:/Users/poimu/Desktop/DNP3-EXTRA` workspace resolves to it).
- Branch: `develop`; initial and final HEAD: `6855ecad13407f9610870f5e5c8edb0cb5afbcdd`.
- Initially unstaged: `AGENTS.md` and the existing Catch assertion-parentheses workaround in `opendnp3/cpp/tests/unit/TestProductionAuthentication.cpp`. Both remain untouched by O2. Staging was and remains empty.
- The task expressly authorized this phase's builds/tests and prohibited commits/pushes. No Git remote operation was performed and no remote synchronization is asserted.

## Requirements and applicability

Normative baseline: local `IEEE 1815/IEEE 1815-2012.pdf`, not a later edition. The supplied Device Profile `IEEE 1815/4812449245627490050_724147149003390.pdf`, PDF p12 (original p52), identifies G122V0/V1/V2 with the requested READ/RESPONSE/UNSOLICITED_RESPONSE qualifiers. That page and IEEE Table 12-63 were also rendered and visually inspected.

| Requirement | IEEE 1815-2012 reference, printed pages | O2 behavior |
| --- | --- | --- |
| Own-association statistics and indexes | 7.5.2.2, pp204-207; Table 7-6, pp206-207 | Indexes 0-17; association ID 0; Outstation index 17 stays zero. No cross-association reporting. |
| Reporting thresholds and special actions | 7.6.1.4.2, p242; Table 7-15, p243; Table 7-6 | Separate local reporting thresholds; approved provisional `delta >= threshold`; existing successful Session Key change forces index 2 reporting. No new authentication reactions. |
| Event classes and mandatory static reporting | 5.1.4, Tables 5-1/5-2, pp104-106 | Configurable Class 1/2/3; reject Class 0 and unknown/no-class values. G121 mandatory Class 0 remains unchanged. |
| Quality and continuity | 11.6, Table 11-5, pp322-326 | Mask reserved bits 5/7 (`0x5F`). Preserve O1's conservative DISCONTINUITY behavior. Rollover does not set DISCONTINUITY. |
| Synchronization and clock accuracy | 4.5.5, p83; 10.3.1-10.3.2, p298; 10.3.3, p299 | Missing synchronization must not inhibit functions. Preserve actual usable absolute clock readings, even when unsynchronized; NEED_TIME remains application-controlled. |
| Counter and reporting model | 11.9.10, Tables 11-19/11-20, pp349-350 | One AuthenticationStatistics counter source; native event snapshots only; no Database counter copies, freezing, or clearing. |
| Event wire layouts | A.47.1/A.47.2, pp760-763 | V1: 7-byte body; V2: 13-byte body with UINT48 occurrence time; little endian, index in prefix. |
| Qualifiers and function codes | Table 12-63, p374 | V0 READ: 00/01/06/17/28; V1/V2 READ: 06/07/08. Native responses use 28; generated serializers verified with both 17/28. Solicited 81 and unsolicited 82 verified. |

The security addendum ledger was read. G122 supports the supplied SA statistics scope; this does not discharge unrelated security-addendum, persistence, or full profile obligations.

## Native implementation

`AuthenticationStatistics::Increment` and `RequireReport` notify the new `IAuthenticationStatisticsReporter` synchronously at the actual condition. `SecurityStatEventPublisher` obtains `IDnpTimeSource::Now()` before returning to authentication, copies index/value/flags/association/time into an `Event<SecurityStatSpec>`, and submits it to `IEventReceiver`. The notification happens before a potentially slow retention Save. Reporting is acknowledged through the existing `ReportGenerated` only after actual native acceptance.

`OutstationConfig::securityStatThresholds` configures reporting deadbands independently of the existing protocol-Max configuration. Existing public aggregate member order is preserved before appending O2 fields. `securityStatConfig[0..17]` uses the existing `SecurityStatConfig`/`EventConfig` conventions for class and default event variation. Invalid classes/variations throw during construction. This does not implement remote ASSIGN_CLASS.

Existing modules reused: `SecurityStat`, measurement info/specs, `EventType`, `EventBufferConfig`, `IEventReceiver`, `EventLists`, `EventStorage`, `EventUpdate`, `EventSelection`, `EventBuffer`, `IEventSelector`, `ReadHandler`, `IEventWriteHandler`, `ASDUEventWriteHandler`, `EventWriters`, `HeaderWriter`, `ResponseContext`, and existing `OutstationStates` confirmation/retry/removal machinery. New dedicated module: `outstation/SecurityStatEventPublisher.{h,cpp}`. Context changes only connect ownership and post a coalesced notification through the existing executor; the occurrence callback does not transmit or reenter authentication. A weak lifetime guard cancels queued notification work after context destruction, and the runtime reporter is detached before destruction.

Native indexed/range selection is extended only for G122V0. Limited-count reads and class filters reuse existing selection. G122's default variation is restored on unselect so an expired explicit-V2 READ cannot change subsequent Class polling. Other event types retain existing behavior.

## Storage, overflow, and lifecycle

- `maxSecurityStatEvents` is a separate bounded native typed-list capacity. Default capacity is zero; configure it explicitly or use `EventBufferConfig::AllTypes(n)`. No second event queue/database is introduced.
- The legacy storage Update result means overflow, not acceptance. The G122 receiver checks nonzero capacity and validates own-association index/class/variation before insertion; only V2 requires usable occurrence time; its bool result explicitly means acceptance. Rejected events never advance the reporting baseline.
- At capacity, native EventUpdate drops the oldest same-type event, including a selected/written record if it is the oldest, and accepts the new snapshot. The native overflow latch/IIN records loss. It does not recursively increment security statistics or alter continuity flags. Previously serialized in-flight APDU bytes remain owned by the native transmission buffers.
- Accepted snapshots are copied by value; later counter/time changes cannot change events, fragments, or retransmissions. READ does not reconstruct historical timestamps or poll pending reporting conditions. A later real counter increment or forced occurrence can submit a fresh current snapshot after rejection; it does not recreate a rejected historical event.
- Matching native CONFIRMs clear written events; wrong/late CONFIRMs retain them. Existing solicited timeout, unsolicited retries, disconnect/reconnect, and multi-fragment continuation are used unchanged. Native 16-bit index/count response prefixes are emitted; 8-bit prefixes are also supported by HeaderWriter serializers.

## Timestamp blocker resolution

The original blanket synchronization gate was a confirmed defect in both `SecurityStatEventPublisher::Report` and `EventBuffer::Update(Event<SecurityStatSpec>)`. It rejected all events before enqueue when time was not SYNCHRONIZED, including V1, although V1 has no timestamp. Thus reporting conditions could remain pending indefinitely and later increments could replace the original occurrence instead of buffering it.

IEEE evidence re-examined: 4.5.5 (printed p83, also rendered and visually verified), 10.3.1-10.3.3 (pp298-299), 7.5.2.2 (pp204-207), 11.9.10/Table 11-19 (pp349-350), A.47.1/A.47.2 (pp760-763), Table 12-63 (p374), and the Device Profile PDF p12. Section 4.5.5 expressly prohibits function inhibition due to failure to receive synchronization; Table 11-19 makes timestamps optional. A.47.2 requires occurrence time, not response time. Section 10.3 distinguishes a dependable local clock from master synchronization and permits inaccurate reported times when synchronization is absent. Neither the profile nor A.47 mandates that every event wait for a synchronized clock.

| Clock at occurrence | Snapshot and ordinary Class/V0 reporting | Explicit G122V2 READ |
| --- | --- | --- |
| Synchronized, UINT48-representable UTC | Capture and preserve it; use configured V1/V2 default. | Use captured timestamp. |
| Usable absolute UTC, UNSYNCHRONIZED quality | Capture the real reading and preserve its internal quality. Use configured V1/V2; make no accuracy guarantee. | Use captured timestamp; do not relabel the internal snapshot synchronized. |
| INVALID, unknown quality, out-of-range, or throwing source | Store an immutable untimed snapshot with INVALID internal time and V1 default; no fabricated timestamp is emitted. | Do not convert, substitute V1, retime, or bypass the untimed event. Retain it for V1, V0, or Class polling. |

`SecurityStat::HasTime()` centralizes the distinction between usable absolute time and unavailable time. `SecurityStatEventPublisher` catches clock-source failure locally so it cannot reject a valid untimed counter event. It does not retry publication when the clock changes. The reporting baseline advances only on the same native acceptance result as before.

For explicit V2, native selection writes only the ordered timestamped prefix, up to the requested count, and stops at the first unselected untimed event. This avoids returning a newer event before an older event for the same point (5.1.5.1.2, p107). If there is no reportable V2 prefix, the response contains no event objects and retains the native Class-events IIN; no CONFIRM can delete the unwritten events. V1 or Class/V0 polling drains them. A later clock synchronization never reconstructs their missing occurrence time. Supported-type null-response handling follows the general Table 4-14 behavior (p85), rather than inventing OBJECT_UNKNOWN, PARAM_ERROR, or an authentication error. The choice to retain the ordered untimed prefix is an implementation policy; IEEE does not define a conversion that can recover nonexistent historical time. A V2-only poller cannot drain such a prefix and must use V1 or Class/V0. This unavoidable case-C representation limit is not concealed as a valid V2 event.

NEED_TIME remains owned by `IOutstationApplication::GetApplicationIIN`, as in native OpenDNP3. It requests time from the master; it is not a per-event accuracy bit. The tests verify propagation with and without the application flag in solicited/unsolicited responses, independent of snapshot quality and later clock changes. G122 does not automatically set or clear it when Now() quality changes. Section 4.5.5 requires support for time-write and G80V1 clearing/rearm when requesting time. Existing `WriteHandler` supports time writes but its G80V1 handler only clears DEVICE_RESTART; the broader NEED_TIME clear/rearm capability is a pre-existing gap outside this event-publication correction. Full time-service/NEED_TIME conformance is not claimed, and no system-wide clock or IIN lifecycle was added.

**P6b-O2-OPEN-01 is closed as a blanket-publication blocker.** P6-OPEN-01 remains open: 7.6.1.4.2's reporting boundary versus 11.9.10.2; retain the approved `>=`. P4-OPEN-01 and P6-OPEN-02/03, DISCONTINUITY clearing/rearming, platform retention, threshold persistence and absent Update Key producers remain unchanged. No Master decoding, ISOEHandler, G0V210, cross-association, authentication transition, TLS/crypto or embedded changes were made.

## Generation and static review

Compiled the repository's Scala 2.13.2 generator sources using Java 11 and ran the official `com.automatak.render.dnp3.Generate` entry point twice into separate isolated trees. The two entire output trees are byte-identical. O2 Group122 codec/metadata outputs match the source tree after line-ending/trailing-whitespace normalization; generated logic was not hand-authored. `GroupVariationSerialization.h` regenerated unchanged. Existing generated differences were left untouched: Group120/Group121 comment whitespace and StaticDoubleBinaryVariation's pre-existing `if` versus `else if` form. The system Java 21 compiler attempt failed; the cached Java 11 archive was truncated, so a fresh Java 11 JRE was obtained for the successful run. Build tools/archives are not source changes.

Reviewed the complete task diff and all new source files for ownership, bounded storage, baseline advancement, qualifier dispatch, scope, and unsafe fallbacks. `git diff --check`: PASS. A separate trailing-whitespace scan covers new untracked source files. No staging, broad formatting, application main.cpp test harness, secret, PDF reference, or compiled artifact was added to Git.

## Executed validation

Configuration: existing Visual Studio 17 2022 / MSVC x64 Release; `DNP3_SA_CRYPTO=ON`, `DNP3_TESTS=ON`.

| Check | Result |
| --- | --- |
| Fresh pre-O2 library and unit-test build | PASS, before source edits |
| Final-source OpenDNP3 library and unit-test build | PASS |
| New G122 cases | PASS: 22 cases, 208 assertions |
| Existing G121 cases | PASS: 8 cases, 889 assertions |
| Combined final G121/G122 run | PASS: 30 cases, 1097 assertions |
| Native event storage/responses/state-machine/unsolicited selection | PASS: 56 cases, 6206 assertions |
| Broader selected event/authentication regressions | FAIL: 11 cases, 60 assertions; final output byte-for-byte identical to fresh pre-O2 output |
| General Outstation tests | FAIL: 1 case/assertion at TestOutstation.cpp:403, the existing analog READ variation mismatch; same failure as archived O1/parent reports, not freshly rebuilt as a separate parent in O2 |
| Official generator repeatability and O2 output consistency | PASS, as qualified above |
| Whitespace/diff review | PASS |

The broader baseline comparison includes `AuthenticationRuntime` in addition to other authentication tests, explaining its broader failure count than the earlier handoff's 10-case/59-assertion selection. The existing Catch compatibility edit remained in place for both fresh baseline and O2 builds; it is not an O2 change. Deprecation warnings from existing LinkConfig tests and CMake dependency declarations are separate from O2 results.

Permanent tests inspect actual APDUs and cover exact codec bytes and both response qualifiers, truncated bodies/malformed headers, threshold equality/below threshold, modulo rollover, forced Session Key reporting, protocol-Max separation, zero-capacity rejection/pending baseline, overflow, immutable time/value snapshots, permitted READ qualifiers/indexes, all event classes/invalid classes, limited count, matching/wrong/late CONFIRM, timeout/retry, disconnect/reconnect, fragmentation, independent contexts, G121 isolation, configured variation restoration, and actual secure-context RX/TX accounting. No interoperability/Test Harness run, embedded build, or full conformance validation was performed.

Logs (workspace-relative, build outputs only): `build-p6b-o1/o2-baseline-build.log`, `build-p6b-o1/o2-baseline-tests.log`, `build-p6b-o2/build-verified.log`, `build-p6b-o2/test-g122.log`, `build-p6b-o2/test-security-final.log`, `build-p6b-o2/test-native-events.log`, `build-p6b-o2/test-baseline-comparison.log`, `build-p6b-o2/test-outstation-general.log`, and `build-p6b-o2/generator/`.

## Exact task paths

All paths below are relative to the Git root; the two initial user changes are excluded.

```
DNP3_PDD_PLAN/ENGINEERING_EVIDENCE.md#record-08
REPO_MAP.md
opendnp3/cpp/lib/CMakeLists.txt
opendnp3/cpp/lib/include/opendnp3/app/EventType.h
opendnp3/cpp/lib/include/opendnp3/app/MeasurementInfo.h
opendnp3/cpp/lib/include/opendnp3/app/SecurityStat.h
opendnp3/cpp/lib/include/opendnp3/gen/GroupVariation.h
opendnp3/cpp/lib/include/opendnp3/outstation/EventBufferConfig.h
opendnp3/cpp/lib/include/opendnp3/outstation/MeasurementConfig.h
opendnp3/cpp/lib/include/opendnp3/outstation/OutstationConfig.h
opendnp3/cpp/lib/src/app/MeasurementFactory.h
opendnp3/cpp/lib/src/app/MeasurementInfo.cpp
opendnp3/cpp/lib/src/app/MeasurementTypeSpecs.h
opendnp3/cpp/lib/src/app/WriteConversions.h
opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp
opendnp3/cpp/lib/src/auth/AuthenticationStatistics.cpp
opendnp3/cpp/lib/src/auth/AuthenticationStatistics.h
opendnp3/cpp/lib/src/gen/Attributes.cpp
opendnp3/cpp/lib/src/gen/GroupVariation.cpp
opendnp3/cpp/lib/src/gen/objects/Group122.cpp
opendnp3/cpp/lib/src/gen/objects/Group122.h
opendnp3/cpp/lib/src/outstation/EventBufferConfig.cpp
opendnp3/cpp/lib/src/outstation/IEventReceiver.h
opendnp3/cpp/lib/src/outstation/IEventSelector.h
opendnp3/cpp/lib/src/outstation/OutstationContext.cpp
opendnp3/cpp/lib/src/outstation/OutstationContext.h
opendnp3/cpp/lib/src/outstation/ReadHandler.cpp
opendnp3/cpp/lib/src/outstation/SecurityStatEventPublisher.cpp
opendnp3/cpp/lib/src/outstation/SecurityStatEventPublisher.h
opendnp3/cpp/lib/src/outstation/event/ASDUEventWriteHandler.cpp
opendnp3/cpp/lib/src/outstation/event/ASDUEventWriteHandler.h
opendnp3/cpp/lib/src/outstation/event/EventBuffer.cpp
opendnp3/cpp/lib/src/outstation/event/EventBuffer.h
opendnp3/cpp/lib/src/outstation/event/EventLists.cpp
opendnp3/cpp/lib/src/outstation/event/EventLists.h
opendnp3/cpp/lib/src/outstation/event/EventStorage.cpp
opendnp3/cpp/lib/src/outstation/event/EventStorage.h
opendnp3/cpp/lib/src/outstation/event/IEventWriteHandler.h
opendnp3/cpp/tests/unit/CMakeLists.txt
opendnp3/cpp/tests/unit/TestSecurityStatEvents.cpp
opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/ObjectGroup.scala
opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/groups/Group122.scala
```

## Timestamp-resolution validation and exact follow-up changes

The timestamp-resolution task changed only these existing O2 paths (no new module or queue):

- `opendnp3/cpp/lib/include/opendnp3/app/SecurityStat.h`: usable occurrence-time predicate.
- `opendnp3/cpp/lib/src/outstation/SecurityStatEventPublisher.cpp`: accept unsynchronized UTC, catch unavailable-clock failures, V1 default fallback.
- `opendnp3/cpp/lib/src/outstation/event/EventBuffer.cpp`: remove V1 clock gate; require usable time only for direct V2 insertion.
- `opendnp3/cpp/lib/src/outstation/event/EventStorage.cpp`: retain untimed prefix for explicit V2 without reordering.
- `opendnp3/cpp/tests/unit/TestSecurityStatEvents.cpp`: replace the obsolete blanket-block expectation and add focused clock-state/APDU/lifecycle tests.
- `REPO_MAP.md` and this report: update the resolved behavior and its limits.

Executed using the already verified MSVC x64 Release configuration and tool paths:

| Check | Timestamp-resolution result |
| --- | --- |
| OpenDNP3 and unittests build | PASS; final test-only incremental rebuild also passed |
| G122 tests | PASS: 30 cases, 275 assertions |
| G121 regressions | PASS: 8 cases, 889 assertions |
| Native event regressions | PASS: 56 cases, 6206 assertions |
| Relevant event/authentication regression selection | Same 11 failed cases / 60 failed assertions; byte-for-byte identical to recorded fresh committed O1 baseline (HEAD 6855ecad plus the existing excluded Catch workaround) |
| Scala generator | Official Generate rerun using existing compiled Scala 2.13.2 sources/Java 11; complete output byte-identical to prior verified generator tree. O2 generated source matches with only line-ending/trailing-whitespace normalization. No Scala or generated file changed in this follow-up. |
| Static scope and whitespace review | PASS, including new untracked source; existing AGENTS/Catch hashes preserved; staging empty |

The O1 comparison reuses the fresh pre-O2 build/run recorded earlier in this chat, avoiding a redundant full baseline build. The general Outstation analog READ failure in the preceding table is historical for this follow-up and was not rerun; it was not fixed or claimed passed. No interoperability/Test Harness, embedded or full conformance run occurred.

Clock tests exercise V1 without synchronization or absolute time, V2 with synchronized/usable unsynchronized UTC, actual occurrence-time immutability, unavailable/out-of-range/throwing clocks, default-V2 fallback under Class 1/2/3 and V0 polls, all explicit V2 READ count forms retaining untimed events, ordering across usable/unavailable/restored clocks, application NEED_TIME propagation, native buffer retention/removal, solicited timeout and unsolicited retransmission across clock changes, and no baseline advancement on zero-capacity rejection.

Follow-up logs and the initial changed-file hashes are under `build-p6b-o2/timestamp-resolution/`. They are build outputs, not staged source files.

## Required disposition

- P6b-O2: COMPLETE for the assigned native implementation and timestamp-publication correction; case-C explicit V2 cannot represent nonexistent time and retains events as documented.
- G122V1: VERIFIED, including absent/unsynchronized clocks.
- G122V2: VERIFIED for synchronized and usable unsynchronized absolute occurrence time; no invalid placeholder is emitted.
- G121: PRESERVED.
- MASTER G121/G122: NOT IMPLEMENTED. Generated low-level codecs are not Master dispatch/delivery.
- G0V210: NOT IMPLEMENTED.
- Ready for final review and a separately authorized controlled commit: YES, with the documented existing baseline failures and limits. No full IEEE/SA v5/Level 4 conformance claim.
- COMMIT: NOT CREATED.
- PUSH: NOT PERFORMED.
- Git root: `D:/C drive/User/Desktop/DNP3-EXTRA`; branch `develop`; HEAD `6855ecad13407f9610870f5e5c8edb0cb5afbcdd` unchanged. Staging: EMPTY. All existing O2/user work preserved. No push attempted; remote verification is not applicable.


<a id="record-09"></a>

## Record 09 — ENGINEERING_EVIDENCE.md#record-09

# P6c security Device Attributes

Status: IMPLEMENTED and manually validated. Focused final review and `git diff --check`: PASS; no additional defect found. C++ builds/tests were executed by the user, not the agent. The authorized local commit follows report finalization; its hash is recorded in the final chat response. No push authorized or performed.

Baseline: develop at 28be44142213ca71ca03efdb2a97a925da4d79dc. Git root resolves to `D:/C drive/User/Desktop/DNP3-EXTRA` (workspace alias `C:/Users/poimu/Desktop/DNP3-EXTRA`). Independent AGENTS.md and TestProductionAuthentication.cpp/Catch edits are preserved and excluded.

## Requirements and actual behavior

IEEE 1815-2012 section 5.5.1-5.5.8 (printed pp148-154), Table 5-16 (p150), Table 12-1 (p352), A.1.1/A.1.2 (pp438-439), A.1.43/A.1.44 (pp485-486), and section 7.5.2.2 (pp204-207). Supplied Device Profile PDF p4 explicitly selects G0V209/V210 READ qualifier 00 and RESPONSE qualifiers 00/17. This is the selected security attribute slice, not an assertion of full Group 0 or Level 4 conformance.

There was no existing native Group 0 implementation in this baseline; the G0V209 document was a contract. Preserve its requirement to report only real supported SA versions. The existing SA implementation is still incomplete, with no supported complete version to advertise. Accordingly, Outstation G0V209 remains unavailable (OBJECT_UNKNOWN), is omitted from discovery, and never fabricates version 0 or 5. Master G0V209 decoding and typed delivery are implemented for an external device's actual UINTn value.

G0V210 returns a read-only UINT (type 2) at standard attribute set index 0. The value comes from the size of the existing association-owned G121 snapshot, currently 18 when attached by the secured Outstation READ path. It is 0 without that runtime/snapshot (including compatibility/noncrypto operation). It is not the number of users, associations, pending events, enabled event classes or configured thresholds. No new capability setting or duplicated statistic-count constant is introduced.

Exact active-runtime response object: `00 D2 00 00 00 02 01 12`. No-runtime value: `00 D2 00 00 00 02 01 00`. G0V209 explicit request: `00 D1 00 00 00`; unavailable response contains no value and sets IIN2 OBJECT_UNKNOWN (02).

IEEE 5.5.2 requires V254/V255 for attribute-capable devices. Their minimal dependency is included: V254 READ returns the supported V210 value; V255 returns `00 FF 17 01 00 FE 02 D2 00` (read-only V210, excludes V254/V255 and unsupported V209). Both accept request qualifiers 00 and 06. V209/V210 requests accept 00; value responses accept 00/17. V254 never appears in a response. Private sets are not published; ranges containing an unavailable set return PARAM_ERROR, with the valid set-zero part retained. Attributes are not selected by Class 0.

Master preserves received set indexes, type codes, raw little-endian UINTn bytes, list properties and header metadata. An attribute set index is not an Association ID or a G121/G122 point index; no remapping, merging or local-statistic updates occur. The numeric accessor detects uint64 overflow rather than truncating. Raw bytes remain available for any UINTn length 1..255. V255 supports normal/extended even-length lists (types 254/255). This slice parses only the selected Group 0 variations and their UINT/list payloads; it adds no private-attribute provisioning or other attribute families.

## Native integration and preservation

Reuses APDUParser's two-pass validation, RangeParser/CountIndexParser, HeaderWriter, IAPDUHandler, MeasurementHandler/ISOEHandler, ReadHandler, Database and ResponseContext. Added the small shared DeviceAttribute model/parser and bounded DeviceAttributeSelection module because none existed. No parallel APDU engine, authentication state machine or application main harness was added. Solicited polls use the existing Scan/HeaderWriter interface with an 8-bit range header (the generic ScanRange convenience uses 16-bit ranges and is not the profile's Group 0 request). Fragment/CONFIRM scheduling remains native.

ISOEHandler adds a default no-op typed attribute overload to preserve source compatibility; binary clients must rebuild. Attribute byte spans borrow the APDU and must be copied before the callback returns. HeaderWriter reserves the full object before writing. Selection is bounded, cleared with native Unselect and retained on insufficient response space. V255 lists only actual attributes. A narrow WriteHandler whitelist keeps newly recognized read-only Group 0 bodies from causing preceding mixed-WRITE side effects.

G120/G121/G122 codecs, counters, authentication/event behavior and previously documented NEED_TIME/continuity/P6a limitations are unchanged.

## Generator and tests

Scala Group0 is registered in ObjectGroup. Corrected signed Byte handling in variation names, numeric IDs and generated ID() rendering: variations above 127 must retain their unsigned wire values. Used the existing Java 11/Scala 2.13.2 generator and official Generate entry point into `build-p6c/generator/output`; copied only scoped C++ metadata, Group0.h and the generated Group 0 Java/C# declarations/lookup entries. Existing Java/C# omissions for other security groups were preserved rather than importing unrelated generator differences. Existing Attributes and GroupVariationSerialization outputs compare unchanged after line-ending/trailing-whitespace normalization. No G120/G121/G122 outputs were copied or edited. No C++ compiler or test executable was run by the agent.

Permanent TestDeviceAttributes.cpp (16 cases / 458 assertions, manually run by the user: PASS) covers generated IDs; actual count/absent runtime; honest unsupported G209; mandatory discovery; index semantics; Class 0/statistic preservation; profile response qualifiers; UINTn including 3/8-byte values and overflow; normal/extended lists; mixed types/header order; every representative truncated prefix before callbacks; malformed type/length/qualifier/range; atomic writes/fragment retention; native Master exact READ/fragment CONFIRMs; native compatibility Outstation; mixed read-only WRITE protection; unchanged legacy callback implementation.

Manual validation supplied by the user in this chat:

| Check | Result |
| --- | --- |
| MSVC Release `unittests` build, including library dependencies | PASS; exit code 0 |
| `[device-attributes] -r compact` | PASS; 16 cases / 458 assertions; exit code 0 |
| `*APDUParsing*,*MeasurementHandler*,[master-security-statistics],[security-stat-read],[security-stat-events] -r compact` | PASS; 91 cases / 1938 assertions; exit code 0 |
| Focused final review and scoped/staged whitespace checks | PASS; no additional defect found |

No prior phase's test result is substituted for P6c validation. No C++ build or test executable was run by the agent. Noncrypto builds, language-binding builds, interoperability/Test Harness and embedded validation were not performed. Existing authentication baseline failures were not rerun; no new result is claimed for them. Remaining limitations: Outstation G0V209 cannot advertise an SA version yet; only the selected attribute family and its required discovery dependency are supported; callback spans borrow the APDU and binary clients must rebuild. Existing NEED_TIME/continuity/P6a limitations remain unchanged.

Successful manual validation and focused review satisfy the authorization for one local commit containing only the 34 paths below. Independent AGENTS.md and Catch edits remain excluded. No push or subsequent phase.

## Exact P6c paths

```
DNP3_PDD_PLAN/ENGINEERING_EVIDENCE.md#record-03
DNP3_PDD_PLAN/ENGINEERING_EVIDENCE.md#record-09
REPO_MAP.md
opendnp3/cpp/lib/CMakeLists.txt
opendnp3/cpp/lib/include/opendnp3/app/DeviceAttribute.h
opendnp3/cpp/lib/include/opendnp3/gen/GroupVariation.h
opendnp3/cpp/lib/include/opendnp3/master/ISOEHandler.h
opendnp3/cpp/lib/src/app/HeaderWriter.cpp
opendnp3/cpp/lib/src/app/HeaderWriter.h
opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp
opendnp3/cpp/lib/src/app/parsing/CountIndexParser.cpp
opendnp3/cpp/lib/src/app/parsing/DeviceAttributeParser.cpp
opendnp3/cpp/lib/src/app/parsing/DeviceAttributeParser.h
opendnp3/cpp/lib/src/app/parsing/IAPDUHandler.cpp
opendnp3/cpp/lib/src/app/parsing/IAPDUHandler.h
opendnp3/cpp/lib/src/app/parsing/RangeParser.cpp
opendnp3/cpp/lib/src/gen/GroupVariation.cpp
opendnp3/cpp/lib/src/gen/objects/Group0.h
opendnp3/cpp/lib/src/master/MeasurementHandler.cpp
opendnp3/cpp/lib/src/master/MeasurementHandler.h
opendnp3/cpp/lib/src/outstation/Database.cpp
opendnp3/cpp/lib/src/outstation/Database.h
opendnp3/cpp/lib/src/outstation/DeviceAttributeSelection.cpp
opendnp3/cpp/lib/src/outstation/DeviceAttributeSelection.h
opendnp3/cpp/lib/src/outstation/ReadHandler.cpp
opendnp3/cpp/lib/src/outstation/WriteHandler.h
opendnp3/cpp/tests/unit/CMakeLists.txt
opendnp3/cpp/tests/unit/TestDeviceAttributes.cpp
opendnp3/dotnet/CLRInterface/src/gen/GroupVariation.cs
opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/GroupVariation.scala
opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/ObjectGroup.scala
opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/generators/GroupVariationLines.scala
opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/groups/Group0.scala
opendnp3/java/bindings/src/main/java/com/automatak/dnp3/enums/GroupVariation.java
```


<a id="record-10"></a>

## Record 10 — ENGINEERING_EVIDENCE.md#record-10

# SA remote Update Keys: Windows Methods 4/68

Date: 2026-11-03. Baseline: develop / 92a1c5e69247e94c19e619bc9a019d05167d2b3a.
This records the Windows implementation and local validation, not independent
conformance evidence. Method 4 checkpoint `556691a4d03bd848618025de10e994f54bac0acc`
was pushed and verified before the Method 68 extension. The final SCS rule below
supersedes that checkpoint's authority-fingerprint reset allowance.

## IEEE contract and implementation map

IEEE 1815-2012: 7.5.4.4–7.5.4.7 and Table 7-14 (printed pp226–238),
7.5.5.5–7.5.5.7 (pp239–241), 7.6.1.4.9/Table 7-16 (p245),
Table 7-17 (p246), Table 7-18 (p247), 7.6.2.2.2 (p250),
Tables 7-23/7-24 (pp262–265), A.45.10–A.45.15/Tables A-10–A-13
(pp743–757). Table 7-6 controls statistics; 7.5.2.2 uses ASSOC=0 for the
reporting association's G121/G122 values. G120V8 (User Certificate) is CODEC_ONLY;
runtime certificate-chain distribution is not added. Method 68 uses independently
provisioned authority/Outstation SPKIs and V10 user certification. G120V5 remains
the existing Session Key Status procedure.

| Objects | Before | Checkpoint |
| --- | --- | --- |
| V10 | CODEC_ONLY | VERIFIED local Methods 4/68 ADD/CHANGE/DELETE; authority MAC/signature; SCS and reserved identities |
| V11/V12 | CODEC_ONLY | VERIFIED native Master/Outstation ownership for both methods; shared KSQ; random challenges |
| V13/V15 | CODEC_ONLY | VERIFIED local Methods 4/68 mutual proof; V15-only verification and pending-key recovery |
| V14 | CODEC_ONLY | VERIFIED local Method 68 DSA signature path; DER interoperability remains RUK-OPEN-02 |

Existing generated codecs and parser/serializer were reused without generation
changes. Master uses `IMasterOperations::ChangeUpdateKey`, `UpdateKeyTask` and
existing callbacks/timers. `RemoteUpdateKeys` is an association-owned lifecycle
inside `AuthenticationSession`, sharing `SessionKeys`, provider and statistics.
Outstation routes strict native free-format objects. Ordinary C/R, Aggressive,
authorization and independent owners retain their existing paths.

## Security and persistence

Remote operation is opt-in: AES256RFC3394, HMACSHA256, 32-byte challenges;
network MAC length 16, explicitly supported serial length 8. Certification is
the exact A-10 transcript; directional confirmations are the exact A-13 bytes.
Challenge expansion uses FIPS186-2 Appendix 3.1 general-purpose construction
(Change Notice 1 p74), fresh CSPRNG seeds, and the RFC4186 Appendix A KAT.
This is not a FIPS140 validation claim.

`IUpdateKeyTrust` is Outstation-only. The Master never receives BC and forwards
authority ciphertext unchanged through `IUpdateKeySource`. External authority
transport/provisioning is outside this implementation. Credentials are isolated
by association/user; names are bounded at 128 bytes, capacity configurable 2..16,
and receive storage is bounded. No production default keys exist.

Authority role/expiry changes remain pending until proof under a different,
verified Update Key. DELETE erases credentials immediately, including Common
when trusted UTC is unavailable; revocation needs no expiry calculation. Private roles still
require explicit application policy; standard roles cannot silently gain rights.
Startup permits only Common without trusted UTC. Runtime expiry uses monotonic
deadlines; DNP clock changes cannot extend authorization. Invalid/unavailable DNP
time suppresses Error publication rather than fabricating a timestamp.

The existing Windows adapter now journals two Credential Manager snapshots and
a generation/hash commit marker. Readback verifies writes; missing/torn/corrupt
referenced state fails closed without fallback. Uncertain I/O disables that user.
The Master persists pending credentials before transmission and activates them
after verified peer proof, including restart recovery. Session Keys are never
persisted. Temporary secrets are wiped. Windows tests execute real Credential
Manager calls in an isolated test namespace and remove the records afterward.
Power-loss hardware durability and STM32 NVM integration are NOT VERIFIED.
The adapter has one serialized credential owner per configured namespace;
administrative provisioning must not race runtime writes. Separate Master and
Outstation credential owners use separate namespaces. The journal is not a
multi-process compare-and-swap database.

Statistics 15/16 count real successful/terminal transmitted exchanges once.
Pure verification, duplicate final proof and local construction do not count.
Native G121/G122 and event confirmation/removal are exercised.

## Method 68 and configuration

`allowMethod68` defaults false. Each request explicitly selects 4 or 68; an
existing user's V11 method must match its certified method. There is no fallback
to another algorithm. Method 68 uses RSA2048 OAEP with SHA256 and MGF1SHA256,
an empty OAEP label, and a 256-bit Update Key. V10 certification and V14 use
DSA SHA256 with L=2048/N=256, never RSA signatures or ECDSA. Public keys are
bounded, self-contained SPKI DER; private DER stays behind credential/provider
boundaries. OpenSSL validates key type/size/domain/public/private/pairwise
consistency, consumes the entire encoding and rejects noncanonical SPKI/signatures.
No certificate chain or trust-on-first-use is implied by SPKI decoding.

The Master receives its user's private key and an independently trusted Outstation
public key through the explicit source. It locally encrypts A-11 without RFC3394
padding, signs A-12, and sends V13+V14. Outstation verifies the authority-certified
user signature, decrypts with its provisioned private key, checks name/RB, commits,
and returns the A-13 HMAC. V15-only recovery remains available for either method.
The authority private key never enters the Master boundary. Names are limited to
126 bytes for Method 68 because OAEP2048/SHA256 carries at most 190 plaintext
bytes including the 32-byte key and 32-byte challenge; Method 4 permits 128.

Windows record schema 2 includes Method/SPKI and up to 72 certification bytes.
Schema 1 Method 4 records remain readable and upgrade on the next verified write;
the actual Credential Manager migration is tested. Only active/pending Update
Keys and user metadata persist; Session Keys never do.

Receive input/user count is bounded. The fixed 16-entry remote metadata table
includes 16 x 1024-byte public-key slots; SessionKeys are separately allocated
once to configured capacity. RSA/DSA use bounded inputs but provider allocations.
STM32/FreeRTOS RAM/stack sizing and a non-OpenSSL backend are not measured here.
Native file transfer, firmware/code loading and local login are not implemented;
standard roles cannot gain those permissions through a coarse file-mode check.
Table 7-12 permits local interpretation: the gate restricts native monitoring,
controls/freezing and configuration, then ANDs the explicit application policy.
Combined administrator/ordinary roles require provisioned PRIVATE policy.

## Validation

Release build, verified installed CMake 4.4/MSVC:

```powershell
& 'C:\Program Files\CMake\bin\cmake.exe' --build 'D:\C drive\User\Desktop\DNP3-EXTRA\build-p6b-o1\native' --config Release --target unittests integrationtests --parallel 4
```

Method 4 checkpoint: build exit 0; focused 21 cases / 2,078 assertions;
unfiltered 700 / 57,393; TCP 2 / 181. Final Methods 4/68 validation after the
certified DELETE/trusted-time correction:

| Gate | Cases | Assertions | Process exit |
| --- | ---: | ---: | ---: |
| Release targets `unittests integrationtests` | — | — | 0 |
| Unit `[remote-update-keys] -r compact` | 35 | 3,733 | 0 |
| Complete unfiltered unit suite `-r compact` | 714 | 59,048 | 0 |
| Native TCP integration `[sa-tcp] -r compact` | 2 | 240 | 0 |

Zero failing cases/assertions in each test run. The TCP remote-update case runs
both methods through Catch GENERATE, alongside the existing SA TCP case.
Unit and integration executables are the existing Release binaries under
`D:\C drive\User\Desktop\DNP3-EXTRA\build-p6b-o1\native\cpp\tests\unit\Release`
and `...\integration\Release`, respectively. Scoped whitespace check passed.
Tests include malformed/unowned V12/V13,
lost-stage responses, bounded retries, invalid certification/ciphertext,
role/capacity/bootstrap/expiry, critical persistence failures before/after write,
restart recovery, actual Windows journal corruption and independent old keys.
Existing SA tests remain included in the unfiltered suite.

## Exact changed-file manifest

Paths below are relative to Git root
`D:\C drive\User\Desktop\DNP3-EXTRA`. They cover both checkpoints, not just
the final asymmetric extension. The pre-existing `AGENTS.md` edit is excluded.
No generated objects, Scala models or G0V209 implementation were changed.

Production:

```text
opendnp3/cpp/lib/CMakeLists.txt
opendnp3/cpp/lib/include/opendnp3/auth/AuthenticationConfig.h
opendnp3/cpp/lib/include/opendnp3/auth/UpdateKeyConfig.h
opendnp3/cpp/lib/include/opendnp3/auth/WindowsAuthenticationCredentials.h
opendnp3/cpp/lib/include/opendnp3/master/IMasterOperations.h
opendnp3/cpp/lib/src/auth/AuthenticationSession.cpp
opendnp3/cpp/lib/src/auth/AuthenticationSession.h
opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.cpp
opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.h
opendnp3/cpp/lib/src/auth/SessionKeys.cpp
opendnp3/cpp/lib/src/auth/SessionKeys.h
opendnp3/cpp/lib/src/auth/UpdateKeyFunctions.cpp
opendnp3/cpp/lib/src/auth/UpdateKeyFunctions.h
opendnp3/cpp/lib/src/auth/WindowsAuthenticationCredentials.cpp
opendnp3/cpp/lib/src/crypto/CryptoProvider.h
opendnp3/cpp/lib/src/crypto/OpenSSLCryptoProvider.cpp
opendnp3/cpp/lib/src/master/IMasterTask.h
opendnp3/cpp/lib/src/master/MasterContext.cpp
opendnp3/cpp/lib/src/master/MasterContext.h
opendnp3/cpp/lib/src/master/MasterStack.cpp
opendnp3/cpp/lib/src/master/MasterStack.h
opendnp3/cpp/lib/src/master/UpdateKeyTask.cpp
opendnp3/cpp/lib/src/master/UpdateKeyTask.h
opendnp3/cpp/lib/src/outstation/OutstationChallenger.cpp
opendnp3/cpp/lib/src/outstation/OutstationChallenger.h
opendnp3/cpp/lib/src/outstation/OutstationContext.cpp
opendnp3/cpp/lib/src/outstation/OutstationContext.h
```

Permanent tests and build registration:

```text
opendnp3/cpp/tests/dnp3mocks/include/dnp3mocks/RemoteUpdateKeyCredentials.h
opendnp3/cpp/tests/dnp3mocks/include/dnp3mocks/AsymmetricUpdateKeyCredentials.h
opendnp3/cpp/tests/unit/CMakeLists.txt
opendnp3/cpp/tests/unit/TestRemoteUpdateKeys.cpp
opendnp3/cpp/tests/integration/CMakeLists.txt
opendnp3/cpp/tests/integration/TestSecureAuthentication.cpp
```

Engineering evidence:

```text
REPO_MAP.md
DNP3_PDD_PLAN/PROFILE_MATRIX.csv
DNP3_PDD_PLAN/ENGINEERING_EVIDENCE.md#record-02
DNP3_PDD_PLAN/ENGINEERING_EVIDENCE.md#record-10
```

## OPEN / platform boundaries

- **RUK-OPEN-01:** 7.5.5.5 requires SCS greater than any previous value for the
  user, while A.45.10 permits wrap to zero. Provisionally reject all remote
  resets/wrap, including authority-key or certification-method changes. Another
  configured authority method could still validate historical certifications;
  a different fingerprint alone cannot establish a fresh trust epoch. Named
  tombstones are never evicted. At SCS exhaustion/capacity exhaustion, protected
  administrative reprovisioning must revoke historical trust before clearing
  replay state; no remote reset API is provided. Tests prove cross-method replay,
  wrap and tombstone-eviction rejection. Authoritative clarification and an
  independent authority/Outstation wrap-boundary test remain required.
- **RUK-OPEN-02:** A.45.10/A.45.14 specify DSA certification/signature bytes but
  do not specify r/s wire representation. Provisionally use strict DER
  Dss-Sig-Value per RFC5758 §3.1 / RFC3279 §2.2.2, with no alternate parser or
  algorithm fallback. Independent Method 68 authority/Master/Outstation testing
  must establish interoperability of both V10 and V14. Local RFC6979 KAT and
  loopback tests do not close this issue. No full G0V209 SA advertisement is added.
- Existing P4-OPEN-01, P6-OPEN-01/03, NEED_TIME and statistic retention/quality
  limitations remain. No new resolution or embedded validation is claimed.
- External authority integration and trusted time are provisioning contracts;
  no HTTP service, authority database or insecure distribution is invented.
- Shared protocol/provider boundaries remain portable; STM32 crypto, NVM,
  resource sizing and independent Triangle MicroWorks testing remain separate.

Primary external references used where needed:
[FIPS186-2 Change Notice 1](https://csrc.nist.gov/files/pubs/fips/186-2/upd1/final/docs/fips186-2-change1.pdf),
[RFC4186 Appendix A](https://www.rfc-editor.org/rfc/rfc4186.html#appendix-A),
[RFC5758 §3.1](https://www.rfc-editor.org/rfc/rfc5758.html#section-3.1),
[RFC3279 §2.2.2](https://www.rfc-editor.org/rfc/rfc3279.html#section-2.2.2),
[RFC6979 Appendix A.2.2](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.2).

<a id="record-11"></a>

## Record 11 - 2026-11-07: V-06c MAC policy and B03 authenticated FC6 (Windows Host)

**Revision identity:** `develop`, baseline Git HEAD `54a552a` at test time, plus the reviewed, then-uncommitted V-06c/B03 source and permanent tests. The eventual commit containing this record identifies the complete tested local change set. Build: `build-sa-b06-vcpkg`, MSVC Release on Windows.

**Selected behavior and scope:** V-06c rejects disabled/unsupported Challenge MAC algorithms without cancelling independent responder/monitoring/CONFIRM ownership. B03 enables authenticated FC6 (DIRECT_OPERATE_NR) for G12V1 and G41V1/V2/V3, Q17/Q28, using Challenge/Reply or configured Aggressive Mode in SA REQUIRED. The Master does not retry FC6, an unusable Aggressive Challenge fails closed, and an FC6 `TaskCompletion::SUCCESS` means only local authenticated submission with `CommandStatus::UNDEFINED`, never confirmed remote execution. The Outstation must authorize execution; FC6 has no ordinary application command response.

**Executed evidence (reported Windows PowerShell output):**

| Scope | Command / scenario | Observed result |
| --- | --- | --- |
| V-06c focused | `unittests.exe '[sa-v06-mac-policy]' --reporter compact` | PASS; 3 cases, 606 assertions |
| V-06c prior full regression | `unittests.exe --reporter compact`; `integrationtests.exe --reporter compact` | PASS; 777 cases / 64,148 assertions; 16 cases / 12,506 assertions (before B03) |
| B03 focused | `unittests.exe '[sa-fc6]' --reporter compact` | PASS; 9 cases, 6,659 assertions |
| B03 V-06c regression | `unittests.exe '[sa-v06-mac-policy]' --reporter compact` | PASS; 3 cases, 606 assertions |
| B03 complete unit regression | `unittests.exe --reporter compact` | PASS; exact case/assertion totals not captured in supplied final excerpt |
| B03 complete integration regression | `integrationtests.exe --reporter compact` | PASS; 16 cases, 12,534 assertions |
| B03 same-project, separate-process TCP | `ProcessSmoke.py --only method4`; `--only method68` | PASS; SA lifecycle and selected authenticated FC6 command readbacks; local CLI callbacks and peer shutdown checked |
| B03 general security TCP regression | `ProcessSmoke.py --only negative`; `--only reply-timeout` | PASS; no unauthorized command execution in tested negative scenarios; four None/0 timer configurations |
| Source hygiene | Scoped `git diff --check` | PASS |

**Assessment:** `VERIFIED_HOST` for the specific V-06c and B03 behaviors exercised above. These are same-implementation Host results, not independent-peer interoperability or a complete certification. All 69 PROFILE + 36 SEC + 14 CFG requirements retain their own acceptance scope and subcase obligations; do not blanket-upgrade matrices. B03 primarily adds evidence for the FC6 portions of PROFILE-019, PROFILE-035/036/037 and CFG-08, not all control/physical I/O conditions.

**Open/limited:** `TIMEOUT-ZERO` requires normative/product clarification; configured Aggressive FC6 without usable retained Challenge history fails locally; `CFG-09` CROB Trip/Close mapping and rejected forms remain pending; G0V209, G120V8, MAC/TLS selections, independent-peer interoperability, trusted RTU I/O, STM32H743/FreeRTOS, NVM/entropy/hardware acceptance remain open. Preserve `P4-OPEN-01` and the provisional G120V7 Code 5/7 meanings. No full SA v5 or Level 4 conformance claim.


<a id="record-12"></a>

## Record 12 - 2026-11-07: B07 selected Aggressive acceptance source coverage (unexecuted)

Historical status at source-authoring time. Subsequent user-supplied Windows
execution and the bounded Host acceptance review are recorded in [Record 13](#record-13);
the original no-execution statement below is retained as history.

Baseline: `develop`, `3478a2b448b6ba092cfa5e2b03fb6b09af7f2fd7`, plus B07 test/document changes.
The [B07 acceptance matrix](B07_ACCEPTANCE_MATRIX.md) maps PROFILE-050/056 and SEC-T1-04/05
through the exact selected functions, directions, qualifiers and ownership boundaries.
It distinguishes existing permanent coverage from five new parameterized test cases.

Changes add exact typed FC3/4/5 envelopes/ECHO, selected non-command native routing,
actual FC129/130 monitoring corruption/contention, receiving-key expiry/reconnect,
and correctly signed CSQ half-window boundary checks. Runtime seeds and keys come
from genuine production negotiation and Challenge/Reply. The isolated codec boundary
fixture is explicitly identified separately. No production defect was established;
no production code, public API, optional MAC selection or capability advertisement changed.

Validation: scoped `git diff --check` only. **NOT BUILT / NOT TESTED.** No new Host
execution result or VERIFIED_HOST promotion is claimed. Record 11's V-06c/B03
results remain historical evidence for their stated scope. Windows execution,
independent-peer interoperability, MAC-SELECTION, TIMEOUT-ZERO and P4-OPEN-01
remain open; provisional G120V7 Code 5/7 meanings are preserved.


<a id="record-13"></a>

## Record 13 - 2026-11-07: B07 Windows Host acceptance review (user-reported execution)

**Revision and provenance:** reviewed `develop` HEAD
`3478a2b448b6ba092cfa5e2b03fb6b09af7f2fd7` plus the current uncommitted B07 test diff
in TestProductionAuthentication.cpp and TestAggressiveMode.cpp. The supplied results
are attributed to that B07 tree as reported by the user, not to baseline HEAD alone.
No test or production source was changed during this documentation review. Exact
run commands, build directory/compiler version, execution timestamps, per-case logs
and a tested-binary/source hash binding were not supplied; no values are inferred.

**Windows execution supplied by the user:**

| Scope | Result supplied | Evidence category and limit |
| --- | --- | --- |
| Release build | PASS | Reported Windows compilation; not protocol acceptance by itself |
| Unit suite | PASS; 791 cases, 91,225 assertions | Host unit execution of the reviewed suite, including the five parameterized B07 cases and existing B03/V-06c coverage. Totals are suite-wide, not B07-only; no separate focused B07 totals were supplied |
| Integration suite | PASS; 16 cases, 12,534 assertions | Existing same-project integration/TCP regression. It does not add a B07-specific separate-process run, external implementation or RTU endpoint |

The agent did **not** run builds or tests. Agent work here was static code/assertion
review, documentation changes and scoped `git diff --check`. Record 12's initial
NOT BUILT / NOT TESTED statement is historical; the current evidence is the supplied
execution above. Record 11's ProcessSmoke Method4/68 and other process results remain
historical evidence with their stated scope; no new ProcessSmoke run was supplied.

**Traceability and assertion audit:** the [reviewed B07 matrix](B07_ACCEPTANCE_MATRIX.md)
maps every selected-function and security/ownership row to PROFILE-050/056, exact
native witness requirements, directions, payload/envelope qualifiers, user/association,
production methods and permanent tests. C2 denotes user2/Control/Master-to-Outstation;
M1/129 and M1/130 denote common user1/Monitoring/Outstation-to-Master. New cases use
the existing NETWORK MAL4/16-octet policy, V3 Q07/count1 and V9 Q5B/count1.

| B07 evidence | Supported finding | Accepted boundary |
| --- | --- | --- |
| A: selected FC3 FC4 FC5 envelopes retain typed qualifier and echo bytes | G12V1/G41V1,V2,V3 Q17/Q28, real prior Challenge history, exact per-stage ECHO/SEQ, independently assembled Table A-9 MAC inputs, callbacks and invocation counts | Host typed positive envelope/SBO/direct witness; same provider/implementation, not independent interoperability or physical control proof |
| B: selected non-command functions traverse native Aggressive routing | Native FC1,2,13,20,21,22,23 witnesses, real SA routing and captured verified responses, native time/IIN/assignment callback observations | Capture task is a test-only native task, not an authentication bypass. Native side-effect closure is limited: no post-enable/disable event check, no timestamp-value assertion, and Class1 assignment is idempotent with no target-class/database transition assertion (matrix R2) |
| C: monitoring faults preserve pending control and both borrowed transmissions | FC129/130 rejection without SOE, task completion, CONFIRM or extra operations; original valid token works once; duplicate rejected; both TX owners retained; UNS branch can complete its original user2 SELECT authentication | Solicited FC5 already executed validly; UNS branch stops before the full SBO/CONFIRM cycle finishes (R3). USR99 mutation also changes authenticated input; native group mutation can fail parsing before MAC, so these do not isolate valid-MAC wrong-USR or valid-encoding data tampering (R4) |
| D: expired monitoring keys and reconnect reject retained Aggressive responses | Real expiry prevents native delivery/acknowledgment; borrowed Outstation buffer retained; old response rejected immediately after reconnect | Reconnect clears eligibility. No explicit new ready/KSQ/key assertion or fresh Challenge re-priming precedes replay; not proof of old-response rejection after renewed eligibility (R1) |
| E: signed CSQ half-window boundaries do not consume rejected tokens | Correctly re-MACed delta0/7FFFFFFF/80000000/80000001/FFFFFFFF in both helper directions isolates CSQ policy; rejected token preserves next valid token | Executed codec evidence, not a runtime negotiated boundary. Zero-initialized output weakens this case's dirty-buffer clearing claim; existing exact READ/Table-A9 replay case separately checks clearing after nonzero successful decode (R5) |

**Disposition:** `VERIFIED_HOST` for the selected Aggressive envelope/dispatch/replay/
ownership witnesses explicitly mapped in B07, using the supplied execution and static
review together. No blocking production defect was established. Existing FC6, V-06c,
CONFIRM, timeout/disconnect and unsupported-MAC cases are reused; no new production
fix, public API or algorithm is justified by this review. Full PROFILE-050/056 payload
cross-products/native semantic acceptance and all other Profile/CFG/SEC obligations
are not blanket-promoted. PROFILE_MATRIX.csv and SECURITY_MATRIX.csv remain unchanged.

**Remaining gates and smallest next slice:** preserve MAC-SELECTION, TIMEOUT-ZERO,
P4-OPEN-01/provisional G120V7 Code5/7, independent-peer and G0V209 limitations. No
complete SA v5, IEEE Level4, physical restart/I/O, STM32H743/FreeRTOS, entropy/NVM or
RTU hardware acceptance is claimed. Host fake-lower-layer tests, same-project TCP,
independent-peer interoperability and physical RTU evidence are distinct categories.

The smallest next engineering slice is a **test-only B07-D extension**: explicitly
prove both users' post-reconnect readiness and changed session identity/material,
restore the appropriate history via genuine fresh Challenge/Reply, then assert old
response rejection without SOE/CONFIRM/task completion and current response acceptance.
This distinguishes stale-session/history rejection from reset eligibility gating.
Do not alter production code unless that focused extension reproduces a defect.
Matrix R2/R4/R5 list subsequent native-effect/isolated-fault/dirty-output hardening.
