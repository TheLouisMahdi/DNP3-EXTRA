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

- **G0V209 (first slice):** reports actual negotiated/implemented SA version capability; its return value must not advertise unimplemented SAv5. Status PARTIAL: the Master decodes an external device's real UINTn value; the Outstation returns OBJECT_UNKNOWN and omits the attribute from discovery because no complete SA v5 version is supported (`P6c_REPORT.md`).
- **G0V210, G121, G122:** represent actual supported security-statistic points and events; these cannot be replaced by made-up counters. Status IMPLEMENTED from real per-association statistics: G0V210 with mandatory V254/V255 discovery (`P6c_REPORT.md`), G121 READ/Class 0 and G122V1/V2 publication (`P6b-O2_REPORT.md`), Master typed decode and delivery (`P6b-M1_REPORT.md`).
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
| 15 | Update Key Changes | D | No operational Update Key success producer; no runtime increments | 1 |
| 16 | Failed Update Key Changes | D | No operational Update Key failure producer; no runtime increments | 1 |
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
- Indexes 15/16 require actual Update Key procedure success/failure sources.
  Credential loading and G120 serialization are not Update Key changes. Do not
  fabricate increments while the corresponding operational procedure is absent.
- P6b consumes real reporting-threshold state for G121/G122 publication and G0V210, including retention/discontinuity quality and event snapshots; that wire support is implemented and user-validated (`P6b-O2_REPORT.md`, `P6b-M1_REPORT.md`, `P6c_REPORT.md`). No full SA compliance is advertised by the runtime index enum, and G0V209 remains unavailable on the Outstation.
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

COMMIT READY for the completed static subset: YES. Full P6a completion: NO (P6-OPEN-03 unowned recovery; indexes 15/16 absent). Statistics and G0 wire support is committed and user-validated as recorded in the P6b/P6c reports; no push was performed by the agent.
