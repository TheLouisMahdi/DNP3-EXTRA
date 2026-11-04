# Windows protocol issue register

Scope checked against `PROGRESS.md`, the IEEE and security traceability matrices, P4/P6 and remote-key reports, and relevant Master, Outstation, TLS and event TODOs. The private GitHub issue list was empty when queried. This is a rolling issue register. Local uncommitted candidates are identified explicitly. The implementation slice resolves G50 qualifiers, dangling class selectors and the G80 NEED_TIME acknowledgment. It also verifies four-anchor mutual TLS.

Baseline `60436c6ab62f6bd851aa1875797d010a5ac33836`. Published source anchors below refer to the source slice `275300426ed5e210fef69703c99475b11af15408`. Independent interoperability was not executed. The [IEEE 1815-2012 listing](https://standards.ieee.org/ieee/1815/5414/) was checked. No applicable official correction was established for the cited SA ambiguities. Original IEEE and product documents are available locally through [the source index](01_SOURCE_MAP.md).

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

IEEE Table 12-23 (p. 360), Device Profile pp. 8–9, PROFILE-038. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE Table 12-24 (p. 360), Device Profile pp. 9–10, PROFILE-043–046. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment p. 4, Table 1 row 14. TLS trust-store capacity is a product requirement. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE §7.5.5.7 (p. 241) versus Annex A.45.7.2.2. Device Profile p. 11 G120V7. Security amendment p. 5 authorization. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE §7.6.1.4.2 (pp. 242–243) versus §11.9.10.2 (pp. 349–350). Device Profile p. 12. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE Table 7-6 (pp. 206–207), §7.5.3.2 and §7.5.3.3. Device Profile p. 12. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE §7.5.2.1 (p. 203), Table 7-8 rows 5/6/10/12 (pp. 215–222). Device Profile pp. 10–12. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE §7.5.5.5 (pp. 239–240) versus Annex A.45.10. Device Profile p. 11, Security amendment p. 4 row 16. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE Annex A.45.10/A.45.14 and Table 7-16 (p. 245). Device Profile p. 11, Security amendment p. 4 row 16. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE Annex A.45.8, Device Profile p. 11, Security amendment p. 4 row 16. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE §5.5 (pp. 148–154), Annex A.1.1 (p. 438), Device Profile p. 4. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE §11.9.10/Table 11-19 (pp. 349–350). Device Profile p. 12. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE Annex A.47 and §11.9.10. Device Profile p. 12 G122V1/V2. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

**Source**

IEEE §4.4.4 (pp. 48–54), Table 12-8 (p. 354), Table 12-20 (p. 358). Device Profile pp. 6 and 8. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

**Problem**

Generic function scheduling awaits a response. Typed function 6 is absent.

**Affected implementation**

Master. [opendnp3/cpp/lib/src/master/MasterContext.cpp:724](../opendnp3/cpp/lib/src/master/MasterContext.cpp#L724) · `void MContext::PerformFunction` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep acknowledged commands on existing task ownership. A no-response task needs transmission-based completion without claiming remote execution.

**Implementation**

Existing boundary remains. This slice contains no correction for this issue.

**Validation**

No new issue-specific build or execution result claimed.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

Implement typed TX completion and SA negative tests when optional Master issuance is selected.

### IIN-WRITE-SCOPE - NEED_TIME clear and rearm

**Source**

IEEE §4.5.5 (p. 83), Table 12-26 (p. 361). Device Profile p. 10 G80V1. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE §4.4 restart functions, Table 12-23 (p. 360). Device Profile p. 12. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE §7.5.3.3 and Annex A.45.3/A.45.9. Device Profile pp. 10–11, Security amendment p. 3 rows 4–5. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE §7.5 response lifecycle and Table 7-14. Security amendment p. 3 row 3. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE Clause 7 algorithm selection. Security amendment p. 3 row 9. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE Table 7-16 (p. 245), Security amendment p. 4 row 16 and p. 5 row 4. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment pp. 3–4 row 11. TLS 1.3 names are defined by RFC 8446. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment p. 4 row 13. No DNP wire mapping established. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment p. 4 row 15. Certificate policy is external to IEEE DNP application objects. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment p. 5 row 7. Local access policy is outside IEEE wire semantics. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment p. 5 row 9. IEEE Clause 7. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE Table 7-12 (p. 228), Security amendment p. 5 row 10 and p. 6 row 4. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment p. 5 row 11 and Table 1 pp. 3–4. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment p. 6 row 1. No applicable IEEE DNP wire behavior established. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment p. 6 row 2. No applicable IEEE DNP wire behavior established. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment p. 6 rows 3–4. No applicable IEEE DNP wire behavior established. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment p. 6 row 5. No applicable IEEE DNP wire behavior established. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment p. 6 row 6. No applicable IEEE DNP wire behavior established. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment p. 6 rows 7–8. No applicable IEEE DNP wire behavior established. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE §12.1.1 and parsing tables (pp. 351 onward). Supplied Device Profile excerpt pp. 1–2 selects Level 3 plus listed features. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE Table 12-24 (p. 360), Device Profile pp. 9–10. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE §4.2–4.5 application response ownership. Device Profile p. 10. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

Security amendment p. 5 row 2. Listener recovery is transport policy. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

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

IEEE §4.1.5.3 (p. 17), §5.1.5 and Table 5-3 (p. 107), and Table 12-24 (p. 360). Device Profile pp. 5–8 and 12. Original tracking in the EventSelection.cpp default-variation TODO.

**Problem**

After the confirm deadline expired, a new class poll could send the buffered event with the explicit variation from the previous request. An analog event configured for G32V1 was returned as G32V2.

**Affected implementation**

Outstation. [opendnp3/cpp/lib/src/outstation/event/EventSelection.cpp:26](../opendnp3/cpp/lib/src/outstation/event/EventSelection.cpp#L26) · `EventSelection::SelectByClass` at published source `275300426ed5e210fef69703c99475b11af15408`. The candidate changes this function and [opendnp3/cpp/tests/unit/TestOutstationEventResponses.cpp:117](../opendnp3/cpp/tests/unit/TestOutstationEventResponses.cpp#L117) locally.

**Engineering decision**

A class READ selects event classes without specifying each event’s reporting variation. Table 5-3 uses the configured default in that case. The local SelectByClass change mirrors SelectByTypeGeneric at EventSelection.h:54–78, where selection of an unselected record assigns its default or the explicitly requested variation. EventTypeImpl.h:46–50 applies the same default assignment through typed storage. The change preserves event data, class, ownership and confirmation state.

**Implementation**

`EventSelection::SelectByClass` restores the configured variation through `IEventType::SelectDefaultVariation` before setting the selected state. `TestOutstationEventResponses.cpp` covers native response and confirmation ownership.

**Validation**

TestOutstationEventResponses.cpp, OutstationEventResponsesTestSuite - Class poll uses the default variation after an explicit event response times out. The explicit G32V2 READ succeeds, its CONFIRM arrives late, the class poll returns the same point/value as G32V1, and a valid new CONFIRM removes the event. The reproduction exited 1 at the G32V1 assertion before the production fix. The Release build and focused validation exited 0 with 74 cases and 401 assertions after the fix. The unfiltered unit suite passed 720 cases and 59,077 assertions. Full parallel and serial CTest runs both exited 8 with a Method 4 timeout. The candidate remains local pending an integration result that supports publishing it.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

The Method 4 failure can occur independently of this patch. The clock regression uses a static G30 READ and bypasses class/event selection. The event candidate remains local by request. Dedicated TCP or independent peer coverage of the expired-confirm and class reselect sequence remains open.

### METHOD68-RESTART-TIMEOUT - Intermittent post-restart READ timeout

**Source**

IEEE Clause 7 ownership and response lifecycle. Security amendment p. 4 row 16. Original tracking: PROGRESS.md, engineering reports or the source marker at the cited anchor.

**Problem**

One preliminary regression timed out after Method 68 restart. A subsequent run passed with unchanged success requirements.

**Affected implementation**

Master/Outstation. [cli/tests/ProcessSmoke.py:168](../cli/tests/ProcessSmoke.py#L168) · `def secure` at `275300426ed5e210fef69703c99475b11af15408`.

**Engineering decision**

Keep the failure visible. A clean rerun cannot isolate a timing or ownership cause.

**Implementation**

Peer.task in cli/tests/ProcessSmoke.py includes nearby peer output on a failed completion assertion. The success assertion remains enforced. The source slice contains no production correction for the timeout.

**Validation**

One preliminary pc-method68 run failed at an authenticated READ after restart. pc-method68 passed in the full Release CTest run at `275300426ed5e210fef69703c99475b11af15408`. The pass does not identify the cause of the earlier timeout.

**Status**

NOT_YET_IMPLEMENTED

**Remaining dependency**

Capture safe per-peer timing and authentication ownership on recurrence and reproduce with a deterministic fixture.

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
