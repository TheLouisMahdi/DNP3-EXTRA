# B07 selected Aggressive Mode acceptance matrix

Source baseline: `develop`, `3478a2b448b6ba092cfa5e2b03fb6b09af7f2fd7`.
Review date: 2026-11-07. **Disposition: VERIFIED_HOST for the selected Aggressive
envelope/runtime witnesses mapped below, based on user-reported Windows execution
and static review of the current B07 diff.** This is a scoped Host disposition,
not closure of every native Profile subcase, product deployment or full SA v5.

| User-supplied execution evidence | Reported result | What it establishes |
| --- | --- | --- |
| Release build | PASS | The reported Windows source/build configuration compiled; not protocol conformance by itself |
| Unit suite | PASS; 791 cases, 91,225 assertions | Host unit execution of the reviewed suite, including its five new parameterized B07 cases and existing B03/V-06c cases; these totals are for the entire suite, not B07 alone |
| Integration suite | PASS; 16 cases, 12,534 assertions | Existing same-project integration/TCP coverage and regression; not a new B07-specific TCP case or independent-peer evidence |

The report is attributed to baseline HEAD above plus the reviewed, uncommitted B07
test diff. It is user-supplied execution evidence, not an agent rerun. Exact commands,
build directory, compiler version, run timestamps, per-case output and binary/source
hash binding were not supplied; none is inferred. Test/production source is unchanged
by this review, so no later code edits are represented as tested by those results.
See [Record 13](ENGINEERING_EVIDENCE.md#record-13) for the review disposition.
[Record 12](ENGINEERING_EVIDENCE.md#record-12) preserves the earlier unexecuted status;
[Record 11](ENGINEERING_EVIDENCE.md#record-11) preserves prior V-06c/B03 execution,
including the separate ProcessSmoke runs. No new ProcessSmoke run is reported here.
The PROFILE/SEC CSV outcomes and G0V209 advertisement remain unchanged.

## Authority and scope

- PROFILE-050: G120V3, request FC1-31/Q07 and response FC129/130/Q07.
- PROFILE-056: G120V9, request FC1-31/Q5B and response FC129/130/Q5B.
- IEEE 1815-2012 7.5.2.3.2, 7.5.3.3, A.45.3 and A.45.9; Table A-9 binds the
  actual saved Challenge and current ASDU through the V9 header/length prefix.
- SEC-T1-04/05 require Aggressive capability while discouraging its use. New tests
  use the existing NETWORK default MAL=4 (HMAC-SHA256, 16 octets), not a new product
  algorithm selection. Existing explicit legacy/serial tests are identified below;
  they do not resolve SEC-T1-09/MAC-SELECTION. GMAC is not introduced.
- FC1-31 is an envelope range. Selected native requests are FC1,2,3,4,5,6,13,20,21,22,23.
  Do not import FC7-12 or other unselected optional functions. FC0 is the selected
  CONFIRM dependency, including the normative embedded-Challenge Aggressive exception.
  Standalone FC32/33 authentication and FC131 Authentication Response are not ordinary
  V3/native/V9 wrappers. Existing anti-nesting tests remain applicable.

## Exact wire and ownership contract

| Direction | Native function | V3 | V9 | Key and identity | Association binding |
| --- | --- | --- | --- | --- | --- |
| Master to Outstation | Selected request below | First object; Q07, count=1; UInt32 CSQ and UInt16 USR | Last object; Q5B, count=1, length=16 under MAL4 | Configured user's Control Direction key; new B07 requests use authorized user 2 | Context association 7 and expected peer addresses; helper also rejects a different association argument |
| Outstation to Master | FC129 solicited | First object after four-byte header; Q07/count=1 | Last object; Q5B/count=1/length=16 | Common user 1, Monitoring Direction key | Same association; foreign source is rejected before authentication/task dispatch |
| Outstation to Master | FC130 unsolicited, UNS=1 | Same framing as FC129 | Same framing as FC129 | Common user 1; unsolicited Challenge history | Same association; CON leads to native confirmation only after authentication |
| Master to Outstation | FC0 protected CONFIRM | Q07/count=1; common user 1 | Q5B/count=1 | Control key; exact SEQ/UNS and owned embedded Challenge, or existing standalone confirmation exchange | Independent from user-2 command and monitoring ownership |

There is no association field in V3/V9 and no address bytes in Table A-9's MAC
input. Context routing and configured association enforce that boundary. USR=0
is invalid in V3; Outstation-issued *V1* USR=0 is a separate rule. Native payload
qualifiers below are independent of V3 Q07 and V9 Q5B.

## Permanent test index

`A` = [TestAggressiveMode.cpp](../opendnp3/cpp/tests/unit/TestAggressiveMode.cpp).
`P` = [TestProductionAuthentication.cpp](../opendnp3/cpp/tests/unit/TestProductionAuthentication.cpp).
`T` = [TestSecureAuthentication.cpp](../opendnp3/cpp/tests/integration/TestSecureAuthentication.cpp).
Names below are exact searchable TEST_CASE suffixes (omit the file's class prefix).

| ID | Location and exact suffix | Coverage newly asserted |
| --- | --- | --- |
| B07-A | P: B07 selected FC3 FC4 FC5 envelopes retain typed qualifier and echo bytes | Production Master/Outstation; G12V1 and G41V1/2/3, Q17/Q28; FC3 and FC4 separately, FC5; exact ECHO; independent Table A-9 HMAC assembly for both directions |
| B07-B | P: B07 selected non-command functions traverse native Aggressive routing | Production scheduler, SA and native handlers for the ten selected witnesses below; FC129 decoded only after genuine verification; exact native objects reach a test-only IMasterTask |
| B07-C | P: B07 monitoring faults preserve pending control and both borrowed transmissions | Real FC129/FC130; nine faults each; no measurement delivery, task completion, CONFIRM, successful-auth increment or extra command invocation on rejection; both borrowed TX buffers survive; original valid wire still authenticates once; duplicate cannot authenticate again; user-2 pending Challenge remains completable |
| B07-D | P: B07 expired monitoring keys and reconnect reject retained Aggressive responses | Actual Master clock/key expiry, FC129/130 withheld from native dispatch; no measurement/CONFIRM or false callback; Outstation TX bytes remain borrowed; old wire fails again after genuine fresh negotiation |
| B07-E | A: B07 signed CSQ half-window boundaries do not consume rejected tokens | Correctly re-MACed CSQs in both directions: delta 0, 7FFFFFFF, 80000000, 80000001, FFFFFFFF; only forward half-window accepted; rejected tokens do not consume the next valid token; output erased on failure |

### Reused evidence locators

These exact permanent cases support the reused rows below; they are not new B07
execution counts. Links identify the current reviewed source, not a tested binary hash.

| Evidence group | Exact permanent locator |
| --- | --- |
| READ/MAC/erasure | A [exact READ wire and independent Table A9 transcript](../opendnp3/cpp/tests/unit/TestAggressiveMode.cpp#L71) |
| Association/no seed and frame corruption | A [no challenge and wrong associations cannot authenticate](../opendnp3/cpp/tests/unit/TestAggressiveMode.cpp#L114); A [malformed tampered truncated and wrong user messages are rejected](../opendnp3/cpp/tests/unit/TestAggressiveMode.cpp#L133) |
| Monitoring and CSQ | A [Monitoring IIN and unsolicited context are authenticated](../opendnp3/cpp/tests/unit/TestAggressiveMode.cpp#L164); A [independent challenge histories and CSQ rollover](../opendnp3/cpp/tests/unit/TestAggressiveMode.cpp#L183); A [association Challenge watermark spans UNS categories and preserves forward gaps](../opendnp3/cpp/tests/unit/TestAggressiveMode.cpp#L468) |
| Explicit algorithms | A [explicit IEEE legacy MAC options](../opendnp3/cpp/tests/unit/TestAggressiveMode.cpp#L276); A [each transcript retains its selected MAC after Code 5](../opendnp3/cpp/tests/unit/TestAggressiveMode.cpp#L511) |
| CONFIRM | A [embedded Challenge produces exact first Aggressive Confirm transcript](../opendnp3/cpp/tests/unit/TestAggressiveMode.cpp#L300); A [embedded Challenge ordering fields and cancellation fail closed](../opendnp3/cpp/tests/unit/TestAggressiveMode.cpp#L347); A [V3 native V1 V9 response uses full incoming MAC in Confirm seed](../opendnp3/cpp/tests/unit/TestAggressiveMode.cpp#L386); P [embedded Challenge requires Aggressive Confirm with ordinary transmit disabled](../opendnp3/cpp/tests/unit/TestProductionAuthentication.cpp#L1534) |
| Production eligibility/denial | P [aggressive operation and response require prior challenge completion](../opendnp3/cpp/tests/unit/TestProductionAuthentication.cpp#L1127); P [aggressive invalid MAC authorization and replay fail closed](../opendnp3/cpp/tests/unit/TestProductionAuthentication.cpp#L1153); P [Code 7 distinguishes policy denial from OPERATE ownership failure](../opendnp3/cpp/tests/unit/TestProductionAuthentication.cpp#L2917) |
| Borrowed TX/lifetime | P [outstation reset preserves aggressive response bytes already in flight](../opendnp3/cpp/tests/unit/TestProductionAuthentication.cpp#L2069); P [master aggressive TX lifetime survives reset timeout and disconnect](../opendnp3/cpp/tests/unit/TestProductionAuthentication.cpp#L2160) |
| B03 | P exact tag `[sa-fc6]`, nine cases beginning with [FC6 authenticates selected typed forms and completes only its protected TX](../opendnp3/cpp/tests/unit/TestProductionAuthentication.cpp#L4172); includes invalid/unauthorized traffic, phase timeout/disconnect, expired/foreign Challenges, no-history downgrade, independent CONFIRM/monitoring, owned Error and exact TX deadline |
| V-06c | P exact tag `[sa-v06-mac-policy]`: [unsupported control MAC drops silently without cancelling independent monitoring](../opendnp3/cpp/tests/unit/TestProductionAuthentication.cpp#L3811); [unsupported monitoring MAC drops silently without cancelling independent control](../opendnp3/cpp/tests/unit/TestProductionAuthentication.cpp#L3873); [unsupported MAC settles only its native CONFIRM responder](../opendnp3/cpp/tests/unit/TestProductionAuthentication.cpp#L4048) |
| Same-project TCP | T [session keys authenticated READ CONTROL and reconnect](../opendnp3/cpp/tests/integration/TestSecureAuthentication.cpp#L119), including its FC6 extension; T [interrupted renewal cannot authorize and reconnect negotiates fresh keys](../opendnp3/cpp/tests/integration/TestSecureAuthentication.cpp#L661) |
| Native class behavior (separate from B07 envelopes) | [ProfileClasses - ENABLE_UNSOLICITED arms and DISABLE_UNSOLICITED clears class 1](../opendnp3/cpp/tests/unit/TestProfileClasses.cpp#L67); [ProfileClasses - ASSIGN_CLASS maps G60V1 to class 0 and rejects count qualifiers](../opendnp3/cpp/tests/unit/TestProfileClasses.cpp#L95) |

All five cases are covered by the supplied unit-suite PASS, at the assertion scope
below. No focused B07 count/result was supplied separately. B07-A through D exercise
production components on a Host; B07-E is executed codec evidence only.

B07-B's capture task only supplies selected native request bytes and observes the
native response. It uses IMasterTask, the existing scheduler, APDURequest, session
negotiation, role authorization and context routing; it does not manufacture
successful authentication or change a public API. B07-E is a helper/codec boundary
fixture, not runtime proof; production fixtures B07-A through D use real startup
and Challenge/Reply history. Half-window rejection is the existing engineering
replay policy, not a newly inferred normative algorithm.

## Selected function acceptance matrix

Every row below maps to PROFILE-050 (V3/Q07) and PROFILE-056 (V9/Q5B), with
SEC-T1-04/05 covering Aggressive reception/issuance. Additional native requirement
IDs are listed explicitly. Payload qualifiers are independent of the outer wrapper.

Production references: [AGG](../opendnp3/cpp/lib/src/auth/AggressiveMode.cpp)
(`RememberChallenge`, `Create`, `Verify`),
[MC](../opendnp3/cpp/lib/src/master/MasterContext.cpp),
[OC](../opendnp3/cpp/lib/src/outstation/OutstationContext.cpp), and
[OS](../opendnp3/cpp/lib/src/outstation/OutstationStates.cpp).
`C2` means Master-to-Outstation, association 7, configured user 2, Control key;
`M1/129` and `M1/130` mean Outstation-to-Master, common user 1, Monitoring key,
solicited and unsolicited history respectively. All use V3 Q07/count1 and V9
Q5B/count1/16-octet MAL4 except legacy fixtures explicitly identified elsewhere.
Normal Challenge/Reply bootstrap and mode-disabled baseline cases are separate
from these Aggressive frames and need not contain V3/V9. Native grouped CSV
response qualifiers apply function-specifically: WRITE/configuration acknowledgment
is null, READ carries the selected data, and FC6 has no ordinary response even
when its grouped control row lists ECHO.
`H` means VERIFIED_HOST for the stated witness; `R` means existing suite evidence
reused. Neither label promotes every payload variation or native side effect.

| Native request / exact additional requirements | Native witness and qualifiers | Direction / ownership | Production behavior and permanent evidence | Host disposition / limit |
| --- | --- | --- | --- | --- |
| FC1 READ; PROFILE-043 witness | B07-B item 0: G60V1/Q06 Class 0; actual G1 response data | C2 -> M1/129 | MC `ResumeActiveTask` wraps; OC `ProcessObjects`/`RespondToReadRequest`/`HandleRead` uses native database; MC `ProcessAuthenticatedResponse` releases verified objects to B07NativeTask. B07-B checks nonempty G1 payload and exact captured native bytes. A exact READ/Table A9 and T session keys READ CONTROL tests are reused | H/R: Aggressive Class-0 READ witness. Other selected READ objects/qualifiers retain their own tests; no assertion that every measurement variation has an Aggressive cross-product witness |
| FC2 WRITE; PROFILE-038 and PROFILE-047 | B07-B items 1/2: G50V1/Q07/count1/time=1000; G80V1/Q00/start=stop=7/value0 | C2 -> M1/129 null | OC `RouteAuthentication` authorizes, `HandleWrite` invokes WriteHandler; B07-B checks exact request objects, null authenticated response, one timestamp callback and cleared DEVICE_RESTART. Native time/IIN tests remain separate | H: authenticated dispatch and IIN-clear witness. Timestamp value/latency is not checked at the callback; see R2 |
| FC3 SELECT; PROFILE-019,035,036,037; CFG-08 | G12V1 and G41V1/2/3; Q17/Q28 | C2 -> M1/129 exact ECHO | OC `RouteAuthentication` binds `selectUser`; `HandleSelect` and ControlState create the native selection. B07-A checks per-stage function, group/variation/qualifier, full successful ECHO, independent Table A-9 HMAC and selection count | H: typed selected positive envelope/ECHO cases; native control-policy/physical-output acceptance is separate |
| FC4 OPERATE; PROFILE-019,035,036,037; CFG-08 | Same four forms/Q17,Q28; genuine preceding SELECT | C2 -> M1/129 exact ECHO | OC `RouteAuthentication` checks authenticated user equals `selectUser`; `HandleOperate` validates native selection/sequence/deadline. B07-A checks matching response SEQ/ECHO, callback and one operation. P aggressive invalid MAC authorization and replay fail closed, Code 7 OPERATE-ownership and native control-boundary tests provide negatives | H/R: successful typed SBO and reused authorization/selection boundaries; not a new per-type negative cross-product |
| FC5 DIRECT_OPERATE; PROFILE-019,035,036,037; CFG-08 | Same four forms/Q17,Q28; no SELECT | C2 -> M1/129 exact ECHO | OC authenticated dispatch -> `HandleDirectOperate`; B07-A checks function5, exact envelope/ECHO and one operation without a SELECT. B07-C/D use a pending FC5 task for solicited-monitoring rejection | H: selected typed direct-control envelope; a valid FC5 may already execute before its response is rejected, so monitoring failure does not undo that authenticated operation |
| FC6 DIRECT_OPERATE_NR; PROFILE-019,035,036,037; CFG-08 | G12V1/G41V1/2/3; Q17/Q28 | C2; **no ordinary command response** | MC explicit no-response SA phases and `CompleteAuthenticatedNoResponseTask`; OC `ProcessDirectOperateNoAck` preserves native no-response/deduplication. P all nine [sa-fc6] cases, T FC6 extension and Record 11's ProcessSmoke evidence | R: current suites passed; no new process run. SUCCESS means local authenticated submission with UNDEFINED point status, not proven remote execution |
| FC13 COLD_RESTART; PROFILE-068; response PROFILE-042 | B07-B item3: no objects; G52V2/Q07/count1/fine-delay37 response | C2 -> M1/129 | OC `HandleRestart` calls MockOutstationApplication and serializes its delay; MC authenticated native capture checks exact G52V2 objects | H: simulated callback/delay envelope only; RESTART-APP and physical RTU restart are not closed |
| FC20 ENABLE_UNSOLICITED; PROFILE-044,045,046; CFG-11 | B07-B item4: G60V2,V3,V4/Q06, without count fields | C2 -> M1/129 null | OC `HandleEnableUnsolicited` applies native class mask; B07-B checks exact request, null authenticated response and no request-error IIN. TestProfileClasses 'ENABLE_UNSOLICITED arms and DISABLE_UNSOLICITED clears class 1' exercises native event behavior separately | H/R: envelope/acknowledgment witness; B07-B itself does not observe class-mask change or subsequent event delivery (R2) |
| FC21 DISABLE_UNSOLICITED; PROFILE-044,045,046; CFG-11 | B07-B item5: G60V2,V3,V4/Q06 | C2 -> M1/129 null | OC `HandleDisableUnsolicited` clears native class mask; same B07-B and native ProfileClasses evidence | H/R: envelope/acknowledgment witness, not full authenticated enable/disable behavioral closure (R2) |
| FC22 ASSIGN_CLASS; PROFILE-003,010,020 and PROFILE-044 witnesses | B07-B items6/7/8: G60V2/Q06 + each G1V0,G3V0,G30V0/Q06; simulated point0 for each family | C2 -> M1/129 null | OC `HandleAssignClass` -> AssignClassHandler/Database; B07-B checks callback type and range0..0, exact request and null verified response. TestProfileClasses covers Class0 assignment and qualifier rejection separately | H/R: family dispatch/callback envelope. All points already start in Class1, target PointClass and actual database transition are not asserted; PROFILE-043/045/046 class choices are not new B07-B witnesses (R2) |
| FC23 DELAY_MEASURE; PROFILE-069; response PROFILE-042 | B07-B item9: no objects; G52V2/Q07/count1/fine-delay0 response | C2 -> M1/129 | OC `HandleDelayMeasure` emits native fine-delay object; MC verified native capture checks its exact bytes | H: no-object/fine-delay envelope; no physical clock-accuracy claim |
| FC0 CONFIRM; PROFILE-067 plus normative 7.5.2.3.2(e)-(h) dependency | Exact SEQ/UNS; V3/Q07 + V9/Q5B for Aggressive CONFIRM; embedded V1 precedes V9 where applicable | Master-to-Outstation common user1/Control key, association7; no ordinary response | MC `CheckConfirmTransmit`/`ProcessAuthenticatedResponse`, AGG embedded-history rules and OC `ProcessConfirm`/OS confirmation ownership. A embedded Challenge/Confirm transcript and ordering suites; P embedded Challenge suite; B03 independent CONFIRM tests | R: complete existing CONFIRM cases. B07-C additionally checks queued CONFIRM/control contention, then stops after the original SELECT is authenticated; it does not finish that full SBO/CONFIRM cycle (R3) |

## Security/ownership coverage and precise gaps

| Obligation / exact authority | Ownership and production behavior | Permanent evidence | Host acceptance boundary |
| --- | --- | --- | --- |
| First Challenge, per-session eligibility, enable/disable; PROFILE-050/056, SEC-T1-04/05, 7.5.3.3 | C2/M1 histories; AGG `RememberChallenge`, MC `ResumeActiveTask`/SessionKeys installation, OC `RouteAuthentication`/`BeginTx` require ready keys and directional eligibility | P aggressive operation and response require prior challenge completion; A no challenge and wrong associations cannot authenticate; B03 configured Aggressive FC6 cannot downgrade; B07-A/B real bootstrap | H/R: no injected runtime keys or manufactured successful authentication. Codec fixtures use controlled seeds and are identified as such |
| Exact framing/transcript and MAC policy; PROFILE-050 Q07, PROFILE-056 Q5B, A.45.3/A.45.9; SEC-T1-09 limitation | AGG `Create`/`Verify` and AuthenticationMACPolicy bind full Challenge and current ASDU, V3 count1, V9 count1/length selected from V1 MAL; NETWORK default4 | A exact READ/Table A9, explicit IEEE legacy MAC options, each transcript retains its selected MAC after Code5; T explicit legacy boolean; B07-A independent transcript assembly | H/R for tested configuration. Same crypto provider is used; no independent-peer/crypto-certification claim and no product MAC selection inferred |
| FC129/130 monitoring; PROFILE-050/056 response columns | M1/129 and M1/130; OC `BeginTx`, MC `RouteAuthentication`/`ProcessAuthenticatedResponse` preserve distinct history and native dispatch | A Monitoring IIN and unsolicited context; P embedded Challenge suite; B07-C/D actual responses/events | H/R: actual binary-event FC130 witness. Not every event family/variation or fragmentation combination is repeated under B07 |
| User/association; A.45.3 USR, PROFILE-050/056, SEC-T2-10 roles remain product-limited | C2 vs M1; contexts check peer addresses/association; MC insists monitoring USR=1, OC finds configured user/key and authorizes; no address bytes are added to MAC | A no challenge and wrong associations; B03 FC6 invalid/unauthorized traffic incl. common-user valid MAC denial; B07-C fault0 altered USR99 and fault1 unchanged valid wire from foreign peer | H/R for those cases. Unknown-user mutation also changes MAC input; it does not isolate a correctly MACed, configured wrong-USR monitoring case (R4) |
| Invalid/shortened/altered frames; PROFILE-050/056, A.45.9 | MC/OC pass accepted envelopes through AGG `Verify` before dispatch; rejected frames must not consume the valid token | A malformed/tampered/truncated suite; P aggressive invalid MAC/authorization; B03 FC6; B07-C nine faults, original valid wire and replay | H/R: fail-closed behavior and token preservation. Some cases fail structural parsing before MAC; native-group mutation is not an isolated payload-value MAC test (R4) |
| Replay/stale CSQ/boundaries; A.45.3 and existing engineering half-window policy | AGG `Verify` compares candidate CSQ with selected history and advances only after valid MAC; contexts synchronize native Challenger sequence | A independent histories/rollover, association watermark across UNS categories; P/B03 control replay; B07-C monitoring duplicate; B07-E signed deltas0,7FFFFFFF,80000000,80000001,FFFFFFFF | H runtime replay witnesses; executed codec evidence for exact half-window. Do not describe B07-E as a runtime negotiated-peer test; dirty-output caveat R5 |
| Expiry/reconnect; PROFILE-050/056 readiness dependency; SEC-T1-07/08 remain separately scoped | MC session readiness and reset eligibility gate M1; SessionKeys/context disconnect/install retain correct lifetime/ownership | P master aggressive TX lifetime; B03 expiry cases; B07-D expiry and immediate post-reconnect old-response rejection; T renewal/reconnect tests | H/R for expiry and reset-gate rejection. B07-D does not directly assert fresh KSQ/keys or restore Challenge eligibility before replay (R1) |
| Control/monitoring contention and pending CONFIRM; PROFILE-050/056, PROFILE-067, CFG-06/11 | MC/OC separate task, responder, Challenger, confirmation and borrowed TX ownership; MC `CheckConfirmTransmit`; OS validates SEQ/UNS | P embedded Challenge and both TX-lifetime cases; B03 independent CONFIRM/monitoring; B07-C original-buffer equality and later valid reply | H/R. C's solicited branch holds an Aggressive FC5 task after its valid operation; only its unsolicited branch holds a pending user-2 Control Challenge. See R3 |
| Timeout/disconnect/no unauthorized execution; PROFILE-019/035..037, CFG-08 and 7.5.2.3.2(i) for FC6 | MC task timers/OnLowerLayerDown, OC one-shot authenticated release/authorization and no-response dispatcher; independent owners retained | P aggressive invalid MAC/authorization and TX lifetime; nine B03 phase/negative cases; AuthenticationRuntime timeout/disconnect; T interrupted renewal; B07-D no monitoring delivery | R/H for asserted phases. A valid operation may precede a lost/rejected monitoring response; no claim that response failure rolls it back |
| Unsupported/disallowed MAL; PROFILE-050/056 V1-history dependency; preserve P4-OPEN-01 | MasterResponder rejects V1 MAL; MC `CancelAuthenticationReply` and OC monitoring-only cleanup preserve independent exchange/TX owners; AGG uses retained history's algorithm | All three P [sa-v06-mac-policy] cases for2/6; A each transcript retains selected MAC after Code5 | R: included in reported full unit pass, no new focused count. MAL is in V1, not invented in V3/V9. GMAC6 remains unsupported; Code5/7 interpretation stays provisional |

## Assertion audit and review concerns

These are limits on the claim, not newly demonstrated production defects. Passing
the suite does not turn an unasserted property into executed evidence.

| Review ID | What the current assertions establish | False-positive risk / unproven extension | Disposition |
| --- | --- | --- | --- |
| R1 - B07-D reconnect | Expired monitoring cannot deliver/complete/confirm; borrowed Outstation bytes survive; old response is rejected immediately after reconnect | Pumping exchange traffic alone is not an explicit ready/changed-KSQ/key assertion. Reconnect clears monitoring eligibility, and no fresh Challenge is primed before old replay, so rejection can happen before MAC verification. This does not prove old-key rejection after eligibility is restored | Accepted Host reset-gate witness only. Smallest next slice is a test-only B07-D extension described below |
| R2 - B07-B native effects | Genuine SA dispatch, exact selected request, authenticated response/capture; timestamp callback count; restart IIN cleared; typed assignment callback/range | FC20/21 have no post-mask/event check; G50 callback value is not asserted; assignment starts in Class1 and does not assert tuple PointClass/database transition. A broken native no-op could pass some of these checks. Native ProfileClasses/time evidence remains separate | Accept envelope/dispatch witness, not complete CFG-11/class/time semantic acceptance; no native CSV promotion |
| R3 - B07-C completion scope | Bad frames cannot deliver, complete a task or queue a CONFIRM; both TX buffers/control owner remain; original response authenticates once. UNS branch later authenticates the original SELECT Reply | It stops while further SELECT-response/SBO/CONFIRM work remains. In the solicited branch the valid FC5 already executed before the corrupted monitoring frame arrived | Accept stated contention/ownership witness; do not claim full cycle completion or zero prior authenticated execution |
| R4 - B07-C fault isolation | Unknown USR, foreign peer, changed tag, coherent length15, altered IIN/native group and qualifier/count mutations are rejected; original valid wire still works | USR99 mutation retains the old MAC and therefore does not isolate identity gating. Byte14 changes the native group and can fail parsing before MAC. A correctly MACed wrong configured USR and syntactically valid value-only tamper would make stronger isolated negatives | Current fail-closed assertions valid; narrow integrity/identity claims accordingly. Foreign-address test keeps the original MAC and does isolate routing |
| R5 - B07-E boundary/output | Correctly re-MACed deltas isolate stale/half-window rejection from MAC corruption; rejected candidate leaves Sequence and next valid token usable | Output starts zero; the rejected-candidate zero-byte loop alone cannot prove clearing pre-existing nonzero bytes. Forward-then-replay branch asserts rejection but not output bytes. A exact READ/Table A9 test separately checks output erasure after a successful decode followed by replay; Guard clearing also reviewed statically | Accept signed boundary/codec evidence. Do not attribute a new dirty-buffer erasure proof to B07-E |
| R6 - evidence independence | A/B07-A assemble Table A-9 inputs separately; runtime fixtures use genuine negotiation and production routing; reported suites pass | Both peers/helpers and crypto provider belong to this project. B07NativeTask intentionally validates only single-response/request-error framing and captures bytes; external semantic checks are limited to the witnesses above | Accept same-project Host evidence only, not independent-peer interoperability, RTU behavior or full SA v5 |

## Smallest justified next engineering slice

Extend **B07-D only**, with test/fixture assertions and no production change unless
that extension reproduces a defect: assert both users are ready after reconnect,
assert changed session identity/material using existing secret-clearing snapshots,
complete a genuine fresh Challenge/Reply to restore the required direction/category's
eligibility, then submit the retained old response and a genuine current response.
Require old rejection with no SOE/CONFIRM/task completion, and current acceptance.
This isolates stale-session/history rejection from the current reset-gate rejection.
Do not fake readiness/history or add optional algorithms. R2/R4/R5 are subsequent
focused assertion-hardening items; none authorizes unrelated protocol expansion.

## Defect-to-change mapping and limits

| Finding | Scoped correction | Production change |
| --- | --- | --- |
| Gaps in exact selected typed FC3/4/5 envelope/ECHO assertions | B07-A | None |
| No explicit native runtime envelope witnesses for the selected non-command function list | B07-B plus test-only scheduler access/capture task | None |
| Generic corruption coverage did not establish runtime monitoring rejection while both TX owners and a Control Challenge remain live | B07-C | None |
| Missing receiving-Master monitoring expiry/reconnect witness | B07-D | None |
| Existing rollover tests did not distinguish signed half-window CSQ rejection from MAC rejection | B07-E | None |

No blocking production defect was established by this review. The supplied Release,
unit and integration PASS results support VERIFIED_HOST for the mapped, bounded B07
envelope/dispatch/ownership witnesses, together with existing baseline evidence.
R1-R6 restrict the accepted claim; properties not asserted remain unverified.
AggressiveMode, MasterContext, OutstationContext, public APIs, generated code,
B03/V-06c and the supplied tested test diff are unchanged by this documentation review.

Remaining product/external gates: independent-peer interoperability; MAC-SELECTION;
TIMEOUT-ZERO; P4-OPEN-01 and provisional G120V7 Code5/7 meanings. G0V209 advertisement
stays gated. No complete SA v5, general Level4 or RTU hardware acceptance is claimed.
Native payload/class/time, physical restart/I/O, entropy/NVM and platform obligations
remain with their own Profile/CFG/security requirements. The agent did not build or
run tests during this review; the Windows execution results are user-supplied.
