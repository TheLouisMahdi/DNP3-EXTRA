# DNP3 IEEE 1815-2012 decision register

Derived from `OPEN_DECISIONS` in the editable XLSX; normative choices and product defaults are separate from test evidence.
Project-owner direction: implement selected requirements according to IEEE 1815-2012. Where the IEEE text contradicts itself, use the recorded fail-closed/Annex interpretation; preserve the exact conflict as traceability, not as an undefined development choice.

**Status:** decisions selected for implementation; no new production code, build, or Test Harness execution was performed during this reference update.

## D-01 - Vendor/model/firmware identity blank

- **Linked requirements:** CFG-01
- **Classification:** `EXTERNAL_AUTHORITY_REQUIRED`
- **Implementation decision:** Provision actual manufacturer, model, hardware and firmware/software revision from controlled release metadata; reject incomplete production identity.
- **IEEE/source anchors:** 14.7.1-14.7.2 pp469-470; Profile p1
- **Rationale:** CLI identifies a diagnostic role; inspected files expose no authoritative RTU identity.
- **Security/configuration boundary:** No invented identities; simulation labels stay separate.
- **Permanent tests:** Load complete and incomplete release manifests; inspect emitted profile.
- **Decision state:** `EXTERNAL_OPEN`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** Product owner must supply identity.

## D-02 - TX FT3 maximum blank

- **Linked requirements:** CFG-02
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** Use 292 octets RX and TX total FT3 bytes, with 250 user octets including the one-octet transport header and at most 249 application octets.
- **IEEE/source anchors:** 9.2.4.1.2 and 9.2.4.2 pp319,322-323; Profile p2
- **Rationale:** 255 LENGTH counts five link fields and 250 data octets; 10 header bytes plus 250 data bytes plus 32 CRC bytes.
- **Security/configuration boundary:** Reject oversized or bad-CRC frames; never use 292 as payload.
- **Permanent tests:** Accept 292, segment 250 APDU octets; reject corrupt final CRC and LENGTH inconsistencies.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** Runtime acceptance pending.

## D-03 - APDU RX/TX defaults and upper bounds blank

- **Linked requirements:** CFG-03
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** Set 4096-byte configurable Host RX/TX as a gated target. Use 2048 as current protected-path fallback until all fixed auth buffers and reassembly are checked; fallback does not demonstrate requested Host TX >2048.
- **IEEE/source anchors:** 4.3 p80; 8.2 pp313-314; 10.2.1 p337; Profile p2
- **Rationale:** Profile p2 conditions TX configurability on size >2048; the requested Host target exceeds it. CLI wires RX/TX settings; OutstationChallenger and MasterResponder still use DEFAULT_MAX_APDU_SIZE=2048.
- **Security/configuration boundary:** Reject configurations above verified capacity; proposed Host cap 4096. Support configured TX caps of 2048 and Master request cap 249; minimum Master receive capability 2048, RTU Outstation receive >249. A larger transport buffer alone is insufficient.
- **Permanent tests:** Test 2048/2049/4096/4097, authenticated and unprotected, both directions, truncated/missing segments and queue bounds.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** 4096 protected-path implementation evidence pending.
- **2026-11-10 reference gate:** IEEE §4.3 (PDF pp80-81): Master sends ONE complete Application Fragment per request; 249 is a configurable maximum mode for capable Masters, not an unconditional maximum. §8.2 Transport Segments each contain <=249 Application octets; full request may span many segments when receiver supports it.
- **2026-11-10 reference gate:** G120V8 must fit as a complete Object in one Application Fragment with all APDU and Q5B overhead; fail closed if configured receiver/buffer cannot hold it. Never divide a signed certificate between multiple Application Fragments. Test 249/250 transport data and app buffer 2048/2049/4096/4097 plus malformed/reordered segments.

## D-04 - Retries defaults and per-function eligibility

- **Linked requirements:** CFG-04;PROFILE-067;PROFILE-069
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** Use two retries for eligible transactions; link 0-5 and application 1-5. Treat first transmission separately.
- **IEEE/source anchors:** 4.4.5 p97; 4.4.15 pp106-107; 9.2.6 pp325-326; 10.2 pp337-340; F0_PRODUCT_DECISIONS.md F0-04
- **Rationale:** Never replay DIRECT_OPERATE at application level; disable automatic application retries for FC6 and restart; honor FC23 and time WRITE restrictions at both layers.
- **Security/configuration boundary:** Confirmed link retry uses same FCB. Preserve approved F01-D: one user-data NACK/DFC=0 reset recovery per logical send, independent of timeout retries; NACK during reset, DFC=1 and a second NACK fail. Eligible application retry preserves APDU identity and association; never apply generic retry to hazardous or prohibited functions.
- **Permanent tests:** Drop acknowledgments; verify exact limits, timeout/reconnect and zero duplicate actuation.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** Application retry plumbing and per-function coverage pending.

## D-05 - Link confirm default unselected

- **Linked requirements:** CFG-05
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** Expose Never, Always and On multi-frame fragments. Initial RTU Host setting On multi-frame; use Never when appropriate for a reliable TCP deployment.
- **IEEE/source anchors:** 9.2.4.1.3 pp319-320; 9.2.6 pp325-326; 10.2.1 p337
- **Rationale:** Profile p2 permits all modes; IEEE generally recommends disabling link confirmations.
- **Security/configuration boundary:** Receive and ACK valid confirmed traffic regardless of local transmit policy; use per-peer FCB/FCV state.
- **Permanent tests:** Exercise all modes for one and multiple segments, loss of ACK, duplicate and link reset.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** TCP/independent-peer evidence pending.

## D-06 - Four timeout limits/defaults missing

- **Linked requirements:** CFG-07
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** Set link confirm 2 s, transport reassembly 5 s, application confirm 5 s and complete application response 5 s as separate configurable defaults; proposed Host bounds 100-120000 ms.
- **IEEE/source anchors:** 4.3 pp80-81; 4.6.4 p132; 8.2.4 pp313-314; 9.3.1 pp328-333; 10.2 pp337-340
- **Rationale:** Timers correspond to distinct states. CLI already separates response, RX fragment and solicited/unsolicited confirmation; inspect link timer before wiring.
- **Security/configuration boundary:** Use monotonic clocks; SA reply has independent D-11 policy; complete-response deadline is separate from intermediate progress.
- **Permanent tests:** Expire each independently; test boundaries, late messages and rollover.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** Defaults are Host policy; end-to-end timing and applicable timer ranges pending.

## D-07 - Owner-approved CROB point policy (Pulse On = Sometimes)

- **Linked requirements:** CFG-09;PROFILE-019;CFG-08
- **Classification:** OWNER_APPROVED
- **Project-owner authorization (2026-11-11):** Owner-approved D-07 (2026-11-11): support CLOSE 0x41 and TRIP 0x81 on configured Complementary points (Latch or Two-output as appropriate). Permit 0x01 NUL/PULSE_ON only on explicitly enabled Activation points; deny on Complementary, disabled or undefined points. Require count=1, no queue/clear, no Pulse Off or Latch OpType. Use the configured safe point pulse duration rather than Master-requested duration; preserve exact request/echo and validate timing semantics. SELECT validates and arms only, never actuates. Authenticate SA v5, authorize the user and recheck interlocks and safe execution conditions before every actuation. Preserve generic library capabilities.
- **IEEE/source anchors:** 4.4.4 pp90-96; A.8.1.3.2, Tables A-1/A-2 pp550-552; Profile physical pp3,6.
- **Permanent tests:** Test 0x41/0x81 on both Complementary models and 0x01 on enabled Activation; deny 0x01 on Complementary/disabled/unknown points, unsupported TCC/OpType, queue/clear, count=0 or >1 and invalid timing/configuration. Check configured pulse duration, no actuation on SELECT, authorization/interlock denial, expired/mismatched selection and duplicate/replay without extra execution. Exercise G12V1 Q17/Q28, FC3/4/5/6 under SA REQUIRED, exact acknowledged echo and no FC129 for FC6; record receiver effects and generic compatibility regression.
- **Decision state:** OWNER_APPROVED_IMPLEMENTATION_PENDING
- **External/deployment gate:** Actual RTU point indices, point models, safe pulse durations, physical output mapping and interlocks remain product/deployment inputs. Host may use explicit test-only fixtures. No new runtime test evidence; implementation pending. Overlapping pulse/busy policy remains PROPOSED, not approved.
- **Source correction:** Tavanir Profile physical p3 selects Pulse On = Sometimes, not Never. The missing product-specific explanation does not block Host policy implementation after this owner decision.

## D-08 - Timed binary event variation policy / explanation missing

- **Linked requirements:** CFG-10;PROFILE-008;PROFILE-009;PROFILE-039;PROFILE-040
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** Default binary event G2V2; configured G2V3 is the alternative default and requires CTO. Preserve explicit G2V1 requests without making it an untimed default.
- **IEEE/source anchors:** 5.1.3 pp145-147; A.3.1-A.3.3 pp532-534; A.24 pp696-699; Profile p3
- **Rationale:** Default time-tagged behavior follows selected profile.
- **Security/configuration boundary:** Keep explicit G2V1 read support; do not substitute an untimed default.
- **Permanent tests:** Verify explicit variations, default G2V0, uint16 offset boundary and CTO synchronization.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** Independent-peer test pending.

## D-09 - Startup unsolicited enablement/classes incomplete

- **Linked requirements:** CFG-11;PROFILE-044;PROFILE-045;PROFILE-046;PROFILE-067
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** When configured for unsolicited, send one startup NULL series immediately and retry until confirmed independently of ordinary retry count; gate class data until applicable FC20 enable; class policy configurable.
- **IEEE/source anchors:** 4.6.3-4.6.6 pp131-135; 5.1.1.1 pp143-144; Profile p4
- **Rationale:** Separate startup NULL and event data; restore SA before protected restart clear and enable.
- **Security/configuration boundary:** Use FC0 with UNS and exact SEQ; preserve pending event ownership.
- **Permanent tests:** Test startup NULL, missing confirmation, one class enabled, disable/restart and event retention.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** D-10 contract exception separate.

## D-10 - Static unsolicited after restart versus IEEE startup NULL

- **Linked requirements:** CFG-12
- **Classification:** `IEEE_IMPLEMENTATION_POLICY_FIXED`
- **Implementation decision:** IEEE-strict startup: on outstation restart assert IIN1.7 (and IIN1.4 when time is required); if unsolicited is configured, transmit the initial FC130 unsolicited NULL with FIR=FIN=CON=UNS=1, no data objects and NO G120V1 (IEEE 7.5.2.3.2(h)); retry until matching FC0/UNS/SEQ application confirmation regardless of ordinary unsolicited retry count. Ignore pre-restart unsolicited enablement; retain events. Do not originate unsolicited event data until a new FC20 ENABLE_UNSOLICITED for the relevant class/points. Send only events in normal unsolicited responses, except the explicitly permitted deprecated G10V2/G40V2 cases; never put static objects in the startup NULL. The Master SHALL parse static objects if received from another peer. Master confirms the initial NULL immediately even during other requests; on IIN1.7 it establishes SA keys if configured, writes G80V1 index 7 = 0 to clear restart, performs the normative startup/integrity sequence, then issues FC20 after having received the NULL. Static integrity reporting is solicited, not a substitute for the Tavanir-selected static-unsolicited subcase. IEEE 4.6.6 pp133-135; 5.1.1.1 pp143-144; 7.5.2.3.2(h) p250.
- **IEEE/source anchors:** IEEE 4.6.6 pp133-135; 5.1.1.1 pp143-144; 7.5.2.3.2(h) p250; Profile p4
- **Rationale:** IEEE 4.6.6/5.1.1.1/7.5.2.3.2(h) fixed. Tavanir p4 static-unsolicited selection contradicts this behavior: contractual variance is documented, not implemented as nonstandard traffic.
- **Security/configuration boundary:** No G120V1 in initial unsolicited NULL. Master must parse static if received; Outstation sends only permitted unsolicited events/legacy exceptions.
- **Permanent tests:** Permanent unit/wire/separate-process TCP: initial NULL exactly no object/G120V1; UNS/SEQ/FIR/FIN/CON and FC0 matching; wrong/late/duplicate confirm; unlimited startup retries until correct confirm; event retention through restart; FC20 after startup; prohibit pre-enable unsolicited events; confirm unsolicited during solicited transaction; Master IIN1.7/SA/G80V1/integrity/FC20 ordering; parse received peer static while local Outstation never emits forbidden restart static; permitted legacy G10V2/G40V2 only when IEEE allows; secure-auth restart/reconnect.
- **Decision state:** `OWNER_IEEE_STRICT_FIXED`
- **External/deployment gate (if any):** `CONTRACT_VARIANCE_RECORDED`
- **Remaining evidence or factual variance:** IEEE 4.6.6/5.1.1.1/7.5.2.3.2(h) fixed. Tavanir p4 static-unsolicited selection contradicts this behavior: contractual variance is documented, not implemented as nonstandard traffic. Runtime PASS remains unproven.
- **Project-owner authorization:** Owner: IEEE 1815-2012 strict. No proprietary static unsolicited at startup.

## D-11 - Zero security response timeout undefined

- **Linked requirements:** SEC-T1-03
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** Configure zero as alias for finite 2.0 s; accept 0.1-120.0 s in 100 ms steps; persist setting and use monotonic expiry.
- **IEEE/source anchors:** 7.6.1.4 and 7.6.1.4.1 p284; Security p3 T1 r3
- **Rationale:** IEEE sets default and resolution; Tavanir gives 0-120 s with no zero semantics.
- **Security/configuration boundary:** No indefinite acceptance window. Contract interpretation of zero remains open.
- **Permanent tests:** Test 0, 0.1, 2.0, 120.0, out-of-range, timeout and late reply.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** Contract confirmation of zero semantics.

## D-12 - MAC choices left unchecked

- **Linked requirements:** SEC-T1-09;PROFILE-048;PROFILE-049;PROFILE-050;PROFILE-056
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** TCP baseline HMAC-SHA-256 truncated to 16 octets. Additional algorithms require explicit supported-media policy and configuration.
- **IEEE/source anchors:** 7.6.1.1 pp283-284; 7.6.2.1 pp290-292; Security p3 T1 r9
- **Rationale:** IEEE TCP default; source checkboxes for the required product option set are unmarked.
- **Security/configuration boundary:** No TCP 8-byte substitution or automatic SHA-1 fallback. IEEE §7.6.1.1.1 separately requires configurable legacy SHA-1 capability (10 octets on TCP), disabled in the selected Host policy. Reject invalid length and mismatched negotiation. IEEE §7.6.1.1.1 requires configurable HMAC-SHA-1 support (10 bytes on TCP); disable by default in production but retain supported explicit interoperability mode. HMAC-SHA-256/16 is the default network MAC.
- **Permanent tests:** Test known answer, wrong length, cross-media code and unsupported algorithm.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** Any additional mandatory Tavanir option remains unconfirmed. Full IEEE legacy capability requires separate evidence. IEEE §7.6.1.1.1 requires configurable HMAC-SHA-1 support (10 bytes on TCP); disable by default in production but retain supported explicit interoperability mode. HMAC-SHA-256/16 is the default network MAC. Acceptance evidence pending.

## D-13 - TLS 1.3 table includes TLS 1.2 cipher names

- **Linked requirements:** SEC-T1-11;SEC-T2-02
- **Classification:** `IEEE_2012_BASELINE_FIXED`
- **Implementation decision:** TLS 1.2 with mTLS, explicit trust/name verification, no NULL ciphers or silent downgrade. Implement mandatory TLS_RSA_WITH_AES_128_SHA interoperability capability per IEEE §7.8.2, separately configurable from secure-production ECDHE+AEAD policy. TLS 1.3, if enabled, uses actual TLS 1.3 suites defined in RFC 8446, never TLS 1.2 names.
- **IEEE/source anchors:** 7.8.1-7.8.4 pp296-297; Security pp3-5
- **Rationale:** IEEE §7.8.1-7.8.4 p296-297 fixes 2012 behavior. Tavanir Tables 1/2 differ; apply IEEE 2012 to claimed baseline and classify TLS 1.3 as optional extension. Production cipher availability and client/server certificates require tests/provisioning.
- **Security/configuration boundary:** TLS1.3 uses independent cipher API; preserve selected TLS1.2 choices; no NULL, obsolete protocol or silent downgrade.
- **Permanent tests:** Test negotiated version/cipher, selected RSA/ECDSA identities, invalid namespace and IEEE mandatory suite separately.
- **Decision state:** `IMPLEMENTATION_POLICY_FIXED`
- **External/deployment gate (if any):** `DEPLOYMENT_POLICY_INPUT`
- **Remaining evidence or factual variance:** IEEE §7.8.1-7.8.4 p296-297 fixes 2012 behavior. Tavanir Tables 1/2 differ; apply IEEE 2012 to claimed baseline and classify TLS 1.3 as optional extension. Production cipher availability and client/server certificates require tests/provisioning. Runtime PASS remains unproven.
- **Project-owner authorization:** Owner: TLS 1.2 is the IEEE 1815-2012 acceptance baseline; separately configurable TLS 1.3 is an extension, not an IEEE-2012 claim.

## D-14 - Cipher change request timer and TLS1.3 KeyUpdate meaning

- **Linked requirements:** SEC-T1-13
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** TLS 1.2 called endpoint initiates symmetric rekey at application SA key-change interval/count trigger; default 2 s, selected RTU configuration 1-60 s. Generic IEEE-facing support must cover the SA reply timer range through at least 120 s. Terminate on timeout.
- **IEEE/source anchors:** 7.8.5 pp297-298; 7.6.1.4.1 p284; Security p4 T1 r13
- **Rationale:** F0-23 records the differing published ranges. Separate selected RTU and generic IEEE configuration validation.
- **Security/configuration boundary:** Ignore requests from calling endpoint as specified; do not map TLS 1.3 KeyUpdate to this rule.
- **Permanent tests:** Test scheduled and count triggers, caller initiation, timely/late peer and disconnect.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `NORMATIVE_PEER_REVIEW`
- **Remaining evidence or factual variance:** Runtime renegotiation and validation of both configuration ranges remain pending.

## D-15 - Certificate authority provisioning not defined

- **Linked requirements:** SEC-T1-14;SEC-T2-02
- **Classification:** `IMPLEMENTATION_POLICY_FIXED__DEPLOYMENT_INPUT_REQUIRED`
- **Implementation decision:** Support at least four concurrent provisioned CA anchors and mutual chain plus peer identity validation, including expiry at handshake; support 8192-byte certificate minimum maximum and individual certificate configuration.
- **IEEE/source anchors:** 7.8.7.1-7.8.7.4.4 pp298-299; Security p4 T1 r14
- **Rationale:** Trust policy fixed by IEEE §7.8.7. Physical production CA keys and peer identities cannot be inferred; test fixture CA is test-only.
- **Security/configuration boundary:** Fail handshake for absent, invalid, expired, wrong-name or untrusted peer. Do not auto-enroll roots.
- **Permanent tests:** Test each anchor, intermediates, wrong identity, expiry, oversize and no client certificate.
- **Decision state:** `IMPLEMENTATION_POLICY_FIXED`
- **External/deployment gate (if any):** `PRODUCTION_TRUST_PROVISIONING`
- **Remaining evidence or factual variance:** Trust policy fixed by IEEE §7.8.7. Physical production CA keys and peer identities cannot be inferred; test fixture CA is test-only. Runtime PASS remains unproven.
- **Project-owner authorization:** Owner: provisionable >=4 CA anchors and explicit mutually verified peer identities; no trust-on-first-use or auto-root enrollment.

## D-16 - CRL file/provider/refresh policy unresolved

- **Linked requirements:** SEC-T1-15
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** Check authenticated local CRL every 12 h; hourly resolution; proposed 1-168 h Host range. Reject known revoked new peers and terminate sessions using newly confirmed revoked certificates.
- **IEEE/source anchors:** 7.8.7.4.3-4.4 p299; Security p4 T1 r15
- **Rationale:** Missing CRL access does not by itself terminate established sessions; expiry alone also does not terminate them.
- **Security/configuration boundary:** Keep last validated CRL; require usable revocation policy for new connections; surface refresh error separately.
- **Permanent tests:** Test cached/new revocation, stale/unreachable source, invalid CRL signature, unrelated session and expiry.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** Current OpenSSL CRL loading is handshake evidence only; active sweep pending.

## D-17 - RUK Method 4 / Method 68 selection and association ownership

- **Linked requirements:** SEC-T1-16;SEC-T2-04
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** Default Method 4, AES-256 Key Wrap and HMAC-SHA-256; Method 68 opt-in per association after provisioning and D-24 interoperability proof.
- **IEEE/source anchors:** 7.5.4.6 pp271-273; 7.6.1.4.9 pp286-287; Security pp4-5
- **Rationale:** Method 4 is mandatory and default under IEEE when remote Update Key changes are supported.
- **Security/configuration boundary:** One active method per association; reject mismatch without downgrade. Method 68 uses RSAES-OAEP-2048/SHA-256, DSA SHA-256 L2048/N256 and 256-bit Update Key. IEEE §7.6.1.2.1 requires AES-128 Key Wrap capability; selected remote-Update-Key Method 4 remains AES-256 Key Wrap/HMAC-SHA-256 default. The two requirements must not be conflated; method 68 is opt-in per association.
- **Permanent tests:** Test both provisioned peers, method mismatch, replay, confirmation loss and rekey continuity.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** D-18 and D-24 remain applicable to asymmetric path. IEEE §7.6.1.2.1 requires AES-128 Key Wrap capability; selected remote-Update-Key Method 4 remains AES-256 Key Wrap/HMAC-SHA-256 default. The two requirements must not be conflated; method 68 is opt-in per association. Acceptance evidence pending.

## D-18 - G120V8 certificate IEC source reviewed; runtime and production PKI still pending

- **Linked requirements:** PROFILE-055;SEC-T1-16
- **Classification:** `IEEE_IMPLEMENTATION_POLICY_FIXED`
- **Implementation decision:** IEEE A.45.8 pp778-782: G120V8 is a Master-to-Outstation FC32 (0x20) request and the sole object; Q=0x5B variable length, valid object prefix length <=65535. Wire body begins UINT8 Key Change Method (ASYMMETRIC only, no Method 4), UINT8 Certificate Type (1 ID/X.509v3; 2 Attribute/RFC5755), then the corresponding authority-signed IEC/TS 62351-8 certificate. Master relays authority certificate unchanged; authority is not the Master. For configured Method 68 validate the IEEE-listed id-dsa-with-sha256 certificate signatures; respect the external IEC profile's additional required algorithms without inventing a profile. Validate ASN.1/DER, trust chain, algorithm/method consistency, signatures, issuer, identity/public key (ID cert), holder/preceding ID cert (Attribute cert), certificate validity, roles, allowed operations (Attribute: Delete/Change only), allowed AoR(s), monotonically increasing revision, status-change sequence/monotonic serial, replay and user-association ownership. Apply secure-time rules from Table A-8, including later re-evaluation after trusted time sync. Obey user-status/key-change lifecycle; delete immediately; defer add/role/expiry activation until normative successful key change. Respond using permitted FC131/IIN or eligible FC131/G120V7 errors, without inventing success objects. No conflation with TLS transport PKI.
- **IEEE/source anchors:** IEEE A.45.8 pp778-782; Table A-8 p782; 7.5.5.5 pp281-282; 7.6.1.4.9 pp286-287
- **Rationale:** IEC/TS 62351-8:2011 has now been provided and inspected. RFC 5280/5755 full certificate-profile rules and applicable IEC/TS 62351-3 revocation clauses remain pre-implementation checks. Operational CA/AA, AoR and independent peer are separate post-implementation/deployment gates. Method 4 MUST NOT use G120V8.
- **Security/configuration boundary:** Method 4 prohibited for G120V8; asymmetric Update Key method only; explicit external CA, AoR and identity; fail closed.
- **Permanent tests:** Permanent unit/integration/wire/separate-process TCP Master↔Outstation FC32/Q5B: valid external ID certificate; Attribute after ID; Add/Delete/Change; actual asymmetric Update Key lifecycle; correct FC131/error semantics; invalid authority, bad signature, wrong AoR, wrong holder/user/association, absent ID, Method 4 with V8, bad certificate type, method/signature mismatch, malformed/truncated/oversize ASN.1 and Q5B length, expired/future-dated/revoked according to applicable standards, stale revision/SCS/serial, replay, role escalation, restart/time sync; ensure no state mutation or premature role activation on rejection. Separate fixture CA from configurable production trust, preserve test output + commit SHA.
- **Decision state:** `OWNER_IEEE_STRICT_FIXED`
- **External/deployment gate (if any):** `EXTERNAL_NORMATIVE_PROFILE_INPUT`
- **Remaining evidence or factual variance:** IEC/TS 62351-8:2011 has now been provided and inspected. RFC 5280/5755 full certificate-profile rules and applicable IEC/TS 62351-3 revocation clauses remain pre-implementation checks. Operational CA/AA, AoR and independent peer are separate post-implementation/deployment gates. Method 4 MUST NOT use G120V8. Runtime PASS remains unproven.
- **Project-owner authorization:** Owner: IEEE A.45.8 strict, FC32/Q5B singleton, externally signed ID/Attribute certificates with real validation and permanent TCP test harness.
- **2026-11-10 reference gate:** Annex A.45.8.2 (physical PDF p778) explicitly encodes UINT8 Key Change Method + UINT8 Certificate Type + Certificate. Therefore Q5B size L implies Certificate length = L-2, 2<=L<=65535, maximum certificate 65533. Annex A.45.8.3 (PDF p782) incorrectly says minus one octet and incorrectly calls certificate IEC/TS 62351-5. This is an internal source contradiction, NOT a claimed IEEE erratum.
- **2026-11-10 reference gate:** Require ONE complete FC32/Q5B single-Object Application Fragment, which can span multiple <=249-Application-octet Transport Segments. Do not split the object across Application Fragments. Reject missing/empty/invalid DER, L=0/1/2 and truncated prefix or configured receiver overflow; include L=3/65534/65535 capacity limits and signed certificate scenarios.

- **2026-11-10 IEC 2011 source resolution:** The complete 48-page IEC/TS 62351-8:2011 PDF has been supplied and its applicable Clause 1, 5.2, 9.2-9.5, 11 and Table 8 requirements reviewed. OID `1.2.840.10070.8.1`; X.509v3 ID and AC v2; 8192-octet maximum supported token, 3-year maximum lifetime, UTC second resolution; nonempty UserRoleInfo, signed RoleID -32768..32767, AoR 1..64 UTF8, revision 0..255, roleDefinition 0..23 UTF8, Add=1/Delete=2/Change=3, SCS 0..2^32-1; one record per (AoR,roleDefinition). IEC specifies 2011 legacy SHA-1/SHA256 and RSA-1024/2048 support; avoid interpreting legacy compatibility as secure production issuance approval. Use IEEE Table A-8 operation/issuer/AoR rules and DNP3-specific Table 7-12 role permissions. Profile C software token is not G120V8.
- **2026-11-10 capacity and implementation gate:** IEC token support up to 8192 octets plus FC32/Q5B/APDU overhead must fit one accepted Application Fragment; proposed 4096 Host cap cannot meet maximum. Review CFG-03, receiver allocation limits and segmented transport without fragmenting the certificate object. Current develop@6fc3129a static: Scala Group120Var8 codec present; RemoteUpdateKeys.cpp whitelist/ProcessHeader lacks V8; runtime MISSING, tests NOT_EXECUTED.
- **PRE_IMPL_NORMATIVE_DEPENDENCIES:** independently verify RFC5280 X.509 and RFC5755 AC path rules plus applicable IEC/TS 62351-3 revocation; decide Host trust fixtures, configured AoR, fail-closed CRL/ACRL handling. Full IEC text is no longer an external missing input.
- **DUE_AFTER_IMPLEMENTATION:** independent-peer RFC/IEEE wire interoperability, external certificate/signature vectors, actual Windows positive/negative TCP evidence, secure-time/expiry/revocation/restart evidence. Production CA/AA, real device identity/AoR are DUE_AT_DEPLOYMENT; STM32 key NVM/entropy remain deferred hardware scope. See G120V8_DUE_AFTER_IMPLEMENTATION.md.

## D-19 - Role permissions and default authentication policy undefined

- **Linked requirements:** SEC-T2-09;SEC-T2-10;SEC-T2-11;SEC-T1-02;SEC-T3-03
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** Configure at least two distinct users. Administrator changes security policy; ordinary user may change permitted technical settings; both perform explicitly granted ordinary actions.
- **IEEE/source anchors:** 7.5.4.4 pp267-268; Table 7-12 p270; 7.5.5.7 p283; Security pp3,5
- **Rationale:** Separate local administration from SA authority-assigned roles and protected-function authorization.
- **Security/configuration boundary:** Deny by default; validate association, user, expiry, operation and ownership; authority owns remote role assignment.
- **Permanent tests:** Test two users, role matrix, role/association substitution, expired/disabled user and rejected escalation.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** Deployment provisioning remains external.

## D-20 - Local RTU password and credential storage policy

- **Linked requirements:** SEC-T2-07;SEC-T3-04;SEC-T3-06
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** For human passwords use salted PBKDF2-HMAC-SHA-256 with 600000 iterations and random 128-bit salt, 256-bit verifier; protect recoverable keys with Windows DPAPI under service identity and restrictive ACLs.
- **IEEE/source anchors:** No direct IEEE password KDF clause; 7.6.1.4.10 p288 for protocol key material; Security pp5-6
- **Rationale:** Store verifiers and recoverable keys separately; parameters versioned; baseline minimum password length 15, allow at least 64, check compromised-password list and rate-limit.
- **Security/configuration boundary:** Reject default/hardcoded production secrets; never write plaintext keys or expose them in diagnostics; test credentials isolated.
- **Permanent tests:** Test same-password unique salts, failed verification, cross-account DPAPI deny, log scan and restart.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** Physical NVM evidence outside Host.

## D-21 - Hardware/network ports and secrets need target integration

- **Linked requirements:** SEC-T3-01;SEC-T3-02;SEC-T3-05
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** Close unnecessary Windows listeners and disable unused user accounts; bind to explicit interfaces and allowlist; keep physical connector disablement separate.
- **IEEE/source anchors:** Security p6 T3 r1-3,5; no direct IEEE listener-hardening clause
- **Rationale:** Network controls apply to Windows Host; physical connector controls apply to RTU.
- **Security/configuration boundary:** No diagnostic or cleartext listener enabled by default in secure deployment; secrets externally provisioned.
- **Permanent tests:** Scan bound ports, wrong-interface attempt, disabled user, secure startup and configuration persistence.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `HOST_SCOPE_TRACKED`
- **Remaining evidence or factual variance:** Physical port validation outside Host.

## D-22 - Firmware signing requirements are recommended, not mandatory

- **Linked requirements:** SEC-T3-07;SEC-T3-08
- **Classification:** `OUTSIDE_WINDOWS_HOST`
- **Implementation decision:** Retain SEC-T3-07/08 as recommended firmware signing and verification.
- **IEEE/source anchors:** Security p6 T3 r7-8; no direct IEEE firmware-signing clause
- **Rationale:** Firmware acceptance is deferred to RTU target.
- **Security/configuration boundary:** Keep original classifications; Windows executable signing is separate.
- **Permanent tests:** Target later: valid signature, modified image, wrong signer and rollback policy.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `HOST_SCOPE_TRACKED`
- **Remaining evidence or factual variance:** No Windows Host acceptance gate.

## D-23 - P4-OPEN-01 G120V7 code 5 / 7 ambiguity

- **Linked requirements:** PROFILE-054;SEC-T1-01
- **Classification:** `IEEE_ANNEX_ENUM_SELECTED`
- **Implementation decision:** Encode and decode G120V7 error reasons per IEEE A.45.7.2.2: 5 = MAC Algorithm Not Supported; 7 = Authorization Failed. Reject forbidden operation regardless of diagnostic code. Never downgrade MAC/key policy on error.
- **IEEE/source anchors:** A.45.7.2.2 pp776-777; 7.5.5.7 p283; 7.6.2.1.2 p292
- **Rationale:** Normative selected wire mapping is Annex A.45.7.2.2 p776. §7.5.5.7 p283 incorrectly calls authorization error 5; P4-OPEN-01 remains an explicitly recorded IEEE internal conflict, not an unchosen implementation behavior.
- **Security/configuration boundary:** Reject authorization regardless of error mapping; never treat authorization denial as a cue to weaken MAC policy.
- **Permanent tests:** Test both error codes, no authorization bypass, no fallback and peer behavior.
- **Decision state:** `IEEE_WIRE_MAPPING_FIXED`
- **External/deployment gate (if any):** `DOCUMENTED_IEEE_INTERNAL_CONFLICT`
- **Remaining evidence or factual variance:** Normative selected wire mapping is Annex A.45.7.2.2 p776. §7.5.5.7 p283 incorrectly calls authorization error 5; P4-OPEN-01 remains an explicitly recorded IEEE internal conflict, not an unchosen implementation behavior. Runtime PASS remains unproven.
- **Project-owner authorization:** Owner: use exact G120V7 Code 5 = MAC Algorithm Not Supported and Code 7 = Authorization Failed from Annex A.45.7.2.2.

## D-24 - RUK-OPEN-01/02 SCS wrap and Method 68 signature encoding

- **Linked requirements:** PROFILE-057;PROFILE-061;PROFILE-059;PROFILE-060;PROFILE-062
- **Classification:** `ENGINEERING_SECURITY_BASELINE_FIXED`
- **Implementation decision:** IEEE §7.5.5.5 demands receiver SCS greater than previously received; A.45.10.2.2 says the authority wraps after 0xFFFFFFFF. Preserve receiver anti-replay: reject 0 after max in same authority/user trust epoch; perform explicit, authorized new epoch/credential re-enrollment before exhaustion, not an implicit replay-state reset. For Method 68, Table A-12 input order, DSA-SHA-256 (L=2048,N=256), RSAES-OAEP-2048/SHA256, and canonical DER DSA signature per current crypto provider are selected implementation profile; verify canonical encoding, fail closed, require independent wire vector/peer interop before VERIFIED.
- **IEEE/source anchors:** 7.5.5.5 p282; A.45.10.2.2 p787; A.45.14.2.2/Table A-12 pp796-797
- **Rationale:** IEEE §7.5.5.5 p282 and A.45.10.2.2 p787 conflict at wrap; secure receiver rule takes precedence within a trust epoch. A.45.14.2.2/Table A-12 pp796-797 specifies signed data but not DER packaging, so DER is a documented implementation profile choice, not a sourced IEEE requirement.
- **Security/configuration boundary:** Do not accept zero after max by silently clearing replay state. Treat native DER as provisional until independent authoritative vectors.
- **Permanent tests:** Test max−1/max/zero, durable replay, wrong signer, signature mutation and externally supplied wire vectors.
- **Decision state:** `IMPLEMENTATION_POLICY_FIXED__SOURCE_CONFLICT_DOCUMENTED`
- **External/deployment gate (if any):** `INDEPENDENT_INTEROP_TEST`
- **Remaining evidence or factual variance:** IEEE §7.5.5.5 p282 and A.45.10.2.2 p787 conflict at wrap; secure receiver rule takes precedence within a trust epoch. A.45.14.2.2/Table A-12 pp796-797 specifies signed data but not DER packaging, so DER is a documented implementation profile choice, not a sourced IEEE requirement. Runtime PASS remains unproven.
- **Project-owner authorization:** Owner: SCS strictly monotonic per issuer+user+association, persistent replay barrier; fail closed before UINT32 wrap and require controlled authority reset/re-enrollment. Use canonical ASN.1 DER DSA-SHA256 signature bytes for Method 68 as implemented; do not label DER an explicit IEEE 1815 wire mandate.

## D-25 - G121/G122 thresholds/time/retention unresolved

- **Linked requirements:** PROFILE-063;PROFILE-064;PROFILE-065;PROFILE-066;PROFILE-002
- **Classification:** `IEEE_THRESHOLD_RULE_SELECTED`
- **Implementation decision:** IEEE §7.6.1.4.2 p284: create a G122 event when counter increment since startup or previous G122 event reaches the configured threshold (delta >= threshold). Threshold max 65535, defaults per Table 7-6; update threshold baseline only when the event occurs; persist monotonic uint32 totals, do not freeze/clear, preserve association and CONFIRM ownership.
- **IEEE/source anchors:** 7.4.1.8 p221; 7.5.2.2/Table 7-6 pp246-249; 7.6.1.4.2 p284; 11.9.10/Table 11-19 pp391-392; Table 12-63 p416; A.46/A.47 pp800-805
- **Rationale:** §11.9.10.2 p392 uses 'exceeds', conflicting with precise SHALL 'incremented by the amount' in §7.6.1.4.2. Select explicit threshold SHALL rule; retain P6-OPEN-01 as an IEEE textual discrepancy, not a pending product choice.
- **Security/configuration boundary:** No unrequested index aliasing or cross-association mutation. Follow Annex association ID and quality bits.
- **Permanent tests:** Test thresholds −1/equal/+1, concurrent events, wrap/restart/quality, report confirmation, two associations and exact event time.
- **Decision state:** `IEEE_7_6_1_4_2_FIXED`
- **External/deployment gate (if any):** `G122_RUNTIME_TESTS`
- **Remaining evidence or factual variance:** §11.9.10.2 p392 uses 'exceeds', conflicting with precise SHALL 'incremented by the amount' in §7.6.1.4.2. Select explicit threshold SHALL rule; retain P6-OPEN-01 as an IEEE textual discrepancy, not a pending product choice. Runtime PASS remains unproven.
- **Project-owner authorization:** Owner: generate G122 event when increment since startup/previous report is >= configured threshold; Class-1 initial mapping; retain per-association totals durably.

## D-26 - G0V209 truthful advertisement gated

- **Linked requirements:** PROFILE-001;SEC-T1-01
- **Classification:** `IMPLEMENTATION_EVIDENCE_PENDING`
- **Implementation decision:** Advertise G0V209 value 5 only once actual configured SA v5 capability is demonstrated; omit unsupported attribute meanwhile.
- **IEEE/source anchors:** A.1.1 p480; 7.6.1.5 p290
- **Rationale:** Codec declaration and partial SA implementation are insufficient.
- **Security/configuration boundary:** No false support advertisement in Compatibility or partial builds.
- **Permanent tests:** Test targeted G0V209 read under verified SA and compatibility/partial profiles.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `CURRENT_CODE_AND_TEST_EVIDENCE`
- **Remaining evidence or factual variance:** Current runtime and independent-peer evidence pending.

## D-27 - Cold restart has no production application effect

- **Linked requirements:** PROFILE-068;PROFILE-047
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** Use meaningful simulated Cold Restart hook: return G52V2/Q07 count 1 before reset; initial simulated quiet period 1000 ms, clear volatile command/session/reassembly state, reload configured values and assert DEVICE_RESTART.
- **IEEE/source anchors:** 4.4.9 p100; 5.1.1.1 pp143-144; A.25.2 p701
- **Rationale:** Preserve pending event handling per startup rules; CLI restart console currently asserts IIN only.
- **Security/configuration boundary:** Respect advertised delay; reauthenticate, clear restart IIN, integrity poll, enable unsolicited.
- **Permanent tests:** Test real separate-process wire and state changes; no second actuation or physical reboot claim.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** Host hook/runtime pending; physical reboot outside Host.

## D-28 - Counter-free production profile vs generic library

- **Linked requirements:** CFG-13
- **Classification:** `CONTRACT_EXPLICIT`
- **Implementation decision:** Configure no G20-G23 counter points in selected Windows RTU profile; preserve generic stack counters.
- **IEEE/source anchors:** Profile p4; IEEE A.10-A.13 reference only pp558-606
- **Rationale:** Contract says no counters reported.
- **Security/configuration boundary:** Keep unrelated diagnostics and generic library available.
- **Permanent tests:** Test Class 0 integrity and explicit counter request in RTU profile; generic regression.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `CURRENT_CODE_AND_TEST_EVIDENCE`
- **Remaining evidence or factual variance:** Runtime evidence pending.

## D-29 - User credential expiry/persistence semantics

- **Linked requirements:** SEC-T1-17
- **Classification:** `ENGINEERING_BASELINE_SELECTED`
- **Implementation decision:** For SA User Status Change, start day-based expiry at receipt to nearest second and activate role/expiry after successful key change; preserve authenticated receipt/expiry record across restart.
- **IEEE/source anchors:** 7.5.5.5-7.5.5.7 pp281-283; A.45.10.2.2 p788; Security p4 T1 r17
- **Rationale:** Use elapsed monotonic time while running and trustworthy persisted time basis across restart; a wall-clock correction cannot extend access.
- **Security/configuration boundary:** Deny expired or unverifiable credentials and invalidate deleted user's keys immediately.
- **Permanent tests:** Test receipt vs activation, expiration boundary, restart, forward/backward clock and lost time basis.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `PRODUCT_OR_CONTRACT_DECISION`
- **Remaining evidence or factual variance:** Trusted production time source/provisioning remains deployment input.

## D-30 - 2026-11-10 selected G32V5 and G41V4 denial code not runtime verified

- **Linked requirements:** All 119 IDs; applies to applicable Windows and independent-peer evidence
- **Classification:** `IMPLEMENTATION_EVIDENCE_PENDING`
- **Implementation decision:** Require current revision, named tests, peer identities, wire captures and results for Windows and independent-peer acceptance.
- **IEEE/source anchors:** DNP3_PDD_PLAN/WINDOWS_HOST_ROADMAP.md; IEEE 14.7 pp469-470
- **Rationale:** Static and historical evidence remain distinct.
- **Security/configuration boundary:** No PASS inferred from tests present or historical hashes.
- **Permanent tests:** Run focused named cases on Windows and attach logs with exact revision and configurations.
- **Decision state:** `DISPOSITION_RECORDED`
- **External/deployment gate (if any):** `CURRENT_CODE_AND_TEST_EVIDENCE`
- **Remaining evidence or factual variance:** Latest execution ledger documents scoped prior Windows tests at c25dd10. No runtime tests executed in this reference task.
