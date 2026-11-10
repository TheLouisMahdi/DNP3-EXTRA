# IEEE reference decision register

Derived from the workbook's OPEN_DECISIONS sheet. Engineering defaults are project choices. External gates remain explicit. Physical page numbers refer to the supplied PDFs.

## D-01 — Vendor/model/firmware identity blank

- **IDs** — CFG-01
- **Classification** — EXTERNAL_AUTHORITY_REQUIRED
- **Baseline** — Provision actual manufacturer, model, hardware and firmware/software revision from controlled release metadata; reject incomplete production identity.
- **Source** — 14.7.1–14.7.2 pp469–470; Profile p1
- **Rationale** — CLI identifies a diagnostic role; inspected files expose no authoritative RTU identity.
- **Boundary** — No invented identities; simulation labels stay separate.
- **Acceptance** — Load complete and incomplete release manifests; inspect emitted profile.
- **Remaining** — Product owner must supply identity.

## D-02 — TX FT3 maximum blank

- **IDs** — CFG-02
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Use 292 octets RX and TX total FT3 bytes, with 250 user octets including the one-octet transport header and at most 249 application octets.
- **Source** — 9.2.4.1.2 and 9.2.4.2 pp319,322–323; Profile p2
- **Rationale** — 255 LENGTH counts five link fields and 250 data octets; 10 header bytes plus 250 data bytes plus 32 CRC bytes.
- **Boundary** — Reject oversized or bad-CRC frames; never use 292 as payload.
- **Acceptance** — Accept 292, segment 250 APDU octets; reject corrupt final CRC and LENGTH inconsistencies.
- **Remaining** — Runtime acceptance pending.

## D-03 — APDU RX/TX defaults and upper bounds blank

- **IDs** — CFG-03
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Set 4096-byte configurable Host RX/TX as a gated target. Use 2048 as current protected-path fallback until all fixed auth buffers and reassembly are checked; fallback does not demonstrate requested Host TX >2048.
- **Source** — 4.3 p80; 8.2 pp313–314; 10.2.1 p337; Profile p2
- **Rationale** — Profile p2 conditions TX configurability on size >2048; the requested Host target exceeds it. CLI wires RX/TX settings; OutstationChallenger and MasterResponder still use DEFAULT_MAX_APDU_SIZE=2048.
- **Boundary** — Reject configurations above verified capacity; proposed Host cap 4096. Support configured TX caps of 2048 and Master request cap 249; minimum Master receive capability 2048, RTU Outstation receive >249. A larger transport buffer alone is insufficient.
- **Acceptance** — Test 2048/2049/4096/4097, authenticated and unprotected, both directions, truncated/missing segments and queue bounds.
- **Remaining** — 4096 protected-path implementation evidence pending.

## D-04 — Retries defaults and per-function eligibility

- **IDs** — CFG-04;PROFILE-067;PROFILE-069
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Use two retries for eligible transactions; link 0–5 and application 1–5. Treat first transmission separately.
- **Source** — 4.4.5 p97; 4.4.15 pp106–107; 9.2.6 pp325–326; 10.2 pp337–340; F0_PRODUCT_DECISIONS.md F0-04
- **Rationale** — Never replay DIRECT_OPERATE at application level; disable automatic application retries for FC6 and restart; honor FC23 and time WRITE restrictions at both layers.
- **Boundary** — Confirmed link retry uses same FCB. Preserve approved F01-D: one user-data NACK/DFC=0 reset recovery per logical send, independent of timeout retries; NACK during reset, DFC=1 and a second NACK fail. Eligible application retry preserves APDU identity and association; never apply generic retry to hazardous or prohibited functions.
- **Acceptance** — Drop acknowledgments; verify exact limits, timeout/reconnect and zero duplicate actuation.
- **Remaining** — Application retry plumbing and per-function coverage pending.

## D-05 — Link confirm default unselected

- **IDs** — CFG-05
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Expose Never, Always and On multi-frame fragments. Initial RTU Host setting On multi-frame; use Never when appropriate for a reliable TCP deployment.
- **Source** — 9.2.4.1.3 pp319–320; 9.2.6 pp325–326; 10.2.1 p337
- **Rationale** — Profile p2 permits all modes; IEEE generally recommends disabling link confirmations.
- **Boundary** — Receive and ACK valid confirmed traffic regardless of local transmit policy; use per-peer FCB/FCV state.
- **Acceptance** — Exercise all modes for one and multiple segments, loss of ACK, duplicate and link reset.
- **Remaining** — TCP/independent-peer evidence pending.

## D-06 — Four timeout limits/defaults missing

- **IDs** — CFG-07
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Set link confirm 2 s, transport reassembly 5 s, application confirm 5 s and complete application response 5 s as separate configurable defaults; proposed Host bounds 100–120000 ms.
- **Source** — 4.3 pp80–81; 4.6.4 p132; 8.2.4 pp313–314; 9.3.1 pp328–333; 10.2 pp337–340
- **Rationale** — Timers correspond to distinct states. CLI already separates response, RX fragment and solicited/unsolicited confirmation; inspect link timer before wiring.
- **Boundary** — Use monotonic clocks; SA reply has independent D-11 policy; complete-response deadline is separate from intermediate progress.
- **Acceptance** — Expire each independently; test boundaries, late messages and rollover.
- **Remaining** — Defaults are Host policy; end-to-end timing and applicable timer ranges pending.

## D-07 — Pulse On = Sometimes with missing explanation

- **IDs** — CFG-09;PROFILE-019;CFG-08
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Support Trip/Close. Permit Pulse On only on explicitly configured eligible points with selected TCC/OpType, count=1 and interlocks; default deny.
- **Source** — 4.4.4 pp90–96; A.8.1.3.2 and Table A-1 pp550–552; Profile pp3,6
- **Rationale** — Use fixed per-point IEEE control model; validate NUL/TRIP/CLOSE separately from PULSE_ON.
- **Boundary** — Reject reserved TCC, prohibited OpTypes, queue/clear and invalid timing/count; no actuation on SELECT.
- **Acceptance** — Test both eligible trip/close directions, NUL policy, denied bits, unauthorized/replayed and expired SELECT.
- **Remaining** — Physical interlocks and actuator parameters outside Host.

## D-08 — Timed binary event variation policy / explanation missing

- **IDs** — CFG-10;PROFILE-008;PROFILE-009;PROFILE-039;PROFILE-040
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Default binary event G2V2; configured G2V3 is the alternative default and requires CTO. Preserve explicit G2V1 requests without making it an untimed default.
- **Source** — 5.1.3 pp145–147; A.3.1–A.3.3 pp532–534; A.24 pp696–699; Profile p3
- **Rationale** — Default time-tagged behavior follows selected profile.
- **Boundary** — Keep explicit G2V1 read support; do not substitute an untimed default.
- **Acceptance** — Verify explicit variations, default G2V0, uint16 offset boundary and CTO synchronization.
- **Remaining** — Independent-peer test pending.

## D-09 — Startup unsolicited enablement/classes incomplete

- **IDs** — CFG-11;PROFILE-044;PROFILE-045;PROFILE-046;PROFILE-067
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — When configured for unsolicited, send one startup NULL series immediately and retry until confirmed independently of ordinary retry count; gate class data until applicable FC20 enable; class policy configurable.
- **Source** — 4.6.3–4.6.6 pp131–135; 5.1.1.1 pp143–144; Profile p4
- **Rationale** — Separate startup NULL and event data; restore SA before protected restart clear and enable.
- **Boundary** — Use FC0 with UNS and exact SEQ; preserve pending event ownership.
- **Acceptance** — Test startup NULL, missing confirmation, one class enabled, disable/restart and event retention.
- **Remaining** — D-10 contract exception separate.

## D-10 — Static unsolicited after restart versus IEEE startup NULL

- ****IDs**** — CFG-12
- ****Classification (external gate only)**** — EXTERNAL_AUTHORITY_REQUIRED
- ****Project owner decision**** — PROJECT OWNER DECISION (2026-11-10): IEEE 1815-2012 STRICT implementation only, with permanent Master/Outstation Test Harness and separate-process TCP tests. No proprietary static-on-restart unsolicited mode. Tavanir's static-unsolicited selection remains a separate contractual discrepancy, not an implementation choice.
- ****Implementation requirement**** — IEEE-strict startup: on outstation restart assert IIN1.7 (and IIN1.4 when time is required); if unsolicited is configured, transmit the initial FC130 unsolicited NULL with FIR=FIN=CON=UNS=1, no data objects and NO G120V1 (IEEE 7.5.2.3.2(h)); retry until matching FC0/UNS/SEQ application confirmation regardless of ordinary unsolicited retry count. Ignore pre-restart unsolicited enablement; retain events. Do not originate unsolicited event data until a new FC20 ENABLE_UNSOLICITED for the relevant class/points. Send only events in normal unsolicited responses, except the explicitly permitted deprecated G10V2/G40V2 cases; never put static objects in the startup NULL. The Master SHALL parse static objects if received from another peer. Master confirms the initial NULL immediately even during other requests; on IIN1.7 it establishes SA keys if configured, writes G80V1 index 7 = 0 to clear restart, performs the normative startup/integrity sequence, then issues FC20 after having received the NULL. Static integrity reporting is solicited, not a substitute for the Tavanir-selected static-unsolicited subcase. IEEE 4.6.6 pp133-135; 5.1.1.1 pp143-144; 7.5.2.3.2(h) p250.
- ****Source**** — IEEE 4.6.6 pp133-135; 5.1.1.1 pp143-144; 7.5.2.3.2(h) p250; Profile p4
- ****Rationale**** — IEEE governs wire behavior; explicit project-owner decision selects IEEE strict. Contract deviation remains separately visible.
- ****Boundary**** — No G120V1 in initial unsolicited NULL. Master must parse static if received; Outstation sends only permitted unsolicited events/legacy exceptions.
- ****Acceptance**** — Permanent unit/wire/separate-process TCP: initial NULL exactly no object/G120V1; UNS/SEQ/FIR/FIN/CON and FC0 matching; wrong/late/duplicate confirm; unlimited startup retries until correct confirm; event retention through restart; FC20 after startup; prohibit pre-enable unsolicited events; confirm unsolicited during solicited transaction; Master IIN1.7/SA/G80V1/integrity/FC20 ordering; parse received peer static while local Outstation never emits forbidden restart static; permitted legacy G10V2/G40V2 only when IEEE allows; secure-auth restart/reconnect.
- ****Decision / gate status**** — IEEE_IMPLEMENTATION_DECIDED__CONTRACT_ACCEPTANCE_OPEN
- ****Remaining**** — Implementation policy APPROVED IEEE-strict; source conflict remains: Tavanir Profile PDF p4 selects static unsolicited on restart, which the selected strict IEEE behavior does not satisfy. Contract acceptance requires external reconciliation; runtime/wire Test Harness evidence pending.

## D-11 — Zero security response timeout undefined

- **IDs** — SEC-T1-03
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Configure zero as alias for finite 2.0 s; accept 0.1–120.0 s in 100 ms steps; persist setting and use monotonic expiry.
- **Source** — 7.6.1.4 and 7.6.1.4.1 p284; Security p3 T1 r3
- **Rationale** — IEEE sets default and resolution; Tavanir gives 0–120 s with no zero semantics.
- **Boundary** — No indefinite acceptance window. Contract interpretation of zero remains open.
- **Acceptance** — Test 0, 0.1, 2.0, 120.0, out-of-range, timeout and late reply.
- **Remaining** — Contract confirmation of zero semantics.

## D-12 — MAC choices left unchecked

- **IDs** — SEC-T1-09;PROFILE-048;PROFILE-049;PROFILE-050;PROFILE-056
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — TCP baseline HMAC-SHA-256 truncated to 16 octets. Additional algorithms require explicit supported-media policy and configuration.
- **Source** — 7.6.1.1 pp283–284; 7.6.2.1 pp290–292; Security p3 T1 r9
- **Rationale** — IEEE TCP default; source checkboxes for the required product option set are unmarked.
- **Boundary** — No TCP 8-byte substitution or automatic SHA-1 fallback. IEEE §7.6.1.1.1 separately requires configurable legacy SHA-1 capability (10 octets on TCP), disabled in the selected Host policy. Reject invalid length and mismatched negotiation.
- **Acceptance** — Test known answer, wrong length, cross-media code and unsupported algorithm.
- **Remaining** — Any additional mandatory Tavanir option remains unconfirmed. Full IEEE legacy capability requires separate evidence.

## D-13 — TLS 1.3 table includes TLS 1.2 cipher names

- **IDs** — SEC-T1-11;SEC-T2-02
- **Classification** — EXTERNAL_AUTHORITY_REQUIRED
- **Baseline** — Default TLS 1.2 with configured applicable ECDHE/GCM suite and mTLS; permit separately configured TLS 1.3 only with supported native suite identifiers.
- **Source** — 7.8.1–7.8.4 pp296–297; Security pp3–5
- **Rationale** — Table 1 version and suite boxes are unmarked in the supplied PDF image; Table 2 lists TLS 1.2 and 1.3. TLS 1.2 is the chosen Host baseline. IEEE also specifies TLS_RSA_WITH_AES_128_SHA support, requiring separate evidence.
- **Boundary** — TLS1.3 uses independent cipher API; preserve selected TLS1.2 choices; no NULL, obsolete protocol or silent downgrade.
- **Acceptance** — Test negotiated version/cipher, selected RSA/ECDSA identities, invalid namespace and IEEE mandatory suite separately.
- **Remaining** — Tavanir must reconcile TLS version and suite table; no claim of full IEEE TLS conformance.

## D-14 — Cipher change request timer and TLS1.3 KeyUpdate meaning

- **IDs** — SEC-T1-13
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — TLS 1.2 called endpoint initiates symmetric rekey at application SA key-change interval/count trigger; default 2 s, selected RTU configuration 1–60 s. Generic IEEE-facing support must cover the SA reply timer range through at least 120 s. Terminate on timeout.
- **Source** — 7.8.5 pp297–298; 7.6.1.4.1 p284; Security p4 T1 r13
- **Rationale** — F0-23 records the differing published ranges. Separate selected RTU and generic IEEE configuration validation.
- **Boundary** — Ignore requests from calling endpoint as specified; do not map TLS 1.3 KeyUpdate to this rule.
- **Acceptance** — Test scheduled and count triggers, caller initiation, timely/late peer and disconnect.
- **Remaining** — Runtime renegotiation and validation of both configuration ranges remain pending.

## D-15 — Certificate authority provisioning not defined

- **IDs** — SEC-T1-14;SEC-T2-02
- **Classification** — EXTERNAL_AUTHORITY_REQUIRED
- **Baseline** — Support at least four concurrent provisioned CA anchors and mutual chain plus peer identity validation, including expiry at handshake; support 8192-byte certificate minimum maximum and individual certificate configuration.
- **Source** — 7.8.7.1–7.8.7.4.4 pp298–299; Security p4 T1 r14
- **Rationale** — Support can be tested with fixtures; production anchors/identity are external.
- **Boundary** — Fail handshake for absent, invalid, expired, wrong-name or untrusted peer. Do not auto-enroll roots.
- **Acceptance** — Test each anchor, intermediates, wrong identity, expiry, oversize and no client certificate.
- **Remaining** — Deployment acceptance requires provisioned CA chains and peer identities.

## D-16 — CRL file/provider/refresh policy unresolved

- **IDs** — SEC-T1-15
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Check authenticated local CRL every 12 h; hourly resolution; proposed 1–168 h Host range. Reject known revoked new peers and terminate sessions using newly confirmed revoked certificates.
- **Source** — 7.8.7.4.3–4.4 p299; Security p4 T1 r15
- **Rationale** — Missing CRL access does not by itself terminate established sessions; expiry alone also does not terminate them.
- **Boundary** — Keep last validated CRL; require usable revocation policy for new connections; surface refresh error separately.
- **Acceptance** — Test cached/new revocation, stale/unreachable source, invalid CRL signature, unrelated session and expiry.
- **Remaining** — Current OpenSSL CRL loading is handshake evidence only; active sweep pending.

## D-17 — RUK Method 4 / Method 68 selection and association ownership

- **IDs** — SEC-T1-16;SEC-T2-04
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Default Method 4, AES-256 Key Wrap and HMAC-SHA-256; Method 68 opt-in per association after provisioning and D-24 interoperability proof.
- **Source** — 7.5.4.6 pp271–273; 7.6.1.4.9 pp286–287; Security pp4–5
- **Rationale** — Method 4 is mandatory and default under IEEE when remote Update Key changes are supported.
- **Boundary** — One active method per association; reject mismatch without downgrade. Method 68 uses RSAES-OAEP-2048/SHA-256, DSA SHA-256 L2048/N256 and 256-bit Update Key.
- **Acceptance** — Test both provisioned peers, method mismatch, replay, confirmation loss and rekey continuity.
- **Remaining** — D-18 and D-24 remain applicable to asymmetric path.

## D-18 — G120V8 user certificate authority/profile not provided

- ****IDs**** — PROFILE-055;SEC-T1-16
- ****Classification (external gate only)**** — EXTERNAL_AUTHORITY_REQUIRED
- ****Project owner decision**** — PROJECT OWNER DECISION (2026-11-10): implement G120V8 strictly according to IEEE 1815-2012 A.45.8 and referenced RFC 5280, RFC 5755, IEC/TS 62351-8 as applicable. Complete production Master/Outstation certificate processing and permanent Test Harness are required. Test-only external CA and certificates are fixtures, NEVER deployment trust. Do not replace certificate validation with a mock, parser or TLS certificate. External standards access, production CA and Area of Responsibility provisioning remain independent gates.
- ****Implementation requirement**** — IEEE A.45.8 pp778-782: G120V8 is a Master-to-Outstation FC32 (0x20) request and the sole object; Q=0x5B variable length, valid object prefix length <=65535. Wire body begins UINT8 Key Change Method (ASYMMETRIC only, no Method 4), UINT8 Certificate Type (1 ID/X.509v3; 2 Attribute/RFC5755), then the corresponding authority-signed IEC/TS 62351-8 certificate. Master relays authority certificate unchanged; authority is not the Master. For configured Method 68 validate the IEEE-listed id-dsa-with-sha256 certificate signatures; respect the external IEC profile's additional required algorithms without inventing a profile. Validate ASN.1/DER, trust chain, algorithm/method consistency, signatures, issuer, identity/public key (ID cert), holder/preceding ID cert (Attribute cert), certificate validity, roles, allowed operations (Attribute: Delete/Change only), allowed AoR(s), monotonically increasing revision, status-change sequence/monotonic serial, replay and user-association ownership. Apply secure-time rules from Table A-8, including later re-evaluation after trusted time sync. Obey user-status/key-change lifecycle; delete immediately; defer add/role/expiry activation until normative successful key change. Respond using permitted FC131/IIN or eligible FC131/G120V7 errors, without inventing success objects. No conflation with TLS transport PKI.
- ****Source**** — IEEE A.45.8 pp778-782; Table A-8 p782; 7.5.5.5 pp281-282; 7.6.1.4.9 pp286-287
- ****Rationale**** — Project owner selected exact IEEE; no guessed certificate fields, synthetic trust or substitution of TLS certificates.
- ****Boundary**** — Method 4 prohibited for G120V8; asymmetric Update Key method only; explicit external CA, AoR and identity; fail closed.
- ****Acceptance**** — Permanent unit/integration/wire/separate-process TCP Master↔Outstation FC32/Q5B: valid external ID certificate; Attribute after ID; Add/Delete/Change; actual asymmetric Update Key lifecycle; correct FC131/error semantics; invalid authority, bad signature, wrong AoR, wrong holder/user/association, absent ID, Method 4 with V8, bad certificate type, method/signature mismatch, malformed/truncated/oversize ASN.1 and Q5B length, expired/future-dated/revoked according to applicable standards, stale revision/SCS/serial, replay, role escalation, restart/time sync; ensure no state mutation or premature role activation on rejection. Separate fixture CA from configurable production trust, preserve test output + commit SHA.
- ****Decision / gate status**** — IEEE_IMPLEMENTATION_DECIDED__CERT_PROFILE_AND_PROVISIONING_OPEN
- ****Remaining**** — Implementation policy APPROVED IEEE-strict; obtain/read actual applicable IEC/TS 62351-8 edition and certificate profile plus authoritative fixtures before claiming full certificate format validation. Product CA chains, AoR and deployment credentials must be explicitly provisioned. Runtime and independent-peer evidence pending; D-24 remains separate.

## D-19 — Role permissions and default authentication policy undefined

- **IDs** — SEC-T2-09;SEC-T2-10;SEC-T2-11;SEC-T1-02;SEC-T3-03
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Configure at least two distinct users. Administrator changes security policy; ordinary user may change permitted technical settings; both perform explicitly granted ordinary actions.
- **Source** — 7.5.4.4 pp267–268; Table 7-12 p270; 7.5.5.7 p283; Security pp3,5
- **Rationale** — Separate local administration from SA authority-assigned roles and protected-function authorization.
- **Boundary** — Deny by default; validate association, user, expiry, operation and ownership; authority owns remote role assignment.
- **Acceptance** — Test two users, role matrix, role/association substitution, expired/disabled user and rejected escalation.
- **Remaining** — Deployment provisioning remains external.

## D-20 — Local RTU password and credential storage policy

- **IDs** — SEC-T2-07;SEC-T3-04;SEC-T3-06
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — For human passwords use salted PBKDF2-HMAC-SHA-256 with 600000 iterations and random 128-bit salt, 256-bit verifier; protect recoverable keys with Windows DPAPI under service identity and restrictive ACLs.
- **Source** — No direct IEEE password KDF clause; 7.6.1.4.10 p288 for protocol key material; Security pp5–6
- **Rationale** — Store verifiers and recoverable keys separately; parameters versioned; baseline minimum password length 15, allow at least 64, check compromised-password list and rate-limit.
- **Boundary** — Reject default/hardcoded production secrets; never write plaintext keys or expose them in diagnostics; test credentials isolated.
- **Acceptance** — Test same-password unique salts, failed verification, cross-account DPAPI deny, log scan and restart.
- **Remaining** — Physical NVM evidence outside Host.

## D-21 — Hardware/network ports and secrets need target integration

- **IDs** — SEC-T3-01;SEC-T3-02;SEC-T3-05
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Close unnecessary Windows listeners and disable unused user accounts; bind to explicit interfaces and allowlist; keep physical connector disablement separate.
- **Source** — Security p6 T3 r1–3,5; no direct IEEE listener-hardening clause
- **Rationale** — Network controls apply to Windows Host; physical connector controls apply to RTU.
- **Boundary** — No diagnostic or cleartext listener enabled by default in secure deployment; secrets externally provisioned.
- **Acceptance** — Scan bound ports, wrong-interface attempt, disabled user, secure startup and configuration persistence.
- **Remaining** — Physical port validation outside Host.

## D-22 — Firmware signing requirements are recommended, not mandatory

- **IDs** — SEC-T3-07;SEC-T3-08
- **Classification** — OUTSIDE_WINDOWS_HOST
- **Baseline** — Retain SEC-T3-07/08 as recommended firmware signing and verification.
- **Source** — Security p6 T3 r7–8; no direct IEEE firmware-signing clause
- **Rationale** — Firmware acceptance is deferred to RTU target.
- **Boundary** — Keep original classifications; Windows executable signing is separate.
- **Acceptance** — Target later: valid signature, modified image, wrong signer and rollback policy.
- **Remaining** — No Windows Host acceptance gate.

## D-23 — P4-OPEN-01 G120V7 code 5 / 7 ambiguity

- **IDs** — PROFILE-054;SEC-T1-01
- **Classification** — EXTERNAL_AUTHORITY_REQUIRED
- **Baseline** — Keep P4-OPEN-01 open; provisional code 5 MAC Algorithm Not Supported, code 7 Authorization Failed.
- **Source** — A.45.7.2.2 pp776–777; 7.5.5.7 p283; 7.6.2.1.2 p292
- **Rationale** — Role enforcement prose labels authorization error 5; Annex lists 7; MAC negotiation cross-reference supports 5.
- **Boundary** — Reject authorization regardless of error mapping; never treat authorization denial as a cue to weaken MAC policy.
- **Acceptance** — Test both error codes, no authorization bypass, no fallback and peer behavior.
- **Remaining** — Authoritative clarification or agreed independent-peer profile required.

## D-24 — RUK-OPEN-01/02 SCS wrap and Method 68 signature encoding

- **IDs** — PROFILE-057;PROFILE-061;PROFILE-059;PROFILE-060;PROFILE-062
- **Classification** — EXTERNAL_AUTHORITY_REQUIRED
- **Baseline** — Persist high-water SCS per authority/association/user; fail closed at rollover pending reconciled policy. Method 68 signs Annex Table A-12 ordered data with certified user private key.
- **Source** — 7.5.5.5 p282; A.45.10.2.2 p787; A.45.14.2.2/Table A-12 pp796–797
- **Rationale** — Authority wraps UINT32; receiver prose requires larger than previously seen. Annex specifies signed data, but no DER encoding found there.
- **Boundary** — Do not accept zero after max by silently clearing replay state. Treat native DER as provisional until independent authoritative vectors.
- **Acceptance** — Test max−1/max/zero, durable replay, wrong signer, signature mutation and externally supplied wire vectors.
- **Remaining** — SCS rollover reconciliation and Method 68 signature wire encoding evidence outstanding.

## D-25 — G121/G122 thresholds/time/retention unresolved

- **IDs** — PROFILE-063;PROFILE-064;PROFILE-065;PROFILE-066;PROFILE-002
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Use per-association uint32 counters, configured Table 7-6 thresholds and Class 1 initial event assignment; G122V2 for genuinely time-stamped events, V1 when selected/untimed; retain uint32 totals durably across restart, reset reporting and moving-threshold baselines to retained totals, and never expose freeze/clear.
- **Source** — 7.4.1.8 p221; 7.5.2.2/Table 7-6 pp246–249; 7.6.1.4.2 p284; 11.9.10/Table 11-19 pp391–392; Table 12-63 p416; A.46/A.47 pp800–805
- **Rationale** — Use delta >= threshold to generate under §7.6.1.4.2; §11.9.10.2 says exceeds. Keep P6-OPEN-01 and separate state-machine thresholds from event confirmation. Never fabricate time.
- **Boundary** — No unrequested index aliasing or cross-association mutation. Follow Annex association ID and quality bits.
- **Acceptance** — Test thresholds −1/equal/+1, concurrent events, wrap/restart/quality, report confirmation, two associations and exact event time.
- **Remaining** — Current persistence hook exists; prove durable Windows store and restart continuity. P6-OPEN-01 remains provisional.

## D-26 — G0V209 truthful advertisement gated

- **IDs** — PROFILE-001;SEC-T1-01
- **Classification** — IMPLEMENTATION_EVIDENCE_PENDING
- **Baseline** — Advertise G0V209 value 5 only once actual configured SA v5 capability is demonstrated; omit unsupported attribute meanwhile.
- **Source** — A.1.1 p480; 7.6.1.5 p290
- **Rationale** — Codec declaration and partial SA implementation are insufficient.
- **Boundary** — No false support advertisement in Compatibility or partial builds.
- **Acceptance** — Test targeted G0V209 read under verified SA and compatibility/partial profiles.
- **Remaining** — Current runtime and independent-peer evidence pending.

## D-27 — Cold restart has no production application effect

- **IDs** — PROFILE-068;PROFILE-047
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — Use meaningful simulated Cold Restart hook: return G52V2/Q07 count 1 before reset; initial simulated quiet period 1000 ms, clear volatile command/session/reassembly state, reload configured values and assert DEVICE_RESTART.
- **Source** — 4.4.9 p100; 5.1.1.1 pp143–144; A.25.2 p701
- **Rationale** — Preserve pending event handling per startup rules; CLI restart console currently asserts IIN only.
- **Boundary** — Respect advertised delay; reauthenticate, clear restart IIN, integrity poll, enable unsolicited.
- **Acceptance** — Test real separate-process wire and state changes; no second actuation or physical reboot claim.
- **Remaining** — Host hook/runtime pending; physical reboot outside Host.

## D-28 — Counter-free production profile vs generic library

- **IDs** — CFG-13
- **Classification** — CONTRACT_EXPLICIT
- **Baseline** — Configure no G20–G23 counter points in selected Windows RTU profile; preserve generic stack counters.
- **Source** — Profile p4; IEEE A.10–A.13 reference only pp558–606
- **Rationale** — Contract says no counters reported.
- **Boundary** — Keep unrelated diagnostics and generic library available.
- **Acceptance** — Test Class 0 integrity and explicit counter request in RTU profile; generic regression.
- **Remaining** — Runtime evidence pending.

## D-29 — User credential expiry/persistence semantics

- **IDs** — SEC-T1-17
- **Classification** — ENGINEERING_BASELINE_SELECTED
- **Baseline** — For SA User Status Change, start day-based expiry at receipt to nearest second and activate role/expiry after successful key change; preserve authenticated receipt/expiry record across restart.
- **Source** — 7.5.5.5–7.5.5.7 pp281–283; A.45.10.2.2 p788; Security p4 T1 r17
- **Rationale** — Use elapsed monotonic time while running and trustworthy persisted time basis across restart; a wall-clock correction cannot extend access.
- **Boundary** — Deny expired or unverifiable credentials and invalidate deleted user's keys immediately.
- **Acceptance** — Test receipt vs activation, expiration boundary, restart, forward/backward clock and lost time basis.
- **Remaining** — Trusted production time source/provisioning remains deployment input.

## D-30 — 2026-11-10 selected G32V5 and G41V4 denial code not runtime verified

- **IDs** — All 119 IDs; applies to applicable Windows and independent-peer evidence
- **Classification** — IMPLEMENTATION_EVIDENCE_PENDING
- **Baseline** — Require current revision, named tests, peer identities, wire captures and results for Windows and independent-peer acceptance.
- **Source** — DNP3_PDD_PLAN/WINDOWS_HOST_ROADMAP.md; IEEE 14.7 pp469–470
- **Rationale** — Static and historical evidence remain distinct.
- **Boundary** — No PASS inferred from tests present or historical hashes.
- **Acceptance** — Run focused named cases on Windows and attach logs with exact revision and configurations.
- **Remaining** — Latest execution ledger documents scoped prior Windows tests at c25dd10. No runtime tests executed in this reference task.

The D-20 password settings use the OWASP guidance as an engineering source. [Password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) and [authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).

The IEC catalog identifies the edition referenced for D-18. [IEC TS 62351-8:2011](https://webstore.iec.ch/en/publication/6911).
