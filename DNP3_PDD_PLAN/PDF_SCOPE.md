# PDF-based project scope and acceptance

This document governs project scope. The target is the supplied Level 3 RTU
Outstation with its explicitly selected extensions, runtime settings and security
requirements. IEEE 1815-2012 defines correct behavior for those selections.
Historical Level 4 work packages do not expand this acceptance scope.

## Authority and exact sources

| Priority | Repository source | Page references and use |
| --- | --- | --- |
| 1 | `IEEE 1815/4812449245627490050_724147149003390.pdf` | 12-page Device Profile excerpt, original pages 41–52 of 78. PDF p1 / original p41 declares Level 3 requests and responses, Slave selected, Master unselected. PDF pp1–4 / original pp41–44 select runtime settings. PDF pp4–12 / original pp44–52 contain the implementation table. |
| 2 | `IEEE 1815/الزامت حداقل مورد نیاز.pdf` | Six-page minimum security amendment. PDF pp1–2 introduce the amendment. Table 1 is on PDF pp3–4, Table 2 on p5 and Table 3 on p6. Footer pagination differs, so references here use physical PDF pages. |
| 3 | `IEEE 1815/IEEE 1815-2012.pdf` | Normative encoding, state machines, qualifiers, roles, errors and security procedures applicable to the selected requirements and necessary protocol dependencies. |

The PDFs are excerpts. They do not establish coverage of the unavailable parent
documents. Obtain a missing parent clause before assigning its requirements or
claiming complete contractual coverage. Conflicting selections require a recorded
resolution against IEEE behavior and the requirement owner's product decision.

## Acceptance sets and roles

- `PROFILE_MATRIX.csv` retains exactly `PROFILE-001` through `PROFILE-069`.
  Assess each row against its exact selected function, request qualifier, response
  qualifier and role. An ECHO entry is function-specific. A no-response operation
  has no application acknowledgment. Grouped rows require all applicable subcases.
- `ENGINEERING_EVIDENCE.md#record-02` and `SECURITY_MATRIX.csv` retain the same 36 IDs,
  `SEC-T1-01`–`17`, `SEC-T2-01`–`11`, and `SEC-T3-01`–`08`. Preserve mandatory,
  recommended and unresolved classifications. Track conditional applicability and
  hardware dependencies explicitly, with reasons and evidence.
- The RTU Outstation is the contractual role. Table headings distinguish
  “Master may issue”, “Outstation shall parse”, “Master shall parse” and
  “Outstation may issue”. Optional Master issuance does not become a mandatory
  RTU deliverable. Preserve existing Master functionality and use it for testing.
  Additional project-required Master behavior needs its own explicit scope.
- `IEEE_TRACEABILITY.csv` contains 712 standards-reference and optional expansion
  audit rows. It is outside the contractual denominator. A selected behavior may
  cite an IEEE row without importing the rest of that inventory into the backlog.

## Additional Profile settings checklist

Unchecked boxes below track acceptance work, rather than source selection or
implementation status. The selected values were read from the PDF images.
Keep this checklist separate from the original 69-row denominator.

| Check | ID and source | Selected requirement and acceptance evidence needed |
| --- | --- | --- |
| [ ] | CFG-01, p1 / original 41 | Level 3 Outstation and explicitly listed extensions. Identify vendor/device metadata left blank in the form without fabricating values. |
| [ ] | CFG-02, p2 / original 42 | Link receive frame size must be 292 octets. Transmit size is blank. Document the product value and verify frame boundaries. |
| [ ] | CFG-03, p2 / original 42 | Application receive fragment size must exceed 249 octets. Transmit size above 2048 must be configurable. Both size fields are blank. Verify configured bounds, segmentation, reassembly and resource limits. |
| [ ] | CFG-04, p2 / original 42 | Link retries configurable 0–5. Application retries configurable 1–5, fixed retries disallowed. Test limits, exhaustion and reconnect while respecting IEEE function-specific retry prohibitions, including direct controls. |
| [ ] | CFG-05, p2 / original 42 | Link confirmation configurable as Never, Always or On multi-frame fragments. Exercise each permitted policy. |
| [ ] | CFG-06, p2 / original 42 | Application confirmation selected for event data and multi-fragment responses. Verify CONFIRM ownership, timeout, retry and event retention. |
| [ ] | CFG-07, pp2–3 / original 42–43 | Configurable waits for link confirm, complete application fragment, application confirm and complete application response. Numeric ranges/defaults and explanatory attachment are absent. Resolve role applicability and test approved values and boundaries. |
| [ ] | CFG-08, p3 / original 43 | SELECT/OPERATE, DIRECT OPERATE and DIRECT OPERATE NO ACK selected Always. Verify execution, denial and no-response semantics with selected G12/G41 wire forms and SA policy. Compatibility-only FC6 evidence does not close authenticated control acceptance. |
| [ ] | CFG-09, p3 / original 43 | WRITE Binary Outputs, Count > 1, Pulse Off, Latch On/Off, Queue and Clear Queue selected Never. Pulse On selected Sometimes; Trip/Close selected Always. Resolve the exact IEEE field/operation mapping and verify the production control policy and rejected forms. Preserve reusable library capabilities. |
| [ ] | CFG-10, p3 / original 43 | Default binary change events are Only time-tagged. Absolute-time form and Configurable are both selected for default timed events. Verify actual default variation and obtain the missing configuration explanation. |
| [ ] | CFG-11, p4 / original 44 | Unsolicited responses configurable and ENABLE/DISABLE UNSOLICITED supported. Verify enable/disable, startup, event delivery, confirmations and retry behavior. Configuration explanation is absent. |
| [ ] | CFG-12, p4 / original 44 | Static unsolicited data selected When Device Restarts, with other options unselected. Resolve the exact IEEE-compatible startup sequence and static-data delivery requirement. Test real restart integration separately from a startup null unsolicited response. |
| [ ] | CFG-13, p4 / original 44 | No Counters Reported selected for both counter defaults and rollover. Production configuration must report no physical counter points. General Level 4 G20–G23 implementation is outside this target. |
| [ ] | CFG-14, p4 / original 44 | Multi-fragment responses selected Yes. Test selected data families across fragments, sequence progression, confirmations and malformed/incomplete transfers. |

## Security and scope boundaries

SA v5, truthful G0V209 reporting, G120V8 user certificates, selected G120
procedures, G121/G122 statistics, TLS, credentials, roles and deployed RTU
security remain in scope. A codec or test credential fixture alone cannot satisfy
the corresponding runtime requirement. Apply IEEE Clause 7 and the relevant
Annex A object definitions to the selected exchanges.

SEC-T1-04/05 require Aggressive capabilities while discouraging their use.
SEC-T1-10 explicitly requires AES-256 key wrap. SEC-T2-05/06 accept 128-bit
keys and recommend 256-bit keys. Preserve these distinctions. TLS 1.2/1.3,
port 19999, at least four CAs, credential expiry, secure defaults and required
parameter configurability retain their selected scope.

G20–G23, new G34/G13/G43 features and other IEEE variations or qualifiers are
outside acceptance when justified solely by general Level 4 tables. Preserve
existing implementations. New expansion requires an explicit project decision.
Normative dependencies necessary for a selected requirement remain applicable.

## Decisions and source discrepancies

- SEC-T1-09 leaves MAC selections unchecked. Decide the supported/required set
  and negotiation policy without selecting an algorithm from an example.
- SEC-T1-11 lists TLS 1.2-style names under TLS 1.3. Resolve valid product suites
  and control-center interoperability. SEC-T1-16 / SEC-T2-04 also need approved
  remote update-key algorithm choices and provisioning policy.
- SEC-T1-15 supplies no revocation interval. Decide the interval, trusted-time
  source, revocation mechanism and failure policy. Verify security-response
  timeout zero semantics against IEEE before accepting SEC-T1-03.
- Supply the Profile's blank sizes, identity fields, timeout parameters and
  missing configuration explanations. Resolve CFG-09, CFG-10 and CFG-12 against
  IEEE semantics. Do not invent missing physical I/O behavior or parameters.
- SEC PDF p6 Table 3 row 4 requires strong passwords for human users. The SECURITY_MATRIX.csv source summary reflects this requirement. Historical
  `SEC-T3-04` evidence described least privilege and requires reassessment.
  Preserve the ID and historical status until supported. Role authorization remains covered by Table 2.
- Define production CA/credential provisioning, password strength and storage,
  role permissions, NVM retention, physical ports, network services, trusted time
  and firmware policy. Recommended firmware signature rows SEC-T3-07/08 retain
  their category until a product decision changes their applicability.

## Validation responsibility and completion

Windows verification covers portable protocol behavior, configuration APIs,
wire exchanges, failure cases, TLS/SA lifecycle and process interoperability.
Record the source revision, exact cases, inputs, results and limits for each
applicable behavior. Distinguish same-project peers from independent peers.

Physical RTU acceptance additionally requires target evidence for STM32H743 /
FreeRTOS integration, clock accuracy, entropy, credential/NVM protection and
retention, real I/O/interlocks/restart, port hardening and applicable firmware
controls. Windows simulation cannot close those deployment obligations.

Completion requires implemented behavior and actual relevant passing evidence
for every applicable selected Profile subcase, CFG checklist item and mandatory
security obligation. Keep recommended items, unresolved choices and conditional
items visible with dispositions. A blocked mandatory requirement prevents full
acceptance until resolved. Compilation, isolated codecs or historical positive
statuses alone do not establish completion. Report Profile 69-row coverage,
runtime checklist coverage and security 36-row dispositions separately. Any
mandatory-only security percentage must show its classification-based denominator.
Full IEEE Level 4 coverage is outside this completion rule.

## 2026-11-10 source-selection correction

The 12-page Tavanir Device Profile, physical PDF page 3 (original page 43), explicitly selects **Pulse On = Sometimes** and **Pulse Off = Never**. The earlier summary incorrectly grouped Pulse On with the Never choices. This correction preserves the rest of the historical scope text; the original Profile remains authoritative. Whether Pulse On is permitted on a given point is determined by explicit point configuration and interlocks (D-07 / CFG-09), never by inventing a product approval. This file is a corrected repository copy of the historical source; its former Google Drive copy must be reconciled separately.
