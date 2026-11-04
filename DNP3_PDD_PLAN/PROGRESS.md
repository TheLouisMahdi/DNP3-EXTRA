# Progress audit

The baseline audit uses the IEEE 1815-2012 parsing obligations in §12.1, the source partitions in the source index, and executed Windows evidence at the revision in `PROGRESS_EVIDENCE.json`. The IEEE matrix is a provisional inventory of work packages. Its rows differ in granularity and some mandatory Level 4 obligations remain unenumerated. It has no percentage denominator. [Source index](01_SOURCE_MAP.md)

`02_PROFILE_MATRIX.csv` holds the selected Device Profile rows and their audit columns. For this denominator, each supplied object/function row is treated as one selected mandatory Outstation obligation. A grouped row receives full credit only for its assessed scope. Master status is diagnostic and does not alter that count. The original wire expectations remain in the matrix. `local_code_status` mirrors the Outstation outcome for existing consumers.

`03_SECURITY_MATRIX.md` owns the security requirement text. `SECURITY_PROGRESS.csv` joins to its 36 IDs for classification, source location, role assessments and evidence. The mandatory denominator includes applicable Windows protocol and deferred RTU obligations. The unresolved MAC selection and two recommended firmware rows are displayed separately. Recommended 256-bit lengths and discouraged Aggressive usage are notes within rows and do not create extra denominator items.

Full `VERIFIED` means the cited execution evidence exercises the assessed behavior at the stated revision. `VERIFIED_SUBSET` records execution of only part of a row and receives no full-verification or implementation-coverage credit. `DECODE_ONLY` records typed decoding without an operational implementation and also receives no implementation-coverage credit. Implemented without verification means the reviewed path exists and full row execution coverage is unestablished. Partial includes known gaps within a row. Missing includes codec-only objects without an operational path. The assessment of G0V209 distinguishes executed Master decoding from missing Outstation advertisement. G120V10 and G120V14 retain partial status because unresolved sequence-wrap and wire-signature behavior affect their complete rows. TLS versions were executed on Windows, while the contradictory product cipher list remains blocked.

`CONDITIONAL` remains a distinct classification and is not included in mandatory denominators. An IEEE row's `outcome` is an aggregate assessment and may differ from its Outstation status; the Profile and Security outcome columns continue to mirror their Outstation status.

Every strict percentage uses applicable mandatory rows. Verified coverage counts only verified rows. Implementation coverage adds implemented rows awaiting full verification. Partial, missing, blocked and unaudited rows receive zero credit. Role breakdowns exclude rows marked not applicable with a role justification, such as hardware port closure for the Master. No Outstation mandatory rows are excluded in this audit.

The generator tracks the latest commit touching C++ sources, tests, application/build configuration or the console. A different source revision or local source edit makes positive and partial assessments historical in the dashboard until the affected scope is reviewed. The CSVs retain the recorded assessments. Update the audit revision after rechecking the rows and update execution evidence only after tests run. Documentation-only dashboard commits preserve the source revision. The older 714/59,048 unit and 2/240 SA TCP totals are historical baseline evidence. The separate 12/241 integration result includes SA TCP and other integration cases.

## Open decisions

| ID | Boundary |
| --- | --- |
| IEEE-ENUMERATION | Enumerate Level 4 obligations and decide conditional applicability. |
| G0V209 | Outstation omits version advertisement. Master supports typed decoding. |
| G120V8 | Codec exists without runtime certificate handling. |
| P4-OPEN-01 | Provisional G120V7 code 5/7 interpretation. |
| RUK-OPEN-01 | Strict SCS monotonicity versus sequence wrap. |
| RUK-OPEN-02 | Provisional DER representation for Method 68 DSA signatures. |
| P6-OPEN-01 | Provisional G121/G122 threshold boundary. |
| P6-OPEN-02 | Critical-message accounting boundary. |
| P6-OPEN-03 | Authentication-failure user ownership. |
| STAT-RETENTION | Durable retention, quality and rearming limits. |
| G122-UNTIMED | Explicit V2 cannot time an untimed historical event. |
| FC6-MASTER | Typed Master no-response control API absent. |
| TIME-QUALIFIERS | G50 READ and WRITE qualifier edges remain. |
| CLASS-EDGE | Dangling and unsupported class header behavior. |
| IIN-WRITE-SCOPE | Narrow restart-bit write support and qualifier coverage. |
| RESTART-APP | Native restart hook requires an application implementation. |
| AGGRESSIVE-SCOPE | Full function and response matrix needs an audit. |
| TIMEOUT-ZERO | Meaning and handling of a zero security timeout. |
| MAC-SELECTION | Product MAC choices require resolution. |
| METHOD-SELECTION | Additional selectable remote key methods require a product decision. |
| SEC-T1-11 | TLS 1.3 product cipher names conflict with the TLS 1.3 namespace. |
| SEC-T1-13 | Cipher-change request timeout remains missing. |
| SEC-T1-15 | Revocation scheduling and required interval remain open. |
| CA-CAPACITY | Four simultaneous trust authorities lack execution evidence. |
| LOCAL-PASSWORD | Local RTU configuration password absent from the console. |
| RTU-SA-DEFAULT | Product startup policy remains to be confirmed. |
| ROLE-PROVISIONING | Production role policy and authority provisioning remain open. |
| SEC-CONFIG | Full set of security parameter controls remains incomplete. |
| RTU-HARDWARE | Physical port hardening requires RTU audit. |
| RTU-NETWORK | Deployed service and port closure requires RTU audit. |
| RTU-HARDENING | Deployed user disablement and least privilege require RTU audit. |
| RTU-PROVISIONING | Production credential provisioning requires RTU evidence. |
| RTU-CREDENTIAL-HASH | RTU credential storage policy requires audit. |
| RTU-FIRMWARE | Recommended firmware signing and verification require RTU audit. |
| ABSOLUTE-TIME-WRITE-INTEROP | G50V1 WRITE semantics and independent interoperability remain to be validated. |
| ANY-SOURCE-SAME-SEQ-REPLAY | LAN-time replay behavior for a same-sequence write from another source remains unresolved. |
| ATTR-WIRE-AUDIT | G0V210/V254/V255 statistic-count and attribute-discovery wire behavior remains unaudited. |
| CLASS-ASSIGNMENT-WIRE-AUDIT | G12 command class-assignment qualifiers and response wire forms remain unaudited. |
| COMMAND-EVENT-QUALIFIER-CROSS-PRODUCT | G13 command-event qualifier behavior and cross-product interoperability remain open. |
| CONFIRMED-USER-DATA | Confirmed user-data handling for self-addressed destination traffic remains unaudited. |
| CONTROL-WIRE-AUDIT | G12V1 FC3/FC129 qualifier-17 request and response echo wire behavior remains unaudited. |
| COUNTER-FREEZE-WIRE-AUDIT | G20V0 FC7 qualifier-00 freeze request wire behavior remains unaudited. |
| COUNTER-WIRE-AUDIT | Listed G20-G23 counter variations and their wire forms remain unaudited. |
| IEEE-WIRE-AUDIT | Table 14-5 wire forms and malformed-wire coverage remain under audit. |
| INDEPENDENT-PEER | Independent-peer interoperability remains open for Level 4 command-event behavior. |
| INITIATOR-DISCOVERY | Self-address initiator discovery behavior remains unaudited. |
| LAN-TIMESTAMP-ACCURACY | LAN-time timestamp accuracy remains to be assessed. |
| MASTER-ABSOLUTE-READ | Explicit Master G50V1 READ delivery and independent interoperability remain open. |
| NO-OBJECT-WIRE-AUDIT | No-object CONFIRM, COLD_RESTART and DELAY_MEASURE wire forms remain unaudited. |
| PHASE2-SA-V5 | G0V209 advertisement remains gated until Secure Authentication v5 is proven. |
| STANDARD-SET-VALUES | Standard-set values for the listed G0 attributes remain to be audited. |
| TIME-WIRE-AUDIT | G51/G52 response qualifier and quantity wire forms remain unaudited. |

## Regeneration

From the repository root, run `python scripts/progress.py` and `python scripts/progress.py --check`. Generation needs Python 3 and Git history for the tracked source revision. The workflow runs these commands on relevant pushes to `develop` and commits only the generated README block and SVG assets. If branch policy denies the workflow push, run the commands locally and submit the generated diff through the normal branch policy. The private repository landing page follows its default branch. The dashboard is visible on `develop` to authorized readers.
