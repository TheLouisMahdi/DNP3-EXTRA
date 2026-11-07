# Open engineering issues

Acceptance follows [PDF_SCOPE.md](PDF_SCOPE.md). Profile and security CSVs preserve historical statuses and tested revisions. Reassess each applicable requirement against current source before claiming completion.

## Selected requirement blockers

- SA v5 remains partial. G0V209 must report actual verified capability, and G120V8 needs runtime certificate handling. Authenticated FC6 B03 Host validation passed (focused, unit/integration regression and same-project TCP); independent-peer interoperability remains open.
- Resolve MAC selection, TLS 1.3 suite naming, remote update-key methods, revocation interval and trusted-time/provisioning policy.
- Verify zero security-response timeout semantics, configurable limits, security statistics retention/quality and failure ordering.
- Resolve Profile blank sizes/timeouts and control policy, default event and restart unsolicited selections. See CFG-01 through CFG-14.
- SEC-T3-04 historical evidence covers a different summary. Reassess the PDF strong-password requirement.
- Physical RTU evidence is required for entropy, NVM, clock accuracy, ports, real I/O/interlocks/restart and firmware policy. STM32H743/FreeRTOS integration is pending.
- Independent-peer interoperability remains open. Local Windows and same-project TCP evidence has its recorded limits.

## Preserved issue register

Historical issue descriptions below remain searchable. Only PDF-selected requirements and necessary normative dependencies enter acceptance. General Level 4 expansion issues are reference-only.

| ID | Historical boundary |
| --- | --- |
| IEEE-ENUMERATION | Historical optional Level 4 expansion audit. Map only PDF-selected dependencies into acceptance. |
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
| FC6-REQUIRED-MODE | B03 adds authenticated FC6 Challenge/Reply and Aggressive submission under section 7.5.2.3.2(i). Host-focused, regression and same-project TCP tests PASS (2026-11-07); independent-peer verification remains open. SUCCESS denotes local authenticated submission only, with CommandStatus::UNDEFINED. Configured Aggressive FC6 without usable Challenge history fails locally; prime through a genuine exchange. |
| TIME-QUALIFIERS | G50 READ and WRITE qualifier edges remain. |
| CLASS-EDGE | Dangling and unsupported class header behavior. |
| IIN-WRITE-SCOPE | Narrow restart-bit write support and qualifier coverage. |
| RESTART-APP | Native restart hook requires an application implementation. |
| AGGRESSIVE-SCOPE | [B07 reviewed matrix](B07_ACCEPTANCE_MATRIX.md) and [Record 13](ENGINEERING_EVIDENCE.md#record-13) record user-supplied Windows Release/unit/integration PASS and VERIFIED_HOST for the mapped selected envelope/runtime witnesses. Review R1-R6 limit native side-effect, renewed-eligibility replay and isolated-fault claims; the next slice is test-only B07-D hardening. Independent-peer, product MAC and other stated gates remain open. No general IEEE Level 4 or full SA v5 acceptance is implied. |
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
| INDEPENDENT-PEER | Independent-peer interoperability remains open for Level 4 command-event and FC6 control behavior. |
| INITIATOR-DISCOVERY | Self-address initiator discovery behavior remains unaudited. |
| LAN-TIMESTAMP-ACCURACY | LAN-time timestamp accuracy remains to be assessed. |
| MASTER-ABSOLUTE-READ | Explicit Master G50V1 READ delivery and independent interoperability remain open. |
| NO-OBJECT-WIRE-AUDIT | No-object CONFIRM, COLD_RESTART and DELAY_MEASURE wire forms remain unaudited. |
| PHASE2-SA-V5 | G0V209 advertisement remains gated until Secure Authentication v5 is proven. |
| STANDARD-SET-VALUES | Standard-set values for the listed G0 attributes remain to be audited. |
| TIME-WIRE-AUDIT | G51/G52 response qualifier and quantity wire forms remain unaudited. |

## Reference issue IDs

Full engineering details, provisional IEEE interpretations and exact execution records are retained in [ENGINEERING_EVIDENCE.md](ENGINEERING_EVIDENCE.md). The 712-row [IEEE reference](IEEE_TRACEABILITY.csv) is retained for unique clause, wire-form and source references. It is outside the contractual backlog.

ABSOLUTE-TIME-WRITE-INTEROP, AGGRESSIVE-SCOPE, ANY-SOURCE-SAME-SEQ-REPLAY, ATTR-WIRE-AUDIT, CA-CAPACITY, CLASS-ASSIGNMENT-WIRE-AUDIT, CLASS-EDGE, COMMAND-EVENT-QUALIFIER-CROSS-PRODUCT, CONFIRMED-USER-DATA, CONTROL-WIRE-AUDIT, COUNTER-FREEZE-WIRE-AUDIT, COUNTER-WIRE-AUDIT, FC6-REQUIRED-MODE, G0V209, G120V8, G122-UNTIMED, IEEE-ENUMERATION, IEEE-WIRE-AUDIT, IIN-WRITE-SCOPE, INDEPENDENT-PEER, INITIATOR-DISCOVERY, LAN-TIMESTAMP-ACCURACY, LOCAL-PASSWORD, MAC-SELECTION, MASTER-ABSOLUTE-READ, METHOD-SELECTION, NO-OBJECT-WIRE-AUDIT, P4-OPEN-01, P6-OPEN-01, P6-OPEN-02, P6-OPEN-03, PHASE2-SA-V5, RESTART-APP, ROLE-PROVISIONING, RTU-CREDENTIAL-HASH, RTU-FIRMWARE, RTU-HARDENING, RTU-HARDWARE, RTU-NETWORK, RTU-PROVISIONING, RTU-SA-DEFAULT, RUK-OPEN-01, RUK-OPEN-02, SEC-CONFIG, SEC-T1-11, SEC-T1-13, SEC-T1-15, STANDARD-SET-VALUES, STAT-RETENTION, TIME-WIRE-AUDIT, TIMEOUT-ZERO
