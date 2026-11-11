# DNP3-EXTRA - PDF requirement inventory

This inventory tracks **every original selected ID from the supplied 12-page RTU Device Profile and six-page minimum security addendum**. It is the progress denominator: **69 selected Profile object/function rows + 36 security parameters + 14 Profile runtime/configuration groups = 119 tracked IDs**.

**OpenDNP3 3.1.2 is the starting codebase**. Development baseline zero means zero *project-specific changes*, not zero existing protocol functionality.

**Review provenance:** [historical Profile and Security matrices](https://github.com/TheLouisMahdi/DNP3-EXTRA/tree/b94961d4ebd14196be7911d6fc132b6e6c9cc251/DNP3_PDD_PLAN) at `b94961d4ebd14196be7911d6fc132b6e6c9cc251`; CFG source-review classification at `eb45756fb9b7f4e265091280067c8f9285fb1477`. Each color/status in the SVG reflects these **mixed historical assessments**, not current-`develop` acceptance. `VERIFIED` is historical and must not be promoted to the current revision without matching passing evidence.

**Source accuracy:** the fields below preserve the source-derived selections recorded in the historical matrices. They are not a license to invent missing values, to assume every function/qualifier cross-product is legal, or to claim completeness for any unverified subcase. IEEE 1815-2012 defines the normative behavior for selected cases, not an additional Level 4 scope.

## Recorded status distribution (not current acceptance)

| PDF selection | IDs | Prior verified | Code present, unverified | Partial | Blocked | Not implemented | Not audited |
|---|---:|---:|---:|---:|---:|---:|---:|
| Profile objects and functions | 69 | 12 | 46 | 9 | 1 | 1 | 0 |
| Security addendum parameters | 36 | 14 | 2 | 11 | 1 | 3 | 5 |
| Profile runtime configuration | 14 | 0 | 6 | 7 | 1 | 0 | 0 |
| All tracked IDs | 119 | 26 | 54 | 27 | 3 | 4 | 5 |

The security addendum includes **33 mandatory, 2 recommended and 1 unresolved** selection. Group 70 file transfer is separately requested and is not part of the 119-ID contractual denominator.

## Device Profile: 69 selected object and function rows

Function codes are decimal; qualifiers hexadecimal. Preserve selected codes as sets, not an assumed Cartesian product of every field.

| ID | Group/Variation | Description | Request FC | Request Q | Response FC | Response Q | Recorded status | PDF page |
|---|---|---|---|---|---|---|---|---|
| PROFILE-001 | G0V209 | Secure authentication version | 1 | 00 | 129 | 00\|17 | BLOCKED | p4 |
| PROFILE-002 | G0V210 | Security statistics per association | 1 | 00 | 129 | 00\|17 | VERIFIED | p4 |
| PROFILE-003 | G1V0 | Binary input any | 1\|22 | 00\|01\|06 | - | - | IMPLEMENTED_NOT_VERIFIED | p4 |
| PROFILE-004 | G1V1 | Binary input packed | 1 | 00\|01\|06 | 129 | 00\|01 | IMPLEMENTED_NOT_VERIFIED | p4 |
| PROFILE-005 | G1V2 | Binary input with flags | 1 | 00\|01\|06 | 129 | 00\|01 | IMPLEMENTED_NOT_VERIFIED | p5 |
| PROFILE-006 | G2V0 | Binary input event any | 1 | 06\|07\|08 | - | - | IMPLEMENTED_NOT_VERIFIED | p5 |
| PROFILE-007 | G2V1 | Binary event without time | 1 | 06\|07\|08 | 129\|130 | 17\|28 | IMPLEMENTED_NOT_VERIFIED | p5 |
| PROFILE-008 | G2V2 | Binary event absolute time | 1 | 06\|07\|08 | 129\|130 | 17\|28 | IMPLEMENTED_NOT_VERIFIED | p5 |
| PROFILE-009 | G2V3 | Binary event relative time | 1 | 06\|07\|08 | 129\|130 | 17\|28 | IMPLEMENTED_NOT_VERIFIED | p5 |
| PROFILE-010 | G3V0 | Double-bit input any | 1\|22 | 00\|01\|06 | - | - | IMPLEMENTED_NOT_VERIFIED | p5 |
| PROFILE-011 | G3V1 | Double-bit input packed | 1 | 00\|01\|06 | 129 | 00\|01 | IMPLEMENTED_NOT_VERIFIED | p5 |
| PROFILE-012 | G3V2 | Double-bit input with flags | 1 | 00\|01\|06 | 129 | 00\|01 | IMPLEMENTED_NOT_VERIFIED | p5 |
| PROFILE-013 | G4V0 | Double-bit event any | 1 | 06\|07\|08 | - | - | IMPLEMENTED_NOT_VERIFIED | p5 |
| PROFILE-014 | G4V1 | Double-bit event without time | 1 | 06\|07\|08 | 129\|130 | 17\|28 | IMPLEMENTED_NOT_VERIFIED | p6 |
| PROFILE-015 | G4V2 | Double-bit event absolute time | 1 | 06\|07\|08 | 129\|130 | 17\|28 | IMPLEMENTED_NOT_VERIFIED | p6 |
| PROFILE-016 | G4V3 | Double-bit event relative time | 1 | 06\|07\|08 | 129\|130 | 17\|28 | IMPLEMENTED_NOT_VERIFIED | p6 |
| PROFILE-017 | G10V0 | Binary output status any | 1 | 00\|01\|06 | - | - | IMPLEMENTED_NOT_VERIFIED | p6 |
| PROFILE-018 | G10V2 | Binary output status with flags | 1 | 00\|01\|06 | 129 | 00\|01 | IMPLEMENTED_NOT_VERIFIED | p6 |
| PROFILE-019 | G12V1 | CROB | 3\|4\|5\|6 | 17\|28 | 129 | ECHO | PARTIAL | p6 |
| PROFILE-020 | G30V0 | Analog input any | 1\|22 | 00\|01\|06 | - | - | IMPLEMENTED_NOT_VERIFIED | p6 |
| PROFILE-021 | G30V1 | Analog input 32-bit with flags | 1 | 00\|01\|06 | 129 | 00\|01 | IMPLEMENTED_NOT_VERIFIED | p6 |
| PROFILE-022 | G30V2 | Analog input 16-bit with flags | 1 | 00\|01\|06 | 129 | 00\|01 | IMPLEMENTED_NOT_VERIFIED | p7 |
| PROFILE-023 | G30V3 | Analog input 32-bit without flags | 1 | 00\|01\|06 | 129 | 00\|01 | IMPLEMENTED_NOT_VERIFIED | p7 |
| PROFILE-024 | G30V4 | Analog input 16-bit without flags | 1 | 00\|01\|06 | 129 | 00\|01 | IMPLEMENTED_NOT_VERIFIED | p7 |
| PROFILE-025 | G30V5 | Analog input float32 with flags | 1 | 00\|01\|06 | 129 | 00\|01 | IMPLEMENTED_NOT_VERIFIED | p7 |
| PROFILE-026 | G32V0 | Analog input event any | 1 | 06\|07\|08 | - | - | IMPLEMENTED_NOT_VERIFIED | p7 |
| PROFILE-027 | G32V1 | Analog event 32-bit without time | 1 | 06\|07\|08 | 129\|130 | 17\|28 | IMPLEMENTED_NOT_VERIFIED | p7 |
| PROFILE-028 | G32V2 | Analog event 16-bit without time | 1 | 06\|07\|08 | 129\|130 | 17\|28 | IMPLEMENTED_NOT_VERIFIED | p7 |
| PROFILE-029 | G32V4 | Analog event 16-bit with time | 1 | 06\|07\|08 | 129\|130 | 17\|28 | IMPLEMENTED_NOT_VERIFIED | p7 |
| PROFILE-030 | G32V5 | Analog event float32 without time | 1 | 06\|07\|08 | 129\|130 | 17\|28 | IMPLEMENTED_NOT_VERIFIED | p7 |
| PROFILE-031 | G40V0 | Analog output status any | 1 | 00\|01\|06 | - | - | IMPLEMENTED_NOT_VERIFIED | p7 |
| PROFILE-032 | G40V1 | Analog output status 32-bit with flag | 1 | 00\|01\|06 | 129 | 00\|01 | IMPLEMENTED_NOT_VERIFIED | p8 |
| PROFILE-033 | G40V2 | Analog output status 16-bit with flag | 1 | 00\|01\|06 | 129 | 00\|01 | IMPLEMENTED_NOT_VERIFIED | p8 |
| PROFILE-034 | G40V3 | Analog output status float32 with flag | 1 | 00\|01\|06 | 129 | 00\|01 | IMPLEMENTED_NOT_VERIFIED | p8 |
| PROFILE-035 | G41V1 | Analog output 32-bit command | 3\|4\|5\|6 | 17\|28 | 129 | ECHO | IMPLEMENTED_NOT_VERIFIED | p8 |
| PROFILE-036 | G41V2 | Analog output 16-bit command | 3\|4\|5\|6 | 17\|28 | 129 | ECHO | IMPLEMENTED_NOT_VERIFIED | p8 |
| PROFILE-037 | G41V3 | Analog output float32 command | 3\|4\|5\|6 | 17\|28 | 129 | ECHO | IMPLEMENTED_NOT_VERIFIED | p8 |
| PROFILE-038 | G50V1 | Absolute time and date | 1\|2 | 07 | 129 | 07 | IMPLEMENTED_NOT_VERIFIED | p8\|9 |
| PROFILE-039 | G51V1 | CTO absolute synchronized | - | - | 129\|130 | 07 | IMPLEMENTED_NOT_VERIFIED | p9 |
| PROFILE-040 | G51V2 | CTO absolute unsynchronized | - | - | 129\|130 | 07 | IMPLEMENTED_NOT_VERIFIED | p9 |
| PROFILE-041 | G52V1 | Time delay coarse | - | - | 129 | 07 | IMPLEMENTED_NOT_VERIFIED | p9 |
| PROFILE-042 | G52V2 | Time delay fine | - | - | 129 | 07 | IMPLEMENTED_NOT_VERIFIED | p9 |
| PROFILE-043 | G60V1 | Class 0 | 1\|22 | 06 | - | - | IMPLEMENTED_NOT_VERIFIED | p9 |
| PROFILE-044 | G60V2 | Class 1 | 1\|20\|21\|22 | 06\|07\|08 | - | - | IMPLEMENTED_NOT_VERIFIED | p9 |
| PROFILE-045 | G60V3 | Class 2 | 1\|20\|21\|22 | 06\|07\|08 | - | - | IMPLEMENTED_NOT_VERIFIED | p9\|10 |
| PROFILE-046 | G60V4 | Class 3 | 1\|20\|21\|22 | 06\|07\|08 | - | - | IMPLEMENTED_NOT_VERIFIED | p10 |
| PROFILE-047 | G80V1 | Internal indications packed | 1\|2 | 00\|01 | 129 | 00\|01 | PARTIAL | p10 |
| PROFILE-048 | G120V1 | Authentication challenge | 32 | 5B | 131 | 5B | VERIFIED | p10 |
| PROFILE-049 | G120V2 | Authentication reply | 32 | 5B | 131 | 5B | VERIFIED | p10 |
| PROFILE-050 | G120V3 | Aggressive mode request | 1-31 | 07 | 129\|130 | 07 | PARTIAL | p10 |
| PROFILE-051 | G120V4 | Session key status request | 32 | 07 | - | - | VERIFIED | p10 |
| PROFILE-052 | G120V5 | Session key status | - | - | 131 | 5B | VERIFIED | p11 |
| PROFILE-053 | G120V6 | Session key change | 32 | 5B | - | - | VERIFIED | p11 |
| PROFILE-054 | G120V7 | Authentication error | 33 | 5B | 131 | 5B | PARTIAL | p11 |
| PROFILE-055 | G120V8 | User certificate | 32 | 5B | - | - | NOT_IMPLEMENTED | p11 |
| PROFILE-056 | G120V9 | Message authentication code | 1-31 | 5B | 129\|130 | 5B | PARTIAL | p11 |
| PROFILE-057 | G120V10 | User status change | 32 | 5B | - | - | PARTIAL | p11 |
| PROFILE-058 | G120V11 | Update key change request | 32 | 5B | - | - | VERIFIED | p11 |
| PROFILE-059 | G120V12 | Update key change reply | - | - | 131 | 5B | VERIFIED | p11 |
| PROFILE-060 | G120V13 | Update key change | 32 | 5B | - | - | VERIFIED | p11 |
| PROFILE-061 | G120V14 | Update key change signature | 32 | 5B | - | - | PARTIAL | p11 |
| PROFILE-062 | G120V15 | Update key change confirmation | 32 | 5B | 131 | 5B | VERIFIED | p12 |
| PROFILE-063 | G121V1 | Security statistics 32-bit with flag | 1 | 00\|01\|06\|17\|28 | 129 | 00\|01\|17\|28 | IMPLEMENTED_NOT_VERIFIED | p12 |
| PROFILE-064 | G122V0 | Security statistics event any | 1 | 00\|01\|06\|17\|28 | - | - | IMPLEMENTED_NOT_VERIFIED | p12 |
| PROFILE-065 | G122V1 | Security statistics event with flag | 1 | 06\|07\|08 | 129\|130 | 17\|28 | IMPLEMENTED_NOT_VERIFIED | p12 |
| PROFILE-066 | G122V2 | Security statistics event with flag and time | 1 | 06\|07\|08 | 129\|130 | 17\|28 | PARTIAL | p12 |
| PROFILE-067 | Function-only | No-object CONFIRM | 0 | - | - | - | VERIFIED | p12 |
| PROFILE-068 | Function-only | No-object COLD_RESTART | 13 | - | - | - | PARTIAL | p12 |
| PROFILE-069 | Function-only | No-object DELAY_MEASURE | 23 | - | - | - | VERIFIED | p12 |

## Minimum security addendum: 36 selected parameters

Values below are selections/ranges copied from the PDF-derived matrix. Blank choices, certificate/TLS algorithm ambiguities and hardware dependencies are not silently filled.

| ID | Parameter | Selected value / constraint | Class | Recorded status | PDF row |
|---|---|---|---|---|---|
| SEC-T1-01 | Secure Authentication | Fixed: Version 5 \| Mandatory, no false reporting | MANDATORY | PARTIAL | PDF p3, Table 1, row 1 |
| SEC-T1-02 | Maximum users | Configurable, at least 2 \| Mandatory | MANDATORY | VERIFIED | PDF p3, Table 1, row 2 |
| SEC-T1-03 | Security response timeout | Configurable 0-120 s per addendum; IEEE 7.6.1.4.1 default 2 s, 100 ms steps and maximum at least 120 s \| Zero semantics still OPEN | MANDATORY | PARTIAL | PDF p3, Table 1, row 3 |
| SEC-T1-04 | Aggressive receive | Yes, not recommended \| Capability required; usage policy separate | MANDATORY | VERIFIED | PDF p3, Table 1, row 4 |
| SEC-T1-05 | Aggressive issue | Yes, not recommended \| Capability required; usage policy separate | MANDATORY | VERIFIED | PDF p3, Table 1, row 5 |
| SEC-T1-06 | Challenge-response | Mandatory \| Mandatory | MANDATORY | VERIFIED | PDF p3, Table 1, row 6 |
| SEC-T1-07 | Session key change interval | Configurable, 15-120 min \| Mandatory | MANDATORY | IMPLEMENTED_NOT_VERIFIED | PDF p3, Table 1, row 7 |
| SEC-T1-08 | Session key change count | Configurable, default 1000 messages \| Mandatory | MANDATORY | VERIFIED | PDF p3, Table 1, row 8 |
| SEC-T1-09 | Requested MAC | Selectable SHA-256 (16/8 octets), AES-GMAC \| Final required *selection set* not filled by checkboxes; track separately | UNRESOLVED | PARTIAL | PDF p3, Table 1, row 9 |
| SEC-T1-10 | Session key wrapping | AES-256 mandatory; AES-128 not recommended \| Mandatory AES-256 | MANDATORY | VERIFIED | PDF p3, Table 1, row 10 |
| SEC-T1-11 | TLS cipher suites | TLS 1.2 and TLS 1.3 lists \| Conflicting TLS 1.3 naming; clarify before coding | MANDATORY | BLOCKED | PDF p3-4, Table 1, row 11 |
| SEC-T1-12 | DNP TCP port using TLS | Fixed: 19999 \| Mandatory when using TLS | MANDATORY | VERIFIED | PDF p4, Table 1, row 12 |
| SEC-T1-13 | Cipher-change request timeout | Configurable, 1-60 s \| Mandatory | MANDATORY | NOT_IMPLEMENTED | PDF p4, Table 1, row 13 |
| SEC-T1-14 | Supported CAs | At least 4 \| Mandatory | MANDATORY | IMPLEMENTED_NOT_VERIFIED | PDF p4, Table 1, row 14 |
| SEC-T1-15 | Certificate revocation check time | Addendum numeric field blank; IEEE 7.8.7.4.3 default 12 h, configurable at 1-hour resolution \| CRL distribution/freshness and live-session scheduling remain open | MANDATORY | NOT_IMPLEMENTED | PDF p4, Table 1, row 15 |
| SEC-T1-16 | Remote update-key changes | Configurable, symmetric/asymmetric algorithm options \| Must distinguish alternatives vs minimum mandatory options | MANDATORY | PARTIAL | PDF p4, Table 1, row 16 |
| SEC-T1-17 | User-credential expiry | Yes \| Mandatory | MANDATORY | VERIFIED | PDF p4, Table 1, row 17 |
| SEC-T2-01 | Protocol authentication | Challenge-response; Aggressive Mode not recommended | MANDATORY | VERIFIED | PDF p5, Table 2, row 1 |
| SEC-T2-02 | Protected communications | TLS 1.2 and TLS 1.3 | MANDATORY | VERIFIED | PDF p5, Table 2, row 2 |
| SEC-T2-03 | Session-key encryption and exchange | Key wrap | MANDATORY | VERIFIED | PDF p5, Table 2, row 3 |
| SEC-T2-04 | Update-key protection | Symmetric and asymmetric approaches indicated; must agree on operative choice | MANDATORY | PARTIAL | PDF p5, Table 2, row 4 |
| SEC-T2-05 | Session key length | 128-bit acceptable; 256-bit recommended | MANDATORY | VERIFIED | PDF p5, Table 2, row 5 |
| SEC-T2-06 | Update key length | 128-bit acceptable; 256-bit recommended | MANDATORY | VERIFIED | PDF p5, Table 2, row 6 |
| SEC-T2-07 | Local RTU configuration password | Mandatory | MANDATORY | NOT_IMPLEMENTED | PDF p5, Table 2, row 7 |
| SEC-T2-08 | Random generation for security keys | Mandatory | MANDATORY | VERIFIED | PDF p5, Table 2, row 8 |
| SEC-T2-09 | Authentication enabled by default | Mandatory; disabling for protocol configuration accepted (as described) | MANDATORY | PARTIAL | PDF p5, Table 2, row 9 |
| SEC-T2-10 | Minimum user roles | Administrator for security settings, ordinary user for technical settings; both may perform ordinary tasks | MANDATORY | PARTIAL | PDF p5, Table 2, row 10 |
| SEC-T2-11 | Security parameter configurability | Mandatory for all protocol/configuration security parameters | MANDATORY | PARTIAL | PDF p5, Table 2, row 11 |
| SEC-T3-01 | Close unused hardware ports | Mandatory | MANDATORY | NOT_AUDITED | PDF p6, Table 3, row 1 |
| SEC-T3-02 | Close unused network ports | Mandatory | MANDATORY | NOT_AUDITED | PDF p6, Table 3, row 2 |
| SEC-T3-03 | Disable unnecessary users | Mandatory | MANDATORY | PARTIAL | PDF p6, Table 3, row 3 |
| SEC-T3-04 | Strong passwords for human users | Mandatory strong passwords (security PDF p6 Table 3 row 4) | MANDATORY | PARTIAL | PDF p6, Table 3, row 4 |
| SEC-T3-05 | Do not hardcode credentials | Mandatory | MANDATORY | PARTIAL | PDF p6, Table 3, row 5 |
| SEC-T3-06 | Hash stored credentials | Mandatory | MANDATORY | NOT_AUDITED | PDF p6, Table 3, row 6 |
| SEC-T3-07 | Secure firmware update with digital-signature verification | Recommended | RECOMMENDED | NOT_AUDITED | PDF p6, Table 3, row 7 |
| SEC-T3-08 | Check digital signature during firmware update | Recommended | RECOMMENDED | NOT_AUDITED | PDF p6, Table 3, row 8 |

## Device Profile: 14 runtime and configuration groups

**All selected settings and boundary conditions are included.** A compound CFG row is incomplete if any of its selected subcases is incomplete.

| ID | PDF location | Selected values and known gaps | Recorded source status |
|---|---|---|---|
| CFG-01 | p1 / original 41 | Level 3 Outstation and explicitly listed extensions. Identify vendor/device metadata left blank in the form without fabricating values. | PARTIAL |
| CFG-02 | p2 / original 42 | Link receive frame size must be 292 octets. Transmit size is blank. Document the product value and verify frame boundaries. | PARTIAL |
| CFG-03 | p2 / original 42 | Application receive fragment size must exceed 249 octets. Transmit size above 2048 must be configurable. Both size fields are blank. Verify configured bounds, segmentation, reassembly and resource limits. | IMPLEMENTED_NOT_VERIFIED |
| CFG-04 | p2 / original 42 | Link retries configurable 0-5. Application retries configurable 1-5, fixed retries disallowed. Test limits, exhaustion and reconnect while respecting IEEE function-specific retry prohibitions, including direct controls. | PARTIAL |
| CFG-05 | p2 / original 42 | Link confirmation configurable as Never, Always or On multi-frame fragments. Exercise each permitted policy. | IMPLEMENTED_NOT_VERIFIED |
| CFG-06 | p2 / original 42 | Application confirmation selected for event data and multi-fragment responses. Verify CONFIRM ownership, timeout, retry and event retention. | PARTIAL |
| CFG-07 | pp2-3 / original 42-43 | Configurable waits for link confirm, complete application fragment, application confirm and complete application response. Numeric ranges/defaults and explanatory attachment are absent. Resolve role applicability and test approved values and boundaries. | PARTIAL |
| CFG-08 | p3 / original 43 | SELECT/OPERATE, DIRECT OPERATE and DIRECT OPERATE NO ACK selected Always. Verify execution, denial and no-response semantics with selected G12/G41 wire forms and SA policy. Compatibility-only FC6 evidence does not close authenticated control acceptance. | IMPLEMENTED_NOT_VERIFIED |
| CFG-09 | p3 / original 43 | Owner-approved D-07 (2026-11-11): support CLOSE 0x41 and TRIP 0x81 on configured Complementary points (Latch or Two-output as appropriate). Permit 0x01 NUL/PULSE_ON only on explicitly enabled Activation points; deny on Complementary, disabled or undefined points. Require count=1, no queue/clear, no Pulse Off or Latch OpType. Use the configured safe point pulse duration rather than Master-requested duration; preserve exact request/echo and validate timing semantics. SELECT validates and arms only, never actuates. Authenticate SA v5, authorize the user and recheck interlocks and safe execution conditions before every actuation. Preserve generic library capabilities. | IMPLEMENTED_NOT_VERIFIED |
| CFG-10 | p3 / original 43 | Default binary change events are Only time-tagged. Absolute-time form and Configurable are both selected for default timed events. Verify actual default variation and obtain the missing configuration explanation. | PARTIAL |
| CFG-11 | p4 / original 44 | Unsolicited responses configurable and ENABLE/DISABLE UNSOLICITED supported. Verify enable/disable, startup, event delivery, confirmations and retry behavior. Configuration explanation is absent. | PARTIAL |
| CFG-12 | p4 / original 44 | Static unsolicited data selected When Device Restarts, with other options unselected. Resolve the exact IEEE-compatible startup sequence and static-data delivery requirement. Test real restart integration separately from a startup null unsolicited response. | BLOCKED |
| CFG-13 | p4 / original 44 | No Counters Reported selected for both counter defaults and rollover. Production configuration must report no physical counter points. General Level 4 G20-G23 implementation is outside this target. | IMPLEMENTED_NOT_VERIFIED |
| CFG-14 | p4 / original 44 | Multi-fragment responses selected Yes. Test selected data families across fragments, sequence progression, confirmations and malformed/incomplete transfers. | IMPLEMENTED_NOT_VERIFIED |

## Evidence and progress update rule

1. Audit every selected object/variation, FC, qualifier, role, parameter value, range and relevant negative subcase against the **current source revision**.
2. One incomplete selected subcase makes its parent row PARTIAL. An unknown product choice cannot be replaced with an invented value.
3. Only use current-revision VERIFIED after recording actual Windows unit, process/TCP, wire and negative test evidence with source SHA; keep independent-peer and physical RTU acceptance separate.
4. Reconcile the machine-readable CSV, SVG, README and execution ledger together. Do not inflate completion by merely counting commits.
5. A fraction of the 119 tracked rows is *requirement-row coverage*, not a percent of engineering effort or full IEEE Level 4 compliance.

## Open items

- `P4-OPEN-01` remains unresolved. G120V7 Code 5 = MAC Algorithm Not Supported; Code 7 = Authorization Failed is the provisional interpretation.
- G0V209 truthful capability advertisement and G120V8 certificate trust need runtime and interoperability evidence.
- TLS1.3 cipher names, MAC selections, CA/CRL revocation cadence, product-specific timeouts, application retries and startup/static unsolicited policy need explicit treatment.
- Deployment-only credentials, trusted time, IO/interlocks, target NVM, STM32H743/FreeRTOS and hardware firmware controls remain separate.
- The excerpts do not establish unavailable parent-document requirements or supply blank product parameter values.

