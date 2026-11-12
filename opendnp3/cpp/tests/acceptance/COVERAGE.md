# Acceptance scenario coverage

448 original scenario IDs, 54 requirements. 344 Host scenarios have executable bindings (631 vectors). 97 Host scenarios remain NOT_RUN. 7 scenarios require evidence outside this Host campaign.

A scenario suffix in the table expands to `AT-<requirement ID>-<suffix>`. The registry gives the binding, vectors, independent golden values and sources. Record executed evidence by tested revision in the [canonical workbook](../../../../DNP3_PDD_PLAN/DNP3_IEEE1815_IMPLEMENTATION_REFERENCE.xlsx).

| Requirement | Executable suffixes | Pending Host suffixes | External suffixes |
| --- | --- | --- | --- |
| PROFILE-003 | `RD00`, `RD01`, `RD06`, `DEFAULT`, `BAD`, `AS00`, `AS01`, `AS06` | — | — |
| PROFILE-004 | `RD00`, `RD01`, `RD06`, `VALUE`, `BAD` | — | — |
| PROFILE-005 | `RD00`, `RD01`, `RD06`, `VALUE`, `BAD` | — | — |
| PROFILE-006 | `R06Q28`, `R07Q28`, `R08Q28`, `DEFAULT`, `NEG` | — | — |
| PROFILE-007 | `R06Q17`, `R06Q28`, `R07Q17`, `R07Q28`, `R08Q17`, `R08Q28`, `UQ17`, `UQ28`, `NEG`, `BATCH` | — | — |
| PROFILE-008 | `R06Q17`, `R06Q28`, `R07Q17`, `R07Q28`, `R08Q17`, `R08Q28`, `UQ17`, `UQ28`, `NEG`, `VALUE` | — | — |
| PROFILE-009 | `R06Q17`, `R06Q28`, `R07Q17`, `R07Q28`, `R08Q17`, `R08Q28`, `UQ17`, `UQ28`, `NEG`, `CTO` | — | — |
| PROFILE-010 | `RD00`, `RD01`, `RD06`, `DEFAULT`, `BAD`, `AS00`, `AS01`, `AS06` | — | — |
| PROFILE-011 | `RD00`, `RD01`, `RD06`, `VALUE`, `BAD` | — | — |
| PROFILE-012 | `RD00`, `RD01`, `RD06`, `VALUE`, `BAD` | — | — |
| PROFILE-013 | `R06Q28`, `R07Q28`, `R08Q28`, `DEFAULT`, `NEG` | — | — |
| PROFILE-014 | `R06Q17`, `R06Q28`, `R07Q17`, `R07Q28`, `R08Q17`, `R08Q28`, `UQ17`, `UQ28`, `NEG`, `BATCH` | — | — |
| PROFILE-015 | `R06Q17`, `R06Q28`, `R07Q17`, `R07Q28`, `R08Q17`, `R08Q28`, `UQ17`, `UQ28`, `NEG`, `VALUE` | — | — |
| PROFILE-016 | `R06Q17`, `R06Q28`, `R07Q17`, `R07Q28`, `R08Q17`, `R08Q28`, `UQ17`, `UQ28`, `NEG`, `CTO` | — | — |
| PROFILE-017 | `RD00`, `RD01`, `RD06`, `DEFAULT`, `BAD` | — | — |
| PROFILE-018 | `RD00`, `RD01`, `RD06`, `VALUE`, `BAD` | — | — |
| PROFILE-020 | `RD00`, `RD01`, `RD06`, `DEFAULT`, `BAD`, `AS00`, `AS01`, `AS06` | — | — |
| PROFILE-021 | `RD00`, `RD01`, `RD06`, `VALUE`, `BAD` | — | — |
| PROFILE-022 | `RD00`, `RD01`, `RD06`, `VALUE`, `BAD` | — | — |
| PROFILE-023 | `RD00`, `RD01`, `RD06`, `VALUE`, `BAD` | — | — |
| PROFILE-024 | `RD00`, `RD01`, `RD06`, `VALUE`, `BAD` | — | — |
| PROFILE-025 | `RD00`, `RD01`, `RD06`, `VALUE`, `BAD` | — | — |
| PROFILE-026 | `R06Q28`, `R07Q28`, `R08Q28`, `DEFAULT`, `NEG` | — | — |
| PROFILE-027 | `R06Q17`, `R06Q28`, `R07Q17`, `R07Q28`, `R08Q17`, `R08Q28`, `UQ17`, `UQ28`, `NEG`, `BATCH` | — | — |
| PROFILE-028 | `R06Q17`, `R06Q28`, `R07Q17`, `R07Q28`, `R08Q17`, `R08Q28`, `UQ17`, `UQ28`, `NEG` | — | — |
| PROFILE-029 | `R06Q17`, `R06Q28`, `R07Q17`, `R07Q28`, `R08Q17`, `R08Q28`, `UQ17`, `UQ28`, `NEG`, `VALUE` | — | — |
| PROFILE-030 | `R06Q17`, `R06Q28`, `R07Q17`, `R07Q28`, `R08Q17`, `R08Q28`, `UQ17`, `UQ28`, `NEG`, `VALUE` | — | — |
| PROFILE-031 | `RD00`, `RD01`, `RD06`, `DEFAULT`, `BAD` | — | — |
| PROFILE-032 | `RD00`, `RD01`, `RD06`, `VALUE`, `BAD` | — | — |
| PROFILE-033 | `RD00`, `RD01`, `RD06`, `VALUE`, `BAD` | — | — |
| PROFILE-034 | `RD00`, `RD01`, `RD06`, `VALUE`, `BAD` | — | — |
| PROFILE-035 | `SBO17`, `DO17`, `NR17`, `SBO28`, `DO28`, `NR28`, `SBO-OWNER`, `ECHO`, `REJECT`, `DUP` | — | — |
| PROFILE-036 | `SBO17`, `DO17`, `NR17`, `SBO28`, `DO28`, `NR28`, `SBO-OWNER`, `ECHO`, `REJECT`, `DUP` | — | — |
| PROFILE-037 | `SBO17`, `DO17`, `NR17`, `SBO28`, `DO28`, `NR28`, `SBO-OWNER`, `ECHO`, `REJECT`, `DUP` | — | — |
| PROFILE-038 | `READ`, `WRITE`, `NEG`, `EDGE` | — | — |
| PROFILE-039 | `F129G2`, `F129G4`, `F130G2`, `F130G4`, `NEG` | — | — |
| PROFILE-040 | `F129G2`, `F129G4`, `F130G2`, `F130G4`, `NEG` | — | — |
| PROFILE-041 | `RESTART`, `NEG` | — | `RTU` |
| PROFILE-042 | `DELAY`, `RESTART`, `NEG` | — | `MEASURED` |
| PROFILE-043 | `READ06`, `ASSIGN`, `ILLEGAL` | — | — |
| PROFILE-044 | `READ06`, `READ07`, `READ08`, `ASSIGN`, `ILLEGAL`, `ENABLE`, `DISABLE` | — | — |
| PROFILE-045 | `READ06`, `READ07`, `READ08`, `ASSIGN`, `ILLEGAL`, `ENABLE`, `DISABLE` | — | — |
| PROFILE-046 | `READ06`, `READ07`, `READ08`, `ASSIGN`, `ILLEGAL`, `ENABLE`, `DISABLE` | — | — |
| PROFILE-063 | `RX00`, `RX01`, `RX17`, `RX28`, `READ00`, `READ01`, `READ06`, `READ17`, `READ28`, `IIN`, `SNAP`, `RET` | — | `WIDE-TX` |
| PROFILE-064 | `READ00`, `READ01`, `READ06`, `READ17`, `READ28`, `BAD` | — | — |
| PROFILE-065 | `R06Q17`, `R06Q28`, `R07Q17`, `R07Q28`, `R08Q17`, `R08Q28`, `UQ17`, `UQ28`, `NEG`, `THRESH`, `QUEUE`, `DISCONT`, `CLASS`, `TCP` | — | `Q17-TX` |
| SEC-T1-07 | `T15`, `T16`, `T30`, `T60`, `T120` | `CONFIG`, `ISOLATION`, `FAIL`, `TCP` | — |
| SEC-T1-14 | — | `SERVER-CA1`, `SERVER-CA2`, `SERVER-CA3`, `SERVER-CA4`, `CLIENT-CA1`, `CLIENT-CA2`, `CLIENT-CA3`, `CLIENT-CA4`, `REMOVE`, `UNTRUSTED`, `BAD-BUNDLE`, `CHAIN` | — |
| CFG-03 | `TPDU`, `TIMEOUT`, `MASTER-CLI`, `OUTSTATION-CLI`, `MASTER-RX`, `OUTSTATION-RX`, `MASTER-TX`, `OUTSTATION-TX` | — | `PRODUCT` |
| CFG-05 | `MASTER-NEVER-249`, `MASTER-NEVER-250`, `MASTER-ALWAYS-249`, `MASTER-ALWAYS-250`, `MASTER-MULTIFRAME-249`, `MASTER-MULTIFRAME-250`, `OUTSTATION-NEVER-249`, `OUTSTATION-NEVER-250`, `OUTSTATION-ALWAYS-249`, `OUTSTATION-ALWAYS-250`, `OUTSTATION-MULTIFRAME-249`, `OUTSTATION-MULTIFRAME-250` | `RETRY`, `OWNER`, `STALE`, `DFC`, `BCAST`, `TCP` | — |
| CFG-08 | — | `M4-CHALLENGE-G12V1-SBO`, `M4-CHALLENGE-G12V1-DO`, `M4-CHALLENGE-G12V1-NR`, `M4-CHALLENGE-G41V1-SBO`, `M4-CHALLENGE-G41V1-DO`, `M4-CHALLENGE-G41V1-NR`, `M4-CHALLENGE-G41V2-SBO`, `M4-CHALLENGE-G41V2-DO`, `M4-CHALLENGE-G41V2-NR`, `M4-CHALLENGE-G41V3-SBO`, `M4-CHALLENGE-G41V3-DO`, `M4-CHALLENGE-G41V3-NR`, `M4-AGGRESSIVE-G12V1-SBO`, `M4-AGGRESSIVE-G12V1-DO`, `M4-AGGRESSIVE-G12V1-NR`, `M4-AGGRESSIVE-G41V1-SBO`, `M4-AGGRESSIVE-G41V1-DO`, `M4-AGGRESSIVE-G41V1-NR`, `M4-AGGRESSIVE-G41V2-SBO`, `M4-AGGRESSIVE-G41V2-DO`, `M4-AGGRESSIVE-G41V2-NR`, `M4-AGGRESSIVE-G41V3-SBO`, `M4-AGGRESSIVE-G41V3-DO`, `M4-AGGRESSIVE-G41V3-NR`, `M68-CHALLENGE-G12V1-SBO`, `M68-CHALLENGE-G12V1-DO`, `M68-CHALLENGE-G12V1-NR`, `M68-CHALLENGE-G41V1-SBO`, `M68-CHALLENGE-G41V1-DO`, `M68-CHALLENGE-G41V1-NR`, `M68-CHALLENGE-G41V2-SBO`, `M68-CHALLENGE-G41V2-DO`, `M68-CHALLENGE-G41V2-NR`, `M68-CHALLENGE-G41V3-SBO`, `M68-CHALLENGE-G41V3-DO`, `M68-CHALLENGE-G41V3-NR`, `M68-AGGRESSIVE-G12V1-SBO`, `M68-AGGRESSIVE-G12V1-DO`, `M68-AGGRESSIVE-G12V1-NR`, `M68-AGGRESSIVE-G41V1-SBO`, `M68-AGGRESSIVE-G41V1-DO`, `M68-AGGRESSIVE-G41V1-NR`, `M68-AGGRESSIVE-G41V2-SBO`, `M68-AGGRESSIVE-G41V2-DO`, `M68-AGGRESSIVE-G41V2-NR`, `M68-AGGRESSIVE-G41V3-SBO`, `M68-AGGRESSIVE-G41V3-DO`, `M68-AGGRESSIVE-G41V3-NR`, `DENY`, `REPLAY`, `TIMEOUT`, `NOACK` | `PEER` |
| CFG-09 | — | `CLOSE`, `TRIP`, `COUNT`, `PULSE-OFF`, `LATCH-ON`, `LATCH-OFF`, `QUEUE`, `CLEAR`, `BADCODE`, `WRITE`, `PULSE-ON` | `RTU` |
| CFG-13 | `COMPAT` | `STATIC`, `EVENT`, `NEG` | — |
| CFG-14 | — | `STATIC`, `MIX`, `UNSOL`, `WRAP`, `TRANSPORT`, `LOSS`, `MALFORMED`, `TIME`, `TCP` | — |

## External gates

| Scenario | Gate | Required evidence or decision |
| --- | --- | --- |
| `AT-PROFILE-041-RTU` | EXTERNAL_HARDWARE | Physical restart and approved target delay. IEEE Annex A.25.1 and Device Profile p9. |
| `AT-PROFILE-042-MEASURED` | EXTERNAL_HARDWARE | Actual nonzero target processing delay and independent timing measurement. IEEE 1815-2012 §4.4.15, Annex A.25.2 and Device Profile p9. The Host zero-duration response is a separate test. |
| `AT-PROFILE-063-WIDE-TX` | EXTERNAL_POLICY | Approve an Outstation wide-range transmit selection. Device Profile p12 makes Outstation transmission permissive and Master reception mandatory. Host receive cases stay in scope. |
| `AT-PROFILE-065-Q17-TX` | EXTERNAL_POLICY | Approve optional Outstation Q17 transmission for the selected large object family. Device Profile p12. Master reception stays in Host scope. |
| `AT-CFG-03-PRODUCT` | EXTERNAL_POLICY | Approve concrete RX/TX limits for the product. Device Profile p2 sets RX >249 and conditional TX configurability above 2048, with product fields left open. |
| `AT-CFG-08-PEER` | EXTERNAL_PEER | Repeat the selected security matrix with an independent peer. A second instance of the project cannot supply independent-peer evidence. |
| `AT-CFG-09-RTU` | EXTERNAL_HARDWARE | Physical output, pulse timing and fail-safe evidence on the target. Device Profile p3. |

The external allocation uses the two contractual PDFs and IEEE 1815-2012. The Security Addendum's product/peer constraints do not turn unbound Host SA cases into external gates.

D-07 owner approved 2026-11-11: AT-CFG-09-PULSE-ON is HOST/PROCESS_TCP and NOT_RUN until an actual executable binding is implemented. Physical RTU mapping and timing remain external.
