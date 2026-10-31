# Source index and engineering partition

## Input integrity and scope

| ID | Original file | PDF pages | What it governs |
|---|---|---:|---|
| IEEE | `IEEE 1815-2012.pdf` | 821 | Normative formats, functions, object semantics and layer behavior |
| PROFILE | `4812449245627490050_724147149003390.pdf` | 12 | Supplied RTU profile, selection boxes and implementation-table requirements |
| SEC | `الزامت حداقل مورد نیاز.pdf` | 6 | Amended security requirements, constraints and hardening |

The PROFILE is **a 12-page excerpt** showing its original document page numbering **41 to 52 of 78**. It identifies the outstation role and Level 3 request/response support. Do not assume absent pages of the full 78-page document are available.

The SEC introduction (PDF p2) describes modified security tables relating to a larger requirements document. The other pages/rows of that parent document have **not** been supplied. Do not claim complete contract coverage based solely on this excerpt.

## Source partitions: IEEE (PDF page, 1-based)

| Logical module | IEEE sections | Starting PDF page | Engineering use |
|---|---|---:|---|
| Object terminology and static/event/class | 4.1 | 55 | Point models; class semantics |
| APDU headers, fragments, function handling | 4.2-4.5 | 61-123 | Reuse existing request/response paths; IIN |
| READ/WRITE/device attributes | 5.5.1-5.5.8 | 190-195 | Required for G0V209 and other Group 0 values |
| Attribute data types | 5.5.4.3 / Table 5-16 | 192 | Code 2 for UINT; byte length |
| Security behavior | Clause 7 | 213 | SA v5 protocol and roles |
| Security messages, procedures | 7.5.1-7.5.5 | 228-281 | Stateful authentication, not just serialization |
| Transport | Clause 8 | 309 | Protected existing infrastructure |
| Data link | Clause 9 | 316 | Protected existing infrastructure |
| Object library definitions | Clause 11 | 349 | Generic wire shapes |
| Subset-level parsing tables | Clause 12.1 | 393 | Check obligations by level |
| Special object parsing guidance | Clause 12.2 | 404 | Qualifier/function compatibility |
| Device Attributes G0 | Annex A.1 | 480 | Attribute variations |
| G0V209 | A.1.1 | 480 (printed p438) | First requested object |
| G0V210 | A.1.2 | 481 (printed p439) | Second attribute candidate |
| G0V254 and G0V255 | A.1.43 and A.1.44 | 527, 528 | Group 0 discovery/all attributes behavior |
| SA message objects G120 | A.45 | 761 | G120V1-V15 |
| Security statistics G121 | A.46 | 800 | G121V1 |
| Security event G122 | A.47 | 802 | G122V1-V2 |

For other Groups, look up their *specific* Annex A entry and the corresponding Clause 12 table **when that variation is selected**; do not paste all 821 pages into Codex context.

## Profile partitions

| PDF page(s) | Portion | Implementation concern |
|---|---|---|
| 1-2 | Device profile declaration and notable objects | Level 3 outstation; extras G0/G120/G121/G122 |
| 2-4 | Link, fragmentation, retries, control modes, events and unsolicited options | Runtime configuration and behavior; several numeric fields are blank |
| 4 | G0V209/V210, G1V0/V1 | Device attributes and binary inputs |
| 5 | G1V2, G2, G3, G4V0 | Binary and double-bit static/event |
| 6 | G4V1-V3, G10, G12, G30V0/V1 | Control and analog start |
| 7 | G30, G32, G40V0 | Analog and events |
| 8 | G40, G41, G50V1 | Analog output and time |
| 9 | G50-V52, G60V1-V3 | Time, Class 0-2 |
| 10 | G60V4, G80V1, G120V1-V4 | Class 3, internal indications, SA |
| 11 | G120V5-V14 | SA messages |
| 12 | G120V15, G121V1, G122, no-object functions | Security counters/events and function-only support |

The complete **identified Group/Variation rows** appear in `02_PROFILE_MATRIX.csv`; entries record **what the profile shows**, not proof of code support. The column `qualifier_status` flags cases where response echoes the request or the table is function-specific.

## Security partitions

| PDF page(s) | Portion | File |
|---|---|---|
| 1-2 | Title, revision, relationship to amended RTU rules | `03_SECURITY_MATRIX.md` |
| 3-4 | Table 1, parameters 1-17 | `03_SECURITY_MATRIX.md` |
| 5 | Table 2, requirements 1-11 | `03_SECURITY_MATRIX.md` |
| 6 | Table 3, hardening 1-8 | `03_SECURITY_MATRIX.md` |

## Items intentionally not inferred

- Source tree, OpenDNP3 commit/tag, existing STM32 adaptations, and generated-code workflow are unknown until the local C++ project is available.
- Vendor name and device name fields are blank in PROFILE PDF p1; application fragmentation sizes are also left blank on p2.
- The PROFILE states **No Counters Reported** (p4). Do not treat all standard counter objects as product requirements solely because OpenDNP3 implements them.
- Device Profile Level 3 is explicit. A separate, complete Level 4 target requires a distinct approved gap assessment; it does not follow automatically from the supplied profile.
