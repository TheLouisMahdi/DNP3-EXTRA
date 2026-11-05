Implementation blueprint
1. Purpose, authority and scope boundaries
Audit baseline is the current develop working tree, including uncommitted documentation, at HEAD 76a4b89bd68a81acd32e90c946f0818f3568efb2. This document specifies future work. No production changes, builds or tests were performed.

Authoritative sources under IEEE 1815/ are the 12-page 4812449245627490050_724147149003390.pdf (original pp41–52 of 78), the six-page الزامت حداقل مورد نیاز.pdf, and IEEE 1815-2012.pdf. Profile p1 selects Level 3 requests/responses and Slave. Master is unselected. Profile pp1–4 select settings and pp4–12 contain the implementation table. Security Table 1 is on physical pp3–4, Table 2 on p5 and Table 3 on p6. Footer pagination differs.

The acceptance sets are 69 Profile IDs, 36 security IDs and 14 additional runtime checklist entries. Compound entries require every applicable assertion. The 712-row IEEE reference inventory is outside the contractual backlog. Preserve working extensions, including counters and G34/G13/G43, while production follows No Counters Reported. Do not expand the selected qualifier/variation sets.

Outstation must accept selected requests and implement their applicable procedures. Preserve existing Master capabilities. Optional Master issuance becomes project work only when necessary for selected functionality/testing or explicitly requested. Response-only information objects do not imply a new READ operation.
Assessment rules and evidence limits
VERIFIED requires matching implementation and sufficient actual passing evidence for the whole assessed behavior. IMPLEMENTED_UNVERIFIED means an operational path exists but complete execution coverage is absent. PARTIAL identifies behavior or coverage gaps. MISSING identifies absent runtime functionality. BLOCKED identifies unresolved product, specification, external or target dependencies. NOT_APPLICABLE requires source-based justification.

No whole requirement is promoted to VERIFIED in this audit. Tests reviewed below establish fixture and assertion coverage, not fresh execution. Historical matrices alone establish no conformance. FC6-B3a commit a1d3ddcc096f329bdcc7f07da167a596eb0cb2e6 contains sequence-wrap/TCP tests. The preserved report records 5 cases/392 assertions and CTest 8/8 on a pre-commit tree based on 0b8026098e2c5564eb95eaa7641daf3b3425a52c. That subset concerns Compatibility mode. PROGRESS_EVIDENCE.json records older execution at 4d9f7bbaea1fcf305d942abe7891384df18a6199. Neither closes authenticated FC6 or current full-product acceptance. The local unverified acceptance runner supplies no accepted result.

Source PDF images were checked because text extraction loses numeric glyphs and checkboxes. The excerpts do not establish complete coverage of unavailable parent documents. External certificate definitions required by Annex A.45.8 remain explicit dependencies. Unresolved interpretations below are implementation gates.
2. Requirements coverage matrix
All 119 entries map to a component design/package Bxx and validation V-xx below. Profile assessments distinguish Master and Outstation. Security/runtime assessments concern the RTU obligation. Separate mandatory, recommended, conditional and unresolved dispositions.

Paths below use S/ for opendnp3/cpp/lib/src/, A/ for opendnp3/cpp/lib/include/opendnp3/, U/ for opendnp3/cpp/tests/unit/ and I/ for opendnp3/cpp/tests/integration/.

FCs are decimal, qualifiers hexadecimal. Sets are function-specific, not a Cartesian product. FC6 has no solicited application response. G60 count qualifiers apply only to READ. G80 WRITE uses qualifier 00 at index 7 with value zero, despite the grouped CSV qualifier field. G50/G51/G52 quantity is one. V0 requests select defaults and cannot become data response variations. G120V3/V9 frame an Aggressive message. Their 1–31 range does not mandate unselected functions.
Profile selections
Original document page = physical Profile PDF page + 40. Source/test entries identify existing paths and assertions, not completed execution of every displayed wire form.
ID	PDF p	Object	Request FC / Q	Response FC / Q	Master / Outstation	IEEE reference	Existing source / test	Package / validation
PROFILE-001	4	G0V209	1 / 00	129 / 00|17	IMPLEMENTED_UNVERIFIED / MISSING	A.1.1–2; 5.5	S/outstation/DeviceAttributeSelection.cpp; U/TestDeviceAttributes.cpp	B16 / V-16
PROFILE-002	4	G0V210	1 / 00	129 / 00|17	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.1.1–2; 5.5	S/outstation/DeviceAttributeSelection.cpp; U/TestDeviceAttributes.cpp	B11 / V-11
PROFILE-003	4	G1V0	1|22 / 00|01|06	- / -	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.2	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-004	4	G1V1	1 / 00|01|06	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.2	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-005	5	G1V2	1 / 00|01|06	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.2	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-006	5	G2V0	1 / 06|07|08	- / -	PARTIAL / PARTIAL	A.3; 4.5–4.6	S/outstation/event/EventBuffer.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-007	5	G2V1	1 / 06|07|08	129|130 / 17|28	PARTIAL / PARTIAL	A.3; 4.5–4.6	S/outstation/event/EventBuffer.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-008	5	G2V2	1 / 06|07|08	129|130 / 17|28	PARTIAL / PARTIAL	A.3; 4.5–4.6	S/outstation/event/EventBuffer.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-009	5	G2V3	1 / 06|07|08	129|130 / 17|28	PARTIAL / PARTIAL	A.3; 4.5–4.6	S/outstation/event/EventBuffer.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-010	5	G3V0	1|22 / 00|01|06	- / -	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.4	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-011	5	G3V1	1 / 00|01|06	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.4	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-012	5	G3V2	1 / 00|01|06	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.4	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-013	5	G4V0	1 / 06|07|08	- / -	PARTIAL / PARTIAL	A.5; 4.5–4.6	S/outstation/event/EventBuffer.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-014	6	G4V1	1 / 06|07|08	129|130 / 17|28	PARTIAL / PARTIAL	A.5; 4.5–4.6	S/outstation/event/EventBuffer.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-015	6	G4V2	1 / 06|07|08	129|130 / 17|28	PARTIAL / PARTIAL	A.5; 4.5–4.6	S/outstation/event/EventBuffer.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-016	6	G4V3	1 / 06|07|08	129|130 / 17|28	PARTIAL / PARTIAL	A.5; 4.5–4.6	S/outstation/event/EventBuffer.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-017	6	G10V0	1 / 00|01|06	- / -	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.6	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-018	6	G10V2	1 / 00|01|06	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.6	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-019	6	G12V1	3|4|5|6 / 17|28	129 / ECHO	PARTIAL / PARTIAL	A.8; 4.4.4–5	S/outstation/CommandResponseHandler.cpp; U/TestProfileControls.cpp	B03 / V-03
PROFILE-020	6	G30V0	1|22 / 00|01|06	- / -	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.14	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-021	6	G30V1	1 / 00|01|06	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.14	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-022	7	G30V2	1 / 00|01|06	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.14	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-023	7	G30V3	1 / 00|01|06	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.14	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-024	7	G30V4	1 / 00|01|06	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.14	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-025	7	G30V5	1 / 00|01|06	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.14	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-026	7	G32V0	1 / 06|07|08	- / -	PARTIAL / PARTIAL	A.16; 4.5–4.6	S/outstation/event/EventBuffer.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-027	7	G32V1	1 / 06|07|08	129|130 / 17|28	PARTIAL / PARTIAL	A.16; 4.5–4.6	S/outstation/event/EventBuffer.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-028	7	G32V2	1 / 06|07|08	129|130 / 17|28	PARTIAL / PARTIAL	A.16; 4.5–4.6	S/outstation/event/EventBuffer.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-029	7	G32V4	1 / 06|07|08	129|130 / 17|28	PARTIAL / PARTIAL	A.16; 4.5–4.6	S/outstation/event/EventBuffer.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-030	7	G32V5	1 / 06|07|08	129|130 / 17|28	PARTIAL / PARTIAL	A.16; 4.5–4.6	S/outstation/event/EventBuffer.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-031	7	G40V0	1 / 00|01|06	- / -	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.19	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-032	8	G40V1	1 / 00|01|06	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.19	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-033	8	G40V2	1 / 00|01|06	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.19	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-034	8	G40V3	1 / 00|01|06	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.19	S/outstation/Database.cpp; U/TestProfileMeasurements.cpp	B02 / V-02
PROFILE-035	8	G41V1	3|4|5|6 / 17|28	129 / ECHO	PARTIAL / PARTIAL	A.20; 4.4.4–5	S/outstation/CommandResponseHandler.cpp; U/TestProfileControls.cpp	B03 / V-03
PROFILE-036	8	G41V2	3|4|5|6 / 17|28	129 / ECHO	PARTIAL / PARTIAL	A.20; 4.4.4–5	S/outstation/CommandResponseHandler.cpp; U/TestProfileControls.cpp	B03 / V-03
PROFILE-037	8	G41V3	3|4|5|6 / 17|28	129 / ECHO	PARTIAL / PARTIAL	A.20; 4.4.4–5	S/outstation/CommandResponseHandler.cpp; U/TestProfileControls.cpp	B03 / V-03
PROFILE-038	8|9	G50V1	1|2 / 07	129 / 07	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.23.1; Table 12-23	S/outstation/WriteHandler.cpp; U/TestProfileTime.cpp	B04 / V-04
PROFILE-039	9	G51V1	- / -	129|130 / 07	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.24; Table 12-23	S/master/MeasurementHandler.cpp; U/TestProfileMeasurements.cpp	B04 / V-04
PROFILE-040	9	G51V2	- / -	129|130 / 07	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.24; Table 12-23	S/master/MeasurementHandler.cpp; U/TestProfileMeasurements.cpp	B04 / V-04
PROFILE-041	9	G52V1	- / -	129 / 07	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.25; Table 12-23	S/master/TimeSyncHandler.h; U/TestProfileTime.cpp	B04 / V-04
PROFILE-042	9	G52V2	- / -	129 / 07	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.25; Table 12-23	S/master/TimeSyncHandler.h; U/TestProfileTime.cpp	B04 / V-04
PROFILE-043	9	G60V1	1|22 / 06	- / -	PARTIAL / PARTIAL	A.26; 4.4–4.6	S/outstation/AssignClassHandler.cpp; U/TestProfileClasses.cpp	B02 / V-02
PROFILE-044	9	G60V2	1|20|21|22 / 06|07|08	- / -	PARTIAL / PARTIAL	A.26; 4.4–4.6	S/outstation/AssignClassHandler.cpp; U/TestProfileClasses.cpp	B02 / V-02
PROFILE-045	9|10	G60V3	1|20|21|22 / 06|07|08	- / -	PARTIAL / PARTIAL	A.26; 4.4–4.6	S/outstation/AssignClassHandler.cpp; U/TestProfileClasses.cpp	B02 / V-02
PROFILE-046	10	G60V4	1|20|21|22 / 06|07|08	- / -	PARTIAL / PARTIAL	A.26; 4.4–4.6	S/outstation/AssignClassHandler.cpp; U/TestProfileClasses.cpp	B02 / V-02
PROFILE-047	10	G80V1	READ 1 / 00,01; WRITE 2 / 00 index7	129 / 00|01	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	A.28; 4.4.2	S/outstation/WriteHandler.cpp; U/TestProfileTime.cpp	B04 / V-04
PROFILE-048	10	G120V1	32 / 5B	131 / 5B	PARTIAL / PARTIAL	Clause 7; A.45.1	S/auth/SessionKeys.cpp; U/TestProductionAuthentication.cpp	B06 / V-06
PROFILE-049	10	G120V2	32 / 5B	131 / 5B	PARTIAL / PARTIAL	Clause 7; A.45.2	S/auth/SessionKeys.cpp; U/TestProductionAuthentication.cpp	B06 / V-06
PROFILE-050	10	G120V3	1-31 / 07	129|130 / 07	PARTIAL / PARTIAL	Clause 7; A.45.3	S/auth/AggressiveMode.cpp; U/TestProductionAuthentication.cpp	B07 / V-07
PROFILE-051	10	G120V4	32 / 07	- / -	PARTIAL / PARTIAL	Clause 7; A.45.4	S/auth/SessionKeys.cpp; U/TestProductionAuthentication.cpp	B06 / V-06
PROFILE-052	11	G120V5	- / -	131 / 5B	PARTIAL / PARTIAL	Clause 7; A.45.5	S/auth/SessionKeys.cpp; U/TestProductionAuthentication.cpp	B06 / V-06
PROFILE-053	11	G120V6	32 / 5B	- / -	PARTIAL / PARTIAL	Clause 7; A.45.6	S/auth/SessionKeys.cpp; U/TestProductionAuthentication.cpp	B06 / V-06
PROFILE-054	11	G120V7	33 / 5B	131 / 5B	PARTIAL / PARTIAL	Clause 7; A.45.7	S/auth/SessionKeys.cpp; U/TestProductionAuthentication.cpp	B06 / V-06
PROFILE-055	11	G120V8	32 / 5B	- / -	MISSING / MISSING	Clause 7; A.45.8	S/auth/SessionKeys.cpp; U/TestProductionAuthentication.cpp	B08 / V-08
PROFILE-056	11	G120V9	1-31 / 5B	129|130 / 5B	PARTIAL / PARTIAL	Clause 7; A.45.9	S/auth/AggressiveMode.cpp; U/TestProductionAuthentication.cpp	B07 / V-07
PROFILE-057	11	G120V10	32 / 5B	- / -	PARTIAL / PARTIAL	Clause 7; A.45.10	S/auth/RemoteUpdateKeys.cpp; U/TestRemoteUpdateKeys.cpp	B09 / V-09
PROFILE-058	11	G120V11	32 / 5B	- / -	PARTIAL / PARTIAL	Clause 7; A.45.11	S/auth/RemoteUpdateKeys.cpp; U/TestRemoteUpdateKeys.cpp	B09 / V-09
PROFILE-059	11	G120V12	- / -	131 / 5B	PARTIAL / PARTIAL	Clause 7; A.45.12	S/auth/RemoteUpdateKeys.cpp; U/TestRemoteUpdateKeys.cpp	B09 / V-09
PROFILE-060	11	G120V13	32 / 5B	- / -	PARTIAL / PARTIAL	Clause 7; A.45.13	S/auth/RemoteUpdateKeys.cpp; U/TestRemoteUpdateKeys.cpp	B09 / V-09
PROFILE-061	11	G120V14	32 / 5B	- / -	PARTIAL / PARTIAL	Clause 7; A.45.14	S/auth/RemoteUpdateKeys.cpp; U/TestRemoteUpdateKeys.cpp	B09 / V-09
PROFILE-062	12	G120V15	32 / 5B	131 / 5B	PARTIAL / PARTIAL	Clause 7; A.45.15	S/auth/RemoteUpdateKeys.cpp; U/TestRemoteUpdateKeys.cpp	B09 / V-09
PROFILE-063	12	G121V1	1 / 00|01|06|17|28	129 / 00|01|17|28	PARTIAL / PARTIAL	A.46; 11.9.10; Table 11-19	S/auth/AuthenticationStatistics.cpp; U/TestSecurityStatRead.cpp	B11 / V-11
PROFILE-064	12	G122V0	1 / 00|01|06|17|28	- / -	PARTIAL / PARTIAL	A.47; 11.9.10; Table 11-19	S/outstation/SecurityStatEventPublisher.cpp; U/TestSecurityStatEvents.cpp	B11 / V-11
PROFILE-065	12	G122V1	1 / 06|07|08	129|130 / 17|28	PARTIAL / PARTIAL	A.47; 11.9.10; Table 11-19	S/outstation/SecurityStatEventPublisher.cpp; U/TestSecurityStatEvents.cpp	B11 / V-11
PROFILE-066	12	G122V2	1 / 06|07|08	129|130 / 17|28	PARTIAL / PARTIAL	A.47; 11.9.10; Table 11-19	S/outstation/SecurityStatEventPublisher.cpp; U/TestSecurityStatEvents.cpp	B11 / V-11
PROFILE-067	12	G-V-	0 / -	- / -	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	4.3–4.4; A.25	S/outstation/OutstationContext.cpp; U/TestOutstation.cpp	B04 / V-04
PROFILE-068	12	G-V-	13 / -	- / -	IMPLEMENTED_UNVERIFIED / BLOCKED	4.3–4.4; A.25	S/outstation/OutstationContext.cpp; U/TestOutstation.cpp	B04 / V-04
PROFILE-069	12	G-V-	23 / -	- / -	IMPLEMENTED_UNVERIFIED / IMPLEMENTED_UNVERIFIED	4.3–4.4; A.25	S/outstation/OutstationContext.cpp; U/TestOutstation.cpp	B04 / V-04


Security amendment
Required Aggressive capability and discouraged usage coexist. AES-256 wrap is explicitly mandatory. The 128-bit key minimum and 256-bit recommendation remain distinct. Unchecked algorithms remain product decisions. Source categories are preserved in each entry.
ID	PDF reference	Source selection and category	RTU assessment	Package / validation
SEC-T1-01	PDF p3, Table 1, row 1	Secure Authentication — Fixed: Version 5 / Mandatory, no false reporting	PARTIAL	B16 / V-16
SEC-T1-02	PDF p3, Table 1, row 2	Maximum users — Configurable, at least 2 / Mandatory	IMPLEMENTED_UNVERIFIED	B06 / V-06
SEC-T1-03	PDF p3, Table 1, row 3	Security response timeout — Configurable, 0-120 s / Mandatory range; legal zero semantics to verify in IEEE	PARTIAL	B06 / V-06
SEC-T1-04	PDF p3, Table 1, row 4	Aggressive receive — Yes, not recommended / Capability required; usage policy separate	IMPLEMENTED_UNVERIFIED	B07 / V-07
SEC-T1-05	PDF p3, Table 1, row 5	Aggressive issue — Yes, not recommended / Capability required; usage policy separate	IMPLEMENTED_UNVERIFIED	B07 / V-07
SEC-T1-06	PDF p3, Table 1, row 6	Challenge-response — Mandatory / Mandatory	PARTIAL	B06 / V-06
SEC-T1-07	PDF p3, Table 1, row 7	Session key change interval — Configurable, 15-120 min / Mandatory	PARTIAL	B06 / V-06
SEC-T1-08	PDF p3, Table 1, row 8	Session key change count — Configurable, default 1000 messages / Mandatory	IMPLEMENTED_UNVERIFIED	B06 / V-06
SEC-T1-09	PDF p3, Table 1, row 9	Requested MAC — Selectable SHA-256 (16/8 octets), AES-GMAC / Final required selection set not filled by checkboxes; track separately	BLOCKED	B10 / V-10
SEC-T1-10	PDF p3, Table 1, row 10	Session key wrapping — AES-256 mandatory; AES-128 not recommended / Mandatory AES-256	IMPLEMENTED_UNVERIFIED	B10 / V-10
SEC-T1-11	PDF p3-4, Table 1, row 11	TLS cipher suites — TLS 1.2 and TLS 1.3 lists / Conflicting TLS 1.3 naming; clarify before coding	BLOCKED	B12 / V-12
SEC-T1-12	PDF p4, Table 1, row 12	DNP TCP port using TLS — Fixed: 19999 / Mandatory when using TLS	IMPLEMENTED_UNVERIFIED	B12 / V-12
SEC-T1-13	PDF p4, Table 1, row 13	Cipher-change request timeout — Configurable, 1-60 s / Mandatory	MISSING	B13 / V-13
SEC-T1-14	PDF p4, Table 1, row 14	Supported CAs — At least 4 / Mandatory	PARTIAL	B12 / V-12
SEC-T1-15	PDF p4, Table 1, row 15	Certificate revocation check time — Configurable; numeric value blank / OPEN: no default/range supplied	BLOCKED	B13 / V-13
SEC-T1-16	PDF p4, Table 1, row 16	Remote update-key changes — Configurable, symmetric/asymmetric algorithm options / Must distinguish alternatives vs minimum mandatory options	BLOCKED	B09 / V-09
SEC-T1-17	PDF p4, Table 1, row 17	User-credential expiry — Yes / Mandatory	PARTIAL	B14 / V-14
SEC-T2-01	PDF p5, Table 2, row 1	Protocol authentication — Challenge-response; Aggressive Mode not recommended	PARTIAL	B06 / V-06
SEC-T2-02	PDF p5, Table 2, row 2	Protected communications — TLS 1.2 and TLS 1.3	IMPLEMENTED_UNVERIFIED	B12 / V-12
SEC-T2-03	PDF p5, Table 2, row 3	Session-key encryption and exchange — Key wrap	IMPLEMENTED_UNVERIFIED	B10 / V-10
SEC-T2-04	PDF p5, Table 2, row 4	Update-key protection — Symmetric and asymmetric approaches indicated; must agree on operative choice	BLOCKED	B09 / V-09
SEC-T2-05	PDF p5, Table 2, row 5	Session key length — 128-bit acceptable; 256-bit recommended	IMPLEMENTED_UNVERIFIED	B10 / V-10
SEC-T2-06	PDF p5, Table 2, row 6	Update key length — 128-bit acceptable; 256-bit recommended	IMPLEMENTED_UNVERIFIED	B10 / V-10
SEC-T2-07	PDF p5, Table 2, row 7	Local RTU configuration password — Mandatory	MISSING	B14 / V-14
SEC-T2-08	PDF p5, Table 2, row 8	Random generation for security keys — Mandatory	PARTIAL	B15 / V-15
SEC-T2-09	PDF p5, Table 2, row 9	Authentication enabled by default — Mandatory; disabling for protocol configuration accepted (as described)	PARTIAL	B14 / V-14
SEC-T2-10	PDF p5, Table 2, row 10	Minimum user roles — Administrator for security settings, ordinary user for technical settings; both may perform ordinary tasks	PARTIAL	B14 / V-14
SEC-T2-11	PDF p5, Table 2, row 11	Security parameter configurability — Mandatory for all protocol/configuration security parameters	PARTIAL	B01 / V-01
SEC-T3-01	PDF p6, Table 3, row 1	Close unused hardware ports — Mandatory	BLOCKED	B15 / V-15
SEC-T3-02	PDF p6, Table 3, row 2	Close unused network ports — Mandatory	BLOCKED	B15 / V-15
SEC-T3-03	PDF p6, Table 3, row 3	Disable unnecessary users — Mandatory	PARTIAL	B14 / V-14
SEC-T3-04	PDF p6, Table 3, row 4	Strong passwords for human users — Mandatory strong passwords (security PDF p6 Table 3 row 4)	PARTIAL	B14 / V-14
SEC-T3-05	PDF p6, Table 3, row 5	Do not hardcode credentials — Mandatory	PARTIAL	B14 / V-14
SEC-T3-06	PDF p6, Table 3, row 6	Hash stored credentials — Mandatory	PARTIAL	B14 / V-14
SEC-T3-07	PDF p6, Table 3, row 7	Secure firmware update with digital-signature verification — Recommended	BLOCKED	B15 / V-15
SEC-T3-08	PDF p6, Table 3, row 8	Check digital signature during firmware update — Recommended	BLOCKED	B15 / V-15


Additional runtime/configuration selections
ID and Profile PDF p (original page +40)	Selected behavior and required observation	Assessment	Package / validation
CFG-01, p1 / original 41	Level 3 Outstation and explicitly listed extensions. Identify vendor/device metadata left blank in the form without fabricating values.	BLOCKED	B01 / V-01
CFG-02, p2 / original 42	Link receive frame size must be 292 octets. Transmit size is blank. Document the product value and verify frame boundaries.	PARTIAL	B05 / V-05
CFG-03, p2 / original 42	Application receive fragment size must exceed 249 octets. Transmit size above 2048 must be configurable. Both size fields are blank. Verify configured bounds, segmentation, reassembly and resource limits.	BLOCKED	B05 / V-05
CFG-04, p2 / original 42	Link retries configurable 0–5. Application retries configurable 1–5, fixed retries disallowed. Test limits, exhaustion and reconnect while respecting IEEE function-specific retry prohibitions, including direct controls.	PARTIAL	B05 / V-05
CFG-05, p2 / original 42	Link confirmation configurable as Never, Always or On multi-frame fragments. Exercise each permitted policy.	PARTIAL	B05 / V-05
CFG-06, p2 / original 42	Application confirmation selected for event data and multi-fragment responses. Verify CONFIRM ownership, timeout, retry and event retention.	PARTIAL	B02 / V-02
CFG-07, pp2–3 / original 42–43	Configurable waits for link confirm, complete application fragment, application confirm and complete application response. Numeric ranges/defaults and explanatory attachment are absent. Resolve role applicability and test approved values and boundaries.	BLOCKED	B05 / V-05
CFG-08, p3 / original 43	SELECT/OPERATE, DIRECT OPERATE and DIRECT OPERATE NO ACK selected Always. Verify execution, denial and no-response semantics with selected G12/G41 wire forms and SA policy. Compatibility-only FC6 evidence does not close authenticated control acceptance.	PARTIAL	B03 / V-03
CFG-09, p3 / original 43	WRITE Binary Outputs, Count > 1, Pulse On/Off, Latch On/Off, Queue and Clear Queue selected Never. Trip/Close selected Always. Resolve the exact IEEE field/operation mapping and verify the production control policy and rejected forms. Preserve reusable library capabilities.	BLOCKED	B01 / V-01
CFG-10, p3 / original 43	Default binary change events are Only time-tagged. Absolute-time form and Configurable are both selected for default timed events. Verify actual default variation and obtain the missing configuration explanation.	BLOCKED	B01 / V-01
CFG-11, p4 / original 44	Unsolicited responses configurable and ENABLE/DISABLE UNSOLICITED supported. Verify enable/disable, startup, event delivery, confirmations and retry behavior. Configuration explanation is absent.	PARTIAL	B02 / V-02
CFG-12, p4 / original 44	Static unsolicited data selected When Device Restarts, with other options unselected. Resolve the exact IEEE-compatible startup sequence and static-data delivery requirement. Test real restart integration separately from a startup null unsolicited response.	BLOCKED	B02 / V-02
CFG-13, p4 / original 44	No Counters Reported selected for both counter defaults and rollover. Production configuration must report no physical counter points. General Level 4 G20–G23 implementation is outside this target.	PARTIAL	B01 / V-01
CFG-14, p4 / original 44	Multi-fragment responses selected Yes. Test selected data families across fragments, sequence progression, confirmations and malformed/incomplete transfers.	PARTIAL	B02 / V-02


RTU assessment totals across 119 entries — BLOCKED 16, IMPLEMENTED_UNVERIFIED 37, MISSING 4, PARTIAL 62. None is fully VERIFIED or NOT_APPLICABLE in this conservative audit.
3. Current implementation gap analysis
Confirmed behavior and missing boundaries
- S/outstation/Database.cpp selects configured static G1/G3/G10/G30/G40 variations and ranges. S/outstation/event/EventBuffer.cpp selects event types, variations and count/class limits. S/master/MeasurementHandler.cpp delivers typed measurements and CTO-relative times. These operational paths exist. Exhaustive selected qualifier/malformed/fragment cross-products remain unestablished by current execution evidence.
- S/app/parsing/APDUParser.cpp gates G50V1/G50V3 and G51/G52 to qualifier 07, G120V3/V4 to count objects and other G120 objects to free format. S/app/parsing/CountParser.cpp validates one time/CTO/delay value. Existing tests reject malformed time counts and indexes. Do not rewrite these correct gates.
- S/outstation/WriteHandler.cpp clears DEVICE_RESTART at index 7 when zero is written. NEED_TIME clear is an existing extension delegated to the application. S/outstation/Database.cpp::SelectIIN supports both read widths. The extension is preserved, while selected index-7 behavior is tested separately.
- S/outstation/DeviceAttributeSelection.cpp advertises only 210,211,212,213,214,215,230 and discovery. It rejects 209 with OBJECT_UNKNOWN. Existing G209 codec/Master tests prove decoding, not Outstation SA version support.
- S/master/MasterContext.cpp::DirectOperateNoAck returns false in REQUIRED mode. S/master/CommandTask.cpp uses SingleExecutionNoRetry and the shared typed writer for Compatibility FC6. Per-point status remains UNDEFINED after local transmission. U/TestProfileControls.cpp covers both widths, sequence wrap, subsequent SBO, timeout and disconnect. Those assertions must survive authenticated support.
- S/auth/SessionKeys.cpp::ValidConfig accepts replyTimeoutMs from 100 to 120000 in 100ms units, excluding the selected zero. It allows disabled or 1-second-to-120-minute renewal intervals, wider than the selected 15–120 minutes. A product configuration boundary is needed without narrowing the reusable core arbitrarily.
- S/auth/AuthenticationMAC.h recognizes algorithms 2–5 and applies transport-specific policy. There is no GMAC path in this policy. AES-128/AES-256 wrapping already uses shared crypto providers. Do not implement unselected GMAC until its policy and required IEEE IV/sequence behavior are resolved.
- S/auth/RemoteUpdateKeys.cpp::MethodAllowed permits 4 or explicitly enabled 68. Its existing certification, candidate, transaction and durable install machinery must be reused. More methods are product-gated. S/app/parsing/FreeFormatParser.cpp only validates G120V8 certificate nonemptiness before codec dispatch. Neither RemoteUpdateKeys nor UpdateKeyTask supplies the selected V8 runtime certificate transaction.
- S/auth/AuthenticationStatistics.cpp::Persist now latches continuous=false after save failure. Later saves do not restore it. CaptureStaticSnapshot and Publish use this latch. Increment still calls Publish before Persist, so a failure on that increment cannot affect its already-published event. Durable production storage and acquisition-quality/rearming policy remain open.
- S/outstation/SecurityStatEventPublisher.cpp restricts classes to 1–3, captures occurrence time, falls back to V1 for untimed class/default events and preserves the historical snapshot. Explicit V2 cannot manufacture a missing timestamp. Resolve handling of an untimed backlog against Table 11-19 and peer behavior without silently changing requested variation.
- S/channel/tls/SSLContext.cpp enforces peer certificates, chain verification and optional exact DNS/IP SAN matching. It loads a trust file and uses separate TLS 1.2 and TLS 1.3 suite APIs. No revocation scheduler or cipher-change request transaction exists in that context. A file containing four roots is not proof of four-CA rotation/revocation lifecycle.
- A/auth/AuthenticationConfig.h separates credential retrieval from authorization and defaults to REQUIRED. S/auth/WindowsAuthenticationCredentials.cpp supplies Windows persistence/expiry interfaces. CLI test profiles and same-account authority processes do not establish RTU configuration passwords, password hashing, production authority isolation or target entropy.
Source-test evidence boundaries
U/TestProfileMeasurements.cpp tests typed measurement/CTO and malformed header behavior. U/TestProfileClasses.cpp checks class-0 qualifier rejection, class enable/disable and dangling assignments. U/TestProfileTime.cpp checks G50 reads/writes, G80 clearing, delay parsing and LAN time ownership. U/TestSecurityStatRead.cpp explicitly includes save-failure discontinuity and all read index encodings. U/TestSecurityStatEvents.cpp supplies event/CONFIRM tests. U/TestProductionAuthentication.cpp, U/TestAuthenticationDirections.cpp and U/TestRemoteUpdateKeys.cpp exercise reusable security state machines. Assertion presence alone receives no VERIFIED credit.

I/TestEventIntegration.cpp contains real local TCP measurements/attributes/G80 exchanges. I/TestSecureAuthentication.cpp contains local SA exchanges. cli/tests/ProcessSmoke.py uses two project executables. None is an independent DNP3 peer or a physical RTU. Historical exact revisions remain in ENGINEERING_EVIDENCE.md. Each package must identify which old cases it reuses and which selected subcases require additions.
4. Detailed engineering design grouped by existing components
Shared constraints
All new protocol state belongs to the existing association/user/task that owns it. Validate the entire APDU structure before mutating application state. Preserve buffers until lower-layer TX completion, retain confirmed events until the owning CONFIRM, bound collections to configured capacities and clear keys/candidates on abort. Match peers by actual association/source and exchange state, never by an invented transaction identifier.

Use existing APDU parser/writer, RequestHistory, CommandSetOps, database and event queue. Do not introduce another serializer, generic task scheduler or security engine. Extend public configuration additively with compatible defaults. Production Profile policy belongs at provisioning/application boundaries, preserving other users of the reusable stack. Existing optional extensions keep regression coverage.
B01 — Selected product configuration policy
Modify A/outstation/OutstationParams.h only for missing reusable controls, A/auth/AuthenticationConfig.h only for missing security options, and cli/Security.h/.cpp plus apps/outstation/main.cpp for selected product configuration. Reuse IOutstationApplication and ICommandHandler. Establish a bounded immutable validated configuration snapshot before enabling the stack. Reject incomplete/contradictory settings with an explicit diagnostic, not a permissive default.

Represent approved retry limits, timer ranges, default event variations and allowed control codes in that snapshot. Do not equate maxControlsPerRequest to the Profile's Count > 1 without deciding whether that checkbox addresses CROB repetition count. Resolve the prohibition on Pulse/Latch with selected Trip/Close using A.8 control-code semantics. Keep hardware policy in the command adapter. Disable physical counters in the product database only. Proposed test additions belong in U/TestAuthenticationConfig.cpp and U/TestProfileControls.cpp. No generic new policy framework is justified.
B02 — Selected measurement, event, class and fragment audit
Reuse S/outstation/Database.cpp, StaticDataMap.h, StaticWriters.cpp, ReadHandler.cpp, AssignClassHandler.cpp, S/outstation/event/EventBuffer.cpp, EventSelection.cpp and EventWriting.cpp. Master reuses MeasurementHandler.cpp. Fix only cases failing the selected form assertions. Use count/range/index parsing already in S/app/parsing. G2V3/G4V3 offsets require a preceding G51 CTO within its defined scope, with synchronized/unsynchronized quality propagated. Split CTO/relative batches when the 16-bit offset cannot represent occurrence time.

For selected G60 READ allow 06 and event-class 07/08 only. FC20/21/22 require 06 class headers. ASSIGN_CLASS must validate complete class/target pairs, supported group, range and sparse holes, without invoking application callbacks for rejected pairs. Inspect the existing dangling-pair test before modifying IsExpectingAssignment. Queued events retain class/variation semantics at their defined snapshot boundary.

Fragment through the existing ResponseContext and bounded writers. A retry must preserve selected bytes/events, and only matching sequence/UNS confirmation releases ownership. CFG-12 requires a product resolution of static-at-restart semantics. Do not treat a null startup unsolicited response as proof of that requirement. Keep this gate independent from ordinary event/fragment fixes.
B03 — Authenticated FC6 vertical slice
IEEE 4.4.5 prohibits Master direct-control retries. Section 7.5.2.3.2(i), printed p208 / PDF p250, requires the Master either to wait for a challenge before proceeding or to issue no-ack operations only in Aggressive Mode. FC6 is mandatory critical in Table 7-7, printed p210 / PDF p252. The Outstation's selected FC6 must authenticate and authorize before executing, and produce no solicited application command response.

Extend S/master/MasterContext.cpp and S/master/MasterContext.h and CommandTask.cpp/.h, A/master/ICommandProcessor.h documentation, and the existing Outstation authentication dispatch in S/outstation/OutstationContext.cpp. Keep typed construction and callbacks. Add an association-owned no-ack security phase or extend the current task state with an explicit phase discriminator. Normal mode must retain the original critical ASDU, observe the normative challenge window, correlate the challenge, and complete local submission only after the owned Reply transmission releases its buffer. Resolve the exact wait-window timer against IEEE 7.5.2.3.2 and 7.6 before coding.

Aggressive mode requires ready keys and a valid retained challenge. Complete after the actual protected TX. No key, no valid challenge, invalid MAC, expired credential or authorization denial permits execution. No fallback to Compatibility mode. Success means local submission/authentication progress, never confirmed remote operation. Preserve UNDEFINED point status. Keep independent protected CONFIRMs and monitoring exchanges isolated from the command task. Ignore an ordinary unsolicited/solicited response as proof of FC6 completion. On disconnect/timeout abort only the owning task, clear retained candidate bytes safely and never automatically resend the control.
B04 — Selected clock, IIN and no-object operations
Reuse S/outstation/ReadHandler.cpp, WriteHandler.cpp, OutstationContext.cpp, S/master/MeasurementHandler.cpp, TimeSyncHandler.h, RestartOperationTask.cpp and the IOutstationApplication hooks. G50V1 request/response uses 07/count1 and six little-endian timestamp octets. G51 CTO uses 07/count1. G52V1/V2 uses 07/count1 and UInt16 delay, with coarse/fine units from A.25. FC23 must use fine delay semantics. G80 uses packed bits, absolute bit index and 00/01 reads, with selected WRITE 00 index7 zero only.

FC0 has no object body, must match active confirmation ownership and cannot free unrelated events. FC13 invokes the existing cold restart callback and reports its real supported delay/status. Do not simulate a hardware restart as accepted evidence. Keep a production restart adapter target-side. Validate malformed mixed time writes before callbacks and preserve existing compatible NEED_TIME and LAN-time extensions.
B05 — Link, transport, retry and timeout configuration
Inspect/extend A/link/LinkConfig.h, S/link/LinkContext.cpp and S/link/LinkContext.h, PriLinkLayerStates.cpp, S/transport/TransportRx.cpp and S/transport/TransportRx.h and A/outstation/OutstationParams.h where the selected controls are missing. Native LinkConfig currently exposes timeout/keepalive; OutstationParams exposes fragment sizes, confirmation timeouts and numUnsolRetries (default infinite). That default does not establish configurable 1–5 product retry behavior.

Separate link retransmission, unsolicited retries and prohibited application request retries. Never use a single counter for all three. Count attempted retransmissions with a bounded counter reset only on defined success/new transaction. Resolve a configurable complete-fragment assembly deadline and whether complete-response timeout is an applicable RTU field or a peer test parameter. Use the existing executor timer, cancel on disconnect and discard incomplete reassembly on expiry. Respect the 292-octet link receive limit and fragmentation buffers without allocating from untrusted lengths.
B06 — SA timing, session renewal and user bounds
Modify S/auth/SessionKeys.cpp and S/auth/SessionKeys.h, AuthenticationSession.cpp and existing config tests, preserving current per-user keys and shared policy. IEEE 7.5.2–7.5.5 state tables and 7.6 security parameters govern the transitions. Resolve SEC-T1-03 zero against normative timer semantics first. Merely accepting zero in ValidConfig risks immediate retry loops. A zero policy must define deadline behavior, retries and scheduler work bounds, and fail closed when its required response cannot arrive.

Enforce selected 15–120-minute renewal limits at the product boundary, preserve message-limit default 1000, and ensure renewal triggers on either elapsed lifetime or consumed count. A transaction owns its KSQ, expected user, candidate keys and original deadline. Invalid user/status replies must not reset foreign ownership or extend the deadline. Exhaustion must not spin or reuse expired keys. Verify at least two independent users and configured capacity limits. Keep error suppression/rate limits and key erasure on every terminal exit.
B07 — Challenge/Reply and Aggressive coexistence
Reuse S/auth/AggressiveMode.cpp and S/auth/AggressiveMode.h, S/master/MasterResponder.cpp, S/outstation/OutstationChallenger.cpp and native Context routing. IEEE 7.5.2.3, Tables 7-8 and 7-13, and A.45.1–3/7/9 govern these exchanges. V3 and V9 protect the exact enclosed ASDU bytes with the correct direction/user/key. G120V7 errors use their own sequence/suppression rules, not ordinary event replay handling.

Test optional critical requests and collision of protected CONFIRM, next command and monitoring response. Keep separate replay histories and TX owners. Provisional Code5=MAC Algorithm Not Supported and Code7=Authorization Failed follows A.45.7.2.2. P4-OPEN-01 remains open against 7.5.5.7. Resolve by authoritative correction or independent-peer evidence, not by relabeling all errors.
B08 — Runtime G120V8 certificates
A.45.8, printed pp736–740 / PDF pp778–782, requires FC32, qualifier5B, sole object in the request. The fields are key-change method, certificate type (1 ID, 2 attribute), and unmodified IEC/TS 62351-8 X.509v3 certificate bytes. It is an asymmetric alternative to V10, not a TLS peer certificate exchange. Accept only approved asymmetric methods. Attribute certificates require an already trusted ID certificate.

Reuse generated Group120Var8, FreeFormatParser and RemoteUpdateKeys' user lifecycle. Add S/auth/UserCertificate.h and S/auth/UserCertificate.cpp only because no existing component decodes and validates the required certificate extensions. It returns a bounded normalized user-status record, not an independent user store. Add an IUpdateKeyTrust-compatible certificate validation method with a fail-closed default for source compatibility. Reuse OpenSSL parsing/verification through the crypto boundary. Register only these new implementation files in the existing library CMake list when implemented.

Validate chain, signature, certificate type, allowed method, subject/key identity, roleDefinition, roles, area of responsibility, operation and monotonic revision/SCS. Table A-8 maps certificate fields to DNP3 user status. Validate expiry using the table's secure-time versus interval behavior and re-evaluate when secure time becomes available. Preserve authority signature bytes and reject trailing ASN.1 data, oversized DER, unknown required extensions and mismatched AOR. Do not interpret a certificate as granting permissions before all checks succeed.

Route accepted normalized records into S/auth/RemoteUpdateKeys.cpp with the existing durable journal and role-update atomicity. Extend S/master/UpdateKeyTask.cpp and A/auth/UpdateKeyConfig.h with an additive immutable certificate request alternative. The Master forwards authority-issued bytes without editing them. Abort does not partially install a user. Preserve existing V10 support. External IEC/TS 62351-8/RFC 5280 editions, supported OIDs, AOR and authority policy must be supplied before claiming interoperable certificate support. Proposed U/TestUserCertificate.cpp is justified by this new decoder/trust boundary.
B09 — Remote Update Key completion and policy
Reuse S/auth/RemoteUpdateKeys.cpp and S/auth/RemoteUpdateKeys.h, UpdateKeyFunctions.cpp, S/master/UpdateKeyTask.cpp and A/auth/UpdateKeyConfig.h. IEEE 7.5.4.5–7, 7.5.5 and 7.6/Table 7-16 with A.45.10–15 govern user status, method and proof. Current methods 4/68 remain the supported subset unless the requirement owner selects more. Unselected methods need no speculative code.

Retain serialized status/SCS ownership, separate Common/user identities, candidate old/new keys and restart-safe pending install. Require the correct final proof before durable activation. Retransmit only protocol-permitted handshake stages, never duplicate a user-change side effect or count a retry as another successful change. Preserve RUK-OPEN-01 sequence-wrap semantics and RUK-OPEN-02 Method68 DSA wire representation as explicit gates. Match integer ranges and signed/unsigned wrap to IEEE before changing comparisons.
B10 — MAC and wrapping policy
Reuse S/auth/AuthenticationMAC.h and S/crypto/CryptoProvider.h, OpenSSLCryptoProvider.cpp. IEEE 7.6 and MAC/key-wrap parameter tables govern identifiers, truncation and permitted transports. Keep authentication algorithm choice separate from authorization and credential storage.

Current HMAC and AES wrapping implementations remain. Validate algorithm/key/tag length tuples and reject unexpected negotiation or downgrade. Clear output on crypto failure. Add GMAC only if approved, with the exact IEEE nonce/IV derivation, key reuse limits and replay ownership established before implementation. A generic AES-GCM helper with an arbitrary nonce is insufficient. Do not map a MAC rejection to authorization failure. Product AES-256 wrapping policy must not silently accept AES-128 as fallback.
B11 — Statistics durability, quality and event timing
Modify S/auth/AuthenticationStatistics.cpp and S/auth/AuthenticationStatistics.h, S/outstation/SecurityStatEventPublisher.cpp and native security-stat selectors only as necessary. IEEE 7.5.2.2, Table7-6, 11.9.10/Table11-19, A.46–47 govern counts, association, flags, retention and events. G121 contains flags/UInt16 association/UInt32 count. G122V2 adds six-byte occurrence time. Preserve index association semantics and UInt32 modulo rollover, and never clear/freeze totals.

Reuse IAuthenticationStatisticsStore and reporter contracts. Capture occurrence time and count before slow storage. Then perform retention and assemble the final quality for that same event before enqueueing it. A small local immutable occurrence snapshot or additive reporter argument is justified, rather than a second event queue. Save failure must latch discontinuity, including the event caused by that increment. A later successful Save cannot prove continuity was restored. Recovery requires a defined acquisition/rebaseline policy, not an automatic flag clear.

Supply production storage in B15, with association/role isolation, atomic records and power-loss handling. Preserve load-failure protection against overwriting unread totals. Event threshold acknowledgment occurs only after buffer acceptance. On a full buffer leave the report condition pending. Disconnected/link retries never reset durable totals. G122 class0/none is forbidden. Explicit V2 on an untimed snapshot requires a documented normative resolution and an independent-peer test, not a fabricated timestamp.
B12 — TLS trust, identity and CA capacity
Reuse S/channel/tls/SSLContext.cpp, TLSClient.cpp, TLSServer.cpp, A/channel/TLSConfig.h and cli/Security.cpp. Security Table1 rows11/12/14 and Table2 row2 select TLS1.2/1.3, port19999 and at least four CAs. IEEE Clause13 establishes network role behavior but does not resolve the addendum's invalid TLS1.3 suite names.

Validate configured suites via separate TLS1.2/1.3 APIs and reject empty/invalid effective policy. Treat chain, trust, validity and expected SAN as independent checks. Test four roots and replacement/removal of a root, not just a PEM parse. Keep actual listener ownership and reconnect behavior. No platform-specific verification may bypass shared identity policy.
B13 — Revocation and cipher-change lifecycle
The addendum selects configurable cipher-change request timeout1–60s and revocation check time without a value. Define the product operation/initiator and rotation semantics first. TLS1.3 does not supply arbitrary renegotiation. Model an application request with bounded state and executor deadline only after the owner chooses reconnect/rotation behavior.

Extend TLSConfig/SSLContext and the existing channel owner, with a trust/revocation provider if required by the approved mechanism. A revocation cache entry needs issuer identity, freshness and trusted clock, plus explicit unavailable/stale policy. Existing sockets must follow the chosen expiry/revocation policy. No background service or new channel class is justified. Design atomic trust replacement so failed reload retains a known valid context and cannot admit an unverified peer.
B14 — Credentials, roles and configuration security
Reuse A/auth/AuthenticationConfig.h interfaces, S/auth/WindowsAuthenticationCredentials.cpp, S/auth/RemoteUpdateKeys.cpp and cli/Security.cpp. Separate DNP3 Update Keys, TLS private keys and human passwords. Windows Credential Manager protection is not evidence of human-password hashing or RTU NVM security.

Provide authenticated product configuration entry points with a password-verifier backend, approved strength rules and access policy. Store salted password hashes using an approved target-appropriate scheme, never reversible passwords or hardcoded keys. Missing inputs fail closed. Keep cryptographic key material in protected key storage instead of trying to hash keys needed for MAC operations.

SEC-T3-04 is strong human passwords in the PDF, not the archived least-privilege summary. Reassess that row. SEC-T2-10 requires an administrator able to manage security and ordinary tasks, and an ordinary technical user restricted from security changes. Do not assume IEEE SECADM automatically supplies that combined role. Use explicit authorization and tested private-role mappings when necessary. Expiry/revocation/deletion must invalidate affected pending work without resetting another user's exchange. Test default REQUIRED and audited explicit maintenance disable/enable.
B15 — Target adapters and physical RTU evidence
Production destinations are the application implementations of existing clock, command, entropy, credential/statistics-store and channel/executor seams. Use S/DNP3ManagerImpl.cpp and S/channel/IAsyncChannel.h to identify the runtime boundary. No existing STM32H743/FreeRTOS board implementation is established in this checkout. Choose board, storage and I/O integration paths with the target project before creating files.

Proposed target files must remain outside shared protocol classes. Implement monotonic timers, bounded scheduling, secure time, hardware RNG health/failure behavior, atomic protected NVM, interlocks and real restart. Disable unused physical/network ports and accounts in the deployed image. Firmware signature checks are recommended rows with an explicit product disposition, not automatically mandatory. Windows tests cannot establish entropy, flash power-loss behavior, physical controls or port closure.
B16 — Truthful version reporting and acceptance closure
After selected SA procedures, certificate behavior and validation gates pass, extend S/outstation/DeviceAttributeSelection.cpp to include G0V209 set0 using the existing UINTn attribute writer. Reuse A/app/DeviceAttribute.h and S/master/MeasurementHandler.cpp. Report version5 only when the supported product configuration actually implements the required version. Preserve V210 actual statistic count and V254/255 discovery. Never report zero as a fictitious version.

Reconcile all 119 entries against execution revisions, product decisions and target dispositions. Preserve unverified/blocked categories for unresolved behavior. Do not close aggregate SA v5 because a session-key exchange passes.
Generator and API synchronization
Scala models live under opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/groups/. Reuse Group0.scala, Group12.scala, Group41.scala, Group50.scala, Group51.scala, Group52.scala, Group60.scala, Group80.scala and Group120/121/122.scala as relevant. ObjectGroup.scala registers families. The selected codecs largely exist, including V8, so certificate runtime support does not justify changing its wire format.

If a real wire-model change is necessary, update the Scala model and regenerate S/gen/objects/ and A/gen/ plus affected Java/.NET enum outputs. Use the pinned Maven/Scala workflow. Do not hand-edit generated C++ as the source of truth. New config fields need compatible defaults and fail-closed behavior. New certificate interfaces need a default rejection implementation so old credential providers remain source-compatible.
5. Ordered implementation packages
Each package's exact requirement IDs are the matrix rows bearing that package ID. Requirements cross-cutting a later package also remain governed by the component sections above. Complete one package's acceptance before promoting any associated row. A package that contains multiple failing wire forms should be executed as one focused family/variation task at a time, without broad refactoring.
Order/ID	Work unit	Dependencies	Complexity	Exit and required platform
1 B01	Validated selected product configuration	Product decisions for blank/control fields	MEDIUM	Explicit settings, rejected contradictions, Windows policy tests and target configuration review
2 B02	Selected measurements/classes/events/fragment audit	B01 for default/static-restart policy	MEDIUM	Every selected wire form and ownership assertion in V-02, Windows plus independent peer
3 B04	Time/IIN/restart no-object closure	B01 and target restart for hardware exit	MEDIUM	V-04 wire tests, actual target restart separately
4 B05	Retry/timeout/fragment configuration	B01 timeout applicability	MEDIUM	Bounded retries/timers, V-05 boundary tests, Windows and target timer evidence
5 B06	SA timer/renewal/user limits	Zero-timeout normative decision	MEDIUM	Existing C/R transitions preserved, V-06 deadlines and per-user isolation
6 B07	C/R/Aggressive ownership regression closure	B06, Code5/7 interpretation gate	HIGH	V-07 collision/replay tests, independent SA peer for ambiguity
7 B03	Authenticated FC6	B06/B07, normative wait-window decision	HIGH	V-03 no-response/security phases, independent peer, physical command adapter later
8 B10	Approved MAC/key-wrap policy	Approved MAC set, GMAC details if selected	MEDIUM	Exact vectors and no downgrade, independent peer
9 B08	Certificate validator then lifecycle integration	Certificate schemas/OIDs/AOR and B09 journal contract	HIGH	V-08 DER/trust tests before runtime routing, then authenticated user mutation and external peer
10 B09	Approved remote-key methods and lifecycle	Method policy, B10, reusable journal before B08 integration	HIGH	V-09 transaction/recovery tests, wrap/signature ambiguities resolved
11 B11	Statistics same-event quality and retention	B06 accounting; target backend in B15	MEDIUM	V-11 Windows ordering/ownership; target power-loss persistence
12 B12	TLS trust/identity/CA capacity	Approved suite policy	MEDIUM	V-12 both roles/versions and four-CA lifecycle
13 B13	Revocation/cipher-change lifecycle	B12, revocation/rotation product policy	HIGH	V-13 freshness/timeout/atomic replacement, external endpoint
14 B14	Configuration credentials and roles	B01/B09, password/provisioning policy	HIGH	V-14 human security and per-user expiry, Windows backend then target
15 B15	Physical adapters and hardening	Board/runtime/storage decisions	HIGH	V-15 physical test records and deployed image review
16 B16	G0V209 and acceptance reconciliation	B03/B06–B15 applicable exits	LOW	Truthful advertisement and requirement-by-requirement evidence, external SA peer


B08 and B09 have no execution cycle. Reuse/audit the existing B09 journal contract first, implement certificate decoding independently, then integrate certified records after the method-policy gate. Independent measurement/time/statistics/TLS work proceeds while certificate/product decisions remain blocked. HIGH packages require separately reviewable validator/state-machine/test commits within the same package. A one-task implementer must stop at the specified sub-boundary rather than invent missing policy.
Exact package membership
- B01 — SEC-T2-11, CFG-01, CFG-09, CFG-10, CFG-13
- B02 — PROFILE-003, PROFILE-004, PROFILE-005, PROFILE-006, PROFILE-007, PROFILE-008, PROFILE-009, PROFILE-010, PROFILE-011, PROFILE-012, PROFILE-013, PROFILE-014, PROFILE-015, PROFILE-016, PROFILE-017, PROFILE-018, PROFILE-020, PROFILE-021, PROFILE-022, PROFILE-023, PROFILE-024, PROFILE-025, PROFILE-026, PROFILE-027, PROFILE-028, PROFILE-029, PROFILE-030, PROFILE-031, PROFILE-032, PROFILE-033, PROFILE-034, PROFILE-043, PROFILE-044, PROFILE-045, PROFILE-046, CFG-06, CFG-11, CFG-12, CFG-14
- B03 — PROFILE-019, PROFILE-035, PROFILE-036, PROFILE-037, CFG-08
- B04 — PROFILE-038, PROFILE-039, PROFILE-040, PROFILE-041, PROFILE-042, PROFILE-047, PROFILE-067, PROFILE-068, PROFILE-069
- B05 — CFG-02, CFG-03, CFG-04, CFG-05, CFG-07
- B06 — PROFILE-048, PROFILE-049, PROFILE-051, PROFILE-052, PROFILE-053, PROFILE-054, SEC-T1-02, SEC-T1-03, SEC-T1-06, SEC-T1-07, SEC-T1-08, SEC-T2-01
- B07 — PROFILE-050, PROFILE-056, SEC-T1-04, SEC-T1-05
- B08 — PROFILE-055
- B09 — PROFILE-057, PROFILE-058, PROFILE-059, PROFILE-060, PROFILE-061, PROFILE-062, SEC-T1-16, SEC-T2-04
- B10 — SEC-T1-09, SEC-T1-10, SEC-T2-03, SEC-T2-05, SEC-T2-06
- B11 — PROFILE-002, PROFILE-063, PROFILE-064, PROFILE-065, PROFILE-066
- B12 — SEC-T1-11, SEC-T1-12, SEC-T1-14, SEC-T2-02
- B13 — SEC-T1-13, SEC-T1-15
- B14 — SEC-T1-17, SEC-T2-07, SEC-T2-09, SEC-T2-10, SEC-T3-03, SEC-T3-04, SEC-T3-05, SEC-T3-06
- B15 — SEC-T2-08, SEC-T3-01, SEC-T3-02, SEC-T3-07, SEC-T3-08
- B16 — PROFILE-001, SEC-T1-01
6. Test and validation matrix
All tests below are specifications, NOT RUN by this audit. Existing filters are identified where known. New V-xx tags are proposed additions, not currently callable tests. Unit or same-project results do not replace independent-peer or physical evidence.
Validation	Permanent destination and invocation scope	Concrete positive, negative, boundary and lifecycle oracle
V-01	U/TestAuthenticationConfig.cpp; U/TestProfileControls.cpp; proposed [pdf-config]	Accept selected values, reject missing/out-of-range settings before stack enable. No counters in product Class0. Pulse/Latch/Queue/Count policy rejection invokes no physical command. Trip/Close permitted only after authorization.
V-02	U/TestProfileMeasurements.cpp [profile-measurements], U/TestProfileClasses.cpp [profile-classes], U/TestOutstationEventResponses.cpp; I/TestEventIntegration.cpp	For every assigned Profile row generate each listed request Q and parse each listed response Q with exact type/index/value/flags. Exercise narrow/wide indexes, sparse/empty/range overflow, quantity0/1/max and resource rejection. V0 returns the configured legal variation. G2/G4 relative time with both CTO qualities, absent/malformed/overflow CTO and fragment boundaries. Reject malformed mixed headers before callbacks. Wrong/stale CONFIRM retains events, correct CONFIRM releases exactly once. Lost confirmation/retry preserves bytes. Class changes, enable/disable and reconnect preserve intended ownership.
V-03	U/TestProfileControls.cpp [fc6-master] and [profile-controls], U/TestProductionAuthentication.cpp; I/TestSecureAuthentication.cpp; cli/tests/ProcessSmoke.py pc-compat plus proposed pc-auth-fc6	All G12V1/G41V1–3 Q17/Q28. SELECT never operates, exact OPERATE echo required, altered payload/status/sequence denies. Normal FC6 waits for a correlated challenge and owned Reply TX, Aggressive FC6 requires valid retained challenge/key. Test reply before original TX-ready, competing CONFIRM, missing/wrong/late challenge, timeout and disconnect at each phase, sequence15→0, key expiry and denied role. Exactly one accepted Outstation invocation, zero command application responses, no application retry, callback never fabricates remote success. Wrong MAC/replay/expired credentials invoke zero commands.
V-04	U/TestProfileTime.cpp [profile-time], [level4-iin], U/TestMeasurementHandler.cpp, U/TestOutstation.cpp; I/TestEventIntegration.cpp	G50V1 READ/WRITE Q07/count1 exact six-byte time. Counts0/2 and Q08/indexed/mixed truncation rejected without callbacks. G51 CTO quality/one-value rule. FC23 G52V2 fine delay and FC13 actual coarse/fine delay with correct units. G80 00/01 read indexes and packed bits, WRITE00/index7/zero clears restart only. Set-bit, wrong index/range and truncated body fail. FC0 wrong seq/UNS has no release. Verify real target restart separately.
V-05	U/TestLinkLayer.cpp, U/TestTransportLayer.cpp and U/utils/TransportTestObject.cpp	Retry0/1/5 and invalid6, all confirmation modes and multi-frame boundary. Link receive292 and oversize rejection, selected fragment capacity and just-over-limit, split transport segments, duplicate/missing/out-of-order fragment, timeout at deadline−1/deadline/deadline+1. Disconnect cancels timers and stale callbacks cannot affect a new session. No request retry for direct controls.
V-06	U/TestSessionKeys.cpp, U/TestAuthenticationConfig.cpp, U/TestProductionAuthentication.cpp; I/TestSecureAuthentication.cpp	Approved zero semantics plus 100/120000/120001ms and granularity. Renewal15/120min bounds and default1000 count, count rollover/expiry. Simultaneous two-user exchanges and capacity exhaustion. Foreign USR/KSQ, stale V5/V6, mismatched nonce/MAC and expired keys leave correct owner/deadline unchanged. Terminal failure clears candidates and performs bounded recovery.
V-07	U/TestAuthenticationDirections.cpp, U/TestAuthenticationRuntime.cpp, U/TestProductionAuthentication.cpp; I/TestSecureAuthentication.cpp	Both C/R directions and Aggressive send/receive. Exact ASDU MAC, altered header/payload, replay and stale challenge rejected. Independent confirm/command/monitoring buffers survive collisions. Code5 versus7 emits the provisional correct error and increments correct statistics. Suppressed/error-limit cases transmit no extra error.
V-08	Proposed U/TestUserCertificate.cpp; extend U/TestRemoteUpdateKeys.cpp and I/TestSecureAuthentication.cpp	Exact G120V8 FC32/Q5B sole-object envelope. Valid ID then attribute certificate, certified add/change/delete. Reject symmetric methods, type0/reserved, extra objects, malformed/oversized DER, trailing bytes, untrusted/expired/revoked chain, wrong AOR/OID/subject/key, stale revision and absent ID certificate. Trusted-time acquisition reevaluates expiry. Storage failure leaves old active user, no half-install, external authority bytes unchanged.
V-09	U/TestRemoteUpdateKeys.cpp; I/TestSecureAuthentication.cpp; pc-method4 and pc-method68	Selected method success and unsupported rejection, SCS/KSQ bounds, same/lower revision, user/name mismatch, tampered certification, wrong signature representation, delayed/duplicate V12/V15. Disconnect/restart/power-loss before/after durable activation, pending-key recovery, exact-once counts and per-user isolation. Existing handshake retries never repeat a control or user side effect.
V-10	U/TestCryptoProvider.cpp, U/TestAuthenticationConfig.cpp; proposed [pdf-mac-policy]	Approved MAC algorithm/tag/key tuples and official known-answer vectors for selected HMAC/wrap. Truncated/tampered unwrap fails with zeroized output. Reject transport-invalid algorithms and downgrade. GMAC, if selected, requires nonce uniqueness/replay vectors and independent peer before acceptance.
V-11	U/TestAuthenticationStatistics.cpp, U/TestSecurityStatRead.cpp [security-stat-read], U/TestSecurityStatEvents.cpp, U/TestMasterSecurityStatistics.cpp	All G121 00/01/06/17/28 request selections and 00/01/17/28 response forms. G122V0 range/index/all selectors and V1/V2 count/all event queries. Association and index separation. Rollover, load/save failure and throwing/slow store, same-event discontinuity, later-save sticky quality. Event buffer full leaves report pending, accepted event alone acknowledges threshold. Wrong CONFIRM/duplicate retries do not reset totals. Untimed V2 backlog follows approved interpretation. Target cold restart preserves totals.
V-12	cli/tests/ProcessSmoke.py pc-tls; U/TestAuthenticationConfig.cpp where shared config applies	Both client/server and TLS1.2/1.3. Port19999, each of four independent CAs, root removal, exact DNS/IP SAN, untrusted/expired/wrong peer. Invalid/empty suites fail configuration. Reconnect rechecks peer and listener ownership releases port. External TLS/DNP3 endpoint confirms policy interoperability.
V-13	Extend pc-tls plus proposed [tls-lifecycle] in existing ASIO TLS fixture	Cipher-change deadline1/60s and outside range rejection, pending request timeout and disconnect, failed reload rollback. CRL/OCSP as approved, revoked/good/unknown/stale/unavailable responses and trusted-time jumps. Revocation cannot admit a new peer through an old cached verdict. No uncontrolled renegotiation or lingering timers.
V-14	U/TestRemoteUpdateKeys.cpp, U/TestAuthenticationConfig.cpp; cli/tests/ProcessSmoke.py	Admin can ordinary+security operations, technical user cannot security operations, unauthorized/expired/deleted accounts cannot execute. REQUIRED by default, explicit maintenance disable audit and secure re-enable. Password verifier stores no plaintext, rejects weak/incorrect passwords and corrupted verifier state, unique salt and approved policy. Check reports/source for hardcoded credentials and secret logging.
V-15	Existing protocol fixtures plus target project's permanent hardware tests	Fault-injected RNG, NVM torn writes and power cycles, reboot counter continuity, clock drift/time-loss, stack/heap bounds and worst-case execution. Probe physical/network ports, disabled accounts and actual I/O interlocks/restart. If firmware signature recommendations are adopted, valid image accepted and altered/wrong-signer/rollback image rejected before boot/update.
V-16	U/TestDeviceAttributes.cpp [device-attributes], I/TestSecureAuthentication.cpp, external SA peer	G0V209 set0 UINTn equals actual supported version. Q00 READ and Q00/Q17 decoding, bad set/type/length rejected. Discovery includes only real capabilities, V210 equals actual statistics per association. A configuration lacking required SA procedures never advertises complete v5. Tie all tests and reviewed policies to exact release revision.


Run the smallest relevant Release target when authorized, then related native/ASIO and CLI process regressions. On the final implementation revision run the full applicable CTest suite. Record actual counts and failures, never infer them from source test names. All proposed test paths must be registered in their existing CMake source list if added.
7. Product decisions and external blockers
Gate	Decision/source needed	Work permitted independently
D01	Blank Profile identity/frame sizes, timer ranges and missing configuration attachments	Measurement wire audit and current callback tests
D02	Count/Pulse/Latch/Trip-Close mapping, default timed events and restart-static unsolicited interpretation	Existing library regression tests, no new permissive product policy
D03	IEEE zero timeout semantics and authenticated no-ack wait window	Existing nonzero SA renewal/ownership tests
D04	Selected MAC set, transport negotiation and any GMAC nonce requirements	Existing HMAC/AES wrap vectors
D05	Valid TLS1.3 suite names, cipher-change operation, revocation interval/mechanism/failure policy	Current TLS identity/CA tests
D06	Approved remote-key alternatives, SCS wrap and Method68 signature representation	Method4 durability/ownership regression
D07	Applicable IEC/TS62351-8/RFC5280 definitions, OIDs, AOR, authority roots, time/expiry policy	Bounded certificate envelope rejection and existing V10 lifecycle tests
D08	Production passwords, hashing parameters, provisioning and role mappings	Shared fail-closed authorization tests
D09	Board/runtime, entropy, storage, clocks, I/O, port policy and firmware recommendation disposition	Portable protocol and Windows endpoint verification
D10	Parent specification pages and independent DNP3/SA test endpoint/Test Harness	Current selected requirements only, with excerpt limitation recorded


IEEE 1815-2012 A.45.8 reproduces external certificate definitions but says the referenced specifications control disagreements. Obtain them before finalizing extension encodings. P4-OPEN-01, RUK-OPEN-01/02, statistics threshold/rearming and untimed-event interpretation remain visible. Independent-peer testing can expose ambiguity but cannot silently change a normative requirement.
8. Final acceptance checklist
- [ ] All 69 Profile rows have every selected function/qualifier/role behavior implemented and actual relevant passing evidence.
- [ ] All CFG-01–14 subrequirements are implemented or have a documented source-based disposition, including the no-counter product policy.
- [ ] All 36 security IDs retain mandatory/recommended/unresolved distinctions. No blocked mandatory item is concealed by a percentage.
- [ ] Selected SA controls, certificates, keys, credentials, statistics and TLS fail closed in positive/negative/lifecycle tests.
- [ ] Existing Master/Outstation extensions and API/generator synchronization survive regression.
- [ ] Windows results identify exact tested revision and actual outputs. Old results remain historical.
- [ ] Independent-peer evidence identifies the peer/version/configuration. Same-project CLI evidence is labeled accordingly.
- [ ] Physical RTU acceptance covers hardware/runtime/security requirements on the real deployed image.
- [ ] Scope remains the supplied PDFs and necessary IEEE dependencies. Missing parent requirements and product decisions remain explicit.
- [ ] The released evidence package contains no secrets, generated credential material or unsupported certification claim.