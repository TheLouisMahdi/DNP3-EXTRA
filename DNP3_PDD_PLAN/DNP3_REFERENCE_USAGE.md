# DNP3 Windows Host reference usage

Use this package as the operational reference for selected Windows Host requirements. Keep the external and runtime gates in the audit report visible.

1. Filter `DNP3_REFERENCE_119.csv` by the requested ID. Read the contract selection, role, exact wire combinations, acceptance case and evidence status.
2. Use the linked procedure IDs in `DNP3_REFERENCE_WIRE_PROCEDURES.csv`. FC values are decimal unless explicitly hex. Q values are hex. M is Master and O is Outstation. Compact historical FC/Q cells preserve source presentation and cannot be combined freely.
3. Read the linked D-IDs in `IEEE_REFERENCE_OPEN_DECISIONS.md`. Keep engineering policy, contract selection, IEEE rule and actual runtime evidence separate. Open the exact source pages when a selected subcase has an unresolved interpretation.
4. Start code navigation at repository AGENTS.md, REPO_MAP.md and the Windows Host roadmap. For generated wire objects and enums, inspect the authoritative Scala models. Preserve generic behavior outside the selected RTU profile.
5. Record the actual tested revision, configured role, exact permanent test and captured wire/receiver result. Scoped prior execution stays with its tested revision. Hardware ports, STM32/FreeRTOS, physical actuators and recommended firmware validation are outside Windows Host acceptance.

Edit `DNP3_IEEE1815_IMPLEMENTATION_REFERENCE.xlsx`. Regenerate the two CSVs as UTF-8 from the values of IMPLEMENTATION_INDEX and WIRE_PROCEDURES. Preserve header names, column order and leading zeroes in Q values. Compare the exported rows with the workbook after reopening it. Regenerate the decision register from OPEN_DECISIONS. Do not edit the CSVs independently.

Binding project-owner implementation policy (2026-11-10): D-10/CFG-12 and D-18/PROFILE-055 must be implemented strictly to IEEE 1815-2012 with permanent test-harness coverage. See the OPEN_DECISIONS rows and linked procedures. D-10's contradictory Tavanir contractual acceptance and D-18's external certificate specification/production trust provisioning remain separate open gates. Reference changes do not establish runtime compliance.

The IEEE body page index maps printed page n to physical PDF page n+42. The Profile and Security page numbers refer to their own PDF physical pages. The 119 IDs remain the exact contract denominator.

## Fixed implementation policy and remaining evidence

Implementation choices D-10, D-13, D-15, D-18, D-23, D-24 and D-25 are defined in the workbook's OPEN_DECISIONS. All eleven linked exceptional requirement rows contain exact behavior and a test obligation. `SOURCE_VARIANCE_DOCUMENTED` does not mean a missing product choice; it means source contradictions or external deployment inputs remain recorded. `IMPLEMENTATION_AND_PERMANENT_TESTS_REQUIRED` never means runtime verified. For Method 68, DER is the chosen current crypto-provider profile, not an explicit IEEE Annex A.45.14 format requirement. For G122, use >= threshold from §7.6.1.4.2. Never silently close P4-OPEN-01 or P6-OPEN-01 as an official erratum.

## Pre-implementation precision gates (2026-11-10)

- **Packet sizes:** IEEE §4.3 Rules 1-7 and §§8.2.1-8.2.2. A Transport Segment carries at most 249 Application octets, but a Master Application request is one complete Application Fragment (which may need many transport segments). Any Master able to transmit more than 249 bytes must offer a configurable 249-byte request-fragment limit. Respect each Outstation's configured maximum receive fragment length; never split an object across Application Fragments.
- **G120V8:** Annex A.45.8.2 defines two UINT8 fields before the certificate. For Q5B object length L, the certificate occupies L-2 bytes, within L<=65535, and a nonempty DER certificate is required. A.45.8.3 incorrectly says subtract one byte and names IEC/TS 62351-5; retain this conflict in D-18. The complete certificate and all framing overhead must fit a receiver-accepted Application Fragment.
- **Profile selection:** the original 12-page Device Profile PDF, physical p3, selects Pulse On = Sometimes. Older PDF_SCOPE.md wording of Never is incorrect; the original PDF and corrected reference take precedence.
- **Review columns:** NORMATIVE_BACKLOG_71 column C is historical pre-final review status; column K is the current *scoped normative review result*. Historical labels must not override the detailed final result. No workbook review status implies passing source/runtime tests.
- **Owner-decision cells:** empty approvals were replaced with literal `NOT_RECORDED` or `EXTERNAL_INPUT_REQUIRED` text where appropriate. These values explicitly do not constitute owner approval, installation-specific product decisions, or successful acceptance evidence.
- **Acceptance test descriptions:** each of the twelve generic CFG cases in IMPLEMENTATION_INDEX now specifies exact test conditions and failure expectations. These are required permanent cases to implement, not executed test results.

## IEC/TS 62351-8:2011 source audit - 2026-11-10

- The IEC source previously called unavailable is now provided and inspected. Read `G120V8_IEC62351_2011_PROFILE.md` for exact normative certificate values and `G120V8_DUE_AFTER_IMPLEMENTATION.md` for tagged test/deployment gates.
- The canonical 15-sheet XLSX remains the editable master and the two CSVs remain derived exports. **Do not patch CSVs separately or claim workbook synchronization** unless the XLSX itself has been opened, updated, exported and compared. IEC source review and any supplementary workbook do not prove runtime implementation.
- Reviewed `develop@6fc3129a` still lacks G120V8 native runtime handling. `PROFILE-055` is MISSING_RUNTIME pending code and permanent tests. Keep `P4-OPEN-01` provisional.
