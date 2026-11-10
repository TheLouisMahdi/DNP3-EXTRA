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
