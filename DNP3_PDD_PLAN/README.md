# DNP3 PDD Planning Pack

**Status:** Reviewed planning documents only. No protocol source was edited, generated, built, or tested.

## Place beside existing PDFs

```text
DNP3/
  IEEE 1815/
    4812449245627490050_724147149003390.pdf
    IEEE 1815-2012.pdf
    الزامت حداقل مورد نیاز.pdf
  DNP3_PDD_PLAN/
    README.md
    01_SOURCE_MAP.md
    02_PROFILE_MATRIX.csv
    03_SECURITY_MATRIX.md
    04_G0V209_CONTRACT.md
    05_PHASES_AND_CODEX.md
    06_PREVIOUS_GUIDELINE_AUDIT.md
```

**Read in order:** `01` -> `02` -> `04` -> `05`; consult `03` for security work. `06` records corrections to the earlier draft.

## Precision-Driven Development rules

- Implement only the authorized object, role, and behavior. Do not invent additional tasks.
- Inspect the exact local OpenDNP3 revision and relevant code paths first. The PDF-only ZIP is **not a source-code audit**.
- Preserve existing parser, serializers, APDU handling, transport, public signatures, and project layout unless a demonstrated requirement demands a minimal localized change.
- Reuse existing functions and generic object machinery before introducing a model, helper, or dispatch branch. Do not maintain a second protocol engine.
- The shared C++ code must have no new Windows-only dependency. Windows hosting and STM32 platform integration are distinct concerns.
- For each authorized feature: Outstation first -> Master second -> requested local end-to-end verification. No tests, test harnesses, or implementation changes are authorized by this pack itself.
- An object is only *documented* here, not proven supported or standards-conformant.

## Evidence labels

- **PROFILE:** explicitly listed in the 12-page RTU implementation table or its device profile checkboxes.
- **IEEE:** a requirement or format in IEEE 1815-2012.
- **SEC:** the 6-page security addendum.
- **UPSTREAM:** documented OpenDNP3 upstream behavior; not yet confirmed against the user's source.
- **DECISION:** project sequencing or policy, not a normative requirement.
- **OPEN:** requires source audit, equipment details, or resolution of conflicting/blank requirements.

All page references identify **PDF file page number (1-based)** unless explicitly called "IEEE printed page". A quoted group/variation is a DNP3 on-wire identifier, not a C++ class name.

**Boundary:** IEEE 1815-2012 is the standards baseline in the supplied documents. Do not silently add later IEEE editions, unspecified Level 4 features, or security behavior absent from requirements.
