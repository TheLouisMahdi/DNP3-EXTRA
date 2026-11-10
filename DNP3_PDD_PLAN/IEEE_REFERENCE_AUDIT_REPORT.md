# DNP3 119-requirement implementation-reference audit

## Authority and revision

- Editable authority: `DNP3_IEEE1815_IMPLEMENTATION_REFERENCE.xlsx`; two UTF-8 CSV files are generated from the workbook.
- Source authority: supplied Tavanir Device Profile and security addendum; IEEE 1815-2012 for normative DNP3 behavior. Production values not defined by a standard remain explicit engineering policy, not invented IEEE requirements.
- GitHub baseline inspected before this reference edit: `develop@2d636c8d6346770ec9ccb99f7466ae2bec09fd99`. Recheck HEAD before publication.
- This edit changes **reference artifacts only**; production code, Test Harness and test evidence were not changed.

## Scope and integrity

- Exactly 119 unique requirement IDs: 69 PROFILE, 14 CFG and 36 SEC.
- The original 71 normatively inspected backlog items remain tracked: 67 verified for reviewed subcases; four are marked `IEEE_IMPLEMENTATION_POLICY_FIXED__SOURCE_VARIANCE_DOCUMENTED` instead of claiming unqualified normative reconciliation.
- Eleven `IMPLEMENTATION_INDEX` rows and associated cases now contain explicit implementation decisions and permanent-test obligations.
- The 30 D-IDs remain unique. D-10/D-13/D-15/D-18/D-23/D-24/D-25 have precise implementation policy; D-12/D-17 were additionally annotated to preserve IEEE-mandatory legacy capabilities.

## Fixed IEEE implementation decisions

| Decision | Fixed technical implementation | Evidence boundary |
| --- | --- | --- |
| D-10 / CFG-12 | §4.6.6, §5.1.1.1 startup NULL, no objects/G120V1, matching FC0 confirmation, buffered events, explicit FC20 after restart; no prohibited static unsolicited data | Tavanir p4 contract selection is inconsistent; document deviation, never falsely claim satisfaction |
| D-13 / TLS | TLS 1.2 IEEE 2012 baseline; §7.8.2 mandatory TLS_RSA_WITH_AES_128_SHA compatibility capability; secure mTLS production policy; TLS 1.3 separately configurable with native RFC 8446 suite identifiers | TLS 1.3 is not an IEEE-2012 cipher-suite requirement; supplied Tavanir tables differ |
| D-15 / trust | At least four configurable CA roots, chain/name/expiry verification and fail-closed peer authentication | Real CA roots/peer identities must be provisioned externally |
| D-18 / G120V8 | Annex A.45.8 FC32/Q5B single object; only asymmetric methods; external ID/Attribute certificates, holder/AoR/roles/revision/expiry/replay validation | Applicable IEC/TS 62351-8 profile and production PKI cannot be fabricated; permanent wire tests required |
| D-23 / G120V7 | Annex A.45.7.2.2 code 5 = MAC Algorithm Not Supported and code 7 = Authorization Failed | §7.5.5.7 uses contradictory code 5 language; P4-OPEN-01 remains documented |
| D-24 / Method 68 + SCS | Persist monotonic per-owner SCS. Fail closed near UINT32 wrap; controlled authority re-enrollment. Sign A-12 transcript with DSA-SHA256 and canonical DER representation as a documented implementation profile | IEEE describes SCS wrap by authority but strict greater-than receiver rule; A.45.14 does not specify DER; independent-peer encoding evidence required |
| D-25 / G122 | Generate security-statistic event at `delta >= threshold` per §7.6.1.4.2; durable per-association totals, no freeze/clear, correct G122V1/V2 flags and time | §11.9.10.2 uses 'exceeds'; P6-OPEN-01 retained as text discrepancy |

Additional interoperability requirements that secure defaults do not eliminate:
- IEEE §7.6.1.1.1: configurable HMAC-SHA-1 (10-byte TCP MAC), disabled by default in the selected production policy.
- IEEE §7.6.1.2.1: AES-128 Key Wrap support independent of the Method 4 AES-256 Update Key policy.
- IEEE §7.8.2: TLS_RSA_WITH_AES_128_SHA support independent of preferred modern production TLS suites.

## What is decided versus what is still evidence

The implementation behavior is selected; **this is not an assertion of implemented, tested or IEEE-certified behavior**. Active evidence obligations include:

- Actual source modifications for selected requirements not yet implemented.
- Windows Master/Outstation independent-process TCP/TLS Test Harness, including negative, replay, timeout and malformed tests at a recorded commit.
- IEC/TS 62351-8 exact applicable certificate profile, independent Method 68 wire interoperability vector and production CA/AoR identities.
- Product identity and actual credential provisioning.
- Independent-peer interoperability where claimed.
- The contractual variance for CFG-12 and textual IEEE contradictions P4-OPEN-01/P6-OPEN-01 remain visible; an engineering decision is not an official erratum.

## Validation

- Workbook and UTF-8 CSV index export were checked cell for cell.
- ID set remained 119 unique, original 30 decision IDs unchanged, source worksheets retained, and formula error scan returned zero hits.
- No C++ build, runtime test or CI execution was performed during this reference-only update. Historical Windows CTest results apply only to their previously recorded SHA and exact test scope.

## Pre-implementation technical clarification (2026-11-10)

Reference-only corrections against IEEE 1815-2012 §4.3 Rules 1-7 (PDF pp80-81), §§8.2.1-8.2.2 (pp310-313), and Annex A.45.8.2-.3 (pp778-782):

- FRAGMENT now differentiates maximum 249 Application octets *per Transport Segment* from the independently configurable complete Master request Application Fragment; Masters must be able to restrict to 249 when able to transmit larger, and may transmit a larger single fragment when permitted by the peer receive capacity. No DNP3 object can be split across application fragments.
- G120V8 Q5B object-size prefix includes two explicit UINT8 fields before the certificate; certificate size = size prefix - 2, and the maximum size-prefix 65535 yields a maximum 65533 certificate octets. A.45.8.3 says minus one octet, contradicting the A.45.8.2 drawing, and has an IEC/TS 62351-5 vs -8 wording discrepancy; both remain traceable, not an official erratum. A full certificate must fit a single receiver-accepted Application Fragment with overhead, using multiple Transport Segments if necessary.
- Tavanir original Device Profile physical p3 selects Pulse On = Sometimes. Google Drive historical PDF_SCOPE.md says Never; it must be corrected rather than treated as selection authority.
- NORMATIVE_BACKLOG_71 columns C and K explicitly distinguish historical and completed scoped reviews. Twenty-three owner-decision fields without actual explicit authorization are now labeled NOT_RECORDED or equivalent, not silently approved.
- Twelve generic CFG acceptance narratives were replaced with defined positive, negative, malformed, boundary, timeout and process-level cases. These are implementation test plans only.

**Verification scope:** reconstructed workbook, two generated CSVs, unique IDs, live Git hashes, cell-by-cell export agreement and formal source passages. No production code, CI, simulator, Windows build or test execution was performed in this reference-only task. IEEE 1815-2012 may still require consulting the external IEC/TS 62351-8 profile for real certificate acceptance.

## Supplemental IEC/TS 62351-8:2011 audit (2026-11-10)

- Full user-supplied IEC edition 1.0 reviewed. OID/ASN.1, roles, AoR, serial/revision, token maximum 8192 bytes, maximum lifetime 3 years, ID/AC profiles and legacy algorithm capabilities are now `NORMATIVE_DEFINED`. Prior statements that **the IEC 2011 normative text itself is missing** are superseded.
- See `G120V8_IEC62351_2011_PROFILE.md` and `G120V8_DUE_AFTER_IMPLEMENTATION.md`. RFC5280/5755 profile detail and applicable IEC62351-3 CRL clauses require pre-implementation review; real device identity, operator CA and independent peer are acceptance/deployment inputs.
- Code review at develop@6fc3129a found codec but no native V8 processing in RemoteUpdateKeys; status MISSING_RUNTIME. No Windows tests were executed.
- Workbook/derived CSV sync still requires a separate controlled edit to the existing 15-sheet XLSX. Do not regenerate it by discarding unrelated sheets, and do not edit generated CSVs alone.
