# Security requirements ledger (SEC)

**Source:** `الزامت حداقل مورد نیاز.pdf` (6 PDF pages), final-revision date displayed on cover: 1405/06/22. This document *amends* security tables in a larger RTU requirements document. It is not itself the entire parent specification.

## Table 1 - DNP3 security parameters (SEC PDF pp3-4)

| ID | Parameter | Source requirement | Status for implementation |
|---|---|---|---|
| SEC-T1-01 | Secure Authentication | Fixed: Version 5 | Mandatory, no false reporting |
| SEC-T1-02 | Maximum users | Configurable, at least 2 | Mandatory |
| SEC-T1-03 | Security response timeout | Configurable, 0-120 s | Mandatory range; legal zero semantics to verify in IEEE |
| SEC-T1-04 | Aggressive receive | Yes, not recommended | Capability required; usage policy separate |
| SEC-T1-05 | Aggressive issue | Yes, not recommended | Capability required; usage policy separate |
| SEC-T1-06 | Challenge-response | Mandatory | Mandatory |
| SEC-T1-07 | Session key change interval | Configurable, 15-120 min | Mandatory |
| SEC-T1-08 | Session key change count | Configurable, default 1000 messages | Mandatory |
| SEC-T1-09 | Requested MAC | Selectable SHA-256 (16/8 octets), AES-GMAC | Final required *selection set* not filled by checkboxes; track separately |
| SEC-T1-10 | Session key wrapping | AES-256 mandatory; AES-128 not recommended | Mandatory AES-256 |
| SEC-T1-11 | TLS cipher suites | TLS 1.2 and TLS 1.3 lists | Conflicting TLS 1.3 naming; clarify before coding |
| SEC-T1-12 | DNP TCP port using TLS | Fixed: 19999 | Mandatory when using TLS |
| SEC-T1-13 | Cipher-change request timeout | Configurable, 1-60 s | Mandatory |
| SEC-T1-14 | Supported CAs | At least 4 | Mandatory |
| SEC-T1-15 | Certificate revocation check time | Configurable; numeric value blank | OPEN: no default/range supplied |
| SEC-T1-16 | Remote update-key changes | Configurable, symmetric/asymmetric algorithm options | Must distinguish alternatives vs minimum mandatory options |
| SEC-T1-17 | User-credential expiry | Yes | Mandatory |

**Caution:** The security table uses checkboxes for some algorithms and modes. A checkbox not selected in the source does not establish that every listed algorithm is simultaneously mandatory. Preserve the exact list and requirement category until a compliant algorithm selection is approved. Do not silently commit to an algorithm based on a sample.

### TLS inconsistency

SEC p3 presents names of the `TLS_ECDHE_*_WITH_*` form under TLS 1.3. Those are TLS 1.2-style cipher-suite identifiers; TLS 1.3 has different cipher suite naming and cipher-suite negotiation. This is a **source inconsistency**, not permission to weaken TLS. Resolve using RFC 8446 and requirement-owner approval before implementation. Note that the table also repeats some entries.

## Table 2 - RTU security requirements (SEC PDF p5)

| ID | Subject | Level or statement |
|---|---|---|
| SEC-T2-01 | Protocol authentication | Challenge-response; Aggressive Mode not recommended |
| SEC-T2-02 | Protected communications | TLS 1.2 and TLS 1.3 |
| SEC-T2-03 | Session-key encryption and exchange | Key wrap |
| SEC-T2-04 | Update-key protection | Symmetric and asymmetric approaches indicated; must agree on operative choice |
| SEC-T2-05 | Session key length | 128-bit acceptable; 256-bit recommended |
| SEC-T2-06 | Update key length | 128-bit acceptable; 256-bit recommended |
| SEC-T2-07 | Local RTU configuration password | Mandatory |
| SEC-T2-08 | Random generation for security keys | Mandatory |
| SEC-T2-09 | Authentication enabled by default | Mandatory; disabling for protocol configuration accepted (as described) |
| SEC-T2-10 | Minimum user roles | Administrator for security settings, ordinary user for technical settings; both may perform ordinary tasks |
| SEC-T2-11 | Security parameter configurability | Mandatory for all protocol/configuration security parameters |

This table distinguishes *acceptable minimum* from *recommendation*: do not reclassify the suggested 256-bit length as strictly required where the document accepts 128-bit.

## Table 3 - Hardening (SEC PDF p6)

| ID | Requirement | Level |
|---|---|---|
| SEC-T3-01 | Close unused hardware ports | Mandatory |
| SEC-T3-02 | Close unused network ports | Mandatory |
| SEC-T3-03 | Disable unnecessary users | Mandatory |
| SEC-T3-04 | Least privilege for users | Mandatory |
| SEC-T3-05 | Do not hardcode credentials | Mandatory |
| SEC-T3-06 | Hash stored credentials | Mandatory |
| SEC-T3-07 | Secure firmware update with digital-signature verification | Recommended |
| SEC-T3-08 | Check digital signature during firmware update | Recommended |

## Dependencies and boundary

- **G0V209 (first slice):** reports actual negotiated/implemented SA version capability; its return value must not advertise unimplemented SAv5.
- **G0V210, G121, G122:** represent actual supported security-statistic points and events; these cannot be replaced by made-up counters.
- **G120V1-V15:** are protocol structures that participate in a security state machine; merely serializing them is insufficient.
- **TLS:** a separate secure transport feature; not a substitute for DNP3 SAv5.
- **Platform:** key storage, RNG, time and TLS configuration require Windows vs STM32 adapters later; no new platform interface is prescribed in this planning phase.

**Completion rule:** no security requirement is marked fulfilled until the actual implementation and its configured behavior have been inspected and a user-authorized verification step has completed. This ledger contains no implementation and no test code.

## P4-OPEN-01 - IEEE Authentication Error Code Ambiguity

**Status: OPEN - deferred independent verification in P10.**

- IEEE 1815-2012 §7.5.5.7 refers to Code 5 for Authorization Failed.
- Annex A.45.7.2.2 defines Code 7 for Authorization Failed and Code 5 for MAC Algorithm Not Supported.
- Current implementation deliberately follows the Annex wire-format assignment: authenticated authorization denial uses G120V7 Code 7; Code 5 remains MAC Algorithm Not Supported.
- This is a provisional interoperability decision, not a confirmed official IEEE erratum.
- Verify against official IEEE corrections and Triangle MicroWorks SA v5 Test Harness during P10.
- Do not close this issue without independent interoperability evidence.

Implementation verification remains static only (NOT BUILT / NOT TESTED). Error suppression follows §7.5.2.4 and Table 7-6: explicit suppression and unavailable/busy transmission paths may suppress an Error; the send threshold is reopened only after successful Session Key change. No UTC timestamp is fabricated when the application time source is invalid.
