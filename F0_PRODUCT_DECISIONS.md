# F0 - source-fixed product constraints and unresolved choices

**Recorded:** 2026-11-09  
**Baseline:** `develop` at `64f6f932ed9f386a81275bcc65119ceb708d5b05` (before this documentation-only change)  
**Scope:** 69 PROFILE + 36 SEC + 14 CFG = 119 tracked IDs. F0 is a decision prerequisite, not an additional requirement.  
**Status:** **SOURCE RULES RECORDED; PRODUCT APPROVALS STILL OPEN.** No code changes, test execution or deployment validation are represented by this register.

## Reading rules

- **FIXED** means explicitly selected in the supplied RTU Device Profile, the minimum security addendum, or required by the applicable IEEE 1815-2012 text. It is not a product default invented from source code.
- **FIXED + OPEN** means the specified constraint is recorded, but an additional choice or disputed interpretation remains. The open portion is not approved.
- **OPEN** means no owner-approved value can be derived. Existing OpenDNP3 defaults and suggestions are not product decisions.
- **TARGET DEFERRED** means the Windows Host design may proceed, but actual STM32H743/FreeRTOS security and hardware acceptance remains outstanding.
- **PROVISIONAL** preserves a known interpretation while awaiting authoritative clarification. It is not a published IEEE correction.

The referenced PDFs are 12-page Device Profile (physical pages 1-12), six-page minimum-security addendum (physical pages 1-6), and IEEE Std 1815-2012. Source-only decisions do not turn historical requirement statuses into VERIFIED.

## A. Device Profile and runtime settings

| F0 ID | Requirement | Disposition | Recorded constraint; remaining decision / evidence gate | Source |
| --- | --- | --- | --- | --- |
| F0-01 | CFG-01 | FIXED + OPEN | Outstation (Slave), Level 3 requests/responses plus explicitly listed extensions. Actual vendor, device, product ID and revision are blank; obtain official values. | Profile p1 |
| F0-02 | CFG-02 | FIXED + OPEN | Maximum received FT3 data-link frame = **292 on-wire octets**. Transmitted-frame maximum is blank. Do not substitute the APDU size for a frame limit. | Profile p2 |
| F0-03 | CFG-03, CFG-14 | FIXED + OPEN | Application receive fragment must exceed **249 octets**; transmitted fragment sizes above **2048 octets** must be configurable; multi-fragment responses supported. Actual RX/TX defaults and maximum bounded memory budget await product approval. | Profile pp2,4 |
| F0-04 | CFG-04 | FIXED + OPEN | Link retries configurable **0..5**; application retries configurable **1..5**, not fixed. Defaults and precise operation-specific eligibility remain open. No blind retry of direct controls, no duplicate operation. **Approved F01-D policy:** for a confirmed logical send, one NACK/DFC=0 on user data may trigger at most one RESET_LINK_STATES recovery; a NACK during reset or any DFC=1 ACK/NACK fails, and a second NACK fails. This allowance is independent of the existing per-frame timeout retry limit. | Profile p2; IEEE application/control behavior; approved F01-D product policy |
| F0-05 | CFG-05 | FIXED + OPEN | Link confirmation policy must support Never, Always, and On multi-frame fragments. TCP production default is not selected by PDF. Link confirm is separate from application confirm. | Profile p2 |
| F0-06 | CFG-07 | FIXED + OPEN | Waiting for link confirm, complete application fragment, application confirm and complete application response is **configurable**. Source PDF omits numeric defaults/ranges and its explanatory attachment; assign no fabricated values. Determine timer owner by Master/Outstation role. | Profile pp2-3 |
| F0-07 | CFG-10 | FIXED + OPEN | Default binary change events must be **time-tagged**. The form selects absolute time and configurability but supplies no configuration explanation. Exact configured G2V2/G2V3 policy and CTO/time-quality handling remain open; existing library G2V1 default is not proof of product selection. | Profile p3 |
| F0-08 | CFG-11 | FIXED + OPEN | Unsolicited delivery must be configurable; ENABLE/DISABLE UNSOLICITED supported. Initial enablement, allowed classes and explanation remain product decisions. | Profile p4 |
| F0-09 | CFG-12 | FIXED + OPEN | Static data in unsolicited responses is selected **When Device Restarts**. Exact legal startup sequence, static snapshot scope, security gate and restart-vs-reconnect distinction need an owner-approved, IEEE-consistent interpretation. NULL unsolicited alone is insufficient evidence. | Profile p4 |
| F0-10 | CFG-09, PROFILE-019 | FIXED + OPEN | Profile selects Trip/Close Always, but WRITE binary outputs, Count >1, standalone Pulse On/Off, Latch On/Off, Queue/Clear Queue Never. IEEE TCC encoding for complementary controls can use CLOSE+PULSE_ON (0x41) and TRIP+PULSE_ON (0x81); the mapping of that encoding to this product's Never selections is **not yet approved**. Real indices, count, pulse timing and interlocks are open. | Profile p3; IEEE Annex A.8.1 |
| F0-11 | CFG-13 | FIXED | Deployed Outstation reports **No Counters Reported** for counter defaults and rollover. Keep generic G20-G23 library support intact; verify actual production database has no physical counter points. | Profile p4 |
| F0-27 | CFG-06 | FIXED | Application confirmation selected for reporting event data and multi-fragment responses; verify CON/SEQ, association ownership, event retention and confirm timeout. | Profile p2 |
| F0-28 | CFG-08, PROFILE-019/035/036/037 | FIXED | SELECT/OPERATE (FC3/4), DIRECT OPERATE (FC5), and DIRECT OPERATE NO ACK (FC6) are selected for listed G12/G41 control forms. FC6 has no application response; sender completion cannot establish physical execution. Requires authenticated receiver-side effect tests. | Profile p3, pp6-8 |

## B. Secure Authentication v5 and user credentials

| F0 ID | Requirement | Disposition | Recorded constraint; remaining decision / evidence gate | Source |
| --- | --- | --- | --- | --- |
| F0-12 | SEC-T1-03 | FIXED + OPEN | IEEE reply timeout default **2 s**, configurable in **100 ms** increments, maximum at least **120 s**. Addendum says configurable **0..120 s**, but meaning of **0** is unspecified. Rejecting zero until clarified is a *proposed conservative interim policy*, not proof that zero is prohibited by IEEE. Track TIMEOUT-ZERO. | IEEE 7.6.1.4.1; addendum p3 |
| F0-13 | SEC-T1-01/02/06/07/08, SEC-T2-09 | FIXED | SA **v5** selected; enabled by default and Challenge/Reply mandatory. At least **2 users**. Session-key renewal configurable **15..120 min** (IEEE default **15 min**); message-count default **1000**. IEEE requires security settings from 7.6.1.4 to survive restart; Host settings and hardware retention require evidence. | Addendum pp3,5; IEEE 7.6.1.4, 7.6.1.4.3-4 and 7.6.1.4.8 |
| F0-14 | SEC-T1-09, PROFILE-050/056 | OPEN | SHA-256 MAC with 16- or 8-octet output and AES-GMAC appear as **unchecked choices**; do not invent an authorized allowlist. Network HMAC-SHA-256/16 is only a candidate until approval. Aggressive send and receive are required capabilities but usage is discouraged. Preserve no implicit SHA-1 downgrade. | Addendum p3; IEEE 7.6.1.4.7 |
| F0-15 | SEC-T1-10, SEC-T2-03/05/06 | FIXED | **AES-256 Key Wrap** mandatory for session-key wrapping. Security Table 2 permits **128-bit minimum** session/update-key lengths and recommends 256-bit; that minimum is not permission to downgrade mandatory AES-256 Key Wrap. Apply valid key-length constraints to each selected exchange. | Addendum pp3,5 |
| F0-16 | SEC-T1-16, SEC-T2-04, PROFILE-057..062 | FIXED + OPEN | For implementations supporting remote Update Key changes, **Method 4 (AES-256 Key Wrap + HMAC-SHA-256)** is mandatory and the default per IEEE. Only **one** key-change method may be active for a Master/Outstation pair. Additional methods (including 68), signing authorities and provisioning need explicit product approval; existing Method 68 code does not select it contractually. Preserve RUK-OPEN-01/02. | IEEE 7.6.1.4.9, Table 7-16; addendum p4 |
| F0-17 | PROFILE-055, SEC-T1-16/17 | FIXED + OPEN | G120V8 User Certificate is selected; IEEE Annex A.45.8 has certificate structures distinct from a generic TLS server certificate. Certificate type/profile, trusted CA, identity/AOR, expiry/revocation, role binding and provisioning authority require an external product definition. Runtime acceptance remains incomplete. | Profile p11; IEEE Annex A.45.8 |
| F0-18 | SEC-T2-09/10/11, SEC-T3-03/04/05 | FIXED + OPEN | Default-on protocol authentication, minimum Admin and normal technical-user roles, and configurable security parameters are selected. Actual permissions (including independent Trip/Close privilege), enrollment, recovery and credential expiry policy remain unapproved. Authentication is not automatic authorization. | Addendum p5 Table 2; p6 Table 3 |
| F0-19 | SEC-T2-07, SEC-T3-04/06 | FIXED + OPEN | Local RTU configuration must be password-protected; human-password strength and hashed credential storage are required. Concrete local interface, approved password/KDF policy, work factors, rate limits and recovery require product and target approval. No hardcoded production password or DNP3 update key reuse. | Addendum pp5-6 |
| F0-20 | SEC-T2-08/11, SEC-T3-03/05/06 | FIXED + TARGET DEFERRED | Secure random key generation, configurable security policy, no hardcoded credentials, hashed stored credentials and unnecessary-user disablement are required. Persist required IEEE security parameters across restart. Actual RTU entropy, NVM, trust clock and port/user evidence remain deferred. | Addendum pp5-6; IEEE 7.6.1.4 |
| F0-21 | PROFILE-054, SEC-T1-01 | PROVISIONAL | **P4-OPEN-01 stays open**: provisional G120V7 code 5 = MAC Algorithm Not Supported; code 7 = Authorization Failed. Neither mapping is asserted to be an official IEEE erratum. | Engineering issue register |

## C. TLS, trust and RTU hardening

| F0 ID | Requirement | Disposition | Recorded constraint; remaining decision / evidence gate | Source |
| --- | --- | --- | --- | --- |
| F0-22 | SEC-T1-11/12, SEC-T2-02 | FIXED + OPEN | **TLS 1.2 and 1.3**, DNP TLS port **19999** and certificate-protected communication selected. The addendum's TLS 1.3 entries reuse TLS 1.2-format suite names; these cannot be adopted literally. The valid TLS 1.3 AES-GCM candidates from RFC 8446 require approval and peer interoperability evidence. Do not silently replace listed names. | Addendum pp3-5; RFC 8446 |
| F0-23 | SEC-T1-13 | FIXED + OPEN | Addendum requests configurable **1..60 s** change-cipher timeout; IEEE 7.8.5 requires the same configurable range as the SA reply timeout (up to at least **120 s**). This is a tracked conflict. TLS 1.3 has no renegotiation procedure equivalent to TLS 1.2; do not substitute handshake timeout or silently redefine KeyUpdate semantics. | Addendum p4; IEEE 7.8.5, 7.6.1.4.1; RFC 8446 |
| F0-24 | SEC-T1-14, SEC-T2-02 | FIXED + OPEN | Support **at least four** configurable certificate authorities. Production TLS/SA trust separation, trust anchors, peer identity rules, renewal and signer are still product decisions. Verify four distinct chains and rejection conditions. | Addendum p4; IEEE 7.8.7 |
| F0-25 | SEC-T1-15 | FIXED + OPEN | **Fill the addendum's blank CRL interval from IEEE**: check/evaluate CRLs every **12 hours by default**, configurable at **one-hour resolution**. Refuse a confirmed-revoked certificate at establishment; terminate sessions using confirmed-revoked certificates. CRL retrieval failure must **not itself terminate an established session**. Certificate expiry alone does not end an established session, but expired credentials cannot establish a new one. CRL sources, cache freshness, establishment-time missing-CRL policy and trusted clock remain open. | IEEE 7.8.7.4.3-4; addendum p4 |
| F0-26 | SEC-T3-01..08 | FIXED + TARGET DEFERRED | Hardware/network port hardening, unnecessary accounts, password policy, credential handling are mandatory. **SEC-T3-07/08 (signed firmware update/check) are recommended**, not silently reclassified as mandatory. Hardware-specific acceptance is deferred to STM32H743/FreeRTOS. | Addendum p6 |

## Approved now versus not approved

**Recorded from sources without new product choice:** F0-11, F0-13, F0-15, F0-27, F0-28, plus the **FIXED parts** of the other rows. This resolves omitted IEEE defaults for reply timeout and CRL scheduling in the decision register, not the product-level exceptions.

**Not approved:** TX frame size 292, APDU default 2048, 2-retry default, TCP link-confirm default, five-second timer guesses, G2V2-only default, startup unsolicited policy, CROB TCC/restriction reconciliation, MAC allowlist, optional Method 68 deployment, user certificate authority and AOR, role-permission matrix, password/KDF policy, TLS 1.3 replacement list, change-cipher conflict and CRL distribution/cache policy. Do not translate these proposals into production code solely from this register.

**Existing source observations, not acceptance:** Native AuthenticationConfig at the reviewed revision defaults to REQUIRED, 2 users, 15 minutes/1000 messages, 2-second reply timeout and HMAC-SHA-256/16; default max APDU is 2048, while MeasurementInfo's binary event default is untimed G2V1. These do not establish the still-blank product selections.

## Completion gates and ownership

**Requirement owner / RTU product owner:** approve each outstanding number, algorithm set, interface, deployment policy and any deviation from normative/contract text. Record approver, date, exact decision, affected requirements and source of authority; do not invent signatures or effective dates.

**Engineering owner:** after approval, map every decision to portable Host implementation and permanent positive, negative, boundary, timeout, ownership, replay, wire and separate-process tests as applicable. Verify SHA and full selected subcases; record independent-peer evidence separately.

**RTU integration owner:** later demonstrate actual STM32H743/FreeRTOS entropy, protected NVM, trusted time, physical I/O and interlocks, startup/reset and network/physical-port security. Host success does not close this gate.

**Open normative issue:** retain P4-OPEN-01 and all other named Open Issues, including SEC-T1-11/13, TIMEOUT-ZERO, RUK-OPEN-01/02 and CFG-12 sequencing. No requirement status, progress percentage or G0V209 SA v5 advertisement may be promoted merely because these source rules were recorded.
