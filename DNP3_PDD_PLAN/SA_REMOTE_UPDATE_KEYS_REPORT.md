# SA remote Update Keys: Method 4 checkpoint

Date: 2026-11-03. Baseline: develop / 92a1c5e69247e94c19e619bc9a019d05167d2b3a.
This is a Windows implementation checkpoint, not independent conformance evidence.
Method 68/G120V14 remains the next slice; it is not advertised as operational.

## IEEE contract and implementation map

IEEE 1815-2012: 7.5.4.4–7.5.4.7 and Table 7-14 (printed pp226–238),
7.5.5.5–7.5.5.7 (pp239–241), 7.6.1.4.9/Table 7-16 (p245),
Table 7-17 (p246), Table 7-18 (p247), 7.6.2.2.2 (p250),
Tables 7-23/7-24 (pp262–265), A.45.10–A.45.15/Tables A-10–A-13
(pp743–757). Table 7-6 controls statistics; 7.5.2.2 uses ASSOC=0 for the
reporting association's G121/G122 values. G120V8 remains the existing session
key status/codec path; this checkpoint does not replace it.

| Objects | Before | Checkpoint |
| --- | --- | --- |
| V10 | CODEC_ONLY | VERIFIED Method 4 ADD/CHANGE/DELETE; external authority MAC; SCS and reserved identities |
| V11/V12 | CODEC_ONLY | VERIFIED native Master task and Outstation ownership; shared KSQ; random challenges |
| V13/V15 | CODEC_ONLY | VERIFIED Method 4 ciphertext forwarding; mutual proof; V15-only verification/recovery |
| V14 | CODEC_ONLY | CODEC_ONLY; Method 68 implementation pending |

Existing generated codecs and parser/serializer were reused without generation
changes. Master uses `IMasterOperations::ChangeUpdateKey`, `UpdateKeyTask` and
existing callbacks/timers. `RemoteUpdateKeys` is an association-owned lifecycle
inside `AuthenticationSession`, sharing `SessionKeys`, provider and statistics.
Outstation routes strict native free-format objects. Ordinary C/R, Aggressive,
authorization and independent owners retain their existing paths.

## Security and persistence

Remote operation is opt-in: AES256RFC3394, HMACSHA256, 32-byte challenges;
network MAC length 16, explicitly supported serial length 8. Certification is
the exact A-10 transcript; directional confirmations are the exact A-13 bytes.
Challenge expansion uses FIPS186-2 Appendix 3.1 general-purpose construction
(Change Notice 1 p74), fresh CSPRNG seeds, and the RFC4186 Appendix A KAT.
This is not a FIPS140 validation claim.

`IUpdateKeyTrust` is Outstation-only. The Master never receives BC and forwards
authority ciphertext unchanged through `IUpdateKeySource`. External authority
transport/provisioning is outside this implementation. Credentials are isolated
by association/user; names are bounded at 128 bytes, capacity configurable 2..16,
and receive storage is bounded. No production default keys exist.

Authority role/expiry changes remain pending until proof under a different,
verified Update Key. DELETE erases credentials immediately. Private roles still
require explicit application policy; standard roles cannot silently gain rights.
Startup permits only Common without trusted UTC. Runtime expiry uses monotonic
deadlines; DNP clock changes cannot extend authorization. Invalid/unavailable DNP
time suppresses Error publication rather than fabricating a timestamp.

The existing Windows adapter now journals two Credential Manager snapshots and
a generation/hash commit marker. Readback verifies writes; missing/torn/corrupt
referenced state fails closed without fallback. Uncertain I/O disables that user.
The Master persists pending credentials before transmission and activates them
after verified peer proof, including restart recovery. Session Keys are never
persisted. Temporary secrets are wiped. Windows tests execute real Credential
Manager calls in an isolated test namespace and remove the records afterward.
Power-loss hardware durability and STM32 NVM integration are NOT VERIFIED.

Statistics 15/16 count real successful/terminal transmitted exchanges once.
Pure verification, duplicate final proof and local construction do not count.
Native G121/G122 and event confirmation/removal are exercised.

## Validation

Release build: `cmake --build build-p6b-o1/native --config Release --target
unittests integrationtests --parallel 4`, verified installed CMake 4.4/MSVC.
Build exit 0. Unit `[remote-update-keys]`: 21 cases / 2,078 assertions, exit 0.
Complete unfiltered suite: 700 cases / 57,393 assertions, exit 0.
Integration `[sa-tcp]`: 2 cases / 181 assertions, exit 0 (including Method 4
changed-key controls, TCP reconnect and recreated Outstation).
Scoped whitespace check passed. Tests include malformed/unowned V12/V13,
lost-stage responses, bounded retries, invalid certification/ciphertext,
role/capacity/bootstrap/expiry, critical persistence failures before/after write,
restart recovery, actual Windows journal corruption and independent old keys.
Existing SA tests remain included in the unfiltered suite.

## OPEN / platform boundaries

- **RUK-OPEN-01:** 7.5.5.5 requires SCS greater than any previous value for the
  user, while A.45.10 permits wrap to zero. Same-authority-key wrap permits
  recorded historical certifications to become valid again. Provisionally reject
  same-key resets/wrap; a verified, administratively rotated authority key
  establishes a new trust epoch. Never reuse an old authority key. Tombstones
  cannot be evicted within that epoch. Tests prove historical certificate and
  same-key wrap rejection. Independent authority/Outstation interoperability and
  authoritative clarification are required; this issue is not closed by tests.
- Method 68 not operational at this checkpoint; no G0V209 full-SA advertisement.
- Existing P4-OPEN-01, P6-OPEN-01/03, NEED_TIME and statistic retention/quality
  limitations remain. No new resolution or embedded validation is claimed.
- External authority integration and trusted time are provisioning contracts;
  no HTTP service, authority database or insecure distribution is invented.
- Shared protocol/provider boundaries remain portable; STM32 crypto, NVM,
  resource sizing and independent Triangle MicroWorks testing remain separate.
