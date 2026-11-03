# SA remote Update Keys: Windows Methods 4/68

Date: 2026-11-03. Baseline: develop / 92a1c5e69247e94c19e619bc9a019d05167d2b3a.
This records the Windows implementation and local validation, not independent
conformance evidence. Method 4 checkpoint `556691a4d03bd848618025de10e994f54bac0acc`
was pushed and verified before the Method 68 extension. The final SCS rule below
supersedes that checkpoint's authority-fingerprint reset allowance.

## IEEE contract and implementation map

IEEE 1815-2012: 7.5.4.4–7.5.4.7 and Table 7-14 (printed pp226–238),
7.5.5.5–7.5.5.7 (pp239–241), 7.6.1.4.9/Table 7-16 (p245),
Table 7-17 (p246), Table 7-18 (p247), 7.6.2.2.2 (p250),
Tables 7-23/7-24 (pp262–265), A.45.10–A.45.15/Tables A-10–A-13
(pp743–757). Table 7-6 controls statistics; 7.5.2.2 uses ASSOC=0 for the
reporting association's G121/G122 values. G120V8 (User Certificate) is CODEC_ONLY;
runtime certificate-chain distribution is not added. Method 68 uses independently
provisioned authority/Outstation SPKIs and V10 user certification. G120V5 remains
the existing Session Key Status procedure.

| Objects | Before | Checkpoint |
| --- | --- | --- |
| V10 | CODEC_ONLY | VERIFIED local Methods 4/68 ADD/CHANGE/DELETE; authority MAC/signature; SCS and reserved identities |
| V11/V12 | CODEC_ONLY | VERIFIED native Master/Outstation ownership for both methods; shared KSQ; random challenges |
| V13/V15 | CODEC_ONLY | VERIFIED local Methods 4/68 mutual proof; V15-only verification and pending-key recovery |
| V14 | CODEC_ONLY | VERIFIED local Method 68 DSA signature path; DER interoperability remains RUK-OPEN-02 |

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
verified Update Key. DELETE erases credentials immediately, including Common
when trusted UTC is unavailable; revocation needs no expiry calculation. Private roles still
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
The adapter has one serialized credential owner per configured namespace;
administrative provisioning must not race runtime writes. Separate Master and
Outstation credential owners use separate namespaces. The journal is not a
multi-process compare-and-swap database.

Statistics 15/16 count real successful/terminal transmitted exchanges once.
Pure verification, duplicate final proof and local construction do not count.
Native G121/G122 and event confirmation/removal are exercised.

## Method 68 and configuration

`allowMethod68` defaults false. Each request explicitly selects 4 or 68; an
existing user's V11 method must match its certified method. There is no fallback
to another algorithm. Method 68 uses RSA2048 OAEP with SHA256 and MGF1SHA256,
an empty OAEP label, and a 256-bit Update Key. V10 certification and V14 use
DSA SHA256 with L=2048/N=256, never RSA signatures or ECDSA. Public keys are
bounded, self-contained SPKI DER; private DER stays behind credential/provider
boundaries. OpenSSL validates key type/size/domain/public/private/pairwise
consistency, consumes the entire encoding and rejects noncanonical SPKI/signatures.
No certificate chain or trust-on-first-use is implied by SPKI decoding.

The Master receives its user's private key and an independently trusted Outstation
public key through the explicit source. It locally encrypts A-11 without RFC3394
padding, signs A-12, and sends V13+V14. Outstation verifies the authority-certified
user signature, decrypts with its provisioned private key, checks name/RB, commits,
and returns the A-13 HMAC. V15-only recovery remains available for either method.
The authority private key never enters the Master boundary. Names are limited to
126 bytes for Method 68 because OAEP2048/SHA256 carries at most 190 plaintext
bytes including the 32-byte key and 32-byte challenge; Method 4 permits 128.

Windows record schema 2 includes Method/SPKI and up to 72 certification bytes.
Schema 1 Method 4 records remain readable and upgrade on the next verified write;
the actual Credential Manager migration is tested. Only active/pending Update
Keys and user metadata persist; Session Keys never do.

Receive input/user count is bounded. The fixed 16-entry remote metadata table
includes 16 x 1024-byte public-key slots; SessionKeys are separately allocated
once to configured capacity. RSA/DSA use bounded inputs but provider allocations.
STM32/FreeRTOS RAM/stack sizing and a non-OpenSSL backend are not measured here.
Native file transfer, firmware/code loading and local login are not implemented;
standard roles cannot gain those permissions through a coarse file-mode check.
Table 7-12 permits local interpretation: the gate restricts native monitoring,
controls/freezing and configuration, then ANDs the explicit application policy.
Combined administrator/ordinary roles require provisioned PRIVATE policy.

## Validation

Release build, verified installed CMake 4.4/MSVC:

```powershell
& 'C:\Program Files\CMake\bin\cmake.exe' --build 'D:\C drive\User\Desktop\DNP3-EXTRA\build-p6b-o1\native' --config Release --target unittests integrationtests --parallel 4
```

Method 4 checkpoint: build exit 0; focused 21 cases / 2,078 assertions;
unfiltered 700 / 57,393; TCP 2 / 181. Final Methods 4/68 validation after the
certified DELETE/trusted-time correction:

| Gate | Cases | Assertions | Process exit |
| --- | ---: | ---: | ---: |
| Release targets `unittests integrationtests` | — | — | 0 |
| Unit `[remote-update-keys] -r compact` | 35 | 3,733 | 0 |
| Complete unfiltered unit suite `-r compact` | 714 | 59,048 | 0 |
| Native TCP integration `[sa-tcp] -r compact` | 2 | 240 | 0 |

Zero failing cases/assertions in each test run. The TCP remote-update case runs
both methods through Catch GENERATE, alongside the existing SA TCP case.
Unit and integration executables are the existing Release binaries under
`D:\C drive\User\Desktop\DNP3-EXTRA\build-p6b-o1\native\cpp\tests\unit\Release`
and `...\integration\Release`, respectively. Scoped whitespace check passed.
Tests include malformed/unowned V12/V13,
lost-stage responses, bounded retries, invalid certification/ciphertext,
role/capacity/bootstrap/expiry, critical persistence failures before/after write,
restart recovery, actual Windows journal corruption and independent old keys.
Existing SA tests remain included in the unfiltered suite.

## Exact changed-file manifest

Paths below are relative to Git root
`D:\C drive\User\Desktop\DNP3-EXTRA`. They cover both checkpoints, not just
the final asymmetric extension. The pre-existing `AGENTS.md` edit is excluded.
No generated objects, Scala models or G0V209 implementation were changed.

Production:

```text
opendnp3/cpp/lib/CMakeLists.txt
opendnp3/cpp/lib/include/opendnp3/auth/AuthenticationConfig.h
opendnp3/cpp/lib/include/opendnp3/auth/UpdateKeyConfig.h
opendnp3/cpp/lib/include/opendnp3/auth/WindowsAuthenticationCredentials.h
opendnp3/cpp/lib/include/opendnp3/master/IMasterOperations.h
opendnp3/cpp/lib/src/auth/AuthenticationSession.cpp
opendnp3/cpp/lib/src/auth/AuthenticationSession.h
opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.cpp
opendnp3/cpp/lib/src/auth/RemoteUpdateKeys.h
opendnp3/cpp/lib/src/auth/SessionKeys.cpp
opendnp3/cpp/lib/src/auth/SessionKeys.h
opendnp3/cpp/lib/src/auth/UpdateKeyFunctions.cpp
opendnp3/cpp/lib/src/auth/UpdateKeyFunctions.h
opendnp3/cpp/lib/src/auth/WindowsAuthenticationCredentials.cpp
opendnp3/cpp/lib/src/crypto/CryptoProvider.h
opendnp3/cpp/lib/src/crypto/OpenSSLCryptoProvider.cpp
opendnp3/cpp/lib/src/master/IMasterTask.h
opendnp3/cpp/lib/src/master/MasterContext.cpp
opendnp3/cpp/lib/src/master/MasterContext.h
opendnp3/cpp/lib/src/master/MasterStack.cpp
opendnp3/cpp/lib/src/master/MasterStack.h
opendnp3/cpp/lib/src/master/UpdateKeyTask.cpp
opendnp3/cpp/lib/src/master/UpdateKeyTask.h
opendnp3/cpp/lib/src/outstation/OutstationChallenger.cpp
opendnp3/cpp/lib/src/outstation/OutstationChallenger.h
opendnp3/cpp/lib/src/outstation/OutstationContext.cpp
opendnp3/cpp/lib/src/outstation/OutstationContext.h
```

Permanent tests and build registration:

```text
opendnp3/cpp/tests/dnp3mocks/include/dnp3mocks/RemoteUpdateKeyCredentials.h
opendnp3/cpp/tests/dnp3mocks/include/dnp3mocks/AsymmetricUpdateKeyCredentials.h
opendnp3/cpp/tests/unit/CMakeLists.txt
opendnp3/cpp/tests/unit/TestRemoteUpdateKeys.cpp
opendnp3/cpp/tests/integration/CMakeLists.txt
opendnp3/cpp/tests/integration/TestSecureAuthentication.cpp
```

Engineering evidence:

```text
REPO_MAP.md
DNP3_PDD_PLAN/02_PROFILE_MATRIX.csv
DNP3_PDD_PLAN/03_SECURITY_MATRIX.md
DNP3_PDD_PLAN/SA_REMOTE_UPDATE_KEYS_REPORT.md
```

## OPEN / platform boundaries

- **RUK-OPEN-01:** 7.5.5.5 requires SCS greater than any previous value for the
  user, while A.45.10 permits wrap to zero. Provisionally reject all remote
  resets/wrap, including authority-key or certification-method changes. Another
  configured authority method could still validate historical certifications;
  a different fingerprint alone cannot establish a fresh trust epoch. Named
  tombstones are never evicted. At SCS exhaustion/capacity exhaustion, protected
  administrative reprovisioning must revoke historical trust before clearing
  replay state; no remote reset API is provided. Tests prove cross-method replay,
  wrap and tombstone-eviction rejection. Authoritative clarification and an
  independent authority/Outstation wrap-boundary test remain required.
- **RUK-OPEN-02:** A.45.10/A.45.14 specify DSA certification/signature bytes but
  do not specify r/s wire representation. Provisionally use strict DER
  Dss-Sig-Value per RFC5758 §3.1 / RFC3279 §2.2.2, with no alternate parser or
  algorithm fallback. Independent Method 68 authority/Master/Outstation testing
  must establish interoperability of both V10 and V14. Local RFC6979 KAT and
  loopback tests do not close this issue. No full G0V209 SA advertisement is added.
- Existing P4-OPEN-01, P6-OPEN-01/03, NEED_TIME and statistic retention/quality
  limitations remain. No new resolution or embedded validation is claimed.
- External authority integration and trusted time are provisioning contracts;
  no HTTP service, authority database or insecure distribution is invented.
- Shared protocol/provider boundaries remain portable; STM32 crypto, NVM,
  resource sizing and independent Triangle MicroWorks testing remain separate.

Primary external references used where needed:
[FIPS186-2 Change Notice 1](https://csrc.nist.gov/files/pubs/fips/186-2/upd1/final/docs/fips186-2-change1.pdf),
[RFC4186 Appendix A](https://www.rfc-editor.org/rfc/rfc4186.html#appendix-A),
[RFC5758 §3.1](https://www.rfc-editor.org/rfc/rfc5758.html#section-3.1),
[RFC3279 §2.2.2](https://www.rfc-editor.org/rfc/rfc3279.html#section-2.2.2),
[RFC6979 Appendix A.2.2](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.2).
