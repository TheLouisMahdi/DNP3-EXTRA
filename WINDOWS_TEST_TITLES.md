# Windows Host test titles - DNP3-EXTRA

> Planning list only. All cases are NOT RUN and must not be treated as implemented tests or passing evidence.
> Source: selected 69 PROFILE, 36 SEC, and 14 CFG requirements; execution phases C/D/E. Target-specific hardware tests are explicitly deferred.
> Baseline for this plan: 9b2534b37152f07a439f892ba8d27c3a9863653f; implementation commits must be verified separately.

## Phase C - FC6 authenticated no-ack
- [ ] FC6 G12V1: authenticated CROB no-ack receiver execution via TCP
- [ ] FC6 G41V1: authenticated analog32 no-ack receiver execution via TCP
- [ ] FC6 G41V2: authenticated analog16 no-ack receiver execution via TCP
- [ ] FC6 G41V3: authenticated analog float32 no-ack receiver execution via TCP
- [ ] FC6 both Method 4 and Method 68, each after a genuine Challenge
- [ ] FC6 malformed, denied, timeout, replay, owner, sequence, Q17/Q28

## Phase D - TLS CRL checks
- [ ] TLS CRL valid issuer chain allows mTLS on TLS1.3
- [ ] TLS CRL revoked server certificate prevents control execution
- [ ] TLS CRL revoked client certificate prevents control execution
- [ ] TLS CRL expired issuer prevents handshake
- [ ] TLS CRL missing file and corrupt signature rejected
- [ ] TLS CRL untrusted/missing issuer and multi-CA chain rejected
- [ ] TLS CRL no stale trust on reconnect/context recreation

## Phase E - FC22 class-assignment qualifiers
- [ ] FC22 G3V0 assign class2 via qualifier Q00
- [ ] FC22 G3V0 assign class2 via qualifier Q01
- [ ] FC22 G3V0 assign class2 via qualifier Q06
- [ ] FC22 G30V0 assign class2 via qualifier Q00
- [ ] FC22 G30V0 assign class2 via qualifier Q01
- [ ] FC22 G30V0 assign class2 via qualifier Q06

## Requirement-level test titles: Profile (69)
- [ ] [PROFILE-001] G0V209 SA version attribute
- [ ] [PROFILE-002] G0V210 security-statistics-per-association attribute
- [ ] [PROFILE-003] G1V0 binary input any variation
- [ ] [PROFILE-004] G1V1 binary input packed
- [ ] [PROFILE-005] G1V2 binary input flags
- [ ] [PROFILE-006] G2V0 binary event any variation
- [ ] [PROFILE-007] G2V1 binary event without time
- [ ] [PROFILE-008] G2V2 binary event absolute time
- [ ] [PROFILE-009] G2V3 binary event relative time and CTO
- [ ] [PROFILE-010] G3V0 double-bit binary input any variation
- [ ] [PROFILE-011] G3V1 double-bit binary input packed
- [ ] [PROFILE-012] G3V2 double-bit binary input flags
- [ ] [PROFILE-013] G4V0 double-bit event any variation
- [ ] [PROFILE-014] G4V1 double-bit event without time
- [ ] [PROFILE-015] G4V2 double-bit event absolute time
- [ ] [PROFILE-016] G4V3 double-bit event relative time and CTO
- [ ] [PROFILE-017] G10V0 binary output status any variation
- [ ] [PROFILE-018] G10V2 binary output status flags
- [ ] [PROFILE-019] G12V1 CROB SELECT/OPERATE/DO/FC6
- [ ] [PROFILE-020] G30V0 analog input any variation
- [ ] [PROFILE-021] G30V1 analog input 32-bit flags
- [ ] [PROFILE-022] G30V2 analog input 16-bit flags
- [ ] [PROFILE-023] G30V3 analog input 32-bit no flags
- [ ] [PROFILE-024] G30V4 analog input 16-bit no flags
- [ ] [PROFILE-025] G30V5 analog input float32 flags
- [ ] [PROFILE-026] G32V0 analog input event any variation
- [ ] [PROFILE-027] G32V1 analog input event 32-bit without time
- [ ] [PROFILE-028] G32V2 analog input event 16-bit without time
- [ ] [PROFILE-029] G32V4 analog input event 16-bit with time
- [ ] [PROFILE-030] G32V5 analog input event float32 without time
- [ ] [PROFILE-031] G40V0 analog output status any variation
- [ ] [PROFILE-032] G40V1 analog output status 32-bit flags
- [ ] [PROFILE-033] G40V2 analog output status 16-bit flags
- [ ] [PROFILE-034] G40V3 analog output status float32 flags
- [ ] [PROFILE-035] G41V1 analog output 32-bit command including FC6
- [ ] [PROFILE-036] G41V2 analog output 16-bit command including FC6
- [ ] [PROFILE-037] G41V3 analog output float32 command including FC6
- [ ] [PROFILE-038] G50V1 absolute time read/write
- [ ] [PROFILE-039] G51V1 synchronized CTO
- [ ] [PROFILE-040] G51V2 unsynchronized CTO
- [ ] [PROFILE-041] G52V1 coarse time delay
- [ ] [PROFILE-042] G52V2 fine time delay
- [ ] [PROFILE-043] G60V1 class 0 read and assignment
- [ ] [PROFILE-044] G60V2 class 1 read/enable/disable/assignment
- [ ] [PROFILE-045] G60V3 class 2 read/enable/disable/assignment
- [ ] [PROFILE-046] G60V4 class 3 read/enable/disable/assignment
- [ ] [PROFILE-047] G80V1 IIN packed read and write restrictions
- [ ] [PROFILE-048] G120V1 SA challenge
- [ ] [PROFILE-049] G120V2 SA reply
- [ ] [PROFILE-050] G120V3 aggressive mode request
- [ ] [PROFILE-051] G120V4 session-key status request
- [ ] [PROFILE-052] G120V5 session-key status
- [ ] [PROFILE-053] G120V6 session-key change
- [ ] [PROFILE-054] G120V7 authentication error
- [ ] [PROFILE-055] G120V8 user certificate runtime (blocked on approved certificate profile)
- [ ] [PROFILE-056] G120V9 message authentication code
- [ ] [PROFILE-057] G120V10 user status change
- [ ] [PROFILE-058] G120V11 update-key change request
- [ ] [PROFILE-059] G120V12 update-key change reply
- [ ] [PROFILE-060] G120V13 update-key change
- [ ] [PROFILE-061] G120V14 update-key change signature
- [ ] [PROFILE-062] G120V15 update-key change confirmation
- [ ] [PROFILE-063] G121V1 security statistics
- [ ] [PROFILE-064] G122V0 security event any variation
- [ ] [PROFILE-065] G122V1 security event flags
- [ ] [PROFILE-066] G122V2 security event flags and time
- [ ] [PROFILE-067] no-object CONFIRM
- [ ] [PROFILE-068] no-object COLD_RESTART
- [ ] [PROFILE-069] no-object DELAY_MEASURE

## Requirement-level test titles: Security Table 1 (17)
- [ ] [SEC-T1-01] SA v5 selected capability and truthful advertisement
- [ ] [SEC-T1-02] minimum two independently authenticated users
- [ ] [SEC-T1-03] SA response timeout 0-120 seconds and expiry semantics
- [ ] [SEC-T1-04] aggressive receive MAC/ownership/replay
- [ ] [SEC-T1-05] aggressive issue with actual peer execution
- [ ] [SEC-T1-06] challenge-response positive/negative exchange
- [ ] [SEC-T1-07] session-key replacement interval 15-120 minutes
- [ ] [SEC-T1-08] session-key change message count including default 1000
- [ ] [SEC-T1-09] approved HMAC/GMAC algorithm and tag sizes (policy pending)
- [ ] [SEC-T1-10] mandatory AES-256 session-key wrap
- [ ] [SEC-T1-11] approved TLS 1.2/1.3 suites (policy pending)
- [ ] [SEC-T1-12] TLS port 19999 and mutual authentication
- [ ] [SEC-T1-13] change-cipher request timeout 1-60 seconds (policy pending)
- [ ] [SEC-T1-14] minimum four certificate authorities
- [ ] [SEC-T1-15] certificate revocation at handshake and renewal policy (interval pending)
- [ ] [SEC-T1-16] remote update-key methods and authority (policy pending)
- [ ] [SEC-T1-17] credential expiration and invalidation

## Requirement-level test titles: Security Table 2 (11)
- [ ] [SEC-T2-01] protocol challenge-response and protected operations
- [ ] [SEC-T2-02] TLS 1.2/1.3 confidentiality, peer identity, downgrade failure
- [ ] [SEC-T2-03] session-key encryption, fresh exchange and zeroization
- [ ] [SEC-T2-04] symmetric/asymmetric update key protection
- [ ] [SEC-T2-05] session key minimum/accepted lengths
- [ ] [SEC-T2-06] update key minimum/accepted lengths
- [ ] [SEC-T2-07] local RTU configuration password (target-specific portion deferred)
- [ ] [SEC-T2-08] cryptographic random key generation and RNG failure
- [ ] [SEC-T2-09] SA default-on and permitted administrative disable
- [ ] [SEC-T2-10] administrator/ordinary user role isolation
- [ ] [SEC-T2-11] security configuration permission, range and persistence

## Requirement-level test titles: Security Table 3 (8; target-only tests deferred)
- [ ] [SEC-T3-01] unused hardware interfaces closed (RTU hardware deferred)
- [ ] [SEC-T3-02] unused network services closed (device deployment deferred)
- [ ] [SEC-T3-03] unused accounts disabled and sessions revoked
- [ ] [SEC-T3-04] strong local password controls (RTU deployment deferred)
- [ ] [SEC-T3-05] no hard-coded credentials and secrets audit
- [ ] [SEC-T3-06] stored credentials salted/hashed (RTU NVM deferred)
- [ ] [SEC-T3-07] signed firmware update (recommended; target deferred)
- [ ] [SEC-T3-08] firmware signature enforcement (recommended; target deferred)

## Requirement-level test titles: runtime/configuration (14)
- [ ] [CFG-01] Outstation Level 3 selected profile and truthful capabilities
- [ ] [CFG-02] link frame 291/292/293 and CRC handling
- [ ] [CFG-03] application fragment 249/250/2048/2049 and reassembly
- [ ] [CFG-04] link/application retries and exhaustion without duplicate controls
- [ ] [CFG-05] Never/Always/Multi-frame link-confirm policies
- [ ] [CFG-06] event and multi-fragment application confirm/retry
- [ ] [CFG-07] configurable timer bounds, expiry and cancellation (product inputs pending)
- [ ] [CFG-08] SBO/DO/FC6 combinations and non-duplicate execution
- [ ] [CFG-09] Trip/Close permitted and unsupported CROB modes denied (mapping pending)
- [ ] [CFG-10] binary default timed events and CTO variations
- [ ] [CFG-11] configurable unsolicited, enable/disable, missed confirm
- [ ] [CFG-12] static unsolicited on restart only (product selection pending)
- [ ] [CFG-13] no counters reported under integrity scans
- [ ] [CFG-14] multi-fragment response and lost-confirm behavior

## Combined Windows log campaign (not run)
- [ ] Build Release targets: dnp3-cli, unittests, integrationtests, asiotests
- [ ] Run focused unit and TCP/process suites and capture separate stdout/stderr/exit codes
- [ ] Run full CTest Release serial, then parallel, and store consolidated logs
- [ ] Correlate every PASS/FAIL/BLOCKED with requirement ID, case, test name and Git SHA
- [ ] Record independent-peer and target RTU acceptance separately; do not mark Windows self-tests as external conformance

## Deferred Group 70 and implementation follow-up

- G70V2/3/4/5/6/7/8 exact Q5B bytes, count/length/offset boundaries, invalid qualifier, and atomic writer failure.
- G70V2 non-overlapping credential fields and credential-free response; no credential content in diagnostics.
- G70V5/6 block 0, maximum 31-bit block, final-bit boundary, empty file and malformed record.
- FC28/G70V7 authorized Outstation metadata reply, directory/file distinction, request ID echo and G70V4 file-not-found status.
- FC28 disabled provider, Compatibility mode, denied SA, foreign association, broadcast, malformed descriptor and capacity failures; provider must not run.
- G70 runtime expansion acceptance: master task ownership, authenticated open, read/write blocks, close/abort/delete, inactivity status 17, deferred event polling and optional activation.
- FC22 one G60 class plus multiple supported object headers; class switch, dangling class, invalid qualifier and no stale-class assignment.
- G122 event timestamp captured before persistence, DC on same event for Save false/throw, and no duplicate report.
- Diagnostic fragment size independent RX/TX, 249/250/2048/4096/65535/65536 boundaries and real multi-fragment transfer.
- G120V8 type 1/2 and method 67..71, vendor opaque method, rejected symmetric/obsolete/reserved fields; validated certificate trust and lifecycle remain separate.
