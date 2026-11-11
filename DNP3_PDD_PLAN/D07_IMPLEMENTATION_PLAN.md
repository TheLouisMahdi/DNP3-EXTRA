# D-07 approved Host implementation plan

Approved 2026-11-11. Requirements CFG-09, PROFILE-019, CFG-08. No new requirement IDs.

Owner-approved D-07 (2026-11-11): support CLOSE 0x41 and TRIP 0x81 on configured Complementary points (Latch or Two-output as appropriate). Permit 0x01 NUL/PULSE_ON only on explicitly enabled Activation points; deny on Complementary, disabled or undefined points. Require count=1, no queue/clear, no Pulse Off or Latch OpType. Use the configured safe point pulse duration rather than Master-requested duration; preserve exact request/echo and validate timing semantics. SELECT validates and arms only, never actuates. Authenticate SA v5, authorize the user and recheck interlocks and safe execution conditions before every actuation. Preserve generic library capabilities.

Actual RTU point indices, point models, safe pulse durations, physical output mapping and interlocks remain product/deployment inputs. Host may use explicit test-only fixtures. No new runtime test evidence; implementation pending. Overlapping pulse/busy policy remains PROPOSED, not approved.

## File-level implementation scope (not executed)

| Path | Exact change |
| --- | --- |
| `cli/Security.h` | Options: explicit per-point model, Activation enablement, configured pulse duration and test-only interlock input; no invented RTU indices or defaults. |
| `cli/Security.cpp` | ParseOptions: validate duplicate indices, permitted models, explicit nonzero safe duration for pulse models and configuration bounds. Preserve compatibility. |
| `cli/main.cpp` | SimulatedCommands::SelectValue/OperateValue: validate raw CROB/count and point model; recheck interlocks and authorization before actuation; separate Complementary Latch, Two-output and Activation; timer and receiver trace for actual simulated pulse duration. SELECT is side-effect-free. Master CLI command path can issue 0x01 explicitly for Host tests. |
| `cli/README.md` | Document explicit opt-in point config and diagnostic commands; distinguish simulation from physical I/O. |
| `opendnp3/cpp/tests/unit/TestProfileControls.cpp` | Add Q17/Q28, 01/41/81, invalid codes/count, SELECT/OPERATE ownership and replay tests. Preserve existing generic CROB tests. |
| `cli/tests/ProcessSmoke.py` | Add profile-crob TCP receiver-side evidence with explicit point models, SA REQUIRED, denied operations and configured pulse timing; include Challenge and Aggressive and selected Method4/68 paths as applicable. |
| `cli/CMakeLists.txt` | Register pc-profile-crob when executable test exists. |
| `opendnp3/cpp/tests/acceptance/phase0.json` | Add real scenario bindings and independent golden vectors only once executable; never fabricate bindings. |
| `opendnp3/cpp/tests/acceptance/DNP3-54-TEST-MATRIX.csv`, `COVERAGE.md` | Host Pulse On scenario pending execution; keep RTU physical gate separate. |
| `ControlRelayOutputBlock.h/.cpp`, `CommandResponseHandler.cpp`, `ControlState.h`, `OutstationContext.cpp`, Scala Group12 | Preserve native protocol behavior; modify only if a separately demonstrated defect requires a minimal fix. |

## Acceptance

Test 0x41/0x81 on both Complementary models and 0x01 on enabled Activation; deny 0x01 on Complementary/disabled/unknown points, unsupported TCC/OpType, queue/clear, count=0 or >1 and invalid timing/configuration. Check configured pulse duration, no actuation on SELECT, authorization/interlock denial, expired/mismatched selection and duplicate/replay without extra execution. Exercise G12V1 Q17/Q28, FC3/4/5/6 under SA REQUIRED, exact acknowledged echo and no FC129 for FC6; record receiver effects and generic compatibility regression.

No builds or tests run by this decision update. Do not claim VERIFIED. Busy/overlapping-pulse behavior is not yet approved; define before implementing affected behavior. Physical actuator mapping and target measurements are not Host acceptance.
