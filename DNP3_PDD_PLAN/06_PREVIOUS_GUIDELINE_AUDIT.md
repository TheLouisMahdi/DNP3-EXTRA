# Review of prior `DNP3_ARCHITECTURE_GUIDELINES.md`

**Audit target:** previous document located in this conversation; **not** the user's local Windows file. Previous version was not modified. This pack supersedes its unverified claims.

| Earlier statement / implied policy | Assessment | Replacement |
|---|---|---|
| `g0v209` and `g0v210` are Device Attributes | **Verified** | Keep; these are Group **0**, Variations 209/210. IEEE A.1.1/A.1.2 |
| G0V209 is a simple isolated extension | **Incomplete** | Small wire value, but needs existing Group 0 machinery; IEEE 5.5.2 mandates G0V254/G0V255 discovery for attribute-capable devices |
| G0V209 can report version 5 in the first phase | **Unsafe if inferred** | Report only supported SA version; SEC target Version 5 is a requirement, not evidence of implementation |
| Profile represents Level 3 for both requests/responses | **Verified** | PROFILE PDF p1; role Outstation (Slave) |
| Every object in IEEE 1815, G34, G13/43, file transfer, or a full Level 4 expansion belongs in the supplied mandatory scope | **Not established** | These are outside the supplied explicit PROFILE; require separate Level 4 gap approval |
| Generic counter development should be scheduled | **Not supported by profile** | PROFILE p4 checks `No Counters Reported`; do not create an artificial counter roadmap |
| Group 60 Class reads can collect different point types | **Verified with qualification** | Only eligible configured static points/events; Group 0 and Group 120 are not ordinary Class 0 measurements |
| Specific source paths in OpenDNP3 are already known | **Only upstream-oriented** | Exact local revision and file mapping remain unverified; inspect the C++ source before naming edit locations |
| Add new `port/stm32/` or a new abstraction layer | **Speculative under PDD** | Do not create directories/interfaces unless existing integration and a concrete requirement make them necessary |
| Every change automatically gets tests, fixtures, benchmarks, or new infrastructure | **Overly broad** | This user explicitly wants testing during implementation slices; perform only the authorized focused checks, without adding infrastructure by default |
| Windows runtime can be copied wholesale to STM32 | **False if implied** | Shared protocol C++ may be portable, ASIO-based runtime and OS integrations need separate evaluation |
| Every G120 variation can be completed by its serializer | **False** | Group 120 requires Clause 7 stateful security behavior |
| Security addendum is a complete standalone specification | **Incomplete** | SEC p2 explicitly calls it an amendment to other RTU requirements; missing parent pages are not present |
| Listed TLS 1.3 cipher names are valid TLS 1.3 suites | **Incorrect** | Security PDF lists TLS 1.2-like names under TLS 1.3; record a conflict for clarification |
| Specific settings such as blank device names/fragment sizes are known | **Unverified** | PROFILE p1 and p2 have blanks; do not invent defaults as contract requirements |
| Use `C++11` across all targets | **Provisional** | Upstream source requirement may use C++11; local MCU compiler and build settings must be audited |

## Source confidence

- **High:** G0V209 encoding/type/index, PROFILE listed rows, selected checkboxes, SEC tables. Direct PDF pages reviewed.
- **Medium:** Full qualifier coverage beyond the supplied implementation table; legal cases require Clause 12 and applicable Annex A when selected.
- **Unknown:** Current local C++ features, commit, generated-code origin, available STM32 port, resource limits, and real SA v5 runtime capability.

## Approval boundary

The corrected documentation supports planning and a **read-only audit**. It does not authorize a change to OpenDNP3 source, a fake SA v5 value, creation of tests, or a speculative framework. G0V209 remains the first planned object.
