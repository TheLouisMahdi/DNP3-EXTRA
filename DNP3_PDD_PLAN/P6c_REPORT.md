# P6c security Device Attributes

Status: IMPLEMENTED and manually validated. Focused final review and `git diff --check`: PASS; no additional defect found. C++ builds/tests were executed by the user, not the agent. The authorized local commit follows report finalization; its hash is recorded in the final chat response. No push authorized or performed.

Baseline: develop at 28be44142213ca71ca03efdb2a97a925da4d79dc. Git root resolves to `D:/C drive/User/Desktop/DNP3-EXTRA` (workspace alias `C:/Users/poimu/Desktop/DNP3-EXTRA`). Independent AGENTS.md and TestProductionAuthentication.cpp/Catch edits are preserved and excluded.

## Requirements and actual behavior

IEEE 1815-2012 section 5.5.1-5.5.8 (printed pp148-154), Table 5-16 (p150), Table 12-1 (p352), A.1.1/A.1.2 (pp438-439), A.1.43/A.1.44 (pp485-486), and section 7.5.2.2 (pp204-207). Supplied Device Profile PDF p4 explicitly selects G0V209/V210 READ qualifier 00 and RESPONSE qualifiers 00/17. This is the selected security attribute slice, not an assertion of full Group 0 or Level 4 conformance.

There was no existing native Group 0 implementation in this baseline; the G0V209 document was a contract. Preserve its requirement to report only real supported SA versions. The existing SA implementation is still incomplete, with no supported complete version to advertise. Accordingly, Outstation G0V209 remains unavailable (OBJECT_UNKNOWN), is omitted from discovery, and never fabricates version 0 or 5. Master G0V209 decoding and typed delivery are implemented for an external device's actual UINTn value.

G0V210 returns a read-only UINT (type 2) at standard attribute set index 0. The value comes from the size of the existing association-owned G121 snapshot, currently 18 when attached by the secured Outstation READ path. It is 0 without that runtime/snapshot (including compatibility/noncrypto operation). It is not the number of users, associations, pending events, enabled event classes or configured thresholds. No new capability setting or duplicated statistic-count constant is introduced.

Exact active-runtime response object: `00 D2 00 00 00 02 01 12`. No-runtime value: `00 D2 00 00 00 02 01 00`. G0V209 explicit request: `00 D1 00 00 00`; unavailable response contains no value and sets IIN2 OBJECT_UNKNOWN (02).

IEEE 5.5.2 requires V254/V255 for attribute-capable devices. Their minimal dependency is included: V254 READ returns the supported V210 value; V255 returns `00 FF 17 01 00 FE 02 D2 00` (read-only V210, excludes V254/V255 and unsupported V209). Both accept request qualifiers 00 and 06. V209/V210 requests accept 00; value responses accept 00/17. V254 never appears in a response. Private sets are not published; ranges containing an unavailable set return PARAM_ERROR, with the valid set-zero part retained. Attributes are not selected by Class 0.

Master preserves received set indexes, type codes, raw little-endian UINTn bytes, list properties and header metadata. An attribute set index is not an Association ID or a G121/G122 point index; no remapping, merging or local-statistic updates occur. The numeric accessor detects uint64 overflow rather than truncating. Raw bytes remain available for any UINTn length 1..255. V255 supports normal/extended even-length lists (types 254/255). This slice parses only the selected Group 0 variations and their UINT/list payloads; it adds no private-attribute provisioning or other attribute families.

## Native integration and preservation

Reuses APDUParser's two-pass validation, RangeParser/CountIndexParser, HeaderWriter, IAPDUHandler, MeasurementHandler/ISOEHandler, ReadHandler, Database and ResponseContext. Added the small shared DeviceAttribute model/parser and bounded DeviceAttributeSelection module because none existed. No parallel APDU engine, authentication state machine or application main harness was added. Solicited polls use the existing Scan/HeaderWriter interface with an 8-bit range header (the generic ScanRange convenience uses 16-bit ranges and is not the profile's Group 0 request). Fragment/CONFIRM scheduling remains native.

ISOEHandler adds a default no-op typed attribute overload to preserve source compatibility; binary clients must rebuild. Attribute byte spans borrow the APDU and must be copied before the callback returns. HeaderWriter reserves the full object before writing. Selection is bounded, cleared with native Unselect and retained on insufficient response space. V255 lists only actual attributes. A narrow WriteHandler whitelist keeps newly recognized read-only Group 0 bodies from causing preceding mixed-WRITE side effects.

G120/G121/G122 codecs, counters, authentication/event behavior and previously documented NEED_TIME/continuity/P6a limitations are unchanged.

## Generator and tests

Scala Group0 is registered in ObjectGroup. Corrected signed Byte handling in variation names, numeric IDs and generated ID() rendering: variations above 127 must retain their unsigned wire values. Used the existing Java 11/Scala 2.13.2 generator and official Generate entry point into `build-p6c/generator/output`; copied only scoped C++ metadata, Group0.h and the generated Group 0 Java/C# declarations/lookup entries. Existing Java/C# omissions for other security groups were preserved rather than importing unrelated generator differences. Existing Attributes and GroupVariationSerialization outputs compare unchanged after line-ending/trailing-whitespace normalization. No G120/G121/G122 outputs were copied or edited. No C++ compiler or test executable was run by the agent.

Permanent TestDeviceAttributes.cpp (16 cases / 458 assertions, manually run by the user: PASS) covers generated IDs; actual count/absent runtime; honest unsupported G209; mandatory discovery; index semantics; Class 0/statistic preservation; profile response qualifiers; UINTn including 3/8-byte values and overflow; normal/extended lists; mixed types/header order; every representative truncated prefix before callbacks; malformed type/length/qualifier/range; atomic writes/fragment retention; native Master exact READ/fragment CONFIRMs; native compatibility Outstation; mixed read-only WRITE protection; unchanged legacy callback implementation.

Manual validation supplied by the user in this chat:

| Check | Result |
| --- | --- |
| MSVC Release `unittests` build, including library dependencies | PASS; exit code 0 |
| `[device-attributes] -r compact` | PASS; 16 cases / 458 assertions; exit code 0 |
| `*APDUParsing*,*MeasurementHandler*,[master-security-statistics],[security-stat-read],[security-stat-events] -r compact` | PASS; 91 cases / 1938 assertions; exit code 0 |
| Focused final review and scoped/staged whitespace checks | PASS; no additional defect found |

No prior phase's test result is substituted for P6c validation. No C++ build or test executable was run by the agent. Noncrypto builds, language-binding builds, interoperability/Test Harness and embedded validation were not performed. Existing authentication baseline failures were not rerun; no new result is claimed for them. Remaining limitations: Outstation G0V209 cannot advertise an SA version yet; only the selected attribute family and its required discovery dependency are supported; callback spans borrow the APDU and binary clients must rebuild. Existing NEED_TIME/continuity/P6a limitations remain unchanged.

Successful manual validation and focused review satisfy the authorization for one local commit containing only the 34 paths below. Independent AGENTS.md and Catch edits remain excluded. No push or subsequent phase.

## Exact P6c paths

```
DNP3_PDD_PLAN/04_G0V209_CONTRACT.md
DNP3_PDD_PLAN/P6c_REPORT.md
REPO_MAP.md
opendnp3/cpp/lib/CMakeLists.txt
opendnp3/cpp/lib/include/opendnp3/app/DeviceAttribute.h
opendnp3/cpp/lib/include/opendnp3/gen/GroupVariation.h
opendnp3/cpp/lib/include/opendnp3/master/ISOEHandler.h
opendnp3/cpp/lib/src/app/HeaderWriter.cpp
opendnp3/cpp/lib/src/app/HeaderWriter.h
opendnp3/cpp/lib/src/app/parsing/APDUParser.cpp
opendnp3/cpp/lib/src/app/parsing/CountIndexParser.cpp
opendnp3/cpp/lib/src/app/parsing/DeviceAttributeParser.cpp
opendnp3/cpp/lib/src/app/parsing/DeviceAttributeParser.h
opendnp3/cpp/lib/src/app/parsing/IAPDUHandler.cpp
opendnp3/cpp/lib/src/app/parsing/IAPDUHandler.h
opendnp3/cpp/lib/src/app/parsing/RangeParser.cpp
opendnp3/cpp/lib/src/gen/GroupVariation.cpp
opendnp3/cpp/lib/src/gen/objects/Group0.h
opendnp3/cpp/lib/src/master/MeasurementHandler.cpp
opendnp3/cpp/lib/src/master/MeasurementHandler.h
opendnp3/cpp/lib/src/outstation/Database.cpp
opendnp3/cpp/lib/src/outstation/Database.h
opendnp3/cpp/lib/src/outstation/DeviceAttributeSelection.cpp
opendnp3/cpp/lib/src/outstation/DeviceAttributeSelection.h
opendnp3/cpp/lib/src/outstation/ReadHandler.cpp
opendnp3/cpp/lib/src/outstation/WriteHandler.h
opendnp3/cpp/tests/unit/CMakeLists.txt
opendnp3/cpp/tests/unit/TestDeviceAttributes.cpp
opendnp3/dotnet/CLRInterface/src/gen/GroupVariation.cs
opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/GroupVariation.scala
opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/ObjectGroup.scala
opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/generators/GroupVariationLines.scala
opendnp3/generation/dnp3/src/main/scala/com/automatak/render/dnp3/objects/groups/Group0.scala
opendnp3/java/bindings/src/main/java/com/automatak/dnp3/enums/GroupVariation.java
```
