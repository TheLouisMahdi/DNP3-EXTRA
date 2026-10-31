# First implementation slice: G0V209

**Decision:** Start with **Object Group 0 / Variation 209** (decimal), named **Secure Authentication Version**. This is a device attribute, **not** Group 209 and **not** an SA v5 authentication exchange.

## Normative traceability

| Source | Location | Finding |
|---|---|---|
| PROFILE | PDF p1 | Named as an additional supported object |
| PROFILE | PDF p4, Group 0 / Variation 209 row | READ 1, request qualifier `0x00`, RESPONSE 129, response qualifiers `0x00` / `0x17` |
| IEEE | 5.5.1-5.5.5, PDF pp190-192 | Standard attributes use index **0** and have a type/length/value payload |
| IEEE | Table 5-16, PDF p192 (printed p150) | `UINT` attribute type code = `2` (`0x02`) |
| IEEE | Annex A.1.1, PDF p480 (printed p438) | The variation represents the supported SA version, encoded as UINTn |
| IEEE | 5.5.2, PDF p191 (printed p149) | Attribute-capable outstations **shall include** G0V254 and G0V255 discovery behavior (dependency, not part of this small initial slice) |
| SEC | Table 1 row 1, PDF p3 | Product target is SA Version 5 |

## Interface/behavior contract: only as supported by source

| Aspect | Required behavior |
|---|---|
| Addressing | Read attribute **set index 0**, the standard device attribute set |
| Master request | Function `READ = 1 (0x01)`, object header `Group=0x00`, `Variation=0xD1` (209), qualifier `0x00` (8-bit start/stop), start=0, stop=0 |
| Outstation response | `RESPONSE = 129 (0x81)`, Group 0 / Variation 209; use only permitted qualifiers `0x00` or `0x17` as per supplied profile |
| Value | Type `UINT = 0x02`; one byte specifying value length; value is UINTn in little-endian order if multi-byte |
| Minimal representation for value 5 | Attribute value bytes **`02 01 05`** (`UINT`, length=1, value=5) **only when SA v5 is genuinely supported** |
| Role | Outstation returns the real supported version; Master reads and presents/consumes the attribute |
| READ grouping | Explicit Group 0 attribute read; **not** automatically returned by Class 0 scan (G60V1) |
| Unsupported attribute/error | Preserve baseline OpenDNP3 IIN/error semantics after inspecting current parser/handler; do not invent a second error-handling path |
| Concurrent/mixed reads | Existing APDU object-header parser and writer must remain the single mechanism |

**Reference request object header only**, excluding application control, function byte, link-layer, and fragment framing: `00 D1 00 00 00`. Do not treat this header as a complete DNP3 packet or the `02 01 05` example as validation of live SA support.

**Caution:** The format permits `UINTn` rather than an invented fixed-size C++ integer wire format; the reported **version number and response behavior must be correct**, independently of host byte order. Do not assert a constant `5` while the SA-v5 implementation is absent.

## Functions-first inspection checklist (future Codex task, no code yet)

1. Determine the exact local OpenDNP3 revision and whether G0 support already exists (object enum/metadata, Attribute decoder, generic writer, Outstation READ dispatch, Master result handler). Record actual file names, not guessed paths.
2. Locate existing reusable UINT write/read primitives and qualifier `0x00`/`0x17` handling. Do not modify Link/Transport/CRC/TLS.
3. Identify the **single** source of truth for the runtime SA version; if none exists, mark this functional dependency OPEN. Do not insert an invented hardcoded constant.
4. Outstation: add only missing behavior needed to answer the specific READ. Master: reuse existing explicit READ construction and response parser; add only missing support if proven absent.
5. After those two roles are implemented, perform the *user-requested* local Outstation -> Master check for exact bytes, index, data type and value. No tests or harnesses are created by this planning document.
6. Record status as *slice verified* if the narrow transaction passes. Record **Group 0 overall conformance as pending** until G0V254/G0V255 and other applicable obligations are completed.

## Explicit exclusions from first slice

- No G0V210, G0V254, G0V255 implementation within this slice without separate authorization.
- No G120 authentication messages, keys, challenge-response, MAC, session management or TLS.
- No generalized attribute framework until the existing code proves one is strictly necessary. Reuse existing structure first.
- No changes to STM32 board code, Windows UI, Class 0 configuration, other objects, or source tree structure.

**Acceptance gate:** A plan is ready; the actual patch is **blocked on the local source audit**. If true SA v5 support is not yet present, an honest G0V209 implementation must not advertise it. Decide correct unsupported capability behavior from IEEE/local implementation before committing a value.
