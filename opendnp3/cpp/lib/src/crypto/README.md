# Internal SA cryptographic services

`CryptoProvider.h` is a C++14, `ser4cpp`-buffer interface shared by Master and
Outstation. It has no OpenSSL, ASIO, OS, or protocol-state types. The current
implementation is `OpenSSLCryptoProvider.cpp`; a future target can implement the
same functions and select that source at build time. No target provider is
implemented or verified by this slice.

Enable `DNP3_SA_CRYPTO=ON` to compile the adapter and its existing Catch-suite
tests. This option defaults to OFF, is independent of `DNP3_TLS`, and requires
OpenSSL 3.0 or newer's `OpenSSL::Crypto` target. It does not change TLS settings
or activate authentication in either protocol role. No new public API is added.

The adapter uses OpenSSL's default library context/providers: `RAND_bytes_ex`
(256-bit requested strength), `EVP_Q_mac` (HMAC, SHA256 or SHA1), `EVP_aes_128_wrap` /
`EVP_aes_256_wrap` (RFC 3394's default IV, without padding), and
`CRYPTO_memcmp` for tag verification. SHA256 supports 8/16-byte tags and a
32-byte full digest; SHA1 supports 8/10-byte tags and a 20-byte full digest.
SHA1 and AES128 are explicit IEEE 1815-2012 interoperability options; the
authentication configuration defaults remain SHA256 and AES256. Algorithm/configuration failure
returns an error without fallback. The caller must supply valid buffer views,
use exact output sizes, check every result, and wipe caller-owned secrets via
`Clear`. Views are borrowed and not advanced. Input/output overlap is rejected;
on failure the output view is wiped even when it overlaps an input.

Owned digest and unwrap scratch memory are wiped before release; OpenSSL owns
and frees its cryptographic contexts. Unverified unwrap plaintext is kept in a
temporary buffer until integrity succeeds. Unwrap integrity/provider failures
both return `CRYPTO_ERROR`; HMAC mismatches return `AUTHENTICATION_FAILED`.
This API intentionally does not expose provider diagnostics or secret logging.

`TestCryptoProvider.cpp` uses public known-answer vectors from RFC 4231
sections 4.2, 4.3, 4.6, 4.7, RFC 2202 section 3, and RFC 3394 sections
4.1, 4.3, 4.5, 4.6. It also checks
tampering, sizes, invalid pointers, overlaps, failure-output clearing, and
unavailable-provider errors in an isolated thread-default OpenSSL context.
RNG success/non-repetition is a smoke check, not an entropy certification.
Run `unittests.exe "[crypto]"` and the existing regression filter
`"AuthWireCodec*,APDUParsingTestSuite*,APDUWritingTestSuite*"` in the built
unit-test directory.

Requirements navigation: `DNP3_PDD_PLAN/03_SECURITY_MATRIX.md`, SEC-T1-09/10
and SEC-T2-08 (historical transcription, not the source PDF). This slice
implements only the explicitly approved primitives, not IEEE clause 7 state
machines or the security addendum's complete algorithm selection. AES-GMAC remains an unsupported optional algorithm. SA v5 activation, session/key lifecycle,
replay protection, G0 capability reporting and security statistics remain outside
this slice. The IEEE/profile/security PDFs are absent from the new workspace;
no protocol-compliance or target-compatibility claim is made here.
