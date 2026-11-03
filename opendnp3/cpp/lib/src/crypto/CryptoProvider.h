// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_CRYPTOPROVIDER_H
#define OPENDNP3_CRYPTOPROVIDER_H

#include <ser4cpp/container/SequenceTypes.h>

namespace opendnp3
{
namespace crypto
{

    enum class Result
    {
        OK,
        INVALID_INPUT,
        INVALID_OUTPUT_SIZE,
        AUTHENTICATION_FAILED,
        CRYPTO_ERROR
    };

    // Internal, stateless, link-time provider boundary shared by both roles. A target
    // provider implements these signatures instead of OpenSSLCryptoProvider.cpp.
    // No protocol state, SA activation, logging or ownership of caller buffers.
    // Views must describe valid memory (null is allowed only for empty views).
    // Outputs must not overlap inputs. Every failure wipes the entire non-null output
    // view, including a rejected overlapping view. Callers own and wipe their secrets.
    // Views are passed by value and are never advanced. Output sizes must be exact.
    void Clear(ser4cpp::wseq_t output);

    // Equal-length byte comparison in constant time; invalid views fail closed.
    bool ConstantTimeEqual(ser4cpp::rseq_t first, ser4cpp::rseq_t second);

    // Empty output is a successful no-op. Nonempty output uses a CSPRNG, without fallback.
    Result GenerateRandom(ser4cpp::wseq_t output);
    Result SHA256(ser4cpp::rseq_t message, ser4cpp::wseq_t output);
    // IEEE A.45.11 / FIPS186-2 Appendix 3.1, general-purpose form
    // (Change Notice 1 p74). Fresh CSPRNG seed for every 32-byte challenge.
    Result GenerateUpdateKeyChallenge(ser4cpp::wseq_t output);
    // Deterministic provider primitive, for known-answer tests. 20..64 seed
    // bytes, 32 output bytes. Production callers use GenerateUpdateKeyChallenge.
    Result ExpandUpdateKeyChallenge(ser4cpp::rseq_t seed, ser4cpp::wseq_t output);

    // Nonempty key, possibly empty message. Output: full 32-byte digest or its first
    // 8/16 bytes. Only the 8/16-byte tags are accepted by VerifyHMACSHA256.
    Result ComputeHMACSHA256(ser4cpp::rseq_t key, ser4cpp::rseq_t message, ser4cpp::wseq_t output);
    Result VerifyHMACSHA256(ser4cpp::rseq_t key, ser4cpp::rseq_t message, ser4cpp::rseq_t tag);

    // Explicit IEEE 1815-2012 interoperability option. Output: 8/10-byte tag
    // or full 20-byte digest. Protocol verification accepts only 8/10-byte tags.
    Result ComputeHMACSHA1(ser4cpp::rseq_t key, ser4cpp::rseq_t message, ser4cpp::wseq_t output);
    Result VerifyHMACSHA1(ser4cpp::rseq_t key, ser4cpp::rseq_t message, ser4cpp::rseq_t tag);
    Result AES128KeyWrap(ser4cpp::rseq_t key, ser4cpp::rseq_t plaintext, ser4cpp::wseq_t output);
    Result AES128KeyUnwrap(ser4cpp::rseq_t key, ser4cpp::rseq_t wrapped, ser4cpp::wseq_t output);

    // RFC 3394, default A6 IV, no padding. KEK must be exactly 32 bytes.
    // Plaintext: >=16 bytes, multiple of 8. Wrapped size = plaintext size + 8.
    // Input is limited to INT_MAX - 16 bytes by the OpenSSL EVP adapter.
    // Unwrap publishes plaintext only after integrity verification; a failed unwrap
    // returns CRYPTO_ERROR (no unauthenticated plaintext is returned).
    Result AES256KeyWrap(ser4cpp::rseq_t key, ser4cpp::rseq_t plaintext, ser4cpp::wseq_t output);
    Result AES256KeyUnwrap(ser4cpp::rseq_t key, ser4cpp::rseq_t wrapped, ser4cpp::wseq_t output);

} // namespace crypto
} // namespace opendnp3

#endif
