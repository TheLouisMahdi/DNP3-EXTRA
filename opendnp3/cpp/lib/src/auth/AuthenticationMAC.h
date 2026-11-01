// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_AUTHENTICATIONMAC_H
#define OPENDNP3_AUTHENTICATIONMAC_H
#include "crypto/CryptoProvider.h"
namespace opendnp3
{
inline uint8_t ResolveAuthenticationMAC(uint8_t algorithm, size_t tagLength)
{
    return algorithm ? algorithm : (tagLength == 8 ? 3 : (tagLength == 16 ? 4 : 0));
}
inline size_t AuthenticationTagLength(uint8_t algorithm)
{
    switch (algorithm)
    {
    case 2:
        return 10;
    case 3:
    case 5:
        return 8;
    case 4:
        return 16;
    default:
        return 0;
    }
}
inline bool ValidAuthenticationMAC(uint8_t algorithm, size_t tagLength)
{
    return AuthenticationTagLength(algorithm) != 0 && AuthenticationTagLength(algorithm) == tagLength;
}
inline crypto::Result WrapAuthenticationKeys(
    uint8_t algorithm, bool unwrap, ser4cpp::rseq_t key, ser4cpp::rseq_t input, ser4cpp::wseq_t output)
{
    using Operation = crypto::Result (*)(ser4cpp::rseq_t, ser4cpp::rseq_t, ser4cpp::wseq_t);
    Operation operation = nullptr;
    if (algorithm == 1)
        operation = unwrap ? crypto::AES128KeyUnwrap : crypto::AES128KeyWrap;
    if (algorithm == 2)
        operation = unwrap ? crypto::AES256KeyUnwrap : crypto::AES256KeyWrap;
    if (!operation)
    {
        crypto::Clear(output);
        return crypto::Result::INVALID_INPUT;
    }
    return operation(key, input, output);
}
inline crypto::Result ComputeAuthenticationMAC(uint8_t algorithm,
                                               ser4cpp::rseq_t key,
                                               ser4cpp::rseq_t input,
                                               ser4cpp::wseq_t output)
{
    if (!AuthenticationTagLength(algorithm) || output.length() != AuthenticationTagLength(algorithm))
    {
        crypto::Clear(output);
        return crypto::Result::INVALID_OUTPUT_SIZE;
    }
    return algorithm == 2 || algorithm == 5 ? crypto::ComputeHMACSHA1(key, input, output)
                                            : crypto::ComputeHMACSHA256(key, input, output);
}
inline crypto::Result VerifyAuthenticationMAC(uint8_t algorithm,
                                              ser4cpp::rseq_t key,
                                              ser4cpp::rseq_t input,
                                              ser4cpp::rseq_t tag)
{
    if (!AuthenticationTagLength(algorithm) || tag.length() != AuthenticationTagLength(algorithm))
        return crypto::Result::INVALID_INPUT;
    return algorithm == 2 || algorithm == 5 ? crypto::VerifyHMACSHA1(key, input, tag)
                                            : crypto::VerifyHMACSHA256(key, input, tag);
}
} // namespace opendnp3
#endif
