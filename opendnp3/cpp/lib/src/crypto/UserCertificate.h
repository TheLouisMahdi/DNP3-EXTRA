// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_USERCERTIFICATE_H
#define OPENDNP3_USERCERTIFICATE_H

#include "opendnp3/auth/UpdateKeyConfig.h"
#include <ser4cpp/container/SequenceTypes.h>

namespace opendnp3
{
namespace crypto
{
struct UserCertificate
{
    UpdateKeyRequest status;
    uint64_t expiresUnixMs = 0;
    uint8_t revision = 0;
    std::array<uint8_t, 32> subject{};
    std::array<uint8_t, 32> issuer{};
    UserCertificateBinding binding;
    UserCertificateBinding holder;
};

struct CertificateTime
{
    uint64_t utc;
    bool secure;
};

enum class CertificateResult { VALID, INVALID_SIGNATURE, INVALID_DATA };
CertificateResult VerifyUserIdentity(IUserCertificatePolicy& policy, uint16_t association,
                                     ser4cpp::rseq_t der, CertificateTime time, UserCertificate& result);
CertificateResult VerifyUserAttribute(IUserCertificatePolicy& policy, uint16_t association,
                                      ser4cpp::rseq_t der, CertificateTime time, UserCertificate& result);
inline CertificateResult VerifyUserIdentity(IUserCertificatePolicy& policy, uint16_t association,
                                           ser4cpp::rseq_t der, uint64_t utc, UserCertificate& result)
{
    return VerifyUserIdentity(policy, association, der, {utc, true}, result);
}
inline CertificateResult VerifyUserAttribute(IUserCertificatePolicy& policy, uint16_t association,
                                            ser4cpp::rseq_t der, uint64_t utc, UserCertificate& result)
{
    return VerifyUserAttribute(policy, association, der, {utc, true}, result);
}
bool SameCertificate(const UserCertificateBinding& lhs, const UserCertificateBinding& rhs);
enum class CertificateBindingResult { VALID, REVOKED, INVALID };
CertificateBindingResult CheckUserCertificateBinding(IUserCertificatePolicy& policy, uint16_t association,
                                                      const UserCertificateBinding& binding, bool attribute, CertificateTime time);
}
}
#endif
