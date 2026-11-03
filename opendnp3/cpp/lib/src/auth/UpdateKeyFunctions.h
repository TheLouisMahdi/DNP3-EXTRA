// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_UPDATEKEYFUNCTIONS_H
#define OPENDNP3_UPDATEKEYFUNCTIONS_H

#include "gen/objects/Group120.h"

namespace opendnp3
{
namespace updatekeys
{
    constexpr size_t MAX_NAME = 128;
    constexpr size_t KEY_SIZE = 32;
    constexpr size_t CHALLENGE_SIZE = 32;
    constexpr size_t MAC_SIZE = 16; // SHA-256 over TCP, 7.6.1.1.2. Table 7-16 specifies key length.
    constexpr size_t MAX_PUBLIC_KEY = 1024;

    bool ValidName(ser4cpp::rseq_t name);
    bool IsCommon(ser4cpp::rseq_t name);
    bool ValidRole(uint16_t role);
    // A.45.10/Table A-10. Does not include KCM or the Certification Data length/value.
    bool CertificationData(const Group120Var10& status, ser4cpp::wseq_t output, size_t& size);
    // A.45.15/Table A-13. Receiver identity and challenge order are direction-specific.
    bool ConfirmationData(bool fromMaster, ser4cpp::rseq_t outstationName, ser4cpp::rseq_t userName,
                          ser4cpp::rseq_t masterChallenge, ser4cpp::rseq_t outstationChallenge,
                          uint32_t sequence, uint16_t user, ser4cpp::wseq_t output, size_t& size);
    bool VerifyMAC(ser4cpp::rseq_t key, ser4cpp::rseq_t message, ser4cpp::rseq_t mac);
    // A.45.13/Table A-11. Zero padding to the RFC 3394 multiple-of-eight boundary.
    bool KeyData(ser4cpp::rseq_t name, ser4cpp::rseq_t key, ser4cpp::rseq_t challenge,
                 ser4cpp::wseq_t output, size_t& size);
    bool ReadKeyData(ser4cpp::rseq_t input, ser4cpp::rseq_t name, ser4cpp::rseq_t challenge,
                     ser4cpp::wseq_t key);
}
}
#endif
