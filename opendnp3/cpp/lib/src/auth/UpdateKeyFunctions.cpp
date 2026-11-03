// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/UpdateKeyFunctions.h"

#include "crypto/CryptoProvider.h"

#include <ser4cpp/serialization/LittleEndian.h>

#include <array>
#include <cstring>

namespace opendnp3
{
namespace updatekeys
{
namespace
{
    bool Valid(ser4cpp::rseq_t value)
    {
        return value.is_empty() || static_cast<const uint8_t*>(value);
    }
    bool Overlaps(ser4cpp::rseq_t input, ser4cpp::wseq_t output)
    {
        if (input.is_empty() || output.is_empty()) return false;
        const auto a = reinterpret_cast<uintptr_t>(static_cast<const uint8_t*>(input));
        const auto b = reinterpret_cast<uintptr_t>(static_cast<uint8_t*>(output));
        return a <= b ? b - a < input.length() : a - b < output.length();
    }
    class Output final
    {
    public:
        explicit Output(ser4cpp::wseq_t value_) : value(value_) {}
        ~Output() { if (!committed) crypto::Clear(value); }
        ser4cpp::wseq_t value;
        bool committed = false;
    };
}

bool IsCommon(ser4cpp::rseq_t name)
{
    static const uint8_t common[] = {'C', 'o', 'm', 'm', 'o', 'n', 0};
    return Valid(name) && name.equals(ser4cpp::rseq_t(common, sizeof(common)));
}

bool ValidName(ser4cpp::rseq_t name)
{
    // Names are opaque authority identities, not C strings. Preserve every octet;
    // only Common has a protocol-defined spelling and terminating null.
    return Valid(name) && !name.is_empty() && name.length() <= MAX_NAME;
}

bool ValidRole(uint16_t role)
{
    return role <= 6 || role >= 32768;
}

bool CertificationData(const Group120Var10& status, ser4cpp::wseq_t output, size_t& size)
{
    size = 0;
    Output guard(output);
    const bool asymmetric = status.keyChangeMethod == 68;
    if ((status.keyChangeMethod != 4 && !asymmetric) || status.operation < 1 || status.operation > 3
        || !ValidName(status.userName) || !ValidRole(status.userRole) || !Valid(status.userPublicKey)
        || (asymmetric ? (status.userPublicKey.is_empty() || status.userPublicKey.length() > MAX_PUBLIC_KEY)
                       : !status.userPublicKey.is_empty())
        || Overlaps(status.userName, output) || Overlaps(status.userPublicKey, output)) return false;
    const auto required = 11 + (asymmetric ? 2 : 0) + status.userName.length() + status.userPublicKey.length();
    if (!static_cast<uint8_t*>(output) || output.length() < required) return false;
    auto dest = output;
    ser4cpp::LittleEndian::write(dest, status.operation, status.seqNum, status.userRole, status.userRoleExpiryDays,
                               static_cast<uint16_t>(status.userName.length()));
    if (asymmetric) ser4cpp::UInt16::write_to(dest, static_cast<uint16_t>(status.userPublicKey.length()));
    dest.copy_from(status.userName);
    dest.copy_from(status.userPublicKey);
    size = required;
    guard.committed = true;
    return true;
}

bool ConfirmationData(bool fromMaster, ser4cpp::rseq_t outstationName, ser4cpp::rseq_t userName,
                      ser4cpp::rseq_t masterChallenge, ser4cpp::rseq_t outstationChallenge,
                      uint32_t sequence, uint16_t user, ser4cpp::wseq_t output, size_t& size)
{
    size = 0;
    Output guard(output);
    const auto receiver = fromMaster ? outstationName : userName;
    if (!ValidName(receiver) || !user || !Valid(masterChallenge) || !Valid(outstationChallenge)
        || masterChallenge.length() != CHALLENGE_SIZE || outstationChallenge.length() != CHALLENGE_SIZE
        || Overlaps(receiver, output) || Overlaps(masterChallenge, output) || Overlaps(outstationChallenge, output))
        return false;
    const auto required = receiver.length() + 2 * CHALLENGE_SIZE + 6;
    if (!static_cast<uint8_t*>(output) || output.length() < required) return false;
    auto dest = output;
    dest.copy_from(receiver);
    dest.copy_from(fromMaster ? masterChallenge : outstationChallenge);
    dest.copy_from(fromMaster ? outstationChallenge : masterChallenge);
    ser4cpp::LittleEndian::write(dest, sequence, user);
    size = required;
    guard.committed = true;
    return true;
}

bool VerifyMAC(ser4cpp::rseq_t key, ser4cpp::rseq_t message, ser4cpp::rseq_t mac)
{
    if (!Valid(mac) || (mac.length() != 8 && mac.length() != MAC_SIZE) || key.length() != KEY_SIZE) return false;
    std::array<uint8_t, MAC_SIZE> expected{};
    const bool valid = crypto::ComputeHMACSHA256(key, message, ser4cpp::wseq_t(expected.data(), mac.length()))
            == crypto::Result::OK
        && crypto::ConstantTimeEqual(ser4cpp::rseq_t(expected.data(), mac.length()), mac);
    crypto::Clear(ser4cpp::wseq_t(expected.data(), expected.size()));
    return valid;
}

bool KeyData(ser4cpp::rseq_t name, ser4cpp::rseq_t key, ser4cpp::rseq_t challenge,
             ser4cpp::wseq_t output, size_t& size)
{
    size = 0;
    Output guard(output);
    if (!ValidName(name) || !Valid(key) || !Valid(challenge) || key.length() != KEY_SIZE
        || challenge.length() != CHALLENGE_SIZE || Overlaps(name, output) || Overlaps(key, output)
        || Overlaps(challenge, output)) return false;
    const auto required = (name.length() + KEY_SIZE + CHALLENGE_SIZE + 7) & ~size_t(7);
    if (!static_cast<uint8_t*>(output) || output.length() < required) return false;
    crypto::Clear(output);
    auto dest = output;
    dest.copy_from(name);
    dest.copy_from(key);
    dest.copy_from(challenge);
    size = required;
    guard.committed = true;
    return true;
}

bool ReadKeyData(ser4cpp::rseq_t input, ser4cpp::rseq_t name, ser4cpp::rseq_t challenge,
                 ser4cpp::wseq_t key)
{
    Output guard(key);
    if (!Valid(input) || !ValidName(name) || !Valid(challenge) || challenge.length() != CHALLENGE_SIZE
        || !static_cast<uint8_t*>(key) || key.length() != KEY_SIZE || Overlaps(input, key)
        || Overlaps(name, key) || Overlaps(challenge, key)) return false;
    const auto content = name.length() + KEY_SIZE + CHALLENGE_SIZE;
    if (input.length() != ((content + 7) & ~size_t(7))
        || !crypto::ConstantTimeEqual(input.take(name.length()), name)
        || !crypto::ConstantTimeEqual(input.skip(name.length() + KEY_SIZE).take(CHALLENGE_SIZE), challenge))
        return false;
    // Table A-11 does not prescribe padding values. RFC 3394 authenticates all
    // plaintext bytes; do not reject an authority's otherwise valid padding.
    std::memcpy(key, input.skip(name.length()), KEY_SIZE);
    guard.committed = true;
    return true;
}
}
}
