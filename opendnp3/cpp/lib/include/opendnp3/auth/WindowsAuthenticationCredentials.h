// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_WINDOWSAUTHENTICATIONCREDENTIALS_H
#define OPENDNP3_WINDOWSAUTHENTICATIONCREDENTIALS_H
#ifdef _WIN32
#include "opendnp3/auth/UpdateKeyConfig.h"

#include <string>
#include <functional>
#include <mutex>

namespace opendnp3
{
// Windows Credential Manager adapter. Provisioning is an external
// administrative operation. Target = configured prefix + "/association/user".
// Generic credential blob: exactly 16 or 32 key octets. Required credential attribute
// "DNP3_EXPIRES_UNIX_MS": eight little-endian octets (absolute UTC expiry).
// Legacy 16/32-byte blobs remain supported. Remote records use two protected
// snapshots and a validated commit marker in the same Credential Manager namespace.
// A torn/missing referenced snapshot fails closed, never falls back to an older key.
class WindowsAuthenticationCredentials final : public IUpdateKeyCredentials
{
public:
    explicit WindowsAuthenticationCredentials(std::wstring targetPrefix,
        std::function<bool(uint64_t&)> trustedTime = {});
    bool ReadUpdateKey(
        uint16_t association, uint16_t user, uint8_t* output, size_t capacity, uint64_t& validForMs) override;
    bool TrustedUnixTimeMs(uint64_t& now) override;
    bool ReadUser(uint16_t association, size_t slot, UpdateKeyUser& user) override;
    bool WriteUser(uint16_t association, size_t slot, const UpdateKeyUser& user) override;

private:
    const std::wstring targetPrefix;
    const std::function<bool(uint64_t&)> trustedTime;
    std::mutex mutex;
};
} // namespace opendnp3
#endif
#endif
