// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_WINDOWSAUTHENTICATIONCREDENTIALS_H
#define OPENDNP3_WINDOWSAUTHENTICATIONCREDENTIALS_H
#ifdef _WIN32
#include "opendnp3/auth/AuthenticationConfig.h"

#include <string>

namespace opendnp3
{
// Read-only Windows Credential Manager adapter. Provisioning is an external
// administrative operation. Target = configured prefix + "/association/user".
// Generic credential blob: exactly 16 or 32 key octets. Required credential attribute
// "DNP3_EXPIRES_UNIX_MS": eight little-endian octets (absolute UTC expiry).
// No fallback file, password, generated credential, write or global setting.
class WindowsAuthenticationCredentials final : public IAuthenticationCredentials
{
public:
    explicit WindowsAuthenticationCredentials(std::wstring targetPrefix);
    bool ReadUpdateKey(
        uint16_t association, uint16_t user, uint8_t* output, size_t capacity, uint64_t& validForMs) override;

private:
    const std::wstring targetPrefix;
};
} // namespace opendnp3
#endif
#endif
