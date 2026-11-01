// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_AUTHENTICATIONCONFIG_H
#define OPENDNP3_AUTHENTICATIONCONFIG_H
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace opendnp3
{
// Credential retrieval and authorization are separate trust boundaries. Implementations
// must be thread safe, must not log secrets, and must return false on unavailable data.
class IAuthenticationCredentials
{
public:
    virtual ~IAuthenticationCredentials() = default;
    // Write exactly capacity key bytes (16 for AES-128, 32 for AES-256) and
    // the remaining credential lifetime. No default or generated Update Key.
    // The library clears its caller-owned buffer after copying into the session store.
    virtual bool ReadUpdateKey(
        uint16_t association, uint16_t user, uint8_t* output, size_t capacity, uint64_t& validForMs) = 0;
};
class IAuthenticationAuthorization
{
public:
    virtual ~IAuthenticationAuthorization() = default;
    // Called only AFTER authentication, before dispatch. A true authentication
    // verdict alone never grants a role or permission. No implicit allow policy.
    virtual bool IsAuthorized(uint16_t association,
                              uint16_t user,
                              uint8_t function,
                              const uint8_t* requestAPDU,
                              size_t requestSize) const = 0;
};
struct AuthenticationConfig
{
    enum class Mode
    {
        REQUIRED,
        COMPATIBILITY
    };
    Mode mode = Mode::REQUIRED;
    uint16_t association = 1;
    std::array<uint16_t, 2> users{{1, 2}};
    uint32_t renewalIntervalMs = 900000;
    uint32_t renewalMessageCount = 1000;
    uint32_t replyTimeoutMs = 2000;
    uint8_t tagLength = 16;
    // Zero selects SHA-256 from tagLength. Explicit 2/5 enable legacy SHA-1.
    uint8_t macAlgorithm = 0;
    uint8_t keyWrapAlgorithm = 2;
    uint16_t maxRestartRekeys = 2;
    bool aggressiveTransmit = false;
    bool aggressiveReceive = false;
    std::shared_ptr<IAuthenticationCredentials> credentials;
    std::shared_ptr<IAuthenticationAuthorization> authorization;
};
} // namespace opendnp3
#endif
