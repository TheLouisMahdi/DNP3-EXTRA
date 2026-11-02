// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_AUTHENTICATIONCONFIG_H
#define OPENDNP3_AUTHENTICATIONCONFIG_H
#include "opendnp3/auth/SecurityStatistic.h"
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
// Diagnostics only. Internal Table 7-8 accounting is association-owned and does
// not depend on an observer being installed. No key material is exposed.
class IAuthenticationErrorObserver
{
public:
    virtual ~IAuthenticationErrorObserver() = default;
    virtual void OnErrorReceived(uint16_t association, uint16_t user, uint32_t sequence,
                                 uint8_t code, bool discardedPending) = 0;
    // Table 7-6: authorization denial (indexes 1/9), actual Error TX (index 10).
    // Default methods preserve existing observers.
    virtual void OnAuthorizationFailure(uint16_t, uint16_t, uint32_t) {}
    virtual void OnErrorSent(uint16_t, uint16_t, uint32_t, uint8_t) {}
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
    // Ordered permitted MACs, including the initial macAlgorithm first. Empty
    // preserves the single configured algorithm. SHA-1 requires explicit opt-in.
    // Alternatives may reduce tag strength: configure only an approved policy.
    std::array<uint8_t, 4> permittedMACAlgorithms{{0, 0, 0, 0}};
    enum class Transport { NETWORK, SERIAL };
    Transport transport = Transport::NETWORK;
    uint8_t keyWrapAlgorithm = 2;
    uint16_t maxRestartRekeys = 3;
    // Table 7-6/7-15: stop after Error Messages Sent EXCEEDS this threshold;
    // successful session-key change reopens the budget. Zero permits one Error.
    uint16_t maxErrorMessagesSent = 2;
    // Local-only thresholds. Legacy explicit Max settings above remain aliases
    // for indexes 17/10; contradictory explicit settings fail configuration.
    SecurityStatisticThresholds statisticThresholds = DefaultSecurityStatisticThresholds();
    std::shared_ptr<IAuthenticationStatisticsStore> statisticsStore;
    bool suppressAuthenticationErrors = false;
    bool aggressiveTransmit = false;
    bool aggressiveReceive = false;
    std::shared_ptr<IAuthenticationErrorObserver> errorObserver;
    std::shared_ptr<IAuthenticationCredentials> credentials;
    std::shared_ptr<IAuthenticationAuthorization> authorization;
};
} // namespace opendnp3
#endif
