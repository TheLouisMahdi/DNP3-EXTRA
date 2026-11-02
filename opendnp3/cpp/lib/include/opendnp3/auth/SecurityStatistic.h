// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_SECURITYSTATISTIC_H
#define OPENDNP3_SECURITYSTATISTIC_H

#include <array>
#include <cstdint>

namespace opendnp3
{
// IEEE 1815-2012 Table 7-6. Independent of ordinary DNP3 measurement counters.
enum class SecurityStatistic : uint8_t
{
    UNEXPECTED_MESSAGES = 0,
    AUTHORIZATION_FAILURES = 1,
    AUTHENTICATION_FAILURES = 2,
    REPLY_TIMEOUTS = 3,
    AUTHENTICATION_REKEYS = 4,
    TOTAL_MESSAGES_SENT = 5,
    TOTAL_MESSAGES_RECEIVED = 6,
    CRITICAL_MESSAGES_SENT = 7,
    CRITICAL_MESSAGES_RECEIVED = 8,
    DISCARDED_MESSAGES = 9,
    ERROR_MESSAGES_SENT = 10,
    ERROR_MESSAGES_RECEIVED = 11,
    SUCCESSFUL_AUTHENTICATIONS = 12,
    SESSION_KEY_CHANGES = 13,
    FAILED_SESSION_KEY_CHANGES = 14,
    UPDATE_KEY_CHANGES = 15,
    FAILED_UPDATE_KEY_CHANGES = 16,
    RESTART_REKEYS = 17
};
using SecurityStatisticValues = std::array<uint32_t, 18>;
using SecurityStatisticThresholds = std::array<uint16_t, 18>;
inline SecurityStatisticThresholds DefaultSecurityStatisticThresholds()
{
    return {{3, 5, 5, 3, 3, 100, 100, 100, 100, 10, 2, 10, 100, 10, 5, 1, 1, 3}};
}

// Table 11-19 requires durable retention. The application supplies the platform
// backend, isolated by association and local role. Each runtime serializes its
// calls; a shared backend must be thread safe and must not reenter a stack.
// Save atomically retains the entire snapshot; no secrets.
class IAuthenticationStatisticsStore
{
public:
    virtual ~IAuthenticationStatisticsStore() = default;
    // Return true with zeros for a NEW association; false means retention loss/
    // unavailability, never permission to overwrite unread retained statistics.
    virtual bool Load(uint16_t association, bool master, SecurityStatisticValues& values) = 0;
    virtual bool Save(uint16_t association, bool master, const SecurityStatisticValues& values) = 0;
};
} // namespace opendnp3
#endif
