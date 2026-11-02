// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/AuthenticationStatistics.h"
#include "logging/LogMacros.h"
#include "opendnp3/logging/LogLevels.h"
#include "opendnp3/logging/Logger.h"

#include <cstddef>
#include <utility>

namespace opendnp3
{
namespace
{
    size_t Index(SecurityStatistic statistic) { return static_cast<size_t>(statistic); }
}
AuthenticationStatistics::AuthenticationStatistics(uint16_t association_, bool master_,
    const SecurityStatisticThresholds& thresholds_, std::shared_ptr<IAuthenticationStatisticsStore> store_)
    : association(association_), master(master_), thresholds(thresholds_), store(std::move(store_))
{
    if (store)
    {
        SecurityStatisticValues snapshot{};
        try
        {
            retained = loaded = store->Load(association, master, snapshot);
            if (loaded) values = snapshot;
        }
        catch (...) {}
    }
    if (!master) values[Index(SecurityStatistic::RESTART_REKEYS)] = 0;
    reported = maximumBases = values; // Startup resets baselines, NOT retained totals.
}
bool AuthenticationStatistics::HasMaximum(SecurityStatistic statistic)
{
    return statistic == SecurityStatistic::AUTHENTICATION_FAILURES || statistic == SecurityStatistic::REPLY_TIMEOUTS
        || statistic == SecurityStatistic::AUTHENTICATION_REKEYS || statistic == SecurityStatistic::ERROR_MESSAGES_SENT
        || statistic == SecurityStatistic::RESTART_REKEYS;
}
const AuthenticationStatistics::StaticSnapshot& AuthenticationStatistics::CaptureStaticSnapshot()
{
    staticSnapshot.values = values;
    // A failed Save does not lose the still-live RAM history. A missing/failed
    // initial Load cannot establish continuity with pre-startup values. Keep DC
    // conservative: P6a has no per-point acquisition/transmission quality latch.
    staticSnapshot.flags = loaded ? 0x01 : 0x41;
    return staticSnapshot;
}
void AuthenticationStatistics::Persist()
{
    if (!store || !loaded) return; // Never overwrite unread totals with startup zeros.
    try { retained = store->Save(association, master, values); }
    catch (...) { retained = false; }
}
void AuthenticationStatistics::Increment(SecurityStatistic statistic)
{
    const auto n = Index(statistic);
    if (n >= values.size() || (!master && statistic == SecurityStatistic::RESTART_REKEYS)) return;
    ++values[n]; // Table 11-19: rollover to zero, no saturation/clearing.
    // P6-OPEN-01: provisionally use 7.6.1.4.2's >= for reporting only.
    if (values[n] - reported[n] >= thresholds[n]) pendingReports |= uint32_t(1) << n;
    // Capped distance keeps an exceeded Max latched through uint32 rollover.
    if (HasMaximum(statistic) && maximumDistances[n] <= thresholds[n]) ++maximumDistances[n];
    Persist();
    if (logger && (statistic == SecurityStatistic::UNEXPECTED_MESSAGES
                   || statistic == SecurityStatistic::AUTHORIZATION_FAILURES))
    {
        try
        {
            FORMAT_LOG_BLOCK((*logger), flags::WARN, "Security statistic: association=%u index=%u value=%u",
                             static_cast<unsigned>(association), static_cast<unsigned>(n), static_cast<unsigned>(values[n]));
        }
        catch (...) {} // A diagnostic backend must not interrupt accounting or rejection.
    }
}
void AuthenticationStatistics::Unexpected()
{
    Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    Increment(SecurityStatistic::DISCARDED_MESSAGES);
}
void AuthenticationStatistics::AuthenticationFailed(uint16_t owner)
{
    Increment(SecurityStatistic::AUTHENTICATION_FAILURES);
    if (Exceeded(SecurityStatistic::AUTHENTICATION_FAILURES) && owner) recoveryUser = owner;
}
void AuthenticationStatistics::AuthenticationRekeyStarted()
{
    Increment(SecurityStatistic::AUTHENTICATION_REKEYS); // Recovery initiated, NOT a successful key change.
    ResetMaximum(SecurityStatistic::AUTHENTICATION_FAILURES);
}
void AuthenticationStatistics::CancelRecovery(uint16_t owner)
{
    if (recoveryUser == owner) recoveryUser = 0;
}
void AuthenticationStatistics::Disconnect()
{
    recoveryUser = 0;
    timedOutUser = 0;
    timeoutLimitPending = false;
    ResetMaximum(SecurityStatistic::REPLY_TIMEOUTS);
}
void AuthenticationStatistics::KeyChangeTimeoutLimit(uint16_t owner)
{
    CancelRecovery(owner);
    Increment(SecurityStatistic::FAILED_SESSION_KEY_CHANGES);
    ResetMaximum(SecurityStatistic::REPLY_TIMEOUTS);
    timedOutUser = owner;
    timeoutLimitPending = true; // Runtime propagates the all-user communication failure once.
}
bool AuthenticationStatistics::TakeKeyChangeTimeoutLimit(uint16_t& owner)
{
    if (!timeoutLimitPending) return false;
    owner = timedOutUser;
    timeoutLimitPending = false;
    return true;
}
uint32_t AuthenticationStatistics::Value(SecurityStatistic statistic) const
{
    const auto n = Index(statistic);
    return n < values.size() ? values[n] : 0;
}
bool AuthenticationStatistics::ReportPending(SecurityStatistic statistic) const
{
    const auto n = Index(statistic);
    return n < values.size() && (pendingReports & (uint32_t(1) << n)) != 0;
}
void AuthenticationStatistics::RequireReport(SecurityStatistic statistic)
{
    const auto n = Index(statistic);
    if (n < values.size()) pendingReports |= uint32_t(1) << n;
}
void AuthenticationStatistics::ReportGenerated(SecurityStatistic statistic, uint32_t snapshot)
{
    const auto n = Index(statistic);
    // P6b acknowledges a snapshot only AFTER accepting its generated event.
    if (n >= values.size() || !ReportPending(statistic) || snapshot - reported[n] > values[n] - reported[n]) return;
    reported[n] = snapshot;
    pendingReports &= ~(uint32_t(1) << n);
    if (values[n] != snapshot && values[n] - snapshot >= thresholds[n]) pendingReports |= uint32_t(1) << n;
}
bool AuthenticationStatistics::Exceeded(SecurityStatistic statistic) const
{
    const auto n = Index(statistic);
    return n < values.size() && HasMaximum(statistic) && maximumDistances[n] > thresholds[n];
}
void AuthenticationStatistics::ResetMaximum(SecurityStatistic statistic)
{
    const auto n = Index(statistic);
    if (n >= values.size() || !HasMaximum(statistic)) return;
    maximumBases[n] = values[n];
    maximumDistances[n] = 0;
    if (statistic == SecurityStatistic::AUTHENTICATION_FAILURES) recoveryUser = 0;
}
uint32_t AuthenticationStatistics::Maximum(SecurityStatistic statistic) const
{
    const auto n = Index(statistic);
    return n < values.size() && HasMaximum(statistic) ? maximumBases[n] + thresholds[n] : 0;
}
void AuthenticationStatistics::SessionKeysChanged()
{
    Increment(SecurityStatistic::SESSION_KEY_CHANGES);
    RequireReport(SecurityStatistic::AUTHENTICATION_FAILURES); // Table 7-6, even below report threshold.
    ResetMaximum(SecurityStatistic::AUTHENTICATION_REKEYS);
    ResetMaximum(SecurityStatistic::ERROR_MESSAGES_SENT); // Table 7-6; Table 7-8 row 24 for Outstation.
    if (master) ResetMaximum(SecurityStatistic::AUTHENTICATION_FAILURES); // Table 7-13 row 3.
}
} // namespace opendnp3
