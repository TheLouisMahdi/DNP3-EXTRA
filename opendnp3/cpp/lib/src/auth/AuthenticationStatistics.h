// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_AUTHENTICATIONSTATISTICS_H
#define OPENDNP3_AUTHENTICATIONSTATISTICS_H

#include "opendnp3/auth/SecurityStatistic.h"

#include <memory>

namespace opendnp3
{
class Logger;
class IAuthenticationStatisticsReporter
{
public:
    virtual ~IAuthenticationStatisticsReporter() = default;
    // Synchronous occurrence notification. Copy into bounded storage only;
    // never transmit or reenter authentication. True means event accepted.
    virtual bool Report(SecurityStatistic statistic, uint32_t value, uint8_t flags) = 0;
};
// One bounded, serialized runtime per association. No protocol engine, wire
// publication, remote configuration, counter clearing or freezing.
class AuthenticationStatistics final
{
public:
    struct StaticSnapshot
    {
        SecurityStatisticValues values{};
        uint8_t flags = 0;
    };

    AuthenticationStatistics(uint16_t association, bool master, const SecurityStatisticThresholds& thresholds,
                             std::shared_ptr<IAuthenticationStatisticsStore> store = nullptr);
    AuthenticationStatistics(const AuthenticationStatistics&) = delete;
    AuthenticationStatistics& operator=(const AuthenticationStatistics&) = delete;
    void SetLogger(Logger* value) { logger = value; }
    void SetReporter(IAuthenticationStatisticsReporter* value, const SecurityStatisticThresholds& reportingThresholds);
    void Increment(SecurityStatistic statistic);
    void Unexpected(); // Table 7-8: unexpected input discarded, not pending ASDU.
    // owner must come from legitimate local protocol state, NEVER an unverified Reply USR.
    void AuthenticationFailed(uint16_t owner = 0);
    uint16_t RecoveryUser() const { return recoveryUser; }
    void CancelRecovery(uint16_t owner);
    void Disconnect(); // Clear pending actions/ownership, never totals or report baselines.
    void AuthenticationRekeyStarted();
    void KeyChangeTimeoutLimit(uint16_t owner);
    bool TakeKeyChangeTimeoutLimit(uint16_t& owner);
    uint32_t Value(SecurityStatistic statistic) const;
    const SecurityStatisticValues& Values() const { return values; }
    // One serialized Outstation READ owns this immutable view until the next
    // READ replaces it. No per-point database counters or event acknowledgments.
    const StaticSnapshot& CaptureStaticSnapshot();
    bool Retained() const { return retained; }
    bool ReportPending(SecurityStatistic statistic) const;
    void ReportGenerated(SecurityStatistic statistic, uint32_t reportedValue);
    void RequireReport(SecurityStatistic statistic);
    bool Exceeded(SecurityStatistic statistic) const;
    void ResetMaximum(SecurityStatistic statistic);
    uint32_t Maximum(SecurityStatistic statistic) const;
    void SessionKeysChanged();

private:
    static bool HasMaximum(SecurityStatistic statistic);
    void Publish(SecurityStatistic statistic);
    void Persist();
    const uint16_t association;
    const bool master;
    const SecurityStatisticThresholds thresholds;
    SecurityStatisticThresholds reportingThresholds;
    IAuthenticationStatisticsReporter* reporter = nullptr;
    const std::shared_ptr<IAuthenticationStatisticsStore> store;
    Logger* logger = nullptr;
    SecurityStatisticValues values{}, reported{}, maximumBases{}, maximumDistances{};
    StaticSnapshot staticSnapshot;
    uint32_t pendingReports = 0;
    uint16_t recoveryUser = 0;
    uint16_t timedOutUser = 0;
    bool timeoutLimitPending = false;
    bool loaded = false, retained = false;
};
} // namespace opendnp3
#endif
