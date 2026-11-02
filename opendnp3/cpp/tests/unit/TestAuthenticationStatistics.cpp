// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/AuthenticationStatistics.h"
#include "crypto/CryptoProvider.h"
#include "outstation/OutstationChallenger.h"
#include "opendnp3/auth/AuthenticationConfig.h"

#include <catch.hpp>

#include <limits>
#include <map>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace opendnp3;
namespace
{
struct StatisticStore final : IAuthenticationStatisticsStore
{
    std::map<std::pair<uint16_t, bool>, SecurityStatisticValues> snapshots;
    bool available = true, throws = false;
    bool Load(uint16_t association, bool master, SecurityStatisticValues& values) override
    {
        if (throws) throw std::runtime_error("retention unavailable");
        if (!available) return false;
        values = snapshots[std::make_pair(association, master)];
        return true;
    }
    bool Save(uint16_t association, bool master, const SecurityStatisticValues& values) override
    {
        if (throws) throw std::runtime_error("retention unavailable");
        if (!available) return false;
        snapshots[std::make_pair(association, master)] = values;
        return true;
    }
};
}
TEST_CASE("Security statistics - IEEE indexes and default thresholds", "[sa-statistics]")
{
    const std::array<SecurityStatistic, 18> indexes{{
        SecurityStatistic::UNEXPECTED_MESSAGES, SecurityStatistic::AUTHORIZATION_FAILURES,
        SecurityStatistic::AUTHENTICATION_FAILURES, SecurityStatistic::REPLY_TIMEOUTS,
        SecurityStatistic::AUTHENTICATION_REKEYS, SecurityStatistic::TOTAL_MESSAGES_SENT,
        SecurityStatistic::TOTAL_MESSAGES_RECEIVED, SecurityStatistic::CRITICAL_MESSAGES_SENT,
        SecurityStatistic::CRITICAL_MESSAGES_RECEIVED, SecurityStatistic::DISCARDED_MESSAGES,
        SecurityStatistic::ERROR_MESSAGES_SENT, SecurityStatistic::ERROR_MESSAGES_RECEIVED,
        SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS, SecurityStatistic::SESSION_KEY_CHANGES,
        SecurityStatistic::FAILED_SESSION_KEY_CHANGES, SecurityStatistic::UPDATE_KEY_CHANGES,
        SecurityStatistic::FAILED_UPDATE_KEY_CHANGES, SecurityStatistic::RESTART_REKEYS}};
    const SecurityStatisticThresholds defaults{{3, 5, 5, 3, 3, 100, 100, 100, 100, 10, 2, 10, 100, 10, 5, 1, 1, 3}};
    AuthenticationConfig config;
    REQUIRE(config.statisticThresholds == defaults);
    REQUIRE(config.maxRestartRekeys == 3);
    AuthenticationStatistics statistics(7, true, defaults);
    for (size_t n = 0; n < indexes.size(); ++n)
    {
        REQUIRE(static_cast<size_t>(indexes[n]) == n);
        REQUIRE(statistics.Value(indexes[n]) == 0);
    }
}
TEST_CASE("Security statistics - reporting equality and five independent moving maxima", "[sa-statistics]")
{
    AuthenticationConfig config;
    const auto index = GENERATE(SecurityStatistic::AUTHENTICATION_FAILURES, SecurityStatistic::REPLY_TIMEOUTS,
        SecurityStatistic::AUTHENTICATION_REKEYS, SecurityStatistic::ERROR_MESSAGES_SENT, SecurityStatistic::RESTART_REKEYS);
    AuthenticationStatistics statistics(7, true, config.statisticThresholds);
    const auto threshold = config.statisticThresholds[static_cast<size_t>(index)];
    for (unsigned n = 0; n < threshold; ++n) statistics.Increment(index);
    REQUIRE(statistics.ReportPending(index)); // P6-OPEN-01, reporting >=.
    REQUIRE_FALSE(statistics.Exceeded(index)); // Protocol >, not >=.
    statistics.ReportGenerated(index, threshold);
    REQUIRE_FALSE(statistics.ReportPending(index));
    statistics.Increment(index);
    REQUIRE(statistics.Exceeded(index));
    statistics.ResetMaximum(index);
    REQUIRE(statistics.Maximum(index) == 2u * threshold + 1u);
    REQUIRE_FALSE(statistics.Exceeded(index));
    REQUIRE(statistics.Value(index) == threshold + 1u);
}
TEST_CASE("Security statistics - accepted event snapshots preserve subsequent increments", "[sa-statistics]")
{
    auto thresholds = DefaultSecurityStatisticThresholds();
    thresholds[0] = GENERATE(uint16_t{0}, uint16_t{1});
    AuthenticationStatistics statistics(7, true, thresholds);
    REQUIRE_FALSE(statistics.ReportPending(SecurityStatistic::UNEXPECTED_MESSAGES));
    statistics.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    statistics.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    statistics.ReportGenerated(SecurityStatistic::UNEXPECTED_MESSAGES, 3); // Future value is never accepted.
    REQUIRE(statistics.ReportPending(SecurityStatistic::UNEXPECTED_MESSAGES));
    statistics.ReportGenerated(SecurityStatistic::UNEXPECTED_MESSAGES, 1);
    REQUIRE(statistics.ReportPending(SecurityStatistic::UNEXPECTED_MESSAGES));
    statistics.ReportGenerated(SecurityStatistic::UNEXPECTED_MESSAGES, 2);
    REQUIRE_FALSE(statistics.ReportPending(SecurityStatistic::UNEXPECTED_MESSAGES));
}
TEST_CASE("Security statistics - uint32 rollover and device restart retention", "[sa-statistics]")
{
    auto store = std::make_shared<StatisticStore>();
    store->snapshots[{7, true}][10] = std::numeric_limits<uint32_t>::max() - 1;
    {
        AuthenticationStatistics statistics(7, true, DefaultSecurityStatisticThresholds(), store);
        REQUIRE(statistics.Retained());
        for (unsigned n = 0; n < 3; ++n) statistics.Increment(SecurityStatistic::ERROR_MESSAGES_SENT);
        REQUIRE(statistics.Value(SecurityStatistic::ERROR_MESSAGES_SENT) == 1);
        REQUIRE(statistics.ReportPending(SecurityStatistic::ERROR_MESSAGES_SENT));
        REQUIRE(statistics.Exceeded(SecurityStatistic::ERROR_MESSAGES_SENT));
        statistics.ReportGenerated(SecurityStatistic::ERROR_MESSAGES_SENT, 1);
        REQUIRE(statistics.Exceeded(SecurityStatistic::ERROR_MESSAGES_SENT));
    }
    AuthenticationStatistics restarted(7, true, DefaultSecurityStatisticThresholds(), store);
    REQUIRE(restarted.Value(SecurityStatistic::ERROR_MESSAGES_SENT) == 1);
    REQUIRE_FALSE(restarted.Exceeded(SecurityStatistic::ERROR_MESSAGES_SENT)); // Startup rearms Max only.
}
TEST_CASE("Security statistics - associations and roles are isolated", "[sa-statistics]")
{
    auto store = std::make_shared<StatisticStore>();
    store->snapshots[{7, false}][17] = 123; // Even invalid persisted O index 17 cannot escape as nonzero.
    AuthenticationStatistics master(7, true, DefaultSecurityStatisticThresholds(), store);
    AuthenticationStatistics other(8, true, DefaultSecurityStatisticThresholds(), store);
    AuthenticationStatistics outstation(7, false, DefaultSecurityStatisticThresholds(), store);
    master.Increment(SecurityStatistic::RESTART_REKEYS);
    outstation.Increment(SecurityStatistic::RESTART_REKEYS);
    REQUIRE(master.Value(SecurityStatistic::RESTART_REKEYS) == 1);
    REQUIRE(other.Value(SecurityStatistic::RESTART_REKEYS) == 0);
    REQUIRE(outstation.Value(SecurityStatistic::RESTART_REKEYS) == 0);
    REQUIRE_FALSE(outstation.ReportPending(SecurityStatistic::RESTART_REKEYS));
}
TEST_CASE("Security statistics - retention failure is visible without overwriting unread totals", "[sa-statistics]")
{
    auto store = std::make_shared<StatisticStore>();
    store->snapshots[{7, true}][0] = 17;
    store->throws = GENERATE(false, true);
    store->available = false;
    AuthenticationStatistics statistics(7, true, DefaultSecurityStatisticThresholds(), store);
    REQUIRE_FALSE(statistics.Retained());
    store->available = true;
    store->throws = false;
    statistics.Unexpected();
    REQUIRE(store->snapshots.at({7, true})[0] == 17);
}
TEST_CASE("Security statistics - unknown failures never invent recovery ownership or key changes", "[sa-statistics]")
{
    AuthenticationStatistics statistics(7, false, DefaultSecurityStatisticThresholds());
    for (unsigned n = 0; n < 6; ++n) statistics.AuthenticationFailed();
    REQUIRE(statistics.Exceeded(SecurityStatistic::AUTHENTICATION_FAILURES));
    REQUIRE(statistics.RecoveryUser() == 0);
    REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_REKEYS) == 0);
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == 0);
    statistics.SessionKeysChanged();
    REQUIRE(statistics.ReportPending(SecurityStatistic::AUTHENTICATION_FAILURES));
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == 1);
    REQUIRE(statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 0);
}

TEST_CASE("Security statistics - storage failures retain RAM accounting and recover the complete snapshot", "[sa-statistics]")
{
    auto store = std::make_shared<StatisticStore>();
    AuthenticationStatistics statistics(7, true, DefaultSecurityStatisticThresholds(), store);
    store->throws = true;
    statistics.Unexpected();
    REQUIRE_FALSE(statistics.Retained());
    REQUIRE(statistics.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == 1);
    REQUIRE(statistics.Value(SecurityStatistic::DISCARDED_MESSAGES) == 1);
    store->throws = false;
    statistics.Increment(SecurityStatistic::TOTAL_MESSAGES_RECEIVED);
    REQUIRE(statistics.Retained());
    REQUIRE(store->snapshots.at({7, true}) == statistics.Values());
}

TEST_CASE("Security statistics - successful control authentication requires accepted output", "[sa-statistics]")
{
    AuthenticationStatistics statistics(7, false, DefaultSecurityStatisticThresholds());
    OutstationChallenger challenger(7);
    challenger.SetStatistics(&statistics);

    std::array<uint8_t, 32> key{};
    key.fill(0x11);
    REQUIRE(challenger.SetSessionKey(1, ser4cpp::rseq_t(key.data(), key.size()), 100000, 1000)
            == OutstationChallenger::Result::OK);
    const std::array<uint8_t, 2> request{{0xC1, 0x05}};
    std::array<uint8_t, OutstationChallenger::CHALLENGE_SIZE> challenge{};
    std::array<uint8_t, 16> tag{};
    size_t challengeSize = 0;
    size_t outputSize = 0;

    auto buildReply = [&](uint64_t now) {
        REQUIRE(challenger.Challenge(7, ser4cpp::rseq_t(request.data(), request.size()),
                                   IINField(0, 0), now, ser4cpp::wseq_t(challenge.data(), challenge.size()),
                                   challengeSize) == OutstationChallenger::Result::OK);
        REQUIRE(challengeSize == challenge.size());
        Group120Var1 parsed;
        REQUIRE(parsed.Read(ser4cpp::rseq_t(challenge.data(), challenge.size()).skip(10)));
        std::vector<uint8_t> transcript(challenge.begin(), challenge.end());
        transcript.insert(transcript.end(), request.begin(), request.end());
        REQUIRE(crypto::ComputeHMACSHA256(ser4cpp::rseq_t(key.data(), key.size()),
                                          ser4cpp::rseq_t(transcript.data(), transcript.size()),
                                          ser4cpp::wseq_t(tag.data(), tag.size())) == crypto::Result::OK);
        return parsed.seqNum;
    };

    const auto firstSequence = buildReply(1000);
    REQUIRE(challenger.Reply(7, Group120Var2(firstSequence, 1, ser4cpp::rseq_t(tag.data(), tag.size())),
                             1001, ser4cpp::wseq_t(nullptr, 0), outputSize)
            == OutstationChallenger::Result::OUTPUT_TOO_SMALL);
    REQUIRE(statistics.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == 0);

    const auto secondSequence = buildReply(1002);
    std::array<uint8_t, 2> accepted{};
    REQUIRE(challenger.Reply(7, Group120Var2(secondSequence, 1, ser4cpp::rseq_t(tag.data(), tag.size())),
                             1003, ser4cpp::wseq_t(accepted.data(), accepted.size()), outputSize)
            == OutstationChallenger::Result::AUTHENTICATED);
    REQUIRE(outputSize == request.size());
    REQUIRE(accepted == request);
    REQUIRE(statistics.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == 1);
}

TEST_CASE("Security statistics - challenger busy preserves pending exchange", "[sa-statistics]")
{
    AuthenticationStatistics statistics(7, false, DefaultSecurityStatisticThresholds());
    OutstationChallenger challenger(7);
    challenger.SetStatistics(&statistics);

    const std::array<uint8_t, 2> request{{0xC1, 0x05}};
    std::array<uint8_t, OutstationChallenger::CHALLENGE_SIZE> output{};
    size_t length = 0;
    REQUIRE(challenger.Challenge(7, ser4cpp::rseq_t(request.data(), request.size()), IINField(0, 0), 1000,
                                 ser4cpp::wseq_t(output.data(), output.size()), length)
            == OutstationChallenger::Result::OK);
    REQUIRE(challenger.GetState() == OutstationChallenger::State::WAITING_FOR_REPLY);

    // A second critical request is discarded, not exchanged for the first.
    REQUIRE(challenger.Challenge(7, ser4cpp::rseq_t(request.data(), request.size()), IINField(0, 0), 1001,
                                 ser4cpp::wseq_t(output.data(), output.size()), length)
            == OutstationChallenger::Result::BUSY);
    REQUIRE(challenger.GetState() == OutstationChallenger::State::WAITING_FOR_REPLY);
    REQUIRE(statistics.Value(SecurityStatistic::CRITICAL_MESSAGES_RECEIVED) == 1);
    REQUIRE(statistics.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == 1);
    REQUIRE(statistics.Value(SecurityStatistic::DISCARDED_MESSAGES) == 1);
}
