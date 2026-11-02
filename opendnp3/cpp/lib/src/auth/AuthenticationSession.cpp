// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/AuthenticationSession.h"

#include "auth/AuthenticationMAC.h"
#include "crypto/CryptoProvider.h"

#include <limits>

namespace opendnp3
{
namespace
{
    SecurityStatisticThresholds StatisticThresholds(const AuthenticationConfig& config)
    {
        auto result = config.statisticThresholds;
        if (config.maxErrorMessagesSent != 2) result[10] = config.maxErrorMessagesSent;
        if (config.maxRestartRekeys != 3) result[17] = config.maxRestartRekeys;
        return result;
    }
}
AuthenticationSession::AuthenticationSession(SessionKeys::Role role, const AuthenticationConfig& config_)
    : config(config_), statistics(config.association, role == SessionKeys::Role::MASTER,
                                 StatisticThresholds(config), config.statisticsStore)
{
    SessionKeys::Config settings;
    settings.intervalMs = config.renewalIntervalMs;
    settings.messageLimit = config.renewalMessageCount;
    settings.replyTimeoutMs = config.replyTimeoutMs;
    settings.tagLength = config.tagLength;
    settings.macAlgorithm = config.macAlgorithm;
    settings.keyWrapAlgorithm = config.keyWrapAlgorithm;
    for (size_t n = 0; n < sessions.size(); ++n)
    {
        sessions[n].reset(new SessionKeys(role, config.association, config.users[n], settings));
        sessions[n]->SetStatistics(&statistics);
    }
}
bool AuthenticationSession::Load(uint64_t now)
{
    for (auto& entry : sessions)
        entry->Reset();
    AuthenticationMACPolicy mac(ResolveAuthenticationMAC(config.macAlgorithm, config.tagLength));
    if (!mac.Configure(config) || config.mode != AuthenticationConfig::Mode::REQUIRED
        || (config.maxErrorMessagesSent != 2 && config.statisticThresholds[10] != 2
            && config.maxErrorMessagesSent != config.statisticThresholds[10])
        || (config.maxRestartRekeys != 3 && config.statisticThresholds[17] != 3
            && config.maxRestartRekeys != config.statisticThresholds[17])
        || !config.credentials || !config.authorization
        || config.users[0] != 1 || !config.users[1] || config.users[0] == config.users[1])
        return false;
    struct Key
    {
        std::array<uint8_t, 32> bytes{};
        ~Key()
        {
            crypto::Clear(ser4cpp::wseq_t(bytes.data(), bytes.size()));
        }
    };
    Key previous;
    bool havePrevious = false;
    bool loaded = true;
    try
    {
        for (auto& entry : sessions)
        {
            Key key;
            uint64_t lifetime = 0;
            const size_t keyLength = config.keyWrapAlgorithm == 1 ? 16 : 32;
            if (!config.credentials->ReadUpdateKey(config.association, entry->User(), key.bytes.data(), keyLength,
                                                   lifetime)
                || (havePrevious
                    && crypto::ConstantTimeEqual(ser4cpp::rseq_t(previous.bytes.data(), keyLength),
                                                 ser4cpp::rseq_t(key.bytes.data(), keyLength)))
                || !lifetime || lifetime > std::numeric_limits<uint64_t>::max() - now
                || entry->Configure(ser4cpp::rseq_t(key.bytes.data(), keyLength), now + lifetime, now)
                    != SessionKeys::Result::OK)
            {
                loaded = false;
                break;
            }
            previous.bytes = key.bytes;
            havePrevious = true;
        }
    }
    catch (...)
    {
        loaded = false;
    }
    if (!loaded)
        for (auto& entry : sessions)
            entry->Reset();
    return loaded;
}
SessionKeys* AuthenticationSession::Find(uint16_t user)
{
    for (auto& entry : sessions)
        if (entry->User() == user)
            return entry.get();
    return nullptr;
}
SessionKeys* AuthenticationSession::At(size_t index)
{
    return index < sessions.size() ? sessions[index].get() : nullptr;
}
bool AuthenticationSession::Authorize(uint16_t user, uint8_t function, uint64_t now, ser4cpp::rseq_t request) const
{
    if (!config.authorization)
        return false;
    try
    {
        for (const auto& entry : sessions)
            if (entry->User() == user && entry->Ready(now))
                return config.authorization->IsAuthorized(config.association, user, function, request,
                                                          request.length());
    }
    catch (...)
    {
    }
    return false;
}
void AuthenticationSession::Disconnect()
{
    for (auto& entry : sessions)
        entry->Disconnect();
    statistics.Disconnect(); // Communication failure, Table 7-8 rows 8/9; no stale recovery owner on reconnect.
}
} // namespace opendnp3
