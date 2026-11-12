// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/AuthenticationSession.h"
#include "crypto/CryptoProvider.h"
#include "utils/AcceptanceObservation.h"

#include "opendnp3/auth/WindowsAuthenticationCredentials.h"

#include <catch.hpp>

#include <algorithm>
#include <array>
#include <stdexcept>

using namespace opendnp3;
using namespace ser4cpp;
namespace
{
struct Credentials final : IAuthenticationCredentials
{
    std::array<std::array<uint8_t, 32>, 2> keys{};
    bool missing = false, throws = false, duplicate = false;
    uint64_t expiry = 10000000;
    Credentials()
    {
        for (auto& k : keys)
            REQUIRE(crypto::GenerateRandom(wseq_t(k.data(), k.size())) == crypto::Result::OK);
    }
    ~Credentials()
    {
        for (auto& k : keys)
            crypto::Clear(wseq_t(k.data(), k.size()));
    }
    bool ReadUpdateKey(
        uint16_t association, uint16_t user, uint8_t* output, size_t capacity, uint64_t& lifetime) override
    {
        if (throws)
            throw std::runtime_error("credential unavailable");
        if (missing || association != 7 || user < 1 || user > 2 || capacity != 32)
            return false;
        const auto& k = keys[duplicate ? 0 : user - 1];
        std::copy(k.begin(), k.end(), output);
        lifetime = expiry;
        return true;
    }
};
struct Authorization final : IAuthenticationAuthorization
{
    bool throws = false;
    bool IsAuthorized(uint16_t association, uint16_t user, uint8_t function, const uint8_t*, size_t) const override
    {
        if (throws)
            throw std::runtime_error("policy unavailable");
        return association == 7 && ((user == 1 && function == 2) || (user == 2 && (function == 3 || function == 4)));
    }
};
AuthenticationConfig Config(const std::shared_ptr<Credentials>& source, const std::shared_ptr<Authorization>& policy)
{
    AuthenticationConfig c;
    c.association = 7;
    c.credentials = source;
    c.authorization = policy;
    return c;
}
void Exchange(SessionKeys& master, SessionKeys& outstation, uint64_t now = 1000)
{
    std::array<uint8_t, 2048> a{}, b{};
    size_t na = 0, nb = 0;
    REQUIRE(master.Begin(7, 0, now, wseq_t(a.data(), a.size()), na) == SessionKeys::Result::OK);
    REQUIRE(outstation.Process(7, rseq_t(a.data(), na), now, wseq_t(b.data(), b.size()), nb)
            == SessionKeys::Result::OK);
    REQUIRE(master.Process(7, rseq_t(b.data(), nb), now, wseq_t(a.data(), a.size()), na) == SessionKeys::Result::OK);
    REQUIRE(outstation.Process(7, rseq_t(a.data(), na), now, wseq_t(b.data(), b.size()), nb)
            == SessionKeys::Result::INSTALLED);
    REQUIRE(master.Process(7, rseq_t(b.data(), nb), now, wseq_t(a.data(), a.size()), na)
            == SessionKeys::Result::INSTALLED);
    crypto::Clear(wseq_t(a.data(), a.size()));
    crypto::Clear(wseq_t(b.data(), b.size()));
}
} // namespace
TEST_CASE("AuthenticationConfig - credentials cannot grant authorization before exchange", "[auth-config]")
{
    auto source = std::make_shared<Credentials>();
    auto policy = std::make_shared<Authorization>();
    const auto config = Config(source, policy);
    REQUIRE(config.mode == AuthenticationConfig::Mode::REQUIRED);
    REQUIRE_FALSE(config.aggressiveTransmit);
    REQUIRE_FALSE(config.aggressiveReceive);
    AuthenticationSession master(SessionKeys::Role::MASTER, config), outstation(SessionKeys::Role::OUTSTATION, config);
    REQUIRE(master.Load(1000));
    REQUIRE(outstation.Load(1000));
    REQUIRE_FALSE(outstation.Authorize(2, 3, 1000));
    REQUIRE(outstation.Find(3) == nullptr);
    REQUIRE(outstation.At(2) == nullptr);
    Exchange(*master.Find(1), *outstation.Find(1));
    Exchange(*master.Find(2), *outstation.Find(2));
    REQUIRE(outstation.Authorize(1, 2, 1000));
    REQUIRE_FALSE(outstation.Authorize(1, 3, 1000));
    REQUIRE(outstation.Authorize(2, 3, 1000));
    REQUIRE(outstation.Authorize(2, 4, 1000));
    REQUIRE_FALSE(outstation.Authorize(2, 2, 1000));
    REQUIRE_FALSE(outstation.Authorize(3, 3, 1000));
    REQUIRE_FALSE(crypto::ConstantTimeEqual(master.Find(1)->ControlKey(1000), master.Find(2)->ControlKey(1000)));
    policy->throws = true;
    REQUIRE_FALSE(outstation.Authorize(2, 3, 1000));
    policy->throws = false;
    outstation.Disconnect();
    REQUIRE_FALSE(outstation.Authorize(2, 3, 1000));
    REQUIRE_FALSE(outstation.Authorize(1, 2, 1000));
}
TEST_CASE("AuthenticationConfig - missing invalid expired or duplicate credentials fail closed", "[auth-config]")
{
    auto source = std::make_shared<Credentials>();
    auto policy = std::make_shared<Authorization>();
    auto config = Config(source, policy);
    const auto failure = GENERATE(0, 1, 2, 3, 4, 5, 6, 7, 8);
    if (failure == 0)
        config.credentials.reset();
    if (failure == 1)
        config.authorization.reset();
    if (failure == 2)
        source->missing = true;
    if (failure == 3)
        source->throws = true;
    if (failure == 4)
        source->duplicate = true;
    if (failure == 5)
        source->expiry = 0;
    if (failure == 6)
        config.users[1] = config.users[0];
    if (failure == 7)
        config.users[0] = 0;
    if (failure == 8)
        config.mode = AuthenticationConfig::Mode::COMPATIBILITY;
    AuthenticationSession master(SessionKeys::Role::MASTER, config);
    REQUIRE_FALSE(master.Load(1000));
    for (size_t n = 0; n < 2; ++n)
    {
        REQUIRE_FALSE(master.At(n)->NeedsExchange(1000));
        REQUIRE(master.At(n)->ControlKey(1000).is_empty());
    }
}
#ifdef _WIN32
TEST_CASE("AuthenticationConfig - Windows credential adapter has no fallback", "[auth-config]")
{
    WindowsAuthenticationCredentials missing(L"DNP3-EXTRA-unittest-no-provisioned-credential-c57e27ce");
    std::array<uint8_t, 32> key;
    key.fill(0xCC);
    uint64_t lifetime = 1;
    REQUIRE_FALSE(missing.ReadUpdateKey(7, 2, key.data(), key.size(), lifetime));
    REQUIRE(lifetime == 0);
    for (auto byte : key)
        REQUIRE(byte == 0);
    REQUIRE_FALSE(missing.ReadUpdateKey(7, 2, nullptr, 32, lifetime));
    WindowsAuthenticationCredentials empty(L"");
    REQUIRE_FALSE(empty.ReadUpdateKey(7, 2, key.data(), key.size(), lifetime));
}
#endif

TEST_CASE("AuthenticationConfig - MAC alternatives require explicit supported transport policy", "[auth-config][auth-error]")
{
    auto source = std::make_shared<Credentials>();
    auto authorization = std::make_shared<Authorization>();
    auto config = Config(source, authorization);
    const auto condition = GENERATE(0, 1, 2, 3, 4, 5, 6, 7);
    config.permittedMACAlgorithms = {{4, 2, 0, 0}};
    if (condition == 1) config.permittedMACAlgorithms = {{4, 3, 0, 0}}; // Serial truncation on TCP is prohibited.
    if (condition == 2) config.permittedMACAlgorithms = {{4, 6, 0, 0}}; // Optional GMAC is not implemented.
    if (condition == 3) config.permittedMACAlgorithms = {{4, 4, 0, 0}};
    if (condition == 4) config.permittedMACAlgorithms = {{4, 0, 2, 0}};
    if (condition == 5) config.permittedMACAlgorithms = {{2, 4, 0, 0}}; // Must start at the configured MAC.
    if (condition == 6) config.permittedMACAlgorithms = {{4, 1, 0, 0}}; // Obsolete SHA-1/4.
    if (condition == 7)
    {
        config.transport = AuthenticationConfig::Transport::SERIAL;
        config.permittedMACAlgorithms = {{4, 3, 2, 5}};
    }
    AuthenticationSession session(SessionKeys::Role::MASTER, config);
    REQUIRE(session.Load(1000) == (condition == 0 || condition == 7));
}

TEST_CASE("AuthenticationConfig - runtime zero timeout loads but never supplies session keys",
          "[sa-reply-timeout][sa-zero-runtime]")
{
    auto source = std::make_shared<Credentials>();
    auto policy = std::make_shared<Authorization>();
    auto config = Config(source, policy);
    config.replyTimeoutMs = 0;
    const auto role = GENERATE(SessionKeys::Role::MASTER, SessionKeys::Role::OUTSTATION);
    AuthenticationSession session(role, config);
    REQUIRE(session.Load(0));
    REQUIRE_FALSE(session.At(0)->Ready(0));
    REQUIRE_FALSE(session.At(1)->Ready(0));
}

TEST_CASE("AuthenticationConfig - zero retains credential and range validation", "[sa-zero-runtime]")
{
    auto source = std::make_shared<Credentials>();
    auto policy = std::make_shared<Authorization>();
    auto config = Config(source, policy);
    config.replyTimeoutMs = 0;
    config.credentials.reset();
    AuthenticationSession absent(SessionKeys::Role::MASTER, config);
    REQUIRE_FALSE(absent.Load(0));
    config.credentials = source;
    config.replyTimeoutMs = 1;
    AuthenticationSession invalid(SessionKeys::Role::MASTER, config);
    REQUIRE_FALSE(invalid.Load(0));
}

TEST_CASE("AuthenticationConfig - renewal defaults and per-user settings survive real exchanges", "[auth-config][sa-renewal]")
{
    REQUIRE(AuthenticationConfig().renewalIntervalMs == 900000);
    REQUIRE(AuthenticationConfig().renewalMessageCount == 1000);
    auto source = std::make_shared<Credentials>();
    auto policy = std::make_shared<Authorization>();
    auto config = Config(source, policy);
    config.renewalIntervalMs = GENERATE(0u, 1000u, 900000u, 7200000u);
    config.renewalMessageCount = GENERATE(1u, 1000u, 2000u);
    AuthenticationSession master(SessionKeys::Role::MASTER, config), outstation(SessionKeys::Role::OUTSTATION, config);
    REQUIRE(master.Load(1000));
    REQUIRE(outstation.Load(1000));
    const uint64_t credentialDeadline = 1000 + source->expiry;
    for (uint16_t user : {uint16_t(1), uint16_t(2)})
    {
        Exchange(*master.Find(user), *outstation.Find(user));
        for (auto* engine : {master.Find(user), outstation.Find(user)})
        {
            REQUIRE(engine->RemainingMessages() == config.renewalMessageCount);
            REQUIRE(engine->ValidUntil() == (config.renewalIntervalMs
                ? std::min<uint64_t>(credentialDeadline, 1000ULL + config.renewalIntervalMs) : credentialDeadline));
        }
    }
    master.Find(1)->CountAuthentication(1000);
    REQUIRE(master.Find(1)->RemainingMessages() == config.renewalMessageCount - 1);
    REQUIRE(master.Find(2)->RemainingMessages() == config.renewalMessageCount);
    REQUIRE(outstation.Find(1)->RemainingMessages() == config.renewalMessageCount);
    REQUIRE(outstation.Find(2)->RemainingMessages() == config.renewalMessageCount);
}

TEST_CASE("AuthenticationConfig - invalid renewal settings fail closed for both roles", "[auth-config][sa-renewal]")
{
    auto source = std::make_shared<Credentials>();
    auto policy = std::make_shared<Authorization>();
    auto config = Config(source, policy);
    const auto invalid = GENERATE(0, 1, 2, 3, 4);
    if (invalid == 0) config.renewalIntervalMs = 999;
    if (invalid == 1) config.renewalIntervalMs = 900001;
    if (invalid == 2) config.renewalIntervalMs = 7200001;
    if (invalid == 3) config.renewalMessageCount = 0;
    if (invalid == 4) config.renewalMessageCount = 0x80000000u;
    const auto role = GENERATE(SessionKeys::Role::MASTER, SessionKeys::Role::OUTSTATION);
    AuthenticationSession session(role, config);
    REQUIRE_FALSE(session.Load(1000));
    REQUIRE_FALSE(session.Find(1)->Ready(1000));
    REQUIRE_FALSE(session.Find(2)->Ready(1000));
}


TEST_CASE("AT-SEC-T1-07-CONFIG", "[rtu-acceptance][auth-config][sa-renewal]")
{
    const std::array<uint32_t, 7> intervals{{900000, 7200000, 901000, 899999, 7200001, 0, 899000}};
    for (size_t i = 0; i < intervals.size(); ++i)
    {
        if (!acceptance::Selected(("V" + std::to_string(i + 1)).c_str())) continue;
        auto source = std::make_shared<Credentials>();
        auto config = Config(source, std::make_shared<Authorization>());
        config.renewalIntervalMs = intervals[i];
        AuthenticationSession master(SessionKeys::Role::MASTER, config), outstation(SessionKeys::Role::OUTSTATION, config);
        const auto masterLoaded = master.Load(1000);
        const auto outstationLoaded = outstation.Load(1000);
        const bool accepted = i != 3 && i != 4;
        REQUIRE(masterLoaded == accepted);
        REQUIRE(outstationLoaded == accepted);
        acceptance::Observe("loaded_roles", unsigned(masterLoaded) + unsigned(outstationLoaded));
        if (!accepted)
        {
            REQUIRE_FALSE(master.Find(2)->Ready(1000));
            REQUIRE_FALSE(outstation.Find(2)->Ready(1000));
            REQUIRE_FALSE(outstation.Authorize(2, 3, 1000));
            continue;
        }
        Exchange(*master.Find(2), *outstation.Find(2));
        const uint64_t lifetime = intervals[i] ? intervals[i] : source->expiry;
        REQUIRE(master.Find(2)->ValidUntil() == 1000 + lifetime);
        REQUIRE(outstation.Find(2)->ValidUntil() == 1000 + lifetime);
        REQUIRE(outstation.Authorize(2, 3, 1000 + lifetime - 1));
        REQUIRE_FALSE(outstation.Authorize(2, 3, 1000 + lifetime));
        acceptance::Observe("session_lifetime_ms", master.Find(2)->ValidUntil() - 1000);
    }
}

TEST_CASE("AT-SEC-T1-07-ISOLATION", "[rtu-acceptance][auth-config][sa-renewal]")
{
    auto masterConfig = Config(std::make_shared<Credentials>(), std::make_shared<Authorization>());
    auto outstationConfig = masterConfig;
    masterConfig.renewalIntervalMs = 901000;
    outstationConfig.renewalIntervalMs = 900000;
    AuthenticationSession master(SessionKeys::Role::MASTER, masterConfig), outstation(SessionKeys::Role::OUTSTATION, outstationConfig);
    REQUIRE(master.Load(1000));
    REQUIRE(outstation.Load(1000));
    Exchange(*master.Find(1), *outstation.Find(1), 1000);
    Exchange(*master.Find(2), *outstation.Find(2), 1600);
    const auto masterOtherEpoch = master.Find(2)->Sequence();
    const auto outstationOtherEpoch = outstation.Find(2)->Sequence();
    const auto originalCommonEpoch = master.Find(1)->Sequence();
    REQUIRE(master.Find(1)->ValidUntil() == 902000);
    REQUIRE(outstation.Find(1)->ValidUntil() == 901000);
    REQUIRE(master.Find(2)->ValidUntil() == 902600);
    REQUIRE(outstation.Find(2)->ValidUntil() == 901600);

    REQUIRE(outstation.Authorize(1, 2, 900999));
    REQUIRE_FALSE(outstation.Authorize(1, 2, 901000));
    REQUIRE(master.Find(1)->Ready(901000));
    REQUIRE(outstation.Authorize(2, 3, 901000));
    master.Find(1)->RequestRenewal(901000);
    Exchange(*master.Find(1), *outstation.Find(1), 901000);
    REQUIRE(master.Find(2)->Sequence() == masterOtherEpoch);
    REQUIRE(outstation.Find(2)->Sequence() == outstationOtherEpoch);
    REQUIRE(master.Find(1)->Sequence() != originalCommonEpoch);
    REQUIRE(outstation.Authorize(1, 2, 901600));
    acceptance::Observe("other_user_deadline", outstation.Find(2)->ValidUntil());
    REQUIRE_FALSE(outstation.Authorize(2, 3, 901600));
    acceptance::Observe("changed_user_epochs", unsigned(master.Find(1)->Sequence() != originalCommonEpoch)
                                                  + unsigned(master.Find(2)->Sequence() != masterOtherEpoch));

    master.Disconnect();
    outstation.Disconnect();
    REQUIRE_FALSE(outstation.Authorize(1, 2, 901600));
    REQUIRE_FALSE(outstation.Authorize(2, 3, 901600));
    Exchange(*master.Find(2), *outstation.Find(2), 901601);
    REQUIRE(outstation.Authorize(2, 3, 901601));
    REQUIRE_FALSE(outstation.Authorize(1, 2, 901601));
    acceptance::Observe("ready_users_after_reconnect", unsigned(outstation.Find(1)->Ready(901601))
                                                          + unsigned(outstation.Find(2)->Ready(901601)));
}
