// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/AuthenticationSession.h"
#include "crypto/CryptoProvider.h"

#include "opendnp3/auth/WindowsAuthenticationCredentials.h"

#include <catch.hpp>

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
void Exchange(SessionKeys& master, SessionKeys& outstation)
{
    std::array<uint8_t, 2048> a{}, b{};
    size_t na = 0, nb = 0;
    REQUIRE(master.Begin(7, 0, 1000, wseq_t(a.data(), a.size()), na) == SessionKeys::Result::OK);
    REQUIRE(outstation.Process(7, rseq_t(a.data(), na), 1000, wseq_t(b.data(), b.size()), nb)
            == SessionKeys::Result::OK);
    REQUIRE(master.Process(7, rseq_t(b.data(), nb), 1000, wseq_t(a.data(), a.size()), na) == SessionKeys::Result::OK);
    REQUIRE(outstation.Process(7, rseq_t(a.data(), na), 1000, wseq_t(b.data(), b.size()), nb)
            == SessionKeys::Result::INSTALLED);
    REQUIRE(master.Process(7, rseq_t(b.data(), nb), 1000, wseq_t(a.data(), a.size()), na)
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
