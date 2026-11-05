// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/SessionKeys.h"
#include "auth/AuthenticationStatistics.h"
#include "crypto/CryptoProvider.h"
#include "gen/objects/Group120.h"

#include <catch.hpp>
#include <openssl/crypto.h>
#include <openssl/provider.h>

#include <array>
#include <cstring>

using namespace opendnp3;
using namespace ser4cpp;
namespace
{
using R = SessionKeys::Result;
struct Packet
{
    std::array<uint8_t, 2048> bytes{};
    size_t size = 0;
    wseq_t Write()
    {
        return wseq_t(bytes.data(), bytes.size());
    }
    rseq_t Read() const
    {
        return rseq_t(bytes.data(), size);
    }
    ~Packet()
    {
        crypto::Clear(Write());
    }
};
struct KeyPair
{
    SessionKeys::Config config;
    SessionKeys master;
    SessionKeys outstation;
    std::array<uint8_t, 32> update{};
    Packet request, status, change, confirmation;
    uint64_t now = 1000;
    explicit KeyPair(SessionKeys::Config c = SessionKeys::Config(), uint16_t assoc = 7, uint16_t user = 2)
        : config(c),
          master(SessionKeys::Role::MASTER, assoc, user, c),
          outstation(SessionKeys::Role::OUTSTATION, assoc, user, c)
    {
        REQUIRE(crypto::GenerateRandom(wseq_t(update.data(), update.size())) == crypto::Result::OK);
        REQUIRE(master.Configure(rseq_t(update.data(), c.keyWrapAlgorithm == 1 ? 16 : 32), 10000000, now) == R::OK);
        REQUIRE(outstation.Configure(rseq_t(update.data(), c.keyWrapAlgorithm == 1 ? 16 : 32), 10000000, now) == R::OK);
    }
    ~KeyPair()
    {
        crypto::Clear(wseq_t(update.data(), update.size()));
    }
    void ToStatus(uint16_t assoc = 7)
    {
        REQUIRE(master.Begin(assoc, 3, now, request.Write(), request.size) == R::OK);
        REQUIRE(outstation.Process(assoc, request.Read(), now, status.Write(), status.size) == R::OK);
    }
    void ToChange(uint16_t assoc = 7)
    {
        ToStatus(assoc);
        REQUIRE(master.Process(assoc, status.Read(), now, change.Write(), change.size) == R::OK);
        REQUIRE_FALSE(master.Ready(now));
        REQUIRE(master.ControlKey(now).is_empty());
        REQUIRE(master.MonitoringKey(now).is_empty());
    }
    void Exchange(uint16_t assoc = 7)
    {
        ToChange(assoc);
        REQUIRE(outstation.Process(assoc, change.Read(), now, confirmation.Write(), confirmation.size) == R::INSTALLED);
        REQUIRE(master.Process(assoc, confirmation.Read(), now, request.Write(), request.size) == R::INSTALLED);
        REQUIRE(request.size == 0);
        REQUIRE(master.Ready(now));
        REQUIRE(outstation.Ready(now));
        REQUIRE(crypto::ConstantTimeEqual(master.ControlKey(now), outstation.ControlKey(now)));
        REQUIRE(crypto::ConstantTimeEqual(master.MonitoringKey(now), outstation.MonitoringKey(now)));
        REQUIRE_FALSE(crypto::ConstantTimeEqual(master.ControlKey(now), master.MonitoringKey(now)));
    }
};
} // namespace

TEST_CASE("SessionKeys - actual wrapped exchange and independent direction keys", "[session-keys]")
{
    SessionKeys::Config c;
    c.tagLength = GENERATE(8, 16);
    KeyPair pair(c);
    pair.Exchange();
    REQUIRE(pair.master.Sequence() == 2);
    REQUIRE(pair.outstation.Sequence() == 2);
    REQUIRE(pair.change.bytes[0] == 0xC3);
    REQUIRE(pair.change.bytes[1] == 0x20);
    REQUIRE(pair.change.bytes[2] == 120);
    REQUIRE(pair.change.bytes[3] == 6);
    REQUIRE(pair.change.bytes[4] == 0x5B);
    REQUIRE(pair.change.bytes[5] == 1);
    Group120Var6 change;
    REQUIRE(change.Read(pair.change.Read().skip(8)));
    REQUIRE(change.seqNum == 1);
    REQUIRE(change.userNum == 2);
    Packet plain;
    plain.size = change.keyWrapData.length() - 8;
    REQUIRE(crypto::AES256KeyUnwrap(rseq_t(pair.update.data(), 32), change.keyWrapData, plain.Write().take(plain.size))
            == crypto::Result::OK);
    REQUIRE(plain.bytes[0] == 32);
    REQUIRE(plain.bytes[1] == 0);
    REQUIRE(crypto::ConstantTimeEqual(plain.Read().skip(2).take(32), pair.master.ControlKey(pair.now)));
    REQUIRE(crypto::ConstantTimeEqual(plain.Read().skip(34).take(32), pair.master.MonitoringKey(pair.now)));
    Group120Var5 status;
    REQUIRE(status.Read(pair.status.Read().skip(10)));
    REQUIRE(crypto::ConstantTimeEqual(plain.Read().skip(66).take(status.Size()), pair.status.Read().skip(10)));
    REQUIRE(pair.master.ValidUntil() == pair.now + c.intervalMs);
}

TEST_CASE("SessionKeys - confirmation MAC sequence user and malformed traffic fail closed", "[session-keys]")
{
    AuthenticationStatistics statistics(7, true, DefaultSecurityStatisticThresholds());
    KeyPair pair;
    pair.master.SetStatistics(&statistics);
    pair.ToChange();
    REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
            == R::INSTALLED);
    const auto mutation = GENERATE(0, 1, 2, 3, 4, 5);
    if (mutation == 0)
        pair.confirmation.bytes[pair.confirmation.size - 1] ^= 1;
    if (mutation == 1)
        pair.confirmation.bytes[10] ^= 1; // KSQ
    if (mutation == 2)
        pair.confirmation.bytes[14] ^= 1; // USR
    if (mutation == 3)
        pair.confirmation.bytes[18] = 3; // wrong MAL and tag size
    if (mutation == 4)
        --pair.confirmation.size;
    if (mutation == 5)
        pair.confirmation.bytes[16] = 1; // Unsupported wrap algorithm for this session.
    REQUIRE(pair.master.Process(7, pair.confirmation.Read(), pair.now, pair.request.Write(), pair.request.size)
            != R::INSTALLED);
    REQUIRE(statistics.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == 1);
    REQUIRE(statistics.Value(SecurityStatistic::DISCARDED_MESSAGES) == 1);
    REQUIRE_FALSE(pair.master.Ready(pair.now));
    REQUIRE(pair.master.ControlKey(pair.now).is_empty());
    REQUIRE(pair.request.size == 0);
    REQUIRE(pair.master.Process(7, pair.status.Read(), pair.now, pair.request.Write(), pair.request.size)
            != R::INSTALLED);
}

TEST_CASE("SessionKeys - wrong Update Key and damaged wrap cannot install keys", "[session-keys]")
{
    KeyPair pair;
    pair.ToChange();
    SECTION("wrong Update Key")
    {
        std::array<uint8_t, 32> other{};
        REQUIRE(crypto::GenerateRandom(wseq_t(other.data(), 32)) == crypto::Result::OK);
        REQUIRE(pair.outstation.Configure(rseq_t(other.data(), 32), 10000000, pair.now) == R::OK);
        crypto::Clear(wseq_t(other.data(), 32));
        // New query creates an otherwise matching KSQ, but with a fresh nonce.
        REQUIRE(pair.outstation.Process(7, pair.request.Read(), pair.now, pair.status.Write(), pair.status.size)
                == R::OK);
    }
    SECTION("wrapped ciphertext modified")
    {
        pair.change.bytes[pair.change.size - 1] ^= 1;
    }
    SECTION("application sequence modified")
    {
        pair.change.bytes[0] ^= 1;
    }
    REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
            != R::INSTALLED);
    REQUIRE_FALSE(pair.outstation.Ready(pair.now));
    REQUIRE(pair.outstation.ControlKey(pair.now).is_empty());
}

TEST_CASE("SessionKeys - valid wrap with inconsistent embedded status is rejected", "[session-keys]")
{
    KeyPair pair;
    pair.ToChange();
    Group120Var6 change;
    REQUIRE(change.Read(pair.change.Read().skip(8)));
    Packet plain;
    plain.size = change.keyWrapData.length() - 8;
    REQUIRE(crypto::AES256KeyUnwrap(rseq_t(pair.update.data(), 32), change.keyWrapData, plain.Write().take(plain.size))
            == crypto::Result::OK);
    const auto mutation = GENERATE(0, 1, 2);
    if (mutation == 0)
        plain.bytes[66 + 11] ^= 1; // status challenge nonce
    if (mutation == 1)
    {
        plain.bytes[0] = 31;
    } // invalid Session Key length
    if (mutation == 2)
        std::memcpy(plain.bytes.data() + 34, plain.bytes.data() + 2, 32); // identical direction keys
    REQUIRE(crypto::AES256KeyWrap(rseq_t(pair.update.data(), 32), plain.Read(),
                                  wseq_t(pair.change.bytes.data() + 14, change.keyWrapData.length()))
            == crypto::Result::OK);
    REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
            != R::INSTALLED);
    REQUIRE_FALSE(pair.outstation.Ready(pair.now));
}

TEST_CASE("SessionKeys - replay and duplicate confirmation do not authorize", "[session-keys]")
{
    KeyPair pair;
    pair.Exchange();
    SECTION("V6 replay")
    {
        REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.request.Write(), pair.request.size)
                != R::INSTALLED);
        REQUIRE_FALSE(pair.outstation.Ready(pair.now));
    }
    SECTION("V5 replay")
    {
        REQUIRE(pair.master.Process(7, pair.confirmation.Read(), pair.now, pair.request.Write(), pair.request.size)
                != R::INSTALLED);
        REQUIRE_FALSE(pair.master.Ready(pair.now));
    }
    SECTION("old initial status in renewal")
    {
        pair.master.Disconnect();
        REQUIRE(pair.master.Begin(7, 3, pair.now, pair.request.Write(), pair.request.size) == R::OK);
        REQUIRE(pair.master.Process(7, pair.status.Read(), pair.now, pair.request.Write(), pair.request.size)
                != R::INSTALLED);
        REQUIRE_FALSE(pair.master.Ready(pair.now));
    }
}

TEST_CASE("SessionKeys - lost confirmation recovers without exposing proposed keys", "[session-keys]")
{
    KeyPair pair;
    pair.ToChange();
    REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
            == R::INSTALLED);
    pair.now += pair.config.replyTimeoutMs;
    REQUIRE(pair.master.NeedsExchange(pair.now));
    REQUIRE(pair.master.ControlKey(pair.now).is_empty());
    pair.Exchange();
    REQUIRE(pair.master.Sequence() == 4);
}

TEST_CASE("SessionKeys - expiry message count renewal and disconnect", "[session-keys]")
{
    SessionKeys::Config c;
    c.messageLimit = 2;
    KeyPair pair(c);
    pair.Exchange();
    SECTION("expiry")
    {
        pair.now += c.intervalMs;
    }
    SECTION("count")
    {
        pair.master.CountAuthentication(pair.now);
        pair.outstation.CountAuthentication(pair.now);
        REQUIRE(pair.master.Ready(pair.now));
        pair.master.CountAuthentication(pair.now);
        pair.outstation.CountAuthentication(pair.now);
    }
    SECTION("disconnect")
    {
        pair.master.Disconnect();
        pair.outstation.Disconnect();
    }
    REQUIRE_FALSE(pair.master.Ready(pair.now));
    REQUIRE_FALSE(pair.outstation.Ready(pair.now));
    REQUIRE(pair.master.NeedsExchange(pair.now));
    pair.Exchange();
    REQUIRE(pair.master.Sequence() == 4);
}

TEST_CASE("SessionKeys - users and associations have independent keys and pending state", "[session-keys]")
{
    KeyPair first(SessionKeys::Config(), 7, 2), second(SessionKeys::Config(), 8, 3);
    first.ToChange();
    second.ToChange(8);
    REQUIRE(first.outstation.Process(8, second.change.Read(), first.now, first.confirmation.Write(),
                                     first.confirmation.size)
            == R::WRONG_ASSOCIATION);
    REQUIRE(
        first.outstation.Process(7, first.change.Read(), first.now, first.confirmation.Write(), first.confirmation.size)
        == R::INSTALLED);
    REQUIRE(first.master.Process(7, first.confirmation.Read(), first.now, first.request.Write(), first.request.size)
            == R::INSTALLED);
    REQUIRE(second.outstation.Process(8, second.change.Read(), second.now, second.confirmation.Write(),
                                      second.confirmation.size)
            == R::INSTALLED);
    REQUIRE(
        second.master.Process(8, second.confirmation.Read(), second.now, second.request.Write(), second.request.size)
        == R::INSTALLED);
    REQUIRE_FALSE(crypto::ConstantTimeEqual(first.master.ControlKey(first.now), second.master.ControlKey(second.now)));
    REQUIRE(first.master.Ready(first.now));
    REQUIRE(second.master.Ready(second.now));
    first.master.Reset();
    first.outstation.Reset();
    REQUIRE_FALSE(first.master.NeedsExchange(first.now));
    REQUIRE(second.master.Ready(second.now));
}

TEST_CASE("SessionKeys - bounded buffers unavailable credentials timeout and retry", "[session-keys]")
{
    KeyPair pair;
    SECTION("unavailable credentials and reset")
    {
        pair.master.Reset();
        REQUIRE(pair.master.Begin(7, 3, pair.now, pair.request.Write(), pair.request.size) == R::NO_CREDENTIAL);
        REQUIRE(pair.request.size == 0);
    }
    SECTION("short output")
    {
        REQUIRE(pair.master.Begin(7, 3, pair.now, pair.request.Write().take(7), pair.request.size) == R::INVALID);
        REQUIRE(pair.request.size == 0);
        pair.ToStatus();
        REQUIRE(pair.master.Process(7, pair.status.Read(), pair.now, pair.change.Write().take(8), pair.change.size)
                != R::OK);
        REQUIRE(pair.change.size == 0);
        REQUIRE_FALSE(pair.master.Ready(pair.now));
    }
    SECTION("timeout and bounded retries")
    {
        for (size_t n = 0; n < 3; ++n)
        {
            REQUIRE(pair.master.NeedsExchange(pair.now));
            REQUIRE(pair.master.Begin(7, 3, pair.now, pair.request.Write(), pair.request.size) == R::OK);
            pair.now += pair.config.replyTimeoutMs;
        }
        REQUIRE_FALSE(pair.master.NeedsExchange(pair.now));
        REQUIRE_FALSE(pair.master.Ready(pair.now));
        pair.now += pair.config.intervalMs;
        REQUIRE(pair.master.NeedsExchange(pair.now));
    }
    SECTION("expired pending V6")
    {
        pair.ToChange();
        pair.now += pair.config.replyTimeoutMs;
        REQUIRE(
            pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
            != R::INSTALLED);
    }
    SECTION("credential expiration")
    {
        pair.Exchange();
        pair.now = 10000000;
        REQUIRE_FALSE(pair.master.Ready(pair.now));
        REQUIRE_FALSE(pair.outstation.Ready(pair.now));
        REQUIRE_FALSE(pair.master.NeedsExchange(pair.now));
    }
    SECTION("clock regression")
    {
        pair.Exchange();
        --pair.now;
        REQUIRE_FALSE(pair.master.Ready(pair.now));
        REQUIRE_FALSE(pair.outstation.Ready(pair.now));
    }
    SECTION("oversized APDU rejected before dereference")
    {
        REQUIRE(pair.outstation.Process(7, rseq_t(pair.request.bytes.data(), 2049), pair.now, pair.confirmation.Write(),
                                        pair.confirmation.size)
                == R::INVALID);
    }
}

TEST_CASE("SessionKeys - bad configuration and crypto outage fail closed", "[session-keys]")
{
    SessionKeys::Config c;
    const auto invalid = GENERATE(0, 1, 2, 3, 4);
    if (invalid == 0)
        c.intervalMs = 899999;
    if (invalid == 1)
        c.intervalMs = 7200001;
    if (invalid == 2)
        c.messageLimit = 0;
    if (invalid == 3)
        c.replyTimeoutMs = 120100;
    if (invalid == 4)
        c.tagLength = 12;
    SessionKeys bad(SessionKeys::Role::MASTER, 7, 2, c);
    std::array<uint8_t, 32> key{};
    REQUIRE(crypto::GenerateRandom(wseq_t(key.data(), 32)) == crypto::Result::OK);
    REQUIRE(bad.Configure(rseq_t(key.data(), 32), 10000, 1000) == R::INVALID);
    crypto::Clear(wseq_t(key.data(), 32));
    KeyPair pair;
    REQUIRE(pair.master.Begin(7, 3, pair.now, pair.request.Write(), pair.request.size) == R::OK);
    OSSL_LIB_CTX* context = OSSL_LIB_CTX_new();
    REQUIRE(context != nullptr);
    OSSL_PROVIDER* nullProvider = OSSL_PROVIDER_load(context, "null");
    REQUIRE(nullProvider != nullptr);
    auto* previous = OSSL_LIB_CTX_set0_default(context);
    const auto result
        = pair.outstation.Process(7, pair.request.Read(), pair.now, pair.status.Write(), pair.status.size);
    OSSL_LIB_CTX_set0_default(previous);
    OSSL_PROVIDER_unload(nullProvider);
    OSSL_LIB_CTX_free(context);
    REQUIRE(result == R::CRYPTO_ERROR);
    REQUIRE(pair.status.size == 0);
    REQUIRE_FALSE(pair.outstation.Ready(pair.now));
}

TEST_CASE("SessionKeys - constant time comparison boundary", "[crypto][session-keys]")
{
    uint8_t first[] = {1, 2, 3}, second[] = {1, 2, 3};
    REQUIRE(crypto::ConstantTimeEqual(rseq_t(first, 3), rseq_t(second, 3)));
    for (size_t n = 0; n < 3; ++n)
    {
        second[n] ^= 1;
        REQUIRE_FALSE(crypto::ConstantTimeEqual(rseq_t(first, 3), rseq_t(second, 3)));
        second[n] ^= 1;
    }
    REQUIRE_FALSE(crypto::ConstantTimeEqual(rseq_t(first, 3), rseq_t(second, 2)));
    REQUIRE_FALSE(crypto::ConstantTimeEqual(rseq_t(nullptr, 3), rseq_t(second, 3)));
    REQUIRE(crypto::ConstantTimeEqual(rseq_t(), rseq_t()));
}

TEST_CASE("SessionKeys - explicitly detected Outstation restart establishes fresh keys", "[session-keys]")
{
    KeyPair pair;
    pair.Exchange();
    SessionKeys rebooted(SessionKeys::Role::OUTSTATION, 7, 2, pair.config);
    REQUIRE(rebooted.Configure(rseq_t(pair.update.data(), 32), 10000000, pair.now) == R::OK);
    pair.master.PeerRestart(pair.now);
    REQUIRE(pair.master.Begin(7, 4, pair.now, pair.request.Write(), pair.request.size) == R::OK);
    REQUIRE(rebooted.Process(7, pair.request.Read(), pair.now, pair.status.Write(), pair.status.size) == R::OK);
    REQUIRE(pair.master.Process(7, pair.status.Read(), pair.now, pair.change.Write(), pair.change.size) == R::OK);
    REQUIRE(rebooted.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
            == R::INSTALLED);
    REQUIRE(pair.master.Process(7, pair.confirmation.Read(), pair.now, pair.request.Write(), pair.request.size)
            == R::INSTALLED);
    REQUIRE(crypto::ConstantTimeEqual(pair.master.ControlKey(pair.now), rebooted.ControlKey(pair.now)));
}

TEST_CASE("SessionKeys - explicitly configured IEEE legacy algorithms exchange and renew", "[session-keys]")
{
    SessionKeys::Config config;
    config.macAlgorithm = GENERATE(2, 5);
    config.tagLength = config.macAlgorithm == 2 ? 10 : 8;
    config.keyWrapAlgorithm = GENERATE(1, 2);
    KeyPair pair(config);
    pair.Exchange();
    REQUIRE(pair.status.bytes[16] == config.keyWrapAlgorithm);
    REQUIRE(pair.confirmation.bytes[18] == config.macAlgorithm);
    pair.master.RequestRenewal(pair.now);
    pair.Exchange();
    REQUIRE(pair.master.Sequence() == 4);
    // A corrupted confirmation must not publish the newly proposed keys.
    pair.master.RequestRenewal(pair.now);
    pair.ToChange();
    REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
            == R::INSTALLED);
    pair.confirmation.bytes[pair.confirmation.size - 1] ^= 1;
    REQUIRE(pair.master.Process(7, pair.confirmation.Read(), pair.now, pair.request.Write(), pair.request.size)
            != R::INSTALLED);
    REQUIRE_FALSE(pair.master.Ready(pair.now));
}
TEST_CASE("SessionKeys - unsupported algorithm and inconsistent tag configuration fail closed", "[session-keys]")
{
    SessionKeys::Config config;
    const auto fault = GENERATE(0, 1, 2, 3);
    if (fault == 0)
        config.macAlgorithm = 1;
    if (fault == 1)
        config.macAlgorithm = 6;
    if (fault == 2)
    {
        config.macAlgorithm = 2;
        config.tagLength = 8;
    }
    if (fault == 3)
        config.keyWrapAlgorithm = 3;
    SessionKeys session(SessionKeys::Role::MASTER, 7, 2, config);
    std::array<uint8_t, 32> key{};
    REQUIRE(session.Configure(rseq_t(key.data(), key.size()), 10000, 1000) == R::INVALID);
    REQUIRE_FALSE(session.Ready(1000));
}

TEST_CASE("SessionKeys - default interval remains fifteen minutes", "[session-keys]")
{
    SessionKeys::Config config;
    REQUIRE(config.intervalMs == 900000);
    KeyPair pair(config);
    pair.Exchange();
    const auto expires = pair.now + 900000;
    REQUIRE(pair.master.ValidUntil() == expires);
    REQUIRE(pair.outstation.ValidUntil() == expires);
    REQUIRE(pair.master.Ready(expires - 1));
    REQUIRE(pair.outstation.Ready(expires - 1));
    REQUIRE_FALSE(pair.master.Ready(expires));
    REQUIRE_FALSE(pair.outstation.Ready(expires));
    REQUIRE(pair.master.NeedsExchange(expires));
}

TEST_CASE("SessionKeys - core accepts one second and two hour interval boundaries", "[session-keys]")
{
    SessionKeys::Config config;
    config.intervalMs = GENERATE(1000u, 7200000u);
    KeyPair pair(config);
    pair.Exchange();
    const auto expires = pair.now + config.intervalMs;
    REQUIRE(pair.master.ValidUntil() == expires);
    REQUIRE(pair.outstation.ValidUntil() == expires);
    REQUIRE(pair.master.Ready(expires - 1));
    REQUIRE(pair.outstation.Ready(expires - 1));
    REQUIRE_FALSE(pair.master.Ready(expires));
    REQUIRE_FALSE(pair.outstation.Ready(expires));
}

TEST_CASE("SessionKeys - core rejects invalid interval precision and range", "[session-keys]")
{
    SessionKeys::Config config;
    config.intervalMs = GENERATE(1u, 999u, 1001u, 1500u, 899999u, 7200001u, 7201000u);
    const auto role = GENERATE(SessionKeys::Role::MASTER, SessionKeys::Role::OUTSTATION);
    KeyPair material;
    SessionKeys session(role, 7, 2, config);
    REQUIRE(session.Configure(rseq_t(material.update.data(), material.update.size()), 10000000, material.now)
            == R::INVALID);
    REQUIRE_FALSE(session.Ready(material.now));
}

TEST_CASE("SessionKeys - count only mode retains keys until credential expiration", "[session-keys]")
{
    SessionKeys::Config config;
    config.intervalMs = 0;
    KeyPair pair(config);
    pair.Exchange();
    REQUIRE(pair.master.ValidUntil() == 10000000);
    REQUIRE(pair.outstation.ValidUntil() == 10000000);
    // Neither the normal renewal boundary nor the longest timed interval expires keys.
    for (uint64_t time : {901000ULL, 7201000ULL, 9999999ULL})
    {
        REQUIRE(pair.master.Ready(time));
        REQUIRE(pair.outstation.Ready(time));
        REQUIRE_FALSE(pair.master.ControlKey(time).is_empty());
        REQUIRE_FALSE(pair.outstation.MonitoringKey(time).is_empty());
        REQUIRE_FALSE(pair.master.NeedsExchange(time));
    }
    pair.now = 10000000;
    REQUIRE_FALSE(pair.master.Ready(pair.now));
    REQUIRE_FALSE(pair.outstation.Ready(pair.now));
    REQUIRE(pair.master.ControlKey(pair.now).is_empty());
    REQUIRE(pair.outstation.MonitoringKey(pair.now).is_empty());
    REQUIRE_FALSE(pair.master.NeedsExchange(pair.now));
}

TEST_CASE("SessionKeys - count only mode still renews at the message limit", "[session-keys]")
{
    SessionKeys::Config config;
    config.intervalMs = 0;
    config.messageLimit = 2;
    KeyPair pair(config);
    pair.Exchange();
    pair.now += 7200000;
    pair.master.CountAuthentication(pair.now);
    pair.outstation.CountAuthentication(pair.now);
    REQUIRE(pair.master.Ready(pair.now));
    REQUIRE(pair.outstation.Ready(pair.now));
    pair.master.CountAuthentication(pair.now);
    pair.outstation.CountAuthentication(pair.now);
    REQUIRE_FALSE(pair.master.Ready(pair.now));
    REQUIRE_FALSE(pair.outstation.Ready(pair.now));
    REQUIRE(pair.master.NeedsExchange(pair.now));
    pair.Exchange();
    REQUIRE(pair.master.RemainingMessages() == 2);
    REQUIRE(pair.outstation.RemainingMessages() == 2);
}

TEST_CASE("SessionKeys - count only mode preserves explicit invalidation and failure", "[session-keys]")
{
    SessionKeys::Config config;
    config.intervalMs = 0;
    KeyPair pair(config);
    pair.Exchange();
    SECTION("explicit renewal")
    {
        pair.master.RequestRenewal(pair.now);
        REQUIRE_FALSE(pair.master.Ready(pair.now));
        REQUIRE(pair.outstation.Ready(pair.now));
        REQUIRE(pair.master.NeedsExchange(pair.now));
        pair.Exchange();
    }
    SECTION("peer restart")
    {
        pair.master.PeerRestart(pair.now);
        REQUIRE_FALSE(pair.master.Ready(pair.now));
        REQUIRE(pair.master.ControlKey(pair.now).is_empty());
        REQUIRE(pair.master.NeedsExchange(pair.now));
    }
    SECTION("disconnect")
    {
        pair.master.Disconnect();
        pair.outstation.Disconnect();
        REQUIRE_FALSE(pair.master.Ready(pair.now));
        REQUIRE_FALSE(pair.outstation.Ready(pair.now));
        REQUIRE(pair.master.NeedsExchange(pair.now));
        pair.Exchange();
    }
    SECTION("invalid confirmation MAC")
    {
        pair.master.RequestRenewal(pair.now);
        pair.ToChange();
        REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(),
                                        pair.confirmation.size) == R::INSTALLED);
        pair.confirmation.bytes[pair.confirmation.size - 1] ^= 1;
        REQUIRE(pair.master.Process(7, pair.confirmation.Read(), pair.now, pair.request.Write(), pair.request.size)
                == R::INVALID);
        REQUIRE_FALSE(pair.master.Ready(pair.now));
        REQUIRE(pair.master.ControlKey(pair.now).is_empty());
        REQUIRE_FALSE(pair.master.NeedsExchange(pair.now));
    }
}

TEST_CASE("SessionKeys - count only capped timeouts retain a positive retry delay", "[session-keys]")
{
    SessionKeys::Config config;
    config.intervalMs = 0;
    KeyPair pair(config);
    for (size_t batch = 0; batch < 2; ++batch)
    {
        for (size_t attempt = 0; attempt < 3; ++attempt)
        {
            REQUIRE(pair.master.NeedsExchange(pair.now));
            REQUIRE(pair.master.Begin(7, 3, pair.now, pair.request.Write(), pair.request.size) == R::OK);
            pair.now += config.replyTimeoutMs;
            pair.master.Tick(pair.now);
        }
        REQUIRE_FALSE(pair.master.NeedsExchange(pair.now));
        REQUIRE(pair.master.Begin(7, 3, pair.now, pair.request.Write(), pair.request.size) == R::BUSY);
        REQUIRE_FALSE(pair.master.NeedsExchange(pair.now + config.replyTimeoutMs - 1));
        pair.now += config.replyTimeoutMs;
        REQUIRE(pair.master.NeedsExchange(pair.now));
    }
}

TEST_CASE("SessionKeys - count only repeated failures retain a positive retry delay", "[session-keys]")
{
    SessionKeys::Config config;
    config.intervalMs = 0;
    KeyPair pair(config);
    for (size_t attempt = 0; attempt < 6; ++attempt)
    {
        REQUIRE(pair.master.NeedsExchange(pair.now));
        REQUIRE(pair.master.Begin(7, 3, pair.now, pair.request.Write(), pair.request.size) == R::OK);
        REQUIRE(pair.master.Process(7, rseq_t(), pair.now, pair.status.Write(), pair.status.size) == R::INVALID);
        REQUIRE(pair.status.size == 0);
        REQUIRE_FALSE(pair.master.Ready(pair.now));
        REQUIRE_FALSE(pair.master.NeedsExchange(pair.now));
        REQUIRE(pair.master.Begin(7, 3, pair.now, pair.request.Write(), pair.request.size) == R::BUSY);
        REQUIRE_FALSE(pair.master.NeedsExchange(pair.now + config.replyTimeoutMs - 1));
        pair.now += config.replyTimeoutMs;
    }
    REQUIRE(pair.master.NeedsExchange(pair.now));
}

TEST_CASE("SessionKeys - accepted remote status is distinct from local key validity", "[session-keys][unkeyed-critical]")
{
    KeyPair pair;
    REQUIRE(pair.master.LastKeyStatus() == 0);
    pair.ToChange();
    REQUIRE(pair.master.LastKeyStatus() == 2);
    REQUIRE_FALSE(pair.master.Ready(pair.now));
    REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
        == R::INSTALLED);
    REQUIRE(pair.master.Process(7, pair.confirmation.Read(), pair.now, pair.request.Write(), pair.request.size)
        == R::INSTALLED);
    REQUIRE(pair.master.LastKeyStatus() == 1);
    pair.master.RequestRenewal(pair.now);
    REQUIRE_FALSE(pair.master.Ready(pair.now));
    REQUIRE(pair.master.LastKeyStatus() == 1);
    pair.ToStatus();
    pair.status.bytes[pair.status.size - 1] ^= 1;
    REQUIRE(pair.master.Process(7, pair.status.Read(), pair.now, pair.change.Write(), pair.change.size) != R::OK);
    REQUIRE(pair.master.LastKeyStatus() == 1); // Rejected status cannot replace accepted remote information.
    REQUIRE_FALSE(pair.master.CanSendUnkeyedCritical(pair.now));
    pair.master.Disconnect();
    REQUIRE(pair.master.LastKeyStatus() == 0);
}

TEST_CASE("SessionKeys - non OK critical transmission requires capped Security Idle backoff", "[session-keys][unkeyed-critical]")
{
    KeyPair pair;
    for (size_t attempt = 0; attempt < 3; ++attempt)
    {
        pair.ToChange();
        pair.master.SetChangeQueued(pair.change.Read(), true);
        pair.master.CancelQueuedChange(pair.now);
        REQUIRE(pair.master.LastKeyStatus() == 2);
        REQUIRE(pair.master.CanSendUnkeyedCritical(pair.now) == (attempt == 2));
        REQUIRE(pair.master.ControlKey(pair.now).is_empty());
        if (attempt < 2) pair.now += pair.config.replyTimeoutMs;
    }
    REQUIRE_FALSE(pair.master.IsExchanging());
    REQUIRE_FALSE(pair.master.NeedsExchange(pair.now));
    SECTION("renewal timer retains its existing boundary")
    {
        pair.now += pair.config.intervalMs;
        REQUIRE_FALSE(pair.master.CanSendUnkeyedCritical(pair.now));
        REQUIRE(pair.master.NeedsExchange(pair.now));
        REQUIRE(pair.master.LastKeyStatus() == 2);
    }
    SECTION("disconnect clears association scoped remote status")
    {
        pair.master.Disconnect();
        REQUIRE(pair.master.LastKeyStatus() == 0);
        REQUIRE_FALSE(pair.master.CanSendUnkeyedCritical(pair.now));
    }
    SECTION("credential expiry fails closed")
    {
        REQUIRE_FALSE(pair.master.CanSendUnkeyedCritical(10000000));
        REQUIRE(pair.master.LastKeyStatus() == 0);
    }
}

TEST_CASE("SessionKeys - statistics count installed and failed key changes at real boundaries", "[session-keys][sa-statistics]")
{
    AuthenticationStatistics m(7, true, DefaultSecurityStatisticThresholds());
    AuthenticationStatistics o(7, false, DefaultSecurityStatisticThresholds());
    KeyPair pair;
    pair.master.SetStatistics(&m);
    pair.outstation.SetStatistics(&o);
    pair.Exchange();
    REQUIRE(m.Value(SecurityStatistic::SESSION_KEY_CHANGES) == 1);
    REQUIRE(o.Value(SecurityStatistic::SESSION_KEY_CHANGES) == 1);
    REQUIRE(m.ReportPending(SecurityStatistic::AUTHENTICATION_FAILURES));
    REQUIRE(o.ReportPending(SecurityStatistic::AUTHENTICATION_FAILURES));
    REQUIRE(m.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == 0); // Key Status MAC is not Challenger success.
    pair.ToChange();
    pair.change.bytes[pair.change.size - 1] ^= 1;
    REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
        == R::CRYPTO_ERROR);
    REQUIRE(o.Value(SecurityStatistic::FAILED_SESSION_KEY_CHANGES) == 1);
    REQUIRE(o.Value(SecurityStatistic::SESSION_KEY_CHANGES) == 1);
    // Replaying the failed V6 is now unexpected, not a second owned key change.
    REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
        == R::INVALID);
    REQUIRE(o.Value(SecurityStatistic::FAILED_SESSION_KEY_CHANGES) == 1);
    REQUIRE(o.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(o.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 0);
}

TEST_CASE("SessionKeys - configured Reply Timeout Max and disconnect account failed transaction once",
          "[session-keys][sa-statistics]")
{
    auto thresholds = DefaultSecurityStatisticThresholds();
    thresholds[3] = 1;
    AuthenticationStatistics statistics(7, true, thresholds);
    KeyPair pair;
    pair.master.SetStatistics(&statistics);
    SECTION("Max is strictly exceeded, then backoff and moving Max rearm")
    {
        for (unsigned n = 0; n < 2; ++n)
        {
            REQUIRE(pair.master.Begin(7, 3, pair.now, pair.request.Write(), pair.request.size) == R::OK);
            pair.now += pair.config.replyTimeoutMs;
            pair.master.Tick(pair.now);
            REQUIRE(statistics.Value(SecurityStatistic::REPLY_TIMEOUTS) == n + 1);
            REQUIRE(statistics.Value(SecurityStatistic::FAILED_SESSION_KEY_CHANGES) == n);
        }
        REQUIRE_FALSE(pair.master.NeedsExchange(pair.now));
        REQUIRE(statistics.Maximum(SecurityStatistic::REPLY_TIMEOUTS) == 3);
        uint16_t owner = 0;
        REQUIRE(statistics.TakeKeyChangeTimeoutLimit(owner));
        REQUIRE(owner == 2);
        REQUIRE_FALSE(statistics.TakeKeyChangeTimeoutLimit(owner));
        pair.master.Tick(pair.now);
        REQUIRE(statistics.Value(SecurityStatistic::FAILED_SESSION_KEY_CHANGES) == 1);
    }
    SECTION("Disconnect consumes a pending key transaction only once")
    {
        REQUIRE(pair.master.Begin(7, 3, pair.now, pair.request.Write(), pair.request.size) == R::OK);
        pair.master.Disconnect();
        pair.master.Disconnect();
        REQUIRE(statistics.Value(SecurityStatistic::FAILED_SESSION_KEY_CHANGES) == 1);
        REQUIRE(statistics.Value(SecurityStatistic::REPLY_TIMEOUTS) == 0);
    }
}

TEST_CASE("SessionKeys - failure recovery counts only its first owned transmission", "[session-keys][sa-statistics]")
{
    AuthenticationStatistics statistics(7, true, DefaultSecurityStatisticThresholds());
    KeyPair pair;
    pair.master.SetStatistics(&statistics);
    for (unsigned n = 0; n < 6; ++n) statistics.AuthenticationFailed(2); // Established test exchange owner.
    REQUIRE(pair.master.RequestAuthenticationRenewal(pair.now));
    REQUIRE_FALSE(pair.master.RequestAuthenticationRenewal(pair.now));
    REQUIRE(pair.master.Begin(7, 3, pair.now, pair.request.Write(), pair.request.size) == R::OK);
    REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_REKEYS) == 0);
    pair.master.OnExchangeTransmit(4, 2); // Wrong application's SEQ cannot own this request.
    REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_REKEYS) == 0);
    pair.master.OnExchangeTransmit(4, 3);
    pair.master.OnExchangeTransmit(4, 3);
    REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_REKEYS) == 1);
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == 0);
    REQUIRE_FALSE(statistics.Exceeded(SecurityStatistic::AUTHENTICATION_FAILURES));
}

TEST_CASE("SessionKeys - authentic non OK confirmation preserves the pending change",
          "[session-keys][sa-statistics]")
{
    AuthenticationStatistics statistics(7, true, DefaultSecurityStatisticThresholds());
    KeyPair pair;
    pair.master.SetStatistics(&statistics);
    pair.ToChange();
    REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
        == R::INSTALLED);
    const auto confirmation = pair.confirmation;
    pair.confirmation.bytes[17] = 3; // Table 7-13 row 2: authentic status, but not OK.
    REQUIRE(pair.master.Process(7, pair.confirmation.Read(), pair.now, pair.request.Write(), pair.request.size)
        == R::INVALID);
    REQUIRE(pair.request.size == 0);
    REQUIRE(pair.master.AwaitingKeyConfirmation());
    REQUIRE_FALSE(pair.master.Ready(pair.now));
    REQUIRE(statistics.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == 1);
    REQUIRE(statistics.Value(SecurityStatistic::DISCARDED_MESSAGES) == 0);
    REQUIRE(statistics.Value(SecurityStatistic::FAILED_SESSION_KEY_CHANGES) == 0);
    REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_FAILURES) == 0);
    REQUIRE(pair.master.Process(7, confirmation.Read(), pair.now, pair.request.Write(), pair.request.size)
        == R::INSTALLED);
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == 1);
}

TEST_CASE("SessionKeys - another user's status does not abort an owned status request",
          "[session-keys][sa-statistics]")
{
    AuthenticationStatistics statistics(7, true, DefaultSecurityStatisticThresholds());
    KeyPair pair;
    pair.master.SetStatistics(&statistics);
    pair.ToStatus();
    const auto owned = pair.status;
    pair.status.bytes[14] = 1; // Active exchange belongs to user 2.
    REQUIRE(pair.master.Process(7, pair.status.Read(), pair.now, pair.change.Write(), pair.change.size) == R::INVALID);
    REQUIRE(pair.change.size == 0);
    REQUIRE(pair.master.IsExchanging());
    REQUIRE_FALSE(pair.master.AwaitingKeyConfirmation());
    REQUIRE(statistics.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == 1);
    REQUIRE(statistics.Value(SecurityStatistic::DISCARDED_MESSAGES) == 1);
    REQUIRE(statistics.Value(SecurityStatistic::FAILED_SESSION_KEY_CHANGES) == 0);
    REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_FAILURES) == 0);
    REQUIRE(pair.master.Process(7, owned.Read(), pair.now, pair.change.Write(), pair.change.size) == R::OK);
    REQUIRE(pair.master.AwaitingKeyConfirmation());
}

TEST_CASE("SessionKeys - foreign confirmation returns to status with sent key recovery and original deadline",
          "[session-keys][sa-statistics]")
{
    AuthenticationStatistics statistics(7, true, DefaultSecurityStatisticThresholds());
    KeyPair pair;
    pair.master.SetStatistics(&statistics);
    pair.ToChange();
    pair.master.SetChangeQueued(pair.change.Read(), false); // V6 actually handed to the lower layer.
    REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
        == R::INSTALLED);
    pair.confirmation.bytes[14] = 1;
    REQUIRE(pair.master.Process(7, pair.confirmation.Read(), pair.now + 1, pair.request.Write(), pair.request.size)
        == R::INVALID);
    REQUIRE(pair.request.size == 0);
    REQUIRE(pair.master.IsExchanging());
    REQUIRE_FALSE(pair.master.AwaitingKeyConfirmation());
    REQUIRE(statistics.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == 1);
    REQUIRE(statistics.Value(SecurityStatistic::DISCARDED_MESSAGES) == 1);
    REQUIRE(statistics.Value(SecurityStatistic::FAILED_SESSION_KEY_CHANGES) == 0);
    pair.master.Tick(pair.now + pair.config.replyTimeoutMs - 1);
    REQUIRE(pair.master.IsExchanging());
    pair.now += pair.config.replyTimeoutMs;
    pair.master.Tick(pair.now); // The foreign message did not extend the deadline.
    REQUIRE_FALSE(pair.master.IsExchanging());
    REQUIRE(statistics.Value(SecurityStatistic::REPLY_TIMEOUTS) == 1);
    pair.Exchange(); // Authenticate the peer's installed V6 using retained recovery material.
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == 1);
    REQUIRE(statistics.Value(SecurityStatistic::FAILED_SESSION_KEY_CHANGES) == 0);
}

TEST_CASE("SessionKeys - restart Max rearms on renewal boundary, never on reconnect", "[session-keys][sa-statistics]")
{
    auto thresholds = DefaultSecurityStatisticThresholds();
    thresholds[3] = 0;
    AuthenticationStatistics statistics(7, true, thresholds);
    SessionKeys::Config config;
    config.intervalMs = GENERATE(uint32_t{0}, uint32_t{900000});
    KeyPair pair(config);
    pair.master.SetStatistics(&statistics);
    for (unsigned n = 0; n < 4; ++n) statistics.Increment(SecurityStatistic::RESTART_REKEYS);
    REQUIRE(statistics.Exceeded(SecurityStatistic::RESTART_REKEYS));
    pair.master.Disconnect();
    pair.master.Tick(pair.now);
    REQUIRE(statistics.Exceeded(SecurityStatistic::RESTART_REKEYS));
    REQUIRE(pair.master.Begin(7, 3, pair.now, pair.request.Write(), pair.request.size) == R::OK);
    pair.now += config.replyTimeoutMs;
    pair.master.Tick(pair.now); // Exceeds Reply Timeout Max; starts existing capped-renewal backoff.
    REQUIRE(statistics.Exceeded(SecurityStatistic::RESTART_REKEYS));
    const auto delay = config.intervalMs ? config.intervalMs : config.replyTimeoutMs;
    pair.master.Tick(pair.now + delay - 1);
    REQUIRE(statistics.Exceeded(SecurityStatistic::RESTART_REKEYS));
    pair.master.Tick(pair.now + delay);
    REQUIRE(statistics.Exceeded(SecurityStatistic::RESTART_REKEYS) == (config.intervalMs == 0));
    REQUIRE(statistics.Value(SecurityStatistic::RESTART_REKEYS) == 4);
}

TEST_CASE("SessionKeys - reply timeout range and resolution", "[sa-reply-timeout]")
{
    const uint32_t timeout = GENERATE(0u, 100u, 120000u, 120100u, 1u, 101u);
    SessionKeys::Config config;
    config.replyTimeoutMs = timeout;
    SessionKeys engine(SessionKeys::Role::MASTER, 7, 2, config);
    std::array<uint8_t, 32> key{};
    REQUIRE(engine.Configure(rseq_t(key.data(), key.size()), 1000000, 0)
            == (timeout <= 120000 && timeout % 100 == 0 ? R::OK : R::INVALID));
}

TEST_CASE("SessionKeys - zero at clock origin expires once with bounded recovery", "[sa-reply-timeout]")
{
    SessionKeys::Config config;
    config.replyTimeoutMs = 0;
    SessionKeys master(SessionKeys::Role::MASTER, 7, 2, config);
    SessionKeys outstation(SessionKeys::Role::OUTSTATION, 7, 2, config);
    AuthenticationStatistics stats(7, true, DefaultSecurityStatisticThresholds());
    master.SetStatistics(&stats);
    std::array<uint8_t, 32> key{};
    REQUIRE(master.Configure(rseq_t(key.data(), key.size()), 1000000, 0) == R::OK);
    REQUIRE(outstation.Configure(rseq_t(key.data(), key.size()), 1000000, 0) == R::OK);
    Packet request, status, output;
    REQUIRE(master.Begin(7, 3, 0, request.Write(), request.size) == R::OK);
    REQUIRE(outstation.Process(7, request.Read(), 0, status.Write(), status.size) == R::OK);
    // Both status ownership and awaiting-V6 ownership expire at the clock origin.
    master.Tick(0);
    outstation.Tick(0);
    for (size_t n = 0; n < 100; ++n)
    {
        master.Tick(0);
        REQUIRE_FALSE(master.NeedsExchange(0));
        REQUIRE_FALSE(master.Ready(0));
        REQUIRE_FALSE(outstation.Ready(0));
    }
    REQUIRE(stats.Value(SecurityStatistic::REPLY_TIMEOUTS) == 1);
    REQUIRE_FALSE(master.NeedsExchange(99));
    REQUIRE(master.NeedsExchange(100));
    REQUIRE(master.ControlKey(100).is_empty());
    REQUIRE(master.Process(7, status.Read(), 100, output.Write(), output.size) != R::INSTALLED);
    REQUIRE(output.size == 0);
    // Correcting configuration uses a new engine, as Config is immutable.
    KeyPair recovered;
    recovered.Exchange();
}

TEST_CASE("SessionKeys - nonzero deadline boundaries clear pending candidates", "[sa-reply-timeout]")
{
    const uint64_t elapsed = GENERATE(99u, 100u, 101u);
    SessionKeys::Config config;
    config.replyTimeoutMs = 100;
    KeyPair pair(config);
    AuthenticationStatistics stats(7, true, DefaultSecurityStatisticThresholds());
    pair.master.SetStatistics(&stats);
    pair.ToChange();
    pair.master.Tick(pair.now + elapsed);
    pair.outstation.Tick(pair.now + elapsed);
    REQUIRE(pair.master.IsExchanging() == (elapsed < 100));
    REQUIRE(pair.master.ControlKey(pair.now + elapsed).is_empty());
    if (elapsed >= 100)
    {
        REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now + elapsed,
                                        pair.confirmation.Write(), pair.confirmation.size) != R::INSTALLED);
        REQUIRE_FALSE(pair.outstation.Ready(pair.now + elapsed));
        pair.master.Tick(pair.now + elapsed);
        REQUIRE(stats.Value(SecurityStatistic::REPLY_TIMEOUTS) == 1);
    }
}

TEST_CASE("SessionKeys - selected renewal deadlines expire and reinstall with fresh budgets", "[session-keys][sa-renewal]")
{
    SessionKeys::Config config;
    config.intervalMs = GENERATE(900000u, 7200000u);
    const auto offset = GENERATE(uint64_t(0), uint64_t(1));
    KeyPair pair(config);
    pair.Exchange();
    const auto deadline = pair.now + config.intervalMs;
    const auto sequence = pair.master.Sequence();
    pair.master.CountAuthentication(pair.now);
    pair.outstation.CountAuthentication(pair.now);
    REQUIRE(pair.master.RemainingMessages() == config.messageLimit - 1);
    REQUIRE(pair.outstation.RemainingMessages() == config.messageLimit - 1);
    REQUIRE(pair.master.Ready(deadline - 1));
    REQUIRE(pair.outstation.Ready(deadline - 1));
    pair.now = deadline + offset;
    REQUIRE_FALSE(pair.master.Ready(pair.now));
    REQUIRE_FALSE(pair.outstation.Ready(pair.now));
    REQUIRE(pair.master.ControlKey(pair.now).is_empty());
    REQUIRE(pair.outstation.MonitoringKey(pair.now).is_empty());
    REQUIRE(pair.master.NeedsExchange(pair.now));
    pair.Exchange();
    REQUIRE(pair.master.Sequence() != sequence);
    REQUIRE(pair.master.RemainingMessages() == config.messageLimit);
    REQUIRE(pair.outstation.RemainingMessages() == config.messageLimit);
}

TEST_CASE("SessionKeys - renewal lifetime starts at each role's actual installation", "[session-keys][sa-renewal]")
{
    SessionKeys::Config config;
    config.intervalMs = GENERATE(900000u, 7200000u);
    KeyPair pair(config);
    pair.ToChange();
    const auto outInstalled = pair.now;
    REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
            == R::INSTALLED);
    pair.now += 17;
    REQUIRE(pair.master.Process(7, pair.confirmation.Read(), pair.now, pair.request.Write(), pair.request.size)
            == R::INSTALLED);
    const auto outDeadline = outInstalled + config.intervalMs;
    const auto masterDeadline = pair.now + config.intervalMs;
    REQUIRE(pair.outstation.ValidUntil() == outDeadline);
    REQUIRE(pair.master.ValidUntil() == masterDeadline);
    REQUIRE(pair.outstation.Ready(outDeadline - 1));
    REQUIRE(pair.master.Ready(outDeadline - 1));
    REQUIRE_FALSE(pair.outstation.Ready(outDeadline));
    REQUIRE(pair.master.Ready(outDeadline));
    REQUIRE_FALSE(pair.outstation.Ready(outDeadline + 1));
    REQUIRE(pair.master.Ready(masterDeadline - 1));
    REQUIRE_FALSE(pair.master.Ready(masterDeadline));
    REQUIRE_FALSE(pair.master.Ready(masterDeadline + 1));
    pair.now = masterDeadline + 1;
    pair.Exchange();
    REQUIRE(pair.master.RemainingMessages() == config.messageLimit);
    REQUIRE(pair.outstation.RemainingMessages() == config.messageLimit);
}

TEST_CASE("SessionKeys - configured count limits are local and reinstall resets the budget", "[session-keys][sa-renewal]")
{
    SessionKeys::Config config;
    REQUIRE(config.messageLimit == 1000);
    config.messageLimit = GENERATE(1u, 1000u, 2000u);
    const bool countMaster = GENERATE(false, true);
    KeyPair pair(config);
    pair.Exchange();
    auto& counted = countMaster ? pair.master : pair.outstation;
    auto& independent = countMaster ? pair.outstation : pair.master;
    const auto end = config.messageLimit < 1001 ? 1001u : config.messageLimit + 1;
    for (uint32_t n = 1; n <= end; ++n)
    {
        counted.CountAuthentication(pair.now);
        if (n == 1 || n == 999 || n == 1000 || n == 1001 || n == config.messageLimit)
        {
            CAPTURE(n, config.messageLimit, countMaster);
            REQUIRE(counted.Ready(pair.now) == (n < config.messageLimit));
            REQUIRE(counted.RemainingMessages() == (n < config.messageLimit ? config.messageLimit - n : 0));
            REQUIRE(independent.Ready(pair.now));
            REQUIRE(independent.RemainingMessages() == config.messageLimit);
        }
    }
    REQUIRE(counted.ControlKey(pair.now).is_empty());
    REQUIRE(counted.MonitoringKey(pair.now).is_empty());
    pair.Exchange();
    REQUIRE(pair.master.RemainingMessages() == config.messageLimit);
    REQUIRE(pair.outstation.RemainingMessages() == config.messageLimit);
}
