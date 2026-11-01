// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/SessionKeys.h"
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
        REQUIRE(master.Configure(rseq_t(update.data(), 32), 10000000, now) == R::OK);
        REQUIRE(outstation.Configure(rseq_t(update.data(), 32), 10000000, now) == R::OK);
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
    KeyPair pair;
    pair.ToChange();
    REQUIRE(pair.outstation.Process(7, pair.change.Read(), pair.now, pair.confirmation.Write(), pair.confirmation.size)
            == R::INSTALLED);
    const auto mutation = GENERATE(0, 1, 2, 3, 4);
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
    REQUIRE(pair.master.Process(7, pair.confirmation.Read(), pair.now, pair.request.Write(), pair.request.size)
            != R::INSTALLED);
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
        c.replyTimeoutMs = 0;
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
