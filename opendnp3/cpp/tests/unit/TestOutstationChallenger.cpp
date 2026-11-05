// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "crypto/CryptoProvider.h"
#include "auth/AuthenticationStatistics.h"
#include "outstation/OutstationChallenger.h"
#include "utils/BufferHelpers.h"

#include <catch.hpp>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#include <algorithm>
#include <memory>
#include <vector>

using namespace opendnp3;
using namespace ser4cpp;
using Challenger = OutstationChallenger;
using Result = Challenger::Result;
using State = Challenger::State;

namespace
{
template<class T> rseq_t Read(const T& bytes)
{
    return rseq_t(bytes.data(), bytes.size());
}
template<class T> wseq_t Write(T& bytes)
{
    return wseq_t(bytes.data(), bytes.size());
}
template<class T> bool IsZero(const T& bytes)
{
    return std::all_of(bytes.begin(), bytes.end(), [](uint8_t b) { return b == 0; });
}

struct Fixture
{
    const uint16_t association;
    const size_t tagSize;
    Challenger engine;
    std::array<uint8_t, 32> key1;
    std::array<uint8_t, 16> key2;
    std::vector<uint8_t> request{0xC5, 0x05, 0x0C, 0x01, 0x17, 0x01, 0x00, 0x03, 0x01,
                                 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::array<uint8_t, Challenger::CHALLENGE_SIZE> challenge{};
    std::array<uint8_t, Challenger::MAX_REQUEST_SIZE> authorized{};
    size_t size = 0;

    explicit Fixture(size_t tag = 16, uint16_t associationId = 7, uint32_t replyMs = 2000,
                     uint64_t validUntil = 100000)
        : association(associationId), tagSize(tag), engine(associationId, tag, replyMs)
    {
        key1.fill(0x11);
        key2.fill(0x22);
        REQUIRE(engine.GetState() == State::NO_SESSION_KEYS);
        REQUIRE(engine.SetSessionKey(1, Read(key1), validUntil, 1000) == Result::OK);
        REQUIRE(engine.SetSessionKey(2, Read(key2), validUntil, 1000) == Result::OK);
        REQUIRE(engine.GetState() == State::IDLE);
    }

    void Start(uint64_t now = 1000)
    {
        REQUIRE(engine.Challenge(association, Read(request), IINField(2, 0), now, Write(challenge), size)
                == Result::OK);
        REQUIRE(size == challenge.size());
        REQUIRE(engine.GetState() == State::WAITING_FOR_REPLY);
        REQUIRE(IsZero(authorized)); // no critical-request bytes published by Challenge.
    }

    uint32_t Sequence() const
    {
        Group120Var1 object;
        REQUIRE(object.Read(Read(challenge).skip(10)));
        return object.seqNum;
    }

    std::array<uint8_t, 16> Tag(rseq_t key, const std::vector<uint8_t>* alternate = nullptr) const
    {
        // Independent responder construction from IEEE A.45.2.2.2/Table A-3,
        // PDF p765 (printed p723): whole received Challenge APDU, THEN the
        // whole previously transmitted critical APDU, without lower-layer addresses.
        std::vector<uint8_t> data(challenge.begin(), challenge.end());
        const auto& critical = alternate ? *alternate : request;
        data.insert(data.end(), critical.begin(), critical.end());
        std::array<uint8_t, 16> tag{};
        REQUIRE(crypto::ComputeHMACSHA256(key, Read(data), Write(tag).take(tagSize)) == crypto::Result::OK);
        return tag;
    }

    Result Reply(const std::array<uint8_t, 16>& tag, uint16_t user = 1, uint64_t now = 1001)
    {
        authorized.fill(0xCC);
        size = 123;
        return engine.Reply(association, Group120Var2(Sequence(), user, Read(tag).take(tagSize)), now,
                            Write(authorized), size);
    }

    void Denied()
    {
        REQUIRE(size == 0);
        REQUIRE(IsZero(authorized));
    }
};
} // namespace

TEST_CASE("OutstationChallenger - exact challenge and IEEE MAC input", "[sa3a]")
{
    for (size_t tagSize : {8u, 16u})
    {
        Fixture f(tagSize);
        f.Start();
        // Fixed ASDU header, qualifier/count/size, CSQ, unknown USR, MAL, reason.
        // The only unpredictable part is the following 32-byte Challenge Data.
        HexSequence prefix(tagSize == 8 ? "C5 83 02 00 78 01 5B 01 28 00 01 00 00 00 00 00 03 01"
                                        : "C5 83 02 00 78 01 5B 01 28 00 01 00 00 00 00 00 04 01");
        REQUIRE(Read(f.challenge).take(18).equals(prefix.ToRSeq()));
        Group120Var1 decoded;
        REQUIRE(decoded.Read(Read(f.challenge).skip(10)));
        REQUIRE(decoded.userNum == 0);
        REQUIRE(decoded.challengeData.length() == 32);
        auto tag = f.Tag(Read(f.key1));
        const auto reply = Group120Var2(f.Sequence(), 1, Read(tag).take(tagSize));
        REQUIRE(f.Reply(tag) == Result::AUTHENTICATED);
        REQUIRE(f.size == f.request.size());
        REQUIRE(Read(f.authorized).take(f.size).equals(Read(f.request)));
        REQUIRE(f.engine.GetState() == State::IDLE);
        REQUIRE(f.engine.Reply(f.association, reply, 1002, Write(f.authorized), f.size) == Result::UNEXPECTED_REPLY);
        f.Denied(); // same valid Reply cannot authorize twice.
    }
}

TEST_CASE("OutstationChallenger - invalid MAC sequence user and transcript", "[sa3a]")
{
    Fixture f;
    f.Start();
    auto tag = f.Tag(Read(f.key1));
    SECTION("wrong MAC consumes pending authentication")
    {
        tag[0] ^= 1;
        REQUIRE(f.Reply(tag) == Result::INVALID_MAC);
        tag[0] ^= 1;
        REQUIRE(f.Reply(tag) == Result::UNEXPECTED_REPLY);
    }
    SECTION("wrong challenge sequence consumes pending authentication")
    {
        REQUIRE(f.engine.Reply(f.association, Group120Var2(f.Sequence() + 1, 1, Read(tag)), 1001, Write(f.authorized),
                               f.size)
                == Result::INVALID_SEQUENCE);
        REQUIRE(f.Reply(tag) == Result::UNEXPECTED_REPLY);
    }
    SECTION("unknown user")
    {
        REQUIRE(f.Reply(tag, 42) == Result::INVALID_USER);
    }
    SECTION("zero user")
    {
        REQUIRE(f.Reply(tag, 0) == Result::INVALID_USER);
    }
    SECTION("another known user must use that user's key")
    {
        REQUIRE(f.Reply(tag, 2) == Result::INVALID_MAC);
    }
    SECTION("truncated tag does not downgrade the negotiated length")
    {
        REQUIRE(f.engine.Reply(f.association, Group120Var2(f.Sequence(), 1, Read(tag).take(8)), 1001,
                               Write(f.authorized), f.size)
                == Result::INVALID_MAC);
    }
    SECTION("null MAC")
    {
        REQUIRE(f.engine.Reply(f.association, Group120Var2(f.Sequence(), 1, rseq_t(nullptr, 16)), 1001,
                               Write(f.authorized), f.size)
                == Result::INVALID_MAC);
    }
    SECTION("modified critical ASDU header")
    {
        auto modified = f.request;
        modified[0] ^= 1;
        REQUIRE(f.Reply(f.Tag(Read(f.key1), &modified)) == Result::INVALID_MAC);
    }
    SECTION("modified critical ASDU body")
    {
        auto modified = f.request;
        modified.back() ^= 1;
        REQUIRE(f.Reply(f.Tag(Read(f.key1), &modified)) == Result::INVALID_MAC);
    }
    SECTION("modified Challenge header is covered by MAC")
    {
        f.challenge[2] ^= 1; // IIN is part of the full fragment, not just G120V1.
        REQUIRE(f.Reply(f.Tag(Read(f.key1))) == Result::INVALID_MAC);
    }
    f.Denied();
    REQUIRE(f.engine.GetState() == State::IDLE);
}

TEST_CASE("OutstationChallenger - associations users and one bounded pending request", "[sa3a]")
{
    Fixture f;
    f.Start();
    const auto tag = f.Tag(Read(f.key2));
    SECTION("Reply chooses user and Control Direction key")
    {
        REQUIRE(f.Reply(tag, 2) == Result::AUTHENTICATED);
        REQUIRE(Read(f.authorized).take(f.size).equals(Read(f.request)));
    }
    SECTION("wrong association cannot use or consume pending authentication")
    {
        REQUIRE(f.engine.Reply(8, Group120Var2(f.Sequence(), 2, Read(tag)), 1001, Write(f.authorized), f.size)
                == Result::WRONG_ASSOCIATION);
        f.Denied();
        REQUIRE(f.engine.GetState() == State::WAITING_FOR_REPLY);
        REQUIRE(f.Reply(tag, 2) == Result::AUTHENTICATED);
    }
    SECTION("cross-association MAC does not authenticate a different challenge")
    {
        Fixture other(16, 8);
        other.Start();
        REQUIRE(f.Reply(other.Tag(Read(other.key2)), 2) == Result::INVALID_MAC);
        f.Denied();
    }
    SECTION("busy does not replace pending ASDU")
    {
        auto different = f.request;
        different.back() ^= 1;
        std::array<uint8_t, Challenger::CHALLENGE_SIZE> extra;
        size_t extraSize = 1;
        REQUIRE(f.engine.Challenge(f.association, Read(different), IINField::Empty(), 1001, Write(extra), extraSize)
                == Result::BUSY);
        REQUIRE(extraSize == 0);
        REQUIRE(IsZero(extra));
        REQUIRE(f.Reply(tag, 2) == Result::AUTHENTICATED);
        REQUIRE(Read(f.authorized).take(f.size).equals(Read(f.request)));
    }
    SECTION("caller cannot mutate the queued request after Challenge")
    {
        const auto original = f.request;
        f.request.assign(f.request.size(), 0xFF);
        REQUIRE(f.Reply(tag, 2) == Result::AUTHENTICATED);
        REQUIRE(Read(f.authorized).take(f.size).equals(Read(original)));
    }
}

TEST_CASE("OutstationChallenger - timeouts key expiry reset and fresh challenges", "[sa3a]")
{
    Fixture f;
    f.Start();
    const auto tag = f.Tag(Read(f.key1));
    SECTION("exact timeout boundary")
    {
        REQUIRE(f.Reply(tag, 1, 3000) == Result::EXPIRED);
        f.Denied();
        REQUIRE(f.Reply(tag, 1, 3001) == Result::UNEXPECTED_REPLY);
    }
    SECTION("explicit timer event discards pending state")
    {
        f.engine.Tick(3000);
        REQUIRE(f.engine.GetState() == State::IDLE);
        REQUIRE(f.Reply(tag, 1, 3000) == Result::UNEXPECTED_REPLY);
        f.Denied();
    }
    SECTION("before timeout")
    {
        REQUIRE(f.Reply(tag, 1, 2999) == Result::AUTHENTICATED);
    }
    SECTION("expired user keys")
    {
        f.engine.Tick(100000);
        REQUIRE(f.Reply(tag, 1, 100000) == Result::UNEXPECTED_REPLY);
        f.Denied();
        REQUIRE(f.engine.GetState() == State::NO_SESSION_KEYS);
    }
    SECTION("selected user's validity deadline before reply deadline")
    {
        REQUIRE(f.engine.SetSessionKey(1, Read(f.key1), 1500, 1000) == Result::OK);
        f.Start();
        REQUIRE(f.Reply(f.Tag(Read(f.key1)), 1, 1500) == Result::INVALID_USER);
        f.Denied();
    }
    SECTION("clock moving backwards fails closed")
    {
        REQUIRE(f.Reply(tag, 1, 999) == Result::INVALID_INPUT);
        f.Denied();
        REQUIRE(f.engine.GetState() == State::NO_SESSION_KEYS);
    }
    SECTION("reset destroys pending authorization and session keys")
    {
        f.engine.Reset();
        REQUIRE(f.engine.GetState() == State::NO_SESSION_KEYS);
        REQUIRE(f.Reply(tag) == Result::UNEXPECTED_REPLY);
        f.Denied();
        const auto previous = f.challenge;
        const auto oldSequence = f.Sequence();
        REQUIRE(f.engine.SetSessionKey(1, Read(f.key1), 100000, 1002) == Result::OK);
        f.Start(1002);
        REQUIRE(f.Sequence() == oldSequence + 1);
        REQUIRE_FALSE(Read(previous).skip(18).equals(Read(f.challenge).skip(18)));
        REQUIRE(
            f.engine.Reply(f.association, Group120Var2(oldSequence, 1, Read(tag)), 1003, Write(f.authorized), f.size)
            == Result::INVALID_SEQUENCE);
        f.Denied();
    }
    SECTION("key replacement invalidates pending authentication")
    {
        REQUIRE(f.engine.SetSessionKey(1, Read(f.key1), 100000, 1001) == Result::OK);
        REQUIRE(f.Reply(tag) == Result::UNEXPECTED_REPLY);
        f.Denied();
    }
    SECTION("CSQ is shared across users, not reset on successful authentication")
    {
        REQUIRE(f.Reply(tag) == Result::AUTHENTICATED);
        const auto previous = f.challenge;
        f.authorized.fill(0);
        f.Start(1002);
        REQUIRE(f.Sequence() == 2);
        REQUIRE_FALSE(Read(previous).skip(18).equals(Read(f.challenge).skip(18)));
        REQUIRE(f.Reply(f.Tag(Read(f.key2)), 2, 1003) == Result::AUTHENTICATED);
    }
}

TEST_CASE("OutstationChallenger - missing keys and buffer bounds fail closed", "[sa3a]")
{
    Fixture f;
    SECTION("no keys")
    {
        f.engine.Reset();
        f.challenge.fill(0xCC);
        f.Start(1001);
        REQUIRE(f.Reply(f.Tag(Read(f.key1)), 1, 1002) == Result::INVALID_USER);
        f.Denied();
        REQUIRE(f.engine.GetState() == State::NO_SESSION_KEYS);
    }
    SECTION("invalid key lengths user and expired material")
    {
        REQUIRE(f.engine.SetSessionKey(0, Read(f.key1), 100000, 1000) == Result::INVALID_INPUT);
        REQUIRE(f.engine.SetSessionKey(3, Read(f.key1).take(15), 100000, 1000) == Result::INVALID_INPUT);
        REQUIRE(f.engine.SetSessionKey(3, rseq_t(nullptr, 32), 100000, 1000) == Result::INVALID_INPUT);
        REQUIRE(f.engine.SetSessionKey(3, Read(f.key1), 1000, 1000) == Result::INVALID_INPUT);
        REQUIRE(f.engine.SetSessionKey(3, Read(f.key1), 100000, 1000) == Result::BUSY);
    }
    SECTION("Challenge output too small")
    {
        REQUIRE(f.engine.Challenge(7, Read(f.request), IINField::Empty(), 1000, Write(f.challenge).take(49), f.size)
                == Result::OUTPUT_TOO_SMALL);
        REQUIRE(f.size == 0);
        REQUIRE(f.engine.GetState() == State::IDLE);
    }
    SECTION("null oversized and truncated requests")
    {
        for (auto request :
             {rseq_t(nullptr, 2), Read(f.request).take(1), rseq_t(f.request.data(), Challenger::MAX_REQUEST_SIZE + 1)})
            REQUIRE(f.engine.Challenge(7, request, IINField::Empty(), 1000, Write(f.challenge), f.size)
                    == Result::INVALID_INPUT);
        REQUIRE(f.engine.GetState() == State::IDLE);
    }
    SECTION("output overlapping input is rejected")
    {
        std::array<uint8_t, Challenger::CHALLENGE_SIZE> shared{};
        REQUIRE(f.engine.Challenge(7, Read(shared).take(18), IINField::Empty(), 1000, Write(shared), f.size)
                == Result::INVALID_INPUT);
    }
    SECTION("maximum configured request size")
    {
        f.request.resize(Challenger::MAX_REQUEST_SIZE, 0xAA);
        f.Start();
        REQUIRE(f.Reply(f.Tag(Read(f.key1))) == Result::AUTHENTICATED);
        REQUIRE(f.size == f.request.size());
        REQUIRE(Read(f.authorized).equals(Read(f.request)));
    }
    SECTION("valid MAC with insufficient authorization output still cannot authorize")
    {
        f.Start();
        const auto tag = f.Tag(Read(f.key1));
        REQUIRE(f.engine.Reply(7, Group120Var2(f.Sequence(), 1, Read(tag)), 1001,
                               Write(f.authorized).take(f.request.size() - 1), f.size)
                == Result::OUTPUT_TOO_SMALL);
        REQUIRE(f.size == 0);
        REQUIRE(f.Reply(tag) == Result::UNEXPECTED_REPLY);
        f.Denied();
    }
}

TEST_CASE("OutstationChallenger - CryptoProvider failures never authorize", "[sa3a]")
{
    Fixture f;
    f.Start();
    const auto tag = f.Tag(Read(f.key1));
    std::unique_ptr<OSSL_LIB_CTX, decltype(&OSSL_LIB_CTX_free)> context(OSSL_LIB_CTX_new(), OSSL_LIB_CTX_free);
    REQUIRE(context);
    std::unique_ptr<OSSL_PROVIDER, decltype(&OSSL_PROVIDER_unload)> provider(OSSL_PROVIDER_load(context.get(), "null"),
                                                                             OSSL_PROVIDER_unload);
    REQUIRE(provider);
    struct RestoreContext
    {
        OSSL_LIB_CTX* current;
        OSSL_LIB_CTX* previous;
        ~RestoreContext()
        {
            OSSL_LIB_CTX_set0_default(previous);
            OPENSSL_thread_stop_ex(current);
            ERR_clear_error();
        }
    } restore{context.get(), OSSL_LIB_CTX_set0_default(context.get())};
    REQUIRE(restore.previous);
    REQUIRE(f.Reply(tag) == Result::CRYPTO_ERROR);
    f.Denied();
    REQUIRE(f.engine.GetState() == State::IDLE);
    f.challenge.fill(0xCC);
    REQUIRE(f.engine.Challenge(7, Read(f.request), IINField::Empty(), 1002, Write(f.challenge), f.size)
            == Result::CRYPTO_ERROR);
    REQUIRE(f.size == 0);
    REQUIRE(IsZero(f.challenge));
    REQUIRE(f.engine.GetState() == State::IDLE);
}

TEST_CASE("OutstationChallenger - unprovisioned Outstation emits Challenge without authorizing", "[sa3a]")
{
    Fixture f(GENERATE(8u, 16u));
    Challenger unprovisioned(f.association, f.tagSize);
    REQUIRE(unprovisioned.GetState() == State::NO_SESSION_KEYS);
    REQUIRE(unprovisioned.Challenge(f.association, Read(f.request), IINField(2, 0), 1000,
                                    Write(f.challenge), f.size) == Result::OK);
    REQUIRE(f.size == f.challenge.size());
    REQUIRE(unprovisioned.GetState() == State::WAITING_FOR_REPLY);
    HexSequence prefix(f.tagSize == 8 ? "C5 83 02 00 78 01 5B 01 28 00 01 00 00 00 00 00 03 01"
                                     : "C5 83 02 00 78 01 5B 01 28 00 01 00 00 00 00 00 04 01");
    REQUIRE(Read(f.challenge).take(18).equals(prefix.ToRSeq()));
    Group120Var1 challenge;
    REQUIRE(challenge.Read(Read(f.challenge).skip(10)));
    REQUIRE(challenge.challengeData.length() == Challenger::CHALLENGE_DATA_SIZE);
    REQUIRE(IsZero(f.authorized));
    // Even a correctly calculated tag cannot authenticate an uninstalled user key.
    const auto tag = f.Tag(Read(f.key1));
    f.authorized.fill(0xCC);
    f.size = 123;
    REQUIRE(unprovisioned.Reply(f.association, Group120Var2(f.Sequence(), 1, Read(tag).take(f.tagSize)),
                                1001, Write(f.authorized), f.size) == Result::INVALID_USER);
    f.Denied();
    REQUIRE(unprovisioned.GetState() == State::NO_SESSION_KEYS);
}

TEST_CASE("OutstationChallenger - expired keys permit a fresh Challenge but cannot authenticate", "[sa3a]")
{
    Fixture f(GENERATE(8u, 16u));
    f.Start();
    const auto previous = f.challenge;
    const auto previousSequence = f.Sequence();
    f.engine.Tick(100000);
    REQUIRE(f.engine.GetState() == State::NO_SESSION_KEYS);
    f.Start(100000);
    REQUIRE(f.Sequence() == previousSequence + 1);
    REQUIRE_FALSE(Read(previous).skip(18).equals(Read(f.challenge).skip(18)));
    REQUIRE(f.Reply(f.Tag(Read(f.key1)), 1, 100001) == Result::INVALID_USER);
    f.Denied();
    REQUIRE(f.engine.GetState() == State::NO_SESSION_KEYS);
}

TEST_CASE("OutstationChallenger - keyless pending timeout and replay require a new valid handshake", "[sa3a]")
{
    Fixture f(GENERATE(8u, 16u));
    f.engine.Reset();
    f.Start();
    const auto expiredSequence = f.Sequence();
    const auto expiredTag = f.Tag(Read(f.key1));
    f.engine.Tick(3000);
    REQUIRE(f.engine.GetState() == State::NO_SESSION_KEYS);
    REQUIRE(f.Reply(expiredTag, 1, 3000) == Result::UNEXPECTED_REPLY);
    f.Denied();
    f.Start(3001);
    REQUIRE(f.Sequence() == expiredSequence + 1);
    REQUIRE(f.engine.Reply(f.association, Group120Var2(expiredSequence, 1, Read(expiredTag).take(f.tagSize)),
                           3002, Write(f.authorized), f.size) == Result::INVALID_SEQUENCE);
    f.Denied();
    REQUIRE(f.engine.GetState() == State::NO_SESSION_KEYS);
    REQUIRE(f.engine.SetSessionKey(1, Read(f.key1), 100000, 3003) == Result::OK);
    f.Start(3003);
    const auto validTag = f.Tag(Read(f.key1));
    REQUIRE(f.Reply(validTag, 1, 3004) == Result::AUTHENTICATED);
    REQUIRE(f.size == f.request.size());
    REQUIRE(Read(f.authorized).take(f.size).equals(Read(f.request)));
    REQUIRE(f.Reply(validTag, 1, 3005) == Result::UNEXPECTED_REPLY);
    f.Denied();
}

TEST_CASE("OutstationChallenger - immediate expiry never releases an ASDU", "[sa-reply-timeout]")
{
    Challenger engine(7, 16, 0);
    AuthenticationStatistics stats(7, false, DefaultSecurityStatisticThresholds());
    engine.SetStatistics(&stats);
    std::array<uint8_t, 32> key{};
    REQUIRE(engine.SetSessionKey(1, Read(key), 1000000, 0) == Result::OK);
    const std::array<uint8_t, 2> request{{0xC5, 0x06}};
    std::array<uint8_t, Challenger::CHALLENGE_SIZE> challenge{};
    std::array<uint8_t, Challenger::MAX_REQUEST_SIZE> authorized{};
    size_t size = 0;
    REQUIRE(engine.Challenge(7, Read(request), IINField::Empty(), 0, Write(challenge), size) == Result::OK);
    engine.Tick(0);
    for (size_t n = 0; n < 100; ++n) engine.Tick(0);
    REQUIRE(stats.Value(SecurityStatistic::REPLY_TIMEOUTS) == 1);
    REQUIRE(engine.GetState() == State::IDLE);
    std::array<uint8_t, 16> tag{};
    Group120Var2 reply(1, 1, Read(tag));
    REQUIRE(engine.Reply(7, reply, 0, Write(authorized), size) == Result::UNEXPECTED_REPLY);
    REQUIRE(size == 0);
    REQUIRE(IsZero(authorized));
    REQUIRE(engine.Challenge(7, Read(request), IINField::Empty(), 1, Write(challenge), size) == Result::OK);
    engine.Tick(1);
    REQUIRE(stats.Value(SecurityStatistic::REPLY_TIMEOUTS) == 2);
}

TEST_CASE("OutstationChallenger - nonzero reply expiry boundaries remain exclusive", "[sa-reply-timeout][sa-v06-boundary]")
{
    const uint32_t timeout = GENERATE(100u, 2000u, 120000u);
    const uint64_t elapsed = uint64_t(timeout) - 1 + GENERATE(0u, 1u, 2u);
    CAPTURE(timeout, elapsed);
    AuthenticationStatistics stats(7, false, DefaultSecurityStatisticThresholds());
    Fixture f(16, 7, timeout, uint64_t(1000) + timeout + 10000);
    f.engine.SetStatistics(&stats);
    f.Start();
    const auto csq = f.Sequence();
    const auto tag = f.Tag(Read(f.key1));
    const auto now = 1000 + elapsed;
    const auto result = f.Reply(tag, 1, now);
    REQUIRE(result == (elapsed < timeout ? Result::AUTHENTICATED : Result::EXPIRED));
    REQUIRE(f.size == (elapsed < timeout ? f.request.size() : 0));
    if (elapsed < timeout) REQUIRE(Read(f.authorized).take(f.size).equals(Read(f.request)));
    else REQUIRE(IsZero(f.authorized));
    REQUIRE(f.Sequence() == csq);
    f.engine.Tick(now);
    f.engine.Tick(now + 1);
    REQUIRE(f.Reply(tag, 1, now + 1) == Result::UNEXPECTED_REPLY);
    REQUIRE(f.size == 0);
    REQUIRE(IsZero(f.authorized));
    REQUIRE(stats.Value(SecurityStatistic::REPLY_TIMEOUTS) == (elapsed < timeout ? 0 : 1));
}
