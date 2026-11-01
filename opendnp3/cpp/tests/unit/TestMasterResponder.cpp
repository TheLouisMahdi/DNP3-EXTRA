// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/APDUResponse.h"
#include "app/parsing/APDUHeaderParser.h"
#include "app/parsing/APDUParser.h"
#include "master/MasterResponder.h"
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
using MR = MasterResponder::Result;
using MS = MasterResponder::State;
using OR = OutstationChallenger::Result;

namespace
{
template<class T> rseq_t Read(const T& data)
{
    return rseq_t(data.data(), data.size());
}
template<class T> wseq_t Write(T& data)
{
    return wseq_t(data.data(), data.size());
}
template<class T> bool Zero(const T& data)
{
    return std::all_of(data.begin(), data.end(), [](uint8_t v) { return v == 0; });
}
bool Zero(rseq_t data)
{
    const uint8_t* begin = data;
    return std::all_of(begin, begin + data.length(), [](uint8_t v) { return v == 0; });
}

class ReplyHandler final : public IAPDUHandler
{
public:
    Group120Var2 reply;
    bool valid = false;
    bool IsAllowed(uint32_t count, GroupVariation gv, QualifierCode qc) override
    {
        return count == 0 && gv == GroupVariation::Group120Var2 && qc == QualifierCode::FREE_FORMAT;
    }

private:
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var2>& values) override
    {
        valid = values.Count() == 1;
        if (valid)
            values.ForeachItem([this](const Group120Var2& value) { reply = value; });
        return IINField::Empty();
    }
};

std::vector<uint8_t> Challenge(uint32_t csq = 1, uint8_t algorithm = 4, size_t nonceSize = 32)
{
    std::vector<uint8_t> nonce(nonceSize);
    for (size_t i = 0; i < nonce.size(); ++i)
        nonce[i] = static_cast<uint8_t>(i);
    std::vector<uint8_t> bytes(18 + nonce.size());
    Group120Var1 object(csq, 0, algorithm, 1, Read(nonce));
    APDUResponse response(Write(bytes));
    response.SetControl(AppControlField(true, true, false, false, 5));
    response.SetFunction(FunctionCode::AUTH_RESPONSE);
    response.SetIIN(IINField(2, 0));
    auto writer = response.GetWriter();
    REQUIRE(writer.WriteFreeFormat(&object, 1));
    REQUIRE(response.Size() == bytes.size());
    return bytes;
}

struct Fixture
{
    MasterResponder master;
    OutstationChallenger outstation;
    const size_t tagSize;
    const uint16_t user;
    std::array<uint8_t, 32> key;
    std::vector<uint8_t> request{0xC5, 0x05, 0x0C, 0x01, 0x17, 0x01, 0x00, 0x03, 0x01,
                                 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::array<uint8_t, OutstationChallenger::CHALLENGE_SIZE> challenge{};
    std::array<uint8_t, 30> reply;
    std::array<uint8_t, OutstationChallenger::MAX_REQUEST_SIZE> authorized{};
    size_t replySize = 0;
    size_t authorizedSize = 0;

    explicit Fixture(size_t tag = 16, uint16_t number = 1)
        : master(7, tag), outstation(7, tag), tagSize(tag), user(number)
    {
        key.fill(0x11);
        REQUIRE(master.GetState() == MS::NO_SESSION_KEYS);
        Provision();
        REQUIRE(outstation.SetSessionKey(user, Read(key), 100000, 1000) == OR::OK);
    }
    void Provision(uint64_t now = 1000, uint64_t expiry = 100000)
    {
        REQUIRE(master.SetSessionKey(user, Read(key), expiry, now) == MR::OK);
        REQUIRE(master.GetState() == MS::IDLE);
        REQUIRE(master.RetainRequest(7, Read(request), now) == MR::OK);
        REQUIRE(master.GetState() == MS::WAITING_FOR_CHALLENGE);
    }
    void Start()
    {
        size_t size = 0;
        REQUIRE(outstation.Challenge(7, Read(request), IINField(2, 0), 1001, Write(challenge), size) == OR::OK);
        REQUIRE(size == challenge.size());
        REQUIRE(Zero(authorized));
    }
    MR Respond(rseq_t input, uint64_t now = 1002)
    {
        reply.fill(0xCC);
        replySize = 123;
        return master.Respond(7, input, now, Write(reply), replySize);
    }
    void Denied()
    {
        REQUIRE(replySize == 0);
        REQUIRE(Zero(reply));
        REQUIRE(master.GetState() == MS::NO_SESSION_KEYS);
    }
    OR Verify(uint64_t now = 1003)
    {
        const auto header = APDUHeaderParser::ParseRequest(Read(reply).take(replySize));
        REQUIRE(header.success);
        REQUIRE(header.header.function == FunctionCode::AUTH_REQUEST);
        REQUIRE(header.header.control.ToByte() == 0xC5);
        ReplyHandler handler;
        REQUIRE(APDUParser::Parse(header.objects, handler, nullptr) == ParseResult::OK);
        REQUIRE(handler.valid);
        REQUIRE(handler.reply.userNum == user);
        REQUIRE(handler.reply.hmacValue.length() == tagSize);
        return outstation.Reply(7, handler.reply, now, Write(authorized), authorizedSize);
    }
};
} // namespace

TEST_CASE("MasterResponder - exact IEEE transcript and Reply bytes", "[sa4a]")
{
    // Independent fixture MACs computed with Python stdlib hmac/SHA256 over the
    // literal full Challenge (nonce 00..1F) || literal original critical request.
    // IEEE Table A-3 (PDF p765), A.45.2, and application SEQ rule 7.5.1.3 (p234).
    for (size_t tag : {8u, 16u})
    {
        Fixture f(tag);
        auto challenge = Challenge(1, tag == 8 ? 3 : 4);
        REQUIRE(f.Respond(Read(challenge)) == MR::OK);
        HexSequence expected(
            tag == 8 ? "C5 20 78 02 5B 01 0E 00 01 00 00 00 01 00 7D EF 6B B3 F2 85 05 05"
                     : "C5 20 78 02 5B 01 16 00 01 00 00 00 01 00 09 5C 2D 5E E7 D3 9E E1 45 F6 4A 94 4C 70 7E 46");
        REQUIRE(f.replySize == expected.ToRSeq().length());
        REQUIRE(Read(f.reply).take(f.replySize).equals(expected.ToRSeq()));
        REQUIRE(f.master.GetState() == MS::IDLE);
    }
}

TEST_CASE("MasterResponder - full internal handshake with OutstationChallenger", "[sa4a]")
{
    for (size_t tag : {8u, 16u})
        for (uint16_t user : {1u, 2u})
        {
            Fixture f(tag, user);
            f.Start();
            const auto original = f.request;
            f.request.assign(f.request.size(), 0xFF); // caller mutation cannot change retained request.
            REQUIRE(f.Respond(Read(f.challenge)) == MR::OK);
            REQUIRE(Zero(f.authorized)); // Master emission does not authorize or execute anything.
            REQUIRE(f.Verify() == OR::AUTHENTICATED);
            REQUIRE(f.authorizedSize == original.size());
            REQUIRE(Read(f.authorized).take(f.authorizedSize).equals(Read(original)));
        }
}

TEST_CASE("MasterResponder - wrong key and configured user fail at Challenger", "[sa4a]")
{
    Fixture f;
    f.Start();
    SECTION("wrong Control Direction key")
    {
        auto wrongKey = f.key;
        wrongKey[0] ^= 1;
        REQUIRE(f.master.SetSessionKey(1, Read(wrongKey), 100000, 1001) == MR::OK);
        REQUIRE(f.master.RetainRequest(7, Read(f.request), 1001) == MR::OK);
        // A Responder cannot determine whether the peer holds the same key.
        REQUIRE(f.Respond(Read(f.challenge)) == MR::OK);
        REQUIRE(f.Verify() == OR::INVALID_MAC);
    }
    SECTION("user not provisioned at the Challenger")
    {
        Fixture other(16, 9);
        REQUIRE(other.Respond(Read(f.challenge)) == MR::OK);
        ReplyHandler handler;
        const auto header = APDUHeaderParser::ParseRequest(Read(other.reply).take(other.replySize));
        REQUIRE(header.success);
        REQUIRE(APDUParser::Parse(header.objects, handler, nullptr) == ParseResult::OK);
        REQUIRE(handler.valid);
        REQUIRE(f.outstation.Reply(7, handler.reply, 1003, Write(f.authorized), f.authorizedSize) == OR::INVALID_USER);
    }
    REQUIRE(f.authorizedSize == 0);
    REQUIRE(Zero(f.authorized));
}

TEST_CASE("MasterResponder - malformed or unexpected Challenge fails closed", "[sa4a]")
{
    Fixture f;
    auto bytes = Challenge();
    MR expected = MR::INVALID_CHALLENGE;
    SECTION("wrong function")
    {
        bytes[1] = 0x81;
    }
    SECTION("fragmented")
    {
        bytes[0] &= ~0x40;
    }
    SECTION("unsolicited")
    {
        bytes[0] |= 0x10;
    }
    SECTION("confirm bit requesting excluded Aggressive Mode")
    {
        bytes[0] |= 0x20;
    }
    SECTION("application sequence mismatch")
    {
        bytes[0] ^= 1;
        expected = MR::INVALID_SEQUENCE;
    }
    SECTION("wrong qualifier")
    {
        bytes[6] = 0x07;
    }
    SECTION("zero count")
    {
        bytes[7] = 0;
    }
    SECTION("wrong payload length")
    {
        bytes[8] -= 1;
    }
    SECTION("truncated payload")
    {
        bytes.pop_back();
    }
    SECTION("trailing garbage")
    {
        bytes.push_back(0xFF);
    }
    SECTION("second header")
    {
        const auto copy = bytes;
        bytes.insert(bytes.end(), copy.begin() + 4, copy.end());
    }
    SECTION("two objects in a single header")
    {
        const auto copy = bytes;
        bytes[7] = 2;
        bytes.insert(bytes.end(), copy.begin() + 8, copy.end());
    }
    SECTION("nonzero Outstation Challenge user")
    {
        bytes[14] = 1;
        expected = MR::INVALID_USER;
    }
    SECTION("unsupported MAC algorithm")
    {
        bytes[16] = 6;
        expected = MR::UNSUPPORTED_ALGORITHM;
    }
    SECTION("algorithm downgrade")
    {
        bytes[16] = 3;
        expected = MR::UNSUPPORTED_ALGORITHM;
    }
    SECTION("invalid reason")
    {
        bytes[17] = 0;
    }
    REQUIRE(f.Respond(Read(bytes)) == expected);
    f.Denied();
}

TEST_CASE("MasterResponder - CSQ replay history is association wide", "[sa4a]")
{
    Fixture f;
    auto first = Challenge(0xFFFFFFFFu);
    REQUIRE(f.Respond(Read(first)) == MR::OK);
    SECTION("duplicate when no request is pending")
    {
        REQUIRE(f.Respond(Read(first), 1003) == MR::UNEXPECTED_CHALLENGE);
    }
    SECTION("duplicate against a new request")
    {
        REQUIRE(f.master.RetainRequest(7, Read(f.request), 1003) == MR::OK);
        REQUIRE(f.Respond(Read(first), 1004) == MR::INVALID_SEQUENCE);
    }
    SECTION("reset and key/user replacement do not erase CSQ history")
    {
        f.master.Reset();
        REQUIRE(f.master.SetSessionKey(2, Read(f.key).take(16), 100000, 1003) == MR::OK);
        REQUIRE(f.master.RetainRequest(7, Read(f.request), 1003) == MR::OK);
        REQUIRE(f.Respond(Read(first), 1004) == MR::INVALID_SEQUENCE);
    }
    SECTION("backward CSQ")
    {
        REQUIRE(f.master.RetainRequest(7, Read(f.request), 1003) == MR::OK);
        REQUIRE(f.Respond(Read(Challenge(0xFFFFFFFEu)), 1004) == MR::INVALID_SEQUENCE);
    }
    SECTION("UINT32 rollover and forward gaps are accepted")
    {
        REQUIRE(f.master.RetainRequest(7, Read(f.request), 1003) == MR::OK);
        Group120Var1 embedded;
        const auto wrapped = Challenge(0);
        REQUIRE(embedded.Read(Read(wrapped).skip(10)));
        REQUIRE(f.master.ObserveEmbeddedChallenge(7, embedded, true, 1004));
        REQUIRE(f.Respond(Read(wrapped), 1004) == MR::INVALID_SEQUENCE);
        f.Provision(1005);
        REQUIRE(f.Respond(Read(Challenge(3)), 1006) == MR::OK);
        return;
    }
    f.Denied();
}

TEST_CASE("MasterResponder - association timeout session validity and reset", "[sa4a]")
{
    Fixture f;
    auto bytes = Challenge();
    SECTION("wrong association preserves the actual association's request")
    {
        f.reply.fill(0xCC);
        REQUIRE(f.master.Respond(8, Read(bytes), 1002, Write(f.reply), f.replySize) == MR::WRONG_ASSOCIATION);
        REQUIRE(Zero(f.reply));
        REQUIRE(f.replySize == 0);
        REQUIRE(f.master.GetState() == MS::WAITING_FOR_CHALLENGE);
        REQUIRE(f.Respond(Read(bytes)) == MR::OK);
        return;
    }
    SECTION("pending timeout boundary")
    {
        REQUIRE(f.Respond(Read(bytes), 3000) == MR::EXPIRED);
    }
    SECTION("session expiry before pending timeout")
    {
        f.Provision(1000, 1100);
        REQUIRE(f.Respond(Read(bytes), 1100) == MR::EXPIRED);
    }
    SECTION("clock moving backwards")
    {
        REQUIRE(f.Respond(Read(bytes), 999) == MR::INVALID_INPUT);
    }
    SECTION("explicit timer event")
    {
        f.master.Tick(3000);
        REQUIRE(f.Respond(Read(bytes), 3000) == MR::NO_SESSION_KEYS);
    }
    SECTION("reset")
    {
        f.master.Reset();
        REQUIRE(f.Respond(Read(bytes)) == MR::NO_SESSION_KEYS);
    }
    SECTION("key installation cancels previous pending request")
    {
        REQUIRE(f.master.SetSessionKey(1, Read(f.key), 100000, 1001) == MR::OK);
        REQUIRE(f.Respond(Read(bytes)) == MR::UNEXPECTED_CHALLENGE);
    }
    f.Denied();
}

TEST_CASE("MasterResponder - bounded buffers and pending state", "[sa4a]")
{
    Fixture f;
    auto bytes = Challenge();
    SECTION("busy does not replace exact original request")
    {
        auto other = f.request;
        other.back() ^= 1;
        REQUIRE(f.master.RetainRequest(7, Read(other), 1001) == MR::BUSY);
        f.Start();
        REQUIRE(f.Respond(Read(f.challenge)) == MR::OK);
        REQUIRE(f.Verify() == OR::AUTHENTICATED);
        REQUIRE(Read(f.authorized).take(f.authorizedSize).equals(Read(f.request)));
    }
    SECTION("oversized request rejected")
    {
        REQUIRE(f.master.SetSessionKey(1, Read(f.key), 100000, 1001) == MR::OK);
        REQUIRE(f.master.RetainRequest(7, rseq_t(f.request.data(), MasterResponder::MAX_REQUEST_SIZE + 1), 1001)
                == MR::INVALID_INPUT);
        REQUIRE(f.master.GetState() == MS::NO_SESSION_KEYS);
    }
    SECTION("maximum request size retains exact bytes")
    {
        f.request.resize(MasterResponder::MAX_REQUEST_SIZE, 0xAA);
        f.Provision();
        f.Start();
        REQUIRE(f.Respond(Read(f.challenge)) == MR::OK);
        REQUIRE(f.Verify() == OR::AUTHENTICATED);
        REQUIRE(Read(f.authorized).equals(Read(f.request)));
    }
    SECTION("maximum Challenge size uses the existing variable-length codec")
    {
        const auto large = Challenge(1, 4, MasterResponder::MAX_CHALLENGE_SIZE - 18);
        REQUIRE(f.Respond(Read(large)) == MR::OK);
    }
    SECTION("oversized Challenge")
    {
        REQUIRE(f.Respond(rseq_t(bytes.data(), MasterResponder::MAX_CHALLENGE_SIZE + 1)) == MR::INVALID_CHALLENGE);
        f.Denied();
    }
    SECTION("null Challenge")
    {
        REQUIRE(f.Respond(rseq_t(nullptr, 50)) == MR::INVALID_CHALLENGE);
        f.Denied();
    }
    SECTION("Reply buffer too small")
    {
        f.reply.fill(0xCC);
        REQUIRE(f.master.Respond(7, Read(bytes), 1002, Write(f.reply).take(29), f.replySize) == MR::OUTPUT_TOO_SMALL);
        REQUIRE(f.replySize == 0);
        REQUIRE(Zero(Read(f.reply).take(29)));
        REQUIRE(f.reply[29] == 0xCC);
        REQUIRE(f.master.GetState() == MS::NO_SESSION_KEYS);
    }
    SECTION("null Reply output")
    {
        REQUIRE(f.master.Respond(7, Read(bytes), 1002, wseq_t(nullptr, 30), f.replySize) == MR::OUTPUT_TOO_SMALL);
        REQUIRE(f.replySize == 0);
        REQUIRE(f.master.GetState() == MS::NO_SESSION_KEYS);
    }
    SECTION("overlapping input and output")
    {
        REQUIRE(f.master.Respond(7, Read(bytes), 1002, Write(bytes), f.replySize) == MR::INVALID_CHALLENGE);
        REQUIRE(Zero(bytes));
        REQUIRE(f.replySize == 0);
        REQUIRE(f.master.GetState() == MS::NO_SESSION_KEYS);
    }
    SECTION("invalid test session material cancels pending state")
    {
        REQUIRE(f.master.SetSessionKey(0, Read(f.key), 100000, 1001) == MR::INVALID_INPUT);
        REQUIRE(f.master.SetSessionKey(1, Read(f.key).take(15), 100000, 1001) == MR::INVALID_INPUT);
        REQUIRE(f.master.SetSessionKey(1, rseq_t(nullptr, 32), 100000, 1001) == MR::INVALID_INPUT);
        REQUIRE(f.master.SetSessionKey(1, Read(f.key), 1001, 1001) == MR::INVALID_INPUT);
        REQUIRE(f.Respond(Read(bytes)) == MR::NO_SESSION_KEYS);
        f.Denied();
    }
}

TEST_CASE("MasterResponder - CryptoProvider failure cannot emit a Reply", "[sa4a]")
{
    Fixture f;
    auto bytes = Challenge();
    std::unique_ptr<OSSL_LIB_CTX, decltype(&OSSL_LIB_CTX_free)> context(OSSL_LIB_CTX_new(), OSSL_LIB_CTX_free);
    REQUIRE(context);
    std::unique_ptr<OSSL_PROVIDER, decltype(&OSSL_PROVIDER_unload)> provider(OSSL_PROVIDER_load(context.get(), "null"),
                                                                             OSSL_PROVIDER_unload);
    REQUIRE(provider);
    struct Restore
    {
        OSSL_LIB_CTX* current;
        OSSL_LIB_CTX* previous;
        ~Restore()
        {
            OSSL_LIB_CTX_set0_default(previous);
            OPENSSL_thread_stop_ex(current);
            ERR_clear_error();
        }
    } restore{context.get(), OSSL_LIB_CTX_set0_default(context.get())};
    REQUIRE(restore.previous);
    REQUIRE(f.Respond(Read(bytes)) == MR::CRYPTO_ERROR);
    f.Denied();
}

TEST_CASE("MasterResponder - embedded and standalone Challenges share association CSQ history", "[sa4a]")
{
    Fixture f;
    auto unsolicited = Challenge(11);
    Group120Var1 value;
    REQUIRE(value.Read(Read(unsolicited).skip(10)));
    REQUIRE(f.master.ObserveEmbeddedChallenge(7, value, true, 1001));
    REQUIRE(f.master.GetState() == MS::WAITING_FOR_CHALLENGE);
    REQUIRE_FALSE(f.master.ObserveEmbeddedChallenge(7, value, true, 1001));
    const auto stale = GENERATE(10u, 11u);
    REQUIRE(f.Respond(Read(Challenge(stale)), 1002) == MR::INVALID_SEQUENCE);
    f.Denied();
    f.Provision(1003); // Failure/reset preserves the association watermark.
    auto solicited = Challenge(12);
    REQUIRE(f.Respond(Read(solicited), 1004) == MR::OK);
    value.seqNum = 12;
    REQUIRE_FALSE(f.master.ObserveEmbeddedChallenge(7, value, true, 1005));
    value.seqNum = 13;
    REQUIRE_FALSE(f.master.ObserveEmbeddedChallenge(8, value, false, 1005));
    value.userNum = 1;
    REQUIRE_FALSE(f.master.ObserveEmbeddedChallenge(7, value, false, 1005));
    value.userNum = 0; value.macAlgorithm = 3;
    REQUIRE_FALSE(f.master.ObserveEmbeddedChallenge(7, value, false, 1005));
    value.macAlgorithm = 4;
    REQUIRE(f.master.ObserveEmbeddedChallenge(7, value, true, 1005));
    REQUIRE(f.master.SetSessionKey(1, Read(f.key), 100000, 1006) == MR::OK);
    REQUIRE(f.master.RetainRequest(7, Read(f.request), 1006) == MR::OK);
    REQUIRE(f.Respond(Read(solicited), 1007) == MR::INVALID_SEQUENCE);
    f.Denied();
}
