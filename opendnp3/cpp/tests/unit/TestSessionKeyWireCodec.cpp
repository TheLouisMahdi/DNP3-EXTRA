/*
 * Copyright 2013-2020 Automatak, LLC
 *
 * Licensed to Green Energy Corp (www.greenenergycorp.com) and Automatak
 * LLC (www.automatak.com) under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership. Green Energy Corp and Automatak LLC license
 * this file to you under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License. You may obtain
 * a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "utils/BufferHelpers.h"
#include "app/APDURequest.h"
#include "app/parsing/APDUParser.h"
#include <ser4cpp/util/HexConversions.h>
#include <catch.hpp>
#include <vector>

using namespace opendnp3;
using namespace ser4cpp;

namespace
{
struct SessionWireHandler final : IAPDUHandler
{
    std::vector<std::string> payloads;
    bool IsAllowed(uint32_t, GroupVariation, QualifierCode) override { return true; }
    template<class T> IINField Save(const ICollection<T>& values)
    {
        values.ForeachItem([this](const T& v) {
            std::vector<uint8_t> data(v.Size());
            wseq_t out(data.data(), data.size());
            REQUIRE(v.Write(out));
            payloads.push_back(HexConversions::to_hex(rseq_t(data.data(), data.size())));
        });
        return IINField::Empty();
    }
    template<class T> IINField SaveFixed(const ICollection<T>& values)
    {
        values.ForeachItem([this](const T& v) {
            std::vector<uint8_t> data(T::Size());
            wseq_t out(data.data(), data.size());
            REQUIRE(T::Write(v, out));
            payloads.push_back(HexConversions::to_hex(rseq_t(data.data(), data.size())));
        });
        return IINField::Empty();
    }
    IINField ProcessHeader(const CountHeader&, const ICollection<Group120Var3>& v) override { return SaveFixed(v); }
    IINField ProcessHeader(const CountHeader&, const ICollection<Group120Var4>& v) override { return SaveFixed(v); }
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var5>& v) override { return Save(v); }
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var6>& v) override { return Save(v); }
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var8>& v) override { return Save(v); }
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var9>& v) override { return Save(v); }
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var10>& v) override { return Save(v); }
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var11>& v) override { return Save(v); }
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var12>& v) override { return Save(v); }
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var13>& v) override { return Save(v); }
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var14>& v) override { return Save(v); }
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var15>& v) override { return Save(v); }
};

template<class T> void RoundTrip(const T& value, const std::string& expected)
{
    std::vector<uint8_t> bytes(value.Size() + 8);
    APDURequest request{wseq_t(bytes.data(), bytes.size())};
    auto writer = request.GetWriter();
    REQUIRE(writer.WriteFreeFormat(&value, 1));
    auto wire = request.ToRSeq(); wire.advance(2);
    REQUIRE(HexConversions::to_hex(wire) == expected);
    SessionWireHandler handler;
    REQUIRE(APDUParser::Parse(wire, handler, nullptr) == ParseResult::OK);
    REQUIRE(handler.payloads.size() == 1);
    REQUIRE(handler.payloads[0] == HexConversions::to_hex(wire.skip(6)));
    for (size_t length = 1; length < wire.length(); ++length)
    {
        SessionWireHandler truncated;
        REQUIRE(APDUParser::Parse(wire.take(length), truncated, nullptr) != ParseResult::OK);
        REQUIRE(truncated.payloads.empty());
    }
    for (size_t capacity = 2; capacity < bytes.size(); ++capacity)
    {
        APDURequest small{wseq_t(bytes.data(), capacity)};
        auto limited = small.GetWriter();
        const auto before = limited.Remaining();
        REQUIRE_FALSE(limited.WriteFreeFormat(&value, 1));
        REQUIRE(limited.Remaining() == before);
    }
}
}

TEST_CASE("SessionKeyWireCodec - fixed count authentication objects", "[sa6a]")
{
    Group120Var3 aggressive;
    aggressive.seqNum = 0xFE345678; aggressive.userNum = 0x1234;
    Group120Var4 status; status.userNum = 0xABCD;
    uint8_t bytes[18] = {};
    APDURequest request{wseq_t(bytes, sizeof(bytes))};
    auto writer = request.GetWriter();
    REQUIRE(writer.WriteSingleValue<UInt8>(QualifierCode::UINT8_CNT, aggressive));
    REQUIRE(writer.WriteSingleValue<UInt8>(QualifierCode::UINT8_CNT, status));
    const auto wire = request.ToRSeq().skip(2);
    REQUIRE(HexConversions::to_hex(wire) == "78 03 07 01 78 56 34 FE 34 12 78 04 07 01 CD AB");
    SessionWireHandler h;
    REQUIRE(APDUParser::Parse(wire, h, nullptr) == ParseResult::OK);
    REQUIRE(h.payloads == std::vector<std::string>{"78 56 34 FE 34 12", "CD AB"});
    const std::vector<std::string> invalid = {
        "78 04 07 00", "78 04 07 02 01 00 02 00", "78 04 08 01 00 01 00",
        "78 04 5B 01 02 00 01 00", "78 04 07 01 01", "78 03 07 01 01 00 00 00 01",
        "78 03 08 01 00 00 00 00 00 01 00", "78 03 07 02 00 00 00 00 01 00 00 00 00 00 02 00"
    };
    for (const auto& v : invalid)
    {
        HexSequence data(v); SessionWireHandler rejected;
        REQUIRE(APDUParser::Parse(data.ToRSeq(), rejected, nullptr) != ParseResult::OK);
        REQUIRE(rejected.payloads.empty());
    }
}

TEST_CASE("SessionKeyWireCodec - session status and change exact bytes", "[sa6a]")
{
    HexSequence nonce("AA BB CC DD"), mac("01 02 03 04 05 06 07 08");
    RoundTrip(Group120Var5(0xFE345678, 0x1234, 2, 2, 0, nonce.ToRSeq(), rseq_t()),
              "78 05 5B 01 0F 00 78 56 34 FE 34 12 02 02 00 04 00 AA BB CC DD");
    RoundTrip(Group120Var5(0xFE345678, 0x1234, 2, 1, 3, nonce.ToRSeq(), mac.ToRSeq()),
              "78 05 5B 01 17 00 78 56 34 FE 34 12 02 01 03 04 00 AA BB CC DD 01 02 03 04 05 06 07 08");
    // IEEE A.45.6 UINT24 label conflicts with b31 and prefix-minus-six:
    // project interpretation is UINT32 LE, including a nonzero high octet.
    RoundTrip(Group120Var6(0xFE345678, 0x1234, nonce.ToRSeq()),
              "78 06 5B 01 0A 00 78 56 34 FE 34 12 AA BB CC DD");
    HexSequence body("78 56 34 FE 34 12 F1 F2 80 04 00 AA BB CC DD DE AD");
    Group120Var5 unknown;
    REQUIRE(unknown.Read(body.ToRSeq()));
    REQUIRE(unknown.seqNum == 0xFE345678);
    REQUIRE(unknown.userNum == 0x1234);
    REQUIRE(unknown.keyWrapAlgorithm == 0xF1);
    REQUIRE(unknown.keyStatus == 0xF2);
    REQUIRE(unknown.macAlgorithm == 0x80);
    REQUIRE(HexConversions::to_hex(unknown.challengeData) == "AA BB CC DD");
    REQUIRE(HexConversions::to_hex(unknown.hmacValue) == "DE AD");
    RoundTrip(unknown, "78 05 5B 01 11 00 78 56 34 FE 34 12 F1 F2 80 04 00 AA BB CC DD DE AD");
}

TEST_CASE("SessionKeyWireCodec - remaining authentication opaque and prefixed layouts", "[sa6a]")
{
    HexSequence nonce("AA BB CC DD"), name("55 00"), opaque("DE AD");
    RoundTrip(Group120Var8(68, 1, opaque.ToRSeq()), "78 08 5B 01 04 00 44 01 DE AD");
    RoundTrip(Group120Var9(opaque.ToRSeq()), "78 09 5B 01 02 00 DE AD");
    RoundTrip(Group120Var10(4, 1, 0x12345678, 2, 7, name.ToRSeq(), rseq_t(), opaque.ToRSeq()),
              "78 0A 5B 01 14 00 04 01 78 56 34 12 02 00 07 00 02 00 00 00 02 00 55 00 DE AD");
    RoundTrip(Group120Var11(4, name.ToRSeq(), nonce.ToRSeq()),
              "78 0B 5B 01 0B 00 04 02 00 04 00 55 00 AA BB CC DD");
    RoundTrip(Group120Var12(0x12345678, 2, nonce.ToRSeq()),
              "78 0C 5B 01 0C 00 78 56 34 12 02 00 04 00 AA BB CC DD");
    RoundTrip(Group120Var13(0x12345678, 2, opaque.ToRSeq()),
              "78 0D 5B 01 0A 00 78 56 34 12 02 00 02 00 DE AD");
    RoundTrip(Group120Var14(opaque.ToRSeq()), "78 0E 5B 01 02 00 DE AD");
    RoundTrip(Group120Var15(opaque.ToRSeq()), "78 0F 5B 01 02 00 DE AD");
}

TEST_CASE("SessionKeyWireCodec - malformed prefixes algorithms and lengths fail before callbacks", "[sa6a]")
{
    const std::vector<std::string> invalid = {
        "78 05 5B 00", "78 05 5B 01 0B 00 01 00 00 00 01 00 02 02 00 04 00",
        "78 05 5B 01 0F 00 01 00 00 00 01 00 02 02 00 FF FF AA BB CC DD",
        "78 05 5B 01 0F 00 01 00 00 00 01 00 02 02 03 04 00 AA BB CC DD",
        "78 05 5B 01 0F 00 01 00 00 00 01 00 02 02 00 03 00 AA BB CC DD",
        "78 06 5B 01 06 00 01 00 00 00 01 00", "78 06 5B 01 FF FF 00",
        "78 0A 5B 01 14 00 04 01 78 56 34 12 02 00 07 00 02 00 01 00 02 00 55 00 DE AD",
        "78 0B 5B 01 0B 00 04 02 00 FF FF 55 00 AA BB CC DD",
        "78 0C 5B 01 0D 00 78 56 34 12 02 00 04 00 AA BB CC DD EE",
        "78 0D 5B 01 0A 00 78 56 34 12 02 00 03 00 DE AD",
        "78 09 5B 01 00 00", "78 0E 5B 01 00 00", "78 0F 5B 01 00 00",
        "78 05 07 01", "78 06 06", "78 0B 08 01 00"
    };
    for (const auto& v : invalid)
    {
        INFO(v); HexSequence data(v); SessionWireHandler rejected;
        REQUIRE(APDUParser::Parse(data.ToRSeq(), rejected, nullptr) != ParseResult::OK);
        REQUIRE(rejected.payloads.empty());
    }
    // Entire APDU is validated before even the first valid header is dispatched.
    HexSequence two("78 04 07 01 01 00 78 06 5B 01 FF FF 00");
    SessionWireHandler h;
    REQUIRE(APDUParser::Parse(two.ToRSeq(), h, nullptr) != ParseResult::OK);
    REQUIRE(h.payloads.empty());
}

TEST_CASE("SessionKeyWireCodec - tag sizes and maximum wire bounds", "[sa6a]")
{
    std::vector<uint8_t> bytes(65536, 0xA5), buffer(65544);
    const rseq_t data(bytes.data(), bytes.size());
    const size_t tagSizes[] = {0, 4, 10, 8, 16, 8, 12};
    for (uint8_t alg = 0; alg < 7; ++alg)
    {
        Group120Var5 value(1, 2, 2, 1, alg, data.take(4), data.take(tagSizes[alg]));
        REQUIRE(IsValidAuthObject(value));
        value.hmacValue = data.take(tagSizes[alg] + 1);
        REQUIRE_FALSE(IsValidAuthObject(value));
    }
    Group120Var5 status(1, 2, 2, 2, 0, data.take(65535 - 11), rseq_t());
    Group120Var6 change(0xFFFFFFFF, 2, data.take(65535 - 6));
    auto check = [&](const auto& value) {
        APDURequest request{wseq_t(buffer.data(), buffer.size())};
        auto writer = request.GetWriter();
        REQUIRE(writer.WriteFreeFormat(&value, 1));
        SessionWireHandler h;
        REQUIRE(APDUParser::Parse(request.ToRSeq().skip(2), h, nullptr) == ParseResult::OK);
        REQUIRE(h.payloads.size() == 1);
    };
    check(status); check(change);
    change.keyWrapData = data.take(65535 - 5);
    APDURequest request{wseq_t(buffer.data(), buffer.size())};
    auto writer = request.GetWriter(); const auto before = writer.Remaining();
    REQUIRE_FALSE(writer.WriteFreeFormat(&change, 1));
    REQUIRE(writer.Remaining() == before);
    status.challengeData = data;
    REQUIRE_FALSE(writer.WriteFreeFormat(&status, 1));
    REQUIRE(writer.Remaining() == before);
    wseq_t direct(buffer.data(), buffer.size());
    REQUIRE_FALSE(status.Write(direct));
}
