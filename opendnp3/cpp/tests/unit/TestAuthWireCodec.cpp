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
#include "app/AuthObjectValidation.h"
#include "app/parsing/APDUParser.h"
#include <ser4cpp/util/HexConversions.h>
#include <catch.hpp>
#include <vector>

using namespace opendnp3;
using namespace ser4cpp;

namespace
{
struct AuthHandler final : IAPDUHandler
{
    std::vector<std::string> payloads;
    std::vector<size_t> counts;
    bool IsAllowed(uint32_t, GroupVariation, QualifierCode) override { return true; }
    template<class T> IINField Save(const ICollection<T>& values)
    {
        counts.push_back(values.Count());
        values.ForeachItem([this](const T& value) {
            std::vector<uint8_t> bytes(value.Size());
            wseq_t dest(bytes.data(), bytes.size());
            REQUIRE(value.Write(dest));
            payloads.push_back(HexConversions::to_hex(rseq_t(bytes.data(), bytes.size())));
        });
        return IINField::Empty();
    }
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var1>& v) override { return Save(v); }
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var2>& v) override { return Save(v); }
    IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var7>& v) override { return Save(v); }
};

ParseResult Parse(const std::string& hex, AuthHandler& h)
{
    HexSequence data(hex);
    return APDUParser::Parse(data.ToRSeq(), h, nullptr);
}

template<class T> void RoundTrip(const T& value, const std::string& expected)
{
    std::vector<uint8_t> bytes(value.Size() + 8);
    APDURequest request{wseq_t(bytes.data(), bytes.size())};
    auto writer = request.GetWriter();
    REQUIRE(writer.WriteFreeFormat(&value, 1));
    auto objects = request.ToRSeq();
    objects.advance(2);
    REQUIRE(HexConversions::to_hex(objects) == expected);
    AuthHandler handler;
    REQUIRE(APDUParser::Parse(objects, handler, nullptr) == ParseResult::OK);
    REQUIRE(handler.counts == std::vector<size_t>{1});
    REQUIRE(handler.payloads.size() == 1);
    std::vector<uint8_t> encoded(value.Size());
    wseq_t dest(encoded.data(), encoded.size());
    REQUIRE(value.Write(dest));
    REQUIRE(handler.payloads[0] == HexConversions::to_hex(rseq_t(encoded.data(), encoded.size())));
    for (size_t capacity = 2; capacity < bytes.size(); ++capacity)
    {
        APDURequest small{wseq_t(bytes.data(), capacity)};
        auto limited = small.GetWriter();
        const auto remaining = limited.Remaining();
        REQUIRE_FALSE(limited.WriteFreeFormat(&value, 1));
        REQUIRE(limited.Remaining() == remaining);
    }
}
}

TEST_CASE("AuthWireCodec - exact layouts and round trips")
{
    HexSequence challenge("AA BB CC DD");
    RoundTrip(Group120Var1(0x12345678, 0x1234, 4, 1, challenge.ToRSeq()),
              "78 01 5B 01 0C 00 78 56 34 12 34 12 04 01 AA BB CC DD");
    HexSequence mac("11 22 33 44 55 66 77 88");
    RoundTrip(Group120Var2(0x12345678, 0x1234, mac.ToRSeq()),
              "78 02 5B 01 0E 00 78 56 34 12 34 12 11 22 33 44 55 66 77 88");
    RoundTrip(Group120Var7(0x12345678, 0x1234, 0x5678, 1, DNPTime(0x060504030201ULL), rseq_t()),
              "78 07 5B 01 0F 00 78 56 34 12 34 12 78 56 01 01 02 03 04 05 06");
    HexSequence text("C3 A9");
    RoundTrip(Group120Var7(1, 2, 3, 128, DNPTime(0), text.ToRSeq()),
              "78 07 5B 01 11 00 01 00 00 00 02 00 03 00 80 00 00 00 00 00 00 C3 A9");
}

TEST_CASE("AuthWireCodec - truncated headers payloads and validation before dispatch")
{
    const std::string hex = "78 01 5B 01 0C 00 01 00 00 00 02 00 04 01 AA BB CC DD";
    HexSequence data(hex);
    for (size_t size = 1; size < data.ToRSeq().length(); ++size)
    {
        AuthHandler handler;
        REQUIRE(APDUParser::Parse(data.ToRSeq().take(size), handler, nullptr) != ParseResult::OK);
        REQUIRE(handler.payloads.empty());
    }
    AuthHandler h;
    REQUIRE(Parse(hex + " 78 02 5B 01 06 00 00", h) != ParseResult::OK);
    REQUIRE(h.payloads.empty());
}

TEST_CASE("AuthWireCodec - malformed lengths qualifiers and payloads")
{
    const std::vector<std::string> invalid = {
        "78 01 5B 00", "78 01 5B 01 00 00", "78 01 5B 01 FF FF 00",
        "78 01 5B 01 0B 00 01 00 00 00 02 00 04 01 AA BB CC",
        "78 02 5B 01 05 00 00 00 00 00 00",
        "78 02 5B 01 06 00 00 00 00 00 00 00",
        "78 07 5B 01 0E 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00",
        "78 07 5B 01 0F 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00",
        "78 07 5B 01 10 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 FF",
        "78 01 07 01", "78 02 06", "78 07 00 00 00", "01 02 5B 01 00 00"
    };
    for (const auto& input : invalid)
    {
        INFO(input);
        AuthHandler handler;
        REQUIRE(Parse(input, handler) != ParseResult::OK);
        REQUIRE(handler.payloads.empty());
    }
}

TEST_CASE("AuthWireCodec - multiple objects and maximum count")
{
    HexSequence mac("01 02 03 04");
    const Group120Var2 pair[] = {Group120Var2(1,2,mac.ToRSeq()), Group120Var2(3,4,mac.ToRSeq())};
    uint8_t bytes[38] = {};
    APDURequest request{wseq_t(bytes, sizeof(bytes))};
    auto writer=request.GetWriter();
    REQUIRE(writer.WriteFreeFormat(pair,2));
    auto data=request.ToRSeq(); data.advance(2);
    REQUIRE(HexConversions::to_hex(data) == "78 02 5B 02 0A 00 01 00 00 00 02 00 01 02 03 04 0A 00 03 00 00 00 04 00 01 02 03 04");
    AuthHandler h;
    REQUIRE(APDUParser::Parse(data,h,nullptr) == ParseResult::OK);
    REQUIRE(h.counts == std::vector<size_t>{2});
    REQUIRE(h.payloads.size() == 2);
    std::vector<Group120Var2> values(255, pair[0]);
    std::vector<uint8_t> large(4096);
    APDURequest many{wseq_t(large.data(),large.size())};
    auto w=many.GetWriter();
    REQUIRE(w.WriteFreeFormat(values.data(),255));
    auto objects=many.ToRSeq(); objects.advance(2);
    AuthHandler all;
    REQUIRE(APDUParser::Parse(objects,all,nullptr) == ParseResult::OK);
    REQUIRE(all.payloads.size() == 255);
    REQUIRE_FALSE(w.WriteFreeFormat(values.data(),0));
    REQUIRE_FALSE(w.WriteFreeFormat(static_cast<const Group120Var2*>(nullptr),1));
}

TEST_CASE("AuthWireCodec - maximum length and oversized writer input")
{
    std::vector<uint8_t> tail(65535, 'A');
    const rseq_t data(tail.data(),tail.size());
    Group120Var1 challenge(1,2,4,1,data.take(65535-8));
    Group120Var2 reply(1,2,data.take(65535-6));
    Group120Var7 error(1,2,3,1,DNPTime(0),data.take(65535-15));
    std::vector<uint8_t> buffer(65543);
    auto check=[&](const auto& value) {
        APDURequest request{wseq_t(buffer.data(),buffer.size())};
        auto writer=request.GetWriter();
        REQUIRE(writer.WriteFreeFormat(&value,1));
        auto objects=request.ToRSeq(); objects.advance(2);
        AuthHandler h;
        REQUIRE(APDUParser::Parse(objects,h,nullptr) == ParseResult::OK);
        REQUIRE(h.payloads.size()==1);
        REQUIRE(objects.length()==65541);
    };
    check(challenge); check(reply); check(error);
    reply.hmacValue=data.take(65535-5);
    APDURequest request{wseq_t(buffer.data(),buffer.size())};
    auto writer=request.GetWriter();
    const auto remaining=writer.Remaining();
    REQUIRE_FALSE(writer.WriteFreeFormat(&reply,1));
    REQUIRE(writer.Remaining()==remaining);
    error.time=DNPTime(0x1000000000000ULL);
    REQUIRE_FALSE(IsValidAuthObject(error));
}
