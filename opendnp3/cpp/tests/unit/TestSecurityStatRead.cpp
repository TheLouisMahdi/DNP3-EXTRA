// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/APDUResponse.h"
#include "app/parsing/APDUParser.h"
#include "auth/AuthenticationStatistics.h"
#include "dnp3mocks/MockOutstationApplication.h"
#include "gen/objects/Group121.h"
#include "outstation/Database.h"
#include "outstation/ReadHandler.h"
#include "outstation/ResponseContext.h"
#include "outstation/StaticWriters.h"
#include "outstation/event/EventBuffer.h"
#include "utils/BufferHelpers.h"

#include <ser4cpp/util/HexConversions.h>
#include <catch.hpp>

#include <array>
#include <limits>
#include <vector>

using namespace opendnp3;
using namespace ser4cpp;
namespace
{
struct ReadStore final : IAuthenticationStatisticsStore
{
    SecurityStatisticValues saved{};
    bool available = true;
    bool Load(uint16_t, bool, SecurityStatisticValues& values) override { values = saved; return available; }
    bool Save(uint16_t, bool, const SecurityStatisticValues&) override { return available; }
};

struct SecurityReadFixture
{
    AuthenticationStatistics statistics;
    EventBuffer events{EventBufferConfig{}};
    MockOutstationApplication application;
    Database database;
    ResponseContext response{database, events};
    IINField errors;

    SecurityReadFixture(std::shared_ptr<ReadStore> store = nullptr, uint16_t association = 7,
                        const DatabaseConfig& config = DatabaseConfig())
        : statistics(association, false, DefaultSecurityStatisticThresholds(), store),
          database(config, events, application, StaticTypeBitField()) // Exclude every optional Class 0 type.
    {
    }
    ParseResult Select(const std::string& objects)
    {
        database.Unselect();
        response.Reset();
        database.SetSecurityStatistics(statistics.CaptureStaticSnapshot());
        ReadHandler handler(database, events);
        HexSequence bytes(objects);
        const auto result = APDUParser::Parse(bytes.ToRSeq(), handler, nullptr, ParserSettings::NoContents());
        errors = handler.Errors();
        return result;
    }
    std::vector<uint8_t> Fragment(size_t limit = 2048)
    {
        std::vector<uint8_t> bytes(limit);
        APDUResponse apdu(wseq_t(bytes.data(), bytes.size()));
        auto writer = apdu.GetWriter();
        apdu.SetControl(response.LoadResponse(writer));
        apdu.SetFunction(FunctionCode::RESPONSE);
        apdu.SetIIN(errors);
        bytes.resize(apdu.Size());
        return bytes;
    }
};

std::string Hex(const std::vector<uint8_t>& bytes)
{
    return HexConversions::to_hex(rseq_t(bytes.data(), bytes.size()));
}
} // namespace

TEST_CASE("SecurityStatRead - generated seven octet codec and reserved flags", "[security-stat-read]")
{
    REQUIRE(Group121Var1::Size() == 7);
    std::array<uint8_t, 7> bytes{};
    auto output = wseq_t(bytes.data(), bytes.size());
    const SecurityStat value(0x12345678, Flags(0xFF), 0xABCD);
    REQUIRE(Group121Var1::WriteTarget(value, output));
    REQUIRE(HexConversions::to_hex(rseq_t(bytes.data(), bytes.size())) == "5F CD AB 78 56 34 12");
    for (size_t size = 0; size <= bytes.size(); ++size)
    {
        auto input = rseq_t(bytes.data(), size);
        Group121Var1 decoded;
        REQUIRE(Group121Var1::Read(input, decoded) == (size == 7));
        if (size == 7)
        {
            REQUIRE(decoded.flags == 0x5F);
            REQUIRE(decoded.associationId == 0xABCD);
            REQUIRE(decoded.value == 0x12345678);
        }
    }
}

TEST_CASE("SecurityStatRead - generated serializers support all permitted response qualifiers", "[security-stat-read]")
{
    const auto qualifier = GENERATE(QualifierCode::UINT8_START_STOP, QualifierCode::UINT16_START_STOP,
        QualifierCode::UINT8_CNT_UINT8_INDEX, QualifierCode::UINT16_CNT_UINT16_INDEX);
    AuthenticationStatistics::StaticSnapshot snapshot;
    snapshot.flags = 1;
    snapshot.values[0] = 0x12345678;
    uint32_t selected = 1;
    std::array<uint8_t, 64> bytes{};
    APDUResponse apdu(wseq_t(bytes.data(), bytes.size()));
    apdu.SetControl(AppControlField::Request(0));
    apdu.SetFunction(FunctionCode::RESPONSE);
    apdu.SetIIN(IINField::Empty());
    auto writer = apdu.GetWriter();
    REQUIRE(StaticWriters::WriteSecurityStatistics(snapshot, selected, writer, qualifier));
    REQUIRE(selected == 0);
    const auto hex = HexConversions::to_hex(apdu.ToRSeq());
    if (qualifier == QualifierCode::UINT8_START_STOP)
        REQUIRE(hex == "C0 81 00 00 79 01 00 00 00 01 00 00 78 56 34 12");
    if (qualifier == QualifierCode::UINT16_START_STOP)
        REQUIRE(hex == "C0 81 00 00 79 01 01 00 00 00 00 01 00 00 78 56 34 12");
    if (qualifier == QualifierCode::UINT8_CNT_UINT8_INDEX)
        REQUIRE(hex == "C0 81 00 00 79 01 17 01 00 01 00 00 78 56 34 12");
    if (qualifier == QualifierCode::UINT16_CNT_UINT16_INDEX)
        REQUIRE(hex == "C0 81 00 00 79 01 28 01 00 00 00 01 00 00 78 56 34 12");
}

TEST_CASE("SecurityStatRead - both selectors and all READ index encodings use the same runtime", "[security-stat-read]")
{
    const auto variation = GENERATE(std::string("00"), std::string("01"));
    const auto selection = GENERATE(std::string("06"), std::string("00 00 11"), std::string("01 00 00 11 00"),
                                   std::string("17 02 00 11"), std::string("28 02 00 00 00 11 00"));
    SecurityReadFixture fixture;
    fixture.statistics.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    const auto before = fixture.statistics.Values();
    REQUIRE(fixture.Select("79 " + variation + " " + selection) == ParseResult::OK);
    REQUIRE(fixture.errors == IINField::Empty());
    const auto bytes = fixture.Fragment();
    const bool indexed = selection[0] == '1' || selection[0] == '2';
    REQUIRE(bytes[4] == 121);
    REQUIRE(bytes[5] == 1); // V0 is never a response variation.
    REQUIRE(bytes[6] == (indexed ? 0x17 : 0x00));
    REQUIRE(bytes.size() == (indexed ? 24u : 135u));
    auto input = rseq_t(bytes.data(), bytes.size()).skip(indexed ? 8 : 9);
    for (uint16_t i = 0; i < (indexed ? 2 : 18); ++i)
    {
        const auto index = indexed ? (i ? 17 : 0) : i;
        if (indexed) { REQUIRE(input[0] == index); input.advance(1); }
        Group121Var1 value;
        REQUIRE(Group121Var1::Read(input, value));
        REQUIRE(value.flags == 0x41); // No retention backend: never claim startup continuity.
        REQUIRE(value.associationId == 0);
        REQUIRE(value.value == before[index]);
    }
    REQUIRE(input.is_empty());
    REQUIRE(fixture.statistics.Values() == before);
}

TEST_CASE("SecurityStatRead - validation merges selectors and preserves native IIN errors", "[security-stat-read]")
{
    SecurityReadFixture fixture;
    SECTION("single point and overlapping indexed selectors are emitted once in point order")
    {
        REQUIRE(fixture.Select("79 01 00 00 00 79 00 17 04 02 00 02 01") == ParseResult::OK);
        REQUIRE(Hex(fixture.Fragment()) == "C0 81 00 00 79 01 17 03 00 41 00 00 00 00 00 00 01 41 00 00 00 00 00 00 02 41 00 00 00 00 00 00");
    }
    SECTION("partially available range is clipped with PARAM_ERROR")
    {
        REQUIRE(fixture.Select("79 01 00 11 12") == ParseResult::OK);
        REQUIRE(fixture.errors.IsSet(IINBit::PARAM_ERROR));
        REQUIRE(Hex(fixture.Fragment()) == "C0 81 00 04 79 01 00 11 11 41 00 00 00 00 00 00");
    }
    SECTION("missing range and index do not create points")
    {
        const auto request = GENERATE(std::string("79 01 01 00 01 00 01"), std::string("79 00 28 01 00 FF FF"));
        REQUIRE(fixture.Select(request) == ParseResult::OK);
        REQUIRE(fixture.errors.IsSet(IINBit::PARAM_ERROR));
        REQUIRE(Hex(fixture.Fragment()) == "C0 81 00 04");
    }
    SECTION("truncated index list is rejected by the existing parser")
    {
        REQUIRE(fixture.Select("79 01 28 02 00 00 00") != ParseResult::OK);
    }
    SECTION("count-only READ does not admit unsupported G121 framing")
    {
        REQUIRE(fixture.Select("79 01 07 01") == ParseResult::OK);
        REQUIRE(fixture.errors.IsSet(IINBit::FUNC_NOT_SUPPORTED));
    }
}

TEST_CASE("SecurityStatRead - Class 0 cannot exclude security statistics and mixes ordinary READs", "[security-stat-read]")
{
    DatabaseConfig config;
    config.binary_input[0] = BinaryConfig{};
    SecurityReadFixture fixture(nullptr, 7, config);
    REQUIRE(fixture.database.Update(Binary(true, Flags(1)), 0, EventMode::Suppress));
    REQUIRE(fixture.Select("3C 01 06") == ParseResult::OK);
    const auto classZero = fixture.Fragment();
    REQUIRE(classZero.size() == 135);
    REQUIRE(classZero[4] == 121); // Optional binary type was excluded, G121 was not.
    REQUIRE(fixture.Select("01 02 06 79 01 00 00 00") == ParseResult::OK);
    REQUIRE(Hex(fixture.Fragment()) == "C0 81 00 00 01 02 00 00 00 81 79 01 00 00 00 41 00 00 00 00 00 00");
}

TEST_CASE("SecurityStatRead - fragmented responses retain one snapshot without changing report or Max state", "[security-stat-read]")
{
    SecurityReadFixture fixture;
    for (unsigned n = 0; n < 6; ++n) fixture.statistics.AuthenticationFailed();
    REQUIRE(fixture.statistics.ReportPending(SecurityStatistic::AUTHENTICATION_FAILURES));
    const auto before = fixture.statistics.Values();
    const auto maximum = fixture.statistics.Maximum(SecurityStatistic::AUTHENTICATION_FAILURES);
    REQUIRE(fixture.Select("79 01 06") == ParseResult::OK);
    uint16_t next = 0;
    for (unsigned fragment = 0; fragment < 6; ++fragment)
    {
        const auto bytes = fixture.Fragment(30); // Three seven-byte values per fragment.
        REQUIRE((bytes[0] & 0x80) == (fragment == 0 ? 0x80 : 0));
        REQUIRE((bytes[0] & 0x40) == (fragment == 5 ? 0x40 : 0));
        REQUIRE(bytes[7] == next);
        auto input = rseq_t(bytes.data(), bytes.size()).skip(9);
        while (!input.is_empty())
        {
            Group121Var1 value;
            REQUIRE(Group121Var1::Read(input, value));
            REQUIRE(value.value == before[next++]);
        }
        if (fragment == 0) fixture.statistics.Increment(SecurityStatistic::FAILED_SESSION_KEY_CHANGES);
    }
    REQUIRE(next == 18);
    REQUIRE_FALSE(fixture.response.HasSelection());
    REQUIRE(fixture.statistics.ReportPending(SecurityStatistic::AUTHENTICATION_FAILURES));
    REQUIRE(fixture.statistics.Maximum(SecurityStatistic::AUTHENTICATION_FAILURES) == maximum);
    REQUIRE(fixture.statistics.Value(SecurityStatistic::FAILED_SESSION_KEY_CHANGES) == before[14] + 1);
    REQUIRE(fixture.statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(fixture.statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 0);
    REQUIRE(fixture.statistics.Value(SecurityStatistic::RESTART_REKEYS) == 0);
}

TEST_CASE("SecurityStatRead - association snapshots and retained rollover are isolated", "[security-stat-read]")
{
    auto store = std::make_shared<ReadStore>();
    store->saved[0] = std::numeric_limits<uint32_t>::max();
    SecurityReadFixture first(store, 7), other(nullptr, 8);
    first.statistics.Increment(SecurityStatistic::UNEXPECTED_MESSAGES); // Normal uint32 rollover, not discontinuity.
    REQUIRE(first.Select("79 01 00 00 00") == ParseResult::OK);
    REQUIRE(Hex(first.Fragment()) == "C0 81 00 00 79 01 00 00 00 01 00 00 00 00 00 00");
    first.statistics.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    REQUIRE(other.Select("79 01 00 00 00") == ParseResult::OK);
    REQUIRE(Hex(other.Fragment()) == "C0 81 00 00 79 01 00 00 00 41 00 00 00 00 00 00");
    store->available = false; // Failed Save does not lose already acquired live history.
    first.statistics.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    REQUIRE_FALSE(first.statistics.Retained());
    REQUIRE(first.Select("79 01 00 00 00") == ParseResult::OK);
    REQUIRE(Hex(first.Fragment()) == "C0 81 00 00 79 01 00 00 00 01 00 00 02 00 00 00");
}
