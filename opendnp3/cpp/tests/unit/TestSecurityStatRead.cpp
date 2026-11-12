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
#include "utils/AcceptanceObservation.h"

#include <ser4cpp/util/HexConversions.h>
#include <catch.hpp>

#include <array>
#include <limits>
#include <vector>

using namespace opendnp3;
using namespace ser4cpp;
using acceptance::Observe;
using acceptance::Selected;
namespace
{
struct ReadStore final : IAuthenticationStatisticsStore
{
    SecurityStatisticValues saved{};
    bool available = true;
    bool Load(uint16_t, bool, SecurityStatisticValues& values) override { values = saved; return available; }
    bool Save(uint16_t, bool, const SecurityStatisticValues& values) override
    {
        if (available) saved = values;
        return available;
    }
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

namespace
{
void VerifyReadSelection(const std::string& variation, const std::string& selection)
{
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
    Observe("response_qualifier", bytes[6]);
    uint16_t decoded = 0;
    for (; decoded < (indexed ? 2 : 18); ++decoded)
    {
        const auto index = indexed ? (decoded ? 17 : 0) : decoded;
        if (indexed) { REQUIRE(input[0] == index); input.advance(1); }
        Group121Var1 value;
        REQUIRE(Group121Var1::Read(input, value));
        REQUIRE(value.flags == 0x41); // No retention backend: never claim startup continuity.
        REQUIRE(value.associationId == 0);
        REQUIRE(value.value == before[index]);
        if (index == 0) Observe("first_counter", value.value);
    }
    REQUIRE(input.is_empty());
    Observe("decoded_count", decoded);
    Observe("statistics_unchanged", fixture.statistics.Values() == before);
    REQUIRE(fixture.statistics.Values() == before);
}
} // namespace

TEST_CASE("AT-PROFILE-063-READ00", "[security-stat-read][rtu-acceptance]")
{
    if (Selected("V1")) VerifyReadSelection("01", "00 00 11");
    if (Selected("V2")) VerifyReadSelection("00", "00 00 11");
}

TEST_CASE("AT-PROFILE-063-READ01", "[security-stat-read][rtu-acceptance]")
{
    if (Selected("V1")) VerifyReadSelection("01", "01 00 00 11 00");
    if (Selected("V2")) VerifyReadSelection("00", "01 00 00 11 00");
}

TEST_CASE("AT-PROFILE-063-READ06", "[security-stat-read][rtu-acceptance]")
{
    if (Selected("V1")) VerifyReadSelection("01", "06");
    if (Selected("V2")) VerifyReadSelection("00", "06");
}

TEST_CASE("AT-PROFILE-063-READ17", "[security-stat-read][rtu-acceptance]")
{
    if (Selected("V1")) VerifyReadSelection("01", "17 02 00 11");
    if (Selected("V2")) VerifyReadSelection("00", "17 02 00 11");
}

TEST_CASE("AT-PROFILE-063-READ28", "[security-stat-read][rtu-acceptance]")
{
    if (Selected("V1")) VerifyReadSelection("01", "28 02 00 00 00 11 00");
    if (Selected("V2")) VerifyReadSelection("00", "28 02 00 00 00 11 00");
}

TEST_CASE("AT-PROFILE-063-IIN", "[security-stat-read][rtu-acceptance]")
{
    SecurityReadFixture fixture;
    SECTION("single point and overlapping indexed selectors are emitted once in point order")
    {
        REQUIRE(fixture.Select("79 01 00 00 00 79 00 17 04 02 00 02 01") == ParseResult::OK);
        const auto reply = fixture.Fragment();
        Observe("merged_count", reply.at(7));
        REQUIRE(Hex(reply) == "C0 81 00 00 79 01 17 03 00 41 00 00 00 00 00 00 01 41 00 00 00 00 00 00 02 41 00 00 00 00 00 00");
    }
    SECTION("partially available range is clipped with PARAM_ERROR")
    {
        REQUIRE(fixture.Select("79 01 00 11 12") == ParseResult::OK);
        REQUIRE(fixture.errors.IsSet(IINBit::PARAM_ERROR));
        const auto reply = fixture.Fragment();
        Observe("partial_iin", reply.at(3));
        REQUIRE(Hex(reply) == "C0 81 00 04 79 01 00 11 11 41 00 00 00 00 00 00");
    }
    SECTION("missing range and index do not create points")
    {
        const auto request = GENERATE(std::string("79 01 01 00 01 00 01"), std::string("79 00 28 01 00 FF FF"));
        REQUIRE(fixture.Select(request) == ParseResult::OK);
        REQUIRE(fixture.errors.IsSet(IINBit::PARAM_ERROR));
        const auto reply = fixture.Fragment();
        Observe(request.find(" 28 ") == std::string::npos ? "empty_range_iin" : "empty_index_iin", reply.at(3));
        REQUIRE(Hex(reply) == "C0 81 00 04");
    }
    SECTION("truncated index list is rejected by the existing parser")
    {
        const auto rejected = fixture.Select("79 01 28 02 00 00 00") != ParseResult::OK;
        Observe("truncated_rejected", rejected);
        REQUIRE(rejected);
    }
    SECTION("count-only READ does not admit unsupported G121 framing")
    {
        REQUIRE(fixture.Select("79 01 07 01") == ParseResult::OK);
        Observe("count_only_iin", fixture.Fragment().at(3));
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

    REQUIRE(fixture.Select("3C 01 06") == ParseResult::OK);
    for (uint8_t index = 0; index < 18; ++index)
    {
        const auto fragment = fixture.Fragment(16);
        const uint8_t control = index == 0 ? 0xA0 : index == 17 ? 0x40 : 0x20;
        const std::vector<uint8_t> expected{control, 0x81, 0, 0, 121, 1, 0, index, index, 0x41, 0, 0, 0, 0, 0, 0};
        REQUIRE(fragment == expected);
    }
}

TEST_CASE("AT-PROFILE-063-SNAP", "[security-stat-read][rtu-acceptance]")
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
    Observe("snapshot_points", next);
    REQUIRE(next == 18);
    REQUIRE_FALSE(fixture.response.HasSelection());
    const auto pending = fixture.statistics.ReportPending(SecurityStatistic::AUTHENTICATION_FAILURES);
    Observe("report_pending", pending);
    REQUIRE(pending);
    REQUIRE(fixture.statistics.Maximum(SecurityStatistic::AUTHENTICATION_FAILURES) == maximum);
    REQUIRE(fixture.statistics.Value(SecurityStatistic::FAILED_SESSION_KEY_CHANGES) == before[14] + 1);
    REQUIRE(fixture.statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(fixture.statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 0);
    REQUIRE(fixture.statistics.Value(SecurityStatistic::RESTART_REKEYS) == 0);
}

TEST_CASE("AT-PROFILE-063-RET", "[security-stat-read][rtu-acceptance]")
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
    SecurityReadFixture reopened(store, 7);
    REQUIRE(reopened.Select("79 01 00 00 00") == ParseResult::OK);
    const auto retained = reopened.Fragment();
    REQUIRE(Hex(retained) == "C0 81 00 00 79 01 00 00 00 01 00 00 01 00 00 00");
    Observe("retained_counter", retained.at(12));
    store->available = false; // Live values remain, but uncertain retention is discontinuous.
    first.statistics.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    REQUIRE_FALSE(first.statistics.Retained());
    REQUIRE(first.Select("79 01 00 00 00") == ParseResult::OK);
    const auto discontinuity = first.Fragment();
    Observe("discontinuous_flags", discontinuity.at(9));
    REQUIRE(Hex(discontinuity) == "C0 81 00 00 79 01 00 00 00 41 00 00 02 00 00 00");
}

TEST_CASE("SecurityStatRead - failed save marks G121 discontinuous and later save cannot clear it",
          "[security-stat-read]")
{
    auto store = std::make_shared<ReadStore>();
    SecurityReadFixture fixture(store);

    store->available = false;
    fixture.statistics.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    REQUIRE_FALSE(fixture.statistics.Retained());
    REQUIRE(fixture.Select("79 01 06") == ParseResult::OK);

    auto bytes = fixture.Fragment();
    auto input = rseq_t(bytes.data(), bytes.size()).skip(9);
    for (size_t n = 0; n < 18; ++n)
    {
        Group121Var1 value;
        REQUIRE(Group121Var1::Read(input, value));
        REQUIRE(value.flags == 0x41);
    }

    store->available = true;
    fixture.statistics.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    REQUIRE(fixture.statistics.Retained());
    REQUIRE(fixture.Select("79 01 06") == ParseResult::OK);

    bytes = fixture.Fragment();
    input = rseq_t(bytes.data(), bytes.size()).skip(9);
    for (size_t n = 0; n < 18; ++n)
    {
        Group121Var1 value;
        REQUIRE(Group121Var1::Read(input, value));
        REQUIRE(value.flags == 0x41);
    }
}
