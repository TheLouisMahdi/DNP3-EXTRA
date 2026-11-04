// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/parsing/APDUParser.h"
#include "dnp3mocks/MockLogHandler.h"
#include "dnp3mocks/MockSOEHandler.h"
#include "master/MeasurementHandler.h"
#include "utils/BufferHelpers.h"
#include "utils/MasterTestFixture.h"
#include "utils/OutstationTestObject.h"

#include <catch.hpp>
#include <limits>
#include <string>

using namespace opendnp3;
namespace
{
struct ProfileMeasurements
{
    MockLogHandler log;
    MockSOEHandler soe;
    ParseResult Parse(const std::string& wire)
    {
        HexSequence bytes(wire);
        return MeasurementHandler::ProcessMeasurements(ResponseInfo(false, true, true), bytes.ToRSeq(), log.logger, &soe);
    }
};

struct DeadbandSOE : MockSOEHandler
{
    std::vector<std::pair<HeaderInfo, Indexed<AnalogDeadband>>> records;
    void Process(const HeaderInfo& info, const ICollection<Indexed<AnalogDeadband>>& values) override
    {
        values.ForeachItem([&](const Indexed<AnalogDeadband>& item) { records.emplace_back(info, item); });
    }
};

std::string DeadbandExchange(OutstationTestObject& t, const std::string& request)
{
    t.SendToOutstation(request);
    const auto response = t.lower->PopWriteAsHex();
    t.OnTxReady();
    if (!response.empty() && response.front() == 'E')
        t.SendToOutstation("C" + response.substr(1, 1) + " 00");
    return response;
}
std::string CTO(unsigned variation, const std::string& qualifierAndCount, const std::string& times)
{
    return std::string(variation == 1 ? "33 01 " : "33 02 ") + qualifierAndCount + " " + times;
}
std::string Relative(bool doubleBit, bool wide = false)
{
    return std::string(doubleBit ? "04 03 " : "02 03 ")
        + (wide ? "28 01 00 08 00 " : "17 01 08 ") + "81 01 00";
}
template<class T> void CheckTime(const T& record, uint64_t time, TimestampQuality quality)
{
    REQUIRE(record.meas.time.value == time);
    REQUIRE(record.meas.time.quality == quality);
    REQUIRE(record.info.tsquality == quality);
}
}

TEST_CASE("ProfileMeasurements - valid single CTO retains binary and double-bit relative event decoding",
          "[profile-measurements]")
{
    for (unsigned variation : {1u, 2u})
        for (bool doubleBit : {false, true})
            for (bool wide : {false, true})
            {
                ProfileMeasurements f;
                REQUIRE(f.Parse(CTO(variation, "07 01", "07 00 00 00 00 00 ") + Relative(doubleBit, wide)) == ParseResult::OK);
                REQUIRE(f.soe.TotalReceived() == 1);
                const auto quality = variation == 1 ? TimestampQuality::SYNCHRONIZED : TimestampQuality::UNSYNCHRONIZED;
                if (doubleBit)
                {
                    REQUIRE(f.soe.doubleBinarySOE.size() == 1);
                    const auto& record = f.soe.doubleBinarySOE.at(8);
                    REQUIRE(record.meas.value == DoubleBit::DETERMINED_ON);
                    CheckTime(record, 8, quality);
                }
                else
                {
                    REQUIRE(f.soe.binarySOE.size() == 1);
                    const auto& record = f.soe.binarySOE.at(8);
                    REQUIRE(record.meas.value);
                    CheckTime(record, 8, quality);
                }
            }
}

TEST_CASE("ProfileMeasurements - each valid CTO header replaces the preceding reference",
          "[profile-measurements]")
{
    ProfileMeasurements f;
    const auto wire = CTO(1, "07 01", "07 00 00 00 00 00 ") + Relative(false)
        + " " + CTO(2, "07 01", "15 00 00 00 00 00 ") + Relative(true);
    REQUIRE(f.Parse(wire) == ParseResult::OK);
    REQUIRE(f.soe.TotalReceived() == 2);
    CheckTime(f.soe.binarySOE.at(8), 8, TimestampQuality::SYNCHRONIZED);
    CheckTime(f.soe.doubleBinarySOE.at(8), 22, TimestampQuality::UNSYNCHRONIZED);
}

TEST_CASE("ProfileMeasurements - invalid CTO quantity cannot reuse an earlier reference or partially deliver",
          "[profile-measurements]")
{
    for (unsigned variation : {1u, 2u})
        for (bool doubleBit : {false, true})
        {
            ProfileMeasurements f;
            // The previous handler ignored a two-value CTO, retaining time 7.
            const auto wire = std::string("01 02 00 00 00 81 ")
                + CTO(1, "07 01", "07 00 00 00 00 00 ")
                + CTO(variation, "07 02", "15 00 00 00 00 00 1F 00 00 00 00 00 ") + Relative(doubleBit);
            REQUIRE(f.Parse(wire) == ParseResult::INVALID_OBJECT_QUALIFIER);
            REQUIRE(f.soe.TotalReceived() == 0);
            REQUIRE(f.soe.binarySOE.empty());
            REQUIRE(f.soe.doubleBinarySOE.empty());
        }
}

TEST_CASE("ProfileMeasurements - CTO requires the profile 8-bit count qualifier",
          "[profile-measurements]")
{
    for (unsigned variation : {1u, 2u})
        for (bool doubleBit : {false, true})
        {
            ProfileMeasurements f;
            const auto wire = std::string("01 02 00 00 00 81 ")
                + CTO(variation, "08 01 00", "07 00 00 00 00 00 ") + Relative(doubleBit);
            REQUIRE(f.Parse(wire) == ParseResult::INVALID_OBJECT_QUALIFIER);
            REQUIRE(f.soe.TotalReceived() == 0);

            ProfileMeasurements allObjects;
            const auto noContents = CTO(1, "07 01", "07 00 00 00 00 00 ")
                + CTO(variation, "06", "") + Relative(doubleBit);
            REQUIRE(allObjects.Parse(noContents) == ParseResult::INVALID_OBJECT_QUALIFIER);
            REQUIRE(allObjects.soe.TotalReceived() == 0);
        }
}

TEST_CASE("ProfileMeasurements - zero and truncated CTOs fail before preceding measurement callbacks",
          "[profile-measurements]")
{
    for (unsigned variation : {1u, 2u})
    {
        ProfileMeasurements zero;
        REQUIRE(zero.Parse("01 02 00 00 00 81 " + CTO(variation, "07 00", "")) == ParseResult::COUNT_OF_ZERO);
        REQUIRE(zero.soe.TotalReceived() == 0);
        const std::string time = "07 00 00 00 00 00";
        for (size_t length = 0; length < 6; ++length)
        {
            ProfileMeasurements f;
            const auto prefix = length == 0 ? std::string() : time.substr(0, length * 3 - 1);
            REQUIRE(f.Parse("01 02 00 00 00 81 " + CTO(variation, "07 01", prefix))
                    == ParseResult::NOT_ENOUGH_DATA_FOR_OBJECTS);
            REQUIRE(f.soe.TotalReceived() == 0);
        }
    }
}

TEST_CASE("ProfileMeasurements - ordinary limited event READ quantities remain unchanged",
          "[profile-measurements]")
{
    for (const auto& group : {"02", "04", "20"})
        for (const auto& count : {"07 02", "08 02 00"})
        {
            HexSequence wire(std::string(group) + " 00 " + count);
            REQUIRE(APDUParser::ParseAndLogAll(wire.ToRSeq(), nullptr, ParserSettings::NoContents()) == ParseResult::OK);
        }
}

TEST_CASE("ProfileMeasurements - malformed unsolicited CTO response is neither delivered nor confirmed",
          "[profile-measurements]")
{
    for (unsigned variation : {1u, 2u})
        for (bool doubleBit : {false, true})
        {
            MasterTestFixture master(NoStartupTasks());
            REQUIRE(master.context->OnLowerLayerUp());
            const auto wire = std::string("F0 82 00 00 01 02 00 00 00 81 ")
                + CTO(variation, "07 02", "07 00 00 00 00 00 15 00 00 00 00 00 ") + Relative(doubleBit);
            REQUIRE(master.SendToMaster(wire));
            REQUIRE(master.meas->TotalReceived() == 0);
            REQUIRE(master.lower->HasNoData());
        }
}

TEST_CASE("ProfileMeasurements - valid relative events retain native fragmented response confirmations",
          "[profile-measurements]")
{
    auto params = NoStartupTasks();
    params.startupIntegrityClassMask = ClassField::AllClasses();
    MasterTestFixture master(params);
    REQUIRE(master.context->OnLowerLayerUp());
    master.exe->run_many();
    REQUIRE(master.lower->PopWriteAsHex() == "C0 01 3C 02 06 3C 03 06 3C 04 06 3C 01 06");
    REQUIRE(master.context->OnTxReady());
    REQUIRE(master.SendToMaster("A0 81 00 00 " + CTO(1, "07 01", "07 00 00 00 00 00 ") + Relative(false)));
    CheckTime(master.meas->binarySOE.at(8), 8, TimestampQuality::SYNCHRONIZED);
    REQUIRE(master.lower->PopWriteAsHex() == "C0 00");
    REQUIRE(master.context->OnTxReady());
    REQUIRE(master.SendToMaster("61 81 00 00 " + CTO(2, "07 01", "15 00 00 00 00 00 ") + Relative(true, true)));
    CheckTime(master.meas->doubleBinarySOE.at(8), 22, TimestampQuality::UNSYNCHRONIZED);
    REQUIRE(master.lower->PopWriteAsHex() == "C1 00");
}

TEST_CASE("ProfileMeasurements - G34 READ covers defaults, sparse ranges and both response widths", "[profile-deadband]")
{
    DatabaseConfig db;
    db.analog_input[1].deadband = 65536;
    db.analog_input[1].deadbandVariation = AnalogDeadbandVariation::UInt16;
    db.analog_input[3].deadband = 4294967296.0;
    db.analog_input[300].deadband = 1.5;
    db.analog_input[300].svariation = StaticAnalogVariation::Group30Var5;
    OutstationTestObject t(OutstationConfig{}, db);
    t.LowerLayerUp();

    REQUIRE(DeadbandExchange(t, "C0 01 22 00 06")
            == "C0 81 80 00 22 01 00 01 01 FF FF 22 02 00 03 03 FF FF FF FF 22 03 01 2C 01 2C 01 00 00 C0 3F");
    REQUIRE(DeadbandExchange(t, "C1 01 22 01 00 01 03")
            == "C1 81 80 04 22 01 00 01 01 FF FF 22 01 00 03 03 FF FF");
    REQUIRE(DeadbandExchange(t, "C2 01 22 02 01 2C 01 2C 01") == "C2 81 80 00 22 02 01 2C 01 2C 01 01 00 00 00");
    REQUIRE(DeadbandExchange(t, "C3 01 22 03 00 03 03") == "C3 81 80 00 22 03 00 03 03 00 00 80 4F");
    REQUIRE(DeadbandExchange(t, "C4 01 22 00 07 01") == "C4 81 80 04");
    const auto classZero = DeadbandExchange(t, "C5 01 3C 01 06");
    REQUIRE(classZero.find("1E") != std::string::npos);
    REQUIRE(classZero.find("22 ") == std::string::npos);
    REQUIRE(DeadbandExchange(t, "C6 01 22 00 01 2C 01 2C 01") == "C6 81 80 00 22 03 01 2C 01 2C 01 00 00 C0 3F");
    REQUIRE(DeadbandExchange(t, "C7 01 22 01 06")
            == "C7 81 80 00 22 01 00 01 01 FF FF 22 01 00 03 03 FF FF 22 01 01 2C 01 2C 01 01 00");
    REQUIRE(DeadbandExchange(t, "C8 01 22 02 06")
            == "C8 81 80 00 22 02 00 01 01 00 00 01 00 22 02 00 03 03 FF FF FF FF 22 02 01 2C 01 2C 01 01 00 00 00");
    REQUIRE(DeadbandExchange(t, "C9 01 22 03 06")
            == "C9 81 80 00 22 03 00 01 01 00 00 80 47 22 03 00 03 03 00 00 80 4F 22 03 01 2C 01 2C 01 00 00 C0 3F");

    OutstationTestObject empty(OutstationConfig{});
    empty.LowerLayerUp();
    REQUIRE(DeadbandExchange(empty, "C0 01 22 00 06") == "C0 81 80 00");
    REQUIRE(DeadbandExchange(empty, "C1 01 22 01 00 01 01") == "C1 81 80 04");
}

TEST_CASE("ProfileMeasurements - G34 WRITE validates the entire request before committing", "[profile-deadband]")
{
    DatabaseConfig db;
    db.analog_input[1].deadband = 7;
    db.analog_input[2].deadband = 8;
    db.analog_input[300].deadband = 9;
    OutstationTestObject t(OutstationConfig{}, db);
    t.LowerLayerUp();

    REQUIRE(DeadbandExchange(t, "C0 02 22 01 00 01 02 05 00 06 00") == "C0 81 80 00");
    REQUIRE(DeadbandExchange(t, "C1 02 22 02 01 2C 01 2C 01 FF FF FF FF") == "C1 81 80 00");
    REQUIRE(DeadbandExchange(t, "C2 02 22 03 17 01 01 00 00 80 BF") == "C2 81 80 00"); // -1 normalizes to zero
    REQUIRE(DeadbandExchange(t, "C3 02 22 03 28 01 00 02 00 00 00 80 7F") == "C3 81 80 00"); // +infinity
    const std::string read = " 01 22 03 00 01 02";
    REQUIRE(DeadbandExchange(t, "C4" + read) == "C4 81 80 00 22 03 00 01 02 00 00 00 00 00 00 80 7F");

    const std::string valid = " 02 22 01 17 01 01 0A 00 ";
    REQUIRE(DeadbandExchange(t, "C5" + valid + "22 02 28 01 00 09 00 0B 00 00 00") == "C5 81 80 04");
    REQUIRE(DeadbandExchange(t, "C6" + valid + "22 03 00 02 02 00 00 C0 7F") == "C6 81 80 04");
    REQUIRE(DeadbandExchange(t, "C7" + valid + "22 02 01 2C 01 2C 01 00") == "C7 81 80 04");
    REQUIRE(DeadbandExchange(t, "C8" + valid + "22 00 06") == "C8 81 80 04");
    REQUIRE(DeadbandExchange(t, "C9" + read) == "C9 81 80 00 22 03 00 01 02 00 00 00 00 00 00 80 7F");
    REQUIRE(DeadbandExchange(t, "CA 01 22 02 01 2C 01 2C 01") == "CA 81 80 00 22 02 01 2C 01 2C 01 FF FF FF FF");
}

TEST_CASE("ProfileMeasurements - Master receives the exact G34 type and index and rejects invalid responses",
          "[profile-deadband]")
{
    MockLogHandler log;
    DeadbandSOE soe;
    const auto parse = [&](const std::string& hex) {
        HexSequence wire(hex);
        return MeasurementHandler::ProcessMeasurements(ResponseInfo(false, true, true), wire.ToRSeq(), log.logger, &soe);
    };
    REQUIRE(parse("22 01 00 FF FF FF FF 22 02 01 2C 01 2C 01 FF FF FF FF 22 03 00 02 02 00 00 C0 3F")
            == ParseResult::OK);
    REQUIRE(soe.records.size() == 3);
    REQUIRE(soe.records[0].first.gv == GroupVariation::Group34Var1);
    REQUIRE(soe.records[0].second.index == 255);
    REQUIRE(soe.records[0].second.value.value == 65535);
    REQUIRE(soe.records[1].first.gv == GroupVariation::Group34Var2);
    REQUIRE(soe.records[1].second.index == 300);
    REQUIRE(soe.records[1].second.value.value == 4294967295.0);
    REQUIRE(soe.records[2].first.gv == GroupVariation::Group34Var3);
    REQUIRE(soe.records[2].second.index == 2);
    REQUIRE(soe.records[2].second.value.value == 1.5);
    soe.records.clear();
    REQUIRE(parse("22 01 00 01 01 04 00 22 03 00 02 02 00 00 C0 7F") != ParseResult::OK);
    REQUIRE(parse("22 02 17 01 01 04 00 00 00") != ParseResult::OK);
    REQUIRE(parse("22 00 00 01 01") != ParseResult::OK);
    REQUIRE(soe.records.empty());
}

TEST_CASE("ProfileMeasurements - written deadbands change G32 thresholds without resetting the event baseline",
          "[profile-deadband]")
{
    DatabaseConfig db;
    db.analog_input[1].evariation = EventAnalogVariation::Group32Var5;
    OutstationConfig config;
    config.eventBufferConfig.maxAnalogEvents = 4;
    OutstationTestObject t(config, db);
    t.LowerLayerUp();
    const auto update = [&](double value, uint8_t flags, EventMode mode = EventMode::Detect) {
        t.Transaction([&](IUpdateHandler& handler) { REQUIRE(handler.Update(Analog(value, Flags(flags)), 1, mode)); });
    };
    update(10, 1, EventMode::Force);
    REQUIRE(DeadbandExchange(t, "C0 01 20 05 06") == "E0 81 80 00 20 05 28 01 00 01 00 01 00 00 20 41");
    REQUIRE(DeadbandExchange(t, "C1 02 22 01 00 01 01 05 00") == "C1 81 80 00");
    update(100, 1, EventMode::Suppress);
    update(15, 1);
    REQUIRE(DeadbandExchange(t, "C2 01 20 05 06") == "C2 81 80 00");
    update(16, 1);
    REQUIRE(DeadbandExchange(t, "C3 01 20 05 06") == "E3 81 80 00 20 05 28 01 00 01 00 01 00 00 80 41");
    REQUIRE(DeadbandExchange(t, "C4 02 22 03 00 01 01 00 00 80 7F") == "C4 81 80 00");
    update(std::numeric_limits<double>::infinity(), 1);
    REQUIRE(DeadbandExchange(t, "C5 01 20 05 06") == "C5 81 80 00");
    update(1000, 3);
    REQUIRE(DeadbandExchange(t, "C6 01 20 05 06") == "E6 81 80 00 20 05 28 01 00 01 00 03 00 00 7A 44");
    REQUIRE(DeadbandExchange(t, "C7 02 22 03 00 01 01 00 00 80 BF") == "C7 81 80 00");
    update(1000, 3);
    REQUIRE(DeadbandExchange(t, "C8 01 20 05 06") == "C8 81 80 00");
    update(1000.25, 3);
    REQUIRE(DeadbandExchange(t, "C9 01 20 05 06") == "E9 81 80 00 20 05 28 01 00 01 00 03 00 10 7A 44");
}

TEST_CASE("ProfileMeasurements - G34 resumes after a solicited fragment confirmation", "[profile-deadband]")
{
    DatabaseConfig db;
    db.analog_input[1].deadband = 1;
    db.analog_input[2].deadband = 2;
    db.analog_input[300].deadband = 3;
    OutstationConfig config;
    config.params.maxTxFragSize = 15;
    OutstationTestObject t(config, db);
    t.LowerLayerUp();
    t.SendToOutstation("C0 01 22 02 06");
    REQUIRE(t.lower->PopWriteAsHex() == "A0 81 80 00 22 02 00 01 01 01 00 00 00");
    t.OnTxReady();
    t.SendToOutstation("C0 00");
    REQUIRE(t.lower->PopWriteAsHex() == "21 81 80 00 22 02 00 02 02 02 00 00 00");
    t.OnTxReady();
    t.SendToOutstation("C1 00");
    REQUIRE(t.lower->PopWriteAsHex() == "42 81 80 00 22 02 01 2C 01 2C 01 03 00 00 00");
}
