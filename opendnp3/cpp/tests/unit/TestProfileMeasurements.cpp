// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/parsing/APDUParser.h"
#include "dnp3mocks/MockLogHandler.h"
#include "dnp3mocks/MockSOEHandler.h"
#include "master/MeasurementHandler.h"
#include "utils/BufferHelpers.h"
#include "utils/MasterTestFixture.h"

#include <catch.hpp>
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
