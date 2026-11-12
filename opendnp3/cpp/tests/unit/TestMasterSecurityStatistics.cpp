// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/parsing/APDUParser.h"
#include "dnp3mocks/MockLogHandler.h"
#include "dnp3mocks/MockSOEHandler.h"
#include "master/MeasurementHandler.h"
#include "opendnp3/master/PrintingSOEHandler.h"
#include "utils/BufferHelpers.h"
#include "utils/MasterTestFixture.h"
#include "utils/OutstationTestObject.h"

#include <catch.hpp>
#include <memory>
#include <string>
#include <vector>

using namespace opendnp3;

namespace
{
struct SecuritySOE final : MockSOEHandler
{
    std::vector<ResponseInfo> begins, ends;
    void BeginFragment(const ResponseInfo& info) override { begins.push_back(info); }
    void EndFragment(const ResponseInfo& info) override { ends.push_back(info); }
};

struct Fixture
{
    MockLogHandler log;
    SecuritySOE soe;
    ParseResult Parse(const std::string& wire, ResponseInfo response = ResponseInfo(false, true, true))
    {
        HexSequence bytes(wire);
        return MeasurementHandler::ProcessMeasurements(response, bytes.ToRSeq(), log.logger, &soe);
    }
};

void Check(const MockSOEHandler::Record<Indexed<SecurityStat>>& record, uint16_t index, uint16_t association,
           uint32_t value, uint8_t flags)
{
    REQUIRE(record.meas.index == index);
    REQUIRE(record.meas.value.associationId == association);
    REQUIRE(record.meas.value.value == value);
    REQUIRE(record.meas.value.flags.value == flags);
    REQUIRE(record.info.flagsValid);
}
}

TEST_CASE("MasterSecurityStatistics - G121 supports all response qualifiers", "[master-security-statistics]")
{
    struct Input { const char* header; uint16_t index; QualifierCode qualifier; };
    for (const auto& input : {
        Input{"79 01 00 07 07", 7, QualifierCode::UINT8_START_STOP},
        Input{"79 01 01 34 12 34 12", 0x1234, QualifierCode::UINT16_START_STOP},
        Input{"79 01 17 01 17", 0x17, QualifierCode::UINT8_CNT_UINT8_INDEX},
        Input{"79 01 28 01 00 FF FF", 0xFFFF, QualifierCode::UINT16_CNT_UINT16_INDEX}})
    {
        Fixture f;
        REQUIRE(f.Parse(std::string(input.header) + " A5 EF BE FF FF FF FF") == ParseResult::OK);
        REQUIRE(f.soe.securityStatSOE.size() == 1);
        const auto& record = f.soe.securityStatSOE.front();
        Check(record, input.index, 0xBEEF, 0xFFFFFFFF, 0xA5); // Preserve the received flag byte, including reserved bits.
        REQUIRE(record.info.gv == GroupVariation::Group121Var1);
        REQUIRE(record.info.qualifier == input.qualifier);
        REQUIRE_FALSE(record.info.isEventVariation);
        REQUIRE(record.info.tsquality == TimestampQuality::INVALID);
        REQUIRE_FALSE(record.meas.value.HasTime());
        REQUIRE(f.soe.begins.size() == 1);
        REQUIRE(f.soe.ends.size() == 1);
    }
}

TEST_CASE("MasterSecurityStatistics - G121 range preserves highest indexes and association IDs", "[master-security-statistics]")
{
    Fixture f;
    REQUIRE(f.Parse("79 01 01 FE FF FF FF 01 00 00 01 00 00 00 41 CD AB 78 56 34 12") == ParseResult::OK);
    REQUIRE(f.soe.securityStatSOE.size() == 2);
    Check(f.soe.securityStatSOE[0], 0xFFFE, 0, 1, 0x01);
    Check(f.soe.securityStatSOE[1], 0xFFFF, 0xABCD, 0x12345678, 0x41);
}

TEST_CASE("MasterSecurityStatistics - both G122 variations and prefix sizes", "[master-security-statistics]")
{
    for (bool timed : {false, true})
    {
        for (bool wide : {false, true})
        {
            Fixture f;
            const auto wire = std::string(timed ? "7A 02 " : "7A 01 ")
                + (wide ? "28 01 00 34 12 " : "17 01 12 ") + "5F CD AB 78 56 34 12"
                + (timed ? " 01 02 03 04 05 06" : "");
            REQUIRE(f.Parse(wire) == ParseResult::OK);
            REQUIRE(f.soe.securityStatSOE.size() == 1);
            const auto& record = f.soe.securityStatSOE.front();
            Check(record, wide ? 0x1234 : 0x12, 0xABCD, 0x12345678, 0x5F);
            REQUIRE(record.info.gv == (timed ? GroupVariation::Group122Var2 : GroupVariation::Group122Var1));
            REQUIRE(record.info.isEventVariation);
            REQUIRE(record.info.qualifier == (wide ? QualifierCode::UINT16_CNT_UINT16_INDEX : QualifierCode::UINT8_CNT_UINT8_INDEX));
            REQUIRE(record.meas.value.time.value == (timed ? 0x060504030201ULL : 0));
            REQUIRE(record.meas.value.time.quality == (timed ? TimestampQuality::UNSYNCHRONIZED : TimestampQuality::INVALID));
            REQUIRE(record.info.tsquality == record.meas.value.time.quality);
        }
    }
}

TEST_CASE("MasterSecurityStatistics - max DNP3 time and prior CTO do not change occurrence", "[master-security-statistics]")
{
    Fixture f;
    REQUIRE(f.Parse("33 02 07 01 10 00 00 00 00 00 7A 02 17 01 00 01 00 00 00 00 00 00 FF FF FF FF FF FF") == ParseResult::OK);
    REQUIRE(f.soe.securityStatSOE.size() == 1);
    REQUIRE(f.soe.securityStatSOE[0].meas.value.time.value == 0xFFFFFFFFFFFFULL);
    REQUIRE(f.soe.securityStatSOE[0].meas.value.time.quality == TimestampQuality::UNSYNCHRONIZED);
    REQUIRE(f.soe.securityStatSOE[0].info.headerIndex == 1);
    REQUIRE(f.Parse("7A 02 17 01 00 01 00 00 00 00 00 00 00 00 00 00 00 00") == ParseResult::OK);
    REQUIRE(f.soe.securityStatSOE.size() == 2);
    REQUIRE(f.soe.securityStatSOE[1].meas.value.time.value == 0); // A wire timestamp of zero is preserved, not replaced.
    REQUIRE(f.soe.securityStatSOE[1].meas.value.HasTime());
}

TEST_CASE("MasterSecurityStatistics - different associations and repeated indexes are never merged", "[master-security-statistics]")
{
    Fixture f;
    REQUIRE(f.Parse("7A 01 17 03 00 01 00 00 01 00 00 00 12 41 07 00 02 00 00 00 12 01 09 00 03 00 00 00") == ParseResult::OK);
    REQUIRE(f.soe.securityStatSOE.size() == 3);
    Check(f.soe.securityStatSOE[0], 0, 0, 1, 1);
    Check(f.soe.securityStatSOE[1], 18, 7, 2, 0x41);
    Check(f.soe.securityStatSOE[2], 18, 9, 3, 1);
    REQUIRE(f.soe.securityStatSOE[0].sequence == 0);
    REQUIRE(f.soe.securityStatSOE[1].sequence == 1);
    REQUIRE(f.soe.securityStatSOE[2].sequence == 2);
}

TEST_CASE("MasterSecurityStatistics - mixed object delivery and fragment metadata", "[master-security-statistics]")
{
    Fixture f;
    REQUIRE(f.Parse("01 02 00 00 00 81 79 01 00 05 05 41 00 00 01 00 00 00 7A 01 17 01 12 01 07 00 02 00 00 00",
                    ResponseInfo(false, true, false)) == ParseResult::OK);
    REQUIRE(f.soe.TotalReceived() == 3);
    REQUIRE(f.soe.binarySOE[0].meas.value);
    REQUIRE(f.soe.securityStatSOE[0].sequence == 1);
    REQUIRE(f.soe.securityStatSOE[1].sequence == 2);
    REQUIRE(f.soe.securityStatSOE[0].info.headerIndex == 1);
    REQUIRE(f.soe.securityStatSOE[1].info.headerIndex == 2);
    REQUIRE(f.Parse("7A 02 28 01 00 24 00 01 09 00 03 00 00 00 01 02 03 04 05 06",
                    ResponseInfo(false, false, true)) == ParseResult::OK);
    REQUIRE(f.soe.securityStatSOE.size() == 3);
    Check(f.soe.securityStatSOE[2], 36, 9, 3, 1);
    REQUIRE(f.soe.begins.size() == 2);
    REQUIRE(f.soe.ends.size() == 2);
    REQUIRE(f.soe.begins[0].fir);
    REQUIRE_FALSE(f.soe.begins[0].fin);
    REQUIRE_FALSE(f.soe.ends[1].fir);
    REQUIRE(f.soe.ends[1].fin);
    REQUIRE_FALSE(f.soe.begins[0].unsolicited);
}

TEST_CASE("MasterSecurityStatistics - malformed or truncated objects deliver no partial fragment", "[master-security-statistics]")
{
    for (const auto& wire : {"79 01 00 00 00 41 00 00 78 56 34 12",
                             "79 01 01 00 00 00 00 41 00 00 78 56 34 12",
                             "79 01 17 01 00 41 00 00 78 56 34 12",
                             "79 01 28 01 00 00 00 41 00 00 78 56 34 12",
                             "7A 01 17 01 00 41 00 00 78 56 34 12",
                             "7A 02 28 01 00 00 00 41 00 00 78 56 34 12 01 02 03 04 05 06"})
    {
        HexSequence bytes(wire);
        const auto complete = bytes.ToRSeq();
        for (size_t size = 1; size < complete.length(); ++size)
        {
            Fixture f;
            REQUIRE(MeasurementHandler::ProcessMeasurements(ResponseInfo(false, true, true), complete.take(size),
                                                           f.log.logger, &f.soe) != ParseResult::OK);
            REQUIRE(f.soe.TotalReceived() == 0);
            REQUIRE(f.soe.begins.empty());
            REQUIRE(f.soe.ends.empty());
        }
    }
    Fixture f;
    REQUIRE(f.Parse("01 02 00 00 00 81 7A 02 17 01 00 41 00 00 78") != ParseResult::OK);
    REQUIRE(f.soe.TotalReceived() == 0); // Native two-pass parser validates all headers before dispatch.
    REQUIRE(f.soe.begins.empty());
}

TEST_CASE("MasterSecurityStatistics - unsupported response qualifier and variation rejected", "[master-security-statistics]")
{
    for (const auto& wire : {"79 00 06", "79 01 06", "79 01 07 01", "79 01 08 01 00",
                             "7A 00 06", "7A 01 06", "7A 02 07 01", "7A 01 00 00 00",
                             "7A 02 01 00 00 00 00", "7A 03 17 01 00", "79 01 00 01 00",
                             "7A 01 17 00", "7A 01 28 00 00", "7A 02 28 FF FF"})
    {
        Fixture f;
        REQUIRE(f.Parse(wire) != ParseResult::OK);
        REQUIRE(f.soe.TotalReceived() == 0);
        REQUIRE(f.soe.begins.empty());
    }
}

TEST_CASE("MasterSecurityStatistics - existing SOE implementations may ignore the new overload", "[master-security-statistics]")
{
    MockLogHandler log;
    PrintingSOEHandler legacy;
    HexSequence bytes("79 01 00 00 00 41 00 00 01 00 00 00");
    ISOEHandler* callback = &legacy;
    REQUIRE(MeasurementHandler::ProcessMeasurements(ResponseInfo(false, true, true), bytes.ToRSeq(), log.logger,
                                                   callback) == ParseResult::OK);
}

TEST_CASE("MasterSecurityStatistics - native Master solicited fragments and CONFIRMs", "[master-security-statistics]")
{
    auto params = NoStartupTasks();
    params.startupIntegrityClassMask = ClassField::AllClasses();
    MasterTestFixture t(params);
    REQUIRE(t.context->OnLowerLayerUp());
    t.exe->run_many();
    REQUIRE(t.lower->PopWriteAsHex() == "C0 01 3C 02 06 3C 03 06 3C 04 06 3C 01 06");
    REQUIRE(t.context->OnTxReady());
    REQUIRE(t.SendToMaster("A0 81 00 00 79 01 00 00 00 41 00 00 01 00 00 00"));
    REQUIRE(t.meas->securityStatSOE.size() == 1);
    Check(t.meas->securityStatSOE[0], 0, 0, 1, 0x41);
    REQUIRE(t.lower->PopWriteAsHex() == "C0 00");
    REQUIRE(t.context->OnTxReady());
    REQUIRE(t.SendToMaster("61 81 00 00 7A 02 28 01 00 12 00 01 07 00 02 00 00 00 01 02 03 04 05 06"));
    REQUIRE(t.meas->securityStatSOE.size() == 2);
    Check(t.meas->securityStatSOE[1], 18, 7, 2, 1);
    REQUIRE(t.meas->securityStatSOE[1].meas.value.time.value == 0x060504030201ULL);
    REQUIRE(t.lower->PopWriteAsHex() == "C1 00");
}

TEST_CASE("MasterSecurityStatistics - unsolicited observations and association isolation", "[master-security-statistics]")
{
    MasterTestFixture first(NoStartupTasks()), second(NoStartupTasks(), Addresses(2, 1024));
    REQUIRE(first.context->OnLowerLayerUp());
    REQUIRE(second.context->OnLowerLayerUp());
    const std::string event = "F0 82 00 00 7A 01 17 01 00 41 00 00 01 00 00 00";
    REQUIRE(first.SendToMaster(event));
    REQUIRE(first.meas->securityStatSOE.size() == 1);
    REQUIRE(second.meas->securityStatSOE.empty());
    REQUIRE(first.lower->PopWriteAsHex() == "D0 00");
    REQUIRE(first.context->OnTxReady());
    REQUIRE(first.SendToMaster(event)); // Preserve native repeated unsolicited delivery; do not add deduplication.
    REQUIRE(first.meas->securityStatSOE.size() == 2);
    REQUIRE(first.lower->PopWriteAsHex() == "D0 00");
    REQUIRE(second.SendToMaster(event));
    REQUIRE(second.meas->securityStatSOE.size() == 1);
    Check(second.meas->securityStatSOE[0], 0, 0, 1, 0x41);
    REQUIRE(second.lower->PopWriteAsHex() == "D0 00");
}

TEST_CASE("PROFILE-066 - native timed statistics retain u48 occurrence on unsolicited receive", "[master-security-statistics]")
{
    const bool narrow = GENERATE(false, true);
    const auto prefix = narrow ? "17 01 01 " : "28 01 00 01 01 ";
    const std::string event = std::string("F0 82 00 00 7A 02 ") + prefix + "41 34 12 78 56 34 12 FF FF FF FF FF FF";
    MasterTestFixture master(NoStartupTasks());
    REQUIRE(master.context->OnLowerLayerUp());
    REQUIRE(master.SendToMaster(event));
    REQUIRE(master.meas->securityStatSOE.size() == 1);
    const auto& record = master.meas->securityStatSOE.front();
    Check(record, narrow ? 1 : 257, 0x1234, 0x12345678, 0x41);
    REQUIRE(record.meas.value.HasTime());
    REQUIRE(record.meas.value.time.value == 0xFFFFFFFFFFFFULL);
    REQUIRE(master.lower->PopWriteAsHex() == "D0 00");
    REQUIRE(master.context->OnTxReady());
    master.meas->Clear();
    REQUIRE(master.SendToMaster("F1" + event.substr(2, event.size() - 5)));
    REQUIRE(master.meas->TotalReceived() == 0);
    REQUIRE(master.lower->HasNoData());
}


TEST_CASE("MasterSecurityStatistics - malformed unsolicited fragment is not delivered or confirmed", "[master-security-statistics]")
{
    MasterTestFixture t(NoStartupTasks());
    REQUIRE(t.context->OnLowerLayerUp());
    REQUIRE(t.SendToMaster("F0 82 00 00 7A 02 17 01 00 41 00 00 01"));
    REQUIRE(t.meas->securityStatSOE.empty());
    REQUIRE(t.lower->HasNoData());
}

TEST_CASE("MasterSecurityStatistics - Outstation still rejects response objects before mixed WRITE side effects", "[master-security-statistics]")
{
    for (const auto& objects : {"79 01 00 00 00 01 00 00 01 00 00 00",
                                "79 01 01 00 00 00 00 01 00 00 01 00 00 00",
                                "79 01 17 01 00 01 00 00 01 00 00 00",
                                "79 01 28 01 00 00 00 01 00 00 01 00 00 00",
                                "7A 01 17 01 00 01 00 00 01 00 00 00",
                                "7A 01 28 01 00 00 00 01 00 00 01 00 00 00",
                                "7A 02 17 01 00 01 00 00 01 00 00 00 01 02 03 04 05 06",
                                "7A 02 28 01 00 00 00 01 00 00 01 00 00 00 01 02 03 04 05 06"})
    {
        OutstationConfig config;
        OutstationTestObject t(config);
        t.LowerLayerUp();
        t.SendToOutstation(std::string("C0 02 32 01 07 01 01 00 00 00 00 00 ") + objects);
        REQUIRE(t.application->timestamps.empty());
        REQUIRE(t.lower->PopWriteAsHex() == "C0 81 80 04");
    }
}
