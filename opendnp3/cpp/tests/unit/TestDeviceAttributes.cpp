// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/APDUResponse.h"
#include "app/parsing/APDUParser.h"
#include "auth/AuthenticationStatistics.h"
#include "dnp3mocks/MockLogHandler.h"
#include "dnp3mocks/MockOutstationApplication.h"
#include "dnp3mocks/MockSOEHandler.h"
#include "gen/objects/Group0.h"
#include "master/MeasurementHandler.h"
#include "outstation/Database.h"
#include "outstation/ReadHandler.h"
#include "outstation/ResponseContext.h"
#include "outstation/event/EventBuffer.h"
#include "opendnp3/master/PrintingSOEHandler.h"
#include "utils/BufferHelpers.h"
#include "utils/MasterTestFixture.h"
#include "utils/OutstationTestObject.h"

#include <ser4cpp/util/HexConversions.h>
#include <catch.hpp>
#include <array>
#include <string>
#include <vector>

using namespace opendnp3;
using namespace ser4cpp;
namespace
{
struct AttributeSOE final : MockSOEHandler
{
    struct Sample { HeaderInfo header; uint16_t set; uint8_t type; std::vector<uint8_t> bytes; };
    std::vector<Sample> attributes;
    unsigned begins = 0, ends = 0;
    void BeginFragment(const ResponseInfo&) override { ++begins; }
    void EndFragment(const ResponseInfo&) override { ++ends; }
    void Process(const HeaderInfo& header, const ICollection<Indexed<DeviceAttribute>>& values) override
    {
        values.ForeachItem([&](const Indexed<DeviceAttribute>& item) {
            const uint8_t* data = item.value.value;
            attributes.push_back({header, item.index, item.value.dataType, {data, data + item.value.value.length()}});
        });
    }
    uint64_t Unsigned(size_t index) const
    {
        const auto& sample = attributes.at(index);
        DeviceAttribute value;
        value.dataType = sample.type;
        value.value = rseq_t(sample.bytes.data(), sample.bytes.size());
        uint64_t number = 0;
        REQUIRE(value.GetUnsigned(number));
        return number;
    }
};
struct MasterAttributes
{
    MockLogHandler log;
    AttributeSOE soe;
    ParseResult Parse(const std::string& wire)
    {
        HexSequence input(wire);
        return MeasurementHandler::ProcessMeasurements(ResponseInfo(false, true, true), input.ToRSeq(), log.logger, &soe);
    }
};
struct AttributeRead
{
    AuthenticationStatistics::StaticSnapshot statistics;
    EventBuffer events{EventBufferConfig{}};
    MockOutstationApplication application;
    Database database{DatabaseConfig{}, events, application, StaticTypeBitField()};
    ResponseContext response{database, events};
    IINField errors;
    ParseResult Select(const std::string& wire, bool withStatistics = true)
    {
        database.Unselect();
        response.Reset();
        if (withStatistics) database.SetSecurityStatistics(statistics);
        ReadHandler handler(database, events);
        HexSequence input(wire);
        auto result = APDUParser::Parse(input.ToRSeq(), handler, nullptr, ParserSettings::NoContents());
        errors = handler.Errors();
        return result;
    }
    std::string Fragment(size_t capacity = 2048)
    {
        std::vector<uint8_t> data(capacity);
        APDUResponse responseAPDU(wseq_t(data.data(), data.size()));
        auto writer = responseAPDU.GetWriter();
        responseAPDU.SetControl(response.LoadResponse(writer));
        responseAPDU.SetFunction(FunctionCode::RESPONSE);
        responseAPDU.SetIIN(errors);
        return HexConversions::to_hex(responseAPDU.ToRSeq());
    }
};
}

TEST_CASE("DeviceAttributes - generated unsigned variation identifiers", "[device-attributes]")
{
    REQUIRE(Group0Var209::ID().variation == 209);
    REQUIRE(Group0Var210::ID().variation == 210);
    REQUIRE(Group0Var254::ID().variation == 254);
    REQUIRE(Group0Var255::ID().variation == 255);
    REQUIRE(GroupVariationSpec::from_type(0x00D1) == GroupVariation::Group0Var209);
    REQUIRE(GroupVariationSpec::from_type(0x00D2) == GroupVariation::Group0Var210);
    REQUIRE(GroupVariationSpec::from_type(0x00FF) == GroupVariation::Group0Var255);
}

TEST_CASE("DeviceAttributes - actual count per association and no fabricated SA version", "[device-attributes]")
{
    AttributeRead read;
    REQUIRE(read.Select("00 D2 00 00 00") == ParseResult::OK);
    REQUIRE(read.errors == IINField::Empty());
    REQUIRE(read.Fragment() == "C0 81 00 00 00 D2 00 00 00 02 01 12");
    REQUIRE(read.statistics.values.size() == 18);
    REQUIRE_FALSE(read.database.HasAnySelection());
    REQUIRE(read.Select("00 D1 00 00 00") == ParseResult::OK);
    REQUIRE(read.errors == IINField(IINBit::OBJECT_UNKNOWN));
    REQUIRE(read.Fragment() == "C0 81 00 02");
    REQUIRE(read.Select("00 D2 00 00 00", false) == ParseResult::OK);
    REQUIRE(read.Fragment() == "C0 81 00 00 00 D2 00 00 00 02 01 00");
}

TEST_CASE("DeviceAttributes - mandatory discovery reports only available read-only attributes", "[device-attributes]")
{
    for (const auto& header : {"00 FF 00 00 00", "00 FF 06"})
    {
        AttributeRead read;
        REQUIRE(read.Select(header) == ParseResult::OK);
        REQUIRE(read.errors == IINField::Empty());
        REQUIRE(read.Fragment() == "C0 81 00 00 00 FF 17 01 00 FE 02 D2 00");
    }
    for (const auto& header : {"00 FE 00 00 00", "00 FE 06"})
    {
        AttributeRead read;
        REQUIRE(read.Select(header) == ParseResult::OK);
        REQUIRE(read.Fragment() == "C0 81 00 00 00 D2 00 00 00 02 01 12");
    }
}

TEST_CASE("DeviceAttributes - attribute sets are not association or statistic indexes", "[device-attributes]")
{
    AttributeRead read;
    REQUIRE(read.Select("00 D2 00 01 01") == ParseResult::OK);
    REQUIRE(read.errors == IINField(IINBit::PARAM_ERROR));
    REQUIRE(read.Fragment() == "C0 81 00 04");
    REQUIRE(read.Select("00 D2 00 00 01") == ParseResult::OK);
    REQUIRE(read.errors == IINField(IINBit::PARAM_ERROR));
    REQUIRE(read.Fragment() == "C0 81 00 04 00 D2 00 00 00 02 01 12");
    MasterAttributes master;
    REQUIRE(master.Parse("00 D2 17 02 00 02 01 12 07 02 02 34 12") == ParseResult::OK);
    REQUIRE(master.soe.attributes.size() == 2);
    REQUIRE(master.soe.attributes[0].set == 0);
    REQUIRE(master.soe.attributes[1].set == 7);
    REQUIRE(master.soe.Unsigned(0) == 18);
    REQUIRE(master.soe.Unsigned(1) == 0x1234);
}

TEST_CASE("DeviceAttributes - attributes remain outside Class zero and do not clear statistics", "[device-attributes]")
{
    AttributeRead read;
    read.statistics.values[0] = 123;
    const auto before = read.statistics.values;
    REQUIRE(read.Select("3C 01 06") == ParseResult::OK);
    auto wire = read.Fragment();
    MasterAttributes master;
    REQUIRE(master.Parse(wire.substr(12)) == ParseResult::OK); // strip application header
    REQUIRE(master.soe.attributes.empty());
    REQUIRE(master.soe.securityStatSOE.size() == before.size());
    REQUIRE(read.statistics.values == before);
    REQUIRE(read.Select("00 D2 00 00 00") == ParseResult::OK);
    read.Fragment();
    REQUIRE(read.statistics.values == before);
}

TEST_CASE("DeviceAttributes - Master decodes both profile response qualifiers and UINTn", "[device-attributes]")
{
    for (const auto variation : {"D1", "D2"})
        for (const auto header : {"00 00 00", "17 01 00"})
            for (const auto value : {"01 05", "02 34 12", "03 56 34 12", "04 78 56 34 12", "08 FF FF FF FF FF FF FF FF"})
            {
                MasterAttributes master;
                REQUIRE(master.Parse(std::string("00 ") + variation + " " + header + " 02 " + value) == ParseResult::OK);
                REQUIRE(master.soe.attributes.size() == 1);
                REQUIRE(master.soe.attributes[0].set == 0);
                REQUIRE(master.soe.attributes[0].type == 2);
                REQUIRE_FALSE(master.soe.attributes[0].header.isEventVariation);
                REQUIRE_FALSE(master.soe.attributes[0].header.flagsValid);
                REQUIRE(master.soe.attributes[0].header.tsquality == TimestampQuality::INVALID);
                REQUIRE(master.soe.begins == 1);
                REQUIRE(master.soe.ends == 1);
                const auto number = master.soe.Unsigned(0);
                REQUIRE(number != 0);
            }
}

TEST_CASE("DeviceAttributes - exact unsigned values and borrowed UINT conversion bounds", "[device-attributes]")
{
    MasterAttributes master;
    REQUIRE(master.Parse("00 D1 00 00 00 02 01 05 00 D2 00 00 00 02 04 78 56 34 12") == ParseResult::OK);
    REQUIRE(master.soe.Unsigned(0) == 5);
    REQUIRE(master.soe.Unsigned(1) == 0x12345678);
    std::array<uint8_t, 9> bytes{};
    bytes[8] = 1;
    DeviceAttribute value;
    value.value = rseq_t(bytes.data(), bytes.size());
    uint64_t number = 123;
    REQUIRE_FALSE(value.GetUnsigned(number));
    REQUIRE(number == 123);
    bytes[8] = 0;
    bytes[0] = 18;
    REQUIRE(value.GetUnsigned(number));
    REQUIRE(number == 18);
}

TEST_CASE("DeviceAttributes - Master list parsing preserves properties including extended length", "[device-attributes]")
{
    for (const auto header : {"00 00 00", "17 01 00"})
    {
        MasterAttributes master;
        REQUIRE(master.Parse(std::string("00 FF ") + header + " FE 04 D1 00 D2 00") == ParseResult::OK);
        REQUIRE((master.soe.attributes[0].bytes == std::vector<uint8_t>{209, 0, 210, 0}));
    }
    MasterAttributes master;
    std::string extended = "00 FF 17 01 00 FF 00";
    for (unsigned i = 0; i < 128; ++i) extended += " D2 00";
    REQUIRE(master.Parse(extended) == ParseResult::OK);
    REQUIRE(master.soe.attributes[0].type == 255);
    REQUIRE(master.soe.attributes[0].bytes.size() == 256);
}

TEST_CASE("DeviceAttributes - mixed attributes and measurements retain native header order", "[device-attributes]")
{
    MasterAttributes master;
    REQUIRE(master.Parse("01 02 00 00 00 81 00 D2 00 00 00 02 01 12 00 FF 17 01 00 FE 02 D2 00") == ParseResult::OK);
    REQUIRE(master.soe.binarySOE.size() == 1);
    REQUIRE(master.soe.attributes.size() == 2);
    REQUIRE(master.soe.attributes[0].header.headerIndex == 1);
    REQUIRE(master.soe.attributes[1].header.headerIndex == 2);
    REQUIRE(master.soe.begins == 1);
    REQUIRE(master.soe.ends == 1);
}

TEST_CASE("DeviceAttributes - every truncated object rejects before any callbacks", "[device-attributes]")
{
    for (const auto& wire : {"00 D1 00 00 00 02 04 78 56 34 12", "00 D2 17 01 00 02 02 12 00", "00 FF 17 01 00 FE 02 D2 00"})
    {
        const auto text = std::string(wire);
        const auto size = (text.size() + 1) / 3;
        for (size_t length = 1; length < size; ++length)
        {
            MasterAttributes master;
            REQUIRE(master.Parse("01 02 00 00 00 81 " + text.substr(0, length * 3 - 1)) != ParseResult::OK);
            REQUIRE(master.soe.attributes.empty());
            REQUIRE(master.soe.binarySOE.empty());
            REQUIRE(master.soe.begins == 0);
        }
    }
}

TEST_CASE("DeviceAttributes - malformed types lengths qualifiers and ranges", "[device-attributes]")
{
    for (const auto& wire : {"00 D2 00 00 00 01 01 12", "00 D1 00 00 00 02 00",
         "00 D2 01 00 00 00 00 02 01 12", "00 D2 28 01 00 00 00 02 01 12", "00 D2 06",
         "00 FE 00 00 00", "00 D2 17 00", "00 D2 00 01 00", "00 FF 17 01 00 FE 01 D2",
         "00 FF 17 01 00 02 01 12", "00 FF 17 01 00 FF 00 D2 00", "00 D0 00 00 00 02 01 12"})
    {
        MasterAttributes master;
        REQUIRE(master.Parse(wire) != ParseResult::OK);
        REQUIRE(master.soe.attributes.empty());
    }
    for (const auto& wire : {"00 D2 06", "00 D1 17 01 00", "00 D2 01 00 00 00 00", "00 FE 17 01 00"})
    {
        AttributeRead read;
        REQUIRE(read.Select(wire) == ParseResult::INVALID_OBJECT_QUALIFIER);
        REQUIRE_FALSE(read.database.HasAnySelection());
    }
}

TEST_CASE("DeviceAttributes - atomic writer and native response fragmentation", "[device-attributes]")
{
    AttributeRead read;
    REQUIRE(read.Select("00 D2 00 00 00 00 FF 00 00 00") == ParseResult::OK);
    REQUIRE(read.Fragment(11) == "A0 81 00 00"); // object cannot fit: retain selections
    REQUIRE(read.database.HasAnySelection());
    REQUIRE(read.Fragment(12) == "20 81 00 00 00 D2 00 00 00 02 01 12");
    REQUIRE(read.database.HasAnySelection());
    REQUIRE(read.Fragment(13) == "40 81 00 00 00 FF 17 01 00 FE 02 D2 00");
    REQUIRE_FALSE(read.database.HasAnySelection());
    REQUIRE(read.Select("00 D2 00 00 00") == ParseResult::OK);
    read.database.Unselect();
    REQUIRE_FALSE(read.database.HasAnySelection());
}

TEST_CASE("DeviceAttributes - writer produces exact G209 response without claiming local capability", "[device-attributes]")
{
    std::array<uint8_t, 32> data{};
    APDUResponse response(wseq_t(data.data(), data.size()));
    response.SetControl(AppControlField::Request(0));
    response.SetFunction(FunctionCode::RESPONSE);
    response.SetIIN(IINField::Empty());
    auto writer = response.GetWriter();
    const uint8_t version = 5;
    DeviceAttribute value;
    value.value = rseq_t(&version, 1);
    REQUIRE_FALSE(writer.WriteAttribute(209, 0, value, QualifierCode::UINT16_START_STOP));
    REQUIRE(response.Size() == 4);
    REQUIRE(writer.WriteAttribute(209, 0, value, QualifierCode::UINT8_CNT_UINT8_INDEX));
    REQUIRE(HexConversions::to_hex(response.ToRSeq()) == "C0 81 00 00 00 D1 17 01 00 02 01 05");
    // This is codec-only. Outstation G209 deliberately remains unavailable.
}

TEST_CASE("DeviceAttributes - native Master explicit profile READ and fragmented typed delivery", "[device-attributes]")
{
    MasterTestFixture master(NoStartupTasks());
    auto soe = std::make_shared<AttributeSOE>();
    REQUIRE(master.context->OnLowerLayerUp());
    master.exe->run_many();
    master.context->Scan([](HeaderWriter& writer) {
        return writer.WriteRangeHeader<UInt8>(QualifierCode::UINT8_START_STOP, GroupVariationID(0, 210), 0, 0);
    }, soe);
    master.exe->run_many();
    REQUIRE(master.lower->PopWriteAsHex() == "C0 01 00 D2 00 00 00");
    REQUIRE(master.context->OnTxReady());
    REQUIRE(master.SendToMaster("A0 81 00 00 00 D2 00 00 00 02 01 12"));
    REQUIRE(soe->Unsigned(0) == 18);
    REQUIRE(master.lower->PopWriteAsHex() == "C0 00");
    REQUIRE(master.context->OnTxReady());
    REQUIRE(master.SendToMaster("61 81 00 00 00 FF 17 01 00 FE 02 D2 00"));
    REQUIRE(soe->attributes.size() == 2);
    REQUIRE(soe->begins == 2);
    REQUIRE(soe->ends == 2);
    REQUIRE(master.lower->PopWriteAsHex() == "C1 00");
}

TEST_CASE("DeviceAttributes - native compatibility Outstation and mixed WRITE rejection", "[device-attributes]")
{
    OutstationTestObject outstation(OutstationConfig{});
    outstation.LowerLayerUp();
    outstation.SendToOutstation("C0 01 00 D2 00 00 00");
    REQUIRE(outstation.lower->PopWriteAsHex() == "C0 81 80 00 00 D2 00 00 00 02 01 00");
    outstation.OnTxReady();
    outstation.SendToOutstation("C1 01 00 D1 00 00 00");
    REQUIRE(outstation.lower->PopWriteAsHex() == "C1 81 80 02");
    outstation.OnTxReady();
    outstation.SendToOutstation("C2 02 32 01 07 01 01 00 00 00 00 00 00 D2 00 00 00 02 01 12");
    REQUIRE(outstation.application->timestamps.empty());
    REQUIRE(outstation.lower->PopWriteAsHex() == "C2 81 80 04");
}


TEST_CASE("DeviceAttributes - existing applications may ignore optional typed attributes", "[device-attributes]")
{
    MockLogHandler log;
    PrintingSOEHandler legacy;
    HexSequence input("00 D2 00 00 00 02 01 12");
    REQUIRE(MeasurementHandler::ProcessMeasurements(ResponseInfo(false, true, true), input.ToRSeq(), log.logger, &legacy)
            == ParseResult::OK);
}
