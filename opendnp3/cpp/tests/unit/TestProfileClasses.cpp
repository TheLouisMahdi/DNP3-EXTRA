// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "utils/APDUHexBuilders.h"
#include "utils/OutstationTestObject.h"

#include <dnp3mocks/DatabaseHelpers.h>

#include <catch.hpp>

#include <string>
#include <tuple>

using namespace opendnp3;
namespace
{
// Sends one request frame and consumes its response so the next request can be answered.
std::string Exchange(OutstationTestObject& outstation, const std::string& request)
{
    outstation.SendToOutstation(request);
    auto response = outstation.lower->PopWriteAsHex();
    if (!response.empty())
    {
        outstation.OnTxReady();
    }
    return response;
}
} // namespace

TEST_CASE("ProfileClasses - class 0 READ uses qualifier 06 and rejects count qualifiers", "[profile-classes]")
{
    OutstationTestObject t(OutstationConfig(), configure::by_count_of::binary_input(1));
    t.LowerLayerUp();

    // G60V1 with qualifier 06 returns the class 0 static data.
    REQUIRE(Exchange(t, "C1 01 3C 01 06") == "C1 81 80 00 01 02 00 00 00 02");

    // A count qualifier addresses events, not the class 0 static scan.
    REQUIRE(Exchange(t, "C2 01 3C 01 07 01") == "C2 81 80 01"); // FUNC_NOT_SUPPORTED
    REQUIRE(Exchange(t, "C3 01 3C 01 08 01 00") == "C3 81 80 01");
}

TEST_CASE("ProfileClasses - ENABLE_UNSOLICITED and DISABLE_UNSOLICITED accept only class headers with qualifier 06",
          "[profile-classes]")
{
    OutstationConfig cfg;
    cfg.params.allowUnsolicited = true;
    cfg.eventBufferConfig = EventBufferConfig(5);
    OutstationTestObject t(cfg, configure::by_count_of::binary_input(5));
    t.LowerLayerUp();

    REQUIRE(t.lower->PopWriteAsHex() == hex::NullUnsolicited(0));
    t.OnTxReady();
    t.SendToOutstation(hex::UnsolConfirm(0));

    // A count qualifier is not a class header.
    REQUIRE(Exchange(t, "C1 14 3C 02 07 01") == "C1 81 80 04"); // PARAM_ERROR
    REQUIRE(Exchange(t, "C2 15 3C 03 07 01") == "C2 81 80 04");

    // Only a group 60 header selects a class.
    REQUIRE(Exchange(t, "C3 14 01 00 06") == "C3 81 80 01"); // FUNC_NOT_SUPPORTED
    REQUIRE(Exchange(t, "C4 15 02 00 06") == "C4 81 80 01");

    // The profile form is a class header with qualifier 06.
    REQUIRE(Exchange(t, "C5 14 3C 02 06") == "C5 81 80 00");
    REQUIRE(Exchange(t, "C6 15 3C 02 06") == "C6 81 80 00");
}

TEST_CASE("ProfileClasses - enabling and disabling unsolicited data affects only the selected class", "[profile-classes]")
{
    const auto cls = GENERATE(1, 2, 3);
    const std::string target = "3C 0" + std::to_string(cls + 1) + " 06";
    const std::string other = "3C 0" + std::to_string(cls % 3 + 2) + " 06";
    const std::string iin = cls == 1 ? "82" : cls == 2 ? "84" : "88";
    OutstationConfig cfg;
    cfg.params.allowUnsolicited = true;
    cfg.eventBufferConfig = EventBufferConfig(5);
    auto points = configure::by_count_of::binary_input(2);
    const PointClass classes[] = {PointClass::Class1, PointClass::Class2, PointClass::Class3};
    points.binary_input[0].clazz = classes[cls - 1];
    points.binary_input[1].clazz = classes[cls % 3];
    OutstationTestObject t(cfg, points);
    t.LowerLayerUp();

    REQUIRE(t.lower->PopWriteAsHex() == hex::NullUnsolicited(0));
    t.OnTxReady();
    t.SendToOutstation(hex::UnsolConfirm(0));

    // Neither class is enabled yet.
    t.Transaction([](IUpdateHandler& db) { db.Update(Binary(false, Flags(0x01)), 0, EventMode::Force); });
    REQUIRE(t.lower->PopWriteAsHex().empty());

    REQUIRE(Exchange(t, "C1 14 " + target) == "C1 81 " + iin + " 00");
    REQUIRE(t.lower->PopWriteAsHex() == "F1 82 80 00 02 01 28 01 00 00 00 01");
    t.OnTxReady();
    t.SendToOutstation(hex::UnsolConfirm(1));

    t.Transaction([](IUpdateHandler& db) { db.Update(Binary(true, Flags(0x01)), 1); });
    REQUIRE(t.lower->PopWriteAsHex().empty());
    const std::string otherIIN = cls == 1 ? "84" : cls == 2 ? "88" : "82";
    REQUIRE(Exchange(t, "C2 15 " + target) == "C2 81 " + otherIIN + " 00");
    t.Transaction([](IUpdateHandler& db) { db.Update(Binary(true, Flags(0x01)), 0); });
    REQUIRE(t.lower->PopWriteAsHex().empty());
    REQUIRE(Exchange(t, "C3 01 " + target) == "E3 81 " + otherIIN + " 00 02 01 28 01 00 00 00 81");
    t.SendToOutstation("C3 00");
    REQUIRE(Exchange(t, "C4 01 " + other) == "E4 81 80 00 02 01 28 01 00 01 00 81");
}

TEST_CASE("ProfileClasses - ASSIGN_CLASS maps G60V1 to class 0 and rejects count qualifiers", "[profile-classes]")
{
    OutstationTestObject t(OutstationConfig(), configure::by_count_of::binary_input(5));
    t.application->supportsAssignClass = true;
    t.LowerLayerUp();

    // Class 0 header followed by the all-objects header for the assigned type.
    REQUIRE(Exchange(t, "C1 16 3C 01 06 01 00 06") == "C1 81 80 00");
    REQUIRE(t.application->classAssignments.size() == 1);
    REQUIRE(t.application->classAssignments.front()
            == std::make_tuple(AssignClassType::BinaryInput, PointClass::Class0, 0, 4));

    // Assign class takes the same class headers, but not count qualifiers.
    REQUIRE(Exchange(t, "C2 16 3C 02 07 01") == "C2 81 80 01"); // FUNC_NOT_SUPPORTED
    REQUIRE(t.application->classAssignments.size() == 1);
}

TEST_CASE("ProfileClasses - ASSIGN_CLASS G1V0 accepts 8-bit start-stop",
          "[profile-classes][b09]")
{
    OutstationTestObject t(OutstationConfig(),
                           configure::by_count_of::binary_input(5));
    t.application->supportsAssignClass = true;
    t.LowerLayerUp();

    const auto cls = GENERATE(0, 1, 2, 3);
    const PointClass classes[] = {PointClass::Class0, PointClass::Class1, PointClass::Class2, PointClass::Class3};
    // FC22: G60V1..4/Q06, then G1V0/Q00, points 1 through 3.
    REQUIRE(Exchange(t, "C1 16 3C 0" + std::to_string(cls + 1) + " 06 01 00 00 01 03") == "C1 81 80 00");

    REQUIRE(t.application->classAssignments.size() == 1);
    REQUIRE(t.application->classAssignments.front()
            == std::make_tuple(AssignClassType::BinaryInput,
                               classes[cls], 1, 3));
}

TEST_CASE("ProfileClasses - ASSIGN_CLASS reports an incomplete trailing pair", "[profile-classes]")
{
    OutstationTestObject t(OutstationConfig(), configure::by_count_of::binary_input(2));
    t.application->supportsAssignClass = true;
    t.LowerLayerUp();

    REQUIRE(Exchange(t, "C1 16 3C 02 06") == "C1 81 80 04");
    REQUIRE(t.application->classAssignments.empty());
    REQUIRE(Exchange(t, "C2 16 3C 02 06 01 00 06 3C 03 06") == "C2 81 80 04");
    REQUIRE(t.application->classAssignments.size() == 1);
    REQUIRE(Exchange(t, "C3 16 3C 03 06 01 00 06") == "C3 81 80 00");
    REQUIRE(t.application->classAssignments.size() == 2);
}

TEST_CASE("ProfileClasses - ASSIGN_CLASS reports missing indexes inside a range", "[profile-classes]")
{
    const bool analog = GENERATE(false, true);
    OutstationConfig config;
    config.eventBufferConfig = EventBufferConfig::AllTypes(4);
    DatabaseConfig points;
    if (analog)
    {
        points.analog_input[255].evariation = EventAnalogVariation::Group32Var1;
        points.analog_input[257].evariation = EventAnalogVariation::Group32Var1;
    }
    else
    {
        points.double_binary[255].evariation = EventDoubleBinaryVariation::Group4Var1;
        points.double_binary[257].evariation = EventDoubleBinaryVariation::Group4Var1;
    }
    OutstationTestObject t(config, points);
    t.application->supportsAssignClass = true;
    t.LowerLayerUp();
    const std::string target = analog ? "1E 00 01 " : "03 00 01 ";

    // A range selecting only the hole must report PARAM_ERROR without notifying the application.
    REQUIRE(Exchange(t, "C0 16 3C 04 06 " + target + "00 01 00 01") == "C0 81 80 04");
    REQUIRE(t.application->classAssignments.empty());

    // Assign the two existing points to Class 3 and report that the range is incomplete.
    REQUIRE(Exchange(t, "C1 16 3C 04 06 " + target + "FF 00 01 01") == "C1 81 80 04");
    REQUIRE(t.application->classAssignments.size() == 1);
    REQUIRE(t.application->classAssignments.front()
            == std::make_tuple(analog ? AssignClassType::AnalogInput : AssignClassType::DoubleBinaryInput,
                               PointClass::Class3, 255, 257));
    t.Transaction([&](IUpdateHandler& db) {
        if (analog)
        {
            db.Update(Analog(11), 255, EventMode::Force);
            db.Update(Analog(12), 257, EventMode::Force);
        }
        else
        {
            db.Update(DoubleBitBinary(DoubleBit::DETERMINED_OFF), 255, EventMode::Force);
            db.Update(DoubleBitBinary(DoubleBit::DETERMINED_ON), 257, EventMode::Force);
        }
    });
    REQUIRE(Exchange(t, "C2 01 3C 02 06") == "C2 81 88 00");
    REQUIRE(Exchange(t, "C3 01 3C 04 06")
            == (analog ? "E3 81 80 00 20 01 28 02 00 FF 00 01 0B 00 00 00 01 01 01 0C 00 00 00"
                       : "E3 81 80 00 04 01 28 02 00 FF 00 41 01 01 81"));
}
