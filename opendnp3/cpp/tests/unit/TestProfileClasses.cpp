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

TEST_CASE("ProfileClasses - ENABLE_UNSOLICITED arms and DISABLE_UNSOLICITED clears class 1", "[profile-classes]")
{
    OutstationConfig cfg;
    cfg.params.allowUnsolicited = true;
    cfg.eventBufferConfig = EventBufferConfig(5);
    OutstationTestObject t(cfg, configure::by_count_of::binary_input(5));
    t.LowerLayerUp();

    REQUIRE(t.lower->PopWriteAsHex() == hex::NullUnsolicited(0));
    t.OnTxReady();
    t.SendToOutstation(hex::UnsolConfirm(0));

    // Class 1 is not armed yet, so the event is not solicited.
    t.Transaction([](IUpdateHandler& db) { db.Update(Binary(false, Flags(0x01)), 0); });
    REQUIRE(t.lower->PopWriteAsHex().empty());

    // Arming class 1 reports the pending event.
    REQUIRE(Exchange(t, "C1 14 3C 02 06") == "C1 81 82 00");
    REQUIRE(t.lower->PopWriteAsHex() == "F1 82 80 00 02 01 28 01 00 00 00 01");
    t.OnTxReady();
    t.SendToOutstation(hex::UnsolConfirm(1));

    // Disarming class 1 stops further unsolicited data.
    REQUIRE(Exchange(t, "C2 15 3C 02 06") == "C2 81 80 00");
    t.Transaction([](IUpdateHandler& db) { db.Update(Binary(true, Flags(0x01)), 1); });
    REQUIRE(t.lower->PopWriteAsHex().empty());
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
