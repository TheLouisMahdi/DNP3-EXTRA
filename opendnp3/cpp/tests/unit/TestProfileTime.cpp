// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/parsing/APDUParser.h"
#include "dnp3mocks/MockLogHandler.h"
#include "master/TimeSyncHandler.h"
#include "utils/BufferHelpers.h"
#include "utils/OutstationTestObject.h"

#include <catch.hpp>

#include <string>

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

struct DelayResponse
{
    MockLogHandler log;

    bool Parse(const std::string& wire, uint16_t& delay)
    {
        HexSequence bytes(wire);
        TimeSyncHandler handler;
        auto result = APDUParser::Parse(bytes.ToRSeq(), handler, &log.logger);
        return (result == ParseResult::OK) && handler.GetTimeDelay(delay);
    }
};

// G50V1 absolute time 0x010203040506, least significant octet first on the wire.
const std::string absoluteTime = "06 05 04 03 02 01";
const std::string readTime = "32 01 07 01"; // Group 50 Var 1, qualifier 07, count 1
} // namespace

TEST_CASE("ProfileTime - G50V1 READ returns exactly one absolute time", "[profile-time]")
{
    OutstationTestObject t(OutstationConfig{});
    t.LowerLayerUp();
    t.application->SetTime(DNPTime(0x010203040506, TimestampQuality::SYNCHRONIZED));

    REQUIRE(Exchange(t, "C0 01") == "C0 81 80 00"); // consume the startup device-restart IIN
    REQUIRE(Exchange(t, "C1 01 " + readTime) == "C1 81 80 00 " + readTime + " " + absoluteTime);

    // The selection is consumed while writing the response: a blank READ afterwards selects nothing
    // and therefore returns no time object.
    REQUIRE(Exchange(t, "C2 01") == "C2 81 80 00");
}

TEST_CASE("ProfileTime - G50V1 READ rejects malformed qualifiers and counts without selecting time",
          "[profile-time]")
{
    OutstationTestObject t(OutstationConfig{});
    t.LowerLayerUp();
    t.application->SetTime(DNPTime(0x010203040506, TimestampQuality::SYNCHRONIZED));

    const std::string malformed[] = {
        "C1 01 32 01 08 00 01", // 16-bit count qualifier; the profile requires 07
        "C1 01 32 01 07 02",    // two values instead of one
        "C1 01 32 01 07 00",    // zero count
    };

    for (const auto& request : malformed)
    {
        REQUIRE(Exchange(t, request) == "C1 81 80 04"); // PARAM_ERROR and no object body
    }

    // An indexed header is a legal READ request, but the database has no index space behind the
    // time object, so it answers FUNC_NOT_SUPPORTED and selects nothing.
    REQUIRE(Exchange(t, "C1 01 32 01 17 01 00") == "C1 81 80 01");

    // A rejected READ leaves no pending selection for a later valid READ.
    REQUIRE(Exchange(t, "C2 01 " + readTime) == "C2 81 80 00 " + readTime + " " + absoluteTime);
}

TEST_CASE("ProfileTime - G50V1 WRITE accepts exactly one absolute time", "[profile-time]")
{
    OutstationTestObject t(OutstationConfig{});
    t.LowerLayerUp();

    REQUIRE(Exchange(t, "C1 02 " + readTime + " " + absoluteTime) == "C1 81 80 00");
    REQUIRE(t.application->timestamps.size() == 1);
    REQUIRE(t.application->timestamps.front().msSinceEpoch == 0x010203040506);
}

TEST_CASE("ProfileTime - G50V1 WRITE rejects truncated, duplicate and indexed bodies", "[profile-time]")
{
    OutstationTestObject t(OutstationConfig{});
    t.LowerLayerUp();

    REQUIRE(Exchange(t, "C1 02 " + readTime + " 06 05 04") == "C1 81 80 04"); // truncated value
    REQUIRE(t.application->timestamps.empty());

    // Only the first time header in a fragment is applied.
    REQUIRE(Exchange(t, "C2 02 " + readTime + " " + absoluteTime + " " + readTime + " " + absoluteTime)
            == "C2 81 80 04");
    REQUIRE(t.application->timestamps.size() == 1);

    REQUIRE(Exchange(t, "C3 02 32 01 17 01 00 " + absoluteTime) == "C3 81 80 04"); // indexed qualifier
    REQUIRE(t.application->timestamps.size() == 1);
}

TEST_CASE("ProfileTime - Master accepts exactly one fine time delay and rejects malformed bodies",
          "[profile-time]")
{
    DelayResponse response;
    uint16_t delay = 0;

    REQUIRE(response.Parse("34 02 07 01 0A 00", delay)); // Group 52 Var 2, qualifier 07, one value
    REQUIRE(delay == 10);

    const char* malformed[] = {
        "34 02 07 02 0A 00 0B 00", // two values
        "34 02 07 00",             // zero count
        "34 02 07 01 0A",          // truncated value
        "34 01 07 01 0A 00",       // coarse delay is a restart response, not a delay measurement
    };

    for (const char* wire : malformed)
    {
        uint16_t unchanged = 0xFFFF;
        REQUIRE_FALSE(response.Parse(wire, unchanged));
        REQUIRE(unchanged == 0xFFFF);
    }
}
