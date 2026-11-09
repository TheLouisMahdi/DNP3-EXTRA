// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "link/CRC.h"
#include "outstation/ControlState.h"
#include "utils/BufferHelpers.h"
#include "utils/CommandCallbackQueue.h"
#include "utils/MasterTestFixture.h"
#include "utils/OutstationTestObject.h"

#include <catch.hpp>
#include <array>
#include <sstream>
#include <string>

using namespace opendnp3;
namespace
{
std::string Byte(uint8_t value)
{
    const char* digits = "0123456789ABCDEF";
    return std::string(1, digits[value >> 4]) + digits[value & 15];
}
std::string Body(unsigned type, bool wide = false, uint8_t status = 0)
{
    const char* headers[] = {"0C 01 ", "29 01 ", "29 02 ", "29 03 "};
    const char* values[] = {"03 01 64 00 00 00 64 00 00 00 ", "64 00 00 00 ", "64 00 ", "00 00 C8 42 "};
    return std::string(headers[type]) + (wide ? "28 01 00 34 12 " : "17 01 03 ") + values[type] + Byte(status);
}
CommandSet Commands(unsigned type, uint16_t index)
{
    switch (type)
    {
    case 0: return CommandSet({WithIndex(ControlRelayOutputBlock(OperationType::LATCH_ON), index)});
    case 1: return CommandSet({WithIndex(AnalogOutputInt32(100), index)});
    case 2: return CommandSet({WithIndex(AnalogOutputInt16(100), index)});
    default: return CommandSet({WithIndex(AnalogOutputFloat32(100), index)});
    }
}
std::string Exchange(OutstationTestObject& outstation, const std::string& request)
{
    outstation.SendToOutstation(request);
    auto response = outstation.lower->PopWriteAsHex();
    if (!response.empty()) outstation.OnTxReady();
    return response;
}
MasterParams MasterConfig(bool wide)
{
    auto params = NoStartupTasks();
    params.controlQualifierMode = wide ? IndexQualifierMode::always_two_bytes : IndexQualifierMode::allow_one_byte;
    return params;
}
struct FC6RequiredCredentials final : IAuthenticationCredentials
{
    bool ReadUpdateKey(uint16_t association, uint16_t user, uint8_t* output, size_t capacity,
                       uint64_t& lifetime) override
    {
        if (association != 7 || user < 1 || user > 2 || !output || capacity != 32)
            return false;
        for (size_t i = 0; i < capacity; ++i)
            output[i] = static_cast<uint8_t>(user * 32 + i);
        lifetime = 10000000;
        return true;
    }
};
struct FC6RequiredAuthorization final : IAuthenticationAuthorization
{
    bool IsAuthorized(uint16_t association, uint16_t user, uint8_t, const uint8_t*, size_t) const override
    {
        return association == 7 && user >= 1 && user <= 2;
    }
};
MasterParams RequiredMasterConfig()
{
    auto params = MasterConfig(false);
    params.authentication.association = 7;
    params.authentication.credentials = std::make_shared<FC6RequiredCredentials>();
    params.authentication.authorization = std::make_shared<FC6RequiredAuthorization>();
    return params;
}
// Valid, different G41V1 commands with the same length and DNP3 CRC-16.
const std::string collisionA = "29 01 17 01 03 79 4D 00 00 00";
const std::string collisionB = "29 01 17 01 03 00 00 01 00 00";
}

TEST_CASE("ProfileControls - Outstation profile variations echo both index widths and all control functions",
          "[profile-controls]")
{
    for (unsigned type = 0; type < 4; ++type)
        for (bool wide : {false, true})
        {
            OutstationTestObject t(OutstationConfig{});
            t.LowerLayerUp();
            const auto body = Body(type, wide);
            REQUIRE(Exchange(t, "C0 03 " + body) == "C0 81 80 00 " + body);
            REQUIRE(t.cmdHandler->NumSelect() == 1);
            REQUIRE(t.cmdHandler->NumOperate() == 0);
            REQUIRE(Exchange(t, "C1 04 " + body) == "C1 81 80 00 " + body);
            REQUIRE(t.cmdHandler->NumOperate() == 1);
            REQUIRE(Exchange(t, "C2 05 " + body) == "C2 81 80 00 " + body);
            REQUIRE(t.cmdHandler->NumOperate() == 2);
            REQUIRE(Exchange(t, "C3 06 " + body).empty());
            REQUIRE(t.cmdHandler->NumOperate() == 3);
            REQUIRE(t.cmdHandler->numStart == t.cmdHandler->numEnd);
            const auto index = wide ? uint16_t(0x1234) : uint16_t(3);
            if (type == 0) REQUIRE(t.cmdHandler->crobOps.back().index == index);
            if (type == 1) REQUIRE(t.cmdHandler->aoInt32Ops.back().index == index);
            if (type == 2) REQUIRE(t.cmdHandler->aoInt16Ops.back().index == index);
            if (type == 3) REQUIRE(t.cmdHandler->aoFloat32Ops.back().index == index);
        }
}

TEST_CASE("ProfileControls - rejected excess SELECT objects cannot arm any OPERATE", "[profile-controls]")
{
    OutstationConfig config;
    config.params.maxControlsPerRequest = 1;
    for (bool wide : {false, true})
    {
        OutstationTestObject t(config);
        t.LowerLayerUp();
        const auto body = Body(0, wide) + " " + Body(1, wide);
        REQUIRE(Exchange(t, "C0 03 " + body) == "C0 81 80 00 " + Body(0, wide) + " " + Body(1, wide, 8));
        REQUIRE(t.cmdHandler->NumSelect() == 1);
        REQUIRE(Exchange(t, "C1 04 " + body) == "C1 81 80 00 " + Body(0, wide, 2) + " " + Body(1, wide, 8));
        REQUIRE(t.cmdHandler->NumOperate() == 0);
    }
}

TEST_CASE("ProfileControls - failed replacement SELECT cannot reuse the old selection", "[profile-controls]")
{
    for (unsigned type = 0; type < 4; ++type)
    {
        OutstationTestObject t(OutstationConfig{});
        t.LowerLayerUp();
        REQUIRE(Exchange(t, "C0 03 " + Body(type)) == "C0 81 80 00 " + Body(type));
        t.cmdHandler->SetResponse(CommandStatus::NOT_SUPPORTED);
        REQUIRE(Exchange(t, "C1 03 " + Body(type)) == "C1 81 80 04 " + Body(type, false, 4));
        t.cmdHandler->SetResponse(CommandStatus::SUCCESS);
        // Sequence 1 matched the old successful SELECT, not the failed replacement.
        REQUIRE(Exchange(t, "C1 04 " + Body(type)) == "C1 81 80 00 " + Body(type, false, 2));
        REQUIRE(t.cmdHandler->NumOperate() == 0);
    }
}

TEST_CASE("ProfileControls - intervening request cancels selection", "[profile-controls]")
{
    for (unsigned type = 0; type < 4; ++type)
    {
        OutstationTestObject t(OutstationConfig{});
        t.LowerLayerUp();
        Exchange(t, "C0 03 " + Body(type));
        REQUIRE(Exchange(t, "C8 01 3C 01 06") == "C8 81 80 00");
        REQUIRE(Exchange(t, "C1 04 " + Body(type)) == "C1 81 80 00 " + Body(type, false, 2));
        REQUIRE(t.cmdHandler->NumOperate() == 0);
    }
}

TEST_CASE("ProfileControls - changed same-sequence SELECT is discarded without replacing selection",
          "[profile-controls]")
{
    OutstationTestObject t(OutstationConfig{});
    t.LowerLayerUp();
    REQUIRE(Exchange(t, "C0 03 " + collisionA) == "C0 81 80 00 " + collisionA);
    REQUIRE(Exchange(t, "C0 03 " + collisionB).empty());
    REQUIRE(t.cmdHandler->NumSelect() == 1);
    REQUIRE(Exchange(t, "C1 04 " + collisionA) == "C1 81 80 00 " + collisionA);
    REQUIRE(t.cmdHandler->NumOperate() == 1);
    REQUIRE(t.cmdHandler->aoInt32Ops.back().value.value == 19833);
}

TEST_CASE("ProfileControls - exact SELECT retry does not restart the timer and timeout boundary is exclusive",
          "[profile-controls]")
{
    for (unsigned type = 0; type < 4; ++type)
    {
        OutstationConfig config;
        config.params.selectTimeout = TimeDuration::Milliseconds(5);
        OutstationTestObject t(config);
        t.LowerLayerUp();
        Exchange(t, "C0 03 " + Body(type));
        t.AdvanceTime(TimeDuration::Milliseconds(2));
        REQUIRE(Exchange(t, "C0 03 " + Body(type)) == "C0 81 80 00 " + Body(type));
        REQUIRE(t.cmdHandler->NumSelect() == 1);
        t.AdvanceTime(TimeDuration::Milliseconds(3));
        REQUIRE(Exchange(t, "C1 04 " + Body(type)) == "C1 81 80 00 " + Body(type, false, 1));
        REQUIRE(t.cmdHandler->NumOperate() == 0);
    }
}

TEST_CASE("ProfileControls - CRC collision cannot substitute a different OPERATE", "[profile-controls]")
{
    HexSequence first(collisionA), second(collisionB);
    REQUIRE(CRC::CalcCrc(first.ToRSeq()) == CRC::CalcCrc(second.ToRSeq()));
    OutstationTestObject t(OutstationConfig{});
    t.LowerLayerUp();
    Exchange(t, "C0 03 " + collisionA);
    REQUIRE(Exchange(t, "C1 04 " + collisionB) == "C1 81 80 00 29 01 17 01 03 00 00 01 00 02");
    REQUIRE(t.cmdHandler->NumOperate() == 0);
}

TEST_CASE("ProfileControls - repeat history compares bytes and exact direct OPERATE retry executes once",
          "[profile-controls]")
{
    OutstationTestObject t(OutstationConfig{});
    t.LowerLayerUp();
    REQUIRE(Exchange(t, "C0 05 " + collisionA) == "C0 81 80 00 " + collisionA);
    REQUIRE(Exchange(t, "C0 05 " + collisionB) == "C0 81 80 00 " + collisionB);
    REQUIRE(t.cmdHandler->NumOperate() == 2);
    REQUIRE(t.cmdHandler->aoInt32Ops.back().value.value == 65536);
    REQUIRE(Exchange(t, "C0 05 " + collisionB) == "C0 81 80 00 " + collisionB);
    REQUIRE(t.cmdHandler->NumOperate() == 2);
}

TEST_CASE("ProfileControls - OPERATE retry uses cached reply and a fresh SELECT can reuse an earlier sequence",
          "[profile-controls]")
{
    OutstationTestObject t(OutstationConfig{});
    t.LowerLayerUp();
    Exchange(t, "C0 03 " + Body(0));
    Exchange(t, "C1 04 " + Body(0));
    REQUIRE(Exchange(t, "C1 04 " + Body(0)) == "C1 81 80 00 " + Body(0));
    REQUIRE(t.cmdHandler->NumOperate() == 1);
    REQUIRE(Exchange(t, "C0 03 " + Body(1)) == "C0 81 80 00 " + Body(1));
    REQUIRE(t.cmdHandler->NumSelect() == 2);
    REQUIRE(Exchange(t, "C1 04 " + Body(1)) == "C1 81 80 00 " + Body(1));
    REQUIRE(t.cmdHandler->NumOperate() == 2);
}

TEST_CASE("ProfileControls - disconnect clears selection", "[profile-controls]")
{
    OutstationTestObject t(OutstationConfig{});
    t.LowerLayerUp();
    Exchange(t, "C0 03 " + Body(0));
    t.LowerLayerDown();
    t.LowerLayerUp();
    REQUIRE(Exchange(t, "C1 04 " + Body(0)) == "C1 81 80 00 " + Body(0, false, 2));
    REQUIRE(t.cmdHandler->NumOperate() == 0);
}

TEST_CASE("ProfileControls - command statuses and required IIN are delivered without execution on failed SELECT",
          "[profile-controls]")
{
    for (unsigned type = 0; type < 4; ++type)
        for (auto status : {CommandStatus::FORMAT_ERROR, CommandStatus::NOT_SUPPORTED, CommandStatus::ALREADY_ACTIVE,
                            CommandStatus::LOCAL, CommandStatus::NOT_AUTHORIZED, CommandStatus::OUT_OF_RANGE})
        {
            OutstationTestObject t(OutstationConfig{});
            t.LowerLayerUp();
            t.cmdHandler->SetResponse(status);
            const auto iin = status == CommandStatus::NOT_SUPPORTED ? "04" : status == CommandStatus::ALREADY_ACTIVE ? "10" : "00";
            REQUIRE(Exchange(t, "C0 03 " + Body(type)) == std::string("C0 81 80 ") + iin + " "
                    + Body(type, false, CommandStatusSpec::to_type(status)));
            t.cmdHandler->SetResponse(CommandStatus::SUCCESS);
            REQUIRE(Exchange(t, "C1 04 " + Body(type)) == "C1 81 80 00 " + Body(type, false, 2));
            REQUIRE(t.cmdHandler->NumOperate() == 0);
        }
}

TEST_CASE("ProfileControls - malformed or empty requests do not partially invoke callbacks", "[profile-controls]")
{
    for (uint8_t function : {uint8_t(3), uint8_t(4), uint8_t(5), uint8_t(6)})
        for (const auto& bad : {std::string(), Body(0) + " 29 01 17 01 03 64 00 00 00",
             std::string("29 01 17 00"), std::string("29 01 00 00 00 64 00 00 00 00"), std::string("29 00 17 01 03")})
        {
            OutstationTestObject t(OutstationConfig{});
            t.LowerLayerUp();
            const auto response = Exchange(t, "C0 " + Byte(function) + " " + bad);
            REQUIRE(response == (function == 6 ? "" : "C0 81 80 04"));
            REQUIRE(t.cmdHandler->NumInvocations() == 0);
            REQUIRE(t.cmdHandler->numStart == 0);
            REQUIRE(t.cmdHandler->numEnd == 0);
        }
}

TEST_CASE("ProfileControls - Master native SBO works for every profile variation and index width", "[profile-controls]")
{
    for (unsigned type = 0; type < 4; ++type)
        for (bool wide : {false, true})
        {
            MasterTestFixture t(MasterConfig(wide));
            CommandCallbackQueue callbacks;
            REQUIRE(t.context->OnLowerLayerUp());
            t.context->SelectAndOperate(Commands(type, wide ? 0x1234 : 3), callbacks.Callback(), TaskConfig::Default());
            t.exe->run_many();
            REQUIRE(t.lower->PopWriteAsHex() == "C0 03 " + Body(type, wide));
            REQUIRE(t.context->OnTxReady());
            REQUIRE(t.SendToMaster("C0 81 00 00 " + Body(type, wide)));
            t.exe->run_many();
            REQUIRE(t.lower->PopWriteAsHex() == "C1 04 " + Body(type, wide));
            REQUIRE(t.context->OnTxReady());
            REQUIRE(t.SendToMaster("C1 81 00 00 " + Body(type, wide)));
            REQUIRE(callbacks.values.size() == 1);
            REQUIRE(callbacks.values.front().summary == TaskCompletion::SUCCESS);
            REQUIRE(callbacks.values.front().results[0].state == CommandPointState::SUCCESS);
            REQUIRE(callbacks.values.front().results[0].status == CommandStatus::SUCCESS);
            REQUIRE(t.lower->HasNoData());
        }
}

TEST_CASE("ProfileControls - Master rejects error IIN even when SELECT bytes match", "[profile-controls]")
{
    for (unsigned type = 0; type < 4; ++type)
        for (uint8_t error : {uint8_t(1), uint8_t(2), uint8_t(4), uint8_t(16)})
        {
            MasterTestFixture t(MasterConfig(false));
            CommandCallbackQueue callbacks;
            t.context->OnLowerLayerUp();
            t.context->SelectAndOperate(Commands(type, 3), callbacks.Callback(), TaskConfig::Default());
            t.exe->run_many();
            REQUIRE(t.lower->PopWriteAsHex() == "C0 03 " + Body(type));
            REQUIRE(t.context->OnTxReady());
            REQUIRE(t.SendToMaster("C0 81 00 " + Byte(error) + " " + Body(type)));
            t.exe->run_many();
            REQUIRE(t.lower->HasNoData());
            REQUIRE(callbacks.values.size() == 1);
            REQUIRE(callbacks.values.front().summary == TaskCompletion::FAILURE_BAD_RESPONSE);
        }
}

TEST_CASE("ProfileControls - Master rejects extra or truncated response objects", "[profile-controls]")
{
    for (bool extra : {false, true})
    {
        MasterTestFixture t(MasterConfig(false));
        CommandCallbackQueue callbacks;
        t.context->OnLowerLayerUp();
        t.context->SelectAndOperate(Commands(0, 3), callbacks.Callback(), TaskConfig::Default());
        t.exe->run_many();
        REQUIRE(t.lower->PopWriteAsHex() == "C0 03 " + Body(0));
        REQUIRE(t.context->OnTxReady());
        const auto payload = extra ? Body(0) + " " + Body(0) : Body(0).substr(0, Body(0).size() - 3);
        REQUIRE(t.SendToMaster("C0 81 00 00 " + payload));
        t.exe->run_many();
        REQUIRE(t.lower->HasNoData());
        REQUIRE(callbacks.values.size() == 1);
        REQUIRE(callbacks.values.front().summary == TaskCompletion::FAILURE_BAD_RESPONSE);
    }
}

TEST_CASE("ProfileControls - Master compares floating-point SELECT echo bits including signed zero", "[profile-controls]")
{
    MasterTestFixture t(MasterConfig(false));
    CommandCallbackQueue callbacks;
    t.context->OnLowerLayerUp();
    t.context->SelectAndOperate(CommandSet({WithIndex(AnalogOutputFloat32(-0.0f), 3)}), callbacks.Callback(), TaskConfig::Default());
    t.exe->run_many();
    REQUIRE(t.lower->PopWriteAsHex() == "C0 03 29 03 17 01 03 00 00 00 80 00");
    REQUIRE(t.context->OnTxReady());
    REQUIRE(t.SendToMaster("C0 81 00 00 29 03 17 01 03 00 00 00 00 00"));
    t.exe->run_many();
    REQUIRE(t.lower->HasNoData());
    REQUIRE(callbacks.values.size() == 1);
    REQUIRE(callbacks.values.front().results[0].state == CommandPointState::SELECT_MISMATCH);
}

TEST_CASE("ProfileControls - Master compares raw CROB operation bytes", "[profile-controls]")
{
    MasterTestFixture t(MasterConfig(false));
    CommandCallbackQueue callbacks;
    t.context->OnLowerLayerUp();
    t.context->SelectAndOperate(CommandSet({WithIndex(ControlRelayOutputBlock(uint8_t(7)), 3)}), callbacks.Callback(), TaskConfig::Default());
    t.exe->run_many();
    REQUIRE(t.lower->PopWriteAsHex() == "C0 03 0C 01 17 01 03 07 01 64 00 00 00 64 00 00 00 00");
    REQUIRE(t.context->OnTxReady());
    REQUIRE(t.SendToMaster("C0 81 00 00 0C 01 17 01 03 08 01 64 00 00 00 64 00 00 00 00"));
    t.exe->run_many();
    REQUIRE(t.lower->HasNoData());
    REQUIRE(callbacks.values.size() == 1);
    REQUIRE(callbacks.values.front().results[0].state == CommandPointState::SELECT_MISMATCH);
}

TEST_CASE("ProfileControls - Master returns failed SELECT statuses and never sends OPERATE", "[profile-controls]")
{
    for (unsigned type = 0; type < 4; ++type)
    {
        MasterTestFixture t(MasterConfig(false));
        CommandCallbackQueue callbacks;
        t.context->OnLowerLayerUp();
        t.context->SelectAndOperate(Commands(type, 3), callbacks.Callback(), TaskConfig::Default());
        t.exe->run_many();
        t.lower->PopWriteAsHex();
        REQUIRE(t.context->OnTxReady());
        REQUIRE(t.SendToMaster("C0 81 00 00 " + Body(type, false, 9)));
        t.exe->run_many();
        REQUIRE(t.lower->HasNoData());
        REQUIRE(callbacks.values.size() == 1);
        REQUIRE(callbacks.values.front().results[0].state == CommandPointState::SELECT_FAIL);
        REQUIRE(callbacks.values.front().results[0].status == CommandStatus::NOT_AUTHORIZED);
    }
}

TEST_CASE("ProfileControls - Master command timeout does not retry control execution", "[profile-controls]")
{
    for (unsigned stage = 0; stage < 3; ++stage)
    {
        auto params = MasterConfig(false);
        params.maxApplicationRetries = 5;
        params.responseTimeout = TimeDuration::Milliseconds(10);
        MasterTestFixture t(params);
        CommandCallbackQueue callbacks;
        t.context->OnLowerLayerUp();
        if (stage == 0) t.context->DirectOperate(Commands(2, 3), callbacks.Callback(), TaskConfig::Default());
        else t.context->SelectAndOperate(Commands(2, 3), callbacks.Callback(), TaskConfig::Default());
        t.exe->run_many();
        REQUIRE(t.lower->PopWriteAsHex() == std::string(stage == 0 ? "C0 05 " : "C0 03 ") + Body(2));
        REQUIRE(t.context->OnTxReady());

        if (stage == 2)
        {
            REQUIRE(t.SendToMaster("C0 81 00 00 " + Body(2)));
            t.exe->run_many();
            REQUIRE(t.lower->PopWriteAsHex() == "C1 04 " + Body(2));
            REQUIRE(t.context->OnTxReady());
        }

        t.exe->advance_time(params.responseTimeout.value);
        t.exe->run_many();
        REQUIRE(callbacks.values.size() == 1);
        REQUIRE(callbacks.values.front().summary == TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
        REQUIRE(t.lower->HasNoData());
        t.exe->advance_time(params.responseTimeout.value);
        t.exe->run_many();
        REQUIRE(t.lower->HasNoData());
        REQUIRE(callbacks.values.size() == 1);
    }
}

TEST_CASE("ProfileControls - Master FC6 sends typed commands once and completes only on transmit readiness",
          "[fc6-master][profile-controls]")
{
    for (unsigned type = 0; type < 4; ++type)
        for (bool wide : {false, true})
        {
            auto params = MasterConfig(wide);
            params.maxApplicationRetries = 5;
            MasterTestFixture t(params);
            CommandCallbackQueue callbacks;
            REQUIRE(t.context->OnLowerLayerUp());
            REQUIRE(t.context->DirectOperateNoAck(Commands(type, wide ? 0x1234 : 3), callbacks.Callback(),
                                                  TaskConfig::Default()));
            t.exe->run_many();
            REQUIRE(t.lower->PopWriteAsHex() == "C0 06 " + Body(type, wide));
            REQUIRE(callbacks.values.empty());
            REQUIRE(t.context->OnTxReady());
            t.exe->run_many();
            REQUIRE(callbacks.values.size() == 1);
            REQUIRE(callbacks.values.front().summary == TaskCompletion::SUCCESS);
            REQUIRE(callbacks.values.front().results[0].status == CommandStatus::UNDEFINED);
            REQUIRE(t.lower->HasNoData());

            t.context->SelectAndOperate(Commands(type, wide ? 0x1234 : 3), callbacks.Callback(),
                                        TaskConfig::Default());
            t.exe->run_many();
            REQUIRE(t.lower->PopWriteAsHex() == "C1 03 " + Body(type, wide));
            REQUIRE(t.context->OnTxReady());
            REQUIRE(t.SendToMaster("C1 81 00 00 " + Body(type, wide)));
            t.exe->run_many();
            REQUIRE(t.lower->PopWriteAsHex() == "C2 04 " + Body(type, wide));
            REQUIRE(t.context->OnTxReady());
            REQUIRE(t.SendToMaster("C2 81 00 00 " + Body(type, wide)));
            t.exe->run_many();
            REQUIRE(callbacks.values.size() == 2);
            REQUIRE(callbacks.values.back().results[0].status == CommandStatus::SUCCESS);
        }
}

TEST_CASE("ProfileControls - Master FC6 sequence wraps without retries and preserves following SBO sequence",
          "[fc6-master][profile-controls]")
{
    auto params = MasterConfig(false);
    params.responseTimeout = TimeDuration::Milliseconds(10);
    MasterTestFixture t(params);
    CommandCallbackQueue callbacks;
    REQUIRE(t.context->OnLowerLayerUp());

    for (unsigned request = 0; request < 17; ++request)
    {
        const auto seq = static_cast<uint8_t>(request & 0x0F);
        const char* hex = "0123456789ABCDEF";
        REQUIRE(t.context->DirectOperateNoAck(Commands(0, 3), callbacks.Callback(), TaskConfig::Default()));
        t.exe->run_many();
        REQUIRE(t.lower->PopWriteAsHex() == std::string("C") + hex[seq] + " 06 " + Body(0));
        REQUIRE(t.lower->HasNoData());
        REQUIRE(callbacks.values.size() == request);

        REQUIRE(t.context->OnTxReady());
        REQUIRE(callbacks.values.size() == request + 1);
        REQUIRE(callbacks.values.back().summary == TaskCompletion::SUCCESS);
        REQUIRE(callbacks.values.back().results.size() == 1);
        REQUIRE(callbacks.values.back().results[0].status == CommandStatus::UNDEFINED);
        t.exe->run_many();
        REQUIRE(t.lower->HasNoData());
        REQUIRE(callbacks.values.size() == request + 1);
        t.exe->advance_time(params.responseTimeout.value);
        t.exe->run_many();
        REQUIRE(t.lower->HasNoData());
        REQUIRE(callbacks.values.size() == request + 1);
    }

    t.context->SelectAndOperate(Commands(0, 3), callbacks.Callback(), TaskConfig::Default());
    t.exe->run_many();
    REQUIRE(t.lower->PopWriteAsHex() == "C1 03 " + Body(0));
    REQUIRE(t.context->OnTxReady());
    REQUIRE(t.SendToMaster("C1 81 00 00 " + Body(0)));
    t.exe->run_many();
    REQUIRE(t.lower->PopWriteAsHex() == "C2 04 " + Body(0));
    REQUIRE(t.context->OnTxReady());
    REQUIRE(t.SendToMaster("C2 81 00 00 " + Body(0)));
    t.exe->run_many();
    REQUIRE(callbacks.values.size() == 18);
    REQUIRE(callbacks.values.back().summary == TaskCompletion::SUCCESS);
    REQUIRE(callbacks.values.back().results[0].status == CommandStatus::SUCCESS);
    REQUIRE(t.lower->HasNoData());
}

TEST_CASE("ProfileControls - Master FC6 transmit timeout does not retry or report operation success",
          "[fc6-master][profile-controls]")
{
    auto params = MasterConfig(false);
    params.responseTimeout = TimeDuration::Milliseconds(10);
    MasterTestFixture t(params);
    CommandCallbackQueue callbacks;
    REQUIRE(t.context->OnLowerLayerUp());
    REQUIRE(t.context->DirectOperateNoAck(Commands(0, 3), callbacks.Callback(), TaskConfig::Default()));
    t.exe->run_many();
    REQUIRE(t.lower->PopWriteAsHex() == "C0 06 " + Body(0));
    REQUIRE(callbacks.values.empty());

    t.exe->advance_time(params.responseTimeout.value);
    t.exe->run_many();
    REQUIRE(callbacks.values.size() == 1);
    REQUIRE(callbacks.values.front().summary == TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    REQUIRE(callbacks.values.front().results[0].status == CommandStatus::UNDEFINED);
    REQUIRE(t.lower->HasNoData());
    t.exe->advance_time(params.responseTimeout.value);
    t.exe->run_many();
    REQUIRE(callbacks.values.size() == 1);
    REQUIRE(t.lower->HasNoData());
}

TEST_CASE("ProfileControls - Master FC6 disconnect reports failure before transmit completion",
          "[fc6-master][profile-controls]")
{
    MasterTestFixture t(MasterConfig(false));
    CommandCallbackQueue callbacks;
    REQUIRE(t.context->OnLowerLayerUp());
    REQUIRE(t.context->DirectOperateNoAck(Commands(1, 3), callbacks.Callback(), TaskConfig::Default()));
    t.exe->run_many();
    REQUIRE(t.lower->PopWriteAsHex() == "C0 06 " + Body(1));
    REQUIRE(callbacks.values.empty());

    REQUIRE(t.context->OnLowerLayerDown());
    REQUIRE(callbacks.values.size() == 1);
    REQUIRE(callbacks.values.front().summary == TaskCompletion::FAILURE_NO_COMMS);
    REQUIRE(callbacks.values.front().results[0].status == CommandStatus::UNDEFINED);
}

TEST_CASE("ProfileControls - REQUIRED FC6 admission does not bypass startup session authentication", "[fc6-master][profile-controls]")
{
    MasterTestFixture t(RequiredMasterConfig());
    CommandCallbackQueue callbacks;
    REQUIRE(t.context->params.authentication.mode == AuthenticationConfig::Mode::REQUIRED);
    REQUIRE(t.context->OnLowerLayerUp());
    REQUIRE(t.context->DirectOperateNoAck(Commands(0, 3), callbacks.Callback(), TaskConfig::Default()));
    REQUIRE(callbacks.values.empty());

    t.exe->run_many();
    REQUIRE(callbacks.values.empty());
    while (!t.lower->HasNoData())
    {
        std::istringstream apdu(t.lower->PopWriteAsHex());
        std::string control;
        std::string function;
        if (apdu >> control >> function)
            REQUIRE(function != "06");
    }
}

TEST_CASE("ProfileControls - bounded selection owns its bytes and handles sequence wrap", "[profile-controls]")
{
    std::array<uint8_t, 4> bytes{{1, 2, 3, 4}};
    const std::array<uint8_t, 4> original{{1, 2, 3, 4}};
    ControlState control(bytes.size());
    const Timestamp now;
    const auto selected = ser4cpp::rseq_t(original.data(), original.size());
    control.Select(AppSeqNum(15), now, ser4cpp::rseq_t(bytes.data(), bytes.size()));
    bytes[0] = 99; // Transport storage is reusable immediately after SELECT returns.
    REQUIRE(control.IsSelectSequence(AppSeqNum(15)));
    REQUIRE_FALSE(control.IsSelectSequence(AppSeqNum(0)));
    REQUIRE(control.OnRequest(FunctionCode::SELECT, AppSeqNum(15), selected));
    REQUIRE(control.ValidateSelection(AppSeqNum(0), now, TimeDuration::Seconds(1), selected) == CommandStatus::SUCCESS);
    const std::array<uint8_t, 5> oversized{{1, 2, 3, 4, 5}};
    control.Select(AppSeqNum(0), now, ser4cpp::rseq_t(oversized.data(), oversized.size()));
    REQUIRE_FALSE(control.IsSelectSequence(AppSeqNum(0)));
    REQUIRE(control.ValidateSelection(AppSeqNum(1), now, TimeDuration::Seconds(1), selected) == CommandStatus::NO_SELECT);
}

TEST_CASE("ProfileControls - Master direct response rejects extra headers and reports changed raw command fields",
          "[profile-controls]")
{
    for (bool extra : {false, true})
    {
        MasterTestFixture t(MasterConfig(false));
        CommandCallbackQueue callbacks;
        t.context->OnLowerLayerUp();
        t.context->DirectOperate(CommandSet({WithIndex(ControlRelayOutputBlock(uint8_t(7)), 3)}), callbacks.Callback(), TaskConfig::Default());
        t.exe->run_many();
        REQUIRE(t.lower->PopWriteAsHex() == "C0 05 0C 01 17 01 03 07 01 64 00 00 00 64 00 00 00 00");
        REQUIRE(t.context->OnTxReady());
        const auto response = std::string("0C 01 17 01 03 08 01 64 00 00 00 64 00 00 00 00")
            + (extra ? " " + Body(1) : "");
        REQUIRE(t.SendToMaster("C0 81 00 00 " + response));
        t.exe->run_many();
        REQUIRE(t.lower->HasNoData());
        REQUIRE(callbacks.values.size() == 1);
        REQUIRE(callbacks.values.front().results[0].state == CommandPointState::OPERATE_FAIL);
        if (extra) REQUIRE(callbacks.values.front().summary == TaskCompletion::FAILURE_BAD_RESPONSE);
    }
}

namespace
{
std::string ReadCommandEvents(OutstationTestObject& outstation, const std::string& request)
{
    const auto response = Exchange(outstation, request);
    if (!response.empty() && response.front() == 'E')
        outstation.SendToOutstation("C" + response.substr(1, 1) + " 00");
    return response;
}

OutstationConfig CommandEventBuffers()
{
    OutstationConfig config;
    config.eventBufferConfig.maxBinaryCommandEvents = 2;
    config.eventBufferConfig.maxAnalogCommandEvents = 2;
    return config;
}
}

TEST_CASE("ProfileControls - G13 reports processed commands without duplicating retries", "[command-events]")
{
    DatabaseConfig database;
    database.binary_command_event[3];
    OutstationTestObject t(CommandEventBuffers(), database);
    t.application->SetTime(DNPTime(0x010203040506));
    t.LowerLayerUp();
    const auto crob = Body(0, false);

    REQUIRE_FALSE(Exchange(t, "C0 03 " + crob).empty());
    REQUIRE(ReadCommandEvents(t, "C1 01 0D 00 06") == "C1 81 80 00"); // successful SELECT alone
    REQUIRE_FALSE(Exchange(t, "C2 03 " + crob).empty());
    const auto operate = Exchange(t, "C3 04 " + crob);
    REQUIRE_FALSE(operate.empty());
    REQUIRE(Exchange(t, "C3 04 " + crob) == operate);
    REQUIRE(t.cmdHandler->NumOperate() == 1);
    REQUIRE(ReadCommandEvents(t, "C4 01 0D 00 06") == "E4 81 80 00 0D 02 28 01 00 03 00 80 06 05 04 03 02 01");

    t.cmdHandler->SetResponse(CommandStatus::NOT_SUPPORTED);
    REQUIRE_FALSE(Exchange(t, "C5 03 " + crob).empty());
    REQUIRE(ReadCommandEvents(t, "C6 01 0D 01 07 01") == "E6 81 80 00 0D 01 28 01 00 03 00 84");
    REQUIRE(ReadCommandEvents(t, "C7 01 0D 02 08 01 00") == "C7 81 80 00");
    REQUIRE(ReadCommandEvents(t, "C8 01 0B 00 06") == "C8 81 80 00"); // independent of output status
}

TEST_CASE("ProfileControls - FC6 reports once and G12 class assignment changes future command events", "[command-events]")
{
    DatabaseConfig database;
    database.binary_command_event[3].withTime = false;
    OutstationTestObject t(CommandEventBuffers(), database);
    t.application->supportsAssignClass = true;
    t.LowerLayerUp();
    const auto crob = Body(0, false);

    REQUIRE(Exchange(t, "C0 16 3C 03 06 0C 00 00 03 03") == "C0 81 80 00");
    REQUIRE(t.application->classAssignments.size() == 1);
    REQUIRE(std::get<0>(t.application->classAssignments.front()) == AssignClassType::BinaryCommandEvent);
    REQUIRE(Exchange(t, "C1 06 " + crob).empty());
    REQUIRE(Exchange(t, "C1 06 " + crob).empty());
    REQUIRE(Exchange(t, "C2 06 " + crob + " 0C 01 17 01 03").empty()); // truncated second object
    REQUIRE(t.cmdHandler->NumOperate() == 1);
    REQUIRE(ReadCommandEvents(t, "C3 01 3C 02 06") == "C3 81 84 00");
    REQUIRE(ReadCommandEvents(t, "C4 01 3C 03 06") == "E4 81 80 00 0D 01 28 01 00 03 00 80");
    REQUIRE(ReadCommandEvents(t, "C5 01 3C 03 06") == "C5 81 80 00");
}

TEST_CASE("ProfileControls - G43 preserves commanded values and status in all wire variations", "[command-events]")
{
    DatabaseConfig database;
    database.analog_command_event[0x1234].clazz = PointClass::Class2;
    OutstationTestObject t(CommandEventBuffers(), database);
    t.application->SetTime(DNPTime(0x010203040506));
    t.LowerLayerUp();
    t.cmdHandler->SetResponse(CommandStatus::NOT_SUPPORTED);

    struct Example { unsigned commandType; unsigned variation; const char* payload; };
    const Example examples[] = {
        {1, 1, "64 00 00 00"}, {2, 2, "64 00"},
        {1, 3, "64 00 00 00 06 05 04 03 02 01"}, {2, 4, "64 00 06 05 04 03 02 01"},
        {3, 5, "00 00 C8 42"}, {3, 6, "00 00 00 00 00 00 59 40"},
        {3, 7, "00 00 C8 42 06 05 04 03 02 01"}, {3, 8, "00 00 00 00 00 00 59 40 06 05 04 03 02 01"}
    };
    unsigned seq = 0;
    for (const auto& example : examples)
    {
        const auto command = Byte(0xC0 + seq++);
        const auto query = Byte(0xC0 + seq);
        const auto response = Byte(0xE0 + seq++);
        REQUIRE_FALSE(Exchange(t, command + " 05 " + Body(example.commandType, true)).empty());
        const std::string qualifier = example.variation % 3 == 0 ? " 06"
            : example.variation % 3 == 1 ? " 07 01" : " 08 01 00";
        REQUIRE(ReadCommandEvents(t, query + " 01 2B " + Byte(example.variation) + qualifier)
                == response + " 81 80 00 2B " + Byte(example.variation) + " 28 01 00 34 12 04 " + example.payload);
    }
}

TEST_CASE("ProfileControls - command event buffer bounds and default-off operation", "[command-events]")
{
    DatabaseConfig database;
    database.binary_command_event[3].withTime = false;
    auto config = CommandEventBuffers();
    config.eventBufferConfig.maxBinaryCommandEvents = 1;
    OutstationTestObject t(config, database);
    t.LowerLayerUp();
    REQUIRE_FALSE(Exchange(t, "C0 05 " + Body(0, false)).empty());
    t.cmdHandler->SetResponse(CommandStatus::NOT_SUPPORTED);
    REQUIRE_FALSE(Exchange(t, "C1 05 " + Body(0, false)).empty());
    const auto event = ReadCommandEvents(t, "C2 01 0D 00 06");
    REQUIRE(event == "E2 81 80 08 0D 01 28 01 00 03 00 84");
    REQUIRE(ReadCommandEvents(t, "C3 01 0D 00 06") == "C3 81 80 00");

    OutstationTestObject off(config);
    off.LowerLayerUp();
    REQUIRE_FALSE(Exchange(off, "C0 05 " + Body(0, false)).empty());
    REQUIRE(ReadCommandEvents(off, "C1 01 0D 00 06") == "C1 81 80 00");
}

TEST_CASE("ProfileControls - command events use native unsolicited retries and confirmation", "[command-events]")
{
    DatabaseConfig database;
    database.binary_command_event[3].withTime = false;
    auto config = CommandEventBuffers();
    config.params.allowUnsolicited = true;
    config.params.unsolClassMask = ClassField::AllEventClasses();
    config.params.unsolConfirmTimeout = TimeDuration::Seconds(5);
    config.params.numUnsolRetries = NumRetries::Fixed(1);
    OutstationTestObject t(config, database);
    t.LowerLayerUp();
    REQUIRE(t.lower->PopWriteAsHex() == "F0 82 80 00");
    t.OnTxReady();
    t.SendToOutstation("D0 00");

    t.SendToOutstation("C0 06 " + Body(0, false));
    const std::string event = "F1 82 80 00 0D 01 28 01 00 03 00 80";
    REQUIRE(t.lower->PopWriteAsHex() == event); // FC6 has no solicited response.
    t.OnTxReady();
    REQUIRE(t.AdvanceTime(TimeDuration::Seconds(5)));
    REQUIRE(t.lower->PopWriteAsHex() == event);
    t.OnTxReady();
    t.SendToOutstation("D1 00");
    REQUIRE(ReadCommandEvents(t, "C1 01 0D 00 06") == "C1 81 80 00");
    REQUIRE(t.cmdHandler->NumOperate() == 1);
}
