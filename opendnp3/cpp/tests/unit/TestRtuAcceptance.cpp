// Licensed under the Apache License, Version 2.0.
#include "dnp3mocks/MockSOEHandler.h"
#include "master/MeasurementHandler.h"
#include "master/TimeSyncHandler.h"
#include "utils/BufferHelpers.h"
#include "utils/AcceptanceObservation.h"
#include "utils/OutstationTestObject.h"
#include "utils/LinkLayerTest.h"
#include "utils/CommandCallbackQueue.h"
#include "utils/MasterTestFixture.h"
#include "transport/TransportRx.h"
#include "transport/TransportTx.h"

#include <ser4cpp/util/HexConversions.h>

#include <catch.hpp>

#include <algorithm>
#include <vector>
#include "app/parsing/APDUParser.h"

#include <string>

using namespace opendnp3;
using acceptance::Observe;
using acceptance::Selected;

namespace
{
constexpr uint64_t sampleTime = 0x010203040506;

void CheckFrame(const std::string& name, const std::string& actual, const char* expected)
{
    const HexSequence bytes(actual);
    const auto data = bytes.ToRSeq();
    Observe(name + "_length", data.length());
    REQUIRE(data.length() == HexSequence(expected).ToRSeq().length());
    for (size_t offset = 0; offset < data.length(); offset += 6)
    {
        uint64_t chunk = 0;
        for (size_t i = offset; i < offset + 6 && i < data.length(); ++i)
            chunk = (chunk << 8) | data[i];
        Observe(name + "_bytes_" + std::to_string(offset), chunk);
    }
    REQUIRE(actual == expected);
}

std::string Request(OutstationTestObject& t, const char* frame)
{
    t.SendToOutstation(frame);
    auto response = t.lower->PopWriteAsHex();
    if (!response.empty())
        t.OnTxReady();
    return response;
}

void Decode(const std::string& reply, MockSOEHandler& soe, bool unsolicited = false)
{
    const HexSequence bytes(reply);
    MockLogHandler log;
    const auto result = MeasurementHandler::ProcessMeasurements(ResponseInfo(unsolicited, true, true),
                                                               bytes.ToRSeq().skip(4), log.logger, &soe);
    Observe("parser_ok", result == ParseResult::OK);
    REQUIRE(result == ParseResult::OK);
}

struct Point
{
    uint16_t index;
    int32_t value;
    uint8_t flags;
};

DatabaseConfig Points(unsigned group, unsigned variation, std::initializer_list<Point> points)
{
    DatabaseConfig config;
    for (const auto& point : points)
    {
        switch (group)
        {
        case 1: config.binary_input[point.index].svariation = static_cast<StaticBinaryVariation>(variation - 1); break;
        case 2: config.binary_input[point.index].evariation = static_cast<EventBinaryVariation>(variation - 1); break;
        case 3: config.double_binary[point.index].svariation = (variation == 1 ? StaticDoubleBinaryVariation::Group3Var1 : StaticDoubleBinaryVariation::Group3Var2); break;
        case 4: config.double_binary[point.index].evariation = static_cast<EventDoubleBinaryVariation>(variation - 1); break;
        case 10: config.binary_output_status[point.index].svariation = StaticBinaryOutputStatusVariation::Group10Var2; break;
        case 30: config.analog_input[point.index].svariation = static_cast<StaticAnalogVariation>(variation - 1); break;
        case 32: config.analog_input[point.index].evariation = static_cast<EventAnalogVariation>(variation - 1); break;
        case 40: config.analog_output_status[point.index].svariation = static_cast<StaticAnalogOutputStatusVariation>(variation - 1); break;
        default: FAIL("Unsupported measurement group");
        }
    }
    return config;
}

void Update(OutstationTestObject& t, unsigned group, std::initializer_list<Point> points, bool event,
            TimestampQuality quality = TimestampQuality::SYNCHRONIZED, uint64_t stride = 1)
{
    t.Transaction([&](IUpdateHandler& db) {
        uint64_t stamp = sampleTime;
        for (const auto& p : points)
        {
            const auto mode = event ? EventMode::Force : EventMode::Suppress;
            const auto flags = Flags(p.flags);
            const auto time = DNPTime(stamp, quality);
            stamp += stride;
            switch (group)
            {
            case 1: case 2: db.Update(Binary(p.value != 0, flags, time), p.index, mode); break;
            case 3: case 4: db.Update(DoubleBitBinary(static_cast<DoubleBit>(p.value), flags, time), p.index, mode); break;
            case 10: db.Update(BinaryOutputStatus(p.value != 0, flags), p.index, mode); break;
            case 30: case 32: db.Update(Analog(p.value, flags, time), p.index, mode); break;
            case 40: db.Update(AnalogOutputStatus(p.value, flags), p.index, mode); break;
            default: FAIL("Unsupported measurement group");
            }
        }
    });
}

template<class T> void CheckPoint(const std::map<uint16_t, MockSOEHandler::Record<T>>& data,
                                  const Point& expected, uint64_t stamp, bool timed)
{
    const auto name = "point_" + std::to_string(expected.index);
    const auto it = data.find(expected.index);
    Observe(name + "_present", it != data.end());
    REQUIRE(it != data.end());
    const auto value = static_cast<int64_t>(it->second.meas.value);
    Observe(name + "_value", value);
    REQUIRE(value == expected.value);
    if (timed)
    {
        Observe(name + "_time", it->second.meas.time.value);
        REQUIRE(it->second.meas.time.value == stamp);
    }
}

void CheckPoints(unsigned group, const std::string& response, std::initializer_list<Point> expected,
                 bool timed = false, bool unsolicited = false)
{
    MockSOEHandler soe;
    Decode(response, soe, unsolicited);
    Observe("typed_delivery_count", soe.TotalReceived());
    REQUIRE(soe.TotalReceived() == expected.size());
    uint64_t stamp = sampleTime;
    for (const auto& point : expected)
    {
        switch (group)
        {
        case 1: case 2: CheckPoint(soe.binarySOE, point, stamp, timed); break;
        case 3: case 4: CheckPoint(soe.doubleBinarySOE, point, stamp, timed); break;
        case 10: CheckPoint(soe.binaryOutputStatusSOE, point, stamp, timed); break;
        case 30: case 32: CheckPoint(soe.analogSOE, point, stamp, timed); break;
        case 40: CheckPoint(soe.analogOutputStatusSOE, point, stamp, timed); break;
        default: FAIL("Unsupported measurement group");
        }
        ++stamp;
    }
}

void StaticRead(unsigned group, unsigned variation, std::initializer_list<Point> points,
                std::initializer_list<Point> selected, const char* request, const char* expected,
                const char* probe = "C1 01", const char* expectedProbe = "C1 81 80 00")
{
    OutstationTestObject t(OutstationConfig{}, Points(group, variation, points));
    t.LowerLayerUp();
    Update(t, group, points, false);
    const auto reply = Request(t, request);
    CheckFrame("reply", reply, expected);
    if (selected.size())
        CheckPoints(group, reply, selected);
    CheckFrame("probe", Request(t, probe), expectedProbe);
}

void EventRead(unsigned group, unsigned variation, bool narrow, bool timed, std::initializer_list<Point> points,
               std::initializer_list<Point> selected, const char* request, const char* expected,
               const char* probeRequest, const char* probeReply)
{
    OutstationConfig config;
    config.eventBufferConfig = EventBufferConfig::AllTypes(10);
    config.params.prefer8BitEventQualifiers = narrow;
    OutstationTestObject t(config, Points(group, variation, points));
    t.LowerLayerUp();
    Update(t, group, points, true);
    const auto reply = Request(t, request);
    CheckFrame("reply", reply, expected);
    CheckPoints(group, reply, selected, timed);
    t.SendToOutstation("C3 00"); // Wrong sequence must not retire the selection.
    Observe("confirms_after_wrong_sequence", t.application->confirms.size());
    REQUIRE(t.application->confirms.empty());
    t.SendToOutstation("C0 00");
    Observe("matching_confirms", t.application->confirms.size());
    REQUIRE(t.application->confirms.size() == 1);
    CheckFrame("probe", Request(t, probeRequest), probeReply);
}

void Unsolicited(unsigned group, unsigned variation, bool narrow, bool timed,
                 std::initializer_list<Point> points, const char* expected)
{
    OutstationConfig config;
    config.eventBufferConfig = EventBufferConfig::AllTypes(10);
    config.params.allowUnsolicited = true;
    config.params.prefer8BitEventQualifiers = narrow;
    config.params.unsolConfirmTimeout = TimeDuration::Seconds(2);
    OutstationTestObject t(config, Points(group, variation, points));
    t.LowerLayerUp();
    CheckFrame("startup", t.lower->PopWriteAsHex(), "F0 82 80 00");
    t.OnTxReady();
    t.SendToOutstation("D0 00");
    CheckFrame("enable", Request(t, "C0 14 3C 02 06"), "C0 81 80 00");
    Update(t, group, points, true);
    const auto reply = t.lower->PopWriteAsHex();
    CheckFrame("reply", reply, expected);
    CheckPoints(group, reply, points, timed, true);
    t.OnTxReady();
    t.SendToOutstation("C1 00"); // Same sequence, wrong UNS bit.
    Observe("confirms_after_wrong_uns", t.application->confirms.size());
    REQUIRE(t.application->confirms.size() == 1);
    t.AdvanceTime(TimeDuration::Seconds(2));
    CheckFrame("retry", t.lower->PopWriteAsHex(), expected);
    t.OnTxReady();
    t.SendToOutstation("D1 00");
    Observe("matching_confirms", t.application->confirms.size());
    REQUIRE(t.application->confirms.size() == 2);
    CheckFrame("probe", Request(t, "C2 01 3C 02 06"), "C2 81 80 00");
}
template<class T>
void CheckCtoPoints(const std::map<uint16_t, MockSOEHandler::Record<T>>& points,
                    uint16_t last, TimestampQuality quality)
{
    uint64_t stamp = sampleTime;
    for (const auto index : {uint16_t(7), last})
    {
        const auto point = points.find(index);
        const auto name = "cto_" + std::to_string(index);
        Observe(name + "_present", point != points.end());
        REQUIRE(point != points.end());
        const auto& value = point->second.meas;
        const auto expectedValue = static_cast<int>(index != 7);
        Observe(name + "_value", static_cast<int>(value.value));
        REQUIRE(static_cast<int>(value.value) == expectedValue);
        Observe(name + "_time", value.time.value);
        REQUIRE(value.time.value == stamp);
        Observe(name + "_quality", static_cast<unsigned>(value.time.quality));
        REQUIRE(value.time.quality == quality);
        stamp += 257;
    }
}

void CommonTime(unsigned group, bool narrow, bool unsolicited, TimestampQuality quality,
                const char* request, const char* expected)
{
    const uint16_t last = narrow ? 8 : 256;
    const std::initializer_list<Point> points = {{7, 0, 1}, {last, 1, 1}};
    OutstationConfig config;
    config.eventBufferConfig = EventBufferConfig::AllTypes(10);
    config.params.prefer8BitEventQualifiers = narrow;
    config.params.allowUnsolicited = unsolicited;
    OutstationTestObject t(config, Points(group, 3, points));
    t.LowerLayerUp();
    if (unsolicited)
    {
        CheckFrame("startup", t.lower->PopWriteAsHex(), "F0 82 80 00");
        t.OnTxReady();
        t.SendToOutstation("D0 00");
        CheckFrame("enable", Request(t, "C0 14 3C 02 06"), "C0 81 80 00");
    }
    Update(t, group, points, true, quality, 257);
    const auto reply = unsolicited ? t.lower->PopWriteAsHex() : Request(t, request);
    CheckFrame("reply", reply, expected);
    if (unsolicited)
        t.OnTxReady();
    MockSOEHandler soe;
    Decode(reply, soe, unsolicited);
    Observe("typed_delivery_count", soe.TotalReceived());
    REQUIRE(soe.TotalReceived() == 2);
    if (group == 2)
        CheckCtoPoints(soe.binarySOE, last, quality);
    else
        CheckCtoPoints(soe.doubleBinarySOE, last, quality);
    const auto before = t.application->confirms.size();
    t.SendToOutstation("C1 00"); // Wrong UNS for FC130; wrong sequence for FC129.
    Observe("wrong_confirm_delta", t.application->confirms.size() - before);
    REQUIRE(t.application->confirms.size() == before);
    t.SendToOutstation(unsolicited ? "D1 00" : "C0 00");
    Observe("matching_confirm_delta", t.application->confirms.size() - before);
    REQUIRE(t.application->confirms.size() == before + 1);
    CheckFrame("probe", Request(t, "C2 01 3C 02 06"), "C2 81 80 00");
}

void TimeReadWrite(const char* request, const char* reply, bool write, uint64_t value,
                   const char* readback = "")
{
    OutstationTestObject t(OutstationConfig{});
    t.application->updateClockOnWrite = true;
    t.application->SetTime(DNPTime(sampleTime, TimestampQuality::SYNCHRONIZED));
    t.LowerLayerUp();
    auto response = Request(t, request);
    CheckFrame("reply", response, reply);
    const auto calls = t.application->timestamps.size();
    Observe("clock_writes", calls);
    REQUIRE(calls == (write ? 1 : 0));
    if (write)
    {
        Observe("written_time", t.application->timestamps.front().msSinceEpoch);
        REQUIRE(t.application->timestamps.front().msSinceEpoch == value);
        response = Request(t, "C1 01 32 01 07 01");
        CheckFrame("readback", response, readback);
    }
    MockSOEHandler soe;
    Decode(response, soe);
    Observe("time_count", soe.timeSOE.size());
    REQUIRE(soe.timeSOE.size() == 1);
    Observe("read_time", soe.timeSOE.front().value);
    REQUIRE(soe.timeSOE.front().value == value);
}

void RejectTime(const char* request, const char* reply, bool unsupported = false)
{
    OutstationTestObject t(OutstationConfig{});
    t.application->supportsTimeWrite = !unsupported;
    t.application->SetTime(DNPTime(sampleTime, TimestampQuality::SYNCHRONIZED));
    t.LowerLayerUp();
    CheckFrame("reply", Request(t, request), reply);
    Observe("clock_writes", t.application->timestamps.size());
    REQUIRE(t.application->timestamps.empty());
    CheckFrame("readback", Request(t, "C1 01 32 01 07 01"), "C1 81 80 00 32 01 07 01 06 05 04 03 02 01");
}

void RejectMeasurement(const char* body)
{
    MockSOEHandler soe;
    MockLogHandler log;
    HexSequence bytes(body);
    const auto result = MeasurementHandler::ProcessMeasurements(ResponseInfo(false, true, true),
                                                               bytes.ToRSeq(), log.logger, &soe);
    Observe("parser_reject", result != ParseResult::OK);
    REQUIRE(result != ParseResult::OK);
    Observe("typed_delivery_count", soe.TotalReceived());
    REQUIRE(soe.TotalReceived() == 0);
}

void DelayMeasure()
{
    OutstationTestObject t(OutstationConfig{});
    t.LowerLayerUp();
    const auto response = Request(t, "C0 17");
    CheckFrame("reply", response, "C0 81 80 00 34 02 07 01 00 00");
    TimeSyncHandler handler;
    HexSequence bytes(response);
    const auto result = APDUParser::Parse(bytes.ToRSeq().skip(4), handler, &t.log.logger);
    uint16_t delay = 65535;
    const auto parsed = result == ParseResult::OK && handler.GetTimeDelay(delay);
    Observe("parser_ok", parsed);
    REQUIRE(parsed);
    Observe("delay_ms", delay);
    REQUIRE(delay == 0);
    Observe("restart_calls", t.application->coldRestartCalls + t.application->warmRestartCalls);
    REQUIRE(t.application->coldRestartCalls + t.application->warmRestartCalls == 0);
}

void SecurityStatistics(const char* response, const char* truncated, uint16_t index)
{
    auto params = NoStartupTasks();
    params.startupIntegrityClassMask = ClassField::AllClasses();
    MasterTestFixture master(params);
    REQUIRE(master.context->OnLowerLayerUp());
    master.exe->run_many();
    CheckFrame("request", master.lower->PopWriteAsHex(), "C0 01 3C 02 06 3C 03 06 3C 04 06 3C 01 06");
    REQUIRE(master.context->OnTxReady());
    master.SendToMaster(response);
    const auto& received = master.meas->securityStatSOE;
    Observe("typed_delivery_count", received.size());
    REQUIRE(received.size() == 1);
    const auto& record = received.front();
    Observe("index", record.meas.index);
    REQUIRE(record.meas.index == index);
    Observe("association", record.meas.value.associationId);
    REQUIRE(record.meas.value.associationId == 0x1234);
    Observe("counter", record.meas.value.value);
    REQUIRE(record.meas.value.value == 0x12345678);
    Observe("flags", record.meas.value.flags.value);
    REQUIRE(record.meas.value.flags.value == 1);
    Observe("has_time", record.meas.value.HasTime());
    REQUIRE_FALSE(record.meas.value.HasTime());
    MasterTestFixture invalid(params);
    REQUIRE(invalid.context->OnLowerLayerUp());
    invalid.exe->run_many();
    CheckFrame("invalid_request", invalid.lower->PopWriteAsHex(), "C0 01 3C 02 06 3C 03 06 3C 04 06 3C 01 06");
    REQUIRE(invalid.context->OnTxReady());
    invalid.SendToMaster(truncated);
    Observe("malformed_delivery_count", invalid.meas->securityStatSOE.size());
    REQUIRE(invalid.meas->securityStatSOE.empty());
}

void ConfirmedLink(bool master, LinkConfirmMode mode, bool confirmed, const char* firstPayload,
                   const char* reset, const char* first, const char* second, const char* repeat)
{
    LinkConfig cfg(master);
    cfg.LocalAddr = master ? 1 : 10;
    cfg.RemoteAddr = master ? 10 : 1;
    cfg.ConfirmMode = mode;
    LinkLayerTest primary(cfg);
    REQUIRE(primary.link.OnLowerLayerUp());
    TransportTx tx(primary.log.logger);
    TransportRx rx(primary.log.logger, 300);
    const auto addr = cfg.GetAddresses();
    const auto ack = [&] {
        if (confirmed)
            REQUIRE(primary.OnFrame(LinkFunction::SEC_ACK, !master, false, false, cfg.LocalAddr, cfg.RemoteAddr));
        primary.exe->run_many();
    };
    const auto frame = [&](const char* name, const char* expected) {
        const auto wire = primary.PopLastWriteAsHex();
        CheckFrame(name, wire, expected);
        primary.link.OnTxReady();
        const HexSequence bytes(wire);
        const auto data = bytes.ToRSeq();
        // Strip the independent LPDU framing and CRC octets to feed the native transport receiver.
        std::vector<uint8_t> tpdu;
        for (size_t offset = 10; offset < data.length();)
        {
            const auto length = std::min<size_t>(16, data.length() - offset - 2);
            for (size_t i = 0; i < length; ++i)
                tpdu.push_back(data[offset + i]);
            offset += length + 2;
        }
        return rx.ProcessReceive(Message(addr, ser4cpp::rseq_t(tpdu.data(), tpdu.size())));
    };
    const HexSequence payload(firstPayload);
    tx.Configure(Message(addr, payload.ToRSeq()));
    const auto accepted = primary.upper->SendDown(tx);
    Observe("accepted", accepted);
    REQUIRE(accepted);
    if (confirmed)
    {
        CheckFrame("reset", primary.PopLastWriteAsHex(), reset);
        primary.link.OnTxReady();
        ack();
    }
    auto received = frame("first", first);
    if (*second)
    {
        Observe("first_delivery_bytes", received.payload.length());
        REQUIRE(received.payload.is_empty());
        ack();
        received = frame("second", second);
    }
    Observe("received_bytes", received.payload.length());
    REQUIRE(received.payload.length() == payload.ToRSeq().length());
    const bool correct = ser4cpp::HexConversions::to_hex(received.payload) == firstPayload;
    Observe("received_exact", correct);
    REQUIRE(correct);
    ack();
    Observe("sender_completions", primary.upper->GetCounters().numTxReady);
    REQUIRE(primary.upper->GetCounters().numTxReady == 1);

    // Use the same APDU length and another legal request/response to exercise
    // FCB and transport state reuse without requiring a second reset.
    tx.Configure(Message(addr, payload.ToRSeq()));
    REQUIRE(primary.upper->SendDown(tx));
    const auto again = primary.PopLastWriteAsHex();
    CheckFrame("repeat", again, repeat);
}
template<class T> void CheckOperation(const std::vector<Operation<T>>& records, uint16_t index,
                                      int64_t value, unsigned mode)
{
    Observe("operation_records", records.size());
    REQUIRE(records.size() == 1);
    const auto& record = records.front();
    Observe("operation_index", record.index);
    REQUIRE(record.index == index);
    const auto actual = static_cast<int64_t>(record.value.value * 2.0);
    Observe("operation_value_times_two", actual);
    REQUIRE(actual == value);
    const auto operationMode = static_cast<unsigned>(record.opType);
    Observe("operation_mode", operationMode);
    REQUIRE(operationMode == mode);
}

void AnalogCommand(unsigned variation, unsigned mode, bool narrow, uint16_t index, double value,
                   const char* first, const char* firstReply, const char* operate, const char* operateReply,
                   const char* readBefore, const char* beforeReply, const char* readAfter, const char* afterReply)
{
    auto params = NoStartupTasks();
    params.controlQualifierMode = narrow ? IndexQualifierMode::allow_one_byte : IndexQualifierMode::always_two_bytes;
    MasterTestFixture master(params);
    REQUIRE(master.context->OnLowerLayerUp());
    const auto initial = Point{index, 123, 1};
    OutstationTestObject outstation(OutstationConfig{}, Points(40, variation, {initial}));
    outstation.cmdHandler->reflectAnalogOutput = true;
    outstation.LowerLayerUp();
    Update(outstation, 40, {initial}, false);
    CheckFrame("clear_restart", Request(outstation, "CE 02 50 01 00 07 07 00"), "CE 81 00 00");
    CheckFrame("read_before", Request(outstation, readBefore), beforeReply);

    CommandSet command;
    switch (variation)
    {
    case 1: command.Add<AnalogOutputInt32>({{AnalogOutputInt32(static_cast<int32_t>(value)), index}}); break;
    case 2: command.Add<AnalogOutputInt16>({{AnalogOutputInt16(static_cast<int16_t>(value)), index}}); break;
    case 3: command.Add<AnalogOutputFloat32>({{AnalogOutputFloat32(static_cast<float>(value)), index}}); break;
    default: FAIL("Unsupported command variation");
    }
    CommandCallbackQueue results;
    if (mode == 0)
        master.context->SelectAndOperate(std::move(command), results.Callback(), TaskConfig::Default());
    else if (mode == 1)
        master.context->DirectOperate(std::move(command), results.Callback(), TaskConfig::Default());
    else
        REQUIRE(master.context->DirectOperateNoAck(std::move(command), results.Callback(), TaskConfig::Default()));
    master.exe->run_many();
    auto commandAPDU = master.lower->PopWriteAsHex();
    CheckFrame("master_request", commandAPDU, first);
    REQUIRE(master.context->OnTxReady());
    auto response = Request(outstation, commandAPDU.c_str());
    CheckFrame("outstation_response", response, firstReply);
    if (mode == 0)
    {
        Observe("operations_after_select", outstation.cmdHandler->NumOperate());
        REQUIRE(outstation.cmdHandler->NumOperate() == 0);
        master.SendToMaster(response);
        master.exe->run_many();
        commandAPDU = master.lower->PopWriteAsHex();
        CheckFrame("operate_request", commandAPDU, operate);
        REQUIRE(master.context->OnTxReady());
        response = Request(outstation, commandAPDU.c_str());
        CheckFrame("operate_response", response, operateReply);
    }
    if (mode != 2)
        master.SendToMaster(response);
    master.exe->run_many();
    Observe("master_completion_count", results.values.size());
    REQUIRE(results.values.size() == 1);
    Observe("master_success", results.values.front().summary == TaskCompletion::SUCCESS);
    REQUIRE(results.values.front().summary == TaskCompletion::SUCCESS);
    REQUIRE(results.values.front().results.size() == 1);
    const auto expected = mode == 2 ? CommandStatus::UNDEFINED : CommandStatus::SUCCESS;
    const auto status = results.values.front().results.front().status;
    Observe("master_point_status", static_cast<unsigned>(status));
    REQUIRE(status == expected);
    Observe("operations", outstation.cmdHandler->NumOperate());
    REQUIRE(outstation.cmdHandler->NumOperate() == 1);
    const auto doubleValue = static_cast<int64_t>(value * 2.0);
    if (variation == 1)
        CheckOperation(outstation.cmdHandler->aoInt32Ops, index, doubleValue, mode);
    else if (variation == 2)
        CheckOperation(outstation.cmdHandler->aoInt16Ops, index, doubleValue, mode);
    else
        CheckOperation(outstation.cmdHandler->aoFloat32Ops, index, doubleValue, mode);
    const auto readback = Request(outstation, readAfter);
    CheckFrame("read_after", readback, afterReply);
    MockSOEHandler soe;
    Decode(readback, soe);
    Observe("typed_delivery_count", soe.TotalReceived());
    REQUIRE(soe.TotalReceived() == 1);
    REQUIRE(soe.analogOutputStatusSOE.count(index) == 1);
    const auto actual = static_cast<int64_t>(soe.analogOutputStatusSOE.at(index).meas.value * 2.0);
    Observe("readback_times_two", actual);
    REQUIRE(actual == doubleValue);
}
void ReadReject(unsigned group, unsigned variation, bool event, std::initializer_list<Point> points,
                const char* request, const char* errorReply, const char* probe, const char* expected)
{
    OutstationConfig config;
    config.eventBufferConfig = EventBufferConfig::AllTypes(10);
    OutstationTestObject t(config, Points(group, variation, points));
    t.LowerLayerUp();
    Update(t, group, points, event);
    CheckFrame("rejection", Request(t, request), errorReply);
    Observe("confirmed_after_bad_request", t.application->confirms.size());
    REQUIRE(t.application->confirms.empty());
    const auto reply = Request(t, probe);
    CheckFrame("unchanged_readback", reply, expected);
    CheckPoints(group, reply, points, event && ((group != 32 && variation != 1) || (group == 32 && variation == 4)));
}
void ClassRead(unsigned clazz, bool counted, std::initializer_list<Point> points,
               std::initializer_list<Point> selected, const char* request, const char* expected,
               const char* otherRequest, const char* otherExpected)
{
    OutstationConfig config;
    config.eventBufferConfig = EventBufferConfig::AllTypes(10);
    auto db = Points(1, 2, points);
    const auto targetClass = static_cast<PointClass>(1u << clazz);
    const auto otherClass = clazz == 1 ? PointClass::Class2 : PointClass::Class1;
    for (auto& pair : db.binary_input)
        pair.second.clazz = clazz ? targetClass : otherClass;
    db.binary_input[30].clazz = otherClass;
    OutstationTestObject t(config, db);
    t.LowerLayerUp();
    Update(t, 1, points, clazz != 0);
    Update(t, 1, {{30, 1, 1}}, true);
    const auto reply = Request(t, request);
    CheckFrame("reply", reply, expected);
    // A Class 0 response includes the other point's static value, without
    // consuming its queued Class 1 event.
    CheckPoints(1, reply, selected);
    if (clazz)
        t.SendToOutstation("C0 00");
    Observe("target_confirmations", t.application->confirms.size());
    REQUIRE(t.application->confirms.size() == (clazz ? 1u : 0u));
    CheckFrame("other_class", Request(t, otherRequest), otherExpected);
    t.SendToOutstation("C1 00");
    Observe("all_confirmations", t.application->confirms.size());
    REQUIRE(t.application->confirms.size() == (clazz ? 2u : 1u));
    if (counted)
    {
        const auto retained = t.application->confirms.front();
        const uint32_t left = clazz == 1 ? retained.num_class1 : clazz == 2 ? retained.num_class2 : retained.num_class3;
        Observe("remaining_target", left);
        REQUIRE(left == points.size() - selected.size());
    }
}
} // namespace

#include "TestRtuAcceptanceCases.inc"
