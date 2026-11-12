/*
 * Copyright 2013-2020 Automatak, LLC
 *
 * Licensed to Green Energy Corp (www.greenenergycorp.com) and Automatak
 * LLC (www.automatak.com) under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership. Green Energy Corp and Automatak LLC license
 * this file to you under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License. You may obtain
 * a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "utils/AcceptanceObservation.h"
#include "utils/MasterTestFixture.h"
#include "utils/OutstationTestObject.h"
#include "utils/ProtocolUtil.h"
#include "utils/TransportTestObject.h"

#include <opendnp3/app/AppConstants.h>

#include "dnp3mocks/MockLogHandler.h"

#include <catch.hpp>
#include <transport/TransportConstants.h>
#include <transport/TransportHeader.h>
#include <ser4cpp/util/HexConversions.h>

#include <algorithm>
#include <array>
#include <chrono>

using namespace opendnp3;
using namespace ser4cpp;

#define SUITE(name) "TransportLayerTestSuite - " name

namespace
{
void DeliverApplicationFragment(MockLinkLayer& link, const std::vector<uint8_t>& fragment, const Addresses& addresses)
{
    constexpr size_t segmentPayload = 249; // Link user-data limit minus the transport header.
    uint8_t sequence = 0;
    for (size_t offset = 0; offset < fragment.size(); offset += segmentPayload)
    {
        const size_t size = std::min(segmentPayload, fragment.size() - offset);
        const uint8_t header = (offset == 0 ? 0x40 : 0) | (offset + size == fragment.size() ? 0x80 : 0)
            | (sequence++ & 0x3F);
        link.SendUp(HexConversions::to_hex(&header, 1, true) + " "
                        + HexConversions::to_hex(fragment.data() + offset, size, true),
                    addresses);
    }
}

void AppendCrob(std::vector<uint8_t>& request, uint16_t index, bool wide)
{
    request.push_back(static_cast<uint8_t>(index));
    if (wide) request.push_back(static_cast<uint8_t>(index >> 8));
    // LATCH_ON, count 1, both timers and request status zero.
    request.insert(request.end(), {0x03, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0});
}

constexpr std::array<size_t, 6> fragmentLimits{{250, 250, 250, 2049, 2049, 2049}};
constexpr std::array<size_t, 6> fragmentSizes{{249, 250, 251, 2048, 2049, 2050}};
} // namespace

TEST_CASE("AT-CFG-03-MASTER-RX", "[rtu-acceptance][transport-fragment]")
{
    for (size_t i = 0; i < fragmentLimits.size(); ++i)
    {
        if (!acceptance::Selected(("V" + std::to_string(i + 1)).c_str())) continue;
        auto params = NoStartupTasks();
        params.maxRxFragSize = static_cast<uint32_t>(fragmentLimits[i]);
        params.maxTxFragSize = 300;
        MasterTestFixture master(params);
        MockLogHandler log;
        MockLinkLayer link;
        TransportLayer transport(log.logger, params.maxRxFragSize, master.exe, params.maxRxFragmentTime);
        transport.SetAppLayer(*master.context);
        transport.SetLinkLayer(link);
        link.SetUpperLayer(transport);
        REQUIRE(transport.OnLowerLayerUp());
        master.context->ScanAllObjects(GroupVariationID(1, 2), master.meas, TaskConfig::Default());
        master.exe->run_many();
        REQUIRE(master.lower->PopWriteAsHex() == "C0 01 01 02 06");
        REQUIRE(master.context->OnTxReady());

        const auto points = fragmentSizes[i] - 11;
        const auto stop = points - 1;
        std::vector<uint8_t> response{0xC0, 0x81, 0, 0, 1, 2, 1, 0, 0,
                                      static_cast<uint8_t>(stop), static_cast<uint8_t>(stop >> 8)};
        response.resize(fragmentSizes[i], 0x81);
        response.back() = 0x01;
        DeliverApplicationFragment(link, response, master.addresses.Reverse());
        master.exe->run_many();
        const bool oversized = fragmentSizes[i] > fragmentLimits[i];
        const auto delivered = master.meas->binarySOE.size();
        REQUIRE(delivered == (oversized ? 0 : points));
        if (!oversized)
        {
            REQUIRE(master.meas->binarySOE.at(0).meas.value);
            REQUIRE_FALSE(master.meas->binarySOE.at(static_cast<uint16_t>(stop)).meas.value);
        }
        acceptance::Observe("delivered_points", delivered);
        const auto overflow = transport.GetStatistics().rx.numTransportBufferOverflow;
        REQUIRE(overflow == (oversized ? 1 : 0));
        acceptance::Observe("buffer_overflows", overflow);

        const auto sequence = static_cast<uint8_t>(oversized ? 0 : 1);
        if (!oversized)
        {
            master.meas->Clear();
            master.context->ScanAllObjects(GroupVariationID(1, 2), master.meas, TaskConfig::Default());
            master.exe->run_many();
            REQUIRE(master.lower->PopWriteAsHex() == "C1 01 01 02 06");
            REQUIRE(master.context->OnTxReady());
        }
        DeliverApplicationFragment(link, {static_cast<uint8_t>(0xC0 | sequence), 0x81, 0, 0, 1, 2, 0, 0, 0, 0x81},
                                   master.addresses.Reverse());
        master.exe->run_many();
        REQUIRE(master.meas->binarySOE.size() == 1);
        REQUIRE(master.meas->binarySOE.at(0).meas.value);
        acceptance::Observe("recovered_points", master.meas->binarySOE.size());
    }
}

TEST_CASE("AT-CFG-03-OUTSTATION-RX", "[rtu-acceptance][transport-fragment]")
{
    for (size_t i = 0; i < fragmentLimits.size(); ++i)
    {
        if (!acceptance::Selected(("V" + std::to_string(i + 1)).c_str())) continue;
        OutstationConfig config;
        config.params.maxRxFragSize = static_cast<uint32_t>(fragmentLimits[i]);
        config.params.maxTxFragSize = 300;
        OutstationTestObject outstation(config);
        MockLinkLayer link;
        TransportLayer transport(outstation.log.logger, config.params.maxRxFragSize,
                                 std::make_shared<exe4cpp::MockExecutor>(), config.params.maxRxFragmentTime);
        transport.SetAppLayer(outstation.context);
        transport.SetLinkLayer(link);
        link.SetUpperLayer(transport);
        REQUIRE(transport.OnLowerLayerUp());

        // Q17 uses 12 bytes per CROB and Q28 13. The two headers plus APCI total 11 bytes.
        const auto bodySize = fragmentSizes[i] - 11;
        const auto wide = (bodySize - 1) % 12 + 1;
        const auto narrow = (bodySize - 13 * wide) / 12;
        std::vector<uint8_t> request{0xC0, 0x06, 12, 1, 0x17, static_cast<uint8_t>(narrow)};
        for (uint16_t index = 0; index < narrow; ++index) AppendCrob(request, index, false);
        request.insert(request.end(), {12, 1, 0x28, static_cast<uint8_t>(wide), 0});
        for (uint16_t index = 0; index < wide; ++index) AppendCrob(request, 256 + index, true);
        REQUIRE(request.size() == fragmentSizes[i]);
        DeliverApplicationFragment(link, request, Addresses());
        const bool oversized = fragmentSizes[i] > fragmentLimits[i];
        const auto operations = outstation.cmdHandler->NumOperate();
        REQUIRE(operations == (oversized ? 0 : narrow + wide));
        REQUIRE(outstation.lower->HasNoData());
        acceptance::Observe("actuations", operations);
        const auto overflow = transport.GetStatistics().rx.numTransportBufferOverflow;
        REQUIRE(overflow == (oversized ? 1 : 0));
        acceptance::Observe("buffer_overflows", overflow);

        std::vector<uint8_t> recovery{0xC1, 0x06, 12, 1, 0x17, 1};
        AppendCrob(recovery, 0, false);
        DeliverApplicationFragment(link, recovery, Addresses());
        REQUIRE(outstation.cmdHandler->NumOperate() == operations + 1);
        REQUIRE(outstation.lower->HasNoData());
        acceptance::Observe("recovered_actuations", outstation.cmdHandler->NumOperate() - operations);
    }
}

TEST_CASE(SUITE("RepeatSendsDoNotLogOrChangeStatistics"))
{
    MockLogHandler log;
    TransportTx tx(log.logger);
    HexSequence hs("12 34 56");
    tx.Configure(Message(Addresses(), hs.ToRSeq()));

    auto segment1 = tx.GetSegment();
    REQUIRE("C0 12 34 56" == HexConversions::to_hex(segment1));
    REQUIRE(tx.Statistics().numTransportTx == 1);

    auto segment2 = tx.GetSegment();
    REQUIRE("C0 12 34 56" == HexConversions::to_hex(segment2));
    REQUIRE(tx.Statistics().numTransportTx == 1);
}

// make sure an invalid state exception gets thrown
// for every event other than LowerLayerUp() since
// the layer starts in the online state
TEST_CASE(SUITE("StateOffline"))
{
    TransportTestObject test;

    REQUIRE_FALSE(test.upper.SendDown("00"));
    REQUIRE_FALSE(test.link.SendUp(""));
    REQUIRE_FALSE(test.transport.OnTxReady());
    REQUIRE_FALSE(test.transport.OnLowerLayerDown());
}

TEST_CASE(SUITE("StateReady"))
{
    TransportTestObject test(true); // makes an implicit call to 'test.link.ThisLayerUp()'

    // check that that the transport layer is correctly forwarding up/down
    REQUIRE(test.upper.IsOnline());
    test.transport.OnLowerLayerDown();
    REQUIRE_FALSE(test.upper.IsOnline());
    test.transport.OnLowerLayerUp();
    REQUIRE(test.upper.IsOnline());

    REQUIRE_FALSE(test.transport.OnLowerLayerUp());
    REQUIRE_FALSE(test.transport.OnTxReady());
}

TEST_CASE(SUITE("allows header-only final frame"))
{
    TransportTestObject test(true);

    test.link.SendUp("41 DE AD BE EF");
    test.link.SendUp("82");

    REQUIRE(test.upper.received.AsHex() == "DE AD BE EF");
}

TEST_CASE(SUITE("ReceiveNoFIR"))
{
    TransportTestObject test(true);
    // try sending a non-FIR w/ no prior packet
    test.link.SendUp("80 77"); // _/FIN
    REQUIRE(test.transport.GetStatistics().rx.numTransportIgnore == 1);
}

TEST_CASE(SUITE("ReceiveWrongSequence"))
{
    TransportTestObject test(true);
    // send a FIR, followed by a FIN w/ the wrong sequence
    test.link.SendUp(test.GetData("40")); // FIR/_/0
    test.link.SendUp(test.GetData("82")); // _/FIN/2
    REQUIRE(test.transport.GetStatistics().rx.numTransportIgnore == 1);
}

TEST_CASE(SUITE("PacketsCanBeOfVaryingSize"))
{
    TransportTestObject test(true);
    test.link.SendUp("40 0A 0B 0C"); // FIR/_/0
    test.link.SendUp("81 0D 0E 0F"); // _/FIN/1
    REQUIRE(test.upper.received.AsHex() == "0A 0B 0C 0D 0E 0F");
}

TEST_CASE(SUITE("ReceiveSinglePacket"))
{
    TransportTestObject test(true);
    // now try receiving 1 a single FIR/FIN with a magic value
    test.link.SendUp("C0 77");
    REQUIRE(test.upper.received.AsHex() == "77");
}

TEST_CASE(SUITE("ReceiveLargestPossibleAPDU"))
{
    TransportTestObject test(true);

    uint32_t num_packets = CalcMaxPackets(opendnp3::DEFAULT_MAX_APDU_SIZE, MAX_TPDU_PAYLOAD);
    uint32_t last_packet_length = CalcLastPacketSize(opendnp3::DEFAULT_MAX_APDU_SIZE, MAX_TPDU_PAYLOAD);

    std::vector<std::string> packets;
    const auto apdu = test.GeneratePacketSequence(packets, num_packets, last_packet_length);
    for (const auto& s : packets)
    {
        test.link.SendUp(s);
    }

    REQUIRE(test.upper.received.AsHex() == apdu); // check that the correct data was written
}

TEST_CASE(SUITE("ReceiveBufferOverflow"))
{
    TransportTestObject test(true, 4); // maximum ASDU size of 4

    REQUIRE(test.link.SendUp("40 11 22 33")); // FIN = 0, FIR = 1, SEQ = 0

    {
        auto stats = test.transport.GetStatistics().rx;
        REQUIRE(stats.numTransportRx == 1);
        REQUIRE(stats.numTransportBufferOverflow == 0);
    }

    REQUIRE(test.link.SendUp("81 44 55")); // FIN = 0, FIR = 1, SEQ = 1

    {
        auto stats = test.transport.GetStatistics().rx;
        REQUIRE(stats.numTransportRx == 2);
        REQUIRE(stats.numTransportBufferOverflow == 1);
    }
}

TEST_CASE(SUITE("ReceiveNewFir"))
{
    TransportTestObject test(true);

    test.link.SendUp(test.GetData("40")); // FIR/_/0
    REQUIRE(test.upper.received.IsEmpty());

    test.link.SendUp("C0 AB CD"); // FIR/FIN/0
    REQUIRE(test.upper.received.AsHex() == "AB CD");
    REQUIRE(test.transport.GetStatistics().rx.numTransportDiscard == 1);
}

TEST_CASE(SUITE("StateSending"))
{
    TransportTestObject test(true);

    // this puts the layer into the Sending state
    REQUIRE(test.upper.SendDown("11"));
    REQUIRE("C0 11" == test.link.PopWriteAsHex()); // FIR/FIN SEQ=0

    // Check that while we're sending, all other send requests are rejected
    REQUIRE_FALSE(test.upper.SendDown("00"));

    REQUIRE_FALSE(test.transport.OnLowerLayerUp());

    // while we are sending, we should still be able to receive data as normal
    test.link.SendUp("C0 77");
    REQUIRE(test.upper.received.AsHex() == "77");

    // this should put us back in the Ready state since it was a single tpdu send
    test.transport.OnTxReady();
    REQUIRE(test.upper.GetCounters().numTxReady == 1);

    REQUIRE_FALSE(test.transport.OnTxReady());
}

TEST_CASE(SUITE("SendSuccess"))
{
    TransportTestObject test(true);

    // this puts the layer into the Sending state
    test.upper.SendDown("11");
    REQUIRE("C0 11" == test.link.PopWriteAsHex()); // FIR/FIN SEQ=0
    test.transport.OnTxReady();

    // this puts the layer into the Sending state
    test.upper.SendDown("11");
    REQUIRE("C1 11" == test.link.PopWriteAsHex()); // FIR/FIN SEQ=1
    test.transport.OnTxReady();
    REQUIRE(test.upper.GetCounters().numTxReady == 2);
}

// if we're in the middle of a send and the layer goes down
TEST_CASE(SUITE("ClosedWhileSending"))
{
    TransportTestObject test(true);
    test.upper.SendDown("11"); // get the layer into the sending state

    test.transport.OnLowerLayerDown();
    REQUIRE_FALSE(test.upper.IsOnline());
}

TEST_CASE(SUITE("SendFullAPDU"))
{
    TransportTestObject test(true);

    uint32_t numPackets = CalcMaxPackets(opendnp3::DEFAULT_MAX_APDU_SIZE, MAX_TPDU_PAYLOAD);
    uint32_t lastPacketLength = CalcLastPacketSize(opendnp3::DEFAULT_MAX_APDU_SIZE, MAX_TPDU_PAYLOAD);

    std::vector<std::string> packets;
    std::string apdu = test.GeneratePacketSequence(packets, numPackets, lastPacketLength);

    test.upper.SendDown(apdu);

    // 9 total packets
    REQUIRE(numPackets == test.link.sends.size());
    REQUIRE(packets.size() == test.link.sends.size());

    for (const auto& packet : packets)
    {
        REQUIRE(packet == test.link.PopWriteAsHex());
    }

    test.transport.OnTxReady();
}

TEST_CASE(SUITE("SendOneTPDU249ByteAPDU"))
{
    TransportTestObject test(true);
    const auto apdu = test.GetData("", 0, MAX_TPDU_PAYLOAD);

    REQUIRE(test.upper.SendDown(apdu));
    REQUIRE(test.link.sends.size() == 1);
    REQUIRE(test.link.PopWriteAsHex() == test.GetData("C0", 0, MAX_TPDU_PAYLOAD));

    REQUIRE(test.transport.OnTxReady());
    REQUIRE(test.upper.GetCounters().numTxReady == 1);
}

TEST_CASE(SUITE("Send250ByteAPDUInTwoTPDUs"))
{
    TransportTestObject test(true);
    const auto apdu = test.GetData("", 0, MAX_TPDU_PAYLOAD + 1);

    REQUIRE(test.upper.SendDown(apdu));
    REQUIRE(test.link.sends.size() == 2);
    REQUIRE(test.link.PopWriteAsHex() == test.GetData("40", 0, MAX_TPDU_PAYLOAD));
    REQUIRE(test.link.PopWriteAsHex() == test.GetData("81", MAX_TPDU_PAYLOAD, 1));

    REQUIRE(test.transport.OnTxReady());
    REQUIRE(test.upper.GetCounters().numTxReady == 1);
}

TEST_CASE(SUITE("ConfiguredReceiveCapacityExactFitAndOneByteOver"))
{
    TransportTestObject test(true, 10);

    test.link.SendUp("40 00 01 02 03 04 05 06 07 08");
    test.link.SendUp("81 09");
    REQUIRE(test.upper.received.AsHex() == "00 01 02 03 04 05 06 07 08 09");
    REQUIRE(test.transport.GetStatistics().rx.numTransportBufferOverflow == 0);

    test.upper.received.Clear();
    test.link.SendUp("40 00 01 02 03 04 05 06 07 08");
    test.link.SendUp("81 09 0A");
    REQUIRE(test.upper.received.IsEmpty());
    REQUIRE(test.transport.GetStatistics().rx.numTransportBufferOverflow == 1);
}

TEST_CASE(SUITE("ReceiveAtConfiguredCapacity2048AndAbove"))
{
    {
        TransportTestObject test(true, 2048);
        const uint32_t apduSize = 2048;
        const uint32_t numPackets = (apduSize + MAX_TPDU_PAYLOAD - 1) / MAX_TPDU_PAYLOAD;
        const uint32_t lastPacketLength = apduSize - (numPackets - 1) * MAX_TPDU_PAYLOAD;
        std::vector<std::string> packets;
        const auto apdu = test.GeneratePacketSequence(packets, numPackets, lastPacketLength);

        for (const auto& packet : packets)
            test.link.SendUp(packet);

        REQUIRE(test.upper.received.AsHex() == apdu);
        REQUIRE(test.upper.received.Size() == apduSize);
        REQUIRE(test.transport.GetStatistics().rx.numTransportBufferOverflow == 0);
    }

    {
        const uint32_t apduSize = 2501;
        TransportTestObject test(true, apduSize);
        const uint32_t numPackets = (apduSize + MAX_TPDU_PAYLOAD - 1) / MAX_TPDU_PAYLOAD;
        const uint32_t lastPacketLength = apduSize - (numPackets - 1) * MAX_TPDU_PAYLOAD;
        std::vector<std::string> packets;
        const auto apdu = test.GeneratePacketSequence(packets, numPackets, lastPacketLength);

        for (const auto& packet : packets)
            test.link.SendUp(packet);

        REQUIRE(test.upper.received.AsHex() == apdu);
        REQUIRE(test.upper.received.Size() == apduSize);
        REQUIRE(test.transport.GetStatistics().rx.numTransportBufferOverflow == 0);
    }
}

TEST_CASE(SUITE("DuplicateAndOutOfOrderSequenceHandling"))
{
    {
        TransportTestObject test(true);
        test.link.SendUp("40 11");
        test.link.SendUp("01 22");
        test.link.SendUp("01 FF"); // duplicate sequence 1
        test.link.SendUp("82 33");

        REQUIRE(test.upper.received.AsHex() == "11 22 33");
        REQUIRE(test.transport.GetStatistics().rx.numTransportIgnore == 1);
    }

    {
        TransportTestObject test(true);
        test.link.SendUp("40 11");
        test.link.SendUp("02 FF"); // sequence 2 arrived before sequence 1
        test.link.SendUp("01 22");
        test.link.SendUp("82 33");

        REQUIRE(test.upper.received.AsHex() == "11 22 33");
        REQUIRE(test.transport.GetStatistics().rx.numTransportIgnore == 1);
    }
}

TEST_CASE(SUITE("MissingTransportSequenceIsIgnored"))
{
    TransportTestObject test(true);
    test.link.SendUp("40 11");
    test.link.SendUp("82 22"); // expected sequence 1, received 2

    REQUIRE(test.upper.received.IsEmpty());
    REQUIRE(test.transport.GetStatistics().rx.numTransportIgnore == 1);
}

TEST_CASE(SUITE("TransportSequenceWrapsFrom63To0"))
{
    TransportTestObject test(true, 100);
    test.link.SendUp("40 00");

    for (uint8_t seq = 1; seq <= 64; ++seq)
    {
        const auto wireSeq = static_cast<uint8_t>(seq % 64);
        const bool fin = seq == 64;
        const auto header = TransportHeader::ToByte(false, fin, wireSeq);
        const auto headerHex = HexConversions::to_hex(&header, 1, true);
        test.link.SendUp(headerHex + " " + test.GetData("", seq, 1));
    }

    REQUIRE(test.upper.received.Size() == 65);
    REQUIRE(test.upper.received.AsHex() == test.GetData("", 0, 65));
    REQUIRE(test.transport.GetStatistics().rx.numTransportIgnore == 0);
}

TEST_CASE(SUITE("ContinuationFromDifferentPeerIsIgnored"))
{
    TransportTestObject test(true);
    const Addresses firstPeer(1, 2);
    const Addresses otherPeer(3, 4);

    test.link.SendUp("40 11", firstPeer);
    test.link.SendUp("81 22", otherPeer);
    REQUIRE(test.upper.received.IsEmpty());
    REQUIRE(test.transport.GetStatistics().rx.numTransportIgnore == 1);

    test.link.SendUp("81 33", firstPeer);
    REQUIRE(test.upper.received.AsHex() == "11 33");
}

TEST_CASE("AT-CFG-03-TIMEOUT", "[rtu-acceptance][transport-fragment]")
{
    const std::array<unsigned, 4> elapsed = {{9, 10, 11, 10000}};
    for (size_t i = 0; i < elapsed.size(); ++i)
    {
        if (!acceptance::Selected(("V" + std::to_string(i + 1)).c_str())) continue;
        const bool configured = i < 3;
        const bool completes = !configured || elapsed[i] < 10;
        const auto timeout = configured ? TimeDuration::Milliseconds(10) : TimeDuration::Max();
        TransportTestObject test(true, DEFAULT_MAX_APDU_SIZE, timeout);
        test.link.SendUp("40 11");
        REQUIRE(test.exe->advance_time(std::chrono::milliseconds(elapsed[i])) == 0);
        REQUIRE(test.transport.GetStatistics().rx.numTransportDiscard == 0);
        test.link.SendUp("81 22");

        const auto stats = test.transport.GetStatistics().rx;
        REQUIRE(test.upper.received.AsHex() == (completes ? "11 22" : ""));
        REQUIRE(stats.numTransportDiscard == (completes ? 0 : 1));
        REQUIRE(stats.numTransportIgnore == (completes ? 0 : 1));
        acceptance::Observe("completed_bytes", test.upper.received.Size());
        acceptance::Observe("expired_fragments", stats.numTransportDiscard);
        acceptance::Observe("ignored_segments", stats.numTransportIgnore);
        test.upper.received.Clear();
        test.link.SendUp("DF 33");
        REQUIRE(test.upper.received.AsHex() == "33");
        acceptance::Observe("recovered_bytes", test.upper.received.Size());
    }
}

TEST_CASE("AT-CFG-03-TPDU", "[rtu-acceptance][transport-fragment]")
{
    TransportTestObject test(true, DEFAULT_MAX_APDU_SIZE, TimeDuration::Milliseconds(10));
    const Addresses owner(1, 2);
    const Addresses foreign(3, 4);
    test.link.SendUp("40 11", owner);
    test.link.SendUp("81 FF", foreign);
    test.link.SendUp("82 FF", owner);
    REQUIRE(test.upper.received.IsEmpty());
    test.link.SendUp("01 22", owner);
    test.link.SendUp("01 FF", owner);
    test.link.SendUp("82 33", owner);
    REQUIRE(test.upper.received.AsHex() == "11 22 33");
    acceptance::Observe("complete_bytes", test.upper.received.Size());
    acceptance::Observe("invalid_segments", test.transport.GetStatistics().rx.numTransportIgnore);
    REQUIRE(test.transport.GetStatistics().rx.numTransportIgnore == 3);

    test.upper.received.Clear();
    test.link.SendUp("40 AA", owner);
    test.link.SendUp("45 BB", owner);
    test.link.SendUp("86 CC", owner);
    REQUIRE(test.upper.received.AsHex() == "BB CC");
    test.upper.received.Clear();
    test.link.SendUp("40 AA", owner);
    REQUIRE(test.transport.OnLowerLayerDown());
    REQUIRE(test.transport.OnLowerLayerUp());
    test.link.SendUp("81 FF", owner);
    REQUIRE(test.upper.received.IsEmpty());
    test.link.SendUp("40 AA", owner);
    test.exe->advance_time(std::chrono::milliseconds(10));
    test.link.SendUp("81 FF", owner);
    REQUIRE(test.upper.received.IsEmpty());
    test.link.SendUp("C0 DD", owner);
    REQUIRE(test.upper.received.AsHex() == "DD");
    acceptance::Observe("recovered_bytes", test.upper.received.Size());
}

TEST_CASE(SUITE("IntermediateSegmentDoesNotExtendAbsoluteFragmentDeadline"))
{
    TransportTestObject test(true, DEFAULT_MAX_APDU_SIZE, TimeDuration::Milliseconds(10));
    test.link.SendUp("40 11");
    REQUIRE(test.exe->advance_time(std::chrono::milliseconds(9)) == 0);
    test.link.SendUp("01 22");
    REQUIRE(test.exe->advance_time(std::chrono::milliseconds(2)) == 0);
    test.link.SendUp("82 33");

    REQUIRE(test.upper.received.IsEmpty());
    REQUIRE(test.transport.GetStatistics().rx.numTransportDiscard == 1);
    REQUIRE(test.transport.GetStatistics().rx.numTransportIgnore == 1);
}

TEST_CASE(SUITE("ExpiredFragmentCannotCompleteButNewFIRFINCan"))
{
    TransportTestObject test(true, DEFAULT_MAX_APDU_SIZE, TimeDuration::Milliseconds(10));
    test.link.SendUp("40 11");
    REQUIRE(test.exe->advance_time(std::chrono::milliseconds(10)) == 0);
    test.link.SendUp("81 22");
    REQUIRE(test.upper.received.IsEmpty());
    REQUIRE(test.transport.GetStatistics().rx.numTransportDiscard == 1);
    REQUIRE(test.transport.GetStatistics().rx.numTransportIgnore == 1);

    test.link.SendUp("DF 33"); // new FIR/FIN with an independent sequence number
    REQUIRE(test.upper.received.AsHex() == "33");
}

TEST_CASE(SUITE("OverflowRecoveryAndDisconnectClearIncompleteReceive"))
{
    {
        TransportTestObject test(true, 4);
        test.link.SendUp("40 11 22 33");
        test.link.SendUp("81 44 55"); // overflow by one byte
        REQUIRE(test.upper.received.IsEmpty());
        REQUIRE(test.transport.GetStatistics().rx.numTransportBufferOverflow == 1);

        test.link.SendUp("C0 AA BB");
        REQUIRE(test.upper.received.AsHex() == "AA BB");
    }

    {
        TransportTestObject test(true);
        test.link.SendUp("40 11");
        REQUIRE(test.transport.OnLowerLayerDown());
        REQUIRE(test.transport.OnLowerLayerUp());
        test.link.SendUp("81 22"); // no buffered FIR remains across reconnect
        REQUIRE(test.upper.received.IsEmpty());
        REQUIRE(test.transport.GetStatistics().rx.numTransportIgnore == 1);

        test.link.SendUp("DF 33");
        REQUIRE(test.upper.received.AsHex() == "33");
    }
}

TEST_CASE(SUITE("MaxFragmentTimePreservesLegacyNoDeadlineBehavior"))
{
    TransportTestObject test(true);
    test.link.SendUp("40 11");
    REQUIRE(test.exe->advance_time(std::chrono::seconds(10)) == 0);
    test.link.SendUp("81 22");

    REQUIRE(test.upper.received.AsHex() == "11 22");
    REQUIRE(test.transport.GetStatistics().rx.numTransportDiscard == 0);
}
