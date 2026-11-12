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
#include "utils/LinkHex.h"
#include "utils/AcceptanceObservation.h"
#include "utils/LinkLayerTest.h"
#include "utils/MockTransportSegment.h"

#include <ser4cpp/util/HexConversions.h>

#include <catch.hpp>

#include <array>

#include <chrono>
#include <iostream>
#include <stdexcept>

using namespace opendnp3;
using namespace ser4cpp;

#define SUITE(name) "LinkLayerTestSuite - " name

// All operations should fail except for OnLowerLayerUp, just a representative
// number of them
TEST_CASE(SUITE("ClosedState"))
{
    LinkLayerTest t;
    MockTransportSegment segment(250, "00", Addresses());
    REQUIRE_FALSE(t.upper->SendDown(segment));
    REQUIRE_FALSE(t.link.OnLowerLayerDown());
    REQUIRE_FALSE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, 1, 2));
}

// Prove that the upper layer is notified when the lower layer comes online
TEST_CASE(SUITE("ForwardsOnLowerLayerUp"))
{
    LinkLayerTest t;

    REQUIRE_FALSE(t.upper->IsOnline());
    REQUIRE(t.link.OnLowerLayerUp());
    REQUIRE(t.upper->IsOnline());
    REQUIRE_FALSE(t.link.OnLowerLayerUp());
}

// Check that once the layer comes up, validation errors can occur
TEST_CASE(SUITE("ValidatesMasterOutstationBit"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();
    t.OnFrame(LinkFunction::SEC_ACK, true, false, false, 1, 1024);
    REQUIRE(t.link.GetStatistics().numBadMasterBit == 1);
}

// Only process frames from your designated remote address
TEST_CASE(SUITE("ValidatesSourceAddress"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();
    t.OnFrame(LinkFunction::SEC_ACK, false, false, false, 1, 1023);
    REQUIRE(t.link.GetStatistics().numUnknownSource == 1);
}

// Only process frame addressed to you directly, or broadcast
TEST_CASE(SUITE("ValidatesDestinationAddress"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();
    t.OnFrame(LinkFunction::SEC_ACK, false, false, false, 2, 1024);
    REQUIRE(t.link.GetStatistics().numUnknownDestination == 1);
}

// Show that the base state of idle logs SecToPri frames as errors
TEST_CASE(SUITE("SecToPriNoContext"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();

    t.OnFrame(LinkFunction::SEC_ACK, false, false, false, 1, 1024);
    REQUIRE(t.link.GetStatistics().numUnexpectedFrame == 1);
}

TEST_CASE(SUITE("SelfAddressIsAnOptInDestinationOnly"), "[level4-self-address]")
{
    LinkConfig config(false);
    LinkLayerTest disabled(config);
    REQUIRE(disabled.link.OnLowerLayerUp());
    REQUIRE_FALSE(disabled.OnFrame(LinkFunction::PRI_REQUEST_LINK_STATUS, true, false, false, 0xFFFC, 1));
    REQUIRE(disabled.NumTotalWrites() == 0);

    config.acceptSelfAddress = true;
    LinkLayerTest enabled(config);
    REQUIRE(enabled.link.OnLowerLayerUp());
    REQUIRE_FALSE(enabled.OnFrame(LinkFunction::PRI_REQUEST_LINK_STATUS, true, false, false, 0xFFFC, 2));
    REQUIRE(enabled.NumTotalWrites() == 0);
    REQUIRE(enabled.OnFrame(LinkFunction::PRI_REQUEST_LINK_STATUS, true, false, false, 0xFFFC, 1));
    REQUIRE(enabled.PopLastWriteAsHex() == LinkHex::LinkStatus(false, false, 1, 1024));

    LinkLayerTest anySource(LinkLayerConfig(config, true));
    REQUIRE(anySource.link.OnLowerLayerUp());
    REQUIRE_FALSE(anySource.OnFrame(LinkFunction::PRI_REQUEST_LINK_STATUS, true, false, false, 1024, 0xFFFC));
    REQUIRE(anySource.NumTotalWrites() == 0);
}

// Show that the base state of idle forwards unconfirmed user data
TEST_CASE(SUITE("UnconfirmedDataPassedUpFromIdleUnreset"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();
    ByteStr bs(250, 0);
    t.OnFrame(LinkFunction::PRI_UNCONFIRMED_USER_DATA, false, false, false, 1, 1024, bs.ToRSeq());
    REQUIRE(t.upper->receivedQueue.size() == 1);
    REQUIRE(t.upper->receivedQueue.front() == bs.ToHex());
}

TEST_CASE(SUITE("SelfAddressUserDataUsesConfiguredDestination"), "[level4-self-address]")
{
    LinkConfig config(false);
    const ByteStr payload(2, 0);
    LinkLayerTest disabled(config);
    REQUIRE(disabled.link.OnLowerLayerUp());
    REQUIRE_FALSE(disabled.OnFrame(LinkFunction::PRI_UNCONFIRMED_USER_DATA, true, false, false, 0xFFFC,
                                   config.RemoteAddr, payload.ToRSeq()));
    REQUIRE(disabled.upper->receivedQueue.empty());

    config.acceptSelfAddress = true;
    LinkLayerTest enabled(LinkLayerConfig(config, true));
    REQUIRE(enabled.link.OnLowerLayerUp());
    REQUIRE_FALSE(enabled.OnFrame(LinkFunction::PRI_UNCONFIRMED_USER_DATA, true, false, false, config.LocalAddr,
                                  0xFFFC, payload.ToRSeq()));
    REQUIRE(enabled.upper->receivedQueue.empty());
    REQUIRE(enabled.OnFrame(LinkFunction::PRI_UNCONFIRMED_USER_DATA, true, false, false, 0xFFFC, config.RemoteAddr,
                            payload.ToRSeq()));
    REQUIRE(enabled.upper->receivedQueue.size() == 1);
    REQUIRE(enabled.upper->receivedQueue.front() == payload.ToHex());
    REQUIRE(enabled.upper->lastReceivedAddresses.source == config.RemoteAddr);
    REQUIRE(enabled.upper->lastReceivedAddresses.destination == config.LocalAddr);
}

// Show that the base state of idle forwards unconfirmed user data with broadcast address
TEST_CASE(SUITE("UnconfirmedBroadcastDataPassedUpFromIdleUnreset"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();
    ByteStr bs(250, 0);
    t.OnFrame(LinkFunction::PRI_UNCONFIRMED_USER_DATA, false, false, false, LinkBroadcastAddress::ShallConfirm, 1024,
              bs.ToRSeq());
    REQUIRE(t.upper->receivedQueue.size() == 1);
    REQUIRE(t.upper->receivedQueue.front() == bs.ToHex());
}

// Show that the base state of idle does not forward confirmed user data
TEST_CASE(SUITE("ConfirmedDataIgnoredFromIdleUnreset"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();
    ByteStr bs(250, 0);
    t.OnFrame(LinkFunction::PRI_CONFIRMED_USER_DATA, false, false, false, 1, 1024, bs.ToRSeq());
    REQUIRE(t.upper->receivedQueue.empty());
    REQUIRE(t.link.GetStatistics().numUnexpectedFrame == 1);
}

// Secondary Reset Links
TEST_CASE(SUITE("SecondaryResetLink"))
{
    LinkLayerTest t(LinkLayerTest::DefaultConfig());
    t.link.OnLowerLayerUp();
    t.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, false, false, false, 1, 1024);

    REQUIRE(t.NumTotalWrites() == 1);
    REQUIRE(t.PopLastWriteAsHex() == LinkHex::Ack(true, false, 1024, 1));
}

// Secondary Reset Links with broadcast address
TEST_CASE(SUITE("BroadcastSecondaryResetLink"))
{
    LinkLayerTest t(LinkLayerTest::DefaultConfig());
    t.link.OnLowerLayerUp();
    t.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, false, false, false, LinkBroadcastAddress::ShallConfirm, 1024);

    REQUIRE(t.NumTotalWrites() == 0);
    REQUIRE(t.link.GetStatistics().numUnexpectedFrame == 1);
}

// When we get another reset links when we're already reset,
// ACK it and reset the link state
TEST_CASE(SUITE("SecondaryResetResetLinkStates"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();
    t.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, false, false, false, 1, 1024);
    REQUIRE(t.NumTotalWrites() == 1);
    t.link.OnTxReady();

    t.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, false, false, false, 1, 1024);
    REQUIRE(t.NumTotalWrites() == 2);
    t.link.OnTxReady();

    REQUIRE(t.NumTotalWrites() == 2);
    REQUIRE(t.PopLastWriteAsHex() == LinkHex::Ack(true, false, 1024, 1));
}

TEST_CASE(SUITE("SecondaryResetConfirmedUserData"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();
    t.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, false, false, false, 1, 1024);
    REQUIRE(t.NumTotalWrites() == 1);
    t.link.OnTxReady();

    ByteStr bytes(250, 0);
    t.OnFrame(LinkFunction::PRI_CONFIRMED_USER_DATA, false, true, true, 1, 1024, bytes.ToRSeq());
    REQUIRE(t.NumTotalWrites() == 2);
    t.link.OnTxReady();

    REQUIRE(t.upper->receivedQueue.front() == bytes.ToHex());
    REQUIRE(t.PopLastWriteAsHex() == LinkHex::Ack(true, false, 1024, 1));
    t.upper->receivedQueue.clear();

    t.OnFrame(LinkFunction::PRI_CONFIRMED_USER_DATA, false, true, true, 1, 1024,
              bytes.ToRSeq());               // send with wrong FCB
    REQUIRE(t.NumTotalWrites() == 3);        // should still get an ACK
    REQUIRE(t.upper->receivedQueue.empty()); // but no data
    REQUIRE(t.PopLastWriteAsHex() == LinkHex::Ack(true, false, 1024, 1));
    REQUIRE(t.link.OnTxReady());
}

TEST_CASE(SUITE("RequestStatusOfLink"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();
    t.OnFrame(LinkFunction::PRI_REQUEST_LINK_STATUS, false, false, false, 1,
              1024); // should be able to request this before the link is reset
    REQUIRE(t.NumTotalWrites() == 1);
    t.link.OnTxReady();

    REQUIRE(t.PopLastWriteAsHex() == LinkHex::LinkStatus(true, false, 1024, 1));

    t.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, false, false, false, 1, 1024);
    REQUIRE(t.NumTotalWrites() == 2);
    t.link.OnTxReady();

    t.OnFrame(LinkFunction::PRI_REQUEST_LINK_STATUS, false, false, false, 1,
              1024); // should be able to request this before the link is reset
    REQUIRE(t.NumTotalWrites() == 3);
    REQUIRE(t.PopLastWriteAsHex() == LinkHex::LinkStatus(true, false, 1024, 1));
}

TEST_CASE(SUITE("BroadcastRequestStatusOfLink"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();
    t.OnFrame(LinkFunction::PRI_REQUEST_LINK_STATUS, false, false, false, LinkBroadcastAddress::ShallConfirm, 1024);
    REQUIRE(t.NumTotalWrites() == 0);
    REQUIRE(t.link.GetStatistics().numUnexpectedFrame == 1);
}

TEST_CASE(SUITE("TestLinkStates"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();
    t.OnFrame(LinkFunction::PRI_TEST_LINK_STATES, false, false, true, 1, 1024);
    REQUIRE(t.NumTotalWrites() == 0);

    t.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, false, false, false, 1, 1024);
    REQUIRE(t.NumTotalWrites() == 1);
    t.link.OnTxReady();

    t.OnFrame(LinkFunction::PRI_TEST_LINK_STATES, false, true, true, 1, 1024);

    REQUIRE(t.NumTotalWrites() == 2);
    REQUIRE(t.PopLastWriteAsHex() == LinkHex::Ack(true, false, 1024, 1));
    REQUIRE(t.link.OnTxReady());
}

TEST_CASE(SUITE("SecondaryTestLinkStatesRetransmitsAckForUnexpectedFCB"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();

    const auto ack = LinkHex::Ack(true, false, 1024, 1);
    REQUIRE(t.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, false, false, false, 1, 1024));
    REQUIRE(t.NumTotalWrites() == 1);
    REQUIRE(t.PopLastWriteAsHex() == ack);
    REQUIRE(t.link.OnTxReady());

    // FCB=1 is expected after reset. The resulting ACK is still the response to repeat
    // after an intervening LINK_STATUS response.
    REQUIRE(t.OnFrame(LinkFunction::PRI_TEST_LINK_STATES, false, true, true, 1, 1024));
    REQUIRE(t.NumTotalWrites() == 2);
    REQUIRE(t.PopLastWriteAsHex() == ack);
    REQUIRE(t.link.OnTxReady());

    REQUIRE(t.OnFrame(LinkFunction::PRI_REQUEST_LINK_STATUS, false, false, false, 1, 1024));
    REQUIRE(t.NumTotalWrites() == 3);
    REQUIRE(t.PopLastWriteAsHex() == LinkHex::LinkStatus(true, false, 1024, 1));
    REQUIRE(t.link.OnTxReady());

    // FCB=1 is now unexpected. It repeats the earlier ACK and must leave FCB=0 expected.
    REQUIRE(t.OnFrame(LinkFunction::PRI_TEST_LINK_STATES, false, true, true, 1, 1024));
    REQUIRE(t.NumTotalWrites() == 4);
    REQUIRE(t.PopLastWriteAsHex() == ack);
    REQUIRE(t.link.OnTxReady());

    ByteStr first(1, 0xAA);
    REQUIRE(t.OnFrame(
        LinkFunction::PRI_CONFIRMED_USER_DATA, false, false, true, 1, 1024, first.ToRSeq()));
    REQUIRE(t.NumTotalWrites() == 5);
    REQUIRE(t.upper->receivedQueue.size() == 1);
    REQUIRE(t.upper->receivedQueue.front() == first.ToHex());
    REQUIRE(t.PopLastWriteAsHex() == ack);
    REQUIRE(t.link.OnTxReady());

    // Repeat the same unexpected FCB. Each request must repeat the ACK without advancing FCB.
    for (uint32_t i = 0; i < 3; ++i)
    {
        REQUIRE(t.OnFrame(LinkFunction::PRI_TEST_LINK_STATES, false, false, true, 1, 1024));
        REQUIRE(t.NumTotalWrites() == 6 + i);
        REQUIRE(t.PopLastWriteAsHex() == ack);
        REQUIRE(t.link.OnTxReady());
    }

    ByteStr second(1, 0xBB);
    REQUIRE(t.OnFrame(
        LinkFunction::PRI_CONFIRMED_USER_DATA, false, true, true, 1, 1024, second.ToRSeq()));
    REQUIRE(t.NumTotalWrites() == 9);
    REQUIRE(t.upper->receivedQueue.size() == 2);
    REQUIRE(t.upper->receivedQueue.back() == second.ToHex());
    REQUIRE(t.PopLastWriteAsHex() == ack);
    REQUIRE(t.link.OnTxReady());

    // A correct TEST_LINK_STATES advances once; the next confirmed FCB=1 is accepted.
    REQUIRE(t.OnFrame(LinkFunction::PRI_TEST_LINK_STATES, false, false, true, 1, 1024));
    REQUIRE(t.NumTotalWrites() == 10);
    REQUIRE(t.PopLastWriteAsHex() == ack);
    REQUIRE(t.link.OnTxReady());

    ByteStr third(1, 0xCC);
    REQUIRE(t.OnFrame(
        LinkFunction::PRI_CONFIRMED_USER_DATA, false, true, true, 1, 1024, third.ToRSeq()));
    REQUIRE(t.NumTotalWrites() == 11);
    REQUIRE(t.upper->receivedQueue.size() == 3);
    REQUIRE(t.upper->receivedQueue.back() == third.ToHex());
    REQUIRE(t.PopLastWriteAsHex() == ack);
    REQUIRE(t.link.OnTxReady());

    // Resetting again restores expected FCB=1.
    REQUIRE(t.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, false, false, false, 1, 1024));
    REQUIRE(t.NumTotalWrites() == 12);
    REQUIRE(t.PopLastWriteAsHex() == ack);
    REQUIRE(t.link.OnTxReady());

    ByteStr fourth(1, 0xDD);
    REQUIRE(t.OnFrame(
        LinkFunction::PRI_CONFIRMED_USER_DATA, false, true, true, 1, 1024, fourth.ToRSeq()));
    REQUIRE(t.NumTotalWrites() == 13);
    REQUIRE(t.upper->receivedQueue.size() == 4);
    REQUIRE(t.upper->receivedQueue.back() == fourth.ToHex());
    REQUIRE(t.PopLastWriteAsHex() == ack);
    REQUIRE(t.link.OnTxReady());

    const auto writes = t.NumTotalWrites();
    REQUIRE_FALSE(t.OnFrame(LinkFunction::PRI_TEST_LINK_STATES, false, false, true, 1, 1023));
    REQUIRE_FALSE(t.OnFrame(LinkFunction::PRI_TEST_LINK_STATES, false, false, true, 2, 1024));
    REQUIRE(t.NumTotalWrites() == writes);
}

TEST_CASE(SUITE("BroadcastTestLinkStates"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();
    t.OnFrame(LinkFunction::PRI_TEST_LINK_STATES, false, false, false, LinkBroadcastAddress::ShallConfirm, 1024);
    REQUIRE(t.NumTotalWrites() == 0);
    REQUIRE(t.link.GetStatistics().numUnexpectedFrame == 1);
}

TEST_CASE(SUITE("SendUnconfirmed"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();

    MockTransportSegment segment(250, HexConversions::increment_hex(0, 250), Addresses());
    t.link.Send(segment);
    REQUIRE(t.NumTotalWrites() == 1);
    t.link.OnTxReady();

    REQUIRE(t.exe->run_many() > 0);

    REQUIRE(t.upper->GetCounters().numTxReady == 1);
    REQUIRE(t.NumTotalWrites() == 1);
}

TEST_CASE(SUITE("Outbound confirmation modes select eligible single and multi-frame sends"))
{
    const LinkConfirmMode modes[] = {
        LinkConfirmMode::Never, LinkConfirmMode::Always, LinkConfirmMode::MultiFrame};
    const bool frameCounts[] = {false, true};

    for (const auto mode : modes)
    {
        for (const auto multiFrame : frameCounts)
        {
            LinkConfig config(true);
            config.ConfirmMode = mode;
            config.Timeout = TimeDuration::Milliseconds(10);
            LinkLayerTest t(config);
            REQUIRE(t.link.OnLowerLayerUp());

            MockTransportSegment segments(multiFrame ? 1 : 2, "AA BB", config.GetAddresses());
            REQUIRE(t.upper->SendDown(segments));

            const bool confirmed = mode == LinkConfirmMode::Always
                || (mode == LinkConfirmMode::MultiFrame && multiFrame);
            if (confirmed)
            {
                REQUIRE(t.PopLastWriteAsHex()
                        == LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr));
                REQUIRE(t.link.OnTxReady());
                REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
            }

            const auto numFrames = multiFrame ? 2 : 1;
            for (size_t i = 0; i < numFrames; ++i)
            {
                const auto payload = multiFrame ? (i == 0 ? "AA" : "BB") : "AA BB";
                const auto expected = confirmed
                    ? LinkHex::ConfirmedUserData(true, i == 0, config.RemoteAddr, config.LocalAddr, payload)
                    : LinkHex::UnconfirmedUserData(true, config.RemoteAddr, config.LocalAddr, payload);
                REQUIRE(t.PopLastWriteAsHex() == expected);
                REQUIRE(t.link.OnTxReady());
                if (confirmed)
                {
                    REQUIRE(
                        t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
                }
            }

            REQUIRE(t.exe->run_many() > 0);
            REQUIRE(t.upper->GetCounters().numTxReady == 1);
            const auto writes = t.NumTotalWrites();
            REQUIRE(t.exe->advance_time(std::chrono::milliseconds(10)) == 0);
            REQUIRE(t.NumTotalWrites() == writes);
        }
    }
}

TEST_CASE("AT-CFG-05-RETRY", "[rtu-acceptance][confirmed-link]")
{
    const uint8_t retryLimits[] = {0, 1, 5};
    const auto timeout = std::chrono::milliseconds(10);

    for (size_t i = 0; i < sizeof(retryLimits) / sizeof(retryLimits[0]); ++i)
    {
        if (!acceptance::Selected(("V" + std::to_string(i + 1)).c_str())) continue;
        const auto retries = retryLimits[i];
        LinkConfig config(true);
        config.ConfirmMode = LinkConfirmMode::Always;
        config.NumRetries = retries;
        config.Timeout = TimeDuration::Milliseconds(10);
        config.KeepAliveTimeout = TimeDuration::Seconds(60);
        LinkLayerTest t(config);
        REQUIRE(t.link.OnLowerLayerUp());

        MockTransportSegment segments(1, "AA", config.GetAddresses());
        REQUIRE(t.upper->SendDown(segments));
        const auto initial = LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr);
        REQUIRE(t.PopLastWriteAsHex() == initial);

        REQUIRE(t.exe->advance_time(timeout) == 0);
        REQUIRE(t.NumTotalWrites() == 1);

        for (uint8_t attempt = 0; attempt <= retries; ++attempt)
        {
            REQUIRE(t.link.OnTxReady());
            REQUIRE(t.exe->advance_time(timeout) > 0);
            REQUIRE(t.exe->run_many() > 0);
            if (attempt < retries)
            {
                REQUIRE(t.PopLastWriteAsHex() == initial);
                REQUIRE(t.NumTotalWrites() == static_cast<uint32_t>(attempt + 2));
            }
            else
            {
                REQUIRE(t.NumTotalWrites() == static_cast<uint32_t>(retries + 1));
                REQUIRE(t.exe->advance_time(timeout) == 0);
                REQUIRE(t.NumTotalWrites() == static_cast<uint32_t>(retries + 1));
                MockTransportSegment additional(1, "BB", config.GetAddresses());
                REQUIRE_FALSE(t.upper->SendDown(additional));
            }
        }

        REQUIRE(t.upper->GetCounters().numTxReady == 0);
        acceptance::Observe("reset_transmissions", t.NumTotalWrites());

        // Allow the reset, then lose every data ACK. The receiver ACKs the
        // repeated FCB and delivers only the first copy, even in Never mode.
        LinkConfig rx(false);
        rx.LocalAddr = config.RemoteAddr;
        rx.RemoteAddr = config.LocalAddr;
        LinkLayerTest receiver(rx);
        LinkLayerTest sender(config);
        REQUIRE(receiver.link.OnLowerLayerUp());
        REQUIRE(sender.link.OnLowerLayerUp());
        const ByteStr payload(1, 0xAA);
        MockTransportSegment data(1, "AA", config.GetAddresses());
        REQUIRE(sender.upper->SendDown(data));
        REQUIRE(sender.PopLastWriteAsHex() == initial);
        REQUIRE(receiver.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, true, false, false, rx.LocalAddr, rx.RemoteAddr));
        const auto ack = LinkHex::Ack(false, false, rx.RemoteAddr, rx.LocalAddr);
        REQUIRE(receiver.PopLastWriteAsHex() == ack);
        REQUIRE(receiver.link.OnTxReady());
        // A reset ACK may arrive before the sender's own completion callback.
        REQUIRE(sender.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
        REQUIRE(sender.link.OnTxReady());
        const auto frame = LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA");
        for (uint8_t attempt = 0; attempt <= retries; ++attempt)
        {
            REQUIRE(sender.PopLastWriteAsHex() == frame);
            REQUIRE(receiver.OnFrame(LinkFunction::PRI_CONFIRMED_USER_DATA, true, true, true, rx.LocalAddr,
                                     rx.RemoteAddr, payload.ToRSeq()));
            REQUIRE(receiver.PopLastWriteAsHex() == ack);
            REQUIRE(receiver.link.OnTxReady());
            REQUIRE(sender.link.OnTxReady());
            sender.exe->advance_time(timeout);
            sender.exe->run_many();
        }
        REQUIRE(sender.NumTotalWrites() == retries + 2);
        REQUIRE(sender.NumTransmitFailures() == 1);
        REQUIRE(sender.upper->GetCounters().numTxReady == 0);
        REQUIRE(receiver.upper->receivedQueue.size() == 1);
        REQUIRE(receiver.upper->receivedQueue.front() == "AA");
        acceptance::Observe("data_transmissions", sender.NumTotalWrites() - 1);
        acceptance::Observe("sender_completions", sender.upper->GetCounters().numTxReady);
        acceptance::Observe("receiver_deliveries", receiver.upper->receivedQueue.size());
    }
    if (acceptance::Selected("V4"))
    {
        LinkConfig config(true);
        config.ConfirmMode = LinkConfirmMode::Always;
        config.NumRetries = 6;
        REQUIRE_THROWS_AS(LinkLayerTest(config), std::invalid_argument);
        acceptance::Observe("invalid_retry_limit_rejected", 1);
    }
}

TEST_CASE(SUITE("ConfirmedLinkRetryStartsAtTheConfiguredDeadline"))
{
    const auto arrival = GENERATE(9, 10, 11);
    LinkConfig config(true);
    config.ConfirmMode = LinkConfirmMode::Always;
    config.NumRetries = 1;
    config.Timeout = TimeDuration::Milliseconds(10);
    config.KeepAliveTimeout = TimeDuration::Seconds(60);
    LinkLayerTest t(config);
    REQUIRE(t.link.OnLowerLayerUp());

    MockTransportSegment segments(1, "AA", config.GetAddresses());
    REQUIRE(t.upper->SendDown(segments));
    const auto reset = LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr);
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.link.OnTxReady());
    t.exe->advance_time(std::chrono::milliseconds(arrival));
    t.exe->run_many();
    REQUIRE(t.NumTotalWrites() == (arrival < 10 ? 1u : 2u));
    if (arrival >= 10)
        REQUIRE(t.PopLastWriteAsHex() == reset);
}

TEST_CASE(SUITE("Confirmed NACK DFC zero recovers once per logical send"))
{
    LinkConfig config(true);
    config.ConfirmMode = LinkConfirmMode::Always;
    config.NumRetries = 0;
    config.Timeout = TimeDuration::Milliseconds(10);
    config.KeepAliveTimeout = TimeDuration::Seconds(60);
    LinkLayerTest t(config);
    REQUIRE(t.link.OnLowerLayerUp());

    MockTransportSegment first(1, "AA", config.GetAddresses());
    REQUIRE(t.upper->SendDown(first));
    const auto reset = LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr);
    const auto firstData = LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA");
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex() == firstData);
    REQUIRE(t.link.OnTxReady());

    REQUIRE(t.OnFrame(LinkFunction::SEC_NACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.NumTotalWrites() == 3);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex() == firstData);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.upper->GetCounters().numTxReady == 1);
    REQUIRE(t.NumTransmitFailures() == 0);

    // A completed send gets a new recovery allowance and continues with the synchronized FCB.
    MockTransportSegment second(1, "BB", config.GetAddresses());
    REQUIRE(t.upper->SendDown(second));
    const auto secondData = LinkHex::ConfirmedUserData(true, false, config.RemoteAddr, config.LocalAddr, "BB");
    REQUIRE(t.PopLastWriteAsHex() == secondData);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_NACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex()
            == LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "BB"));
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.upper->GetCounters().numTxReady == 2);
    REQUIRE(t.NumTransmitFailures() == 0);
}

TEST_CASE(SUITE("Confirmed DFC one and reset NACK fail without recovery"))
{
    LinkConfig config(true);
    config.ConfirmMode = LinkConfirmMode::Always;
    config.NumRetries = 1;
    config.Timeout = TimeDuration::Milliseconds(10);
    config.KeepAliveTimeout = TimeDuration::Seconds(60);
    const auto reset = LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr);

    SECTION("ACK DFC one fails the user-data transaction")
    {
        LinkLayerTest t(config);
        REQUIRE(t.link.OnLowerLayerUp());
        MockTransportSegment segments(1, "AA BB", config.GetAddresses());
        REQUIRE(t.upper->SendDown(segments));
        REQUIRE(t.PopLastWriteAsHex() == reset);
        REQUIRE(t.link.OnTxReady());
        REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
        REQUIRE(t.PopLastWriteAsHex()
                == LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA"));
        REQUIRE(t.link.OnTxReady());

        REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, true, config.LocalAddr, config.RemoteAddr));
        REQUIRE(t.NumTotalWrites() == 2);
        REQUIRE(t.NumTransmitFailures() == 1);
        REQUIRE(t.upper->GetCounters().numTxReady == 0);
        REQUIRE_FALSE(t.upper->SendDown(segments));
    }

    SECTION("NACK DFC one fails without a busy retry")
    {
        LinkLayerTest t(config);
        REQUIRE(t.link.OnLowerLayerUp());
        MockTransportSegment segments(1, "AA", config.GetAddresses());
        REQUIRE(t.upper->SendDown(segments));
        REQUIRE(t.PopLastWriteAsHex() == reset);
        REQUIRE(t.link.OnTxReady());
        REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
        REQUIRE(t.PopLastWriteAsHex()
                == LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA"));
        REQUIRE(t.link.OnTxReady());

        REQUIRE(t.OnFrame(LinkFunction::SEC_NACK, false, false, true, config.LocalAddr, config.RemoteAddr));
        REQUIRE(t.NumTotalWrites() == 2);
        REQUIRE(t.NumTransmitFailures() == 1);
        REQUIRE(t.upper->GetCounters().numTxReady == 0);
    }

    SECTION("NACK during reset synchronization does not recursively reset")
    {
        LinkLayerTest t(config);
        REQUIRE(t.link.OnLowerLayerUp());
        MockTransportSegment segments(1, "AA", config.GetAddresses());
        REQUIRE(t.upper->SendDown(segments));
        REQUIRE(t.PopLastWriteAsHex() == reset);
        REQUIRE(t.link.OnTxReady());

        REQUIRE(t.OnFrame(LinkFunction::SEC_NACK, false, false, false, config.LocalAddr, config.RemoteAddr));
        REQUIRE(t.NumTotalWrites() == 1);
        REQUIRE(t.NumTransmitFailures() == 1);
        REQUIRE(t.upper->GetCounters().numTxReady == 0);
    }

    SECTION("NACK during recovery reset does not start another reset")
    {
        LinkLayerTest t(config);
        REQUIRE(t.link.OnLowerLayerUp());
        MockTransportSegment segments(1, "AA", config.GetAddresses());
        REQUIRE(t.upper->SendDown(segments));
        REQUIRE(t.PopLastWriteAsHex() == reset);
        REQUIRE(t.link.OnTxReady());
        REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
        REQUIRE(t.PopLastWriteAsHex()
                == LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA"));
        REQUIRE(t.link.OnTxReady());

        REQUIRE(t.OnFrame(LinkFunction::SEC_NACK, false, false, false, config.LocalAddr, config.RemoteAddr));
        REQUIRE(t.PopLastWriteAsHex() == reset);
        REQUIRE(t.link.OnTxReady());
        REQUIRE(t.OnFrame(LinkFunction::SEC_NACK, false, false, false, config.LocalAddr, config.RemoteAddr));
        REQUIRE(t.NumTotalWrites() == 3);
        REQUIRE(t.NumTransmitFailures() == 1);
        REQUIRE(t.upper->GetCounters().numTxReady == 0);
    }
}

TEST_CASE("AT-CFG-05-DFC", "[rtu-acceptance][confirmed-link]")
{
    const std::array<LinkFunction, 4> functions{{LinkFunction::SEC_ACK, LinkFunction::SEC_NACK,
                                                 LinkFunction::SEC_NOT_SUPPORTED, LinkFunction::SEC_LINK_STATUS}};
    for (size_t i = 0; i < functions.size(); ++i)
    {
        if (!acceptance::Selected(("V" + std::to_string(i + 1)).c_str())) continue;
        LinkConfig config(true);
        config.ConfirmMode = LinkConfirmMode::Always;
        config.Timeout = TimeDuration::Milliseconds(10);
        LinkLayerTest t(config);
        REQUIRE(t.link.OnLowerLayerUp());
        MockTransportSegment segments(1, "AA", config.GetAddresses());
        REQUIRE(t.upper->SendDown(segments));
        REQUIRE(t.PopLastWriteAsHex() == LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr));
        REQUIRE(t.link.OnTxReady());
        REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
        REQUIRE(t.PopLastWriteAsHex() == LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA"));
        REQUIRE(t.link.OnTxReady());
        REQUIRE(t.OnFrame(functions[i], false, false, true, config.LocalAddr, config.RemoteAddr));
        REQUIRE(t.upper->GetCounters().numTxReady == 0);
        REQUIRE(t.NumTransmitFailures() == (i == 3 ? 0 : 1));
        acceptance::Observe("failures_before_timeout", t.NumTransmitFailures());
        t.exe->advance_time(std::chrono::milliseconds(10));
        t.exe->run_many();
        REQUIRE(t.NumTotalWrites() == 2);
        REQUIRE(t.NumTransmitFailures() == 1);
        REQUIRE(t.upper->GetCounters().numTxReady == 0);
        acceptance::Observe("failures_after_timeout", t.NumTransmitFailures());
        acceptance::Observe("sender_completions", t.upper->GetCounters().numTxReady);
    }
}

TEST_CASE("AT-CFG-05-BCAST", "[rtu-acceptance][confirmed-link]")
{
    LinkConfig master(true);
    master.ConfirmMode = LinkConfirmMode::Always;
    LinkLayerTest tx(master);
    REQUIRE(tx.link.OnLowerLayerUp());
    for (uint16_t address : {uint16_t(LinkBroadcastAddress::ShallConfirm), uint16_t(LinkSelfAddress)})
    {
        MockTransportSegment segment(1, "AA", Addresses(master.LocalAddr, address));
        REQUIRE(tx.upper->SendDown(segment));
        REQUIRE(tx.PopLastWriteAsHex() == LinkHex::UnconfirmedUserData(true, address, master.LocalAddr, "AA"));
        REQUIRE(tx.link.OnTxReady());
        tx.exe->run_many();
    }
    acceptance::Observe("unconfirmed_transmissions", tx.NumTotalWrites());

    LinkConfig outstation(false);
    outstation.acceptSelfAddress = true;
    LinkLayerTest rx(outstation);
    REQUIRE(rx.link.OnLowerLayerUp());
    REQUIRE(rx.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, true, false, false, outstation.LocalAddr, outstation.RemoteAddr));
    REQUIRE(rx.link.OnTxReady());
    const ByteStr bytes(1, 0xAB);
    for (unsigned copy = 0; copy < 2; ++copy)
        REQUIRE(rx.OnFrame(LinkFunction::PRI_CONFIRMED_USER_DATA, true, true, true, LinkBroadcastAddress::ShallConfirm,
                           outstation.RemoteAddr, bytes.ToRSeq()));
    REQUIRE(rx.NumTotalWrites() == 1);
    REQUIRE(rx.upper->receivedQueue.size() == 1);
    REQUIRE(rx.upper->receivedQueue.front() == "AB");
    acceptance::Observe("broadcast_link_acks", rx.NumTotalWrites() - 1);
    acceptance::Observe("broadcast_deliveries", rx.upper->receivedQueue.size());
    REQUIRE(rx.OnFrame(LinkFunction::PRI_UNCONFIRMED_USER_DATA, true, false, false, LinkSelfAddress,
                        outstation.RemoteAddr, bytes.ToRSeq()));
    REQUIRE(rx.upper->receivedQueue.size() == 2);
    REQUIRE(rx.upper->lastReceivedAddresses.destination == outstation.LocalAddr);
    REQUIRE(rx.OnFrame(LinkFunction::PRI_CONFIRMED_USER_DATA, true, false, true, outstation.LocalAddr,
                        outstation.RemoteAddr, bytes.ToRSeq()));
    REQUIRE(rx.NumTotalWrites() == 2);
    REQUIRE(rx.upper->receivedQueue.size() == 3);
    acceptance::Observe("unicast_deliveries", rx.upper->receivedQueue.size() - 2);
}

TEST_CASE(SUITE("Confirmed recovery allowance is shared across segments"))
{
    LinkConfig config(true);
    config.ConfirmMode = LinkConfirmMode::Always;
    config.NumRetries = 1;
    config.Timeout = TimeDuration::Milliseconds(10);
    config.KeepAliveTimeout = TimeDuration::Seconds(60);
    LinkLayerTest t(config);
    REQUIRE(t.link.OnLowerLayerUp());

    MockTransportSegment segments(1, "AA BB", config.GetAddresses());
    REQUIRE(t.upper->SendDown(segments));
    const auto reset = LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr);
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));

    const auto firstData = LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA");
    REQUIRE(t.PopLastWriteAsHex() == firstData);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_NACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex() == firstData);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));

    const auto secondData = LinkHex::ConfirmedUserData(true, false, config.RemoteAddr, config.LocalAddr, "BB");
    REQUIRE(t.PopLastWriteAsHex() == secondData);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_NACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.NumTotalWrites() == 5);
    REQUIRE(t.NumTransmitFailures() == 1);
    REQUIRE(t.upper->GetCounters().numTxReady == 0);
}

TEST_CASE(SUITE("Confirmed reset recovery timeout remains bounded"))
{
    LinkConfig config(true);
    config.ConfirmMode = LinkConfirmMode::Always;
    config.NumRetries = 1;
    config.Timeout = TimeDuration::Milliseconds(10);
    config.KeepAliveTimeout = TimeDuration::Seconds(60);
    LinkLayerTest t(config);
    REQUIRE(t.link.OnLowerLayerUp());

    MockTransportSegment segments(1, "AA", config.GetAddresses());
    REQUIRE(t.upper->SendDown(segments));
    const auto reset = LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr);
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex()
            == LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA"));
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_NACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex() == reset);

    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.exe->advance_time(std::chrono::milliseconds(10)) > 0);
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.NumTotalWrites() == 4);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.exe->advance_time(std::chrono::milliseconds(10)) > 0);
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.NumTotalWrites() == 4);
    REQUIRE(t.NumTransmitFailures() == 1);
    REQUIRE(t.upper->GetCounters().numTxReady == 0);
}

TEST_CASE(SUITE("Confirmed early NACK waits for TX completion and reconnect resets recovery"))
{
    LinkConfig config(true);
    config.ConfirmMode = LinkConfirmMode::Always;
    config.NumRetries = 0;
    config.Timeout = TimeDuration::Milliseconds(10);
    config.KeepAliveTimeout = TimeDuration::Seconds(60);
    LinkLayerTest t(config);
    REQUIRE(t.link.OnLowerLayerUp());

    MockTransportSegment first(1, "AA", config.GetAddresses());
    REQUIRE(t.upper->SendDown(first));
    const auto reset = LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr);
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.exe->advance_time(std::chrono::milliseconds(10)) == 0);
    REQUIRE(t.link.OnTxReady());

    const auto firstData = LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA");
    REQUIRE(t.PopLastWriteAsHex() == firstData);
    REQUIRE(t.OnFrame(LinkFunction::SEC_NACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.exe->advance_time(std::chrono::milliseconds(10)) == 0);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex() == firstData);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.upper->GetCounters().numTxReady == 1);

    REQUIRE(t.link.OnLowerLayerDown());
    REQUIRE(t.link.OnLowerLayerUp());
    MockTransportSegment second(1, "BB", config.GetAddresses());
    REQUIRE(t.upper->SendDown(second));
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    const auto secondData = LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "BB");
    REQUIRE(t.PopLastWriteAsHex() == secondData);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_NACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex() == secondData);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.upper->GetCounters().numTxReady == 2);
    REQUIRE(t.NumTransmitFailures() == 0);
}

TEST_CASE(SUITE("Confirmed frames retain bytes and FCB until ACK"))
{
    LinkConfig config(true);
    config.ConfirmMode = LinkConfirmMode::Always;
    config.NumRetries = 1;
    config.Timeout = TimeDuration::Milliseconds(10);
    config.KeepAliveTimeout = TimeDuration::Seconds(60);
    LinkLayerTest t(config);
    REQUIRE(t.link.OnLowerLayerUp());

    MockTransportSegment segments(1, "AA BB", config.GetAddresses());
    REQUIRE(t.upper->SendDown(segments));
    REQUIRE(t.PopLastWriteAsHex() == LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr));
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));

    const auto first = LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA");
    REQUIRE(t.PopLastWriteAsHex() == first);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.exe->advance_time(std::chrono::milliseconds(10)) > 0);
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.PopLastWriteAsHex() == first);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));

    REQUIRE(t.PopLastWriteAsHex()
            == LinkHex::ConfirmedUserData(true, false, config.RemoteAddr, config.LocalAddr, "BB"));
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.upper->GetCounters().numTxReady == 1);
}

TEST_CASE("AT-CFG-05-OWNER", "[rtu-acceptance][confirmed-link]")
{
    LinkConfig config(true);
    config.ConfirmMode = LinkConfirmMode::Always;
    config.NumRetries = 1;
    config.Timeout = TimeDuration::Milliseconds(10);
    config.KeepAliveTimeout = TimeDuration::Seconds(60);
    LinkLayerTest t(config);
    REQUIRE(t.link.OnLowerLayerUp());

    MockTransportSegment segments(1, "AA", config.GetAddresses());
    REQUIRE(t.upper->SendDown(segments));
    const auto reset = LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr);
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.link.OnTxReady());

    REQUIRE_FALSE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, 999));
    REQUIRE_FALSE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr + 1, config.RemoteAddr));
    REQUIRE_FALSE(t.OnFrame(LinkFunction::SEC_ACK, true, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE_FALSE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, LinkBroadcastAddress::ShallConfirm,
                            config.RemoteAddr));
    REQUIRE(t.OnFrame(LinkFunction::SEC_LINK_STATUS, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.NumTotalWrites() == 1);
    acceptance::Observe("reset_transmissions_before_timeout", t.NumTotalWrites());
    REQUIRE(t.exe->advance_time(std::chrono::milliseconds(10)) > 0);
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.PopLastWriteAsHex() == reset);

    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex()
            == LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA"));
    REQUIRE(t.link.OnTxReady());
    REQUIRE_FALSE(t.OnFrame(LinkFunction::SEC_NACK, false, false, false, config.LocalAddr, 999));
    REQUIRE(t.OnFrame(LinkFunction::SEC_LINK_STATUS, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.NumTotalWrites() == 3);
    REQUIRE(t.exe->advance_time(std::chrono::milliseconds(10)) > 0);
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.PopLastWriteAsHex()
            == LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA"));
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.upper->GetCounters().numTxReady == 1);
    REQUIRE(t.exe->advance_time(std::chrono::milliseconds(20)) == 0);
    REQUIRE(t.NumTotalWrites() == 4);
    REQUIRE(t.upper->receivedQueue.empty());
    acceptance::Observe("transmissions", t.NumTotalWrites());
    acceptance::Observe("sender_completions", t.upper->GetCounters().numTxReady);
    acceptance::Observe("foreign_deliveries", t.upper->receivedQueue.size());
}

TEST_CASE(SUITE("Confirmed ACK received before TX callback completes the reset exchange"))
{
    LinkConfig config(true);
    config.ConfirmMode = LinkConfirmMode::Always;
    LinkLayerTest t(config);
    REQUIRE(t.link.OnLowerLayerUp());

    MockTransportSegment segments(1, "AA", config.GetAddresses());
    REQUIRE(t.upper->SendDown(segments));
    REQUIRE(t.PopLastWriteAsHex() == LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr));
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.NumTotalWrites() == 1);

    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.PopLastWriteAsHex()
            == LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA"));
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.upper->GetCounters().numTxReady == 1);
}

TEST_CASE(SUITE("Confirmed reconnect starts with reset handshake and fresh retry budget"))
{
    LinkConfig config(true);
    config.ConfirmMode = LinkConfirmMode::Always;
    config.NumRetries = 1;
    config.Timeout = TimeDuration::Milliseconds(10);
    config.KeepAliveTimeout = TimeDuration::Seconds(60);
    LinkLayerTest t(config);
    REQUIRE(t.link.OnLowerLayerUp());

    MockTransportSegment first(1, "AA", config.GetAddresses());
    REQUIRE(t.upper->SendDown(first));
    REQUIRE(t.PopLastWriteAsHex() == LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr));
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex()
            == LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA"));
    REQUIRE(t.link.OnTxReady());

    REQUIRE(t.link.OnLowerLayerDown());
    REQUIRE(t.exe->advance_time(std::chrono::milliseconds(20)) == 0);
    REQUIRE(t.NumTotalWrites() == 2);
    REQUIRE(t.upper->GetCounters().numTxReady == 0);
    REQUIRE(t.link.OnLowerLayerUp());

    MockTransportSegment second(1, "BB", config.GetAddresses());
    REQUIRE(t.upper->SendDown(second));
    const auto reset = LinkHex::ResetLinkStates(true, config.RemoteAddr, config.LocalAddr);
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.exe->advance_time(std::chrono::milliseconds(10)) > 0);
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.PopLastWriteAsHex() == reset);
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex()
            == LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "BB"));
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.upper->GetCounters().numTxReady == 1);
}

TEST_CASE(SUITE("CloseBehavior"))
{
    LinkLayerTest t;
    t.link.OnLowerLayerUp();

    MockTransportSegment segments(250, HexConversions::increment_hex(0, 250), Addresses());
    t.link.Send(segments);
    t.link.OnTxReady();

    REQUIRE(t.exe->run_many() > 0);

    t.link.OnLowerLayerDown(); // take it down during the middle of a send
    REQUIRE_FALSE(t.upper->IsOnline());

    t.link.OnLowerLayerUp();
    REQUIRE(t.upper->IsOnline());
    segments.Reset();
    t.link.Send(segments);
    REQUIRE(t.NumTotalWrites() == 2);
}

// ---------------------------------------------------------------------------
// DIAG-CFG-05-STALE-ACK-CORRELATION
//
// Diagnostic characterisation only. This case records what the link layer does
// with a delayed ACK; it is not acceptance evidence, it emits no acceptance
// observations, and it must not be read as closing AT-CFG-05-STALE.
// AT-CFG-05-STALE (CFG-05, "STALE state transition") stays UNRESOLVED: the
// property under test, "no false completion in the allowed timing window", is
// not achievable on this wire format, and this case demonstrates the opposite.
//
// A secondary frame (SEC_ACK / SEC_NACK / SEC_LINK_STATUS) carries no frame
// identity: no sequence number, no echo of the FCB it acknowledges and no
// payload reference. Every ACK emitted for a confirmed user data frame on one
// pair of link addresses is therefore the same LPDU, and a retransmission
// repeats the original octets with the same FCB (IEEE 1815-2012 9.3.1 / 9.3.2
// and Table 9-6). The sending station has no wire information that would let it
// decide whether an arriving ACK answers the frame currently outstanding or an
// earlier transmission of that same frame.
//
// Evidence boundary: the "peer" below is a second instance of this same
// LinkLayerTest fixture, not an independently implemented DNP3 station, and
// every inbound frame is injected as already-parsed link header fields plus
// LSDU through LinkLayerTest::OnFrame. No raw LPDU is encoded, decoded or
// CRC-checked, so these cases characterise state handling only. They assert
// what is demonstrable in that fixture: the repeated frame and the repeated ACK
// are byte-identical, the peer keeps FCB de-duplication, and the stack
// completes a two-segment send on an ACK produced for the first segment.
// See RESULT.md for the timeline, the counterexample and the open decision.
// ---------------------------------------------------------------------------
TEST_CASE("DIAG-CFG-05-STALE-ACK-CORRELATION",
          "[diagnostic][characterization][confirmed-link][at-cfg-05-stale-unresolved]")
{
    // A stale ACK has to be overtaken by a retry, so the exposure starts at
    // NumRetries = 1; the field is bounded to 0..5 by LinkContext.
    const auto timeout = std::chrono::milliseconds(10);

    LinkConfig master(true);
    master.ConfirmMode = LinkConfirmMode::Always;
    master.NumRetries = 1;
    master.Timeout = TimeDuration::Milliseconds(10);
    master.KeepAliveTimeout = TimeDuration::Seconds(60);

    LinkConfig outstation(false);
    outstation.LocalAddr = master.RemoteAddr;
    outstation.RemoteAddr = master.LocalAddr;

    const auto reset = LinkHex::ResetLinkStates(true, master.RemoteAddr, master.LocalAddr);
    const auto ack = LinkHex::Ack(false, false, outstation.RemoteAddr, outstation.LocalAddr);
    const auto firstFrame = LinkHex::ConfirmedUserData(true, true, master.RemoteAddr, master.LocalAddr, "AA");
    const auto secondFrame = LinkHex::ConfirmedUserData(true, false, master.RemoteAddr, master.LocalAddr, "BB");
    const ByteStr firstPayload(1, 0xAA);
    const ByteStr secondPayload(1, 0xBB);

    SECTION("delayed ACK is accepted as the answer to the retransmission")
    {
        LinkLayerTest sender(master);
        LinkLayerTest receiver(outstation);
        REQUIRE(sender.link.OnLowerLayerUp());
        REQUIRE(receiver.link.OnLowerLayerUp());

        MockTransportSegment segments(1, "AA BB", master.GetAddresses());
        REQUIRE(sender.upper->SendDown(segments));

        // Link reset and its ACK.
        REQUIRE(sender.PopLastWriteAsHex() == reset);
        REQUIRE(sender.link.OnTxReady());
        REQUIRE(receiver.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, true, false, false, outstation.LocalAddr,
                                 outstation.RemoteAddr));
        REQUIRE(receiver.PopLastWriteAsHex() == ack);
        REQUIRE(receiver.link.OnTxReady());
        REQUIRE(sender.OnFrame(LinkFunction::SEC_ACK, false, false, false, master.LocalAddr, master.RemoteAddr));

        // First segment with FCB = 1. The peer receives it at once but its ACK is held back.
        REQUIRE(sender.PopLastWriteAsHex() == firstFrame);
        REQUIRE(sender.link.OnTxReady());
        REQUIRE(receiver.OnFrame(LinkFunction::PRI_CONFIRMED_USER_DATA, true, true, true, outstation.LocalAddr,
                                 outstation.RemoteAddr, firstPayload.ToRSeq()));
        const auto delayed = receiver.PopLastWriteAsHex();
        REQUIRE(delayed == ack);
        REQUIRE(receiver.link.OnTxReady());
        REQUIRE(receiver.upper->receivedQueue.size() == 1);

        // The response deadline expires first: the frame is repeated byte for byte, FCB unchanged.
        REQUIRE(sender.exe->advance_time(timeout) > 0);
        REQUIRE(sender.exe->run_many() > 0);
        REQUIRE(sender.PopLastWriteAsHex() == firstFrame);
        REQUIRE(sender.link.OnTxReady());

        // The peer repeats its ACK and withholds the payload (FCB de-duplication).
        REQUIRE(receiver.OnFrame(LinkFunction::PRI_CONFIRMED_USER_DATA, true, true, true, outstation.LocalAddr,
                                 outstation.RemoteAddr, firstPayload.ToRSeq()));
        REQUIRE(receiver.PopLastWriteAsHex() == delayed);
        REQUIRE(receiver.link.OnTxReady());
        REQUIRE(receiver.upper->receivedQueue.size() == 1);

        // The delayed ACK for the first transmission arrives and advances the sender to "BB".
        REQUIRE(sender.OnFrame(LinkFunction::SEC_ACK, false, false, false, master.LocalAddr, master.RemoteAddr));
        REQUIRE(sender.PopLastWriteAsHex() == secondFrame);
        REQUIRE(sender.link.OnTxReady());

        // "BB" is received and acknowledged, but that ACK is lost on the way back. The ACK
        // emitted for "BB" is the same LPDU as the ACK emitted for "AA": it identifies no frame.
        REQUIRE(receiver.OnFrame(LinkFunction::PRI_CONFIRMED_USER_DATA, true, false, true, outstation.LocalAddr,
                                 outstation.RemoteAddr, secondPayload.ToRSeq()));
        REQUIRE(receiver.PopLastWriteAsHex() == ack);
        REQUIRE(receiver.link.OnTxReady());
        REQUIRE(receiver.upper->receivedQueue.size() == 2);

        // The retried ACK for "AA" is accepted as the acknowledgement of "BB".
        REQUIRE(sender.OnFrame(LinkFunction::SEC_ACK, false, false, false, master.LocalAddr, master.RemoteAddr));
        REQUIRE(sender.exe->run_many() > 0);
        REQUIRE(sender.upper->GetCounters().numTxReady == 1);
        REQUIRE(sender.NumTransmitFailures() == 0);
        REQUIRE(sender.link.GetStatistics().numUnexpectedFrame == 0);
    }

    SECTION("duplicate ACK completes a send whose last segment was lost")
    {
        LinkLayerTest sender(master);
        LinkLayerTest receiver(outstation);
        REQUIRE(sender.link.OnLowerLayerUp());
        REQUIRE(receiver.link.OnLowerLayerUp());

        MockTransportSegment segments(1, "AA BB", master.GetAddresses());
        REQUIRE(sender.upper->SendDown(segments));
        REQUIRE(sender.PopLastWriteAsHex() == reset);
        REQUIRE(sender.link.OnTxReady());
        REQUIRE(receiver.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, true, false, false, outstation.LocalAddr,
                                 outstation.RemoteAddr));
        REQUIRE(receiver.PopLastWriteAsHex() == ack);
        REQUIRE(receiver.link.OnTxReady());
        REQUIRE(sender.OnFrame(LinkFunction::SEC_ACK, false, false, false, master.LocalAddr, master.RemoteAddr));

        REQUIRE(sender.PopLastWriteAsHex() == firstFrame);
        REQUIRE(sender.link.OnTxReady());
        REQUIRE(receiver.OnFrame(LinkFunction::PRI_CONFIRMED_USER_DATA, true, true, true, outstation.LocalAddr,
                                 outstation.RemoteAddr, firstPayload.ToRSeq()));
        const auto delayed = receiver.PopLastWriteAsHex();
        REQUIRE(delayed == ack);
        REQUIRE(receiver.link.OnTxReady());

        REQUIRE(sender.exe->advance_time(timeout) > 0);
        REQUIRE(sender.exe->run_many() > 0);
        REQUIRE(sender.PopLastWriteAsHex() == firstFrame);
        REQUIRE(sender.link.OnTxReady());
        REQUIRE(receiver.OnFrame(LinkFunction::PRI_CONFIRMED_USER_DATA, true, true, true, outstation.LocalAddr,
                                 outstation.RemoteAddr, firstPayload.ToRSeq()));
        REQUIRE(receiver.PopLastWriteAsHex() == delayed);
        REQUIRE(receiver.link.OnTxReady());

        REQUIRE(sender.OnFrame(LinkFunction::SEC_ACK, false, false, false, master.LocalAddr, master.RemoteAddr));
        REQUIRE(sender.PopLastWriteAsHex() == secondFrame);
        REQUIRE(sender.link.OnTxReady());

        // "BB" is lost on the wire, so it is neither delivered nor acknowledged. The duplicate
        // ACK for "AA" still completes the two-segment send.
        REQUIRE(sender.OnFrame(LinkFunction::SEC_ACK, false, false, false, master.LocalAddr, master.RemoteAddr));
        REQUIRE(sender.exe->run_many() > 0);
        REQUIRE(sender.upper->GetCounters().numTxReady == 1);
        REQUIRE(sender.NumTransmitFailures() == 0);
        REQUIRE(receiver.upper->receivedQueue.size() == 1);
        REQUIRE(receiver.upper->receivedQueue.front() == "AA");

        // The sender is now one FCB toggle ahead of the peer, so the next send is
        // acknowledged by the peer but never delivered, and the sender completes it too.
        MockTransportSegment following(1, "CC", master.GetAddresses());
        REQUIRE(sender.upper->SendDown(following));
        REQUIRE(sender.PopLastWriteAsHex()
                == LinkHex::ConfirmedUserData(true, true, master.RemoteAddr, master.LocalAddr, "CC"));
        REQUIRE(sender.link.OnTxReady());
        const ByteStr thirdPayload(1, 0xCC);
        REQUIRE(receiver.OnFrame(LinkFunction::PRI_CONFIRMED_USER_DATA, true, true, true, outstation.LocalAddr,
                                 outstation.RemoteAddr, thirdPayload.ToRSeq()));
        REQUIRE(receiver.PopLastWriteAsHex() == ack);
        REQUIRE(receiver.link.OnTxReady());
        REQUIRE(receiver.upper->receivedQueue.size() == 1);
        REQUIRE(sender.OnFrame(LinkFunction::SEC_ACK, false, false, false, master.LocalAddr, master.RemoteAddr));
        REQUIRE(sender.exe->run_many() > 0);
        REQUIRE(sender.upper->GetCounters().numTxReady == 2);
        REQUIRE(sender.NumTransmitFailures() == 0);
    }

    SECTION("without a duplicate ACK the same loss fails instead of completing")
    {
        LinkLayerTest sender(master);
        LinkLayerTest receiver(outstation);
        REQUIRE(sender.link.OnLowerLayerUp());
        REQUIRE(receiver.link.OnLowerLayerUp());

        MockTransportSegment segments(1, "AA BB", master.GetAddresses());
        REQUIRE(sender.upper->SendDown(segments));
        REQUIRE(sender.PopLastWriteAsHex() == reset);
        REQUIRE(sender.link.OnTxReady());
        REQUIRE(receiver.OnFrame(LinkFunction::PRI_RESET_LINK_STATES, true, false, false, outstation.LocalAddr,
                                 outstation.RemoteAddr));
        REQUIRE(receiver.PopLastWriteAsHex() == ack);
        REQUIRE(receiver.link.OnTxReady());
        REQUIRE(sender.OnFrame(LinkFunction::SEC_ACK, false, false, false, master.LocalAddr, master.RemoteAddr));

        REQUIRE(sender.PopLastWriteAsHex() == firstFrame);
        REQUIRE(sender.link.OnTxReady());
        REQUIRE(receiver.OnFrame(LinkFunction::PRI_CONFIRMED_USER_DATA, true, true, true, outstation.LocalAddr,
                                 outstation.RemoteAddr, firstPayload.ToRSeq()));
        REQUIRE(receiver.PopLastWriteAsHex() == ack);
        REQUIRE(receiver.link.OnTxReady());

        // This ACK arrives inside the deadline, so no duplicate is left in flight behind it.
        REQUIRE(sender.OnFrame(LinkFunction::SEC_ACK, false, false, false, master.LocalAddr, master.RemoteAddr));
        REQUIRE(sender.PopLastWriteAsHex() == secondFrame);
        REQUIRE(sender.link.OnTxReady());
        REQUIRE(receiver.upper->receivedQueue.size() == 1);

        // "BB" and its retry are both lost, and no other ACK is outstanding.
        REQUIRE(sender.exe->advance_time(timeout) > 0);
        REQUIRE(sender.exe->run_many() > 0);
        REQUIRE(sender.PopLastWriteAsHex() == secondFrame);
        REQUIRE(sender.link.OnTxReady());
        REQUIRE(sender.exe->advance_time(timeout) > 0);
        REQUIRE(sender.exe->run_many() > 0);

        REQUIRE(sender.NumTotalWrites() == 4);
        REQUIRE(sender.NumTransmitFailures() == 1);
        REQUIRE(sender.upper->GetCounters().numTxReady == 0);
        REQUIRE(receiver.upper->receivedQueue.size() == 1);
        MockTransportSegment blocked(1, "CC", master.GetAddresses());
        REQUIRE_FALSE(sender.upper->SendDown(blocked));
    }
}
