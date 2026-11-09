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
#include "utils/LinkLayerTest.h"
#include "utils/MockTransportSegment.h"

#include <ser4cpp/util/HexConversions.h>

#include <catch.hpp>

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

TEST_CASE(SUITE("Confirmed retries are bounded and start after transmit completion"))
{
    const uint8_t retryLimits[] = {0, 1, 5};
    const auto timeout = std::chrono::milliseconds(10);

    for (const auto retries : retryLimits)
    {
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
    }
}

TEST_CASE(SUITE("Confirmed link rejects retry limits above five"))
{
    LinkConfig config(true);
    config.ConfirmMode = LinkConfirmMode::Always;
    config.NumRetries = 6;
    REQUIRE_THROWS_AS(LinkLayerTest(config), std::invalid_argument);
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

TEST_CASE(SUITE("Confirmed response ownership rejects wrong peer and stale status"))
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
    REQUIRE(t.OnFrame(LinkFunction::SEC_LINK_STATUS, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.NumTotalWrites() == 1);
    REQUIRE(t.exe->advance_time(std::chrono::milliseconds(10)) > 0);
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.PopLastWriteAsHex() == reset);

    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.PopLastWriteAsHex()
            == LinkHex::ConfirmedUserData(true, true, config.RemoteAddr, config.LocalAddr, "AA"));
    REQUIRE(t.link.OnTxReady());
    REQUIRE(t.OnFrame(LinkFunction::SEC_ACK, false, false, false, config.LocalAddr, config.RemoteAddr));
    REQUIRE(t.exe->run_many() > 0);
    REQUIRE(t.upper->GetCounters().numTxReady == 1);
    REQUIRE(t.exe->advance_time(std::chrono::milliseconds(20)) == 0);
    REQUIRE(t.NumTotalWrites() == 3);
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
