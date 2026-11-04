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

#include "mocks/StackPair.h"

#include <opendnp3/ConsoleLogger.h>
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/master/DefaultMasterApplication.h>
#include <opendnp3/outstation/DefaultOutstationApplication.h>
#include <opendnp3/outstation/SimpleCommandHandler.h>

#include <catch.hpp>

#include <iostream>
#include <memory>
#include <thread>

using namespace opendnp3;

#define SUITE(name) "EventIntegrationTestSuite - " name

TEST_CASE(SUITE("TestEventIntegration"))
{
    const uint16_t NUM_STACK_PAIRS = 10;

    const uint16_t NUM_POINTS_PER_TYPE = 50;
    const uint16_t EVENTS_PER_ITERATION = 50;
    const int NUM_ITERATIONS = 10;

    const auto LEVELS = levels::NOTHING | flags::ERR | flags::WARN;

    const auto TEST_TIMEOUT = std::chrono::seconds(5);
    const auto STACK_TIMEOUT = TimeDuration::Seconds(1);

    // run with at least a concurrency of 2, but more if there are more cores
    const auto concurreny = std::max<unsigned int>(std::thread::hardware_concurrency(), 2);

    DNP3Manager manager(concurreny);

    std::vector<std::unique_ptr<StackPair>> pairs;

    for (uint16_t i = 0; i < NUM_STACK_PAIRS; ++i)
    {
        auto pair = std::make_unique<StackPair>(LEVELS, STACK_TIMEOUT, manager, i, NUM_POINTS_PER_TYPE,
                                                EVENTS_PER_ITERATION);
        pairs.push_back(std::move(pair));
    }

    for (auto& pair : pairs)
    {
        pair->WaitForChannelsOnline(TEST_TIMEOUT);
    }

    const auto start = std::chrono::steady_clock::now();

    for (int i = 0; i < NUM_ITERATIONS; ++i)
    {

        for (auto& pair : pairs)
        {
            pair->SendRandomValues();
        }

        for (auto& pair : pairs)
        {
            pair->WaitToRxValues(TEST_TIMEOUT);
        }
    }

    const auto milliseconds
        = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    const auto total_events_transferred = static_cast<uint64_t>(NUM_STACK_PAIRS)
        * static_cast<uint64_t>(EVENTS_PER_ITERATION) * static_cast<uint64_t>(NUM_ITERATIONS);

    const auto rate = (total_events_transferred * 1000) / milliseconds.count();

    std::cout << total_events_transferred << " in " << milliseconds.count() << " ms == " << rate << " events per/sec"
              << std::endl;
}

TEST_CASE(SUITE("Master reads attributes and G80 and G34 writes affect G32 delivery over TCP"),
          "[profile-deadband][level4-iin][device-attributes]")
{
    const auto timeout = std::chrono::seconds(4);
    DNP3Manager manager(2);
    auto server = manager.AddTCPServer("deadband server", levels::NORMAL, ServerAcceptMode::CloseExisting,
                                       IPEndpoint::Localhost(0), nullptr);
    auto client = manager.AddTCPClient("deadband client", levels::NORMAL, ChannelRetry::Default(),
                                       {IPEndpoint::Localhost(server->GetBoundPort())}, "127.0.0.1", nullptr);

    DatabaseConfig database;
    database.analog_input[1].deadband = 17;
    database.analog_input[300].deadband = 23;
    OutstationStackConfig outConfig(database);
    outConfig.outstation.params.authentication.mode = AuthenticationConfig::Mode::COMPATIBILITY;
    outConfig.outstation.eventBufferConfig = EventBufferConfig::AllTypes(8);
    auto outstation = server->AddOutstation("deadband outstation", SuccessCommandHandler::Create(),
                                            DefaultOutstationApplication::Create(), outConfig);
    MasterStackConfig masterConfig;
    masterConfig.master.authentication.mode = AuthenticationConfig::Mode::COMPATIBILITY;
    masterConfig.master.disableUnsolOnStartup = false;
    masterConfig.master.unsolClassMask = ClassField::None();
    masterConfig.master.startupIntegrityClassMask = ClassField::None();
    masterConfig.master.ignoreRestartIIN = true;
    auto soe = std::make_shared<QueuingSOEHandler>();
    auto master = client->AddMaster("deadband master", soe, DefaultMasterApplication::Create(), masterConfig);
    REQUIRE(outstation->Enable());
    REQUIRE(master->Enable());

    master->Scan({Header::Range8(0, 212, 0, 0)}, soe);
    std::vector<std::tuple<GroupVariation, uint16_t, uint64_t>> attributes;
    REQUIRE(soe->unsignedAttributes.DrainTo(attributes, timeout) == 1);
    REQUIRE(attributes.front() == std::make_tuple(GroupVariation::Group0Var212, uint16_t(0), uint64_t(0)));

    for (const auto qualifier : {QualifierCode::UINT8_START_STOP, QualifierCode::UINT16_START_STOP})
    {
        master->Scan({qualifier == QualifierCode::UINT8_START_STOP ? Header::Range8(80, 1, 7, 7)
                                                                 : Header::Range16(80, 1, 7, 7)},
                     soe);
        std::vector<std::pair<HeaderInfo, Indexed<IINValue>>> indications;
        REQUIRE(soe->indications.DrainTo(indications, timeout) == 1);
        REQUIRE(indications.front().first.gv == GroupVariation::Group80Var1);
        REQUIRE(indications.front().first.qualifier == qualifier);
        REQUIRE(indications.front().second.index == 7);
        REQUIRE(indications.front().second.value.value);
    }

    const auto read = [&](const Header& header) {
        std::vector<std::pair<HeaderInfo, Indexed<AnalogDeadband>>> records;
        master->Scan({header}, soe);
        REQUIRE(soe->deadbands.DrainTo(records, timeout) == 1);
        return records.front();
    };
    REQUIRE(read(Header::Range8(34, 0, 1, 1)).second.value.value == 17);
    const auto write = [&](AnalogDeadbandVariation variation, QualifierCode qualifier, uint16_t index, double value) {
        master->PerformFunction("write deadband", FunctionCode::WRITE,
            {Header::WriteAnalogDeadbands(variation, qualifier, {WithIndex(AnalogDeadband{value}, index)})});
    };
    for (auto variation : {AnalogDeadbandVariation::UInt16, AnalogDeadbandVariation::UInt32,
                           AnalogDeadbandVariation::Float32})
    {
        double value = 30;
        for (auto qualifier : {QualifierCode::UINT8_START_STOP, QualifierCode::UINT16_START_STOP,
                               QualifierCode::UINT8_CNT_UINT8_INDEX, QualifierCode::UINT16_CNT_UINT16_INDEX})
        {
            const bool narrow = qualifier == QualifierCode::UINT8_START_STOP
                || qualifier == QualifierCode::UINT8_CNT_UINT8_INDEX;
            const uint16_t index = narrow ? 1 : 300;
            write(variation, qualifier, index, ++value);
            const auto wireVariation = static_cast<uint8_t>(variation);
            const auto result = read(narrow ? Header::Range8(34, wireVariation, 1, 1)
                                            : Header::Range16(34, wireVariation, 300, 300));
            REQUIRE(result.first.gv == GroupVariationSpec::from_type(0x2200 | wireVariation));
            REQUIRE(result.second.index == index);
            REQUIRE(result.second.value.value == value);
        }
    }

    write(AnalogDeadbandVariation::UInt16, QualifierCode::UINT8_START_STOP, 1, 5);
    REQUIRE(read(Header::Range8(34, 0, 1, 1)).second.value.value == 5);
    UpdateBuilder updates;
    updates.Update(Analog(0, Flags(1)), 1, EventMode::Force);
    updates.Update(Analog(5, Flags(1)), 1);
    updates.Update(Analog(6, Flags(1)), 1);
    outstation->Apply(updates.Build());
    (void)outstation->GetStackStatistics(); // barrier after Apply on the Outstation executor
    master->Scan({Header::AllObjects(32, 0)}, soe);
    std::deque<ExpectedValue> events;
    REQUIRE(soe->values.DrainTo(events, timeout) == 2);
    CHECK(events[0].Equals(ExpectedValue(Analog(0), 1)));
    CHECK(events[1].Equals(ExpectedValue(Analog(6), 1)));
}
