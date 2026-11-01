// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "crypto/CryptoProvider.h"
#include "utils/BufferHelpers.h"
#include "utils/CommandCallbackQueue.h"
#include "utils/MasterTestFixture.h"
#include "utils/OutstationTestObject.h"

#include <ser4cpp/util/HexConversions.h>

#include <catch.hpp>

#include <array>

using namespace opendnp3;
using namespace ser4cpp;
namespace
{
struct RuntimeCredentials final : IAuthenticationCredentials
{
    std::array<std::array<uint8_t, 32>, 2> keys{};
    RuntimeCredentials()
    {
        for (auto& k : keys)
            REQUIRE(crypto::GenerateRandom(wseq_t(k.data(), k.size())) == crypto::Result::OK);
    }
    ~RuntimeCredentials()
    {
        for (auto& k : keys)
            crypto::Clear(wseq_t(k.data(), k.size()));
    }
    bool ReadUpdateKey(uint16_t assoc, uint16_t user, uint8_t* out, size_t size, uint64_t& expiry) override
    {
        if (assoc != 7 || user < 1 || user > 2 || !out || size != 32)
            return false;
        std::copy(keys[user - 1].begin(), keys[user - 1].end(), out);
        expiry = 10000000;
        return true;
    }
};
struct RuntimePolicy final : IAuthenticationAuthorization
{
    bool allowControl = true;
    bool IsAuthorized(uint16_t assoc, uint16_t user, uint8_t function, const uint8_t* apdu, size_t size) const override
    {
        return apdu && size >= 2 && apdu[1] == function && assoc == 7
            && ((user == 1 && (function == 0 || function == 1 || function == 2)) || (user == 2 && allowControl));
    }
};
MasterParams MasterSettings(const std::shared_ptr<RuntimeCredentials>& source,
                            const std::shared_ptr<RuntimePolicy>& policy)
{
    auto p = NoStartupTasks();
    p.ignoreRestartIIN = true;
    p.authentication.association = 7;
    p.authentication.credentials = source;
    p.authentication.authorization = policy;
    return p;
}
OutstationConfig OutSettings(const std::shared_ptr<RuntimeCredentials>& source,
                             const std::shared_ptr<RuntimePolicy>& policy,
                             bool unsolicited = false)
{
    OutstationConfig c;
    c.params.allowUnsolicited = unsolicited;
    c.params.authentication.association = 7;
    c.params.authentication.credentials = source;
    c.params.authentication.authorization = policy;
    return c;
}
struct RuntimePair
{
    CommandCallbackQueue results;
    std::shared_ptr<RuntimeCredentials> source = std::make_shared<RuntimeCredentials>();
    std::shared_ptr<RuntimePolicy> policy = std::make_shared<RuntimePolicy>();
    MasterTestFixture master{MasterSettings(source, policy), Addresses()};
    OutstationTestObject outstation{OutSettings(source, policy)};
    size_t changes = 0, controlReplies = 0, monitorReplies = 0;
    std::string savedReply;
    bool corruptControl = false, corruptMonitoring = false;
    explicit RuntimePair(bool unsolicited = false) : outstation(OutSettings(source, policy, unsolicited))
    {
        outstation.LowerLayerUp();
        REQUIRE(master.context->OnLowerLayerUp());
        master.exe->run_many();
    }
    void Pump()
    {
        size_t steps = 0;
        while (master.lower->NumWrites() || outstation.lower->NumWrites())
        {
            REQUIRE(++steps < 100);
            if (master.lower->NumWrites())
            {
                auto hex = master.lower->PopWriteAsHex();
                HexSequence packet(hex);
                std::vector<uint8_t> bytes(packet.ToRSeq().length());
                std::copy(static_cast<const uint8_t*>(packet.ToRSeq()),
                          static_cast<const uint8_t*>(packet.ToRSeq()) + bytes.size(), bytes.begin());
                if (bytes.size() > 3 && bytes[1] == 0x20 && bytes[2] == 120 && bytes[3] == 6)
                    ++changes;
                if (bytes.size() > 3 && bytes[1] == 0x20 && bytes[2] == 120 && bytes[3] == 2)
                {
                    ++controlReplies;
                    savedReply = hex;
                    if (corruptControl)
                    {
                        bytes.back() ^= 1;
                        corruptControl = false;
                        hex = ser4cpp::HexConversions::to_hex(rseq_t(bytes.data(), bytes.size()));
                    }
                }
                REQUIRE(master.context->OnTxReady());
                outstation.SendToOutstation(hex);
            }
            if (outstation.lower->NumWrites())
            {
                auto hex = outstation.lower->PopWriteAsHex();
                HexSequence packet(hex);
                std::vector<uint8_t> bytes(packet.ToRSeq().length());
                std::copy(static_cast<const uint8_t*>(packet.ToRSeq()),
                          static_cast<const uint8_t*>(packet.ToRSeq()) + bytes.size(), bytes.begin());
                if (bytes.size() > 5 && bytes[1] == 0x83 && bytes[4] == 120 && bytes[5] == 2)
                {
                    ++monitorReplies;
                    if (corruptMonitoring)
                    {
                        bytes.back() ^= 1;
                        corruptMonitoring = false;
                        hex = ser4cpp::HexConversions::to_hex(rseq_t(bytes.data(), bytes.size()));
                    }
                }
                outstation.OnTxReady();
                REQUIRE(master.SendToMaster(hex));
                master.exe->run_many();
            }
        }
    }
    void SelectOperate(uint16_t user = 2)
    {
        auto config = TaskConfig::Default();
        config.authenticationUser = user;
        master.context->SelectAndOperate(CommandSet({WithIndex(ControlRelayOutputBlock(OperationType::LATCH_ON), 3)}),
                                         results.Callback(), config);
        master.exe->run_many();
    }
};
} // namespace
TEST_CASE("ProductionAuthentication - real key negotiation gates both request and response paths", "[production-sa]")
{
    RuntimePair pair;
    pair.SelectOperate();
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    pair.Pump();
    REQUIRE(pair.changes == 2);
    REQUIRE(pair.controlReplies == 2);
    REQUIRE(pair.monitorReplies == 2);
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
    pair.outstation.SendToOutstation(pair.savedReply);
    pair.Pump();
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
}
TEST_CASE("ProductionAuthentication - invalid MAC and policy failure cannot execute protected operations",
          "[production-sa]")
{
    RuntimePair pair;
    pair.Pump();
    const auto fault = GENERATE(0, 1, 2);
    if (fault == 0)
        pair.corruptControl = true;
    if (fault == 1)
        pair.policy->allowControl = false;
    pair.SelectOperate(fault == 2 ? 1 : 2);
    pair.Pump();
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    REQUIRE(pair.results.values.empty());
    pair.master.exe->advance_time(pair.master.context->params.responseTimeout.value);
    pair.master.exe->run_many();
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary != TaskCompletion::SUCCESS);
}
TEST_CASE("ProductionAuthentication - unauthenticated monitoring result cannot complete a command", "[production-sa]")
{
    RuntimePair pair;
    pair.Pump();
    pair.corruptMonitoring = true;
    pair.SelectOperate();
    pair.Pump();
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
    REQUIRE(pair.results.values.empty());
    pair.master.exe->advance_time(pair.master.context->params.responseTimeout.value);
    pair.master.exe->run_many();
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary != TaskCompletion::SUCCESS);
}
TEST_CASE("ProductionAuthentication - disconnect forces fresh key negotiation", "[production-sa]")
{
    RuntimePair pair;
    pair.SelectOperate();
    pair.Pump();
    REQUIRE(pair.changes == 2);
    REQUIRE(pair.master.context->OnLowerLayerDown());
    pair.outstation.LowerLayerDown();
    pair.outstation.LowerLayerUp();
    REQUIRE(pair.master.context->OnLowerLayerUp());
    pair.master.exe->run_many();
    pair.Pump();
    REQUIRE(pair.changes == 4);
    pair.SelectOperate();
    pair.Pump();
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 2);
    REQUIRE(pair.results.values.size() == 2);
    REQUIRE(pair.results.values.back().summary == TaskCompletion::SUCCESS);
}

TEST_CASE("ProductionAuthentication - unsolicited confirmation is authenticated before release", "[production-sa]")
{
    RuntimePair pair(true);
    pair.Pump();
    pair.outstation.AdvanceTime(OutSettings(pair.source, pair.policy, true).params.unsolConfirmTimeout);
    const bool invalid = GENERATE(false, true);
    pair.corruptControl = invalid;
    pair.Pump();
    REQUIRE(pair.monitorReplies >= 1);
    REQUIRE(pair.controlReplies >= 1);
    if (invalid)
        REQUIRE(pair.outstation.NumPendingTimers() >= 1);
    else
        REQUIRE(pair.outstation.NumPendingTimers() == 0);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
}
// Default construction must not accidentally create an insecure production stack.
TEST_CASE("ProductionAuthentication - missing credentials fails construction", "[production-sa]")
{
    MasterTestFixture fixture(NoStartupTasks());
    auto master=[&]() {
        return MContext::Create(Addresses(),Logger(nullptr,ModuleId(),"missing",LogLevels::none()),fixture.exe,
            fixture.lower,fixture.meas,fixture.application,fixture.scheduler,MasterParams{});
    };
    REQUIRE_THROWS_AS(master(),std::invalid_argument);
    auto outstation=[&]() {
        return std::make_shared<OContext>(Addresses(),OutstationConfig{},DatabaseConfig{},
            Logger(nullptr,ModuleId(),"missing",LogLevels::none()),fixture.exe,fixture.lower,
            std::make_shared<MockCommandHandler>(CommandStatus::SUCCESS),std::make_shared<MockOutstationApplication>());
    };
    REQUIRE_THROWS_AS(outstation(),std::invalid_argument);
}
