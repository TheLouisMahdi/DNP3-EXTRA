// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/APDUResponse.h"
#include "crypto/CryptoProvider.h"
#include "utils/BufferHelpers.h"
#include "utils/CommandCallbackQueue.h"
#include "utils/MasterTestFixture.h"
#include "utils/OutstationTestObject.h"

#include <ser4cpp/util/HexConversions.h>

#include <catch.hpp>

#include <array>
#include <chrono>

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
                            const std::shared_ptr<RuntimePolicy>& policy,
                            bool aggressive = false,
                            bool receiveAggressive = false)
{
    auto p = NoStartupTasks();
    p.authentication.aggressiveTransmit = aggressive;
    p.authentication.aggressiveReceive = aggressive || receiveAggressive;
    p.ignoreRestartIIN = true;
    p.authentication.association = 7;
    p.authentication.credentials = source;
    p.authentication.authorization = policy;
    return p;
}
OutstationConfig OutSettings(const std::shared_ptr<RuntimeCredentials>& source,
                             const std::shared_ptr<RuntimePolicy>& policy,
                             bool unsolicited = false,
                             bool aggressive = false)
{
    OutstationConfig c;
    c.params.authentication.aggressiveTransmit = aggressive;
    c.params.authentication.aggressiveReceive = aggressive;
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
    std::string savedReply, commonKeyChange, monitoringChallenge;
    bool corruptControl = false, corruptMonitoring = false;
    bool corruptAggressiveControl = false, corruptAggressiveMonitoring = false, denyAggressiveControl = false;
    size_t aggressiveRequests = 0, aggressiveResponses = 0;
    std::string savedAggressive;
    explicit RuntimePair(bool unsolicited = false, bool aggressive = false, bool receiveAggressive = false)
        : master(MasterSettings(source, policy, aggressive, receiveAggressive), Addresses()),
          outstation(OutSettings(source, policy, unsolicited, aggressive))
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
                {
                    ++changes;
                    Group120Var6 change;
                    REQUIRE(change.Read(rseq_t(bytes.data(), bytes.size()).skip(8)));
                    if (change.userNum == 1)
                        commonKeyChange = hex;
                }
                if (bytes.size() > 3 && bytes[1] == 0x20 && bytes[2] == 120 && bytes[3] == 1)
                    monitoringChallenge = hex;
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
                if (bytes.size() > 3 && bytes[1] < 0x20 && bytes[2] == 120 && bytes[3] == 3)
                {
                    ++aggressiveRequests;
                    savedAggressive = hex;
                    if (denyAggressiveControl)
                        policy->allowControl = false;
                    if (corruptAggressiveControl)
                    {
                        bytes.back() ^= 1;
                        corruptAggressiveControl = false;
                        hex = HexConversions::to_hex(rseq_t(bytes.data(), bytes.size()));
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
                if (bytes.size() > 5 && (bytes[1] == 0x81 || bytes[1] == 0x82) && bytes[4] == 120 && bytes[5] == 3)
                {
                    ++aggressiveResponses;
                    if (corruptAggressiveMonitoring)
                    {
                        bytes.back() ^= 1;
                        corruptAggressiveMonitoring = false;
                        hex = HexConversions::to_hex(rseq_t(bytes.data(), bytes.size()));
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
    auto master = [&]() {
        return MContext::Create(Addresses(), Logger(nullptr, ModuleId(), "missing", LogLevels::none()), fixture.exe,
                                fixture.lower, fixture.meas, fixture.application, fixture.scheduler, MasterParams{});
    };
    REQUIRE_THROWS_AS(master(), std::invalid_argument);
    auto outstation = [&]() {
        return std::make_shared<OContext>(Addresses(), OutstationConfig{}, DatabaseConfig{},
                                          Logger(nullptr, ModuleId(), "missing", LogLevels::none()), fixture.exe,
                                          fixture.lower, std::make_shared<MockCommandHandler>(CommandStatus::SUCCESS),
                                          std::make_shared<MockOutstationApplication>());
    };
    REQUIRE_THROWS_AS(outstation(), std::invalid_argument);
}

TEST_CASE("ProductionAuthentication - aggressive operation and response require prior challenge completion",
          "[production-sa][aggressive-runtime]")
{
    RuntimePair pair(false, true);
    pair.SelectOperate();
    pair.Pump();
    REQUIRE(pair.controlReplies == 1);
    REQUIRE(pair.monitorReplies == 1);
    REQUIRE(pair.aggressiveRequests == 1);
    REQUIRE(pair.aggressiveResponses == 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
    pair.outstation.SendToOutstation(pair.savedAggressive);
    pair.Pump();
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    REQUIRE(pair.master.context->OnLowerLayerDown());
    pair.outstation.LowerLayerDown();
    pair.outstation.LowerLayerUp();
    REQUIRE(pair.master.context->OnLowerLayerUp());
    pair.master.exe->run_many();
    pair.Pump();
    pair.outstation.SendToOutstation(pair.savedAggressive);
    pair.Pump();
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
}
TEST_CASE("ProductionAuthentication - aggressive invalid MAC authorization and replay fail closed",
          "[production-sa][aggressive-runtime]")
{
    RuntimePair pair(false, true);
    const auto fault = GENERATE(0, 1, 2);
    if (fault == 0)
        pair.corruptAggressiveControl = true;
    if (fault == 1)
        pair.corruptAggressiveMonitoring = true;
    if (fault == 2)
        pair.denyAggressiveControl = true;
    pair.SelectOperate();
    pair.Pump();
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == (fault == 1 ? 1 : 0));
    REQUIRE(pair.results.values.empty());
    if (fault == 2)
    {
        pair.policy->allowControl = true;
        pair.outstation.SendToOutstation(pair.savedAggressive);
        pair.Pump();
        REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
    }
    pair.master.exe->advance_time(pair.master.context->params.responseTimeout.value);
    pair.master.exe->run_many();
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary != TaskCompletion::SUCCESS);
}

TEST_CASE("ProductionAuthentication - idle monitoring timeout discards payload and permits fresh unsolicited authentication",
          "[production-sa]")
{
    RuntimePair pair(true);
    pair.Pump();
    const auto unsolTimeout = OutSettings(pair.source, pair.policy, true).params.unsolConfirmTimeout;
    pair.outstation.AdvanceTime(unsolTimeout);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto unsolicited = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(unsolicited));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto firstChallenge = pair.master.lower->PopWriteAsHex();
    HexSequence firstPacket(firstChallenge);
    Group120Var1 first;
    REQUIRE(first.Read(firstPacket.ToRSeq().skip(8)));
    const auto firstSequence = first.seqNum;
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(firstChallenge);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto lateReply = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    // Withhold the Reply while the Master has no application task or response timer.
    REQUIRE_FALSE(pair.master.context->activeTask);
    pair.master.exe->advance_time(
        std::chrono::milliseconds(pair.master.context->params.authentication.replyTimeoutMs));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.master.context->confirmQueue.empty());
    // Processing this CON response would have issued a Confirm. Instead it is discarded.
    pair.outstation.AdvanceTime(unsolTimeout);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto retry = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(retry));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto nextChallenge = pair.master.lower->PopWriteAsHex();
    HexSequence nextPacket(nextChallenge);
    Group120Var1 next;
    REQUIRE(next.Read(nextPacket.ToRSeq().skip(8)));
    REQUIRE(next.seqNum == static_cast<uint32_t>(firstSequence + 1));
    REQUIRE(pair.master.context->OnTxReady());
    SECTION("fresh Reply authenticates normally with the existing keys")
    {
        pair.outstation.SendToOutstation(nextChallenge);
        pair.Pump();
    }
    SECTION("late Reply cannot authenticate either expired or replacement payload")
    {
        REQUIRE(pair.master.SendToMaster(lateReply));
        pair.master.exe->run_many();
        REQUIRE(pair.master.lower->NumWrites() == 0);
        REQUIRE(pair.master.context->confirmQueue.empty());
        // Drop the replacement Challenge too; the next native unsolicited retry
        // must establish another fresh Challenge/Reply, using unchanged Session Keys.
        pair.outstation.AdvanceTime(unsolTimeout);
        pair.Pump();
    }
    REQUIRE(pair.outstation.NumPendingTimers() == 0);
    REQUIRE(pair.changes == 2);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("ProductionAuthentication - monitoring timeout preserves key exchange and in flight transmissions",
          "[production-sa]")
{
    RuntimePair pair;
    // Complete only user 1's exchange, leaving user 2's Status Request in flight.
    for (size_t step = 0; step < 2; ++step)
    {
        REQUIRE(pair.master.lower->NumWrites() == 1);
        const auto request = pair.master.lower->PopWriteAsHex();
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(request);
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        const auto response = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(response));
        pair.master.exe->run_many();
    }
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto statusRequest = pair.master.lower->PopWriteAsHex();
    HexSequence request(statusRequest);
    REQUIRE(request.ToRSeq()[2] == 120);
    REQUIRE(request.ToRSeq()[3] == 4);
    REQUIRE(pair.master.context->isSending);
    // Queue a monitoring Challenge behind the ongoing Status Request transmission.
    REQUIRE(pair.master.SendToMaster("F0 82 00 00"));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 0);
    SECTION("unsent expired Challenge is discarded without cancelling the transmission")
    {
        pair.master.exe->advance_time(
            std::chrono::milliseconds(pair.master.context->params.authentication.replyTimeoutMs));
        pair.master.exe->run_many();
        REQUIRE(pair.master.context->isSending);
        REQUIRE(pair.master.lower->NumWrites() == 0);
        REQUIRE(pair.master.context->confirmQueue.empty());
        REQUIRE(pair.master.context->OnTxReady());
        REQUIRE(pair.master.lower->NumWrites() == 1);
        HexSequence pending(pair.master.lower->PopWriteAsHex());
        REQUIRE(pending.ToRSeq()[2] == 120);
        REQUIRE(pending.ToRSeq()[3] == 4); // Session retry, never the expired G120V1.
    }
    SECTION("queued Key Change survives expiration of the Challenge in flight")
    {
        REQUIRE(pair.master.context->OnTxReady());
        REQUIRE(pair.master.lower->NumWrites() == 1);
        HexSequence challenge(pair.master.lower->PopWriteAsHex());
        REQUIRE(challenge.ToRSeq()[2] == 120);
        REQUIRE(challenge.ToRSeq()[3] == 1);
        REQUIRE(pair.master.context->isSending);
        pair.outstation.SendToOutstation(statusRequest);
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        const auto status = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(status));
        pair.master.exe->run_many();
        REQUIRE(pair.master.lower->NumWrites() == 0); // G120V6 is queued, not transmitted.
        pair.master.exe->advance_time(
            std::chrono::milliseconds(pair.master.context->params.authentication.replyTimeoutMs));
        pair.master.exe->run_many();
        REQUIRE(pair.master.context->isSending);
        REQUIRE(pair.master.lower->NumWrites() == 0);
        REQUIRE(pair.master.context->confirmQueue.empty());
        REQUIRE(pair.master.context->OnTxReady());
        REQUIRE(pair.master.lower->NumWrites() == 1);
        const auto change = pair.master.lower->PopWriteAsHex();
        HexSequence packet(change);
        REQUIRE(packet.ToRSeq()[2] == 120);
        REQUIRE(packet.ToRSeq()[3] == 6);
        // The existing Outstation must still validate the queued encrypted message.
        pair.outstation.SendToOutstation(change);
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        HexSequence confirmation(pair.outstation.lower->PopWriteAsHex());
        Group120Var5 value;
        REQUIRE(value.Read(confirmation.ToRSeq().skip(10)));
        REQUIRE(value.userNum == 2);
        REQUIRE(value.keyStatus == 1);
    }
}

TEST_CASE("ProductionAuthentication - embedded Challenge requires Aggressive Confirm with ordinary transmit disabled",
          "[production-sa][embedded-confirm]")
{
    const bool unsolicited = GENERATE(false, true);
    const bool aggressiveResponse = GENERATE(false, true);
    const auto fault = GENERATE(0, 1, 2, 3, 4, 5, 6);
    const auto queueMode = !aggressiveResponse && fault == 0 ? GENERATE(0, 1, 2, 3) : 0;
    RuntimePair pair(unsolicited, false, aggressiveResponse || queueMode == 2);
    pair.Pump();
    // Prime the selected monitoring history through the normal standalone exchange.
    if (unsolicited)
    {
        pair.outstation.AdvanceTime(OutSettings(pair.source, pair.policy, true).params.unsolConfirmTimeout);
        pair.Pump();
        REQUIRE(pair.outstation.NumPendingTimers() == 0);
    }
    else
    {
        pair.SelectOperate();
        pair.Pump();
        REQUIRE(pair.results.values.size() == 1);
        REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
    }
    REQUIRE_FALSE(pair.master.context->params.authentication.aggressiveTransmit);
    REQUIRE_FALSE(pair.commonKeyChange.empty());
    REQUIRE_FALSE(pair.monitoringChallenge.empty());
    // Inspect only ephemeral test session material, using the existing V6 codec and
    // real RFC3394 unwrap. The production credential/session interfaces are unchanged.
    struct Secrets
    {
        std::array<uint8_t, 2048> plain{};
        std::array<uint8_t, 32> wrong{};
        ~Secrets()
        {
            crypto::Clear(wseq_t(plain.data(), plain.size()));
            crypto::Clear(wseq_t(wrong.data(), wrong.size()));
        }
    } secrets;
    HexSequence keyChange(pair.commonKeyChange);
    Group120Var6 change;
    REQUIRE(change.Read(keyChange.ToRSeq().skip(8)));
    REQUIRE(change.keyWrapData.length() >= 24);
    REQUIRE(change.keyWrapData.length() - 8 <= secrets.plain.size());
    REQUIRE(crypto::AES256KeyUnwrap(rseq_t(pair.source->keys[0].data(), 32), change.keyWrapData,
                                     wseq_t(secrets.plain.data(), change.keyWrapData.length() - 8)) == crypto::Result::OK);
    REQUIRE(secrets.plain[0] == 32);
    REQUIRE(secrets.plain[1] == 0);
    const auto controlKey = rseq_t(secrets.plain.data() + 2, 32);
    const auto monitoringKey = rseq_t(secrets.plain.data() + 34, 32);
    REQUIRE(crypto::GenerateRandom(wseq_t(secrets.wrong.data(), secrets.wrong.size())) == crypto::Result::OK);
    const auto peerKey = fault == 6 ? rseq_t(secrets.wrong.data(), secrets.wrong.size()) : monitoringKey;
    std::vector<uint8_t> original{0xF3, 0x82, 0, 0};
    if (!unsolicited)
    {
        pair.SelectOperate();
        for (size_t step = 0; step < 2; ++step)
        {
            REQUIRE(pair.master.lower->NumWrites() == 1);
            const auto request = pair.master.lower->PopWriteAsHex();
            REQUIRE(pair.master.context->OnTxReady());
            pair.outstation.SendToOutstation(request);
            REQUIRE(pair.outstation.lower->NumWrites() == 1);
            const auto response = pair.outstation.lower->PopWriteAsHex();
            pair.outstation.OnTxReady();
            if (step == 0)
            {
                REQUIRE(pair.master.SendToMaster(response));
                pair.master.exe->run_many();
            }
            else
            {
                HexSequence packet(response);
                original.assign(static_cast<const uint8_t*>(packet.ToRSeq()),
                                static_cast<const uint8_t*>(packet.ToRSeq()) + packet.ToRSeq().length());
            }
        }
    }
    std::array<uint8_t, 32> nonce{};
    REQUIRE(crypto::GenerateRandom(wseq_t(nonce.data(), nonce.size())) == crypto::Result::OK);
    Group120Var1 challenge(fault == 4 ? 0 : 100, fault == 1 ? 1 : 0, fault == 2 ? 3 : 4, 1,
                           rseq_t(nonce.data(), nonce.size()));
    std::array<uint8_t, 2048> native{}, encoded{};
    APDUResponse response(wseq_t(native.data(), native.size()));
    response.SetFunction(FunctionCodeSpec::from_type(original[1]));
    response.SetControl(AppControlField(original[0] | 0x20));
    response.SetIIN(IINField(original[2], original[3]));
    REQUIRE(response.AppendObjects(rseq_t(original.data(), original.size()).skip(4)));
    auto writer = response.GetWriter();
    REQUIRE(writer.WriteFreeFormat(&challenge, 1));
    std::vector<uint8_t> incoming(native.data(), native.data() + response.Size());
    if (aggressiveResponse)
    {
        AggressiveMode peer(7, 16, true);
        HexSequence seed(pair.monitoringChallenge);
        REQUIRE(peer.RememberChallenge(seed.ToRSeq(), unsolicited));
        size_t size = 0;
        REQUIRE(peer.Create(7, 1, peerKey, rseq_t(incoming.data(), incoming.size()),
                             wseq_t(encoded.data(), encoded.size()), size));
        incoming.assign(encoded.data(), encoded.data() + size);
        if (fault == 5)
            incoming.back() ^= 1;
    }
    if (fault == 3)
    {
        // G120V1 cannot be followed by regular data, including before an aggressive V9.
        const uint8_t binary[] = {1, 2, 0, 0, 0, 1};
        incoming.insert(incoming.end() - (aggressiveResponse ? 22 : 0), binary, binary + sizeof(binary));
    }
    const auto before = pair.master.context->solSeq.Get();
    REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(incoming.data(), incoming.size()))));
    pair.master.exe->run_many();
    if (!aggressiveResponse && pair.master.lower->NumWrites())
    {
        REQUIRE(pair.master.lower->NumWrites() == 1);
        const auto issued = pair.master.lower->PopWriteAsHex();
        if (queueMode == 0)
            REQUIRE(pair.master.context->OnTxReady());
        else if (queueMode == 1 || queueMode == 3)
        {
            // Even an older identical SEQ/UNS entry must remain independently owned.
            pair.master.context->confirmQueue.push_back(unsolicited
                ? APDUHeader::UnsolicitedConfirm(incoming[0] & 0x0F)
                : APDUHeader::SolicitedConfirm(incoming[0] & 0x0F));
            pair.master.context->confirmQueue.push_back(APDUHeader::UnsolicitedConfirm(7));
        }
        MasterResponder peer(7, 16, 2000, true);
        REQUIRE(peer.SetSessionKey(1, peerKey, 10000000, 0) == MasterResponder::Result::OK);
        REQUIRE(peer.RetainRequest(7, rseq_t(incoming.data(), incoming.size()), 0) == MasterResponder::Result::OK);
        HexSequence received(issued);
        size_t size = 0;
        REQUIRE(peer.Respond(7, received.ToRSeq(), 0, wseq_t(encoded.data(), encoded.size()), size)
                == MasterResponder::Result::OK);
        if (fault == 5)
            encoded[size - 1] ^= 1;
        REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(encoded.data(), size))));
        pair.master.exe->run_many();
        if (queueMode != 0)
        {
            REQUIRE(pair.master.context->isSending); // Original monitoring Challenge is still in flight.
            REQUIRE(pair.master.lower->NumWrites() == 0);
            REQUIRE(pair.master.context->confirmQueue.size() == (queueMode == 2 ? 1 : 3));
            if (queueMode == 3)
            {
                pair.master.exe->advance_time(
                    std::chrono::milliseconds(pair.master.context->params.authentication.replyTimeoutMs));
                pair.master.exe->run_many();
                REQUIRE(pair.master.context->isSending); // Do not cancel the in-flight Challenge.
                REQUIRE(pair.master.lower->NumWrites() == 0);
                REQUIRE(pair.master.context->confirmQueue.size() == 2);
                REQUIRE(pair.master.context->confirmQueue.front().control.UNS == unsolicited);
                REQUIRE(pair.master.context->confirmQueue.front().control.SEQ == (incoming[0] & 0x0F));
                REQUIRE(pair.master.context->confirmQueue.back().control.UNS);
                REQUIRE(pair.master.context->confirmQueue.back().control.SEQ == 7);
                return;
            }
            if (queueMode == 2)
            {
                const auto processed = pair.master.context->solSeq.Get();
                AggressiveMode monitoringPeer(7, 16, true);
                REQUIRE(monitoringPeer.RememberChallenge(received.ToRSeq(), unsolicited));
                original[0] |= 0x20;
                REQUIRE(monitoringPeer.Create(7, 1, monitoringKey, rseq_t(original.data(), original.size()),
                                              wseq_t(encoded.data(), encoded.size()), size));
                REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(encoded.data(), size))));
                pair.master.exe->run_many();
                REQUIRE(pair.master.lower->NumWrites() == 0);
                REQUIRE(pair.master.context->confirmQueue.size() == 1);
                REQUIRE(pair.master.context->solSeq.Get() == processed);
            }
            // Releasing the actual in-flight transmission sends exactly the cached mandatory CONFIRM.
            REQUIRE(pair.master.context->OnTxReady());
        }
    }
    if (fault != 0)
    {
        REQUIRE(pair.master.lower->NumWrites() == 0);
        REQUIRE(pair.master.context->confirmQueue.empty());
        REQUIRE(pair.master.context->solSeq.Get() == before);
        return;
    }
    REQUIRE(pair.master.lower->NumWrites() == 1);
    HexSequence confirm(pair.master.lower->PopWriteAsHex());
    REQUIRE(confirm.ToRSeq().length() == 34);
    REQUIRE(confirm.ToRSeq()[0] == static_cast<uint8_t>(0xC0 | (unsolicited ? 0x10 : 0) | (incoming[0] & 0x0F)));
    REQUIRE(confirm.ToRSeq()[1] == 0);
    HexSequence objects("78 03 07 01 64 00 00 00 01 00 78 09 5B 01 10 00");
    REQUIRE(confirm.ToRSeq().skip(2).take(16).equals(objects.ToRSeq()));
    auto transcript = incoming; // Complete incoming APDU, including V9 MAC when present.
    const auto prefix = confirm.ToRSeq().take(18);
    transcript.insert(transcript.end(), static_cast<const uint8_t*>(prefix), static_cast<const uint8_t*>(prefix) + prefix.length());
    std::array<uint8_t, 16> expected{};
    REQUIRE(crypto::ComputeHMACSHA256(controlKey, rseq_t(transcript.data(), transcript.size()),
                                      wseq_t(expected.data(), expected.size())) == crypto::Result::OK);
    REQUIRE(crypto::ConstantTimeEqual(rseq_t(expected.data(), expected.size()), confirm.ToRSeq().skip(18)));
    REQUIRE(pair.master.context->isSending);
    const auto processed = pair.master.context->solSeq.Get();
    REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(incoming.data(), incoming.size()))));
    pair.master.exe->run_many();
    REQUIRE(pair.master.context->isSending);
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.master.context->confirmQueue.size() == (queueMode == 1 ? 2 : 0));
    if (queueMode == 1)
    {
        REQUIRE(pair.master.context->confirmQueue.front().control.UNS == unsolicited);
        REQUIRE(pair.master.context->confirmQueue.front().control.SEQ == (incoming[0] & 0x0F));
        REQUIRE(pair.master.context->confirmQueue.back().control.UNS);
        REQUIRE(pair.master.context->confirmQueue.back().control.SEQ == 7);
    }
    REQUIRE(pair.master.context->solSeq.Get() == processed);
    REQUIRE(pair.changes == 2);
}
