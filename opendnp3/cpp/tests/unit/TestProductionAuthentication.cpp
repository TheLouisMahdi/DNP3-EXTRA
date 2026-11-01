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
namespace opendnp3
{
class ProductionAuthenticationTestAccess
{
public:
    static SessionKeys& Common(MContext& context) { return *context.authentication->sessions->Find(1); }
    static uint8_t Deferred(MContext& context) { return context.authentication->deferredAuthenticationCount; }
    static SessionKeys& Common(OContext& context) { return *context.authentication->sessions->Find(1); }
    static size_t Pending(OContext& context) { return context.authentication->pendingWireSize; }
    static uint8_t Deferred(OContext& context) { return context.authentication->deferredControlCount; }
    static rseq_t AggressiveBytes(OContext& context, size_t size)
    {
        REQUIRE(size <= context.authentication->aggressiveWire.size());
        return rseq_t(context.authentication->aggressiveWire.data(), size);
    }
    static void LeaveMessages(OContext& context, uint32_t remaining)
    {
        const auto now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            context.executor->get_time().time_since_epoch()).count());
        auto& session = Common(context);
        REQUIRE(session.Ready(now));
        REQUIRE(session.RemainingMessages() >= remaining);
        while (session.RemainingMessages() > remaining)
            session.CountAuthentication(now);
    }
    static void LeaveMessages(MContext& context, uint32_t remaining)
    {
        const auto now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            context.executor->get_time().time_since_epoch()).count());
        auto& session = Common(context);
        REQUIRE(session.Ready(now));
        REQUIRE(session.RemainingMessages() >= remaining);
        while (session.RemainingMessages() > remaining)
            session.CountAuthentication(now);
    }
};
}
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
    const auto queueMode = !aggressiveResponse && fault == 0 ? GENERATE(0, 1, 2, 3, 4, 5) : 0;
    const auto budget = fault == 0
        ? (aggressiveResponse
            ? GENERATE(0u, 2u)
            : GENERATE(0u, 1u, 2u, 3u, 5u))
        : 0u;
    const bool nativeOnly = budget && budget <= 3 ? (aggressiveResponse ? true : GENERATE(false, true)) : false;
    const auto authenticatedCount = aggressiveResponse ? 1u : 2u;
    const auto nativeDeferred = budget <= authenticatedCount ? authenticatedCount + 1 - budget : 1u;
    const auto nativeRemaining = budget ? budget - (authenticatedCount - nativeDeferred) : 0u;
    const auto nativeAbort = nativeOnly ? GENERATE(0, 1, 2, 3) : 0;
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
    if (!nativeOnly)
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
    if (aggressiveResponse && budget)
        ProductionAuthenticationTestAccess::LeaveMessages(*pair.master.context, budget);
    REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(incoming.data(), incoming.size()))));
    pair.master.exe->run_many();
    if (!aggressiveResponse && pair.master.lower->NumWrites())
    {
        REQUIRE(pair.master.lower->NumWrites() == 1);
        const auto issued = pair.master.lower->PopWriteAsHex();
        if (queueMode == 0)
            REQUIRE(pair.master.context->OnTxReady());
        else if (queueMode == 1 || queueMode == 3 || queueMode == 4 || queueMode == 5)
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
        if (budget)
            ProductionAuthenticationTestAccess::LeaveMessages(*pair.master.context, budget);
        REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(encoded.data(), size))));
        pair.master.exe->run_many();
        if (budget && queueMode != 0)
        {
            REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context)
                    == (nativeOnly ? nativeDeferred : (budget <= 3 ? 4 - budget : 0)));
            REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages()
                    == (nativeOnly ? nativeRemaining : (budget <= 3 ? 1 : budget - 3)));
        }
        if (queueMode != 0)
        {
            REQUIRE(pair.master.context->isSending); // Original monitoring Challenge is still in flight.
            REQUIRE(pair.master.lower->NumWrites() == 0);
            REQUIRE(pair.master.context->confirmQueue.size() == (queueMode == 2 ? 1 : 3));
            if (queueMode == 4)
            {
                REQUIRE(pair.master.context->OnLowerLayerDown());
                REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == 0);
                REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages() == 0);
                REQUIRE(pair.master.context->confirmQueue.size() == 2);
                REQUIRE(pair.master.context->confirmQueue.front().control.SEQ == (incoming[0] & 0x0F));
                REQUIRE(pair.master.context->confirmQueue.back().control.SEQ == 7);
                REQUIRE_FALSE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(encoded.data(), size))));
                REQUIRE_FALSE(pair.master.context->OnTxReady());
                REQUIRE(pair.master.lower->NumWrites() == 0);
                return;
            }
            if (queueMode == 3 || queueMode == 5)
            {
                const auto delay = queueMode == 5
                    ? std::chrono::milliseconds(ProductionAuthenticationTestAccess::Common(*pair.master.context).ValidUntil())
                        - std::chrono::duration_cast<std::chrono::milliseconds>(pair.master.exe->get_time().time_since_epoch())
                    : std::chrono::milliseconds(pair.master.context->params.authentication.replyTimeoutMs);
                pair.master.exe->advance_time(delay);
                pair.master.exe->run_many();
                REQUIRE(pair.master.context->isSending); // Do not cancel the in-flight Challenge.
                REQUIRE(pair.master.lower->NumWrites() == 0);
                REQUIRE(pair.master.context->confirmQueue.size() == 2);
                REQUIRE(pair.master.context->confirmQueue.front().control.UNS == unsolicited);
                REQUIRE(pair.master.context->confirmQueue.front().control.SEQ == (incoming[0] & 0x0F));
                REQUIRE(pair.master.context->confirmQueue.back().control.UNS);
                REQUIRE(pair.master.context->confirmQueue.back().control.SEQ == 7);
                REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == 0);
                if (queueMode == 5 || (budget && budget <= 3))
                    REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages()
                            == (queueMode != 5 && nativeOnly && budget > authenticatedCount ? budget - authenticatedCount : 0));
                if (queueMode == 5)
                {
                    REQUIRE(pair.master.context->OnTxReady());
                    pair.master.exe->run_many();
                    while (pair.master.lower->NumWrites())
                    {
                        HexSequence request(pair.master.lower->PopWriteAsHex());
                        REQUIRE(request.ToRSeq()[1] == 0x20); // Expired keys cannot transmit a stale CONFIRM.
                    }
                    REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == 0);
                }
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
    if (nativeOnly)
    {
        // Native CONFIRM remains plain and uses its existing standalone Challenge/Reply lifecycle.
        REQUIRE(confirm.ToRSeq().length() == 2);
        REQUIRE(confirm.ToRSeq()[0] == static_cast<uint8_t>(0xC0 | (unsolicited ? 0x10 : 0) | (incoming[0] & 0x0F)));
        REQUIRE(confirm.ToRSeq()[1] == 0);
        REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == nativeDeferred);
        REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages() == nativeRemaining);
        const auto processed = pair.master.context->solSeq.Get();
        REQUIRE(pair.master.context->confirmQueue.size() == (queueMode == 1 ? 2 : 0));
        REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(incoming.data(), incoming.size()))));
        pair.master.exe->run_many();
        REQUIRE(pair.master.context->solSeq.Get() == processed);
        REQUIRE(pair.master.lower->NumWrites() == 0);
        APDUResponse issued(wseq_t(encoded.data(), encoded.size()));
        issued.SetFunction(FunctionCode::AUTH_RESPONSE);
        issued.SetControl(AppControlField::Request(confirm.ToRSeq()[0] & 0x0F));
        issued.SetIIN(IINField::Empty());
        auto challengeWriter = issued.GetWriter();
        REQUIRE(challengeWriter.WriteFreeFormat(&challenge, 1));
        std::vector<uint8_t> standalone(encoded.data(), encoded.data() + issued.Size());
        // Receive the Challenge before completion of the in-flight native CONFIRM.
        REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(standalone.data(), standalone.size()))));
        pair.master.exe->run_many();
        REQUIRE(pair.master.lower->NumWrites() == 0);
        REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == nativeDeferred + 1);
        REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages() == nativeRemaining);
        if (nativeAbort)
        {
            if (nativeAbort == 2)
                REQUIRE(pair.master.context->OnLowerLayerDown());
            else
            {
                const auto delay = nativeAbort == 3
                    ? std::chrono::milliseconds(ProductionAuthenticationTestAccess::Common(*pair.master.context).ValidUntil())
                        - std::chrono::duration_cast<std::chrono::milliseconds>(pair.master.exe->get_time().time_since_epoch())
                    : std::chrono::milliseconds(pair.master.context->params.authentication.replyTimeoutMs);
                pair.master.exe->advance_time(delay);
                pair.master.exe->run_many();
                REQUIRE(pair.master.context->isSending); // Native CONFIRM remains in flight; its unsent Reply is discarded.
                REQUIRE(pair.master.context->OnTxReady());
                pair.master.exe->run_many();
            }
            REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == 0);
            REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages() == 0);
            while (pair.master.lower->NumWrites())
            {
                HexSequence request(pair.master.lower->PopWriteAsHex());
                REQUIRE(request.ToRSeq()[1] == 0x20);
                REQUIRE(request.ToRSeq()[3] != 2); // A stale generated G120V2 must never be sent.
            }
            return;
        }
        REQUIRE(pair.master.context->OnTxReady());
        REQUIRE(pair.master.lower->NumWrites() == 1);
        HexSequence reply(pair.master.lower->PopWriteAsHex());
        REQUIRE(reply.ToRSeq().length() == 30);
        REQUIRE(reply.ToRSeq()[1] == 0x20);
        HexSequence replyPrefix("78 02 5B 01 16 00 64 00 00 00 01 00");
        REQUIRE(reply.ToRSeq().skip(2).take(12).equals(replyPrefix.ToRSeq()));
        standalone.insert(standalone.end(), static_cast<const uint8_t*>(confirm.ToRSeq()),
                          static_cast<const uint8_t*>(confirm.ToRSeq()) + confirm.ToRSeq().length());
        std::array<uint8_t, 16> expected{};
        REQUIRE(crypto::ComputeHMACSHA256(controlKey, rseq_t(standalone.data(), standalone.size()),
                                          wseq_t(expected.data(), expected.size())) == crypto::Result::OK);
        REQUIRE(crypto::ConstantTimeEqual(rseq_t(expected.data(), expected.size()), reply.ToRSeq().skip(14)));
        REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == 0);
        REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages() == 0);
        REQUIRE(pair.master.context->solSeq.Get() == processed);
        REQUIRE(pair.master.context->confirmQueue.size() == (queueMode == 1 ? 2 : 0));
        const auto epoch = ProductionAuthenticationTestAccess::Common(*pair.master.context).Sequence();
        const auto operations = pair.outstation.cmdHandler->NumOperate();
        REQUIRE(pair.master.context->OnTxReady());
        pair.master.exe->run_many();
        size_t exchanges = 0;
        while (ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages() == 0)
        {
            REQUIRE(++exchanges <= 2);
            REQUIRE(pair.master.lower->NumWrites() == 1);
            const auto packet = pair.master.lower->PopWriteAsHex();
            HexSequence request(packet);
            REQUIRE(request.ToRSeq()[1] == 0x20); // No application request until renewed keys are valid.
            REQUIRE(request.ToRSeq()[2] == 120);
            REQUIRE(request.ToRSeq()[3] == (exchanges == 1 ? 4 : 6));
            REQUIRE(pair.master.context->OnTxReady());
            pair.outstation.SendToOutstation(packet);
            REQUIRE(pair.outstation.lower->NumWrites() == 1);
            const auto status = pair.outstation.lower->PopWriteAsHex();
            pair.outstation.OnTxReady();
            REQUIRE(pair.master.SendToMaster(status));
            pair.master.exe->run_many();
            REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);
        }
        REQUIRE(exchanges == 2);
        REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).Sequence() != epoch);
        REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == 0);
        return;
    }
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
    REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == 0);
    if (budget)
        REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages()
                == (budget <= 4 ? 0 : budget - 4)); // Challenge, Reply, embedded Challenge, Aggressive CONFIRM.
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
    if (budget)
        REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages()
                == (budget <= 4 ? 0 : budget - 4)); // Replay cannot finalize/count again.
    REQUIRE(pair.changes == 2);
    if (budget && budget <= 3)
    {
        REQUIRE(pair.master.context->OnTxReady());
        pair.master.exe->run_many();
        REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages() == 0);
        REQUIRE(pair.changes == 2); // No renewed keys have been installed yet.
        while (pair.master.lower->NumWrites())
        {
            HexSequence request(pair.master.lower->PopWriteAsHex());
            REQUIRE(request.ToRSeq()[1] == 0x20); // Only key exchange, never a protected application request.
        }
    }
}

TEST_CASE("ProductionAuthentication - normal verified response completes before count renewal and cannot execute the next command", "[production-sa]")
{
    RuntimePair pair;
    pair.Pump();
    pair.SelectOperate();
    const auto before = pair.master.context->solSeq.Get();
    std::string reply;
    for (size_t step = 0; step < 3; ++step)
    {
        REQUIRE(pair.master.lower->NumWrites() == 1);
        const auto request = pair.master.lower->PopWriteAsHex();
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(request);
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        reply = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        if (step == 2)
            ProductionAuthenticationTestAccess::LeaveMessages(*pair.master.context, 2);
        REQUIRE(pair.master.SendToMaster(reply));
        pair.master.exe->run_many();
    }
    REQUIRE(pair.master.context->solSeq.Get() == ((before + 1) & 0x0F));
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
    REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages() == 0);
    REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == 0);
    const auto processed = pair.master.context->solSeq.Get();
    REQUIRE(pair.master.SendToMaster(reply));
    pair.master.exe->run_many();
    REQUIRE(pair.master.context->solSeq.Get() == processed);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
    REQUIRE(pair.changes == 2); // Subsequent operations cannot use the exhausted session.
}

TEST_CASE("ProductionAuthentication - outstation queued monitoring Reply counts on send and respects its lifetime", "[production-sa]")
{
    const auto budget = GENERATE(1u, 3u);
    const auto scenario = GENERATE(0, 1, 2, 3, 4, 5); // Send, timeout, disconnect, abort, key replacement, key expiry.
    RuntimePair pair;
    pair.Pump();
    pair.SelectOperate();
    const auto before = pair.master.context->solSeq.Get();
    for (size_t step = 0; step < 2; ++step)
    {
        REQUIRE(pair.master.lower->NumWrites() == 1);
        const auto request = pair.master.lower->PopWriteAsHex();
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(request);
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        const auto response = pair.outstation.lower->PopWriteAsHex();
        if (step == 0)
            pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(response));
        pair.master.exe->run_many();
    }
    // The native SELECT response is still in flight when its monitoring Challenge arrives.
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto challenge = pair.master.lower->PopWriteAsHex();
    HexSequence challenged(challenge);
    REQUIRE(challenged.ToRSeq()[1] == 0x20);
    REQUIRE(challenged.ToRSeq()[3] == 1);
    REQUIRE(pair.master.context->OnTxReady());
    auto& session = ProductionAuthenticationTestAccess::Common(pair.outstation.context);
    const auto expiry = session.ValidUntil();
    ProductionAuthenticationTestAccess::LeaveMessages(pair.outstation.context, budget);
    pair.outstation.SendToOutstation(challenge);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(ProductionAuthenticationTestAccess::Pending(pair.outstation.context) != 0);
    REQUIRE(session.RemainingMessages() == budget - 1); // Only the received Challenge has been counted.
    REQUIRE(pair.master.context->solSeq.Get() == before);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
    if (scenario == 1)
        pair.outstation.AdvanceTime(TimeDuration::Milliseconds(pair.master.context->params.authentication.replyTimeoutMs));
    else if (scenario == 2)
        pair.outstation.LowerLayerDown();
    else if (scenario == 3)
        pair.outstation.SendToOutstation("C0 20 78 02 5B 01 01 00 00");
    else if (scenario == 4)
        REQUIRE(session.Configure(rseq_t(pair.source->keys[0].data(), 32), 10000000, 0) == SessionKeys::Result::OK);
    else if (scenario == 5)
        pair.outstation.AdvanceTime(TimeDuration::Milliseconds(expiry));
    if (scenario == 2)
        REQUIRE_FALSE(pair.outstation.context.OnTxReady());
    else
        REQUIRE(pair.outstation.context.OnTxReady());
    REQUIRE(ProductionAuthenticationTestAccess::Pending(pair.outstation.context) == 0);
    if (scenario != 0)
    {
        REQUIRE(pair.outstation.lower->NumWrites() == 0); // No stale precomputed Reply after abort/expiry/rekey.
        REQUIRE(pair.master.context->solSeq.Get() == before);
        REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
        if (scenario == 1 || scenario == 3)
            REQUIRE(session.RemainingMessages() == budget - 1); // An unsent Reply is never counted.
        if (scenario == 4 || scenario == 5)
            REQUIRE_FALSE(session.Ready(scenario == 5 ? expiry : 0));
        return;
    }
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto reply = pair.outstation.lower->PopWriteAsHex();
    HexSequence accepted(reply);
    REQUIRE(accepted.ToRSeq()[1] == 0x83);
    REQUIRE(accepted.ToRSeq()[5] == 2);
    REQUIRE(session.RemainingMessages() == (budget == 3 ? 1 : 0));
    pair.outstation.OnTxReady();
    pair.outstation.SendToOutstation(challenge); // Replayed Challenge cannot regenerate or recount the Reply.
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(session.RemainingMessages() == (budget == 3 ? 1 : 0));
    REQUIRE(pair.master.SendToMaster(reply)); // Existing Master verifies the exact queued MAC transcript.
    pair.master.exe->run_many();
    REQUIRE(pair.master.context->solSeq.Get() == ((before + 1) & 0x0F));
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
    if (budget == 1)
        REQUIRE_FALSE(session.Ready(0)); // The precomputed Reply does not revive expired session keys.
}

TEST_CASE("ProductionAuthentication - outstation reset preserves aggressive response bytes already in flight", "[production-sa]")
{
    RuntimePair pair(false, true);
    pair.Pump();
    pair.SelectOperate();
    pair.Pump();
    pair.SelectOperate();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto request = pair.master.lower->PopWriteAsHex();
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(request);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    HexSequence response(pair.outstation.lower->PopWriteAsHex());
    REQUIRE(response.ToRSeq()[4] == 120);
    REQUIRE(response.ToRSeq()[5] == 3);
    const auto selections = pair.outstation.cmdHandler->NumSelect();
    REQUIRE(ProductionAuthenticationTestAccess::AggressiveBytes(pair.outstation.context, response.ToRSeq().length())
                .equals(response.ToRSeq()));
    pair.outstation.SendToOutstation("C0 20 78 02 5B 01 01 00 00");
    REQUIRE(ProductionAuthenticationTestAccess::AggressiveBytes(pair.outstation.context, response.ToRSeq().length())
                .equals(response.ToRSeq()));
    REQUIRE(pair.outstation.context.OnTxReady());
    const auto cleared = ProductionAuthenticationTestAccess::AggressiveBytes(pair.outstation.context, response.ToRSeq().length());
    for (size_t i = 0; i < cleared.length(); ++i)
        REQUIRE(cleared[i] == 0);
    pair.outstation.SendToOutstation(request);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == selections);
}

TEST_CASE("ProductionAuthentication - outstation common-user control accounting preserves its retained response", "[production-sa]")
{
    const auto budget = GENERATE(1u, 2u);
    const bool timeout = GENERATE(false, true);
    RuntimePair pair;
    pair.Pump();
    auto& session = ProductionAuthenticationTestAccess::Common(pair.outstation.context);
    MasterResponder controlPeer(7, 16, 2000);
    REQUIRE(controlPeer.SetSessionKey(1, session.ControlKey(0), session.ValidUntil(), 0) == MasterResponder::Result::OK);
    OutstationChallenger monitoringPeer(7, 16, 2000, true);
    REQUIRE(monitoringPeer.SetSessionKey(1, session.MonitoringKey(0), session.ValidUntil(), 0)
            == OutstationChallenger::Result::OK);
    HexSequence read("C5 01 3C 01 06");
    REQUIRE(controlPeer.RetainRequest(7, read.ToRSeq(), 0) == MasterResponder::Result::OK);
    pair.outstation.SendToOutstation("C5 01 3C 01 06");
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    HexSequence challenge(pair.outstation.lower->PopWriteAsHex());
    pair.outstation.OnTxReady();
    std::array<uint8_t, 2048> wire{}, verified{};
    size_t size = 0, verifiedSize = 0;
    REQUIRE(controlPeer.Respond(7, challenge.ToRSeq(), 0, wseq_t(wire.data(), wire.size()), size)
            == MasterResponder::Result::OK);
    ProductionAuthenticationTestAccess::LeaveMessages(pair.outstation.context, budget);
    pair.outstation.SendToOutstation(HexConversions::to_hex(rseq_t(wire.data(), size)));
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    HexSequence response(pair.outstation.lower->PopWriteAsHex());
    REQUIRE(response.ToRSeq()[1] == 0x81);
    REQUIRE((response.ToRSeq()[0] & 0x20) == 0);
    REQUIRE(ProductionAuthenticationTestAccess::Deferred(pair.outstation.context) == 3 - budget);
    REQUIRE(session.RemainingMessages() == 1);
    pair.outstation.OnTxReady();
    pair.outstation.SendToOutstation("C6 01 3C 01 06"); // A new READ cannot consume the retained response's key budget.
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(ProductionAuthenticationTestAccess::Deferred(pair.outstation.context) == 3 - budget);
    if (timeout)
    {
        pair.outstation.AdvanceTime(TimeDuration::Milliseconds(pair.master.context->params.authentication.replyTimeoutMs));
        REQUIRE(ProductionAuthenticationTestAccess::Deferred(pair.outstation.context) == 0);
        REQUIRE_FALSE(session.Ready(pair.master.context->params.authentication.replyTimeoutMs));
        REQUIRE(pair.outstation.lower->NumWrites() == 0);
        return;
    }
    REQUIRE(monitoringPeer.Challenge(7, response.ToRSeq(), IINField::Empty(), 0,
                                     wseq_t(wire.data(), wire.size()), size) == OutstationChallenger::Result::OK);
    const auto request = HexConversions::to_hex(rseq_t(wire.data(), size));
    pair.outstation.SendToOutstation(request);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    HexSequence reply(pair.outstation.lower->PopWriteAsHex());
    REQUIRE(ProductionAuthenticationTestAccess::Deferred(pair.outstation.context) == 0);
    REQUIRE_FALSE(session.Ready(0));
    Group120Var2 value;
    REQUIRE(value.Read(reply.ToRSeq().skip(10)));
    REQUIRE(monitoringPeer.Reply(7, value, 0, wseq_t(verified.data(), verified.size()), verifiedSize)
            == OutstationChallenger::Result::AUTHENTICATED);
    REQUIRE(rseq_t(verified.data(), verifiedSize).equals(response.ToRSeq()));
    pair.outstation.OnTxReady();
    pair.outstation.SendToOutstation(request);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(session.RemainingMessages() == 0);
}
