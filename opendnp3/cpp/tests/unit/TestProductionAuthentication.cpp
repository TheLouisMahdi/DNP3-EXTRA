// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/APDUResponse.h"
#include "app/APDURequest.h"
#include "crypto/CryptoProvider.h"
#include "utils/BufferHelpers.h"
#include "utils/CommandCallbackQueue.h"
#include "utils/MasterTestFixture.h"
#include "utils/OutstationTestObject.h"

#include <ser4cpp/util/HexConversions.h>

#include <catch.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <vector>

using namespace opendnp3;
using namespace ser4cpp;
namespace opendnp3
{
class ProductionAuthenticationTestAccess
{
public:
    static AuthenticationStatistics& Stats(MContext& context) { return context.authentication->sessions->statistics; }
    static AuthenticationStatistics& Stats(OContext& context) { return context.authentication->sessions->statistics; }
    static void ObserveClose(OContext& context, std::function<void()> callback)
    {
        context.authentication->closeTCPConnection = std::move(callback);
    }
    static SessionKeys& Common(MContext& context) { return *context.authentication->sessions->Find(1); }
    static SessionKeys& Session(MContext& context, uint16_t user)
    {
        return *context.authentication->sessions->Find(user);
    }
    static uint8_t Deferred(MContext& context) { return context.authentication->deferredAuthenticationCount; }
    static AggressiveMode& ControlAggressive(MContext& context) { return context.authentication->controlAggressive; }
    static bool ControlEligible(MContext& context) { return context.authentication->controlEligible[1]; }
    static bool ReplyIssued(MContext& context) { return context.authentication->replyIssued; }
    static bool ReplyPending(MContext& context) { return context.authentication->replyPending; }
    static bool CheckConfirm(MContext& context) { return context.CheckConfirmTransmit(); }
    static bool MonitoringWaiting(MContext& context) { return context.authentication->monitorWaiting; }
    static size_t Pending(MContext& context) { return context.authentication->pendingWireSize; }
    static rseq_t PendingBytes(MContext& context)
    {
        return rseq_t(context.authentication->pendingWire.data(), context.authentication->pendingWire.size());
    }
    static rseq_t WireBytes(MContext& context, size_t size)
    {
        REQUIRE(size <= context.authentication->wire.size());
        return rseq_t(context.authentication->wire.data(), size);
    }
    static rseq_t ReplyBytes(MContext& context)
    {
        return rseq_t(context.authentication->reply.data(), context.authentication->reply.size());
    }
    static rseq_t AggressiveBytes(MContext& context, size_t size)
    {
        REQUIRE(size <= context.authentication->aggressiveWire.size());
        return rseq_t(context.authentication->aggressiveWire.data(), size);
    }
    static void ReceiveOtherAssociation(OContext& context, rseq_t apdu)
    {
        const auto expected = context.addresses.Reverse();
        context.OnReceive(Message(Addresses(static_cast<uint16_t>(expected.source ^ 1u), expected.destination), apdu));
    }
    static SessionKeys& Common(OContext& context) { return *context.authentication->sessions->Find(1); }
    static SessionKeys& Session(OContext& context, uint16_t user)
    {
        return *context.authentication->sessions->Find(user);
    }
    static size_t Pending(OContext& context) { return context.authentication->pendingWireSize; }
    static bool MonitoringPending(OContext& context) { return context.authentication->monitoringPending; }
    static OutstationChallenger::State ChallengeState(OContext& context)
    {
        return context.authentication->challenger.GetState();
    }
    static rseq_t ChallengeBytes(OContext& context)
    {
        return rseq_t(context.authentication->challenge.data(), context.authentication->challenge.size());
    }
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
struct RuntimeErrorObserver final : IAuthenticationErrorObserver
{
    size_t received = 0, discarded = 0, denied = 0, sent = 0;
    void OnErrorReceived(uint16_t association, uint16_t, uint32_t, uint8_t, bool pending) override
    {
        REQUIRE(association == 7);
        ++received;
        if (pending) ++discarded;
    }
    void OnAuthorizationFailure(uint16_t, uint16_t, uint32_t) override { ++denied; }
    void OnErrorSent(uint16_t, uint16_t, uint32_t, uint8_t code) override
    {
        REQUIRE(code == 7);
        ++sent;
    }
};
struct RuntimePolicy final : IAuthenticationAuthorization
{
    bool allowControl = true, allowCommonWrite = true, allowCommonSelect = false;
    bool IsAuthorized(uint16_t assoc, uint16_t user, uint8_t function, const uint8_t* apdu, size_t size) const override
    {
        return apdu && size >= 2 && apdu[1] == function && assoc == 7
            && ((user == 1 && (function == 0 || function == 1 || (function == 2 && allowCommonWrite)
                            || (function == 3 && allowCommonSelect)))
                || (user == 2 && allowControl));
    }
};
MasterParams MasterSettings(const std::shared_ptr<RuntimeCredentials>& source,
                            const std::shared_ptr<RuntimePolicy>& policy,
                            bool aggressive = false,
                            bool receiveAggressive = false, bool macAlternatives = false,
                            const std::shared_ptr<IAuthenticationErrorObserver>& observer = nullptr)
{
    auto p = NoStartupTasks();
    p.authentication.errorObserver = observer;
    if (macAlternatives) p.authentication.permittedMACAlgorithms = {{4, 2, 0, 0}};
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
                             bool aggressive = false, bool macAlternatives = false,
                             const std::shared_ptr<IAuthenticationErrorObserver>& observer = nullptr,
                             uint16_t maxErrors = 2, bool suppressErrors = false)
{
    OutstationConfig c;
    c.params.authentication.maxErrorMessagesSent = maxErrors;
    c.params.authentication.suppressAuthenticationErrors = suppressErrors;
    c.params.authentication.errorObserver = observer;
    if (macAlternatives) c.params.authentication.permittedMACAlgorithms = {{4, 2, 0, 0}};
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
    explicit RuntimePair(bool unsolicited = false, bool aggressive = false, bool receiveAggressive = false,
                         const std::shared_ptr<ILogHandler>& masterLog = nullptr, bool macAlternatives = false,
                         const std::shared_ptr<IAuthenticationErrorObserver>& observer = nullptr,
                         uint16_t maxErrors = 2, bool suppressErrors = false)
        : master(MasterSettings(source, policy, aggressive, receiveAggressive, macAlternatives, observer), Addresses(), "test", masterLog),
          outstation(OutSettings(source, policy, unsolicited, aggressive, macAlternatives, observer, maxErrors, suppressErrors))
    {
        outstation.LowerLayerUp();
        REQUIRE(master.context->OnLowerLayerUp());
        master.exe->run_many();
    }
    void Pump(OutstationTestObject* alternate = nullptr)
    {
        auto& peer = alternate ? *alternate : outstation;
        size_t steps = 0;
        while (master.lower->NumWrites() || peer.lower->NumWrites())
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
                peer.SendToOutstation(hex);
            }
            if (peer.lower->NumWrites())
            {
                auto hex = peer.lower->PopWriteAsHex();
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
                peer.OnTxReady();
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
TEST_CASE("ProductionAuthentication - standalone Error dispatch cancels only its Challenge owner", "[production-sa][auth-error]")
{
    const bool masterChallenger = GENERATE(false, true);
    // Match, association, user, CSQ, app SEQ, CON, UNS, qualifier, count,
    // obsolete code, another valid code, wrong function, extra object, unknown user.
    const auto fault = GENERATE(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    const auto code = fault == 0 ? GENERATE(uint8_t{5}, uint8_t{7}, uint8_t{128}) : uint8_t{5};
    const bool cancels = fault == 0 || fault == 10;
    const bool alternatives = fault == 0 && code == 5 ? GENERATE(false, true) : false;
    auto masterLog = std::make_shared<MockLogHandlerImpl>();
    auto observer = std::make_shared<RuntimeErrorObserver>();
    RuntimePair pair(false, false, false, masterLog, alternatives, observer);
    std::string pendingRequest, lateReply;
    Group120Var1 challenge;
    rseq_t borrowed;
    if (masterChallenger)
    {
        // Complete user 1 only; user 2's V4 stays in flight concurrently.
        for (size_t step = 0; step < 2; ++step)
        {
            const auto request = pair.master.lower->PopWriteAsHex();
            REQUIRE(pair.master.context->OnTxReady());
            pair.outstation.SendToOutstation(request);
            REQUIRE(pair.outstation.lower->NumWrites() == 1);
            const auto status = pair.outstation.lower->PopWriteAsHex();
            pair.outstation.OnTxReady();
            REQUIRE(pair.master.SendToMaster(status));
            pair.master.exe->run_many();
        }
        pendingRequest = pair.master.lower->PopWriteAsHex();
        HexSequence inFlight(pendingRequest);
        REQUIRE(inFlight.ToRSeq()[3] == 4);
        borrowed = ProductionAuthenticationTestAccess::WireBytes(*pair.master.context, inFlight.ToRSeq().length());
        REQUIRE(pair.master.SendToMaster("F3 82 00 00"));
        REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
        const auto pending = ProductionAuthenticationTestAccess::PendingBytes(*pair.master.context);
        REQUIRE(challenge.Read(pending.take(ProductionAuthenticationTestAccess::Pending(*pair.master.context)).skip(8)));
    }
    else
    {
        pair.Pump();
        pair.SelectOperate();
        const auto request = pair.master.lower->PopWriteAsHex();
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(request);
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        const auto c1 = pair.outstation.lower->PopWriteAsHex();
        HexSequence packet(c1);
        REQUIRE(challenge.Read(packet.ToRSeq().skip(10)));
        borrowed = ProductionAuthenticationTestAccess::ChallengeBytes(pair.outstation.context);
        pendingRequest = c1;
        REQUIRE(pair.master.SendToMaster(c1));
        REQUIRE(pair.master.lower->NumWrites() == 1);
        lateReply = pair.master.lower->PopWriteAsHex();
        REQUIRE(pair.master.context->OnTxReady());
    }
    const auto appSequence = masterChallenger ? uint8_t{3} : uint8_t{0};
    const auto user = masterChallenger ? uint16_t{1} : uint16_t{0};
    Group120Var7 error(challenge.seqNum, user, 7, code, DNPTime(0), rseq_t());
    const uint8_t privateText = 'E';
    if (code >= 128) error.errorText = rseq_t(&privateText, 1);
    const uint8_t invalidUTF8[] = {0xC0, 0xAF};
    if (fault == 14 || fault == 15)
    {
        error.errorCode = 128;
        error.errorText = fault == 14 ? rseq_t() : rseq_t(invalidUTF8, sizeof(invalidUTF8));
    }
    if (fault == 1) error.associationId = 8;
    if (fault == 2) error.userNum = masterChallenger ? 2 : 1;
    if (fault == 3) --error.seqNum;
    if (fault == 9) error.errorCode = 2;
    if (fault == 10) error.errorCode = 1; // Matching ownership, not code 5, determines cancellation.
    if (fault == 13)
    {
        error.userNum = 3;
        error.errorCode = 11; // Valid Unknown User error: log it without cancelling the active exchange.
    }
    std::array<uint8_t, 128> data{};
    size_t errorSize = 0;
    const auto seq = fault == 4 ? uint8_t(appSequence + 1) : appSequence;
    if (masterChallenger)
    {
        APDUResponse response(wseq_t(data.data(), data.size()));
        response.SetFunction(FunctionCode::AUTH_RESPONSE);
        response.SetControl(AppControlField(true, true, false, false, seq));
        response.SetIIN(IINField::Empty());
        auto writer = response.GetWriter();
        REQUIRE(writer.WriteFreeFormat(&error, 1));
        if (fault == 12) REQUIRE(writer.WriteFreeFormat(&error, 1));
        errorSize = response.Size();
    }
    else
    {
        APDURequest request(wseq_t(data.data(), data.size()));
        request.ConfigureHeader(FunctionCode::AUTH_REQUEST_NO_ACK, seq);
        auto writer = request.GetWriter();
        REQUIRE(writer.WriteFreeFormat(&error, 1));
        if (fault == 12) REQUIRE(writer.WriteFreeFormat(&error, 1));
        errorSize = request.Size();
    }
    const size_t objectOffset = masterChallenger ? 4 : 2;
    if (fault == 5) data[0] |= 0x20;
    if (fault == 6) data[0] |= 0x10;
    if (fault == 7) data[objectOffset + 2] = 0x07;
    if (fault == 8) data[objectOffset + 3] = 0;
    if (fault == 11) data[1] = 0x20;
    const bool validError = fault == 0 || fault == 2 || fault == 3 || fault == 4 || fault == 10 || fault == 13;
    const auto errorWire = HexConversions::to_hex(rseq_t(data.data(), errorSize));
    masterLog->messages.clear();
    pair.outstation.log.ClearLog();
    if (masterChallenger)
    {
        auto& stats = ProductionAuthenticationTestAccess::Stats(*pair.master.context);
        const auto before = stats.Values();
        REQUIRE(pair.master.SendToMaster(errorWire));
        REQUIRE(observer->received == (validError ? 1 : 0));
        REQUIRE(observer->discarded == (cancels ? 1 : 0));
        if (fault == 13)
        {
            REQUIRE(stats.Value(SecurityStatistic::ERROR_MESSAGES_RECEIVED) == before[11] + 1);
            REQUIRE(stats.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == before[0] + 1);
            REQUIRE(stats.Value(SecurityStatistic::DISCARDED_MESSAGES) == before[9] + 1);
            bool logged = false;
            for (const auto& record : masterLog->messages)
                logged = logged || record.message.find("Authentication error received: code=11 user=3 ") == 0;
            REQUIRE(logged);
        }
        if (cancels) REQUIRE(stats.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == before[0]);
        REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context) == (!cancels));
        HexSequence inFlight(pendingRequest);
        REQUIRE(borrowed.equals(inFlight.ToRSeq()));
        REQUIRE(pair.master.lower->NumWrites() == 0);
        REQUIRE(pair.master.context->solSeq.Get() == 0); // Error never releases the protected response.
        REQUIRE(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2).IsExchanging());
        if (!cancels)
        {
            // The valid response path must still complete after any ignored Error.
            REQUIRE(pair.master.context->OnTxReady());
            REQUIRE(pair.master.lower->NumWrites() == 1);
            HexSequence c1(pair.master.lower->PopWriteAsHex());
            REQUIRE(c1.ToRSeq()[3] == 1);
            REQUIRE(pair.master.context->OnTxReady());
            auto& common = ProductionAuthenticationTestAccess::Common(pair.outstation.context);
            MasterResponder peer(7, 16, 2000, true);
            REQUIRE(peer.SetSessionKey(1, common.MonitoringKey(0), common.ValidUntil(), 0) == MasterResponder::Result::OK);
            HexSequence original("F3 82 00 00");
            REQUIRE(peer.RetainRequest(7, original.ToRSeq(), 0) == MasterResponder::Result::OK);
            std::array<uint8_t, 64> reply{};
            size_t size = 0;
            REQUIRE(peer.Respond(7, c1.ToRSeq(), 0, wseq_t(reply.data(), reply.size()), size)
                == MasterResponder::Result::OK);
            REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(reply.data(), size))));
        }
        else
        {
            REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) == 0);
            REQUIRE(pair.master.SendToMaster(errorWire)); // Replay cannot revive the discarded response.
            REQUIRE(pair.master.context->OnTxReady());
        }
        // The independent user 2 exchange must still accept its real V5/V6/V5.
        pair.outstation.SendToOutstation(pendingRequest);
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        const auto status = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(status));
        pair.Pump();
        REQUIRE(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2).Ready(0));
    }
    else
    {
        auto& stats = ProductionAuthenticationTestAccess::Stats(pair.outstation.context);
        const auto before = stats.Values();
        pair.outstation.SendToOutstation(errorWire);
        REQUIRE(observer->received == (validError ? 1 : 0));
        REQUIRE(observer->discarded == (cancels ? 1 : 0));
        if (fault == 13) // Valid unowned Error: one Error received, one unexpected/discarded.
        {
            REQUIRE(stats.Value(SecurityStatistic::ERROR_MESSAGES_RECEIVED) == before[11] + 1);
            REQUIRE(stats.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == before[0] + 1);
            REQUIRE(stats.Value(SecurityStatistic::DISCARDED_MESSAGES) == before[9] + 1);
        }
        if (cancels) // An owned Error cancels its pending ASDU, not an unexpected Error.
            REQUIRE(stats.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == before[0]);
        if (fault == 13)
        {
            bool logged = false;
            LogRecord record;
            while (pair.outstation.log.GetNextEntry(record))
                logged = logged || record.message.find("Authentication error received: code=11 user=3 ") == 0;
            REQUIRE(logged);
        }
        REQUIRE((ProductionAuthenticationTestAccess::ChallengeState(pair.outstation.context)
            == OutstationChallenger::State::WAITING_FOR_REPLY) == (!cancels));
        HexSequence inFlight(pendingRequest);
        REQUIRE(borrowed.equals(inFlight.ToRSeq()));
        REQUIRE(pair.outstation.lower->NumWrites() == 0);
        REQUIRE(ProductionAuthenticationTestAccess::Common(pair.outstation.context).Ready(0));
        pair.outstation.OnTxReady();
        if (cancels) pair.outstation.SendToOutstation(errorWire);
        pair.outstation.SendToOutstation(lateReply);
        REQUIRE(pair.outstation.cmdHandler->NumSelect() == (cancels ? 0 : 1));
    }
    if (fault == 0 && code == 5)
    {
        // No immediate retry occurred above. A subsequent real receive event
        // either uses the approved alternative or fails closed with no Challenge.
        if (masterChallenger)
            REQUIRE(pair.master.SendToMaster("F4 82 00 00"));
        else
            pair.outstation.SendToOutstation("C1 03");
        const auto writes = masterChallenger ? pair.master.lower->NumWrites() : pair.outstation.lower->NumWrites();
        REQUIRE(writes == (alternatives ? 1 : 0));
        if (alternatives)
        {
            HexSequence next(masterChallenger ? pair.master.lower->PopWriteAsHex() : pair.outstation.lower->PopWriteAsHex());
            Group120Var1 value;
            REQUIRE(value.Read(next.ToRSeq().skip(masterChallenger ? 8 : 10)));
            REQUIRE(value.macAlgorithm == 2);
            REQUIRE(value.seqNum == challenge.seqNum + 1);
        }
        REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    }
}

TEST_CASE("ProductionAuthentication - standalone Error preserves independent outstation monitoring", "[production-sa][auth-error]")
{
    RuntimePair pair;
    pair.Pump();
    pair.SelectOperate();
    // Authenticate SELECT and retain its response for Monitoring Direction authentication.
    for (size_t step = 0; step < 2; ++step)
    {
        const auto request = pair.master.lower->PopWriteAsHex();
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(request);
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        const auto response = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(response));
    }
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringPending(pair.outstation.context));
    REQUIRE(pair.outstation.NumPendingTimers() == 1);
    const auto challenge = pair.master.lower->PopWriteAsHex();
    HexSequence c1(challenge);
    Group120Var1 value;
    REQUIRE(value.Read(c1.ToRSeq().skip(8)));
    // A late/unknown-user Reply has no control owner and must not cancel this
    // independently retained Monitoring response or its timer.
    std::array<uint8_t, 64> unexpectedBytes{};
    std::array<uint8_t, 16> unusedTag{};
    Group120Var2 unexpected(value.seqNum, 42, rseq_t(unusedTag.data(), unusedTag.size()));
    APDURequest unexpectedReply(wseq_t(unexpectedBytes.data(), unexpectedBytes.size()));
    unexpectedReply.ConfigureHeader(FunctionCode::AUTH_REQUEST, c1.ToRSeq()[0] & 15);
    auto unexpectedWriter = unexpectedReply.GetWriter();
    REQUIRE(unexpectedWriter.WriteFreeFormat(&unexpected, 1));
    const auto failuresBefore = ProductionAuthenticationTestAccess::Stats(pair.outstation.context)
        .Value(SecurityStatistic::AUTHENTICATION_FAILURES);
    pair.outstation.SendToOutstation(HexConversions::to_hex(unexpectedReply.ToRSeq()));
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringPending(pair.outstation.context));
    REQUIRE(pair.outstation.NumPendingTimers() == 1);
    REQUIRE(ProductionAuthenticationTestAccess::Stats(pair.outstation.context)
        .Value(SecurityStatistic::AUTHENTICATION_FAILURES) == failuresBefore); // Idle: unexpected, not failed owned exchange.
    // An Error without a matching control Challenge must not reset the
    // independent response waiting for its monitoring Challenge.
    Group120Var7 error(value.seqNum, 1, 7, 1, DNPTime(0), rseq_t());
    std::array<uint8_t, 64> data{};
    APDURequest request(wseq_t(data.data(), data.size()));
    request.ConfigureHeader(FunctionCode::AUTH_REQUEST_NO_ACK, c1.ToRSeq()[0] & 15);
    auto writer = request.GetWriter();
    REQUIRE(writer.WriteFreeFormat(&error, 1));
    pair.outstation.SendToOutstation(HexConversions::to_hex(request.ToRSeq()));
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringPending(pair.outstation.context));
    REQUIRE(pair.outstation.NumPendingTimers() == 1);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(challenge);
    pair.Pump();
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
}

TEST_CASE("ProductionAuthentication - user critical transmission during non OK key backoff stays unauthenticated",
          "[production-sa][unkeyed-critical]")
{
    // Qualifies, unknown status, last OK/local invalid, transient retry, authentication busy,
    // recurring task, expired credentials, one-shot READ, CONFIRM, DELAY_MEASURE, INITIALIZE_DATA.
    const auto condition = GENERATE(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    const bool queuedConfirm = condition == 0 ? GENERATE(false, true) : false;
    RuntimePair pair(false, true); // Ordinary Aggressive transmission enabled; this exception must remain normal.
    pair.Pump();
    auto& masterSession = ProductionAuthenticationTestAccess::Session(*pair.master.context, 2);
    auto& peerSession = ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2);
    uint64_t now = 0;
    if (condition == 1)
        masterSession.PeerRestart(now);
    else if (condition == 2)
    {
        now = masterSession.ValidUntil();
        pair.master.exe->advance_time(std::chrono::milliseconds(now));
    }
    else
    {
        masterSession.PeerRestart(now);
        REQUIRE(peerSession.Configure(rseq_t(pair.source->keys[1].data(), 32), 10000000, now) == SessionKeys::Result::OK);
        std::array<uint8_t, SessionKeys::MAX_APDU> request{}, status{}, change{};
        size_t requestSize = 0, statusSize = 0, changeSize = 0;
        const size_t attempts = condition == 3 ? 1 : 3;
        for (size_t n = 0; n < attempts; ++n)
        {
            REQUIRE(masterSession.Begin(7, 9, now, wseq_t(request.data(), request.size()), requestSize)
                == SessionKeys::Result::OK);
            REQUIRE(peerSession.Process(7, rseq_t(request.data(), requestSize), now,
                wseq_t(status.data(), status.size()), statusSize) == SessionKeys::Result::OK);
            REQUIRE(masterSession.Process(7, rseq_t(status.data(), statusSize), now,
                wseq_t(change.data(), change.size()), changeSize) == SessionKeys::Result::OK);
            masterSession.SetChangeQueued(rseq_t(change.data(), changeSize), true);
            masterSession.CancelQueuedChange(now); // Actual existing failure/backoff path; no keys installed.
            if (n + 1 < attempts)
            {
                const auto delay = pair.master.context->params.authentication.replyTimeoutMs;
                pair.master.exe->advance_time(std::chrono::milliseconds(delay)); // Service after setup, not mid exchange.
                pair.outstation.AdvanceTime(TimeDuration::Milliseconds(delay));
                now += delay;
            }
        }
        REQUIRE(masterSession.LastKeyStatus() == 2);
    }
    if (condition == 6)
    {
        pair.master.exe->advance_time(std::chrono::milliseconds(10000000 - now));
        now = 10000000;
    }
    pair.master.exe->run_many();
    // A timer alone never causes a keyless ordinary request.
    while (pair.master.lower->NumWrites())
    {
        HexSequence packet(pair.master.lower->PopWriteAsHex());
        REQUIRE(packet.ToRSeq()[1] == 0x20);
    }
    if (condition == 4)
    {
        REQUIRE(pair.master.SendToMaster("F3 82 00 00"));
        REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
        REQUIRE(pair.master.lower->NumWrites() == 1);
        HexSequence challenge(pair.master.lower->PopWriteAsHex());
        REQUIRE(challenge.ToRSeq()[3] == 1);
    }
    if (condition == 5)
    {
        auto config = TaskConfig::Default();
        config.authenticationUser = 2;
        pair.master.context->AddClassScan(ClassField::AllClasses(), TimeDuration::Seconds(1), pair.master.meas, config);
        pair.master.exe->run_many();
    }
    else if (condition >= 7)
    {
        auto config = TaskConfig::Default();
        config.authenticationUser = 2;
        if (condition == 7)
            pair.master.context->ScanClasses(ClassField::AllClasses(), pair.master.meas, config);
        else
            pair.master.context->PerformFunction("noncritical user request",
                condition == 8 ? FunctionCode::CONFIRM
                    : (condition == 9 ? FunctionCode::DELAY_MEASURE : FunctionCode::INITIALIZE_DATA),
                [](HeaderWriter&) { return true; }, config);
        pair.master.exe->run_many();
    }
    else
        pair.SelectOperate();
    if (condition != 0)
    {
        while (pair.master.lower->NumWrites())
        {
            HexSequence packet(pair.master.lower->PopWriteAsHex());
            REQUIRE(packet.ToRSeq()[1] == 0x20); // Only existing key/authentication traffic, never a critical request.
        }
        if (condition == 4)
        {
            REQUIRE(pair.master.context->OnTxReady());
            pair.master.exe->advance_time(std::chrono::milliseconds(2000));
            pair.master.exe->run_many();
            REQUIRE(pair.master.lower->NumWrites() == 0); // Ending another exchange must not arm this waiting task.
        }
        if (condition >= 7)
        {
            REQUIRE(pair.master.context->tstate == MContext::TaskState::TASK_READY);
            REQUIRE(pair.master.context->activeTask);
            REQUIRE_FALSE(pair.master.context->isSending);
            REQUIRE(pair.master.context->params.responseTimeout.value < pair.master.context->params.taskStartTimeout.value);
            const auto sequence = pair.master.context->solSeq.Get();
            const auto delay = pair.master.context->params.responseTimeout.value;
            pair.master.exe->advance_time(delay);
            pair.outstation.AdvanceTime(TimeDuration::Milliseconds(delay.count()));
            pair.master.exe->run_many();
            // An orphan response timer would move TASK_READY to IDLE and strand the task.
            REQUIRE(pair.master.context->tstate == MContext::TaskState::TASK_READY);
            REQUIRE(pair.master.context->activeTask);
            REQUIRE(pair.master.context->solSeq.Get() == sequence);
            REQUIRE(pair.master.lower->NumWrites() == 0);
            if (condition == 7)
            {
                // A rejected one-shot UserPollTask must still build and authenticate
                // normally once the existing renewal procedure supplies valid keys.
                now += static_cast<uint64_t>(delay.count());
                masterSession.RequestRenewal(now);
                pair.master.exe->advance_time(std::chrono::milliseconds(100));
                pair.outstation.AdvanceTime(TimeDuration::Milliseconds(100));
                pair.master.exe->run_many();
                REQUIRE(pair.master.lower->NumWrites() == 1);
                const auto replies = pair.controlReplies;
                pair.Pump();
                REQUIRE(pair.controlReplies > replies);
                REQUIRE_FALSE(pair.master.context->activeTask);
            }
        }
        REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
        return;
    }
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto request = pair.master.lower->PopWriteAsHex();
    HexSequence critical(request);
    REQUIRE(critical.ToRSeq()[1] == 3); // Normal SELECT, with no G120V3/V9 envelope.
    REQUIRE(critical.ToRSeq()[2] != 120);
    REQUIRE(masterSession.ControlKey(now).is_empty());
    std::array<uint8_t, 64> errorBytes{};
    APDUResponse errorAPDU(wseq_t(errorBytes.data(), errorBytes.size()));
    errorAPDU.SetFunction(FunctionCode::AUTH_RESPONSE);
    errorAPDU.SetControl(AppControlField::Request(pair.master.context->solSeq.Get()));
    errorAPDU.SetIIN(IINField::Empty());
    Group120Var7 unrelated(0, 2, 7, 1, DNPTime(0), rseq_t());
    auto errorWriter = errorAPDU.GetWriter();
    REQUIRE(errorWriter.WriteFreeFormat(&unrelated, 1));
    REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(errorAPDU.ToRSeq())));
    REQUIRE_FALSE(masterSession.IsExchanging()); // App SEQ alone cannot initiate Code 1 recovery.
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyIssued(*pair.master.context));
    const auto sequence = pair.master.context->solSeq.Get();
    REQUIRE(pair.master.SendToMaster("C0 81 00 00")); // Transmission did not authenticate a response.
    REQUIRE(pair.master.context->solSeq.Get() == sequence);
    REQUIRE(pair.results.values.empty());
    REQUIRE(pair.master.context->OnTxReady());
    if (queuedConfirm)
    {
        pair.master.context->confirmQueue.push_back(APDUHeader::SolicitedConfirm(7));
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::CheckConfirm(*pair.master.context));
        REQUIRE(pair.master.context->confirmQueue.size() == 1); // No unrelated key can replace the task's responder.
    }
    pair.outstation.SendToOutstation(request);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto challenge = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(challenge));
    REQUIRE(pair.master.lower->NumWrites() == 0); // No usable key: no fabricated G120V2.
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyIssued(*pair.master.context));
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    pair.outstation.AdvanceTime(TimeDuration::Milliseconds(2000));
    REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(pair.outstation.context)
        != OutstationChallenger::State::WAITING_FOR_REPLY);
    pair.master.exe->advance_time(pair.master.context->params.responseTimeout.value);
    pair.master.exe->run_many();
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    if (queuedConfirm)
    {
        // Service may drain the entry after the timeout, or the normal explicit check may do so.
        if (!pair.master.lower->NumWrites())
            REQUIRE(ProductionAuthenticationTestAccess::CheckConfirm(*pair.master.context));
        REQUIRE(pair.master.context->confirmQueue.empty());
        REQUIRE(pair.master.lower->PopWriteAsHex() == "C7 00");
    }
    REQUIRE(pair.master.lower->NumWrites() == 0);
}

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
TEST_CASE("ProductionAuthentication - outstation monitoring survives only independent user renewal",
          "[production-sa][outstation-monitoring-owner]")
{
    const auto renewedUser = GENERATE(uint16_t{1}, uint16_t{2});
    const bool deferred = GENERATE(false, true);
    const bool timeout = renewedUser == 2 ? GENERATE(false, true) : false;
    RuntimePair pair;
    pair.Pump();
    auto& common = ProductionAuthenticationTestAccess::Common(pair.outstation.context);
    const auto commonKSQ = common.Sequence();
    MasterResponder controlPeer(7, 16, 2000);
    REQUIRE(controlPeer.SetSessionKey(1, common.ControlKey(0), common.ValidUntil(), 0) == MasterResponder::Result::OK);
    OutstationChallenger monitoringPeer(7, 16, 2000, true);
    REQUIRE(monitoringPeer.SetSessionKey(1, common.MonitoringKey(0), common.ValidUntil(), 0)
        == OutstationChallenger::Result::OK);
    HexSequence read("C5 01 3C 01 06");
    REQUIRE(controlPeer.RetainRequest(7, read.ToRSeq(), 0) == MasterResponder::Result::OK);
    pair.outstation.SendToOutstation("C5 01 3C 01 06");
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    HexSequence controlChallenge(pair.outstation.lower->PopWriteAsHex());
    pair.outstation.OnTxReady();
    std::array<uint8_t, SessionKeys::MAX_APDU> wire{}, verified{};
    size_t size = 0, verifiedSize = 0;
    REQUIRE(controlPeer.Respond(7, controlChallenge.ToRSeq(), 0, wseq_t(wire.data(), wire.size()), size)
        == MasterResponder::Result::OK);
    if (deferred)
        ProductionAuthenticationTestAccess::LeaveMessages(pair.outstation.context, 2);
    pair.outstation.SendToOutstation(HexConversions::to_hex(rseq_t(wire.data(), size)));
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    HexSequence response(pair.outstation.lower->PopWriteAsHex());
    REQUIRE(response.ToRSeq()[1] == 0x81);
    REQUIRE((response.ToRSeq()[0] & 0x20) == 0); // No native CONFIRM timer obscures authentication ownership.
    pair.outstation.OnTxReady();
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringPending(pair.outstation.context));
    REQUIRE(pair.outstation.NumPendingTimers() == 1);
    const auto held = ProductionAuthenticationTestAccess::Deferred(pair.outstation.context);
    REQUIRE((held != 0) == deferred);
    REQUIRE(monitoringPeer.Challenge(7, response.ToRSeq(), IINField::Empty(), 0,
        wseq_t(wire.data(), wire.size()), size) == OutstationChallenger::Result::OK);
    const auto monitoringChallenge = HexConversions::to_hex(rseq_t(wire.data(), size));

    // Drive the real V4/V5/V6/V5 exchange while the normal response awaits its C1.
    auto& renewal = ProductionAuthenticationTestAccess::Session(*pair.master.context, renewedUser);
    renewal.RequestRenewal(0);
    REQUIRE(renewal.Begin(7, 9, 0, wseq_t(wire.data(), wire.size()), size) == SessionKeys::Result::OK);
    for (size_t step = 0; step < 2; ++step)
    {
        pair.outstation.SendToOutstation(HexConversions::to_hex(rseq_t(wire.data(), size)));
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        HexSequence status(pair.outstation.lower->PopWriteAsHex());
        pair.outstation.OnTxReady();
        REQUIRE(renewal.Process(7, status.ToRSeq(), 0, wseq_t(wire.data(), wire.size()), size)
            == (step == 0 ? SessionKeys::Result::OK : SessionKeys::Result::INSTALLED));
        if (renewedUser == 2)
        {
            REQUIRE(ProductionAuthenticationTestAccess::MonitoringPending(pair.outstation.context));
            REQUIRE(pair.outstation.NumPendingTimers() == 1);
            REQUIRE(ProductionAuthenticationTestAccess::Deferred(pair.outstation.context) == held);
            REQUIRE(common.Sequence() == commonKSQ);
        }
    }
    REQUIRE(renewal.Ready(0));
    if (renewedUser == 1)
    {
        REQUIRE(common.Sequence() != commonKSQ);
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::MonitoringPending(pair.outstation.context));
        REQUIRE(ProductionAuthenticationTestAccess::Deferred(pair.outstation.context) == 0);
        REQUIRE(pair.outstation.NumPendingTimers() == 0);
    }
    else if (timeout)
    {
        pair.outstation.AdvanceTime(TimeDuration::Milliseconds(2000));
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::MonitoringPending(pair.outstation.context));
        REQUIRE(ProductionAuthenticationTestAccess::Deferred(pair.outstation.context) == 0);
        REQUIRE(pair.outstation.NumPendingTimers() == 0);
    }
    pair.outstation.SendToOutstation(monitoringChallenge);
    if (renewedUser == 1 || timeout)
        REQUIRE(pair.outstation.lower->NumWrites() == 0); // Old keys/deadline cannot release the retained response.
    else
    {
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        HexSequence reply(pair.outstation.lower->PopWriteAsHex());
        Group120Var2 value;
        REQUIRE(value.Read(reply.ToRSeq().skip(10)));
        REQUIRE(monitoringPeer.Reply(7, value, 0, wseq_t(verified.data(), verified.size()), verifiedSize)
            == OutstationChallenger::Result::AUTHENTICATED);
        REQUIRE(rseq_t(verified.data(), verifiedSize).equals(response.ToRSeq()));
        pair.outstation.OnTxReady();
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::MonitoringPending(pair.outstation.context));
        REQUIRE(ProductionAuthenticationTestAccess::Deferred(pair.outstation.context) == 0);
        REQUIRE(pair.outstation.NumPendingTimers() == 0);
        pair.outstation.SendToOutstation(monitoringChallenge);
        REQUIRE(pair.outstation.lower->NumWrites() == 0); // No duplicate Reply after completion.
    }
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
        // Let the monitoring deadline precede the Key Change deadline.
        pair.master.exe->advance_time(
            std::chrono::milliseconds(pair.master.context->params.authentication.replyTimeoutMs / 2));
        pair.master.exe->run_many();
        pair.outstation.SendToOutstation(statusRequest);
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        const auto status = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(status));
        pair.master.exe->run_many();
        REQUIRE(pair.master.lower->NumWrites() == 0); // G120V6 is queued, not transmitted.
        pair.master.exe->advance_time(
            std::chrono::milliseconds(pair.master.context->params.authentication.replyTimeoutMs / 2));
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

TEST_CASE("ProductionAuthentication - queued master Key Change cannot outlive its exchange", "[production-sa]")
{
    // Successful TX, serviced expiry, expiry at TX completion, reset, credential
    // expiry, disconnect, session cancellation, and Update Key replacement.
    const auto scenario = GENERATE(0, 1, 2, 3, 4, 5, 6, 7);
    RuntimePair pair;
    auto& session = ProductionAuthenticationTestAccess::Common(*pair.master.context);
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto request = pair.master.lower->PopWriteAsHex();
    HexSequence v4(request);
    REQUIRE(v4.ToRSeq()[3] == 4);
    const auto borrowed = ProductionAuthenticationTestAccess::WireBytes(*pair.master.context, v4.ToRSeq().length());
    REQUIRE(borrowed.equals(v4.ToRSeq()));
    pair.outstation.SendToOutstation(request); // V4 is still in flight at the Master.
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto status = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(status));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 0);
    const auto pending = ProductionAuthenticationTestAccess::PendingBytes(*pair.master.context);
    const auto pendingSize = ProductionAuthenticationTestAccess::Pending(*pair.master.context);
    REQUIRE(pendingSize > 8);
    const auto queued = HexConversions::to_hex(pending.take(pendingSize));
    HexSequence oldChange(queued);
    Group120Var6 oldValue;
    REQUIRE(oldValue.Read(oldChange.ToRSeq().skip(8)));
    REQUIRE(oldValue.userNum == 1);
    REQUIRE(session.IsExchanging());
    REQUIRE_FALSE(session.Ready(0));
    if (scenario == 1 || scenario == 2 || scenario == 4)
    {
        pair.master.exe->advance_time(std::chrono::milliseconds(
            scenario == 4 ? 10000000 : pair.master.context->params.authentication.replyTimeoutMs));
        if (scenario != 2)
            pair.master.exe->run_many(); // Otherwise OnTxReady must itself enforce expiry.
    }
    else if (scenario == 3)
    {
        REQUIRE(pair.master.SendToMaster("C0 83 00 00 78 02 5B 01 01 00 00"));
        pair.master.exe->run_many();
        REQUIRE_FALSE(session.IsExchanging());
    }
    else if (scenario == 5)
    {
        REQUIRE(pair.master.context->OnLowerLayerDown());
        REQUIRE_FALSE(pair.master.context->OnTxReady());
        REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) == 0);
        for (size_t i = 0; i < pending.length(); ++i)
            REQUIRE(pending[i] == 0);
        REQUIRE(pair.master.context->OnLowerLayerUp());
        pair.master.exe->run_many();
    }
    else if (scenario == 6)
        session.Disconnect();
    else if (scenario == 7)
    {
        REQUIRE(crypto::GenerateRandom(wseq_t(pair.source->keys[0].data(), 32)) == crypto::Result::OK);
        const auto key = rseq_t(pair.source->keys[0].data(), 32);
        REQUIRE(session.Configure(key, 10000000, 0) == SessionKeys::Result::OK);
        REQUIRE(ProductionAuthenticationTestAccess::Common(pair.outstation.context).Configure(key, 10000000, 0)
            == SessionKeys::Result::OK);
    }
    if (scenario != 5)
    {
        REQUIRE(pair.master.context->isSending);
        REQUIRE(borrowed.equals(v4.ToRSeq())); // Cleanup never overwrites an active TX.
        REQUIRE(pair.master.context->OnTxReady());
    }
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    if (scenario == 4)
    {
        REQUIRE(pair.master.lower->NumWrites() == 0); // No credentials, no retry or protected work.
        REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) == 0);
        for (size_t i = 0; i < pending.length(); ++i)
            REQUIRE(pending[i] == 0);
        return;
    }
    if (scenario != 0)
    {
        if (scenario == 3)
        {
            // User 1's backoff must not block user 2's independent negotiation.
            REQUIRE(pair.master.lower->NumWrites() == 1);
            const auto independent = ProductionAuthenticationTestAccess::WireBytes(*pair.master.context, 8);
            REQUIRE(independent[3] == 4);
            REQUIRE(independent[6] == 2); // Little-endian G120V4 user number.
            REQUIRE(independent[7] == 0);
            pair.Pump();
            REQUIRE_FALSE(session.IsExchanging());
            REQUIRE_FALSE(session.Ready(0));
        }
        if (!pair.master.lower->NumWrites())
        {
            pair.master.exe->advance_time(
                std::chrono::milliseconds(pair.master.context->params.authentication.replyTimeoutMs));
            pair.master.exe->run_many();
        }
        REQUIRE(pair.master.lower->NumWrites() == 1);
        const auto retry = pair.master.lower->PopWriteAsHex();
        HexSequence freshRequest(retry);
        REQUIRE(freshRequest.ToRSeq()[1] == 0x20);
        REQUIRE(freshRequest.ToRSeq()[3] == 4); // Restart with V4; never send the obsolete V6.
        if (scenario != 5)
            REQUIRE(freshRequest.ToRSeq()[0] != v4.ToRSeq()[0]);
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(retry);
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        const auto freshStatus = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(freshStatus));
        pair.master.exe->run_many();
    }
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto change = pair.master.lower->PopWriteAsHex();
    HexSequence v6(change);
    REQUIRE(v6.ToRSeq()[3] == 6);
    if (scenario == 0)
        REQUIRE(change == queued);
    else
    {
        Group120Var6 freshValue;
        REQUIRE(freshValue.Read(v6.ToRSeq().skip(8)));
        REQUIRE_FALSE(freshValue.keyWrapData.equals(oldValue.keyWrapData));
    }
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(change);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto confirmation = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(confirmation));
    pair.master.exe->run_many();
    REQUIRE(session.Ready(static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        pair.master.exe->get_time().time_since_epoch()).count())));
    pair.Pump();
    pair.SelectOperate();
    pair.Pump();
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
}

TEST_CASE("ProductionAuthentication - transmitted Key Change retains TX bytes and recovery after timeout", "[production-sa]")
{
    RuntimePair pair;
    const auto request = pair.master.lower->PopWriteAsHex();
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(request);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto status = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(status));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto change = pair.master.lower->PopWriteAsHex();
    HexSequence v6(change);
    REQUIRE(v6.ToRSeq()[3] == 6);
    const auto borrowed = ProductionAuthenticationTestAccess::WireBytes(*pair.master.context, v6.ToRSeq().length());
    REQUIRE(borrowed.equals(v6.ToRSeq()));
    pair.outstation.SendToOutstation(change); // The peer installed keys, but its V5 is lost.
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    pair.master.exe->advance_time(
        std::chrono::milliseconds(pair.master.context->params.authentication.replyTimeoutMs));
    pair.master.exe->run_many();
    REQUIRE(pair.master.context->isSending);
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(borrowed.equals(v6.ToRSeq()));
    // Repeated authentication resets must not discard a transmitted change's
    // recovery key or overwrite bytes still borrowed by the lower layer.
    for (size_t n = 0; n < 2; ++n)
    {
        REQUIRE(pair.master.SendToMaster("C0 83 00 00 78 02 5B 01 01 00 00"));
        REQUIRE(borrowed.equals(v6.ToRSeq()));
    }
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto retry = pair.master.lower->PopWriteAsHex();
    HexSequence retryV4(retry);
    REQUIRE(retryV4.ToRSeq()[3] == 4);
    pair.outstation.SendToOutstation(retry); // Keep this V4 in flight too.
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto retryStatus = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(retryStatus));
    pair.master.exe->run_many();
    REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) > 8);
    REQUIRE(ProductionAuthenticationTestAccess::PendingBytes(*pair.master.context)[3] == 6);
    pair.master.exe->advance_time(
        std::chrono::milliseconds(pair.master.context->params.authentication.replyTimeoutMs));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(ProductionAuthenticationTestAccess::WireBytes(*pair.master.context, retryV4.ToRSeq().length())
        .equals(retryV4.ToRSeq()));
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(pair.master.lower->NumWrites() == 1);
    // Expiry of the second, unsent V6 must preserve recovery from the first,
    // transmitted V6 so the next keyed V5 can still be verified.
    pair.Pump();
    REQUIRE_FALSE(pair.commonKeyChange.empty());
    REQUIRE(pair.commonKeyChange != change);
    REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).Ready(
        static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            pair.master.exe->get_time().time_since_epoch()).count())));
    pair.SelectOperate();
    pair.Pump();
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
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
    const auto criticalSentBefore = ProductionAuthenticationTestAccess::Stats(*pair.master.context)
        .Value(SecurityStatistic::CRITICAL_MESSAGES_SENT);
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
        REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context)
            .Value(SecurityStatistic::CRITICAL_MESSAGES_SENT) == criticalSentBefore);
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
    REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context)
        .Value(SecurityStatistic::CRITICAL_MESSAGES_SENT) == criticalSentBefore + 1); // Mandatory exception: exactly once.
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

TEST_CASE("ProductionAuthentication - master aggressive TX lifetime survives reset timeout and disconnect", "[production-sa]")
{
    const auto scenario = GENERATE(0, 1, 2, 3); // Normal completion, repeated reset, response timeout, disconnect.
    RuntimePair pair(false, true);
    pair.Pump();
    pair.SelectOperate();
    pair.Pump();
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
    pair.SelectOperate();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto packet = pair.master.lower->PopWriteAsHex();
    HexSequence request(packet);
    REQUIRE(request.ToRSeq()[2] == 120);
    REQUIRE(request.ToRSeq()[3] == 3);
    const auto borrowed = ProductionAuthenticationTestAccess::AggressiveBytes(*pair.master.context, request.ToRSeq().length());
    REQUIRE(borrowed.equals(request.ToRSeq()));
    REQUIRE(pair.master.context->isSending);
    REQUIRE(ProductionAuthenticationTestAccess::ControlEligible(*pair.master.context));
    if (scenario == 1)
    {
        for (size_t i = 0; i < 2; ++i)
        {
            REQUIRE(pair.master.SendToMaster("C0 83 00 00 78 02 5B 01 01 00 00"));
            pair.master.exe->run_many();
            REQUIRE(borrowed.equals(request.ToRSeq()));
            REQUIRE_FALSE(ProductionAuthenticationTestAccess::ControlEligible(*pair.master.context));
            REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyIssued(*pair.master.context));
        }
        // Retaining TX bytes must not retain authorization for a response to the reset exchange.
        const auto before = pair.master.context->solSeq.Get();
        const uint8_t response[] = {static_cast<uint8_t>(0xC0 | (request.ToRSeq()[0] & 0x0F)), 0x81, 0, 0};
        REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(response, sizeof(response)))));
        pair.master.exe->run_many();
        REQUIRE(pair.master.context->solSeq.Get() == before);
        REQUIRE(pair.results.values.size() == 1);
        REQUIRE(pair.master.lower->NumWrites() == 0);
        REQUIRE(borrowed.equals(request.ToRSeq()));
    }
    else if (scenario == 2)
    {
        pair.master.exe->advance_time(pair.master.context->params.responseTimeout.value);
        pair.master.exe->run_many();
        REQUIRE(pair.results.values.size() == 2);
        REQUIRE(pair.results.values.back().summary != TaskCompletion::SUCCESS);
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::ControlEligible(*pair.master.context));
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyIssued(*pair.master.context));
        REQUIRE(borrowed.equals(request.ToRSeq()));
        REQUIRE(pair.master.context->isSending);
    }
    else if (scenario == 3)
    {
        // OnLowerLayerDown is delivered after lower-layer transmission cancellation.
        REQUIRE(pair.master.context->OnLowerLayerDown());
        REQUIRE_FALSE(pair.master.context->OnTxReady());
        REQUIRE_FALSE(pair.master.context->OnLowerLayerDown());
    }
    if (scenario != 3)
        REQUIRE(pair.master.context->OnTxReady());
    for (size_t i = 0; i < borrowed.length(); ++i)
        REQUIRE(borrowed[i] == 0);
    if (scenario == 0)
    {
        // Lower-layer-owned bytes were copied above; normal authenticated processing still succeeds.
        pair.outstation.SendToOutstation(packet);
        pair.Pump();
        REQUIRE(pair.results.values.size() == 2);
        REQUIRE(pair.results.values.back().summary == TaskCompletion::SUCCESS);
        REQUIRE(pair.outstation.cmdHandler->NumOperate() == 2);
    }
    else if (scenario == 1)
    {
        pair.master.exe->advance_time(pair.master.context->params.responseTimeout.value);
        pair.master.exe->run_many();
        REQUIRE(pair.results.values.size() == 2);
        REQUIRE(pair.results.values.back().summary != TaskCompletion::SUCCESS);
        REQUIRE(pair.master.lower->NumWrites() == 0);
        REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    }
    else if (scenario == 3)
    {
        pair.outstation.LowerLayerDown();
        pair.outstation.LowerLayerUp();
        REQUIRE(pair.master.context->OnLowerLayerUp());
        pair.master.exe->run_many();
        pair.Pump();
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::ControlEligible(*pair.master.context));
        REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
        pair.SelectOperate();
        REQUIRE(pair.master.lower->NumWrites() == 1);
        HexSequence fresh(pair.master.lower->PopWriteAsHex());
        REQUIRE_FALSE(fresh.ToRSeq()[2] == 120 && fresh.ToRSeq()[3] == 3);
        for (size_t i = 0; i < borrowed.length(); ++i)
            REQUIRE(borrowed[i] == 0);
    }
}

TEST_CASE("ProductionAuthentication - delayed master native CONFIRM Reply validates lifetime without deferred counts", "[production-sa]")
{
    const bool deferred = GENERATE(false, true);
    const auto scenario = GENERATE(0, 1, 2, 3, 4, 5); // Send, timeout, expiry, reset, new KSQ, reset during Reply TX.
    RuntimePair pair(true);
    pair.Pump();
    pair.outstation.AdvanceTime(OutSettings(pair.source, pair.policy, true).params.unsolConfirmTimeout);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto unsolicited = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(unsolicited));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto monitoring = pair.master.lower->PopWriteAsHex();
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(monitoring);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto verified = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    if (deferred)
        ProductionAuthenticationTestAccess::LeaveMessages(*pair.master.context, 1);
    REQUIRE(pair.master.SendToMaster(verified));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto confirmation = pair.master.lower->PopWriteAsHex();
    HexSequence confirm(confirmation);
    REQUIRE(confirm.ToRSeq().length() == 2);
    REQUIRE(confirm.ToRSeq()[1] == 0);
    pair.outstation.SendToOutstation(confirmation); // Delay Master TX completion until after receipt of its Challenge.
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto challenge = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(challenge));
    pair.master.exe->run_many();
    REQUIRE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
    REQUIRE((ProductionAuthenticationTestAccess::Deferred(*pair.master.context) != 0) == deferred);
    REQUIRE(pair.master.lower->NumWrites() == 0);
    auto& common = ProductionAuthenticationTestAccess::Common(*pair.master.context);
    if (scenario == 1)
    {
        pair.master.exe->advance_time(std::chrono::milliseconds(pair.master.context->params.authentication.replyTimeoutMs));
        pair.master.exe->run_many();
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
    }
    else if (scenario == 2)
    {
        // Do not run due timers: OnTxReady itself must reject an expired key/Reply.
        pair.master.exe->advance_time(std::chrono::milliseconds(common.ValidUntil())
            - std::chrono::duration_cast<std::chrono::milliseconds>(pair.master.exe->get_time().time_since_epoch()));
    }
    else if (scenario == 3)
    {
        REQUIRE(pair.master.SendToMaster("C0 83 00 00 78 02 5B 01 01 00 00"));
        pair.master.exe->run_many();
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
    }
    else if (scenario == 4)
        REQUIRE(common.Configure(rseq_t(pair.source->keys[0].data(), 32), 10000000, 0) == SessionKeys::Result::OK);
    REQUIRE(pair.master.context->isSending);
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
    if (scenario >= 1 && scenario <= 4)
    {
        REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == 0);
        while (pair.master.lower->NumWrites())
        {
            HexSequence packet(pair.master.lower->PopWriteAsHex());
            REQUIRE(packet.ToRSeq()[1] == 0x20);
            REQUIRE(packet.ToRSeq()[3] != 2); // Key negotiation may resume; the obsolete Reply must not.
        }
        const auto bytes = ProductionAuthenticationTestAccess::ReplyBytes(*pair.master.context);
        for (size_t i = 0; i < bytes.length(); ++i)
            REQUIRE(bytes[i] == 0);
        return;
    }
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto reply = pair.master.lower->PopWriteAsHex();
    HexSequence packet(reply);
    REQUIRE(packet.ToRSeq()[1] == 0x20);
    REQUIRE(packet.ToRSeq()[3] == 2);
    REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == 0);
    const auto borrowed = ProductionAuthenticationTestAccess::ReplyBytes(*pair.master.context);
    REQUIRE(borrowed.equals(packet.ToRSeq()));
    if (scenario == 5)
    {
        REQUIRE(pair.master.SendToMaster("C0 83 00 00 78 02 5B 01 01 00 00"));
        pair.master.exe->run_many();
        REQUIRE(borrowed.equals(packet.ToRSeq()));
        REQUIRE(pair.master.context->isSending);
    }
    pair.outstation.SendToOutstation(reply); // The real peer verifies the Reply MAC and releases only this CONFIRM.
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(pair.master.context->OnTxReady());
    for (size_t i = 0; i < borrowed.length(); ++i)
        REQUIRE(borrowed[i] == 0);
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
}

TEST_CASE("ProductionAuthentication - expired task Reply preserves independent monitoring and TX completion progress", "[production-sa]")
{
    const bool serviceBeforeCompletion = GENERATE(false, true);
    RuntimePair pair;
    pair.Pump();
    pair.SelectOperate();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto request = pair.master.lower->PopWriteAsHex();
    // Outstation Challenge arrives before the Master receives TX completion for SELECT.
    pair.outstation.SendToOutstation(request);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto challenge = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(challenge));
    pair.master.exe->run_many();
    REQUIRE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
    REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == 0);
    pair.master.context->confirmQueue.push_back(APDUHeader::SolicitedConfirm(7));
    // Start an independent monitoring exchange later, so its deadline has not elapsed when SELECT's Reply expires.
    const auto timeout = pair.master.context->params.authentication.replyTimeoutMs;
    pair.master.exe->advance_time(std::chrono::milliseconds(timeout / 2));
    pair.master.exe->run_many();
    HexSequence unsolicited("F3 82 00 00");
    REQUIRE(pair.master.SendToMaster("F3 82 00 00"));
    pair.master.exe->run_many();
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) != 0);
    REQUIRE(pair.master.lower->NumWrites() == 0);
    pair.master.exe->advance_time(std::chrono::milliseconds(timeout - timeout / 2));
    if (serviceBeforeCompletion)
    {
        pair.master.exe->run_many();
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
        REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
        REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) != 0);
        REQUIRE(pair.master.context->confirmQueue.size() == 1);
    }
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyIssued(*pair.master.context));
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    REQUIRE(pair.master.context->confirmQueue.size() == 1);
    REQUIRE(pair.master.lower->NumWrites() == 1); // Rejection must fall through to servicing the queued monitoring Challenge.
    const auto monitoring = pair.master.lower->PopWriteAsHex();
    HexSequence wire(monitoring);
    REQUIRE(wire.ToRSeq()[1] == 0x20);
    REQUIRE(wire.ToRSeq()[3] == 1);
    REQUIRE(wire.ToRSeq()[0] == 0xC3);
    MasterResponder peer(7, 16, timeout, true);
    auto& common = ProductionAuthenticationTestAccess::Common(*pair.master.context);
    REQUIRE(peer.SetSessionKey(1, common.MonitoringKey(timeout), common.ValidUntil(), timeout) == MasterResponder::Result::OK);
    REQUIRE(peer.RetainRequest(7, unsolicited.ToRSeq(), timeout) == MasterResponder::Result::OK);
    std::array<uint8_t, 2048> reply{};
    size_t size = 0;
    REQUIRE(peer.Respond(7, wire.ToRSeq(), timeout, wseq_t(reply.data(), reply.size()), size) == MasterResponder::Result::OK);
    const auto before = pair.master.context->solSeq.Get();
    REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(reply.data(), size))));
    pair.master.exe->run_many();
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    REQUIRE(pair.master.context->solSeq.Get() == before); // The cancelled SELECT Reply cannot authorize its task response.
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    REQUIRE(pair.master.context->confirmQueue.size() == 2);
    REQUIRE(pair.master.context->confirmQueue.front().control.SEQ == 7);
    REQUIRE_FALSE(pair.master.context->confirmQueue.front().control.UNS);
    REQUIRE(pair.master.context->confirmQueue.back().control.SEQ == 3);
    REQUIRE(pair.master.context->confirmQueue.back().control.UNS);
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(pair.master.lower->NumWrites() == 1);
    REQUIRE(pair.master.lower->PopWriteAsHex() == "C7 00"); // Older unrelated CONFIRM keeps its place.
    REQUIRE(pair.master.context->confirmQueue.size() == 1);
}

TEST_CASE("ProductionAuthentication - Code 1 recovers only a transmitted user critical authentication attempt",
          "[production-sa][auth-error]")
{
    const bool aggressive = GENERATE(false, true);
    // Match, CSQ, user, association, app SEQ, timeout, reconnect, lost KSQ, independent monitoring.
    const auto fault = GENERATE(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    const bool poll = fault == 0 ? GENERATE(false, true) : false;
    RuntimePair pair(false, aggressive);
    pair.Pump();
    if (aggressive)
    {
        pair.SelectOperate();
        pair.Pump(); // Real handshake establishes eligibility, not a fabricated seed.
    }
    uint64_t now = 0;
    if (fault == 9)
    {
        now = ProductionAuthenticationTestAccess::Session(*pair.master.context, 2).ValidUntil() - 1000;
        pair.master.exe->advance_time(std::chrono::milliseconds(now));
        pair.outstation.AdvanceTime(TimeDuration::Milliseconds(now));
        pair.master.exe->run_many();
    }
    const auto executions = pair.outstation.cmdHandler->NumInvocations();
    const auto completions = pair.results.values.size();
    if (poll)
    {
        auto config = TaskConfig::Default();
        config.authenticationUser = 2;
        pair.master.context->ScanClasses(ClassField::AllClasses(), pair.master.meas, config);
        pair.master.exe->run_many();
    }
    else pair.SelectOperate();
    const auto request = pair.master.lower->PopWriteAsHex();
    std::string attemptWire;
    uint32_t csq = 0;
    uint16_t user = 0;
    if (aggressive)
    {
        attemptWire = request;
        HexSequence packet(attemptWire);
        auto prefix = packet.ToRSeq().skip(6);
        Group120Var3 value;
        REQUIRE(Group120Var3::Read(prefix, value));
        csq = value.seqNum;
        user = value.userNum;
    }
    else
    {
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(request);
        const auto challenge = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(challenge));
        attemptWire = pair.master.lower->PopWriteAsHex();
        HexSequence packet(attemptWire);
        Group120Var2 value;
        REQUIRE(value.Read(packet.ToRSeq().skip(8)));
        csq = value.seqNum;
        user = value.userNum;
    }
    HexSequence attempt(attemptWire);
    const auto borrowed = aggressive
        ? ProductionAuthenticationTestAccess::AggressiveBytes(*pair.master.context, attempt.ToRSeq().length())
        : ProductionAuthenticationTestAccess::ReplyBytes(*pair.master.context).take(attempt.ToRSeq().length());
    auto& session = ProductionAuthenticationTestAccess::Session(*pair.master.context, 2);
    REQUIRE(session.LastKeyStatus() == 1);
    // The peer really lost its keys. Its existing enforcement refuses this
    // authenticating ASDU; optional Error emission is emulated below.
    ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2).Disconnect();
    pair.outstation.SendToOutstation(attemptWire);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == executions);
    if (fault == 8)
    {
        REQUIRE(pair.master.SendToMaster("F3 82 00 00"));
        REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    }
    if (fault == 10)
    {
        REQUIRE(pair.master.context->OnTxReady());
        pair.master.context->confirmQueue.push_back(APDUHeader::SolicitedConfirm(7));
        REQUIRE(ProductionAuthenticationTestAccess::CheckConfirm(*pair.master.context));
        REQUIRE(pair.master.lower->PopWriteAsHex() == "C7 00");
    }
    Group120Var7 error(csq, user, 7, 1, DNPTime(0), rseq_t());
    if (fault == 1) --error.seqNum;
    if (fault == 2) error.userNum = 1;
    if (fault == 3) error.associationId = 8;
    if (fault == 5)
    {
        pair.master.exe->advance_time(pair.master.context->params.responseTimeout.value);
        pair.master.exe->run_many();
    }
    if (fault == 6)
    {
        REQUIRE(pair.master.context->OnLowerLayerDown());
        REQUIRE(pair.master.context->OnLowerLayerUp());
        pair.master.exe->run_many();
    }
    if (fault == 7) session.PeerRestart(0);
    if (fault == 9)
    {
        now += 1000; // Session expiry before the response deadline does not erase real attempt ownership.
        pair.master.exe->advance_time(std::chrono::milliseconds(1000));
        pair.master.exe->run_many();
        REQUIRE_FALSE(session.Ready(now));
    }
    std::array<uint8_t, 64> bytes{};
    APDUResponse response(wseq_t(bytes.data(), bytes.size()));
    response.SetFunction(FunctionCode::AUTH_RESPONSE);
    response.SetControl(AppControlField::Request((attempt.ToRSeq()[0] + (fault == 4 ? 1 : 0)) & 0x0F));
    response.SetIIN(IINField::Empty());
    auto writer = response.GetWriter();
    REQUIRE(writer.WriteFreeFormat(&error, 1));
    const auto wire = HexConversions::to_hex(response.ToRSeq());
    const auto previousWrites = pair.master.lower->NumWrites();
    REQUIRE(pair.master.SendToMaster(wire));
    REQUIRE(pair.master.lower->NumWrites() == previousWrites); // Active TX is never overwritten.
    const bool recovers = fault == 0 || fault == 8 || fault == 9 || fault == 10;
    if (!recovers)
    {
        if (fault != 5 && fault != 6) REQUIRE(borrowed.equals(attempt.ToRSeq()));
        REQUIRE(pair.outstation.cmdHandler->NumInvocations() == executions);
        return;
    }
    if (!aggressive) REQUIRE_FALSE(session.IsExchanging()); // A Reply still owns its session until TX completion.
    if (fault != 10) REQUIRE(borrowed.equals(attempt.ToRSeq()));
    REQUIRE(pair.master.context->OnTxReady());
    if (fault == 10)
    {
        REQUIRE(session.Ready(now)); // Do not invalidate a key while another CONFIRM owns its budget.
        pair.outstation.SendToOutstation("C7 00");
        const auto challenge = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(challenge)); // Recovery must still answer the independent CONFIRM's Challenge.
        REQUIRE(pair.master.lower->NumWrites() == 1);
        const auto reply = pair.master.lower->PopWriteAsHex();
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(reply);
    }
    REQUIRE(session.ControlKey(now).is_empty());
    if (fault == 8)
    {
        REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
        HexSequence monitoring(pair.master.lower->PopWriteAsHex());
        REQUIRE(monitoring.ToRSeq()[3] == 1);
        REQUIRE(pair.master.context->OnTxReady());
        pair.master.exe->advance_time(std::chrono::milliseconds(2000));
        pair.master.exe->run_many();
    }
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto statusRequest = pair.master.lower->PopWriteAsHex();
    HexSequence v4(statusRequest);
    REQUIRE(v4.ToRSeq()[1] == 0x20);
    REQUIRE(v4.ToRSeq()[3] == 4);
    auto statusPayload = v4.ToRSeq().skip(6);
    Group120Var4 statusUser;
    REQUIRE(Group120Var4::Read(statusPayload, statusUser));
    REQUIRE(statusUser.userNum == 2);
    const auto pending = ProductionAuthenticationTestAccess::WireBytes(*pair.master.context, v4.ToRSeq().length());
    REQUIRE(pair.master.SendToMaster(wire)); // Duplicate cannot cancel or re-start V4.
    REQUIRE(pending.equals(v4.ToRSeq()));
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(statusRequest);
    pair.Pump();
    REQUIRE(session.Ready(now + (fault == 8 ? 2000 : 0)));
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == executions); // No application-layer retransmission.
    const auto seq = pair.master.context->solSeq.Get();
    const std::string unauthenticated = std::string("C") + "0123456789ABCDEF"[seq] + " 81 00 00";
    REQUIRE(pair.master.SendToMaster(unauthenticated));
    REQUIRE(pair.results.values.size() == completions);
    pair.master.exe->advance_time(pair.master.context->params.responseTimeout.value);
    pair.master.exe->run_many();
    REQUIRE_FALSE(pair.master.context->activeTask);
    REQUIRE(pair.results.values.size() == completions + (poll ? 0 : 1));
    if (!poll) REQUIRE(pair.results.values.back().summary == TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
}

TEST_CASE("ProductionAuthentication - Code 7 reports only authenticated authorization denial", "[production-sa][auth-error]")
{
    const bool aggressive = GENERATE(false, true);
    // Allowed; denied; invalid MAC; wrong CSQ; unknown user; foreign association;
    // replay; busy TX; explicit suppression; unavailable time; expired keys; time overflow.
    const auto fault = GENERATE(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
    auto observer = std::make_shared<RuntimeErrorObserver>();
    RuntimePair pair(false, aggressive, false, nullptr, false, observer, 2, fault == 8);
    pair.Pump();
    if (aggressive)
    {
        pair.SelectOperate();
        pair.Pump();
    }
    if (fault != 9) pair.outstation.application->SetTime(DNPTime(fault == 11 ? 0x1000000000000ULL : 123456789));
    const auto executions = pair.outstation.cmdHandler->NumInvocations();
    pair.policy->allowControl = fault == 0;
    pair.SelectOperate();
    const auto request = pair.master.lower->PopWriteAsHex();
    std::string attempt;
    std::string inFlight;
    uint32_t csq = 0;
    if (aggressive)
    {
        attempt = request;
        HexSequence packet(attempt);
        auto prefix = packet.ToRSeq().skip(6);
        Group120Var3 value;
        REQUIRE(Group120Var3::Read(prefix, value));
        csq = value.seqNum;
        REQUIRE(pair.master.context->OnTxReady());
        if (fault == 7)
        {
            pair.outstation.SendToOutstation("C9 03"); // A genuine, still-transmitting Challenge owns its buffer.
            inFlight = pair.outstation.lower->PopWriteAsHex();
        }
    }
    else
    {
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(request);
        const auto challenge = pair.outstation.lower->PopWriteAsHex();
        if (fault == 7) inFlight = challenge;
        else pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(challenge));
        attempt = pair.master.lower->PopWriteAsHex();
        HexSequence packet(attempt);
        Group120Var2 value;
        REQUIRE(value.Read(packet.ToRSeq().skip(8)));
        csq = value.seqNum;
        REQUIRE(pair.master.context->OnTxReady());
    }
    HexSequence originalAttempt(attempt);
    std::vector<uint8_t> bytes(static_cast<const uint8_t*>(originalAttempt.ToRSeq()),
        static_cast<const uint8_t*>(originalAttempt.ToRSeq()) + originalAttempt.ToRSeq().length());
    if (fault == 2) bytes.back() ^= 1;
    if (fault == 3) bytes[aggressive ? 6 : 8] ^= 1;
    if (fault == 4) bytes[aggressive ? 10 : 12] = 3;
    if (fault == 10) pair.outstation.AdvanceTime(TimeDuration::Milliseconds(900000));
    if (fault == 5)
        ProductionAuthenticationTestAccess::ReceiveOtherAssociation(pair.outstation.context, rseq_t(bytes.data(), bytes.size()));
    else
        pair.outstation.SendToOutstation(HexConversions::to_hex(rseq_t(bytes.data(), bytes.size())));
    if (fault == 0)
    {
        pair.Pump();
        REQUIRE(pair.outstation.cmdHandler->NumInvocations() == executions + 2);
        REQUIRE(observer->denied == 0);
        REQUIRE(observer->sent == 0);
        return;
    }
    const bool authenticated = fault == 1 || fault == 6 || fault == 7 || fault == 8 || fault == 9 || fault == 11;
    const bool emits = fault == 1 || fault == 6;
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == executions);
    REQUIRE(observer->denied == (authenticated ? 1 : 0));
    REQUIRE(observer->sent == (emits ? 1 : 0));
    REQUIRE(pair.outstation.lower->NumWrites() == (emits ? 1 : 0));
    if (emits)
    {
        const auto error = pair.outstation.lower->PopWriteAsHex();
        HexSequence packet(error);
        REQUIRE(packet.ToRSeq().length() == 25); // Header + existing free-format framing + 15-byte V7.
        REQUIRE(packet.ToRSeq()[0] == static_cast<uint8_t>(0xC0 | (originalAttempt.ToRSeq()[0] & 0x0F)));
        REQUIRE(packet.ToRSeq()[1] == 0x83);
        REQUIRE(packet.ToRSeq()[4] == 120);
        REQUIRE(packet.ToRSeq()[5] == 7);
        REQUIRE(packet.ToRSeq()[6] == 0x5B);
        REQUIRE(packet.ToRSeq()[7] == 1);
        Group120Var7 value;
        REQUIRE(value.Read(packet.ToRSeq().skip(10)));
        REQUIRE(value.errorCode == 7);
        REQUIRE(value.seqNum == csq);
        REQUIRE(value.userNum == 2);
        REQUIRE(value.associationId == 7);
        REQUIRE(value.time.value == 123456789);
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(error));
        REQUIRE(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2).Ready(0));
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2).IsExchanging());
        if (fault == 6)
        {
            pair.outstation.SendToOutstation(attempt);
            REQUIRE(pair.outstation.lower->NumWrites() == 0);
            REQUIRE(observer->denied == 1);
            REQUIRE(observer->sent == 1);
        }
    }
    if (fault == 7)
    {
        HexSequence packet(inFlight);
        REQUIRE(ProductionAuthenticationTestAccess::ChallengeBytes(pair.outstation.context)
            .take(packet.ToRSeq().length()).equals(packet.ToRSeq()));
        pair.outstation.OnTxReady();
        REQUIRE(pair.outstation.lower->NumWrites() == 0); // Busy suppression does not leave a stale queued Error.
    }
}

TEST_CASE("ProductionAuthentication - authorization Error suppression reopens only on successful key change",
          "[production-sa][auth-error]")
{
    const auto threshold = GENERATE(uint16_t{0}, uint16_t{2});
    auto observer = std::make_shared<RuntimeErrorObserver>();
    RuntimePair pair(false, false, false, nullptr, false, observer, threshold);
    pair.Pump();
    pair.policy->allowControl = false;
    uint64_t now = 0;
    for (uint32_t n = 0; n < static_cast<uint32_t>(threshold) + 2; ++n)
    {
        pair.outstation.application->SetTime(DNPTime(100000 + now));
        pair.SelectOperate();
        pair.Pump();
        REQUIRE(observer->denied == n + 1);
        REQUIRE(observer->sent == std::min<uint32_t>(n + 1, static_cast<uint32_t>(threshold) + 1));
        REQUIRE(ProductionAuthenticationTestAccess::Stats(pair.outstation.context)
            .Value(SecurityStatistic::AUTHORIZATION_FAILURES) == observer->denied);
        REQUIRE(ProductionAuthenticationTestAccess::Stats(pair.outstation.context)
            .Value(SecurityStatistic::ERROR_MESSAGES_SENT) == observer->sent);
        REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context)
            .Value(SecurityStatistic::ERROR_MESSAGES_RECEIVED) == observer->received);
        REQUIRE(ProductionAuthenticationTestAccess::Stats(pair.outstation.context)
            .Value(SecurityStatistic::AUTHENTICATION_FAILURES) == 0);
        REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
        const auto delay = pair.master.context->params.responseTimeout.value;
        pair.master.exe->advance_time(delay);
        pair.outstation.AdvanceTime(TimeDuration::Milliseconds(delay.count()));
        now += static_cast<uint64_t>(delay.count());
        pair.master.exe->run_many();
        REQUIRE_FALSE(pair.master.context->activeTask);
    }
    const auto sent = observer->sent;
    auto& session = ProductionAuthenticationTestAccess::Session(*pair.master.context, 2);
    session.RequestRenewal(now);
    pair.master.exe->advance_time(std::chrono::milliseconds(100));
    pair.outstation.AdvanceTime(TimeDuration::Milliseconds(100));
    pair.master.exe->run_many();
    pair.Pump(); // Actual V4/V5/V6/V5; an Error or task reset alone never resets the budget.
    REQUIRE(session.Ready(now + 100));
    REQUIRE(observer->sent == sent);
    pair.SelectOperate();
    pair.Pump();
    REQUIRE(observer->sent == sent + 1);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("ProductionAuthentication - Code 7 cannot cancel an indistinguishable independent Monitoring Challenge",
          "[production-sa][auth-error]")
{
    RuntimePair pair;
    pair.Pump();
    pair.outstation.application->SetTime(DNPTime(123456789));
    pair.policy->allowCommonWrite = false;
    auto config = TaskConfig::Default();
    config.authenticationUser = 1;
    pair.master.context->PerformFunction("user WRITE", FunctionCode::WRITE, [](HeaderWriter&) { return true; }, config);
    pair.master.exe->run_many();
    const auto request = pair.master.lower->PopWriteAsHex();
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(request);
    const auto challenge = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(challenge));
    const auto reply = pair.master.lower->PopWriteAsHex(); // Kept in flight while the independent Challenge queues.
    REQUIRE(pair.master.SendToMaster("F0 82 00 00"));
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    const auto pending = ProductionAuthenticationTestAccess::Pending(*pair.master.context);
    const auto pendingBytes = ProductionAuthenticationTestAccess::PendingBytes(*pair.master.context);
    std::vector<uint8_t> saved(static_cast<const uint8_t*>(pendingBytes), static_cast<const uint8_t*>(pendingBytes) + pending);
    pair.outstation.SendToOutstation(reply);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto error = pair.outstation.lower->PopWriteAsHex();
    REQUIRE(pair.master.SendToMaster(error));
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) == pending);
    REQUIRE(ProductionAuthenticationTestAccess::PendingBytes(*pair.master.context).take(pending).equals(rseq_t(saved.data(), saved.size())));
    REQUIRE(pair.master.context->OnTxReady());
    HexSequence next(pair.master.lower->PopWriteAsHex());
    Group120Var1 value;
    REQUIRE(value.Read(next.ToRSeq().skip(8)));
    REQUIRE(value.macAlgorithm == 4); // Code 7 must never select the Code 5 recovery path.
}

TEST_CASE("ProductionAuthentication - Code 7 distinguishes policy denial from OPERATE ownership failure",
          "[production-sa][auth-error]")
{
    const bool aggressive = GENERATE(false, true);
    const bool denyPolicy = GENERATE(false, true);
    const auto selection = GENERATE(0, 1, 2); // Missing SELECT, other user, same user with wrong app sequence.
    auto observer = std::make_shared<RuntimeErrorObserver>();
    RuntimePair pair(false, aggressive, false, nullptr, false, observer);
    pair.Pump();
    pair.outstation.application->SetTime(DNPTime(123456789));
    // Complete a real SELECT/OPERATE to establish both users' session material,
    // the Aggressive seed/sequence, and an empty current SELECT ownership.
    pair.SelectOperate();
    const auto select = pair.master.lower->PopWriteAsHex();
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(select);
    pair.Pump();
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    HexSequence selected(select);
    std::vector<uint8_t> native(static_cast<const uint8_t*>(selected.ToRSeq()),
        static_cast<const uint8_t*>(selected.ToRSeq()) + selected.ToRSeq().length());
    uint8_t appSequence = pair.master.context->solSeq.Get();
    MasterResponder responder(7, 16);
    std::array<uint8_t, 2048> wire{};
    size_t size = 0;
    auto challengeReply = [&](uint16_t user) {
        pair.outstation.SendToOutstation(HexConversions::to_hex(rseq_t(native.data(), native.size())));
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        const auto challenge = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        auto& session = ProductionAuthenticationTestAccess::Session(*pair.master.context, user);
        REQUIRE(responder.SetSessionKey(user, session.ControlKey(0), session.ValidUntil(), 0) == MasterResponder::Result::OK);
        REQUIRE(responder.RetainRequest(7, rseq_t(native.data(), native.size()), 0) == MasterResponder::Result::OK);
        HexSequence packet(challenge);
        REQUIRE(responder.Respond(7, packet.ToRSeq(), 0, wseq_t(wire.data(), wire.size()), size) == MasterResponder::Result::OK);
        pair.outstation.SendToOutstation(HexConversions::to_hex(rseq_t(wire.data(), size)));
    };
    if (selection != 0)
    {
        pair.policy->allowCommonSelect = true;
        native[0] = static_cast<uint8_t>(0xC0 | appSequence);
        challengeReply(selection == 1 ? 1 : 2); // Real, authorized SELECT; never mutate private ownership state.
        pair.Pump(); // Complete its response authentication before the next request.
        REQUIRE(pair.outstation.cmdHandler->NumSelect() == 2);
        if (aggressive)
            REQUIRE(ProductionAuthenticationTestAccess::ControlAggressive(*pair.master.context)
                .RememberChallenge(responder.LastAcceptedChallenge(), false));
        appSequence = static_cast<uint8_t>((appSequence + (selection == 2 ? 2 : 1)) & 15);
    }
    native[0] = static_cast<uint8_t>(0xC0 | appSequence);
    native[1] = FunctionCodeSpec::to_type(FunctionCode::OPERATE);
    pair.policy->allowControl = !denyPolicy;
    REQUIRE(pair.policy->IsAuthorized(7, 2, native[1], native.data(), native.size()) == !denyPolicy);
    uint32_t csq = 0;
    if (aggressive)
    {
        auto& session = ProductionAuthenticationTestAccess::Session(*pair.master.context, 2);
        REQUIRE(ProductionAuthenticationTestAccess::ControlAggressive(*pair.master.context)
            .Create(7, 2, session.ControlKey(0), rseq_t(native.data(), native.size()), wseq_t(wire.data(), wire.size()), size));
        Group120Var3 authenticated;
        auto prefix = rseq_t(wire.data(), size).skip(6);
        REQUIRE(Group120Var3::Read(prefix, authenticated));
        csq = authenticated.seqNum;
        pair.outstation.SendToOutstation(HexConversions::to_hex(rseq_t(wire.data(), size)));
    }
    else
    {
        challengeReply(2);
        Group120Var2 authenticated;
        REQUIRE(authenticated.Read(rseq_t(wire.data(), size).skip(8)));
        csq = authenticated.seqNum;
    }
    // Missing SELECT, another user's SELECT, and a native sequence mismatch
    // must not execute OPERATE or masquerade as an authorization-policy denial.
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    REQUIRE(observer->denied == (denyPolicy ? 1 : 0));
    REQUIRE(ProductionAuthenticationTestAccess::Stats(pair.outstation.context)
        .Value(SecurityStatistic::AUTHORIZATION_FAILURES) == observer->denied);
    REQUIRE(observer->sent == (denyPolicy ? 1 : 0));
    const bool nativeSequenceFailure = selection == 2 && !denyPolicy;
    REQUIRE(pair.outstation.lower->NumWrites() == ((denyPolicy || nativeSequenceFailure) ? 1 : 0));
    if (denyPolicy)
    {
        HexSequence error(pair.outstation.lower->PopWriteAsHex());
        REQUIRE(error.ToRSeq()[1] == 0x83);
        REQUIRE(error.ToRSeq()[5] == 7);
        Group120Var7 value;
        REQUIRE(value.Read(error.ToRSeq().skip(10)));
        REQUIRE(value.errorCode == 7);
        REQUIRE(value.userNum == 2);
        REQUIRE(value.seqNum == csq);
        REQUIRE(value.associationId == 7);
    }
    else if (nativeSequenceFailure)
    {
        const auto response = pair.outstation.lower->PopWriteAsHex();
        HexSequence packet(response);
        REQUIRE(packet.ToRSeq()[1] == 0x81); // Native command rejection, not an Authentication Error.
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(response));
        pair.Pump(); // Also validate the ordinary response's Monitoring MAC.
        REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
        REQUIRE(observer->denied == 0);
        REQUIRE(observer->sent == 0);
    }
}

TEST_CASE("ProductionAuthentication - security statistics count real fragments and authentication once",
          "[production-sa][sa-statistics]")
{
    const bool aggressive = GENERATE(false, true);
    RuntimePair pair(false, aggressive);
    pair.Pump();
    auto& master = ProductionAuthenticationTestAccess::Stats(*pair.master.context);
    auto& outstation = ProductionAuthenticationTestAccess::Stats(pair.outstation.context);
    REQUIRE(master.Value(SecurityStatistic::SESSION_KEY_CHANGES) == 2);
    REQUIRE(outstation.Value(SecurityStatistic::SESSION_KEY_CHANGES) == 2);
    const auto m = master.Values();
    const auto o = outstation.Values();
    pair.SelectOperate();
    pair.Pump();
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    for (auto index : {SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS, SecurityStatistic::CRITICAL_MESSAGES_SENT,
                       SecurityStatistic::CRITICAL_MESSAGES_RECEIVED})
    {
        REQUIRE(master.Value(index) == m[static_cast<size_t>(index)] + 2);
        REQUIRE(outstation.Value(index) == o[static_cast<size_t>(index)] + 2);
    }
    REQUIRE(master.Value(SecurityStatistic::TOTAL_MESSAGES_SENT) - m[5]
        == outstation.Value(SecurityStatistic::TOTAL_MESSAGES_RECEIVED) - o[6]);
    REQUIRE(outstation.Value(SecurityStatistic::TOTAL_MESSAGES_SENT) - o[5]
        == master.Value(SecurityStatistic::TOTAL_MESSAGES_RECEIVED) - m[6]);
    REQUIRE(master.Value(SecurityStatistic::TOTAL_MESSAGES_SENT) > master.Value(SecurityStatistic::CRITICAL_MESSAGES_SENT));
    const auto successes = outstation.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);
    const auto unexpected = outstation.Value(SecurityStatistic::UNEXPECTED_MESSAGES);
    const auto discarded = outstation.Value(SecurityStatistic::DISCARDED_MESSAGES);
    REQUIRE_FALSE(pair.savedReply.empty());
    pair.outstation.SendToOutstation(pair.savedReply); // Exact previously transmitted Reply, after exchange completion.
    REQUIRE(outstation.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == successes);
    REQUIRE(outstation.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == unexpected + 1);
    REQUIRE(outstation.Value(SecurityStatistic::DISCARDED_MESSAGES) == discarded + 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    REQUIRE(outstation.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(outstation.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 0);
}

TEST_CASE("ProductionAuthentication - invalid Reply users never select recovery keys",
          "[production-sa][sa-statistics]")
{
    const uint16_t user = GENERATE(uint16_t{0}, uint16_t{42}, uint16_t{2});
    const bool exhaustedRekeys = GENERATE(false, true);
    RuntimePair pair;
    pair.Pump();
    auto& statistics = ProductionAuthenticationTestAccess::Stats(pair.outstation.context);
    unsigned closes = 0;
    ProductionAuthenticationTestAccess::ObserveClose(pair.outstation.context, [&closes]() { ++closes; });
    // Establish the protocol-Max precondition through the trusted statistics
    // event hook. Actual recovery-TX accounting is exercised separately below.
    if (exhaustedRekeys)
        for (unsigned n = 0; n < 4; ++n) statistics.AuthenticationRekeyStarted();
    const auto initial = statistics.Values();
    auto& common = ProductionAuthenticationTestAccess::Common(pair.outstation.context);
    auto& control = ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2);
    const auto commonKSQ = common.Sequence(), controlKSQ = control.Sequence();
    pair.SelectOperate();
    HexSequence request(pair.master.lower->PopWriteAsHex());
    REQUIRE(pair.master.context->OnTxReady());
    std::vector<uint8_t> critical(static_cast<const uint8_t*>(request.ToRSeq()),
                                static_cast<const uint8_t*>(request.ToRSeq()) + request.ToRSeq().length());
    for (uint8_t n = 0; n < 6; ++n)
    {
        critical[0] = static_cast<uint8_t>(0xC0 | n);
        pair.outstation.SendToOutstation(HexConversions::to_hex(rseq_t(critical.data(), critical.size())));
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        HexSequence challenge(pair.outstation.lower->PopWriteAsHex());
        Group120Var1 value;
        REQUIRE(value.Read(challenge.ToRSeq().skip(10)));
        pair.outstation.OnTxReady();
        std::vector<uint8_t> transcript(static_cast<const uint8_t*>(challenge.ToRSeq()),
            static_cast<const uint8_t*>(challenge.ToRSeq()) + challenge.ToRSeq().length());
        transcript.insert(transcript.end(), critical.begin(), critical.end());
        std::array<uint8_t, 16> tag{};
        REQUIRE(crypto::ComputeHMACSHA256(control.ControlKey(0), rseq_t(transcript.data(), transcript.size()),
            wseq_t(tag.data(), tag.size())) == crypto::Result::OK);
        tag[0] ^= 1; // Definitely incorrect for the known-user case, not a probabilistic zero tag.
        Group120Var2 reply(value.seqNum, user, rseq_t(tag.data(), tag.size()));
        std::array<uint8_t, 64> bytes{};
        APDURequest packet(wseq_t(bytes.data(), bytes.size()));
        packet.ConfigureHeader(FunctionCode::AUTH_REQUEST, n);
        auto writer = packet.GetWriter();
        REQUIRE(writer.WriteFreeFormat(&reply, 1));
        pair.outstation.SendToOutstation(HexConversions::to_hex(packet.ToRSeq()));
        REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_FAILURES) == initial[2] + n + 1);
        REQUIRE(statistics.Value(SecurityStatistic::DISCARDED_MESSAGES) == initial[9] + n + 1);
        REQUIRE(common.Ready(0));
        REQUIRE(control.Ready(0));
        REQUIRE(common.Sequence() == commonKSQ);
        REQUIRE(control.Sequence() == controlKSQ);
    }
    REQUIRE(statistics.Exceeded(SecurityStatistic::AUTHENTICATION_FAILURES) == !exhaustedRekeys);
    REQUIRE(closes == (exhaustedRekeys ? 1u : 0u)); // Association action never chooses a user.
    REQUIRE(statistics.RecoveryUser() == 0);
    REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_REKEYS) == initial[4]);
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == initial[13]);
    REQUIRE(statistics.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == initial[12]);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(pair.outstation.context) != OutstationChallenger::State::WAITING_FOR_REPLY);
}

TEST_CASE("ProductionAuthentication - monitoring recovery counts its first actual exchange transmission",
          "[production-sa][sa-statistics]")
{
    const bool disconnect = GENERATE(false, true);
    RuntimePair pair;
    pair.Pump();
    auto& statistics = ProductionAuthenticationTestAccess::Stats(*pair.master.context);
    auto& other = ProductionAuthenticationTestAccess::Session(*pair.master.context, 2);
    const auto otherKSQ = other.Sequence();
    const auto changes = statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES);
    for (unsigned n = 0; n < 6; ++n)
    {
        REQUIRE(pair.master.SendToMaster("D3 82 00 00"));
        REQUIRE(pair.master.lower->NumWrites() == 1);
        HexSequence challenge(pair.master.lower->PopWriteAsHex());
        if (n < 5) REQUIRE(pair.master.context->OnTxReady()); // Last Challenge stays in flight.
        Group120Var1 value;
        REQUIRE(value.Read(challenge.ToRSeq().skip(8)));
        std::vector<uint8_t> transcript(static_cast<const uint8_t*>(challenge.ToRSeq()),
            static_cast<const uint8_t*>(challenge.ToRSeq()) + challenge.ToRSeq().length());
        const uint8_t original[] = {0xD3, 0x82, 0, 0};
        transcript.insert(transcript.end(), original, original + sizeof(original));
        std::array<uint8_t, 16> tag{};
        REQUIRE(crypto::ComputeHMACSHA256(ProductionAuthenticationTestAccess::Common(pair.outstation.context).MonitoringKey(0),
            rseq_t(transcript.data(), transcript.size()), wseq_t(tag.data(), tag.size())) == crypto::Result::OK);
        tag[0] ^= 1;
        Group120Var2 reply(value.seqNum, 1, rseq_t(tag.data(), tag.size()));
        std::array<uint8_t, 64> data{};
        APDUResponse packet(wseq_t(data.data(), data.size()));
        packet.SetControl(AppControlField::Request(3));
        packet.SetFunction(FunctionCode::AUTH_RESPONSE);
        packet.SetIIN(IINField::Empty());
        auto writer = packet.GetWriter();
        REQUIRE(writer.WriteFreeFormat(&reply, 1));
        REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(packet.ToRSeq())));
    }
    REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_FAILURES) == 6);
    REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_REKEYS) == 0); // Nothing transmitted yet.
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == changes);
    REQUIRE(other.Ready(0));
    REQUIRE(other.Sequence() == otherKSQ);
    REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) == 8); // V4 queued behind C1.
    if (disconnect)
    {
        REQUIRE(pair.master.context->OnLowerLayerDown());
        REQUIRE(statistics.RecoveryUser() == 0);
        REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_FAILURES) == 6);
        REQUIRE(pair.master.context->OnLowerLayerUp());
        pair.master.exe->run_many();
        REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_REKEYS) == 0); // Old intent never resumes.
        return;
    }
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(pair.master.lower->NumWrites() == 1);
    HexSequence statusRequest(pair.master.lower->PopWriteAsHex());
    REQUIRE(statusRequest.ToRSeq()[3] == 4);
    REQUIRE(statusRequest.ToRSeq()[6] == 1); // Established monitoring owner, not a received user selection.
    REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_REKEYS) == 1);
    REQUIRE_FALSE(statistics.Exceeded(SecurityStatistic::AUTHENTICATION_FAILURES));
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == changes);
    REQUIRE(other.Ready(0));
}

TEST_CASE("ProductionAuthentication - reply timeout Max aborts without clearing totals",
          "[production-sa][sa-statistics]")
{
    RuntimePair pair;
    pair.Pump();
    auto& statistics = ProductionAuthenticationTestAccess::Stats(pair.outstation.context);
    const auto keys = statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES);
    for (unsigned n = 0; n < 4; ++n)
    {
        pair.outstation.SendToOutstation("C5 03");
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        pair.outstation.AdvanceTime(TimeDuration::Milliseconds(2000));
        REQUIRE(statistics.Value(SecurityStatistic::REPLY_TIMEOUTS) == n + 1);
    }
    REQUIRE(statistics.Value(SecurityStatistic::DISCARDED_MESSAGES) == 4);
    REQUIRE(statistics.Maximum(SecurityStatistic::REPLY_TIMEOUTS) == 7);
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::Common(pair.outstation.context).Ready(8000));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2).Ready(8000));
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == keys);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    pair.outstation.SendToOutstation("C9 20 78 04 07 01 02 00");
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    HexSequence response(pair.outstation.lower->PopWriteAsHex());
    Group120Var5 status;
    REQUIRE(status.Read(response.ToRSeq().skip(10)));
    REQUIRE(status.keyStatus == 4); // Explicit all-user COMM_FAIL, Table 7-8 row 9.
}

TEST_CASE("ProductionAuthentication - reconnect preserves statistics and does not invent Update Key changes",
          "[production-sa][sa-statistics]")
{
    RuntimePair pair;
    pair.Pump();
    auto& master = ProductionAuthenticationTestAccess::Stats(*pair.master.context);
    auto& outstation = ProductionAuthenticationTestAccess::Stats(pair.outstation.context);
    const auto m = master.Values(), o = outstation.Values();
    REQUIRE(pair.master.context->OnLowerLayerDown());
    pair.outstation.LowerLayerDown();
    REQUIRE(master.Values() == m);
    REQUIRE(outstation.Values() == o);
    pair.outstation.LowerLayerUp();
    REQUIRE(pair.master.context->OnLowerLayerUp());
    pair.master.exe->run_many();
    pair.Pump();
    REQUIRE(master.Value(SecurityStatistic::SESSION_KEY_CHANGES) == m[13] + 2);
    REQUIRE(outstation.Value(SecurityStatistic::SESSION_KEY_CHANGES) == o[13] + 2);
    REQUIRE(master.Value(SecurityStatistic::TOTAL_MESSAGES_SENT) > m[5]);
    REQUIRE(outstation.Value(SecurityStatistic::TOTAL_MESSAGES_SENT) > o[5]);
    REQUIRE(master.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(outstation.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(outstation.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 0);
    REQUIRE(outstation.Value(SecurityStatistic::RESTART_REKEYS) == 0);
}

TEST_CASE("ProductionAuthentication - rejected monitoring Reply preserves another user's exchange and TX bytes",
          "[production-sa][sa-statistics]")
{
    RuntimePair pair;
    // Complete user 1 only; leave user 2's real V4 in flight.
    for (size_t n = 0; n < 2; ++n)
    {
        const auto request = pair.master.lower->PopWriteAsHex();
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(request);
        const auto status = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(status));
        pair.master.exe->run_many();
    }
    const auto request = pair.master.lower->PopWriteAsHex();
    HexSequence held(request);
    REQUIRE(held.ToRSeq()[3] == 4);
    REQUIRE(held.ToRSeq()[6] == 2);
    REQUIRE(pair.master.SendToMaster("D3 82 00 00"));
    auto queued = ProductionAuthenticationTestAccess::PendingBytes(*pair.master.context)
        .take(ProductionAuthenticationTestAccess::Pending(*pair.master.context));
    Group120Var1 challenge;
    REQUIRE(challenge.Read(queued.skip(8)));
    std::array<uint8_t, 64> data{};
    std::array<uint8_t, 16> unusedTag{};
    Group120Var2 invalid(challenge.seqNum, 42, rseq_t(unusedTag.data(), unusedTag.size()));
    APDUResponse reply(wseq_t(data.data(), data.size()));
    reply.SetControl(AppControlField::Request(3));
    reply.SetFunction(FunctionCode::AUTH_RESPONSE);
    reply.SetIIN(IINField::Empty());
    auto writer = reply.GetWriter();
    REQUIRE(writer.WriteFreeFormat(&invalid, 1));
    REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(reply.ToRSeq())));
    REQUIRE(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2).IsExchanging());
    REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) == 0);
    REQUIRE(ProductionAuthenticationTestAccess::WireBytes(*pair.master.context, held.ToRSeq().length()).equals(held.ToRSeq()));
    REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::AUTHENTICATION_FAILURES) == 1);
    REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::CRITICAL_MESSAGES_RECEIVED) == 0);
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(request);
    pair.Pump(); // The original user's V5/V6/V5 still completes, with its original ownership.
    REQUIRE(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2).Ready(0));
}

TEST_CASE("ProductionAuthentication - real peer restarts retain and throttle the association restart statistic",
          "[production-sa][sa-statistics]")
{
    RuntimePair pair;
    pair.Pump();
    pair.outstation.LowerLayerDown();
    std::unique_ptr<OutstationTestObject> restarted;
    auto& statistics = ProductionAuthenticationTestAccess::Stats(*pair.master.context);
    for (unsigned n = 0; n < 5; ++n)
    {
        REQUIRE(pair.master.context->OnLowerLayerDown());
        if (restarted) restarted->LowerLayerDown();
        restarted.reset(new OutstationTestObject(OutSettings(pair.source, pair.policy)));
        restarted->LowerLayerUp();
        REQUIRE(pair.master.context->OnLowerLayerUp());
        pair.master.exe->run_many();
        pair.Pump(restarted.get());
        REQUIRE(statistics.Value(SecurityStatistic::RESTART_REKEYS) == std::min(n + 1, 4u));
        REQUIRE(ProductionAuthenticationTestAccess::Stats(restarted->context).Value(SecurityStatistic::RESTART_REKEYS) == 0);
        REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).Ready(0) == (n < 4));
    }
    REQUIRE(statistics.Exceeded(SecurityStatistic::RESTART_REKEYS));
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == 10); // Initial two users + four accepted restarts.
}

TEST_CASE("ProductionAuthentication - native Error event objects count without standalone recovery",
          "[production-sa][sa-statistics]")
{
    RuntimePair pair;
    pair.Pump();
    auto& statistics = ProductionAuthenticationTestAccess::Stats(*pair.master.context);
    const auto before = statistics.Values();
    auto& key = ProductionAuthenticationTestAccess::Common(pair.outstation.context);
    std::array<uint8_t, 256> native{}, replyBytes{};
    APDUResponse response(wseq_t(native.data(), native.size()));
    response.SetFunction(FunctionCode::UNSOLICITED_RESPONSE);
    response.SetControl(AppControlField(0xF3)); // Table 7-9: native Error events require CON.
    response.SetIIN(IINField::Empty());
    HexSequence binary("01 02 00 00 00 01");
    REQUIRE(response.AppendObjects(binary.ToRSeq())); // Error objects need not be the first header.
    Group120Var7 errors[] = {Group120Var7(123, 1, 8, 1, DNPTime(100), rseq_t()),
                            Group120Var7(124, 2, 8, 7, DNPTime(101), rseq_t())};
    auto writer = response.GetWriter();
    REQUIRE(writer.WriteFreeFormat(errors, 2));
    const auto original = response.ToRSeq();
    MasterResponder peer(7, 16, 2000, true);
    REQUIRE(peer.SetSessionKey(1, key.MonitoringKey(0), key.ValidUntil(), 0) == MasterResponder::Result::OK);
    REQUIRE(peer.RetainRequest(7, original, 0) == MasterResponder::Result::OK);
    REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(original)));
    REQUIRE(statistics.Value(SecurityStatistic::ERROR_MESSAGES_RECEIVED) == before[11]); // Not authenticated yet.
    HexSequence challenge(pair.master.lower->PopWriteAsHex());
    REQUIRE(pair.master.context->OnTxReady());
    size_t size = 0;
    REQUIRE(peer.Respond(7, challenge.ToRSeq(), 0, wseq_t(replyBytes.data(), replyBytes.size()), size)
        == MasterResponder::Result::OK);
    REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(replyBytes.data(), size))));
    REQUIRE(statistics.Value(SecurityStatistic::ERROR_MESSAGES_RECEIVED) == before[11] + 2);
    REQUIRE(statistics.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == before[12] + 1);
    REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_REKEYS) == before[4]);
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == before[13]);
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::Common(*pair.master.context).IsExchanging());
}

TEST_CASE("ProductionAuthentication - rising restart IIN discards the owned pending response and retains TX proof",
          "[production-sa][sa-statistics]")
{
    RuntimePair pair;
    pair.Pump();
    auto& statistics = ProductionAuthenticationTestAccess::Stats(*pair.master.context);
    REQUIRE(pair.master.SendToMaster("D3 82 00 00")); // Also observes the cleared restart bit.
    HexSequence held(pair.master.lower->PopWriteAsHex()); // Monitoring Challenge remains in flight.
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    const auto before = statistics.Values();
    REQUIRE(pair.master.SendToMaster("D4 82 80 00")); // Table 7-8 row 28, rising RESTART.
    REQUIRE(statistics.Value(SecurityStatistic::RESTART_REKEYS) == before[17] + 1);
    REQUIRE(statistics.Value(SecurityStatistic::DISCARDED_MESSAGES) == before[9] + 2);
    REQUIRE(statistics.Value(SecurityStatistic::FAILED_SESSION_KEY_CHANGES) == before[14]);
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::Common(*pair.master.context).Ready(0));
    REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).HasMonitoringHistory());
    REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) == 8);
    REQUIRE(ProductionAuthenticationTestAccess::WireBytes(*pair.master.context, held.ToRSeq().length()).equals(held.ToRSeq()));
    REQUIRE(pair.master.SendToMaster("D4 82 80 00")); // A set bit is not another restart edge.
    REQUIRE(statistics.Value(SecurityStatistic::RESTART_REKEYS) == before[17] + 1);
    SECTION("a live peer proves its old status instead of losing retained MAC history")
    {
        REQUIRE(pair.master.context->OnTxReady());
        pair.Pump();
    }
    SECTION("a genuinely restarted peer follows the existing bounded no MAC bootstrap")
    {
        pair.outstation.LowerLayerDown();
        OutstationTestObject restarted(OutSettings(pair.source, pair.policy));
        restarted.LowerLayerUp();
        REQUIRE(pair.master.context->OnTxReady());
        pair.Pump(&restarted);
    }
    REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).Ready(0));
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == before[13] + 2);
    REQUIRE(statistics.Value(SecurityStatistic::RESTART_REKEYS) == before[17] + 1);
}

TEST_CASE("ProductionAuthentication - foreign Key Status keeps transmission ownership and authenticates before failure counting",
          "[production-sa][sa-statistics]")
{
    const bool authentic = GENERATE(false, true);
    RuntimePair pair;
    // Finish user 1; retain user 2's V4 for the exchange under test.
    for (size_t n = 0; n < 2; ++n)
    {
        const auto request = pair.master.lower->PopWriteAsHex();
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(request);
        const auto status = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(status));
        pair.master.exe->run_many();
    }
    const auto request = pair.master.lower->PopWriteAsHex();
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(request);
    const auto status = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(status));
    HexSequence held(pair.master.lower->PopWriteAsHex()); // User 2 V6 is in flight.
    REQUIRE(held.ToRSeq()[3] == 6);
    auto& owner = ProductionAuthenticationTestAccess::Session(*pair.master.context, 2);
    REQUIRE(owner.AwaitingKeyConfirmation());
    std::array<uint8_t, 256> queryBytes{}, foreignBytes{};
    APDURequest query(wseq_t(queryBytes.data(), queryBytes.size()));
    query.ConfigureHeader(FunctionCode::AUTH_REQUEST, held.ToRSeq()[0] & 15);
    Group120Var4 user;
    user.userNum = 1;
    auto writer = query.GetWriter();
    REQUIRE(writer.WriteSingleValue<ser4cpp::UInt8>(QualifierCode::UINT8_CNT, user));
    size_t size = 0;
    REQUIRE(ProductionAuthenticationTestAccess::Common(pair.outstation.context).Process(
                7, query.ToRSeq(), 0, wseq_t(foreignBytes.data(), foreignBytes.size()), size) == SessionKeys::Result::OK);
    if (!authentic) foreignBytes[size - 1] ^= 1;
    auto& statistics = ProductionAuthenticationTestAccess::Stats(*pair.master.context);
    const auto before = statistics.Values();
    REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(foreignBytes.data(), size))));
    REQUIRE(owner.IsExchanging());
    REQUIRE_FALSE(owner.AwaitingKeyConfirmation());
    REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).Ready(0));
    REQUIRE(ProductionAuthenticationTestAccess::WireBytes(*pair.master.context, held.ToRSeq().length()).equals(held.ToRSeq()));
    REQUIRE(statistics.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == before[0] + 1);
    REQUIRE(statistics.Value(SecurityStatistic::DISCARDED_MESSAGES) == before[9] + 1);
    REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_FAILURES) == before[2] + (authentic ? 0 : 1));
    REQUIRE(statistics.Value(SecurityStatistic::FAILED_SESSION_KEY_CHANGES) == before[14]);
    pair.master.exe->advance_time(std::chrono::milliseconds(2000));
    pair.master.exe->run_many();
    REQUIRE(statistics.Value(SecurityStatistic::REPLY_TIMEOUTS) == before[3] + 1);
    pair.outstation.SendToOutstation(HexConversions::to_hex(held.ToRSeq()));
    const auto late = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(late)); // Old application SEQ cannot complete the fresh status request.
    REQUIRE(pair.master.context->OnTxReady());
    pair.Pump(); // Retained candidate proves the V6 that completed after cancellation.
    REQUIRE(owner.Ready(2000));
}

TEST_CASE("ProductionAuthentication - rejected monitoring Challenge is unexpected without a transmitted Reply",
          "[production-sa][sa-statistics]")
{
    const bool missingKeys = GENERATE(false, true);
    RuntimePair pair;
    pair.Pump();
    pair.SelectOperate();
    for (size_t step = 0; step < 2; ++step)
    {
        const auto request = pair.master.lower->PopWriteAsHex();
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(request);
        const auto response = pair.outstation.lower->PopWriteAsHex();
        if (step == 0) pair.outstation.OnTxReady(); // Leave the native SELECT response in flight.
        REQUIRE(pair.master.SendToMaster(response));
        pair.master.exe->run_many();
    }
    HexSequence challenge(pair.master.lower->PopWriteAsHex());
    REQUIRE(pair.master.context->OnTxReady());
    std::vector<uint8_t> bytes(static_cast<const uint8_t*>(challenge.ToRSeq()),
                              static_cast<const uint8_t*>(challenge.ToRSeq()) + challenge.ToRSeq().length());
    if (missingKeys)
        ProductionAuthenticationTestAccess::Common(pair.outstation.context).Disconnect();
    else
        bytes[12] = 2; // Monitoring Direction must select common user 1.
    auto& statistics = ProductionAuthenticationTestAccess::Stats(pair.outstation.context);
    const auto before = statistics.Values();
    pair.outstation.SendToOutstation(HexConversions::to_hex(rseq_t(bytes.data(), bytes.size())));
    REQUIRE(statistics.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == before[0] + 1);
    REQUIRE(statistics.Value(SecurityStatistic::DISCARDED_MESSAGES) == before[9] + 1);
    REQUIRE(statistics.Value(SecurityStatistic::CRITICAL_MESSAGES_SENT) == before[7]);
    REQUIRE(statistics.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == before[12]);
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::MonitoringPending(pair.outstation.context));
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
    REQUIRE(pair.outstation.context.OnTxReady());
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
}

TEST_CASE("ProductionAuthentication - exceeded restart Max retains an independent pending Challenge",
          "[production-sa][sa-statistics]")
{
    RuntimePair pair;
    pair.Pump();
    auto& statistics = ProductionAuthenticationTestAccess::Stats(*pair.master.context);
    for (unsigned n = 0; n < 4; ++n) statistics.Increment(SecurityStatistic::RESTART_REKEYS);
    const std::string original = "D3 82 00 00";
    auto& keys = ProductionAuthenticationTestAccess::Common(pair.outstation.context);
    MasterResponder peer(7, 16, 2000, true);
    REQUIRE(peer.SetSessionKey(1, keys.MonitoringKey(0), keys.ValidUntil(), 0) == MasterResponder::Result::OK);
    HexSequence request(original);
    REQUIRE(peer.RetainRequest(7, request.ToRSeq(), 0) == MasterResponder::Result::OK);
    REQUIRE(pair.master.SendToMaster(original));
    HexSequence challenge(pair.master.lower->PopWriteAsHex());
    const auto before = statistics.Values();
    REQUIRE(pair.master.SendToMaster("D4 82 80 00")); // Table 7-8 row 29: discard only this ASDU.
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).Ready(0));
    REQUIRE(statistics.Value(SecurityStatistic::RESTART_REKEYS) == before[17]);
    REQUIRE(statistics.Value(SecurityStatistic::DISCARDED_MESSAGES) == before[9] + 1);
    REQUIRE(pair.master.context->OnTxReady());
    std::array<uint8_t, 256> reply{};
    size_t size = 0;
    REQUIRE(peer.Respond(7, challenge.ToRSeq(), 0, wseq_t(reply.data(), reply.size()), size) == MasterResponder::Result::OK);
    REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(reply.data(), size))));
    REQUIRE(statistics.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == before[12] + 1);
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
}
