// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/APDUResponse.h"
#include "app/APDURequest.h"
#include "crypto/CryptoProvider.h"
#include "gen/objects/Group121.h"
#include "master/TaskPriority.h"
#include "utils/AcceptanceObservation.h"
#include "utils/BufferHelpers.h"
#include "utils/CommandCallbackQueue.h"
#include "utils/MasterTestFixture.h"
#include "utils/OutstationTestObject.h"

#include <ser4cpp/util/HexConversions.h>

#include <catch.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <functional>
#include <tuple>
#include <vector>

using namespace opendnp3;
using namespace ser4cpp;
namespace opendnp3
{
class ProductionAuthenticationTestAccess
{
public:
    static void Schedule(MContext& context, const std::shared_ptr<IMasterTask>& task)
    {
        context.ScheduleAdhocTask(task);
    }
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
    static uint32_t MonitoringSequence(MContext& context) { return context.authentication->monitoringAggressive.Sequence(); }
    static bool ControlEligible(MContext& context) { return context.authentication->controlEligible[1]; }
    static bool ReplyIssued(MContext& context) { return context.authentication->replyIssued; }
    static bool ReplyPending(MContext& context) { return context.authentication->replyPending; }
    static bool ReplyInFlight(MContext& context) { return context.authentication->replyInFlight; }
    static bool WireInFlight(MContext& context) { return context.authentication->wireInFlight; }
    static bool ProtectedConfirm(MContext& context) { return context.authentication->protectedConfirm; }
    static bool CheckConfirm(MContext& context) { return context.CheckConfirmTransmit(); }
    static bool MonitoringWaiting(MContext& context) { return context.authentication->monitorWaiting; }
    static MasterResponder::State ResponderState(MContext& context) { return context.authentication->responder.GetState(); }
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
    static bool SessionReady(OContext& context, uint16_t user)
    {
        const auto now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            context.executor->get_time().time_since_epoch()).count());
        return Session(context, user).IsReady(now);
    }
    static bool IsIdle(OContext& context) { return context.state->IsIdle(); }
    static bool StartupNullConfirmed(OContext& context) { return context.unsol.completedNull; }
    static const char* NativeState(OContext& context) { return context.state->Name(); }
    static int64_t ServiceDeadline(MContext& context)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            context.authentication->serviceTimer.expires_at().time_since_epoch()).count();
    }
    static rseq_t AcceptedChallenge(OContext& context)
    {
        return context.authentication->challenger.LastAcceptedChallenge();
    }
    static size_t Pending(OContext& context) { return context.authentication->pendingWireSize; }
    static IINField ResponseIIN(OContext& context) { return context.GetResponseIIN(); }
    static bool UnsolEnabled(OContext& context, PointClass clazz)
    {
        return context.params.unsolClassMask.Intersects(ClassField(clazz));
    }
    static uint32_t BufferedEvents(OContext& context, EventClass clazz)
    {
        return context.eventBuffer.NumEvents(clazz);
    }
    static rseq_t PendingBytes(OContext& context)
    {
        return rseq_t(context.authentication->pendingWire.data(), context.authentication->pendingWire.size());
    }
    static bool MonitoringPending(OContext& context) { return context.authentication->monitoringPending; }
    static MasterResponder::State MonitoringResponderState(OContext& context)
    {
        return context.authentication->monitoring.GetState();
    }
    static bool Transmitting(OContext& context) { return context.isTransmitting; }
    static OutstationChallenger::State ChallengeState(OContext& context)
    {
        return context.authentication->challenger.GetState();
    }
    static rseq_t ChallengeBytes(OContext& context)
    {
        return rseq_t(context.authentication->challenge.data(), context.authentication->challenge.size());
    }
    static uint64_t Now(OContext& context)
    {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            context.executor->get_time().time_since_epoch()).count());
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
    std::function<void()> onAuthorize;
    bool IsAuthorized(uint16_t assoc, uint16_t user, uint8_t function, const uint8_t* apdu, size_t size) const override
    {
        if (onAuthorize)
            onAuthorize();
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
                            const std::shared_ptr<IAuthenticationErrorObserver>& observer = nullptr,
                            uint32_t replyTimeoutMs = 2000,
                            IndexQualifierMode qualifier = IndexQualifierMode::always_two_bytes)
{
    auto p = NoStartupTasks();
    p.controlQualifierMode = qualifier;
    p.authentication.errorObserver = observer;
    p.authentication.replyTimeoutMs = replyTimeoutMs;
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
                             uint16_t maxErrors = 2, bool suppressErrors = false, uint32_t replyTimeoutMs = 2000,
                             bool class1Unsolicited = false, bool selectedInputs = false)
{
    OutstationConfig c;
    c.params.authentication.replyTimeoutMs = replyTimeoutMs;
    c.params.authentication.maxErrorMessagesSent = maxErrors;
    c.params.authentication.suppressAuthenticationErrors = suppressErrors;
    c.params.authentication.errorObserver = observer;
    if (macAlternatives) c.params.authentication.permittedMACAlgorithms = {{4, 2, 0, 0}};
    c.params.authentication.aggressiveTransmit = aggressive;
    c.params.authentication.aggressiveReceive = aggressive;
    c.params.allowUnsolicited = unsolicited;
    if (class1Unsolicited)
    {
        c.params.unsolClassMask = ClassField(PointClass::Class1);
        c.eventBufferConfig = selectedInputs ? EventBufferConfig(1, 1, 1) : EventBufferConfig(1);
    }
    c.params.authentication.association = 7;
    c.params.authentication.credentials = source;
    c.params.authentication.authorization = policy;
    return c;
}
DatabaseConfig BinaryEventDatabase(bool selectedInputs = false)
{
    DatabaseConfig db;
    BinaryConfig binary;
    binary.clazz = PointClass::Class1;
    db.binary_input.emplace(0, binary);
    if (selectedInputs)
    {
        db.double_binary.emplace(0, DoubleBitBinaryConfig());
        db.analog_input.emplace(0, AnalogConfig());
    }
    return db;
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
                         uint16_t maxErrors = 2, bool suppressErrors = false,
                         uint32_t masterTimeoutMs = 2000, uint32_t outstationTimeoutMs = 2000,
                         bool class1Unsolicited = false,
                         IndexQualifierMode qualifier = IndexQualifierMode::always_two_bytes,
                         bool selectedInputs = false)
        : master(MasterSettings(source, policy, aggressive, receiveAggressive, macAlternatives, observer, masterTimeoutMs, qualifier), Addresses(), "test", masterLog),
          outstation(OutSettings(source, policy, unsolicited, aggressive, macAlternatives, observer, maxErrors,
                                 suppressErrors, outstationTimeoutMs, class1Unsolicited, selectedInputs),
                     class1Unsolicited ? BinaryEventDatabase(selectedInputs) : DatabaseConfig())
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

TEST_CASE("ProductionAuthentication - response dispatch can advance the clock before control accounting",
          "[production-sa][sa-dispatch-clock]")
{
    const bool aggressive = GENERATE(false, true);
    RuntimePair pair(false, aggressive);
    pair.Pump();

    auto poll = [&]() {
        pair.master.context->ScanAllObjects(GroupVariationID(30, 5), pair.master.meas, TaskConfig::Default());
        pair.master.exe->run_many();
        pair.Pump();
    };
    poll(); // Establish real Control and Monitoring histories.
    REQUIRE(pair.master.application->taskCompletionEvents.size() == 1);
    REQUIRE(pair.master.application->taskCompletionEvents.back().result == TaskCompletion::SUCCESS);

    auto& session = ProductionAuthenticationTestAccess::Common(pair.outstation.context);
    const auto ksq = session.Sequence();
    const auto requests = pair.aggressiveRequests;
    const auto responses = pair.aggressiveResponses;
    const auto replies = pair.monitorReplies;
    size_t clockAdvances = 0;
    pair.policy->onAuthorize = [&]() {
        ++clockAdvances;
        pair.outstation.AdvanceTime(TimeDuration::Milliseconds(1));
    };
    poll();

    REQUIRE(clockAdvances == 1);
    REQUIRE(session.Ready(1));
    REQUIRE(session.Sequence() == ksq);
    REQUIRE(pair.master.application->taskCompletionEvents.size() == 2);
    REQUIRE(pair.master.application->taskCompletionEvents.back().result == TaskCompletion::SUCCESS);
    REQUIRE(pair.aggressiveRequests == requests + (aggressive ? 1 : 0));
    REQUIRE(pair.aggressiveResponses == responses + (aggressive ? 1 : 0));
    REQUIRE(pair.monitorReplies == replies + (aggressive ? 0 : 1));
}

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
    const uint8_t privateText[] = {'E', 'E'};
    if (code >= 128) error.errorText = rseq_t(privateText, 1);
    if (fault == 14 || fault == 15)
    {
        error.errorCode = 128;
        error.errorText = rseq_t(privateText, sizeof(privateText));
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
    // Encode valid text first, then corrupt the incoming wire without bypassing writer validation.
    if (fault == 14)
    {
        data[objectOffset + 4] = static_cast<uint8_t>(Group120Var7::MIN_SIZE);
        data[objectOffset + 5] = 0;
        errorSize = objectOffset + 6 + Group120Var7::MIN_SIZE; // Vendor code with empty text, not a truncated object.
    }
    if (fault == 15)
    {
        data[errorSize - 2] = 0xC0;
        data[errorSize - 1] = 0xAF; // Overlong UTF-8 encoding.
    }
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
            const auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(
                pair.master.context->params.responseTimeout.value);
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
    // Successful TX, serviced expiry, expiry at TX completion, unowned Reply, credential
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
        const auto ksq = session.Sequence();
        REQUIRE(pair.master.SendToMaster("C0 83 00 00 78 02 5B 01 01 00 00"));
        pair.master.exe->run_many();
        REQUIRE(session.IsExchanging()); // An unowned monitoring Reply cannot cancel this user's queued V6.
        REQUIRE(session.Sequence() == ksq);
        REQUIRE_FALSE(session.Ready(0));
        REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) == pendingSize);
        REQUIRE(pending.take(pendingSize).equals(oldChange.ToRSeq()));
        REQUIRE(pair.master.lower->NumWrites() == 0);
        REQUIRE(pair.results.values.empty());
        REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
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
    if (scenario != 0 && scenario != 3)
    {
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
    if (scenario == 0 || scenario == 3)
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
                const auto executions = pair.outstation.cmdHandler->NumInvocations();
                REQUIRE(pair.master.context->OnLowerLayerDown());
                REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == 0);
                REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages() == 0);
                REQUIRE(pair.master.context->confirmQueue.empty()); // No CONFIRM ownership survives disconnect.
                REQUIRE_FALSE(ProductionAuthenticationTestAccess::ControlAggressive(*pair.master.context).HasPendingConfirm());
                REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
                REQUIRE_FALSE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(encoded.data(), size))));
                REQUIRE_FALSE(pair.master.context->OnTxReady());
                REQUIRE(pair.master.lower->NumWrites() == 0);
                REQUIRE(pair.master.context->OnLowerLayerUp());
                pair.master.exe->run_many();
                REQUIRE(pair.master.context->confirmQueue.empty());
                REQUIRE_FALSE(ProductionAuthenticationTestAccess::Common(*pair.master.context).Ready(0));
                REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(encoded.data(), size))));
                REQUIRE(pair.master.context->confirmQueue.empty());
                REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
                REQUIRE(pair.master.lower->NumWrites() == 1);
                HexSequence fresh(pair.master.lower->PopWriteAsHex());
                REQUIRE(fresh.ToRSeq()[1] == 0x20);
                REQUIRE(fresh.ToRSeq()[3] == 4); // Reconnect negotiates keys instead of replaying old CONFIRMs.
                REQUIRE(pair.outstation.cmdHandler->NumInvocations() == executions);
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

TEST_CASE("ProductionAuthentication - outstation queued monitoring Reply counts on send and respects its lifetime", "[production-sa][sa-zero-runtime]")
{
    const auto budget = GENERATE(1u, 3u);
    const auto scenario = GENERATE(0, 1, 2, 3, 4, 5); // Send, timeout, disconnect, unowned Reply, key replacement, key expiry.
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
    const auto otherKSQ = ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2).Sequence();
    ProductionAuthenticationTestAccess::LeaveMessages(pair.outstation.context, budget);
    pair.outstation.SendToOutstation(challenge);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(ProductionAuthenticationTestAccess::Pending(pair.outstation.context) != 0);
    REQUIRE(session.RemainingMessages() == budget - 1); // Only the received Challenge has been counted.
    REQUIRE(pair.master.context->solSeq.Get() == before);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
    const auto pendingSize = ProductionAuthenticationTestAccess::Pending(pair.outstation.context);
    const auto queued = HexConversions::to_hex(
        ProductionAuthenticationTestAccess::PendingBytes(pair.outstation.context).take(pendingSize));
    const auto ksq = session.Sequence();
    if (scenario == 1)
        pair.outstation.AdvanceTime(TimeDuration::Milliseconds(pair.master.context->params.authentication.replyTimeoutMs));
    else if (scenario == 2)
        pair.outstation.LowerLayerDown();
    else if (scenario == 3)
    {
        pair.outstation.SendToOutstation("C0 20 78 02 5B 01 01 00 00");
        REQUIRE(ProductionAuthenticationTestAccess::Pending(pair.outstation.context) == pendingSize);
        REQUIRE(HexConversions::to_hex(ProductionAuthenticationTestAccess::PendingBytes(pair.outstation.context)
            .take(pendingSize)) == queued);
        REQUIRE(session.Sequence() == ksq);
        REQUIRE(session.RemainingMessages() == budget - 1);
        REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 1); // Only the previously authenticated SELECT.
    }
    else if (scenario == 4)
        REQUIRE(session.Configure(rseq_t(pair.source->keys[0].data(), 32), 10000000, 0) == SessionKeys::Result::OK);
    else if (scenario == 5)
        pair.outstation.AdvanceTime(TimeDuration::Milliseconds(expiry));
    if (scenario == 2)
        REQUIRE_FALSE(pair.outstation.context.OnTxReady());
    else
        REQUIRE(pair.outstation.context.OnTxReady());
    REQUIRE(ProductionAuthenticationTestAccess::Pending(pair.outstation.context) == 0);
    if (scenario != 0 && scenario != 3)
    {
        REQUIRE(pair.outstation.lower->NumWrites() == 0); // No stale precomputed Reply after abort/expiry/rekey.
        REQUIRE(pair.master.context->solSeq.Get() == before);
        REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
        if (scenario == 1)
            REQUIRE(session.RemainingMessages() == budget - 1); // An unsent Reply is never counted.
        if (scenario == 1)
        {
            auto& other = ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2);
            REQUIRE(other.Ready(pair.master.context->params.authentication.replyTimeoutMs));
            REQUIRE(other.Sequence() == otherKSQ);
        }
        if (scenario == 4 || scenario == 5)
            REQUIRE_FALSE(session.Ready(scenario == 5 ? expiry : 0));
        return;
    }
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto reply = pair.outstation.lower->PopWriteAsHex();
    REQUIRE(reply == queued); // The independently owned monitoring Reply survives unchanged.
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
    const auto scenario = GENERATE(0, 1, 2, 3); // Normal completion, unowned Replies, response timeout, disconnect.
    CAPTURE(scenario);
    RuntimePair pair(false, true);
    pair.Pump();
    pair.SelectOperate();
    pair.Pump();
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
    const auto startTime = pair.master.exe->get_time();
    const auto restartRekeys = ProductionAuthenticationTestAccess::Stats(*pair.master.context)
        .Value(SecurityStatistic::RESTART_REKEYS);
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
            REQUIRE(ProductionAuthenticationTestAccess::ControlEligible(*pair.master.context));
            REQUIRE(ProductionAuthenticationTestAccess::ReplyIssued(*pair.master.context));
            REQUIRE(pair.results.values.size() == 1);
            REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
        }
        // An unauthenticated response still cannot complete this live command.
        const auto before = pair.master.context->solSeq.Get();
        // Preserve the peer's IIN; clearing DEVICE_RESTART here would make its real response look like a new restart.
        const auto iin = ProductionAuthenticationTestAccess::ResponseIIN(pair.outstation.context);
        const uint8_t response[] = {static_cast<uint8_t>(0xC0 | (request.ToRSeq()[0] & 0x0F)), 0x81, iin.LSB, iin.MSB};
        REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(response, sizeof(response)))));
        pair.master.exe->run_many();
        REQUIRE(pair.master.context->solSeq.Get() == before);
        REQUIRE(pair.results.values.size() == 1);
        REQUIRE(pair.master.lower->NumWrites() == 0);
        REQUIRE(borrowed.equals(request.ToRSeq()));
        REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
        const auto pendingSize = ProductionAuthenticationTestAccess::Pending(*pair.master.context);
        HexSequence monitoring(HexConversions::to_hex(
            ProductionAuthenticationTestAccess::PendingBytes(*pair.master.context).take(pendingSize)));
        Group120Var1 challenge;
        REQUIRE(challenge.Read(monitoring.ToRSeq().skip(8)));
        // Cancel only this independent monitoring Challenge with its correctly owned Error.
        // The aggressive command and its transmission must survive.
        std::array<uint8_t, 64> errorBytes{};
        APDUResponse error(wseq_t(errorBytes.data(), errorBytes.size()));
        error.SetFunction(FunctionCode::AUTH_RESPONSE);
        error.SetControl(AppControlField::Request(monitoring.ToRSeq()[0] & 0x0F));
        error.SetIIN(IINField::Empty());
        Group120Var7 value(challenge.seqNum, 1, 7, 7, DNPTime(0), rseq_t());
        auto writer = error.GetWriter();
        REQUIRE(writer.WriteFreeFormat(&value, 1));
        REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(error.ToRSeq())));
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
        REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) == 0);
        REQUIRE(ProductionAuthenticationTestAccess::ControlEligible(*pair.master.context));
        REQUIRE(ProductionAuthenticationTestAccess::ReplyIssued(*pair.master.context));
        REQUIRE(borrowed.equals(request.ToRSeq()));
        REQUIRE(pair.results.values.size() == 1);
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
    if (scenario == 0 || scenario == 1)
    {
        // Lower-layer-owned bytes were copied above; normal authenticated processing still succeeds.
        pair.outstation.SendToOutstation(packet);
        pair.Pump();
        REQUIRE(pair.master.exe->get_time() == startTime);
        REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context)
            .Value(SecurityStatistic::RESTART_REKEYS) == restartRekeys);
        REQUIRE(pair.results.values.size() == 2);
        REQUIRE(pair.results.values.back().summary == TaskCompletion::SUCCESS);
        REQUIRE(pair.outstation.cmdHandler->NumOperate() == 2);
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
        REQUIRE_FALSE((fresh.ToRSeq()[2] == 120 && fresh.ToRSeq()[3] == 3));
        for (size_t i = 0; i < borrowed.length(); ++i)
            REQUIRE(borrowed[i] == 0);
    }
}

TEST_CASE("ProductionAuthentication - delayed master native CONFIRM Reply validates lifetime without deferred counts", "[production-sa][sa-zero-runtime]")
{
    const bool deferred = GENERATE(false, true);
    const auto scenario = GENERATE(0, 1, 2, 3, 4, 5); // Send, timeout, expiry, unowned Reply, new KSQ, unowned Reply during TX.
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
    const auto queued = HexConversions::to_hex(ProductionAuthenticationTestAccess::ReplyBytes(*pair.master.context));
    const auto ksq = common.Sequence();
    const auto otherKSQ = ProductionAuthenticationTestAccess::Session(*pair.master.context, 2).Sequence();
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
        REQUIRE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
        REQUIRE(common.Sequence() == ksq);
        REQUIRE(HexConversions::to_hex(ProductionAuthenticationTestAccess::ReplyBytes(*pair.master.context)) == queued);
        REQUIRE((ProductionAuthenticationTestAccess::Deferred(*pair.master.context) != 0) == deferred);
        REQUIRE(pair.master.lower->NumWrites() == 0);
        REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    }
    else if (scenario == 4)
        REQUIRE(common.Configure(rseq_t(pair.source->keys[0].data(), 32), 10000000, 0) == SessionKeys::Result::OK);
    REQUIRE(pair.master.context->isSending);
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
    if (scenario == 1 || scenario == 2 || scenario == 4)
    {
        if (scenario == 1)
        {
            auto& other = ProductionAuthenticationTestAccess::Session(*pair.master.context, 2);
            REQUIRE(other.Ready(pair.master.context->params.authentication.replyTimeoutMs));
            REQUIRE(other.Sequence() == otherKSQ);
        }
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
    REQUIRE(reply == queued);
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
    pair.outstation.SendToOutstation(reply); // Replaying it cannot authorize another CONFIRM or command.
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
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
    HexSequence original(request);
    const auto sequence = pair.master.context->solSeq.Get();
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
        REQUIRE_FALSE(pair.master.context->activeTask);
        REQUIRE(pair.results.values.size() == 1);
        REQUIRE(pair.results.values.front().summary == TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    }
    REQUIRE(pair.master.context->isSending);
    REQUIRE(pair.master.context->txBuffer.as_rslice().take(original.ToRSeq().length()).equals(original.ToRSeq()));
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyIssued(*pair.master.context));
    REQUIRE_FALSE(pair.master.context->activeTask);
    REQUIRE(pair.master.context->solSeq.Get() == ((sequence + 1) & 0x0F));
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    const auto cancelled = ProductionAuthenticationTestAccess::ReplyBytes(*pair.master.context);
    for (size_t i = 0; i < cancelled.length(); ++i)
        REQUIRE(cancelled[i] == 0);
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
    REQUIRE(pair.results.values.size() == 1); // Independent authentication never completes the expired task again.
    REQUIRE(pair.results.values.front().summary == TaskCompletion::FAILURE_RESPONSE_TIMEOUT);

    // Even a late SELECT echo with a valid monitoring MAC cannot revive the completed task.
    std::array<uint8_t, 64> lateBytes{};
    APDUResponse late(wseq_t(lateBytes.data(), lateBytes.size()));
    late.SetFunction(FunctionCode::RESPONSE);
    late.SetControl(AppControlField::Request(sequence));
    late.SetIIN(IINField::Empty());
    REQUIRE(late.AppendObjects(original.ToRSeq().skip(2)));
    REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(late.ToRSeq())));
    REQUIRE(pair.master.lower->NumWrites() == 0); // The older CONFIRM still owns TX.
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(pair.master.lower->NumWrites() == 1);
    HexSequence lateChallenge(pair.master.lower->PopWriteAsHex());
    REQUIRE(lateChallenge.ToRSeq()[1] == 0x20);
    REQUIRE(lateChallenge.ToRSeq()[3] == 1);
    MasterResponder latePeer(7, 16, timeout, true);
    REQUIRE(latePeer.SetSessionKey(1, common.MonitoringKey(timeout), common.ValidUntil(), timeout)
        == MasterResponder::Result::OK);
    REQUIRE(latePeer.RetainRequest(7, late.ToRSeq(), timeout) == MasterResponder::Result::OK);
    REQUIRE(latePeer.Respond(7, lateChallenge.ToRSeq(), timeout, wseq_t(reply.data(), reply.size()), size)
        == MasterResponder::Result::OK);
    const auto authenticated = ProductionAuthenticationTestAccess::Stats(*pair.master.context)
        .Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);
    REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(reply.data(), size))));
    pair.master.exe->run_many();
    REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context)
        .Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == authenticated + 1);
    REQUIRE_FALSE(pair.master.context->activeTask);
    REQUIRE(pair.master.context->solSeq.Get() == before);
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(pair.master.lower->NumWrites() == 0);
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
    if (!aggressive && fault == 9)
    {
        // Both sessions have expired. Neither a duplicate Error nor periodic service may
        // start a new V4 before the transmitted Reply releases its ownership.
        REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) == 0);
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::Common(*pair.master.context).IsExchanging());
        REQUIRE(pair.master.SendToMaster(wire));
        pair.master.exe->advance_time(std::chrono::milliseconds(100));
        now += 100;
        pair.master.exe->run_many();
        REQUIRE_FALSE(session.IsExchanging());
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::Common(*pair.master.context).IsExchanging());
        REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) == 0);
        REQUIRE(pair.master.lower->NumWrites() == previousWrites);
        REQUIRE(borrowed.equals(attempt.ToRSeq()));
    }
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
        const auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(
            pair.master.context->params.responseTimeout.value);
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

namespace
{
CommandSet FC6Commands(unsigned type, uint16_t index);
}

TEST_CASE("ProductionAuthentication - Code 7 distinguishes policy denial from OPERATE ownership failure",
          "[production-sa][auth-error][g41-sa-owner]")
{
    const bool aggressive = GENERATE(false, true);
    const bool denyPolicy = GENERATE(false, true);
    const auto selection = GENERATE(0, 1, 2);
    const auto type = GENERATE(0u, 1u, 2u, 3u);
    const bool wide = GENERATE(false, true);
    CAPTURE(aggressive, denyPolicy, selection, type, wide);

    auto observer = std::make_shared<RuntimeErrorObserver>();
    RuntimePair pair(false, aggressive, false, nullptr, false, observer,
                     2, false, 2000, 2000, false,
                     IndexQualifierMode::allow_one_byte);

    pair.Pump();
    pair.outstation.application->SetTime(DNPTime(123456789));

    // Establish genuine authenticated SELECT/OPERATE and session history.
    auto config = TaskConfig::Default();
    config.authenticationUser = 2;
    pair.master.context->SelectAndOperate(
        FC6Commands(type, wide ? 0x1234 : 3),
        pair.results.Callback(), config);
    pair.master.exe->run_many();
    const auto select = pair.master.lower->PopWriteAsHex();
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(select);
    pair.Pump();
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    HexSequence selected(select);
    std::vector<uint8_t> native(static_cast<const uint8_t*>(selected.ToRSeq()),
        static_cast<const uint8_t*>(selected.ToRSeq()) + selected.ToRSeq().length());
    REQUIRE(native.size() >= 5);
    REQUIRE(native[1] == 3);
    REQUIRE(native[2] == (type == 0 ? 12 : 41));
    REQUIRE(native[3] == (type == 0 ? 1 : type));
    REQUIRE(native[4] == (wide ? 0x28 : 0x17));
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

TEST_CASE("ProductionAuthentication - G121 READ and Class 0 project only the authenticated Outstation runtime",
          "[production-sa][security-stat-read]")
{
    const bool classZero = GENERATE(false, true);
    RuntimePair pair;
    pair.Pump();
    auto& statistics = ProductionAuthenticationTestAccess::Stats(pair.outstation.context);
    auto& common = ProductionAuthenticationTestAccess::Common(pair.outstation.context);
    auto& other = ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2);
    const auto before = statistics.Values();
    const auto commonKSQ = common.Sequence(), otherKSQ = other.Sequence();
    const bool failureReport = statistics.ReportPending(SecurityStatistic::AUTHENTICATION_FAILURES);
    const auto failureMax = statistics.Maximum(SecurityStatistic::AUTHENTICATION_FAILURES);
    const std::string original = classZero ? "C9 01 3C 01 06" : "C9 01 79 01 06";
    HexSequence request(original);
    MasterResponder peer(7);
    REQUIRE(peer.SetSessionKey(1, common.ControlKey(0), common.ValidUntil(), 0) == MasterResponder::Result::OK);
    REQUIRE(peer.RetainRequest(7, request.ToRSeq(), 0) == MasterResponder::Result::OK);
    pair.outstation.SendToOutstation(original);
    HexSequence challenge(pair.outstation.lower->PopWriteAsHex());
    REQUIRE(challenge.ToRSeq()[1] == 0x83);
    REQUIRE(challenge.ToRSeq()[5] == 1); // No unauthenticated G121 data release.
    pair.outstation.OnTxReady();
    std::array<uint8_t, 128> reply{};
    size_t size = 0;
    REQUIRE(peer.Respond(7, challenge.ToRSeq(), 0, wseq_t(reply.data(), reply.size()), size) == MasterResponder::Result::OK);
    pair.outstation.SendToOutstation(HexConversions::to_hex(rseq_t(reply.data(), size)));
    HexSequence response(pair.outstation.lower->PopWriteAsHex());
    REQUIRE(response.ToRSeq().length() == 135);
    REQUIRE(response.ToRSeq()[1] == 0x81);
    REQUIRE(response.ToRSeq().skip(4).take(5).equals(HexSequence("79 01 00 00 11").ToRSeq()));
    auto expected = statistics.Values();
    --expected[5]; // The frozen view precedes actual transmission of this RESPONSE.
    auto input = response.ToRSeq().skip(9);
    for (uint16_t index = 0; index < 18; ++index)
    {
        Group121Var1 value;
        REQUIRE(Group121Var1::Read(input, value));
        REQUIRE(value.associationId == 0);
        REQUIRE(value.flags == 0x41);
        REQUIRE(value.value == expected[index]);
    }
    REQUIRE(statistics.Value(SecurityStatistic::TOTAL_MESSAGES_RECEIVED) == before[6] + 2);
    REQUIRE(statistics.Value(SecurityStatistic::TOTAL_MESSAGES_SENT) == before[5] + 2);
    REQUIRE(statistics.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == before[12] + 1);
    REQUIRE(statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 0);
    REQUIRE(statistics.Value(SecurityStatistic::RESTART_REKEYS) == 0);
    REQUIRE(statistics.ReportPending(SecurityStatistic::AUTHENTICATION_FAILURES) == failureReport);
    REQUIRE(statistics.Maximum(SecurityStatistic::AUTHENTICATION_FAILURES) == failureMax);
    REQUIRE(common.Ready(0));
    REQUIRE(other.Ready(0));
    REQUIRE(common.Sequence() == commonKSQ);
    REQUIRE(other.Sequence() == otherKSQ);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("ProductionAuthentication - zero service settles unsent exchanges without recursion", "[sa-zero-runtime]")
{
    // A zero Reply Timer cannot establish ready keys. Keep this coverage separate
    // from the nonzero queued-Reply/CONFIRM boundary tests above.
    RuntimePair pair(false, false, false, nullptr, false, nullptr, 2, false, 0, 0);
    auto& master = pair.master;
    auto& outstation = pair.outstation;
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::Common(*master.context).Ready(0));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*master.context));
    REQUIRE(ProductionAuthenticationTestAccess::Deferred(*master.context) == 0);
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::Common(*master.context).IsExchanging());
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::Session(*master.context, 2).IsExchanging());
    REQUIRE(ProductionAuthenticationTestAccess::Pending(*master.context) == 0);
    REQUIRE(ProductionAuthenticationTestAccess::Stats(*master.context).Value(SecurityStatistic::REPLY_TIMEOUTS) == 1);
    for (size_t n = 0; n < 10; ++n)
    {
        master.exe->advance_time(std::chrono::milliseconds(100));
        master.exe->run_many();
        REQUIRE(master.lower->NumWrites() == 0);
    }
    REQUIRE(master.context->OnLowerLayerDown());
    master.exe->advance_time(std::chrono::milliseconds(100));
    master.exe->run_many();
    REQUIRE(master.lower->NumWrites() == 0);

    REQUIRE_FALSE(ProductionAuthenticationTestAccess::Common(outstation.context).Ready(0));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::Session(outstation.context, 2).Ready(0));
    REQUIRE(ProductionAuthenticationTestAccess::Pending(outstation.context) == 0);
    REQUIRE(outstation.cmdHandler->NumInvocations() == 0);
    outstation.LowerLayerDown();
    REQUIRE_FALSE(outstation.context.OnTxReady());
}

TEST_CASE("ProductionAuthentication - zero service fairly attempts both users with renewal disabled", "[sa-zero-runtime]")
{
    auto source = std::make_shared<RuntimeCredentials>();
    auto policy = std::make_shared<RuntimePolicy>();
    auto params = MasterSettings(source, policy);
    params.authentication.replyTimeoutMs = 0;
    params.authentication.renewalIntervalMs = 0;
    MasterTestFixture master(params, Addresses());
    REQUIRE(master.context->OnLowerLayerUp());
    master.exe->run_many();
    auto& first = ProductionAuthenticationTestAccess::Common(*master.context);
    auto& second = ProductionAuthenticationTestAccess::Session(*master.context, 2);
    REQUIRE_FALSE(first.NeedsExchange(0)); // User 1's expired attempt is in cooldown.
    REQUIRE(second.NeedsExchange(0));
    for (uint64_t tick = 1; tick <= 20; ++tick) // Include application-sequence rollover.
    {
        master.exe->advance_time(std::chrono::milliseconds(100));
        master.exe->run_many();
        const auto now = tick * 100;
        REQUIRE(first.NeedsExchange(now) == (tick % 2 == 1));
        REQUIRE(second.NeedsExchange(now) == (tick % 2 == 0));
        REQUIRE_FALSE(first.IsExchanging());
        REQUIRE_FALSE(second.IsExchanging());
        REQUIRE(ProductionAuthenticationTestAccess::Stats(*master.context)
                    .Value(SecurityStatistic::REPLY_TIMEOUTS) == tick + 1);
        REQUIRE(ProductionAuthenticationTestAccess::Pending(*master.context) == 0);
        REQUIRE(master.lower->NumWrites() == 0);
    }
}

TEST_CASE("ProductionAuthentication - zero V4 continuation expires before V5 TX and rejects valid stale V6", "[sa-zero-runtime]")
{
    auto source = std::make_shared<RuntimeCredentials>();
    auto policy = std::make_shared<RuntimePolicy>();
    auto config = OutSettings(source, policy);
    config.params.authentication.replyTimeoutMs = 0;
    OutstationTestObject out(config);
    out.LowerLayerUp();
    auto& owner = ProductionAuthenticationTestAccess::Session(out.context, 2);
    auto& other = ProductionAuthenticationTestAccess::Common(out.context);
    const auto otherKSQ = other.Sequence();
    SessionKeys::Config peerConfig;
    SessionKeys peer(SessionKeys::Role::MASTER, 7, 2, peerConfig);
    REQUIRE(peer.Configure(rseq_t(source->keys[1].data(), 32), 10000000, 0) == SessionKeys::Result::OK);
    std::array<uint8_t, 2048> request{}, status{}, change{};
    size_t requestSize = 0, statusSize = 0, changeSize = 0;
    REQUIRE(peer.Begin(7, 0, 0, wseq_t(request.data(), request.size()), requestSize) == SessionKeys::Result::OK);
    out.SendToOutstation(HexConversions::to_hex(rseq_t(request.data(), requestSize)));
    REQUIRE(out.lower->NumWrites() == 0);
    REQUIRE(ProductionAuthenticationTestAccess::Pending(out.context) == 0);
    REQUIRE_FALSE(owner.Ready(0));
    // Capture a fresh real core-generated status solely to form a matching,
    // cryptographically valid V6. Runtime receipt must expire its owner first.
    REQUIRE(owner.Process(7, rseq_t(request.data(), requestSize), 0,
                          wseq_t(status.data(), status.size()), statusSize) == SessionKeys::Result::OK);
    REQUIRE(peer.Process(7, rseq_t(status.data(), statusSize), 0,
                         wseq_t(change.data(), change.size()), changeSize) == SessionKeys::Result::OK);
    REQUIRE(changeSize != 0);
    out.SendToOutstation(HexConversions::to_hex(rseq_t(change.data(), changeSize)));
    REQUIRE(out.lower->NumWrites() == 0);
    REQUIRE(ProductionAuthenticationTestAccess::Pending(out.context) == 0);
    REQUIRE_FALSE(owner.Ready(0));
    REQUIRE(owner.ControlKey(0).is_empty());
    REQUIRE(other.Sequence() == otherKSQ);
    REQUIRE_FALSE(other.Ready(0));
    REQUIRE(out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("ProductionAuthentication - simultaneous timed renewal preserves both user budgets", "[production-sa][sa-renewal]")
{
    RuntimePair pair;
    pair.Pump();
    REQUIRE(pair.changes == 2);
    auto& first = ProductionAuthenticationTestAccess::Common(*pair.master.context);
    auto& second = ProductionAuthenticationTestAccess::Session(*pair.master.context, 2);
    auto& outFirst = ProductionAuthenticationTestAccess::Common(pair.outstation.context);
    auto& outSecond = ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2);
    const auto firstKSQ = first.Sequence();
    const auto secondKSQ = second.Sequence();
    const auto firstKey = HexConversions::to_hex(first.ControlKey(0));
    const auto secondKey = HexConversions::to_hex(second.ControlKey(0));
    const auto interval = pair.master.context->params.authentication.renewalIntervalMs;
    const auto budget = pair.master.context->params.authentication.renewalMessageCount;
    REQUIRE(first.ValidUntil() == interval);
    REQUIRE(second.ValidUntil() == interval);
    REQUIRE(first.Ready(interval - 1));
    REQUIRE(second.Ready(interval - 1));
    pair.outstation.AdvanceTime(TimeDuration::Milliseconds(interval));
    pair.master.exe->advance_time(std::chrono::milliseconds(interval));
    pair.master.exe->run_many();
    REQUIRE_FALSE(first.Ready(interval));
    REQUIRE_FALSE(second.Ready(interval));
    REQUIRE_FALSE(outFirst.Ready(interval));
    REQUIRE_FALSE(outSecond.Ready(interval));
    // Exactly four request/response steps: V4/V5 and V6/V5 for each user.
    for (size_t step = 0; step < 4; ++step)
    {
        REQUIRE(pair.master.lower->NumWrites() == 1);
        const auto request = pair.master.lower->PopWriteAsHex();
        HexSequence wire(request);
        REQUIRE(wire.ToRSeq()[2] == 120);
        REQUIRE(wire.ToRSeq()[3] == (step % 2 == 0 ? 4 : 6));
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(request);
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        const auto response = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(response));
        pair.master.exe->run_many();
        if (step == 1)
        {
            REQUIRE(first.Ready(interval));
            REQUIRE(outFirst.Ready(interval));
            REQUIRE_FALSE(second.Ready(interval));
            REQUIRE_FALSE(outSecond.Ready(interval));
            REQUIRE(second.RemainingMessages() == 0);
            REQUIRE(outSecond.RemainingMessages() == 0);
        }
        if (step >= 1)
        {
            REQUIRE(first.RemainingMessages() == budget);
            REQUIRE(outFirst.RemainingMessages() == budget);
        }
    }
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(first.Sequence() != firstKSQ);
    REQUIRE(second.Sequence() != secondKSQ);
    REQUIRE(first.Sequence() == outFirst.Sequence());
    REQUIRE(second.Sequence() == outSecond.Sequence());
    REQUIRE(HexConversions::to_hex(first.ControlKey(interval)) != firstKey);
    REQUIRE(HexConversions::to_hex(second.ControlKey(interval)) != secondKey);
    REQUIRE(first.ControlKey(interval).equals(outFirst.ControlKey(interval)));
    REQUIRE(second.ControlKey(interval).equals(outSecond.ControlKey(interval)));
    REQUIRE(second.RemainingMessages() == budget);
    REQUIRE(outSecond.RemainingMessages() == budget);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
}

namespace
{
struct MACPolicySessionSnapshot
{
    uint32_t sequence, remaining;
    bool ready, exchanging;
    std::array<uint8_t, 32> control{}, monitoring{};
    MACPolicySessionSnapshot(SessionKeys& session, uint64_t now)
        : sequence(session.Sequence()), remaining(session.RemainingMessages()),
          ready(session.Ready(now)), exchanging(session.IsExchanging())
    {
        REQUIRE(ready);
        const auto c = session.ControlKey(now), m = session.MonitoringKey(now);
        REQUIRE(c.length() == control.size());
        REQUIRE(m.length() == monitoring.size());
        std::copy(static_cast<const uint8_t*>(c), static_cast<const uint8_t*>(c) + c.length(), control.begin());
        std::copy(static_cast<const uint8_t*>(m), static_cast<const uint8_t*>(m) + m.length(), monitoring.begin());
    }
    ~MACPolicySessionSnapshot()
    {
        crypto::Clear(wseq_t(control.data(), control.size()));
        crypto::Clear(wseq_t(monitoring.data(), monitoring.size()));
    }
    void Check(SessionKeys& session, uint64_t now) const
    {
        REQUIRE(session.Sequence() == sequence);
        REQUIRE(session.Ready(now) == ready);
        REQUIRE(session.IsExchanging() == exchanging);
        REQUIRE(session.RemainingMessages() == remaining);
        REQUIRE(crypto::ConstantTimeEqual(session.ControlKey(now), rseq_t(control.data(), control.size())));
        REQUIRE(crypto::ConstantTimeEqual(session.MonitoringKey(now), rseq_t(monitoring.data(), monitoring.size())));
    }
};

std::string UnsupportedMACChallenge(const std::string& original, bool response, uint8_t algorithm)
{
    HexSequence wire(original);
    const size_t prefix = response ? 10 : 8;
    REQUIRE(wire.ToRSeq().length() > prefix + 8);
    REQUIRE(wire.ToRSeq()[1] == (response ? 0x83 : 0x20));
    REQUIRE(wire.ToRSeq()[prefix - 6] == 120);
    REQUIRE(wire.ToRSeq()[prefix - 5] == 1);
    REQUIRE(wire.ToRSeq()[prefix - 4] == 0x5B);
    Group120Var1 before;
    REQUIRE(before.Read(wire.ToRSeq().skip(prefix)));
    REQUIRE(before.macAlgorithm == 4);
    REQUIRE(before.reason == 1);
    std::vector<uint8_t> bytes(static_cast<const uint8_t*>(wire.ToRSeq()),
                              static_cast<const uint8_t*>(wire.ToRSeq()) + wire.ToRSeq().length());
    bytes[prefix + 6] = algorithm; // CSQ and USR precede MAL in A.45.1.
    Group120Var1 after;
    REQUIRE(after.Read(rseq_t(bytes.data(), bytes.size()).skip(prefix)));
    REQUIRE(after.seqNum == before.seqNum);
    REQUIRE(after.userNum == before.userNum);
    REQUIRE(after.reason == before.reason);
    REQUIRE(after.challengeData.equals(before.challengeData));
    REQUIRE(after.macAlgorithm == algorithm);
    return HexConversions::to_hex(rseq_t(bytes.data(), bytes.size()));
}
} // namespace

TEST_CASE("ProductionAuthentication - unsupported control MAC drops silently without cancelling independent monitoring",
          "[production-sa][sa-v06-mac-policy]")
{
    // 2 is implemented legacy HMAC-SHA1 but disallowed by default; 6 is unsupported GMAC.
    const uint8_t algorithm = GENERATE(uint8_t(2), uint8_t(6));
    CAPTURE(algorithm);
    auto observer = std::make_shared<RuntimeErrorObserver>();
    RuntimePair pair(false, false, false, nullptr, false, observer);
    pair.Pump();
    pair.SelectOperate();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto request = pair.master.lower->PopWriteAsHex();
    HexSequence original(request);
    pair.outstation.SendToOutstation(request); // Keep SELECT's Master TX buffer borrowed.
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto challenge = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster("F0 82 00 00")); // Independent Common-user monitoring exchange.
    pair.master.exe->run_many();
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    const auto pendingSize = ProductionAuthenticationTestAccess::Pending(*pair.master.context);
    REQUIRE(pendingSize != 0);
    const auto pending = HexConversions::to_hex(ProductionAuthenticationTestAccess::PendingBytes(*pair.master.context).take(pendingSize));
    MACPolicySessionSnapshot common(ProductionAuthenticationTestAccess::Common(*pair.master.context), 0);
    MACPolicySessionSnapshot control(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2), 0);
    const auto before = ProductionAuthenticationTestAccess::Stats(*pair.master.context).Values();
    const auto sequence = pair.master.context->solSeq.Get();
    REQUIRE(pair.master.SendToMaster(UnsupportedMACChallenge(challenge, true, algorithm)));
    pair.master.exe->run_many();
    // Actual runtime TX queue: neither an authentication Reply nor Code 5/7 was emitted.
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyIssued(*pair.master.context));
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    REQUIRE(observer->sent == 0);
    REQUIRE(observer->denied == 0);
    auto& statistics = ProductionAuthenticationTestAccess::Stats(*pair.master.context);
    REQUIRE(statistics.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == before[0] + 1);
    REQUIRE(statistics.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == before[12]);
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == before[13]);
    REQUIRE(statistics.Value(SecurityStatistic::ERROR_MESSAGES_SENT) == before[10]);
    REQUIRE(statistics.Value(SecurityStatistic::AUTHORIZATION_FAILURES) == before[1]);
    REQUIRE(pair.master.context->isSending);
    REQUIRE(pair.master.context->txBuffer.as_rslice().take(original.ToRSeq().length()).equals(original.ToRSeq()));
    // Regression: unsupported control MAC must settle only its responder owner.
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) == pendingSize);
    REQUIRE(HexConversions::to_hex(ProductionAuthenticationTestAccess::PendingBytes(*pair.master.context).take(pendingSize)) == pending);
    common.Check(ProductionAuthenticationTestAccess::Common(*pair.master.context), 0);
    control.Check(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2), 0);
    REQUIRE_FALSE(pair.master.context->activeTask);
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    REQUIRE(pair.master.context->solSeq.Get() == ((sequence + 1) & 0x0F));
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(pair.master.lower->NumWrites() == 1);
    REQUIRE(pair.master.lower->PopWriteAsHex() == pending); // The independent Challenge survives TX completion.
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(pair.master.lower->NumWrites() == 0); // No retry of the rejected SELECT or authenticated OPERATE.
    REQUIRE(pair.results.values.size() == 1);
}

TEST_CASE("ProductionAuthentication - unsupported monitoring MAC drops silently without cancelling independent control",
          "[production-sa][sa-v06-mac-policy]")
{
    const uint8_t algorithm = GENERATE(uint8_t(2), uint8_t(6));
    CAPTURE(algorithm);
    auto observer = std::make_shared<RuntimeErrorObserver>();
    RuntimePair pair(true, false, false, nullptr, false, observer, 2, false, 10000, 10000, true);
    pair.Pump();
    const auto masterNow = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        pair.master.exe->get_time().time_since_epoch()).count());
    REQUIRE(ProductionAuthenticationTestAccess::Session(*pair.master.context, 1).IsReady(masterNow));
    REQUIRE(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2).IsReady(masterNow));
    REQUIRE(ProductionAuthenticationTestAccess::SessionReady(pair.outstation.context, 1));
    REQUIRE(ProductionAuthenticationTestAccess::SessionReady(pair.outstation.context, 2));
    // LowerLayerUp entered native UnsolicitedConfirmWait before keys existed:
    // BeginTx suppressed that null response. Pump completes V4/V5/V6/V5 for
    // both users, but cannot fire the Outstation's native confirmation timer.
    CAPTURE(ProductionAuthenticationTestAccess::NativeState(pair.outstation.context));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::IsIdle(pair.outstation.context));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::StartupNullConfirmed(pair.outstation.context));
    REQUIRE(ProductionAuthenticationTestAccess::ResponderState(*pair.master.context)
        == MasterResponder::State::NO_SESSION_KEYS); // No critical request retained yet.
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.NumPendingTimers() == 1); // Native null-confirm timeout.
    // Advance the timer's owning executor exactly once, as in the existing
    // embedded-confirm fixture. The retry and its two SA exchanges are genuine.
    pair.outstation.AdvanceTime(OutSettings(pair.source, pair.policy, true).params.unsolConfirmTimeout);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    pair.Pump();
    // Individual assertions identify every startup owner instead of short-circuiting
    // startupSettled(). The recurring Master service timer is expected to remain.
    CAPTURE(masterNow, ProductionAuthenticationTestAccess::Now(pair.outstation.context),
            ProductionAuthenticationTestAccess::ServiceDeadline(*pair.master.context),
            pair.master.exe->num_pending_timers(), pair.outstation.NumPendingTimers());
    REQUIRE(ProductionAuthenticationTestAccess::ServiceDeadline(*pair.master.context)
        > static_cast<int64_t>(masterNow));
    REQUIRE(pair.outstation.NumPendingTimers() == 0);
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE_FALSE(pair.master.context->isSending);
    REQUIRE_FALSE(pair.master.context->activeTask);
    REQUIRE(pair.master.context->tstate == MContext::TaskState::IDLE);
    REQUIRE(pair.master.context->confirmQueue.empty());
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ProtectedConfirm(*pair.master.context));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyInFlight(*pair.master.context));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::WireInFlight(*pair.master.context));
    REQUIRE(ProductionAuthenticationTestAccess::ResponderState(*pair.master.context) == MasterResponder::State::IDLE);
    REQUIRE(ProductionAuthenticationTestAccess::Pending(*pair.master.context) == 0);
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    REQUIRE(ProductionAuthenticationTestAccess::IsIdle(pair.outstation.context));
    REQUIRE(ProductionAuthenticationTestAccess::StartupNullConfirmed(pair.outstation.context));
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringResponderState(pair.outstation.context)
        == MasterResponder::State::IDLE);
    REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(pair.outstation.context)
        == OutstationChallenger::State::IDLE);
    REQUIRE(ProductionAuthenticationTestAccess::Pending(pair.outstation.context) == 0);
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::MonitoringPending(pair.outstation.context));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::Transmitting(pair.outstation.context));
    pair.SelectOperate();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto request = pair.master.lower->PopWriteAsHex();
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(request);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto controlChallenge = pair.outstation.lower->PopWriteAsHex();
    HexSequence controlChallengePacket(controlChallenge);
    REQUIRE(controlChallengePacket.ToRSeq()[1] == 0x83);
    REQUIRE(controlChallengePacket.ToRSeq()[4] == 120);
    REQUIRE(controlChallengePacket.ToRSeq()[5] == 1);
    Group120Var1 controlChallengeValue;
    REQUIRE(controlChallengeValue.Read(controlChallengePacket.ToRSeq().skip(10)));
    // IEEE A.45.1.2.2: the Outstation does not know the responding user yet.
    REQUIRE(controlChallengeValue.userNum == 0);
    HexSequence held(controlChallenge);
    REQUIRE(ProductionAuthenticationTestAccess::ChallengeBytes(pair.outstation.context)
        .take(held.ToRSeq().length()).equals(held.ToRSeq()));
    pair.outstation.OnTxReady(); // The Challenger owns the pending request after TX completes.
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::Transmitting(pair.outstation.context));
    REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(pair.outstation.context)
        == OutstationChallenger::State::WAITING_FOR_REPLY);
    REQUIRE(pair.master.SendToMaster(controlChallenge));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto controlReply = pair.master.lower->PopWriteAsHex();
    HexSequence controlReplyPacket(controlReply);
    REQUIRE(controlReplyPacket.ToRSeq()[1] == 0x20);
    REQUIRE(controlReplyPacket.ToRSeq()[2] == 120);
    REQUIRE(controlReplyPacket.ToRSeq()[3] == 2);
    Group120Var2 controlReplyValue;
    REQUIRE(controlReplyValue.Read(controlReplyPacket.ToRSeq().skip(8)));
    REQUIRE(controlReplyValue.userNum == 2);
    REQUIRE(controlReplyValue.seqNum == controlChallengeValue.seqNum);
    REQUIRE((controlReplyPacket.ToRSeq()[0] & 0x0F) == (controlChallengePacket.ToRSeq()[0] & 0x0F));
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(ProductionAuthenticationTestAccess::ReplyIssued(*pair.master.context));
    REQUIRE(pair.master.context->activeTask);
    REQUIRE(pair.master.context->tstate == MContext::TaskState::WAIT_FOR_RESPONSE);

    // The native state is idle even while the independent SA Challenger waits.
    // CheckForUnsolicited can therefore emit a new event after Challenge TX ends.
    REQUIRE(ProductionAuthenticationTestAccess::IsIdle(pair.outstation.context));
    pair.outstation.Transaction([](IUpdateHandler& update) { update.Update(Binary(true), 0); });
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto response = pair.outstation.lower->PopWriteAsHex();
    HexSequence eventResponse(response);
    REQUIRE(eventResponse.ToRSeq()[1] == 0x82);
    REQUIRE((eventResponse.ToRSeq()[0] & 0x30) == 0x30);
    REQUIRE(eventResponse.ToRSeq()[4] == 2);
    pair.outstation.OnTxReady();
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::Transmitting(pair.outstation.context));
    REQUIRE(pair.master.SendToMaster(response));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto monitoringChallenge = pair.master.lower->PopWriteAsHex();
    HexSequence monitoringChallengePacket(monitoringChallenge);
    REQUIRE(monitoringChallengePacket.ToRSeq()[1] == 0x20);
    REQUIRE(monitoringChallengePacket.ToRSeq()[2] == 120);
    REQUIRE(monitoringChallengePacket.ToRSeq()[3] == 1);
    Group120Var1 monitoringChallengeValue;
    REQUIRE(monitoringChallengeValue.Read(monitoringChallengePacket.ToRSeq().skip(8)));
    REQUIRE(monitoringChallengeValue.userNum == 1);
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringPending(pair.outstation.context));
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringResponderState(pair.outstation.context)
        == MasterResponder::State::WAITING_FOR_CHALLENGE);
    // Respond() cleared user 2's retained request when it produced controlReply.
    // The monitoring Challenger owns the event; no native CONFIRM is issued yet.
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    REQUIRE(ProductionAuthenticationTestAccess::ResponderState(*pair.master.context)
        == MasterResponder::State::IDLE);
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ProtectedConfirm(*pair.master.context));
    REQUIRE(pair.master.context->confirmQueue.empty());
    const auto owner = ProductionAuthenticationTestAccess::ChallengeState(pair.outstation.context);
    REQUIRE(owner == OutstationChallenger::State::WAITING_FOR_REPLY);
    const auto now = ProductionAuthenticationTestAccess::Now(pair.outstation.context);
    REQUIRE(now < 10000); // Both user-2's Reply and the session keys are still within their lifetimes.
    MACPolicySessionSnapshot common(ProductionAuthenticationTestAccess::Common(pair.outstation.context), now);
    MACPolicySessionSnapshot control(ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2), now);
    const auto before = ProductionAuthenticationTestAccess::Stats(pair.outstation.context).Values();
    pair.outstation.SendToOutstation(UnsupportedMACChallenge(monitoringChallenge, false, algorithm));
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(ProductionAuthenticationTestAccess::Pending(pair.outstation.context) == 0);
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::MonitoringPending(pair.outstation.context));
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringResponderState(pair.outstation.context)
        == MasterResponder::State::NO_SESSION_KEYS);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    REQUIRE(observer->sent == 0);
    REQUIRE(observer->denied == 0);
    auto& statistics = ProductionAuthenticationTestAccess::Stats(pair.outstation.context);
    REQUIRE(statistics.Value(SecurityStatistic::UNEXPECTED_MESSAGES) == before[0] + 1);
    REQUIRE(statistics.Value(SecurityStatistic::DISCARDED_MESSAGES)
        == before[static_cast<size_t>(SecurityStatistic::DISCARDED_MESSAGES)] + 1);
    REQUIRE(statistics.Value(SecurityStatistic::AUTHENTICATION_FAILURES)
        == before[static_cast<size_t>(SecurityStatistic::AUTHENTICATION_FAILURES)]);
    REQUIRE(statistics.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == before[12]);
    REQUIRE(statistics.Value(SecurityStatistic::SESSION_KEY_CHANGES) == before[13]);
    REQUIRE(statistics.Value(SecurityStatistic::ERROR_MESSAGES_SENT) == before[10]);
    REQUIRE(statistics.Value(SecurityStatistic::AUTHORIZATION_FAILURES) == before[1]);
    // Regression: resetting the monitoring responder must not reset user 2's Challenger.
    REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(pair.outstation.context) == owner);
    common.Check(ProductionAuthenticationTestAccess::Common(pair.outstation.context), now);
    control.Check(ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2), now);
    // The preserved Control Challenge can still complete using its original, genuine Reply.
    pair.outstation.SendToOutstation(controlReply);
    REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(pair.outstation.context)
        == OutstationChallenger::State::IDLE);
    REQUIRE(statistics.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == before[12] + 1);
    REQUIRE(ProductionAuthenticationTestAccess::AcceptedChallenge(pair.outstation.context).equals(held.ToRSeq()));
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == 1); // Released through authorization and native SELECT.
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
    REQUIRE(observer->denied == 0);
}

TEST_CASE("ProductionAuthentication - unsupported MAC settles only its native CONFIRM responder",
          "[production-sa][sa-v06-mac-policy]")
{
    const uint8_t algorithm = GENERATE(uint8_t(2), uint8_t(6));
    CAPTURE(algorithm);
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
    REQUIRE(pair.master.SendToMaster(verified));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto confirmation = pair.master.lower->PopWriteAsHex();
    HexSequence borrowed(confirmation);
    REQUIRE(borrowed.ToRSeq().length() == 2);
    REQUIRE(borrowed.ToRSeq()[1] == 0);
    REQUIRE(ProductionAuthenticationTestAccess::ProtectedConfirm(*pair.master.context));
    pair.outstation.SendToOutstation(confirmation); // Keep the Master CONFIRM buffer borrowed.
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto challenge = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    MACPolicySessionSnapshot control(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2), 0);
    const auto sequence = pair.master.context->solSeq.Get();
    REQUIRE(pair.master.SendToMaster(UnsupportedMACChallenge(challenge, true, algorithm)));
    pair.master.exe->run_many();
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ProtectedConfirm(*pair.master.context));
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
    REQUIRE(ProductionAuthenticationTestAccess::Deferred(*pair.master.context) == 0);
    REQUIRE(pair.master.context->confirmQueue.empty());
    REQUIRE(pair.master.context->solSeq.Get() == sequence); // A CONFIRM is not a solicited task.
    REQUIRE(pair.master.context->isSending);
    REQUIRE(pair.master.context->txBuffer.as_rslice().take(borrowed.ToRSeq().length()).equals(borrowed.ToRSeq()));
    REQUIRE(pair.master.lower->NumWrites() == 0);
    control.Check(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2), 0);
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(pair.master.lower->NumWrites() == 0); // No Reply, Error, or retry of the abandoned CONFIRM.
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
}


namespace
{
CommandSet FC6Commands(unsigned type, uint16_t index)
{
    switch (type)
    {
    case 0: return CommandSet({WithIndex(ControlRelayOutputBlock(OperationType::LATCH_ON), index)});
    case 1: return CommandSet({WithIndex(AnalogOutputInt32(100), index)});
    case 2: return CommandSet({WithIndex(AnalogOutputInt16(-23), index)});
    default: return CommandSet({WithIndex(AnalogOutputFloat32(6.75f), index)});
    }
}
std::string SubmitFC6(RuntimePair& pair, unsigned type = 0, uint16_t index = 3, uint16_t user = 2)
{
    auto config = TaskConfig::Default();
    config.authenticationUser = user;
    REQUIRE(pair.master.context->DirectOperateNoAck(FC6Commands(type, index), pair.results.Callback(), config));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    auto request = pair.master.lower->PopWriteAsHex();
    HexSequence packet(request);
    REQUIRE(packet.ToRSeq()[1] == 6);
    REQUIRE(pair.results.values.empty());
    return request;
}
std::string ChallengeFC6(RuntimePair& pair, const std::string& request)
{
    pair.outstation.SendToOutstation(request);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto challenge = pair.outstation.lower->PopWriteAsHex();
    HexSequence packet(challenge);
    REQUIRE(packet.ToRSeq()[1] == 0x83);
    REQUIRE(packet.ToRSeq()[4] == 120);
    REQUIRE(packet.ToRSeq()[5] == 1);
    pair.outstation.OnTxReady();
    return challenge;
}
std::string ReplyFC6(RuntimePair& pair, const std::string& challenge)
{
    REQUIRE(pair.master.SendToMaster(challenge));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto reply = pair.master.lower->PopWriteAsHex();
    HexSequence packet(reply);
    REQUIRE(packet.ToRSeq()[1] == 0x20);
    REQUIRE(packet.ToRSeq()[2] == 120);
    REQUIRE(packet.ToRSeq()[3] == 2);
    REQUIRE(pair.results.values.empty());
    return reply;
}
void RequireLocalFC6Result(RuntimePair& pair, TaskCompletion completion)
{
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == completion);
    REQUIRE(pair.results.values.front().results.size() == 1);
    REQUIRE(pair.results.values.front().results.front().status == CommandStatus::UNDEFINED);
}
// Authentication Errors may diagnose a denial; FC6 never emits a normal command response.
void RequireOnlyAuthenticationErrors(RuntimePair& pair)
{
    while (pair.outstation.lower->NumWrites())
    {
        HexSequence packet(pair.outstation.lower->PopWriteAsHex());
        REQUIRE(packet.ToRSeq().length() >= 6);
        REQUIRE(packet.ToRSeq()[1] == 0x83);
        REQUIRE(packet.ToRSeq()[4] == 120);
        REQUIRE(packet.ToRSeq()[5] == 7);
        pair.outstation.OnTxReady();
    }
}
}

TEST_CASE("AT-CFG-08-NOACK", "[rtu-acceptance][production-sa][sa-fc6][profile-controls]")
{
    const auto type = GENERATE(0u, 1u, 2u, 3u, 4u);
    if (type == 4) // Compatibility uses the same native FC6 path without an SA envelope.
    {
        if (!acceptance::Selected("V25")) return;
        MasterTestFixture master(NoStartupTasks(), Addresses());
        OutstationTestObject outstation(OutstationConfig{});
        CommandCallbackQueue results;
        REQUIRE(master.context->OnLowerLayerUp());
        outstation.LowerLayerUp();
        master.context->solSeq = 15;
        REQUIRE(master.context->DirectOperateNoAck(FC6Commands(0, 3), results.Callback(), TaskConfig::Default()));
        master.exe->run_many();
        const auto request = master.lower->PopWriteAsHex();
        REQUIRE(request.substr(0, 8) == "CF 06 0C");
        REQUIRE(results.values.empty());
        outstation.SendToOutstation(request);
        REQUIRE(outstation.cmdHandler->NumOperate() == 1);
        REQUIRE(outstation.lower->HasNoData());
        acceptance::Observe("accepted_actuations", outstation.cmdHandler->NumOperate());
        acceptance::Observe("ordinary_responses", outstation.lower->NumWrites());
        REQUIRE(master.context->OnTxReady());
        master.exe->run_many();
        REQUIRE(results.values.size() == 1);
        REQUIRE(results.values.front().summary == TaskCompletion::SUCCESS);
        REQUIRE(results.values.front().results.front().status == CommandStatus::UNDEFINED);
        REQUIRE(master.context->solSeq.Get() == 0);
        acceptance::Observe("next_sequence", master.context->solSeq.Get());
        master.exe->advance_time(master.context->params.responseTimeout.value);
        master.exe->run_many();
        REQUIRE(master.lower->HasNoData());

        master.context->SelectAndOperate(FC6Commands(0, 3), results.Callback(), TaskConfig::Default());
        master.exe->run_many();
        for (const auto* prefix : {"C0 03", "C1 04"})
        {
            const auto control = master.lower->PopWriteAsHex();
            REQUIRE(control.substr(0, 5) == prefix);
            REQUIRE(master.context->OnTxReady());
            outstation.SendToOutstation(control);
            REQUIRE(master.SendToMaster(outstation.lower->PopWriteAsHex()));
            outstation.OnTxReady();
        }
        REQUIRE(outstation.cmdHandler->NumOperate() == 2);
        acceptance::Observe("actuations_after_next_sbo", outstation.cmdHandler->NumOperate());
        return;
    }

    const bool wide = GENERATE(false, true);
    const bool aggressive = GENERATE(false, true);
    const bool earlyChallenge = !aggressive ? GENERATE(false, true) : false;
    const auto vector = 1 + type * 6 + (wide ? 3 : 0) + (aggressive ? 2 : earlyChallenge ? 1 : 0);
    if (!acceptance::Selected(("V" + std::to_string(vector)).c_str())) return;
    CAPTURE(type, wide, aggressive, earlyChallenge);
    RuntimePair pair(false, aggressive, false, nullptr, false, nullptr, 2, false, 2000, 2000, false,
                     IndexQualifierMode::allow_one_byte);
    pair.Pump();
    if (aggressive)
    {
        pair.SelectOperate();
        pair.Pump(); // Genuine Challenge/Reply establishes Aggressive eligibility.
        pair.results.values.clear();
    }
    const auto operations = pair.outstation.cmdHandler->NumOperate();
    pair.master.context->solSeq = 15; // Wire boundary, not fabricated authentication state.
    const auto request = SubmitFC6(pair, type, wide ? 0x1234 : 3);
    HexSequence original(request);
    const size_t commandOffset = aggressive ? 12 : 2;
    REQUIRE(original.ToRSeq()[commandOffset] == (type == 0 ? 12 : 41));
    REQUIRE(original.ToRSeq()[commandOffset + 1] == (type == 0 ? 1 : type));
    REQUIRE(original.ToRSeq()[commandOffset + 2] == (wide ? 0x28 : 0x17));
    REQUIRE((original.ToRSeq()[0] & 15) == 15);
    std::string protectedWire = request;
    if (!aggressive)
    {
        if (!earlyChallenge)
        {
            REQUIRE(pair.master.context->OnTxReady());
            REQUIRE(pair.master.context->tstate == MContext::TaskState::WAIT_FOR_AUTH_CHALLENGE);
        }
        const auto challenge = ChallengeFC6(pair, request);
        if (earlyChallenge)
        {
            REQUIRE(pair.master.SendToMaster(challenge));
            pair.master.exe->run_many();
            REQUIRE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
            REQUIRE(pair.master.lower->NumWrites() == 0);
            REQUIRE(pair.master.context->txBuffer.as_rslice().take(original.ToRSeq().length()).equals(original.ToRSeq()));
            REQUIRE(pair.master.context->OnTxReady());
            REQUIRE(pair.master.lower->NumWrites() == 1);
            protectedWire = pair.master.lower->PopWriteAsHex();
        }
        else protectedWire = ReplyFC6(pair, challenge);
        REQUIRE(pair.master.context->tstate == MContext::TaskState::WAIT_FOR_AUTH_REPLY_TX);
    }
    else
    {
        REQUIRE(original.ToRSeq()[2] == 120);
        REQUIRE(original.ToRSeq()[3] == 3);
        REQUIRE(pair.master.context->tstate == MContext::TaskState::WAIT_FOR_AGGRESSIVE_TX);
    }
    // Even a same-SEQ response carrying restart IIN cannot acknowledge FC6 or reset its owner.
    const std::array<uint8_t, 4> unrelated{{original.ToRSeq()[0], 0x81, 0x80, 0}};
    REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(unrelated.data(), unrelated.size()))));
    REQUIRE(pair.results.values.empty());
    pair.outstation.SendToOutstation(protectedWire);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations + 1);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    // Normal Reply is consumed once; Aggressive CSQ rejects an identical replay.
    pair.outstation.SendToOutstation(protectedWire);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations + 1);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    acceptance::Observe("accepted_actuations", pair.outstation.cmdHandler->NumOperate() - operations);
    acceptance::Observe("ordinary_responses", pair.outstation.lower->NumWrites());
    REQUIRE(pair.results.values.empty());
    REQUIRE(pair.master.context->OnTxReady());
    RequireLocalFC6Result(pair, TaskCompletion::SUCCESS);
    REQUIRE(pair.master.context->solSeq.Get() == 0);
    acceptance::Observe("next_sequence", pair.master.context->solSeq.Get());
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE_FALSE(pair.master.context->activeTask);
    pair.master.exe->advance_time(std::chrono::milliseconds(2000));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 0); // No FC6 application retry.
    RequireLocalFC6Result(pair, TaskCompletion::SUCCESS);
    pair.SelectOperate();
    pair.Pump(); // Existing FC3/4 still operate after FC6 sequence wrap and responder release.
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations + 2);
    acceptance::Observe("actuations_after_next_sbo", pair.outstation.cmdHandler->NumOperate() - operations);
}

TEST_CASE("ProductionAuthentication - FC6 rejects invalid or unauthorized protected traffic without execution",
          "[production-sa][sa-fc6]")
{
    const bool aggressive = GENERATE(false, true);
    const auto type = GENERATE(0u, 1u, 2u, 3u);
    const bool wide = GENERATE(false, true);
    // MAC, unknown user, foreign association, expired receiving keys, denied control role,
    // genuine common-user MAC with a role that cannot issue FC6.
    const auto fault = GENERATE(0, 1, 2, 3, 4, 5);
    CAPTURE(aggressive, type, wide, fault);
    RuntimePair pair(false, aggressive, false, nullptr, false, nullptr, 2, false, 2000, 2000, false,
                     IndexQualifierMode::allow_one_byte);
    pair.Pump();
    if (aggressive)
    {
        pair.SelectOperate(); pair.Pump();
        if (fault == 5)
        {
            auto config = TaskConfig::Default(); config.authenticationUser = 1;
            pair.master.context->ScanClasses(ClassField::AllClasses(), pair.master.meas, config);
            pair.master.exe->run_many(); pair.Pump(); // Genuine common-user Challenge history.
        }
        pair.results.values.clear();
    }
    const auto operations = pair.outstation.cmdHandler->NumOperate();
    const auto selects = pair.outstation.cmdHandler->NumSelect();
    const auto request = SubmitFC6(pair, type, wide ? 0x1234 : 3, fault == 5 ? 1 : 2);
    std::string protectedWire = request;
    if (!aggressive)
    {
        REQUIRE(pair.master.context->OnTxReady());
        // The prime is Aggressive-only, so the normal Challenger has no dispatched commands.
        protectedWire = ReplyFC6(pair, ChallengeFC6(pair, request));
    }
    HexSequence packet(protectedWire);
    std::vector<uint8_t> bytes(static_cast<const uint8_t*>(packet.ToRSeq()),
                               static_cast<const uint8_t*>(packet.ToRSeq()) + packet.ToRSeq().length());
    if (fault == 0) bytes.back() ^= 1;
    if (fault == 1)
    {
        const size_t userOffset = aggressive ? 10 : 12;
        bytes[userOffset] = 99; bytes[userOffset + 1] = 0;
    }
    if (fault == 3)
    {
        const auto expiry = ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2).ValidUntil();
        pair.outstation.AdvanceTime(TimeDuration::Milliseconds(expiry - ProductionAuthenticationTestAccess::Now(pair.outstation.context)));
    }
    if (fault == 4) pair.policy->allowControl = false;
    const rseq_t wire(bytes.data(), bytes.size());
    if (fault == 2) ProductionAuthenticationTestAccess::ReceiveOtherAssociation(pair.outstation.context, wire);
    else pair.outstation.SendToOutstation(HexConversions::to_hex(wire));
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == selects);
    RequireOnlyAuthenticationErrors(pair);
    REQUIRE(pair.master.context->OnTxReady());
    // A completed local MAC transmission cannot establish whether the receiver executed it.
    RequireLocalFC6Result(pair, TaskCompletion::SUCCESS);
}

TEST_CASE("ProductionAuthentication - disconnect while waiting for G41 OPERATE Reply discards the exchange",
          "[production-sa][g41-sa-disconnect-pending-reply]")
{
    const auto variation = GENERATE(1u, 2u, 3u);
    const bool wide = GENERATE(false, true);
    CAPTURE(variation, wide);

    const uint16_t index = wide ? 0x1234 : 3;

    RuntimePair pair(false, false, false, nullptr, false, nullptr, 2,
                     false, 2000, 2000, false,
                     IndexQualifierMode::allow_one_byte);

    pair.Pump();
    REQUIRE(pair.changes == 2);

    const auto now =
        ProductionAuthenticationTestAccess::Now(pair.outstation.context);

    auto& session =
        ProductionAuthenticationTestAccess::Session(*pair.master.context, 2);

    const MACPolicySessionSnapshot oldSession(session, now);

    auto config = TaskConfig::Default();
    config.authenticationUser = 2;

    const auto submitSbo = [&]() {
        pair.master.context->SelectAndOperate(
            FC6Commands(variation, index),
            pair.results.Callback(),
            config);

        pair.master.exe->run_many();
    };

    submitSbo();

    REQUIRE(pair.master.lower->NumWrites() == 1);

    const auto selectWire = pair.master.lower->PopWriteAsHex();
    HexSequence selectPacket(selectWire);
    const auto select = selectPacket.ToRSeq();

    REQUIRE(select.length() > 5);
    REQUIRE(select[1] == 3);
    REQUIRE(select[2] == 41);
    REQUIRE(select[3] == variation);
    REQUIRE(select[4] == (wide ? 0x28 : 0x17));
    REQUIRE(select[select.length() - 1] == 0);

    REQUIRE(pair.master.context->OnTxReady());

    // Genuine SELECT Challenge and user-2 Reply.
    const auto selectChallenge = ChallengeFC6(pair, selectWire);
    const auto selectReply = ReplyFC6(pair, selectChallenge);

    HexSequence selectReplyPacket(selectReply);
    Group120Var2 selectedUser;

    REQUIRE(selectedUser.Read(selectReplyPacket.ToRSeq().skip(8)));
    REQUIRE(selectedUser.userNum == 2);

    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(selectReply);

    REQUIRE(pair.outstation.cmdHandler->NumSelect() == 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);

    // Authenticate the SELECT response so Master can issue OPERATE.
    REQUIRE(pair.outstation.lower->NumWrites() == 1);

    const auto selectResponseWire =
        pair.outstation.lower->PopWriteAsHex();

    HexSequence selectResponsePacket(selectResponseWire);
    const auto selectResponse = selectResponsePacket.ToRSeq();

    REQUIRE(selectResponse.length() >= 4);
    REQUIRE(selectResponse[1] == 0x81);
    REQUIRE((selectResponse[0] & 0x0F) == (select[0] & 0x0F));
    REQUIRE(selectResponse.skip(4).equals(select.skip(2)));

    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(selectResponseWire));
    pair.master.exe->run_many();

    REQUIRE(pair.master.lower->NumWrites() == 1);

    const auto monitoringChallenge =
        pair.master.lower->PopWriteAsHex();

    HexSequence monitoringPacket(monitoringChallenge);

    REQUIRE(monitoringPacket.ToRSeq().length() >= 4);
    REQUIRE(monitoringPacket.ToRSeq()[1] == 0x20);
    REQUIRE(monitoringPacket.ToRSeq()[2] == 120);
    REQUIRE(monitoringPacket.ToRSeq()[3] == 1);

    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(monitoringChallenge);

    REQUIRE(pair.outstation.lower->NumWrites() == 1);

    const auto monitoringReply =
        pair.outstation.lower->PopWriteAsHex();

    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(monitoringReply));
    pair.master.exe->run_many();

    // Deliver matching native OPERATE.
    REQUIRE(pair.master.lower->NumWrites() == 1);

    const auto operateWire = pair.master.lower->PopWriteAsHex();
    HexSequence operatePacket(operateWire);
    const auto operate = operatePacket.ToRSeq();

    REQUIRE(operate.length() > 5);
    REQUIRE(operate[1] == 4);

    const auto operateSequence =
        ((select[0] & 0x0F) + 1) & 0x0F;

    REQUIRE((operate[0] & 0x0F) == operateSequence);
    REQUIRE(operate.skip(2).equals(select.skip(2)));

    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(operateWire);

    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);

    // Outstation issues a genuine G120V1 Control Challenge.
    REQUIRE(pair.outstation.lower->NumWrites() == 1);

    const auto operateChallengeWire =
        pair.outstation.lower->PopWriteAsHex();

    HexSequence operateChallengePacket(operateChallengeWire);
    const auto challenge = operateChallengePacket.ToRSeq();

    REQUIRE(challenge.length() >= 10);
    REQUIRE(challenge[1] == 0x83);
    REQUIRE((challenge[0] & 0x0F) == operateSequence);
    REQUIRE(challenge[4] == 120);
    REQUIRE(challenge[5] == 1);
    REQUIRE(challenge[6] == 0x5B);

    Group120Var1 challengeObject;

    REQUIRE(challengeObject.Read(challenge.skip(10)));
    REQUIRE(challengeObject.userNum == 0);
    REQUIRE(challengeObject.reason == 1);

    pair.outstation.OnTxReady();

    // Generate the genuine G120V2, but do not deliver it.
    const auto oldReplyWire =
        ReplyFC6(pair, operateChallengeWire);

    HexSequence oldReplyPacket(oldReplyWire);
    const auto oldReply = oldReplyPacket.ToRSeq();

    REQUIRE(oldReply.length() >= 8);
    REQUIRE((oldReply[0] & 0x0F) == operateSequence);
    REQUIRE(oldReply[4] == 0x5B);

    Group120Var2 oldReplyObject;

    REQUIRE(oldReplyObject.Read(oldReply.skip(8)));
    REQUIRE(oldReplyObject.userNum == 2);
    REQUIRE(oldReplyObject.seqNum == challengeObject.seqNum);

    REQUIRE(pair.master.context->OnTxReady());

    REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(
                pair.outstation.context)
            == OutstationChallenger::State::WAITING_FOR_REPLY);

    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
    REQUIRE(pair.results.values.empty());

    // Disconnect while the original G120V2 remains undelivered.
    REQUIRE(pair.master.context->OnLowerLayerDown());
    pair.outstation.LowerLayerDown();

    REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(
                pair.outstation.context)
            == OutstationChallenger::State::NO_SESSION_KEYS);

    REQUIRE(pair.results.values.size() == 1);

    REQUIRE(pair.results.values.front().summary
            == TaskCompletion::FAILURE_NO_COMMS);

    pair.results.values.clear();

    // Reconnect and negotiate replacement sessions.
    pair.outstation.LowerLayerUp();
    REQUIRE(pair.master.context->OnLowerLayerUp());

    pair.master.exe->run_many();
    pair.Pump();

    REQUIRE(pair.changes == 4);

    REQUIRE(ProductionAuthenticationTestAccess::Now(
                pair.outstation.context) == now);

    REQUIRE(ProductionAuthenticationTestAccess::SessionReady(
        pair.outstation.context, 1));

    REQUIRE(ProductionAuthenticationTestAccess::SessionReady(
        pair.outstation.context, 2));

    REQUIRE(session.IsReady(now));
    REQUIRE(session.Sequence() != oldSession.sequence);

    const auto freshKey = session.ControlKey(now);

    REQUIRE(freshKey.length() == oldSession.control.size());

    REQUIRE_FALSE(crypto::ConstantTimeEqual(
        freshKey,
        rseq_t(oldSession.control.data(), oldSession.control.size())));

    REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(
                pair.outstation.context)
            == OutstationChallenger::State::IDLE);

    REQUIRE(ProductionAuthenticationTestAccess::AcceptedChallenge(
                pair.outstation.context).is_empty());

    // The old Reply must be rejected after fresh key negotiation.
    auto& stats =
        ProductionAuthenticationTestAccess::Stats(
            pair.outstation.context);

    const auto successes =
        stats.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);

    const auto unexpected =
        stats.Value(SecurityStatistic::UNEXPECTED_MESSAGES);

    const auto discarded =
        stats.Value(SecurityStatistic::DISCARDED_MESSAGES);

    pair.outstation.SendToOutstation(oldReplyWire);

    REQUIRE(stats.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS)
            == successes);

    REQUIRE(stats.Value(SecurityStatistic::UNEXPECTED_MESSAGES)
            == unexpected + 1);

    REQUIRE(stats.Value(SecurityStatistic::DISCARDED_MESSAGES)
            == discarded + 1);

    REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(
                pair.outstation.context)
            == OutstationChallenger::State::IDLE);

    REQUIRE(ProductionAuthenticationTestAccess::AcceptedChallenge(
                pair.outstation.context).is_empty());

    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.results.values.empty());

    REQUIRE(pair.outstation.cmdHandler->NumSelect() == 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);

    // A fresh authenticated SBO must still execute once.
    submitSbo();
    pair.Pump();

    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
    REQUIRE(pair.results.values.front().results.size() == 1);

    const auto& point =
        pair.results.values.front().results.front();

    REQUIRE(point.index == index);
    REQUIRE(point.state == CommandPointState::SUCCESS);
    REQUIRE(point.status == CommandStatus::SUCCESS);

    REQUIRE(pair.outstation.cmdHandler->NumSelect() == 2);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
}

TEST_CASE("AT-CFG-08-TIMEOUT", "[rtu-acceptance][production-sa][sa-fc6]")
{
    // Startup key gate, initial TX, Challenge wait, queued Reply, Reply TX, Aggressive TX.
    const auto phase = GENERATE(0, 1, 2, 3, 4, 5);
    const bool disconnect = GENERATE(false, true);
    if (!acceptance::Selected(("V" + std::to_string(1 + phase * 2 + disconnect)).c_str())) return;
    CAPTURE(phase, disconnect);
    RuntimePair pair(false, phase == 5);
    if (phase != 0) pair.Pump();
    if (phase == 5)
    {
        pair.SelectOperate(); pair.Pump(); pair.results.values.clear();
    }
    const auto operations = pair.outstation.cmdHandler->NumOperate();
    std::string challenge;
    if (phase == 0)
    {
        auto config = TaskConfig::Default(); config.authenticationUser = 2;
        REQUIRE(pair.master.context->DirectOperateNoAck(FC6Commands(0, 3), pair.results.Callback(), config));
        pair.master.exe->run_many();
        REQUIRE(pair.master.context->tstate == MContext::TaskState::TASK_READY);
    }
    else
    {
        const auto request = SubmitFC6(pair);
        if (phase >= 2 && phase != 5)
        {
            if (phase != 3) REQUIRE(pair.master.context->OnTxReady());
            challenge = ChallengeFC6(pair, request);
            if (phase == 3)
            {
                REQUIRE(pair.master.SendToMaster(challenge));
                REQUIRE(ProductionAuthenticationTestAccess::ReplyPending(*pair.master.context));
                REQUIRE(pair.master.lower->NumWrites() == 0); // Original request still owns TX.
            }
            if (phase == 4) ReplyFC6(pair, challenge); // Leave the genuine Reply in flight, not delivered.
        }
    }
    REQUIRE(pair.results.values.empty());
    if (disconnect) REQUIRE(pair.master.context->OnLowerLayerDown());
    else
    {
        pair.master.exe->advance_time(phase == 0 ? pair.master.context->params.taskStartTimeout.value
                                               : std::chrono::milliseconds(2000));
        pair.master.exe->run_many();
    }
    RequireLocalFC6Result(pair, disconnect ? TaskCompletion::FAILURE_NO_COMMS
                                         : phase == 0 ? TaskCompletion::FAILURE_START_TIMEOUT
                                                      : TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);
    if (pair.master.context->isSending && phase != 0) REQUIRE(pair.master.context->OnTxReady());
    // Startup can still own V4/V6. Neither timeout nor disconnect can enqueue FC6 again.
    while (pair.master.lower->NumWrites())
    {
        HexSequence packet(pair.master.lower->PopWriteAsHex());
        REQUIRE(packet.ToRSeq()[1] != 6);
    }
    REQUIRE(pair.results.values.size() == 1);
    acceptance::Observe("local_task_completion", static_cast<uint8_t>(pair.results.values.front().summary));
    if (disconnect)
    {
        pair.outstation.LowerLayerDown();
        pair.outstation.LowerLayerUp();
        REQUIRE(pair.master.context->OnLowerLayerUp());
        pair.master.exe->run_many();
        pair.Pump();
        REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);
        REQUIRE(pair.results.values.size() == 1);
    }
    acceptance::Observe("actuations_after_abort", pair.outstation.cmdHandler->NumOperate() - operations);
}

TEST_CASE("ProductionAuthentication - FC6 ignores foreign Challenges and rejects delayed or invalid owned Challenges",
          "[production-sa][sa-fc6]")
{
    // Wrong application sequence, foreign association, boundary delay, unsupported MAC, wrong USR, expired Master keys.
    const auto fault = GENERATE(0, 1, 2, 3, 4, 5);
    CAPTURE(fault);
    RuntimePair pair;
    pair.Pump();
    const auto request = SubmitFC6(pair);
    REQUIRE(pair.master.context->OnTxReady());
    const auto challenge = ChallengeFC6(pair, request);
    HexSequence packet(challenge);
    std::vector<uint8_t> bytes(static_cast<const uint8_t*>(packet.ToRSeq()),
                               static_cast<const uint8_t*>(packet.ToRSeq()) + packet.ToRSeq().length());
    if (fault == 0) bytes[0] ^= 1;
    if (fault == 3) bytes[16] = 6; // G120V1 MAL follows the four-byte response header and CSQ/USR.
    if (fault == 4) bytes[14] = 2; // Outstation-issued G120V1 requires USR=0.
    if (fault == 2 || fault == 5)
    {
        const auto delay = fault == 2 ? uint64_t(2000)
            : ProductionAuthenticationTestAccess::Session(*pair.master.context, 2).ValidUntil();
        pair.master.exe->advance_time(std::chrono::milliseconds(delay));
        // Receive at the deadline before dispatching timer callbacks: the responder must still fail closed.
    }
    const rseq_t changed(bytes.data(), bytes.size());
    if (fault == 1)
        REQUIRE_FALSE(pair.master.context->OnReceive(Message(Addresses(99, pair.master.addresses.source), changed)));
    else REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(changed)));
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    if (fault <= 1)
    {
        REQUIRE(pair.results.values.empty());
        pair.master.exe->advance_time(std::chrono::milliseconds(2000));
    }
    pair.master.exe->run_many();
    RequireLocalFC6Result(pair, TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    // Expired-key service may perform a genuine key exchange, but can never resend FC6.
    while (pair.master.lower->NumWrites())
    {
        HexSequence wire(pair.master.lower->PopWriteAsHex());
        const auto apdu = wire.ToRSeq();
        REQUIRE(apdu.length() >= 2);
        REQUIRE(apdu[1] != 6);
        REQUIRE_FALSE((apdu.length() >= 4 && apdu[1] == 0x20 && apdu[3] == 2));
    }
}

TEST_CASE("ProductionAuthentication - configured Aggressive FC6 cannot downgrade without Challenge history",
          "[production-sa][sa-fc6]")
{
    RuntimePair pair(false, true);
    pair.Pump();
    auto config = TaskConfig::Default(); config.authenticationUser = 2;
    REQUIRE(pair.master.context->DirectOperateNoAck(FC6Commands(0, 3), pair.results.Callback(), config));
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    RequireLocalFC6Result(pair, TaskCompletion::FAILURE_MESSAGE_FORMAT_ERROR);
}

TEST_CASE("ProductionAuthentication - FC6 completion and timeout preserve a genuine independent pending CONFIRM",
          "[production-sa][sa-fc6]")
{
    const bool timeout = GENERATE(false, true);
    RuntimePair pair(true, false, false, nullptr, false, nullptr, 2, false, 2000, 2000, true);
    pair.Pump();
    pair.outstation.AdvanceTime(OutSettings(pair.source, pair.policy, true).params.unsolConfirmTimeout);
    pair.Pump(); // Real startup null response, monitoring authentication and authenticated CONFIRM.
    const auto request = SubmitFC6(pair);
    REQUIRE(pair.master.context->OnTxReady());
    const auto controlChallenge = ChallengeFC6(pair, request);
    pair.outstation.Transaction([](IUpdateHandler& update) { update.Update(Binary(true), 0); });
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto event = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(event));
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto monitoringChallenge = pair.master.lower->PopWriteAsHex();
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(monitoringChallenge);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto monitoringReply = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(monitoringReply));
    pair.master.exe->run_many();
    REQUIRE(pair.master.context->confirmQueue.size() == 1);
    const auto confirmSequence = pair.master.context->confirmQueue.front().control.SEQ;
    REQUIRE(pair.master.lower->NumWrites() == 0); // FC6 owns the responder while waiting for its Challenge.
    const auto reply = ReplyFC6(pair, controlChallenge);
    REQUIRE(pair.master.context->confirmQueue.size() == 1);
    if (timeout)
    {
        pair.master.exe->advance_time(std::chrono::milliseconds(2000)); pair.master.exe->run_many();
        RequireLocalFC6Result(pair, TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
        pair.outstation.AdvanceTime(TimeDuration::Milliseconds(2000)); // Expire only the undelivered control Reply.
        REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    }
    else
    {
        pair.outstation.SendToOutstation(reply);
        REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
        REQUIRE(pair.results.values.empty());
    }
    REQUIRE(pair.master.context->confirmQueue.size() == 1);
    REQUIRE(pair.master.context->confirmQueue.front().control.SEQ == confirmSequence);
    REQUIRE(pair.master.context->OnTxReady());
    RequireLocalFC6Result(pair, timeout ? TaskCompletion::FAILURE_RESPONSE_TIMEOUT : TaskCompletion::SUCCESS);
    REQUIRE(pair.master.lower->NumWrites() == 1);
    pair.Pump(); // The same real CONFIRM now authenticates through the ordinary production path.
    REQUIRE(pair.master.context->confirmQueue.empty());
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ProtectedConfirm(*pair.master.context));
    REQUIRE(ProductionAuthenticationTestAccess::IsIdle(pair.outstation.context));
    REQUIRE(pair.results.values.size() == 1);
}


TEST_CASE("ProductionAuthentication - FC6 timeout retains a later independent monitoring exchange",
          "[production-sa][sa-fc6]")
{
    RuntimePair pair(true, false, false, nullptr, false, nullptr, 2, false, 2000, 2000, true);
    pair.Pump();
    pair.outstation.AdvanceTime(OutSettings(pair.source, pair.policy, true).params.unsolConfirmTimeout);
    pair.Pump();
    const auto request = SubmitFC6(pair);
    REQUIRE(pair.master.context->OnTxReady());
    ChallengeFC6(pair, request); // Genuine Control Challenge is lost, so no control Reply can execute.
    pair.master.exe->advance_time(std::chrono::milliseconds(1000));
    pair.master.exe->run_many();
    pair.outstation.Transaction([](IUpdateHandler& update) { update.Update(Binary(true), 0); });
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto event = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(event));
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto challenge = pair.master.lower->PopWriteAsHex();
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(challenge);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto monitoringReply = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    pair.master.exe->advance_time(std::chrono::milliseconds(1000));
    pair.master.exe->run_many();
    RequireLocalFC6Result(pair, TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    // The monitoring exchange's own later deadline has not elapsed. Its genuine
    // Reply still authenticates and leads to the original native CONFIRM.
    pair.outstation.AdvanceTime(TimeDuration::Milliseconds(2000));
    REQUIRE(pair.master.SendToMaster(monitoringReply));
    pair.Pump();
    REQUIRE_FALSE(ProductionAuthenticationTestAccess::MonitoringWaiting(*pair.master.context));
    REQUIRE(ProductionAuthenticationTestAccess::IsIdle(pair.outstation.context));
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
}


TEST_CASE("ProductionAuthentication - FC6 owned authorization Error is terminal before protected TX release",
          "[production-sa][sa-fc6]")
{
    const bool aggressive = GENERATE(false, true);
    RuntimePair pair(false, aggressive);
    pair.Pump();
    if (aggressive) { pair.SelectOperate(); pair.Pump(); pair.results.values.clear(); }
    const auto operations = pair.outstation.cmdHandler->NumOperate();
    const auto request = SubmitFC6(pair);
    std::string protectedWire = request;
    if (!aggressive)
    {
        REQUIRE(pair.master.context->OnTxReady());
        protectedWire = ReplyFC6(pair, ChallengeFC6(pair, request));
    }
    pair.outstation.application->SetTime(DNPTime(123456789));
    pair.policy->allowControl = false;
    pair.outstation.SendToOutstation(protectedWire);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto error = pair.outstation.lower->PopWriteAsHex();
    HexSequence packet(error);
    REQUIRE(packet.ToRSeq()[1] == 0x83);
    REQUIRE(packet.ToRSeq()[4] == 120);
    REQUIRE(packet.ToRSeq()[5] == 7);
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(error));
    RequireLocalFC6Result(pair, TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    REQUIRE(pair.master.context->isSending); // The rejected task cannot erase borrowed protected bytes.
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.results.values.size() == 1);
}

TEST_CASE("ProductionAuthentication - FC6 TX completion at its deadline cannot report authenticated submission",
          "[production-sa][sa-fc6]")
{
    const bool aggressive = GENERATE(false, true);
    RuntimePair pair(false, aggressive);
    pair.Pump();
    if (aggressive) { pair.SelectOperate(); pair.Pump(); pair.results.values.clear(); }
    const auto request = SubmitFC6(pair);
    if (!aggressive)
    {
        REQUIRE(pair.master.context->OnTxReady());
        ReplyFC6(pair, ChallengeFC6(pair, request));
    }
    pair.master.exe->advance_time(std::chrono::milliseconds(2000));
    // Deliberately release TX before executing expired timers: success must check its deadline itself.
    REQUIRE(pair.master.context->OnTxReady());
    RequireLocalFC6Result(pair, TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    pair.master.exe->run_many();
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.master.lower->NumWrites() == 0);
}


namespace
{
// The envelope uses NETWORK's configured default MAL=4. No optional algorithm is enabled here.
std::vector<uint8_t> B07Envelope(const std::string& hex, bool response, uint16_t user)
{
    HexSequence wire(hex);
    const auto apdu = wire.ToRSeq();
    const size_t header = response ? 4 : 2;
    REQUIRE(apdu.length() >= header + 10 + 22);
    REQUIRE(apdu[header] == 120);
    REQUIRE(apdu[header + 1] == 3);
    REQUIRE(apdu[header + 2] == 0x07);
    REQUIRE(apdu[header + 3] == 1);
    auto prefix = apdu.skip(header + 4);
    Group120Var3 v3;
    REQUIRE(Group120Var3::Read(prefix, v3));
    REQUIRE(v3.userNum == user);
    const auto suffix = apdu.length() - 22;
    REQUIRE(apdu[suffix] == 120);
    REQUIRE(apdu[suffix + 1] == 9);
    REQUIRE(apdu[suffix + 2] == 0x5B);
    REQUIRE(apdu[suffix + 3] == 1);
    REQUIRE(apdu[suffix + 4] == 16);
    REQUIRE(apdu[suffix + 5] == 0);
    std::vector<uint8_t> native(static_cast<const uint8_t*>(apdu), static_cast<const uint8_t*>(apdu) + header);
    native.insert(native.end(), static_cast<const uint8_t*>(apdu) + header + 10,
                  static_cast<const uint8_t*>(apdu) + suffix);
    return native;
}
void B07CheckMAC(const std::string& hex, rseq_t challenge, rseq_t key)
{
    HexSequence wire(hex);
    const auto apdu = wire.ToRSeq();
    REQUIRE(apdu.length() >= 16);
    std::vector<uint8_t> transcript(static_cast<const uint8_t*>(challenge),
                                     static_cast<const uint8_t*>(challenge) + challenge.length());
    transcript.insert(transcript.end(), static_cast<const uint8_t*>(apdu),
                      static_cast<const uint8_t*>(apdu) + apdu.length() - 16);
    std::array<uint8_t, 16> mac{};
    // Independent assembly of Table A-9: full genuine Challenge + full current
    // fragment through V9's header/prefix. No addresses or MAC value in the input.
    REQUIRE(crypto::ComputeHMACSHA256(key, rseq_t(transcript.data(), transcript.size()),
                                     wseq_t(mac.data(), mac.size())) == crypto::Result::OK);
    REQUIRE(crypto::ConstantTimeEqual(rseq_t(mac.data(), mac.size()), apdu.skip(apdu.length() - 16)));
}
// Recompute a valid tag for a deliberately invalid envelope. The monitoring key is
// borrowed from the live negotiated session; no new key or eligibility is injected.
void B07ResignMAC(std::vector<uint8_t>& wire, rseq_t challenge, rseq_t key)
{
    REQUIRE(wire.size() > 16);
    std::vector<uint8_t> transcript(static_cast<const uint8_t*>(challenge),
                                    static_cast<const uint8_t*>(challenge) + challenge.length());
    transcript.insert(transcript.end(), wire.begin(), wire.end() - 16);
    REQUIRE(crypto::ComputeHMACSHA256(key, rseq_t(transcript.data(), transcript.size()),
                                     wseq_t(wire.data() + wire.size() - 16, 16)) == crypto::Result::OK);
}
void B07Prime(RuntimePair& pair, bool unsolicited)
{
    pair.Pump();
    if (unsolicited)
    {
        pair.outstation.AdvanceTime(OutSettings(pair.source, pair.policy, true).params.unsolConfirmTimeout);
        pair.Pump(); // Genuine null-response monitoring exchange and authenticated native CONFIRM.
        REQUIRE(ProductionAuthenticationTestAccess::StartupNullConfirmed(pair.outstation.context));
    }
    pair.SelectOperate();
    pair.Pump(); // User 2 and solicited monitoring histories come from real production exchanges.
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.back().summary == TaskCompletion::SUCCESS);
    pair.results.values.clear();
}
// Capture native replies for selected non-command functions without adding a
// public API or bypassing the scheduler, SA routing, or native Outstation handlers.
class B07NativeTask final : public IMasterTask
{
public:
    B07NativeTask(MContext& context, uint8_t function, const std::string& objects)
        : IMasterTask(context.tasks.context, *context.application,
                      TaskBehavior::SingleExecutionNoRetry(Timestamp(context.executor->get_time()) + context.params.taskStartTimeout),
                      context.logger, Config()), function(function), objects(objects) {}
    const char* Name() const override { return "B07 selected function"; }
    int Priority() const override { return priority::USER_REQUEST; }
    bool IsRecurring() const override { return false; }
    bool BuildRequest(APDURequest& request, uint8_t seq) override
    {
        request.ConfigureHeader(FunctionCodeSpec::from_type(function), seq);
        HexSequence body(objects);
        return request.AppendObjects(body.ToRSeq());
    }
    size_t completions = 0;
    TaskCompletion completion = TaskCompletion::FAILURE_BAD_RESPONSE;
    IINField responseIIN;
    std::vector<uint8_t> received;
private:
    static TaskConfig Config() { auto config = TaskConfig::Default(); config.authenticationUser = 2; return config; }
    bool BlocksLowerPriority() const override { return false; }
    MasterTaskType GetTaskType() const override { return MasterTaskType::USER_TASK; }
    ResponseResult ProcessResponse(const APDUResponseHeader& header, const rseq_t& data) override
    {
        responseIIN = header.IIN;
        if (!ValidateSingleResponse(header) || header.IIN.HasRequestError()) return ResponseResult::ERROR_BAD_RESPONSE;
        received.assign(static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + data.length());
        return ResponseResult::OK_FINAL;
    }
    void OnTaskComplete(TaskCompletion result, Timestamp) override { completion = result; ++completions; }
    const uint8_t function;
    const std::string objects;
};
}

TEST_CASE("ProductionAuthentication - disconnect before G41 OPERATE invalidates selection and authentication",
          "[production-sa][g41-sa-disconnect-before-operate]")
{
    const auto variation = GENERATE(1u, 2u, 3u);
    const bool wide = GENERATE(false, true);
    CAPTURE(variation, wide);

    const uint16_t index = wide ? 0x1234 : 3;

    RuntimePair pair(false, true, false, nullptr, false, nullptr, 2,
                     false, 2000, 2000, false,
                     IndexQualifierMode::allow_one_byte);

    B07Prime(pair, false);

    REQUIRE(pair.changes == 2);

    const auto selections = pair.outstation.cmdHandler->NumSelect();
    const auto operations = pair.outstation.cmdHandler->NumOperate();

    const auto now =
        ProductionAuthenticationTestAccess::Now(pair.outstation.context);

    auto& session =
        ProductionAuthenticationTestAccess::Session(*pair.master.context, 2);

    const MACPolicySessionSnapshot oldSession(session, now);

    auto& stats =
        ProductionAuthenticationTestAccess::Stats(pair.outstation.context);

    const auto beforeSelect =
        stats.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);

    auto config = TaskConfig::Default();
    config.authenticationUser = 2;

    const auto submitSbo = [&]() {
        pair.master.context->SelectAndOperate(
            FC6Commands(variation, index),
            pair.results.Callback(),
            config);

        pair.master.exe->run_many();
    };

    submitSbo();

    REQUIRE(pair.master.lower->NumWrites() == 1);

    const auto selectWire = pair.master.lower->PopWriteAsHex();
    const auto select = B07Envelope(selectWire, false, 2);

    REQUIRE(select.size() > 5);
    REQUIRE(select[1] == 3);
    REQUIRE(select[2] == 41);
    REQUIRE(select[3] == variation);
    REQUIRE(select[4] == (wide ? 0x28 : 0x17));
    REQUIRE(select.back() == 0);

    const auto selectSequence = select[0] & 0x0F;
    const auto selectedObjects =
        rseq_t(select.data(), select.size()).skip(2);

    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(selectWire);

    REQUIRE(stats.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS)
            == beforeSelect + 1);

    REQUIRE(pair.outstation.cmdHandler->NumSelect() == selections + 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);

    const auto selectResponseWire =
        pair.outstation.lower->PopWriteAsHex();

    const auto selectResponse =
        B07Envelope(selectResponseWire, true, 1);

    REQUIRE(selectResponse[1] == 0x81);
    REQUIRE((selectResponse[0] & 0x0F) == selectSequence);

    REQUIRE(rseq_t(selectResponse.data(), selectResponse.size())
                .skip(4).equals(selectedObjects));

    pair.outstation.OnTxReady();

    REQUIRE(pair.master.SendToMaster(selectResponseWire));
    pair.master.exe->run_many();

    REQUIRE(pair.master.lower->NumWrites() == 1);

    const auto oldOperateWire =
        pair.master.lower->PopWriteAsHex();

    const auto operate =
        B07Envelope(oldOperateWire, false, 2);

    REQUIRE(operate[1] == 4);

    REQUIRE((operate[0] & 0x0F)
            == ((selectSequence + 1) & 0x0F));

    const auto nativeOperate =
        rseq_t(operate.data(), operate.size());

    REQUIRE(nativeOperate.skip(2).equals(selectedObjects));

    B07CheckMAC(
        oldOperateWire,
        ProductionAuthenticationTestAccess::AcceptedChallenge(
            pair.outstation.context),
        rseq_t(oldSession.control.data(), oldSession.control.size()));

    // The genuine matching FC4 has not reached the Outstation.
    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(pair.results.values.empty());
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);

    REQUIRE(pair.master.context->OnLowerLayerDown());
    pair.outstation.LowerLayerDown();

    REQUIRE_FALSE(
        ProductionAuthenticationTestAccess::SessionReady(
            pair.outstation.context, 2));

    REQUIRE(pair.results.values.size() == 1);

    REQUIRE(pair.results.values.front().summary
            == TaskCompletion::FAILURE_NO_COMMS);

    pair.results.values.clear();

    // Establish replacement sessions after reconnect.
    pair.outstation.LowerLayerUp();
    REQUIRE(pair.master.context->OnLowerLayerUp());
    pair.master.exe->run_many();
    pair.Pump();

    REQUIRE(pair.changes == 4);

    REQUIRE(ProductionAuthenticationTestAccess::Now(
                pair.outstation.context) == now);

    REQUIRE(ProductionAuthenticationTestAccess::SessionReady(
        pair.outstation.context, 1));

    REQUIRE(ProductionAuthenticationTestAccess::SessionReady(
        pair.outstation.context, 2));

    REQUIRE(session.IsReady(now));
    REQUIRE(session.Sequence() != oldSession.sequence);

    const auto freshKey = session.ControlKey(now);

    REQUIRE(freshKey.length() == oldSession.control.size());

    REQUIRE_FALSE(crypto::ConstantTimeEqual(
        freshKey,
        rseq_t(oldSession.control.data(), oldSession.control.size())));

    const auto successes =
        stats.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);

    const auto failures =
        stats.Value(SecurityStatistic::AUTHENTICATION_FAILURES);

    const auto discarded =
        stats.Value(SecurityStatistic::DISCARDED_MESSAGES);

    const auto denied =
        stats.Value(SecurityStatistic::AUTHORIZATION_FAILURES);

    // Authenticate the exact previous native OPERATE using
    // the replacement user-2 session.
    MasterResponder responder(7, 16);

    REQUIRE(responder.SetSessionKey(
                2, freshKey, session.ValidUntil(), now)
            == MasterResponder::Result::OK);

    REQUIRE(responder.RetainRequest(7, nativeOperate, now)
            == MasterResponder::Result::OK);

    pair.outstation.SendToOutstation(
        HexConversions::to_hex(nativeOperate));

    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);

    HexSequence challenge(
        pair.outstation.lower->PopWriteAsHex());

    pair.outstation.OnTxReady();

    std::array<uint8_t, SessionKeys::MAX_APDU> reply{};
    size_t replySize = 0;

    REQUIRE(responder.Respond(
                7,
                challenge.ToRSeq(),
                now,
                wseq_t(reply.data(), reply.size()),
                replySize)
            == MasterResponder::Result::OK);

    pair.outstation.SendToOutstation(
        HexConversions::to_hex(rseq_t(reply.data(), replySize)));

    // Authentication succeeds, but the previous SELECT
    // must no longer authorize execution.
    REQUIRE(stats.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS)
            == successes + 1);

    REQUIRE(stats.Value(SecurityStatistic::AUTHENTICATION_FAILURES)
            == failures);

    REQUIRE(stats.Value(SecurityStatistic::DISCARDED_MESSAGES)
            == discarded + 1);

    REQUIRE(stats.Value(SecurityStatistic::AUTHORIZATION_FAILURES)
            == denied);

    REQUIRE(ProductionAuthenticationTestAccess::AcceptedChallenge(
                pair.outstation.context).equals(challenge.ToRSeq()));

    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);

    // Deliver the retained old-session Aggressive OPERATE
    // only after replacement Challenge history is established.
    pair.outstation.SendToOutstation(oldOperateWire);

    REQUIRE(stats.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS)
            == successes + 1);

    REQUIRE(stats.Value(SecurityStatistic::AUTHENTICATION_FAILURES)
            == failures + 1);

    REQUIRE(stats.Value(SecurityStatistic::DISCARDED_MESSAGES)
            == discarded + 2);

    REQUIRE(stats.Value(SecurityStatistic::AUTHORIZATION_FAILURES)
            == denied);

    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == selections + 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);

    // A completely new authenticated SBO must still succeed.
    submitSbo();
    pair.Pump();

    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
    REQUIRE(pair.results.values.front().results.size() == 1);

    const auto& point =
        pair.results.values.front().results.front();

    REQUIRE(point.index == index);
    REQUIRE(point.state == CommandPointState::SUCCESS);
    REQUIRE(point.status == CommandStatus::SUCCESS);

    REQUIRE(pair.outstation.cmdHandler->NumSelect() == selections + 2);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations + 1);
}

TEST_CASE("ProductionAuthentication - B07 selected FC3 FC4 FC5 envelopes retain typed qualifier and echo bytes",
          "[production-sa][sa-b07]")
{
    const auto type = GENERATE(0u, 1u, 2u, 3u);
    const bool wide = GENERATE(false, true);
    const bool direct = GENERATE(false, true);
    CAPTURE(type, wide, direct);
    RuntimePair pair(false, true, false, nullptr, false, nullptr, 2, false, 2000, 2000, false,
                     IndexQualifierMode::allow_one_byte);
    B07Prime(pair, false);
    const auto operations = pair.outstation.cmdHandler->NumOperate();
    const auto selections = pair.outstation.cmdHandler->NumSelect();
    auto config = TaskConfig::Default(); config.authenticationUser = 2;
    if (direct) pair.master.context->DirectOperate(FC6Commands(type, wide ? 0x1234 : 3), pair.results.Callback(), config);
    else pair.master.context->SelectAndOperate(FC6Commands(type, wide ? 0x1234 : 3), pair.results.Callback(), config);
    pair.master.exe->run_many();
    for (unsigned phase = 0; phase < (direct ? 1u : 2u); ++phase)
    {
        REQUIRE(pair.master.lower->NumWrites() == 1);
        const auto request = pair.master.lower->PopWriteAsHex();
        const auto native = B07Envelope(request, false, 2);
        REQUIRE(native[1] == (direct ? 5 : phase == 0 ? 3 : 4));
        REQUIRE(native[2] == (type == 0 ? 12 : 41));
        REQUIRE(native[3] == (type == 0 ? 1 : type));
        REQUIRE(native[4] == (wide ? 0x28 : 0x17));
        B07CheckMAC(request, ProductionAuthenticationTestAccess::AcceptedChallenge(pair.outstation.context),
                    ProductionAuthenticationTestAccess::Session(*pair.master.context, 2).ControlKey(0));
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(request);
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        const auto response = pair.outstation.lower->PopWriteAsHex();
        const auto echoed = B07Envelope(response, true, 1);
        REQUIRE(echoed[1] == 0x81);
        REQUIRE((echoed[0] & 0x0F) == (native[0] & 0x0F));
        REQUIRE(rseq_t(echoed.data(), echoed.size()).skip(4).equals(rseq_t(native.data(), native.size()).skip(2)));
        HexSequence seed(pair.monitoringChallenge);
        B07CheckMAC(response, seed.ToRSeq(), ProductionAuthenticationTestAccess::Common(pair.outstation.context).MonitoringKey(0));
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(response));
        pair.master.exe->run_many();
    }
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
    REQUIRE(pair.results.values.front().results.front().status == CommandStatus::SUCCESS);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations + 1);
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == selections + (direct ? 0 : 1));
}

namespace
{
enum class ControlFault
{
    Replay,
    InvalidMac,
    ForeignAssociation,
    WrongSequence,
    DeniedPolicy,
    ExpiredKeys,
    UnknownUser,
    NoKeys
};

void CheckAuthenticatedControlFault(unsigned type, bool wide, bool aggressive, unsigned target, ControlFault fault)
{
    CAPTURE(type, wide, aggressive, target, static_cast<unsigned>(fault));

    RuntimePair pair(false, aggressive, false, nullptr, false,
                     nullptr, 2, false, 2000, 2000, false,
                     IndexQualifierMode::allow_one_byte);

    if (aggressive)
        B07Prime(pair, false);
    else
        pair.Pump();

    const auto operations = pair.outstation.cmdHandler->NumOperate();
    const auto selections = pair.outstation.cmdHandler->NumSelect();

    auto config = TaskConfig::Default();
    config.authenticationUser = 2;

    if (target == 5)
        pair.master.context->DirectOperate(
            FC6Commands(type, wide ? 0x1234 : 3),
            pair.results.Callback(), config);
    else
        pair.master.context->SelectAndOperate(
            FC6Commands(type, wide ? 0x1234 : 3),
            pair.results.Callback(), config);

    pair.master.exe->run_many();

    for (unsigned phase = 0; phase < (target == 5 ? 1u : 2u); ++phase)
    {
        const unsigned fc = target == 5 ? 5 : phase == 0 ? 3 : 4;

        REQUIRE(pair.master.lower->NumWrites() == 1);
        const auto request = pair.master.lower->PopWriteAsHex();
        HexSequence packet(request);

        std::vector<uint8_t> native;
        if (aggressive)
            native = B07Envelope(request, false, 2);
        else
            native.assign(
                static_cast<const uint8_t*>(packet.ToRSeq()),
                static_cast<const uint8_t*>(packet.ToRSeq())
                    + packet.ToRSeq().length());

        REQUIRE(native.size() >= 5);
        REQUIRE(native[1] == fc);
        REQUIRE(native[2] == (type == 0 ? 12 : 41));
        REQUIRE(native[3] == (type == 0 ? 1 : type));
        REQUIRE(native[4] == (wide ? 0x28 : 0x17));

        const auto beforeSelect = pair.outstation.cmdHandler->NumSelect();
        const auto beforeOperate = pair.outstation.cmdHandler->NumOperate();

        std::string protectedWire = request;
        REQUIRE(pair.master.context->OnTxReady());

        if (!aggressive)
        {
            pair.outstation.SendToOutstation(request);

            REQUIRE(pair.outstation.cmdHandler->NumSelect() == beforeSelect);
            REQUIRE(pair.outstation.cmdHandler->NumOperate() == beforeOperate);
            REQUIRE(pair.outstation.lower->NumWrites() == 1);

            const auto challenge = pair.outstation.lower->PopWriteAsHex();
            HexSequence challengePacket(challenge);

            REQUIRE(challengePacket.ToRSeq()[1] == 0x83);
            REQUIRE(challengePacket.ToRSeq()[4] == 120);
            REQUIRE(challengePacket.ToRSeq()[5] == 1);

            pair.outstation.OnTxReady();
            protectedWire = ReplyFC6(pair, challenge);
            REQUIRE(pair.master.context->OnTxReady());
        }

        if (fc == target && fault != ControlFault::Replay)
        {
            HexSequence authentic(protectedWire);
            std::vector<uint8_t> wire(
                static_cast<const uint8_t*>(authentic.ToRSeq()),
                static_cast<const uint8_t*>(authentic.ToRSeq()) + authentic.ToRSeq().length());
            switch (fault)
            {
            case ControlFault::Replay: break;
            case ControlFault::InvalidMac: wire.back() ^= 1; break;
            case ControlFault::WrongSequence: wire[0] ^= 1; break;
            case ControlFault::DeniedPolicy: pair.policy->allowControl = false; break;
            case ControlFault::ExpiredKeys: {
                const auto expiry = ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2).ValidUntil();
                pair.outstation.AdvanceTime(TimeDuration::Milliseconds(
                    expiry - ProductionAuthenticationTestAccess::Now(pair.outstation.context)));
                break;
            }
            case ControlFault::UnknownUser:
                wire[aggressive ? 10 : 12] = 99;
                wire[aggressive ? 11 : 13] = 0;
                break;
            case ControlFault::ForeignAssociation: break;
            case ControlFault::NoKeys: {
                OutstationTestObject fresh(OutSettings(pair.source, pair.policy, false, aggressive));
                fresh.LowerLayerUp();
                fresh.SendToOutstation(protectedWire);
                REQUIRE(fresh.cmdHandler->NumInvocations() == 0);
                while (!fresh.lower->HasNoData())
                {
                    const HexSequence response(fresh.lower->PopWriteAsHex());
                    REQUIRE(response.ToRSeq()[1] == 0x83);
                    REQUIRE(response.ToRSeq()[4] == 120);
                    REQUIRE(response.ToRSeq()[5] == 7);
                    fresh.OnTxReady();
                }
                break;
            }
            }

            const rseq_t frame(wire.data(), wire.size());
            if (fault == ControlFault::ForeignAssociation)
                ProductionAuthenticationTestAccess::ReceiveOtherAssociation(pair.outstation.context, frame);
            else if (fault != ControlFault::NoKeys)
                pair.outstation.SendToOutstation(HexConversions::to_hex(frame));

            REQUIRE(pair.outstation.cmdHandler->NumSelect() == beforeSelect);
            REQUIRE(pair.outstation.cmdHandler->NumOperate() == beforeOperate);
            RequireOnlyAuthenticationErrors(pair);
            REQUIRE(pair.results.values.empty());

            pair.master.exe->advance_time(
                pair.master.context->params.responseTimeout.value);
            pair.master.exe->run_many();

            REQUIRE(pair.results.values.size() == 1);
            REQUIRE(pair.results.values.front().summary != TaskCompletion::SUCCESS);
            REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);
            return;
        }

        pair.outstation.SendToOutstation(protectedWire);

        REQUIRE(pair.outstation.cmdHandler->NumSelect()
                == beforeSelect + (fc == 3 ? 1 : 0));
        REQUIRE(pair.outstation.cmdHandler->NumOperate()
                == beforeOperate + (fc == 3 ? 0 : 1));

        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        const auto response = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();

        REQUIRE(pair.master.SendToMaster(response));
        pair.master.exe->run_many();

        if (!aggressive)
        {
            // Complete the genuine monitoring authentication
            // without automatically transmitting the next control.
            REQUIRE(pair.master.lower->NumWrites() == 1);
            const auto challenge = pair.master.lower->PopWriteAsHex();
            HexSequence monitoringChallenge(challenge);

            REQUIRE(monitoringChallenge.ToRSeq()[1] == 0x20);
            REQUIRE(monitoringChallenge.ToRSeq()[2] == 120);
            REQUIRE(monitoringChallenge.ToRSeq()[3] == 1);

            REQUIRE(pair.master.context->OnTxReady());
            pair.outstation.SendToOutstation(challenge);

            REQUIRE(pair.outstation.lower->NumWrites() == 1);
            const auto reply = pair.outstation.lower->PopWriteAsHex();
            HexSequence monitoringReply(reply);

            REQUIRE(monitoringReply.ToRSeq()[1] == 0x83);
            REQUIRE(monitoringReply.ToRSeq()[4] == 120);
            REQUIRE(monitoringReply.ToRSeq()[5] == 2);

            pair.outstation.OnTxReady();
            REQUIRE(pair.master.SendToMaster(reply));
            pair.master.exe->run_many();
        }

        if (fc == target)
        {
            const auto selects = pair.outstation.cmdHandler->NumSelect();
            const auto operates = pair.outstation.cmdHandler->NumOperate();
            const auto results = pair.results.values.size();

            REQUIRE(fault == ControlFault::Replay);
            pair.outstation.SendToOutstation(protectedWire);

            REQUIRE(pair.outstation.cmdHandler->NumSelect() == selects);
            REQUIRE(pair.outstation.cmdHandler->NumOperate() == operates);
            RequireOnlyAuthenticationErrors(pair);
            REQUIRE(pair.results.values.size() == results);
        }
    }

    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
    REQUIRE(pair.results.values.front().results.front().status
            == CommandStatus::SUCCESS);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations + 1);
    REQUIRE(pair.outstation.cmdHandler->NumSelect()
            == selections + (target == 5 ? 0 : 1));
}

void ObserveAuthenticatedControlFaults(const std::array<ControlFault, 4>& faults)
{
    for (size_t i = 0; i < faults.size(); ++i)
    {
        if (!acceptance::Selected(("V" + std::to_string(i + 1)).c_str())) continue;
        unsigned receiverChecks = 0;
        for (unsigned type : {0u, 1u, 2u, 3u})
            for (const bool wide : {false, true})
                for (const bool aggressive : {false, true})
                    for (unsigned target : {3u, 4u, 5u})
                    {
                        CheckAuthenticatedControlFault(type, wide, aggressive, target, faults[i]);
                        ++receiverChecks;
                    }
        acceptance::Observe("receiver_checks", receiverChecks);
    }
}
} // namespace

TEST_CASE("AT-CFG-08-REPLAY", "[rtu-acceptance][production-sa][g41-sa-replay]")
{
    ObserveAuthenticatedControlFaults({{ControlFault::Replay, ControlFault::InvalidMac,
                                       ControlFault::ForeignAssociation, ControlFault::WrongSequence}});
}

TEST_CASE("AT-CFG-08-DENY", "[rtu-acceptance][production-sa][profile-controls]")
{
    ObserveAuthenticatedControlFaults({{ControlFault::DeniedPolicy, ControlFault::ExpiredKeys,
                                       ControlFault::UnknownUser, ControlFault::NoKeys}});
}

TEST_CASE("CFG-09 - authenticated binary output WRITE leaves status unchanged", "[production-sa][profile-crob-write]")
{
    const bool wide = GENERATE(false, true);
    RuntimePair pair;
    pair.Pump();
    REQUIRE(pair.master.context->OnLowerLayerDown());
    pair.outstation.LowerLayerDown();

    DatabaseConfig database;
    database.binary_output_status[3].svariation = StaticBinaryOutputStatusVariation::Group10Var2;
    OutstationTestObject station(OutSettings(pair.source, pair.policy), database);
    station.Transaction([](IUpdateHandler& update) {
        update.Update(BinaryOutputStatus(false, Flags(1)), 3, EventMode::Suppress);
    });
    station.LowerLayerUp();
    REQUIRE(pair.master.context->OnLowerLayerUp());
    pair.master.exe->run_many();
    pair.Pump(&station);

    const auto readback = [&]() {
        pair.master.meas->Clear();
        pair.master.context->ScanRange(GroupVariationID(10, 2), 3, 3, pair.master.meas, TaskConfig::Default());
        pair.master.exe->run_many();
        pair.Pump(&station);
        REQUIRE(pair.master.meas->binaryOutputStatusSOE.size() == 1);
        const auto& value = pair.master.meas->binaryOutputStatusSOE.at(3);
        REQUIRE(value.info.gv == GroupVariation::Group10Var2);
        REQUIRE_FALSE(value.meas.value);
        REQUIRE(value.meas.flags.value == 1);
    };
    readback();
    const auto authorizationFailures = ProductionAuthenticationTestAccess::Stats(station.context)
                                           .Value(SecurityStatistic::AUTHORIZATION_FAILURES);
    const auto replies = pair.controlReplies;
    const auto request = std::make_shared<B07NativeTask>(*pair.master.context, 2,
        wide ? "0A 02 01 03 00 03 00 81" : "0A 02 00 03 03 81");
    ProductionAuthenticationTestAccess::Schedule(*pair.master.context, request);
    pair.master.exe->run_many();
    pair.Pump(&station);
    REQUIRE(pair.controlReplies == replies + 1);
    REQUIRE(request->completions == 1);
    REQUIRE(request->completion == TaskCompletion::FAILURE_BAD_RESPONSE);
    REQUIRE(request->responseIIN.HasRequestError());
    REQUIRE(ProductionAuthenticationTestAccess::Stats(station.context).Value(SecurityStatistic::AUTHORIZATION_FAILURES)
            == authorizationFailures);
    REQUIRE(station.cmdHandler->NumInvocations() == 0);
    readback();
}

TEST_CASE("ProductionAuthentication - B07 selected non-command functions traverse native Aggressive routing",
          "[production-sa][sa-b07]")
{
    // FC1-31 is the envelope range, not a request to implement optional functions.
    const auto item = GENERATE(0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u);
    const std::array<uint8_t, 10> functions{{1, 2, 2, 13, 20, 21, 22, 22, 22, 23}};
    const std::array<const char*, 10> bodies{{"3C 01 06", "32 01 07 01 E8 03 00 00 00 00",
        "50 01 00 07 07 00", "", "3C 02 06 3C 03 06 3C 04 06", "3C 02 06 3C 03 06 3C 04 06",
        "3C 03 06 01 00 06", "3C 03 06 03 00 06", "3C 03 06 1E 00 06", ""}};
    CAPTURE(item, functions[item], bodies[item]);
    RuntimePair pair(true, true, false, nullptr, false, nullptr, 2, false, 2000, 2000, true,
                     IndexQualifierMode::always_two_bytes, true);
    B07Prime(pair, true);
    if (item == 4)
    {
        // FC20 must enable classes 2/3 in addition to the initially enabled class 1.
        REQUIRE(ProductionAuthenticationTestAccess::UnsolEnabled(pair.outstation.context, PointClass::Class1));
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::UnsolEnabled(pair.outstation.context, PointClass::Class2));
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::UnsolEnabled(pair.outstation.context, PointClass::Class3));
    }
    if (item == 5)
        REQUIRE(ProductionAuthenticationTestAccess::UnsolEnabled(pair.outstation.context, PointClass::Class1));
    pair.outstation.application->supportsAssignClass = true;
    pair.outstation.application->coldRestartSupport = RestartMode::SUPPORTED_DELAY_FINE;
    pair.outstation.application->coldRestartTimeDelay = 37;
    auto task = std::make_shared<B07NativeTask>(*pair.master.context, functions[item], bodies[item]);
    ProductionAuthenticationTestAccess::Schedule(*pair.master.context, task);
    pair.master.exe->run_many();
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto request = pair.master.lower->PopWriteAsHex();
    const auto native = B07Envelope(request, false, 2);
    REQUIRE(native[1] == functions[item]);
    HexSequence body(bodies[item]);
    REQUIRE(rseq_t(native.data(), native.size()).skip(2).equals(body.ToRSeq()));
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(request);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto response = pair.outstation.lower->PopWriteAsHex();
    const auto decoded = B07Envelope(response, true, 1);
    REQUIRE(decoded[1] == 0x81);
    REQUIRE((decoded[3] & 0x07) == 0); // No parameter/unknown-object/unsupported-function IIN.
    if (item == 0) { REQUIRE(decoded.size() > 4); REQUIRE(decoded[4] == 1); }
    else if (item == 3 || item == 9)
    {
        HexSequence expected(item == 3 ? "34 02 07 01 25 00" : "34 02 07 01 00 00");
        REQUIRE(rseq_t(decoded.data(), decoded.size()).skip(4).equals(expected.ToRSeq()));
    }
    else REQUIRE(decoded.size() == 4);
    if (item == 1)
    {
        REQUIRE(pair.outstation.application->timestamps.size() == 1);
        REQUIRE(pair.outstation.application->timestamps.front().msSinceEpoch == 1000);
    }
    if (item >= 6 && item <= 8)
    {
        REQUIRE(pair.outstation.application->classAssignments.size() == 1);
        const auto type = item == 6 ? AssignClassType::BinaryInput
            : item == 7 ? AssignClassType::DoubleBinaryInput : AssignClassType::AnalogInput;
        REQUIRE(std::get<0>(pair.outstation.application->classAssignments.front()) == type);
        REQUIRE(std::get<1>(pair.outstation.application->classAssignments.front()) == PointClass::Class2);
        REQUIRE(std::get<2>(pair.outstation.application->classAssignments.front()) == 0);
        REQUIRE(std::get<3>(pair.outstation.application->classAssignments.front()) == 0);
    }
    if (item == 2) REQUIRE_FALSE(ProductionAuthenticationTestAccess::ResponseIIN(pair.outstation.context).IsSet(IINBit::DEVICE_RESTART));
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(response));
    pair.master.exe->run_many();
    REQUIRE(task->completions == 1);
    REQUIRE(task->completion == TaskCompletion::SUCCESS);
    REQUIRE(rseq_t(task->received.data(), task->received.size()).equals(rseq_t(decoded.data(), decoded.size()).skip(4)));
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1); // Bootstrap only; no optional output function added.
    REQUIRE(pair.results.values.empty());

    if (item == 4 || item == 5)
    {
        const bool enabled = item == 4;
        for (auto clazz : {PointClass::Class1, PointClass::Class2, PointClass::Class3})
            REQUIRE(ProductionAuthenticationTestAccess::UnsolEnabled(pair.outstation.context, clazz) == enabled);

        REQUIRE(pair.outstation.lower->NumWrites() == 0);
        const auto received = pair.master.meas->TotalReceived();
        const auto buffered = ProductionAuthenticationTestAccess::BufferedEvents(pair.outstation.context, EventClass::EC1);
        pair.outstation.Transaction([](IUpdateHandler& update) { update.Update(Binary(true), 0); });
        if (enabled)
        {
            REQUIRE(pair.outstation.lower->NumWrites() == 1);
            const auto unsolicited = pair.outstation.lower->PopWriteAsHex();
            const auto native = B07Envelope(unsolicited, true, 1);
            REQUIRE(native[1] == 0x82);
            REQUIRE(native.size() > 4);
            REQUIRE(native[4] == 2); // G2 binary event, not just an unsolicited header.
            pair.outstation.OnTxReady();
            REQUIRE(pair.master.SendToMaster(unsolicited));
            pair.Pump(); // Authenticated unsolicited event and native CONFIRM.
            REQUIRE(pair.master.meas->TotalReceived() > received);
        }
        else
        {
            // NumEvents counts unwritten records; an active unsolicited response has already marked its event written.
            REQUIRE(ProductionAuthenticationTestAccess::BufferedEvents(pair.outstation.context, EventClass::EC1) == buffered + 1);
            REQUIRE(pair.outstation.lower->NumWrites() == 0);
            REQUIRE(pair.master.meas->TotalReceived() == received);
        }
    }
    if (item >= 6 && item <= 8)
    {
        const auto before1 = ProductionAuthenticationTestAccess::BufferedEvents(pair.outstation.context, EventClass::EC1);
        const auto before2 = ProductionAuthenticationTestAccess::BufferedEvents(pair.outstation.context, EventClass::EC2);
        pair.outstation.Transaction([&](IUpdateHandler& update) {
            if (item == 6) update.Update(Binary(true), 0);
            if (item == 7) update.Update(DoubleBitBinary(DoubleBit::DETERMINED_ON), 0);
            if (item == 8) update.Update(Analog(42.0), 0);
        });
        // The assigned point started in class 1. A genuine update must now be class 2.
        REQUIRE(ProductionAuthenticationTestAccess::BufferedEvents(pair.outstation.context, EventClass::EC1) == before1);
        REQUIRE(ProductionAuthenticationTestAccess::BufferedEvents(pair.outstation.context, EventClass::EC2) == before2 + 1);
        REQUIRE(pair.outstation.lower->NumWrites() == 0); // Only class 1 is unsolicited-enabled here.
    }
}

TEST_CASE("ProductionAuthentication - B07 monitoring faults preserve pending control and both borrowed transmissions",
          "[production-sa][sa-b07]")
{
    const bool unsolicited = GENERATE(false, true);
    // Existing structural, routing, tag and user negatives (0-8); separately:
    // 9: configured wrong user with a genuine Monitoring-key MAC,
    // 10: native value-only tamper with unchanged MAC and intact framing,
    // 11: malformed V3 qualifier with a newly valid MAC.
    const auto fault = GENERATE(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
    CAPTURE(unsolicited, fault);
    RuntimePair pair(unsolicited, true, false, nullptr, false, nullptr, 2, false, 2000, 2000, unsolicited);
    pair.Pump();
    if (unsolicited)
    {
        pair.outstation.AdvanceTime(OutSettings(pair.source, pair.policy, true).params.unsolConfirmTimeout);
        pair.Pump(); // Only UNS history/common control has been established; user 2 is still unprimed.
        pair.SelectOperate();
    }
    else
    {
        pair.SelectOperate(); pair.Pump(); pair.results.values.clear();
        auto config = TaskConfig::Default(); config.authenticationUser = 2;
        pair.master.context->DirectOperate(FC6Commands(0, 3), pair.results.Callback(), config);
        pair.master.exe->run_many();
    }
    REQUIRE(pair.master.lower->NumWrites() == 1);
    const auto request = pair.master.lower->PopWriteAsHex(); // Keep the native/Aggressive Master buffer borrowed.
    HexSequence heldRequest(request);
    pair.outstation.SendToOutstation(request);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    auto response = pair.outstation.lower->PopWriteAsHex();
    std::string controlChallenge;
    if (unsolicited)
    {
        controlChallenge = response;
        pair.outstation.OnTxReady();
        pair.outstation.Transaction([](IUpdateHandler& update) { update.Update(Binary(true), 0); });
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        response = pair.outstation.lower->PopWriteAsHex();
        REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(pair.outstation.context)
            == OutstationChallenger::State::WAITING_FOR_REPLY);
    }
    HexSequence packet(response);
    auto native = B07Envelope(response, true, 1);
    REQUIRE(native[1] == (unsolicited ? 0x82 : 0x81));
    const auto operations = pair.outstation.cmdHandler->NumOperate();
    const auto selections = pair.outstation.cmdHandler->NumSelect();
    const auto successes = ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);
    const auto state = ProductionAuthenticationTestAccess::ResponderState(*pair.master.context);
    const auto measurements = pair.master.meas->TotalReceived();
    const auto monitoringCSQ = ProductionAuthenticationTestAccess::MonitoringSequence(*pair.master.context);
    const auto commonBudget = ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages();
    const auto controlBudget = ProductionAuthenticationTestAccess::Session(*pair.master.context, 2).RemainingMessages();
    HexSequence seed(pair.monitoringChallenge);
    const auto monitoringKey = ProductionAuthenticationTestAccess::Common(pair.outstation.context)
        .MonitoringKey(ProductionAuthenticationTestAccess::Now(pair.outstation.context));
    B07CheckMAC(response, seed.ToRSeq(), monitoringKey);
    std::vector<uint8_t> changed(static_cast<const uint8_t*>(packet.ToRSeq()),
                               static_cast<const uint8_t*>(packet.ToRSeq()) + packet.ToRSeq().length());
    const size_t suffix = changed.size() - 22;
    if (fault == 0) changed[12] = 99;
    if (fault == 2) changed.back() ^= 1;
    if (fault == 3) { changed[suffix + 4] = 15; changed.pop_back(); }
    if (fault == 4) changed[2] ^= 1;
    if (fault == 5) changed[14] ^= 1;
    if (fault == 6) changed[6] = 8;
    if (fault == 7) changed[7] = 2;
    if (fault == 8) changed[suffix + 2] = 7;
    if (fault == 9)
    {
        REQUIRE(changed[12] == 1); // Monitoring responses must use common user 1.
        REQUIRE(changed[13] == 0);
        changed[12] = 2; // Configured user 2, but invalid for this direction.
        B07ResignMAC(changed, seed.ToRSeq(), monitoringKey);
        const auto forged = HexConversions::to_hex(rseq_t(changed.data(), changed.size()));
        B07CheckMAC(forged, seed.ToRSeq(), monitoringKey);
        REQUIRE(B07Envelope(forged, true, 2) == native);
    }
    if (fault == 10)
    {
        REQUIRE(suffix > 4); // A real native FC129/130 data value exists.
        changed[suffix - 1] ^= 1;
        const auto altered = B07Envelope(HexConversions::to_hex(rseq_t(changed.data(), changed.size())), true, 1);
        REQUIRE(altered.size() == native.size());
        REQUIRE(std::equal(altered.begin(), altered.end() - 1, native.begin()));
        REQUIRE(altered.back() != native.back());
        // Its original tag is left intact: only the native value changes.
    }
    if (fault == 11)
    {
        changed[6] = 8; // Q08 instead of the required V3 Q07, with a correct tag.
        B07ResignMAC(changed, seed.ToRSeq(), monitoringKey);
        B07CheckMAC(HexConversions::to_hex(rseq_t(changed.data(), changed.size())),
                    seed.ToRSeq(), monitoringKey);
    }
    if (fault == 2)
        REQUIRE(B07Envelope(HexConversions::to_hex(rseq_t(changed.data(), changed.size())), true, 1) == native);
    if (fault == 1)
        REQUIRE_FALSE(pair.master.context->OnReceive(Message(Addresses(99, pair.master.addresses.source),
                                                             rseq_t(changed.data(), changed.size()))));
    else REQUIRE(pair.master.SendToMaster(HexConversions::to_hex(rseq_t(changed.data(), changed.size()))));
    REQUIRE(pair.results.values.empty());
    REQUIRE(pair.master.meas->TotalReceived() == measurements);
    REQUIRE(ProductionAuthenticationTestAccess::MonitoringSequence(*pair.master.context) == monitoringCSQ);
    REQUIRE(ProductionAuthenticationTestAccess::Common(*pair.master.context).RemainingMessages() == commonBudget);
    REQUIRE(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2).RemainingMessages() == controlBudget);
    REQUIRE(pair.master.context->activeTask);
    if (unsolicited)
        REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(pair.outstation.context)
            == OutstationChallenger::State::WAITING_FOR_REPLY);
    REQUIRE(pair.master.context->confirmQueue.empty());
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(ProductionAuthenticationTestAccess::ResponderState(*pair.master.context) == state);
    REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == successes);
    const auto borrowed = unsolicited ? pair.master.context->txBuffer.as_rslice().take(heldRequest.ToRSeq().length())
        : ProductionAuthenticationTestAccess::AggressiveBytes(*pair.master.context, heldRequest.ToRSeq().length());
    REQUIRE(borrowed.equals(heldRequest.ToRSeq()));
    REQUIRE(ProductionAuthenticationTestAccess::AggressiveBytes(pair.outstation.context, packet.ToRSeq().length()).equals(packet.ToRSeq()));
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == selections);
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.OnTxReady();
    // Rejection did not consume the authentic CSQ. The original wire still authenticates once.
    REQUIRE(pair.master.SendToMaster(response));
    pair.master.exe->run_many();
    REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == successes + 1);
    const auto delivered = pair.master.meas->TotalReceived();
    if (unsolicited) REQUIRE(delivered > measurements);
    REQUIRE(pair.master.SendToMaster(response)); // Monitoring replay must not redeliver, confirm, or complete a task twice.
    REQUIRE(pair.master.meas->TotalReceived() == delivered);
    REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == successes + 1);
    if (unsolicited)
    {
        REQUIRE(pair.master.context->confirmQueue.size() == 1);
        const auto reply = ReplyFC6(pair, controlChallenge); // Same V1/V2 wire ownership as FC6; original task is SELECT.
        pair.outstation.SendToOutstation(reply);
        REQUIRE(pair.outstation.cmdHandler->NumSelect() == selections + 1);
        REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);
        REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(pair.outstation.context) == OutstationChallenger::State::IDLE);
        // Deliver the genuine SELECT response before releasing the borrowed Reply TX.
        // Otherwise Pump sends the queued CONFIRM ahead of the SELECT monitoring
        // exchange, leaving its authentication owner pending and blocking OPERATE.
        REQUIRE(pair.outstation.lower->NumWrites() == 1);
        const auto selectResponse = pair.outstation.lower->PopWriteAsHex();
        pair.outstation.OnTxReady();
        REQUIRE(pair.master.SendToMaster(selectResponse));
        REQUIRE(pair.master.context->OnTxReady());
        pair.Pump(); // Finish SELECT monitoring, the unsolicited CONFIRM, and OPERATE.

        REQUIRE(pair.results.values.size() == 1);
        REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
        REQUIRE(pair.results.values.front().results.size() == 1);
        REQUIRE(pair.results.values.front().results.front().status == CommandStatus::SUCCESS);
        REQUIRE(pair.outstation.cmdHandler->NumSelect() == selections + 1);
        REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations + 1);
        REQUIRE(pair.master.context->confirmQueue.empty());
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::ProtectedConfirm(*pair.master.context));
        REQUIRE_FALSE(pair.master.context->activeTask);
        REQUIRE(pair.master.context->tstate == MContext::TaskState::IDLE);
        REQUIRE_FALSE(pair.master.context->isSending);
        REQUIRE_FALSE(ProductionAuthenticationTestAccess::Transmitting(pair.outstation.context));
        REQUIRE(ProductionAuthenticationTestAccess::IsIdle(pair.outstation.context));
        REQUIRE(pair.master.lower->NumWrites() == 0);
        REQUIRE(pair.outstation.lower->NumWrites() == 0);
    }
    else
    {
        REQUIRE(pair.results.values.size() == 1);
        REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
    }
}


TEST_CASE("ProductionAuthentication - authenticated unsolicited CONFIRM preserves G41 selection",
          "[production-sa][sa-b07][g41-sa-confirm]")
{
    const auto variation = GENERATE(1u, 2u, 3u);
    const bool wide = GENERATE(false, true);
    CAPTURE(variation, wide);

    const uint16_t index = wide ? 0x1234 : 3;

    RuntimePair pair(true, true, false, nullptr, false, nullptr, 2,
                     false, 2000, 2000, true,
                     IndexQualifierMode::allow_one_byte);

    B07Prime(pair, true);

    const auto selections = pair.outstation.cmdHandler->NumSelect();
    const auto operations = pair.outstation.cmdHandler->NumOperate();
    const auto& confirms = pair.outstation.application->confirms;
    const auto confirmed = confirms.size();

    pair.outstation.Transaction([](IUpdateHandler& update) {
        update.Update(Binary(true), 0);
    });

    REQUIRE(pair.outstation.lower->NumWrites() == 1);

    const auto eventWire = pair.outstation.lower->PopWriteAsHex();
    const auto event = B07Envelope(eventWire, true, 1);

    REQUIRE(event.size() > 4);
    REQUIRE(event[1] == 0x82);
    REQUIRE((event[0] & 0x30) == 0x30);
    REQUIRE(event[4] == 2);

    const auto eventSequence = event[0] & 0x0F;

    pair.outstation.OnTxReady();

    auto config = TaskConfig::Default();
    config.authenticationUser = 2;

    pair.master.context->SelectAndOperate(
        FC6Commands(variation, index),
        pair.results.Callback(),
        config);

    pair.master.exe->run_many();

    REQUIRE(pair.master.lower->NumWrites() == 1);

    const auto selectWire = pair.master.lower->PopWriteAsHex();
    const auto select = B07Envelope(selectWire, false, 2);

    REQUIRE(select.size() > 5);
    REQUIRE(select[1] == 3);
    REQUIRE(select[2] == 41);
    REQUIRE(select[3] == variation);
    REQUIRE(select[4] == (wide ? 0x28 : 0x17));
    REQUIRE(select.back() == 0);

    const auto selectSequence = select[0] & 0x0F;
    const auto operateSequence = (selectSequence + 1) & 0x0F;
    const auto selectedObjects =
        rseq_t(select.data(), select.size()).skip(2);

    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(selectWire);

    REQUIRE(pair.outstation.cmdHandler->NumSelect() == selections + 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);

    const auto selectResponseWire =
        pair.outstation.lower->PopWriteAsHex();

    const auto selectResponse =
        B07Envelope(selectResponseWire, true, 1);

    REQUIRE(selectResponse[1] == 0x81);
    REQUIRE((selectResponse[0] & 0x0F) == selectSequence);

    REQUIRE(rseq_t(selectResponse.data(), selectResponse.size())
                .skip(4).equals(selectedObjects));

    pair.outstation.OnTxReady();

    // Deliver the previously emitted unsolicited event before
    // the SELECT echo. Retain the FC0 transmit ownership.
    REQUIRE(pair.master.SendToMaster(eventWire));
    pair.master.exe->run_many();

    REQUIRE(pair.master.lower->NumWrites() == 1);

    const auto confirmWire = pair.master.lower->PopWriteAsHex();
    HexSequence confirm(confirmWire);

    REQUIRE(confirm.ToRSeq().length() == 2);
    REQUIRE(confirm.ToRSeq()[0] == (0xD0 | eventSequence));
    REQUIRE(confirm.ToRSeq()[1] == 0);

    REQUIRE(pair.master.context->solSeq.Get() == selectSequence);

    REQUIRE(pair.master.SendToMaster(selectResponseWire));
    pair.master.exe->run_many();

    REQUIRE(pair.master.context->solSeq.Get() == operateSequence);
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.results.values.empty());

    auto& stats =
        ProductionAuthenticationTestAccess::Stats(
            pair.outstation.context);

    const auto authenticated =
        stats.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);

    // Bare CONFIRM must not release the unsolicited event.
    pair.outstation.SendToOutstation(confirmWire);

    REQUIRE(confirms.size() == confirmed);

    REQUIRE(stats.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS)
            == authenticated);

    REQUIRE(pair.outstation.lower->NumWrites() == 1);

    const auto challengeWire =
        pair.outstation.lower->PopWriteAsHex();

    HexSequence challengePacket(challengeWire);
    const auto challenge = challengePacket.ToRSeq();

    REQUIRE(challenge.length() >= 10);
    REQUIRE(challenge[1] == 0x83);
    REQUIRE((challenge[0] & 0x0F) == eventSequence);
    REQUIRE(challenge[4] == 120);
    REQUIRE(challenge[5] == 1);
    REQUIRE(challenge[6] == 0x5B);

    Group120Var1 challengeObject;
    REQUIRE(challengeObject.Read(challenge.skip(10)));

    pair.outstation.OnTxReady();

    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(pair.master.lower->NumWrites() == 0);

    const auto replyWire = ReplyFC6(pair, challengeWire);

    HexSequence replyPacket(replyWire);
    const auto reply = replyPacket.ToRSeq();

    REQUIRE(reply.length() >= 8);
    REQUIRE((reply[0] & 0x0F) == eventSequence);
    REQUIRE(reply[4] == 0x5B);

    Group120Var2 replyObject;
    REQUIRE(replyObject.Read(reply.skip(8)));
    REQUIRE(replyObject.userNum == 1);
    REQUIRE(replyObject.seqNum == challengeObject.seqNum);

    // Authenticate CONFIRM as common user 1 before releasing
    // the matching user-2 OPERATE.
    pair.outstation.SendToOutstation(replyWire);

    REQUIRE(stats.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS)
            == authenticated + 1);

    REQUIRE(confirms.size() == confirmed + 1);
    REQUIRE(confirms.back().is_unsolicited);

    REQUIRE(ProductionAuthenticationTestAccess::IsIdle(
        pair.outstation.context));

    REQUIRE(pair.outstation.cmdHandler->NumSelect() == selections + 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);

    REQUIRE(pair.master.context->solSeq.Get() == operateSequence);
    REQUIRE(pair.master.lower->NumWrites() == 0);

    REQUIRE(pair.master.context->OnTxReady());
    REQUIRE(pair.master.lower->NumWrites() == 1);

    const auto operateWire =
        pair.master.lower->PopWriteAsHex();

    const auto operate = B07Envelope(operateWire, false, 2);

    REQUIRE(operate[1] == 4);
    REQUIRE((operate[0] & 0x0F) == operateSequence);

    REQUIRE(rseq_t(operate.data(), operate.size())
                .skip(2).equals(selectedObjects));

    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(operateWire);

    REQUIRE(stats.Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS)
            == authenticated + 2);

    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations + 1);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);

    const auto operateResponseWire =
        pair.outstation.lower->PopWriteAsHex();

    const auto operateResponse =
        B07Envelope(operateResponseWire, true, 1);

    REQUIRE(operateResponse[1] == 0x81);
    REQUIRE((operateResponse[0] & 0x0F) == operateSequence);

    REQUIRE(rseq_t(operateResponse.data(), operateResponse.size())
                .skip(4).equals(selectedObjects));

    pair.outstation.OnTxReady();

    REQUIRE(pair.master.SendToMaster(operateResponseWire));
    pair.master.exe->run_many();

    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
    REQUIRE(pair.results.values.front().results.size() == 1);

    const auto& point = pair.results.values.front().results.front();

    REQUIRE(point.index == index);
    REQUIRE(point.state == CommandPointState::SUCCESS);
    REQUIRE(point.status == CommandStatus::SUCCESS);

    REQUIRE(confirms.size() == confirmed + 1);
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == selections + 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations + 1);
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);

    // This fixture has capacity for one binary event.
    // A new event must fit without overflow after CONFIRM.
    pair.outstation.Transaction([](IUpdateHandler& update) {
        update.Update(Binary(false), 0);
    });

    REQUIRE(pair.outstation.lower->NumWrites() == 1);

    REQUIRE_FALSE(ProductionAuthenticationTestAccess::ResponseIIN(
        pair.outstation.context).IsSet(IINBit::EVENT_BUFFER_OVERFLOW));

    pair.Pump();

    REQUIRE(confirms.size() == confirmed + 2);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations + 1);
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
}

TEST_CASE("ProductionAuthentication - B07 expired monitoring keys and reconnect reject retained Aggressive responses",
          "[production-sa][sa-b07]")
{
    const bool unsolicited = GENERATE(false, true);
    RuntimePair pair(unsolicited, true, false, nullptr, false, nullptr, 2, false, 2000, 2000, unsolicited);
    pair.Pump();
    const auto masterNow = [&]() -> uint64_t {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            pair.master.exe->get_time().time_since_epoch()).count());
    };
    // Existing snapshots wipe their private key copies and expose only boolean comparisons.
    MACPolicySessionSnapshot oldMaster1(ProductionAuthenticationTestAccess::Session(*pair.master.context, 1), masterNow());
    MACPolicySessionSnapshot oldMaster2(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2), masterNow());
    MACPolicySessionSnapshot oldOut1(ProductionAuthenticationTestAccess::Session(pair.outstation.context, 1),
                                   ProductionAuthenticationTestAccess::Now(pair.outstation.context));
    MACPolicySessionSnapshot oldOut2(ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2),
                                   ProductionAuthenticationTestAccess::Now(pair.outstation.context));
    if (unsolicited)
    {
        pair.outstation.AdvanceTime(OutSettings(pair.source, pair.policy, true).params.unsolConfirmTimeout);
        pair.Pump();
        pair.outstation.Transaction([](IUpdateHandler& update) { update.Update(Binary(true), 0); });
    }
    else
    {
        pair.SelectOperate(); pair.Pump(); pair.results.values.clear();
        auto config = TaskConfig::Default(); config.authenticationUser = 2;
        pair.master.context->DirectOperate(FC6Commands(0, 3), pair.results.Callback(), config);
        pair.master.exe->run_many();
        REQUIRE(pair.master.lower->NumWrites() == 1);
        const auto request = pair.master.lower->PopWriteAsHex();
        REQUIRE(pair.master.context->OnTxReady());
        pair.outstation.SendToOutstation(request);
    }
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto response = pair.outstation.lower->PopWriteAsHex();
    B07Envelope(response, true, 1);
    HexSequence held(response);
    const auto successes = ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);
    const auto measurements = pair.master.meas->TotalReceived();
    const auto operations = pair.outstation.cmdHandler->NumOperate();
    const auto expiry = ProductionAuthenticationTestAccess::Common(*pair.master.context).ValidUntil();
    pair.master.exe->advance_time(std::chrono::milliseconds(expiry)); // Both Master users expire; no key injection.
    REQUIRE(pair.master.SendToMaster(response));
    REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == successes);
    REQUIRE(pair.master.meas->TotalReceived() == measurements);
    REQUIRE(pair.results.values.empty());
    REQUIRE(pair.master.context->confirmQueue.empty());
    REQUIRE(ProductionAuthenticationTestAccess::AggressiveBytes(pair.outstation.context, held.ToRSeq().length()).equals(held.ToRSeq()));
    // Cancel the borrowed lower-layer TX before reconnect, then negotiate through
    // the real V4/V5/V6/V5 path. The old transcript must not gain eligibility.
    REQUIRE(pair.master.context->OnLowerLayerDown());
    pair.outstation.LowerLayerDown();
    pair.outstation.LowerLayerUp();
    REQUIRE(pair.master.context->OnLowerLayerUp());
    pair.master.exe->run_many(); pair.Pump();
    const auto afterReconnect = ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);
    const auto callbacks = pair.results.values.size();
    REQUIRE(pair.master.SendToMaster(response));
    REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == afterReconnect);
    REQUIRE(pair.master.meas->TotalReceived() == measurements);
    REQUIRE(pair.results.values.size() == callbacks);
    REQUIRE(pair.master.context->confirmQueue.empty());
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == operations);

    // Prove renewed sessions on both peers, rather than relying on Pump's lack of writes.
    const auto fresh = [](const MACPolicySessionSnapshot& old, SessionKeys& session, uint64_t now) {
        REQUIRE(session.Ready(now));
        REQUIRE_FALSE(session.IsExchanging());
        REQUIRE(session.Sequence() != old.sequence);
        REQUIRE(session.ControlKey(now).length() == old.control.size());
        REQUIRE(session.MonitoringKey(now).length() == old.monitoring.size());
        REQUIRE_FALSE(crypto::ConstantTimeEqual(session.ControlKey(now), rseq_t(old.control.data(), old.control.size())));
        REQUIRE_FALSE(crypto::ConstantTimeEqual(session.MonitoringKey(now), rseq_t(old.monitoring.data(), old.monitoring.size())));
    };
    fresh(oldMaster1, ProductionAuthenticationTestAccess::Session(*pair.master.context, 1), masterNow());
    fresh(oldMaster2, ProductionAuthenticationTestAccess::Session(*pair.master.context, 2), masterNow());
    fresh(oldOut1, ProductionAuthenticationTestAccess::Session(pair.outstation.context, 1),
          ProductionAuthenticationTestAccess::Now(pair.outstation.context));
    fresh(oldOut2, ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2),
          ProductionAuthenticationTestAccess::Now(pair.outstation.context));
    for (uint16_t user : {uint16_t(1), uint16_t(2)})
    {
        auto& master = ProductionAuthenticationTestAccess::Session(*pair.master.context, user);
        auto& out = ProductionAuthenticationTestAccess::Session(pair.outstation.context, user);
        const auto outNow = ProductionAuthenticationTestAccess::Now(pair.outstation.context);
        REQUIRE(master.Sequence() == out.Sequence());
        REQUIRE(crypto::ConstantTimeEqual(master.ControlKey(masterNow()), out.ControlKey(outNow)));
        REQUIRE(crypto::ConstantTimeEqual(master.MonitoringKey(masterNow()), out.MonitoringKey(outNow)));
    }

    const auto repliesBeforePrime = pair.monitorReplies;
    if (unsolicited)
    {
        // Re-establish UNS history with the genuine startup null Challenge/Reply and CONFIRM.
        pair.outstation.AdvanceTime(OutSettings(pair.source, pair.policy, true).params.unsolConfirmTimeout);
        pair.Pump();
        REQUIRE(ProductionAuthenticationTestAccess::StartupNullConfirmed(pair.outstation.context));
        REQUIRE(pair.monitorReplies > repliesBeforePrime);
    }
    pair.SelectOperate(); pair.Pump(); // Real user-2 control and solicited user-1 monitoring exchanges.
    REQUIRE(pair.results.values.size() == callbacks + 1);
    REQUIRE(pair.results.values.back().summary == TaskCompletion::SUCCESS);
    REQUIRE(pair.monitorReplies > repliesBeforePrime);
    REQUIRE(ProductionAuthenticationTestAccess::IsIdle(pair.outstation.context));
    REQUIRE(pair.master.context->confirmQueue.empty());
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);

    std::string currentRequest;
    if (unsolicited)
        pair.outstation.Transaction([](IUpdateHandler& update) { update.Update(Binary(false), 0); });
    else
    {
        auto config = TaskConfig::Default(); config.authenticationUser = 2;
        pair.master.context->DirectOperate(FC6Commands(0, 3), pair.results.Callback(), config);
        pair.master.exe->run_many();
        REQUIRE(pair.master.lower->NumWrites() == 1);
        currentRequest = pair.master.lower->PopWriteAsHex();
        B07Envelope(currentRequest, false, 2);
        // Keep the Master TX borrowed as well as the independent Outstation response TX.
        pair.outstation.SendToOutstation(currentRequest);
    }
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    const auto currentResponse = pair.outstation.lower->PopWriteAsHex();
    const auto native = B07Envelope(currentResponse, true, 1);
    REQUIRE(native[1] == (unsolicited ? 0x82 : 0x81));
    HexSequence current(currentResponse);
    MACPolicySessionSnapshot renewedMaster1(ProductionAuthenticationTestAccess::Session(*pair.master.context, 1), masterNow());
    MACPolicySessionSnapshot renewedMaster2(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2), masterNow());
    MACPolicySessionSnapshot renewedOut1(ProductionAuthenticationTestAccess::Session(pair.outstation.context, 1),
                                       ProductionAuthenticationTestAccess::Now(pair.outstation.context));
    MACPolicySessionSnapshot renewedOut2(ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2),
                                       ProductionAuthenticationTestAccess::Now(pair.outstation.context));
    const auto currentSuccesses = ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);
    const auto currentMeasurements = pair.master.meas->TotalReceived();
    const auto currentCallbacks = pair.results.values.size();
    const auto currentOperations = pair.outstation.cmdHandler->NumOperate();
    const auto currentSelections = pair.outstation.cmdHandler->NumSelect();
    REQUIRE(currentCallbacks == callbacks + 1);
    const auto task = pair.master.context->activeTask;
    if (!unsolicited)
    {
        REQUIRE(task);
        REQUIRE(ProductionAuthenticationTestAccess::ReplyIssued(*pair.master.context));
    }
    const auto taskState = pair.master.context->tstate;
    const auto responder = ProductionAuthenticationTestAccess::ResponderState(*pair.master.context);
    const auto challenger = ProductionAuthenticationTestAccess::ChallengeState(pair.outstation.context);
    REQUIRE(ProductionAuthenticationTestAccess::Transmitting(pair.outstation.context));
    REQUIRE(pair.master.SendToMaster(response)); // Old session transcript, after genuine renewed eligibility.
    REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == currentSuccesses);
    REQUIRE(pair.master.meas->TotalReceived() == currentMeasurements);
    REQUIRE(pair.results.values.size() == currentCallbacks);
    REQUIRE(pair.master.context->activeTask == task);
    REQUIRE(pair.master.context->tstate == taskState);
    REQUIRE(ProductionAuthenticationTestAccess::ResponderState(*pair.master.context) == responder);
    REQUIRE(ProductionAuthenticationTestAccess::ChallengeState(pair.outstation.context) == challenger);
    REQUIRE(pair.master.context->confirmQueue.empty());
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == currentOperations);
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == currentSelections);
    REQUIRE(ProductionAuthenticationTestAccess::Transmitting(pair.outstation.context));
    renewedMaster1.Check(ProductionAuthenticationTestAccess::Session(*pair.master.context, 1), masterNow());
    renewedMaster2.Check(ProductionAuthenticationTestAccess::Session(*pair.master.context, 2), masterNow());
    renewedOut1.Check(ProductionAuthenticationTestAccess::Session(pair.outstation.context, 1), ProductionAuthenticationTestAccess::Now(pair.outstation.context));
    renewedOut2.Check(ProductionAuthenticationTestAccess::Session(pair.outstation.context, 2), ProductionAuthenticationTestAccess::Now(pair.outstation.context));
    REQUIRE(ProductionAuthenticationTestAccess::AggressiveBytes(pair.outstation.context, current.ToRSeq().length()).equals(current.ToRSeq()));
    if (!unsolicited)
    {
        HexSequence request(currentRequest);
        REQUIRE(ProductionAuthenticationTestAccess::AggressiveBytes(*pair.master.context, request.ToRSeq().length()).equals(request.ToRSeq()));
        REQUIRE(pair.master.context->OnTxReady());
    }
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(currentResponse));
    pair.master.exe->run_many();
    REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == currentSuccesses + 1);
    REQUIRE(pair.master.meas->TotalReceived() == currentMeasurements + (unsolicited ? 1 : 0));
    REQUIRE(pair.results.values.size() == currentCallbacks + (unsolicited ? 0 : 1));
    if (!unsolicited) REQUIRE(pair.results.values.back().summary == TaskCompletion::SUCCESS);
    const auto confirmWrites = pair.master.lower->NumWrites();
    REQUIRE(confirmWrites == (unsolicited ? 1 : 0));
    const auto confirmPending = ProductionAuthenticationTestAccess::ProtectedConfirm(*pair.master.context);
    REQUIRE(confirmPending == unsolicited);
    REQUIRE(pair.master.context->isSending == unsolicited);
    const auto confirmBytes = HexConversions::to_hex(pair.master.context->txBuffer.as_rslice().take(2));
    const auto confirmCount = pair.master.context->confirmQueue.size();
    // Duplicate rejection must also preserve the newly owned, in-flight native CONFIRM.
    REQUIRE(pair.master.SendToMaster(currentResponse));
    REQUIRE(ProductionAuthenticationTestAccess::Stats(*pair.master.context).Value(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS) == currentSuccesses + 1);
    REQUIRE(pair.master.meas->TotalReceived() == currentMeasurements + (unsolicited ? 1 : 0));
    REQUIRE(pair.results.values.size() == currentCallbacks + (unsolicited ? 0 : 1));
    REQUIRE(pair.master.lower->NumWrites() == confirmWrites);
    REQUIRE(pair.master.context->confirmQueue.size() == confirmCount);
    REQUIRE(pair.master.context->isSending == unsolicited);
    REQUIRE(HexConversions::to_hex(pair.master.context->txBuffer.as_rslice().take(2)) == confirmBytes);
    REQUIRE(ProductionAuthenticationTestAccess::ProtectedConfirm(*pair.master.context) == confirmPending);
    pair.Pump(); // Complete only the genuine current response's CONFIRM exchange.
    REQUIRE(ProductionAuthenticationTestAccess::IsIdle(pair.outstation.context));
    REQUIRE(pair.master.context->confirmQueue.empty());
    REQUIRE(pair.master.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.lower->NumWrites() == 0);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == currentOperations);
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == currentSelections);
}
