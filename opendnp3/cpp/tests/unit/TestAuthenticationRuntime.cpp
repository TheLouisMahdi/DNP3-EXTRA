// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_SA_RUNTIME_TESTING
#error Test-only authentication provisioning must only be compiled in unittests.
#endif

#include "utils/BufferHelpers.h"
#include "utils/CommandCallbackQueue.h"
#include "utils/MasterTestFixture.h"
#include "utils/OutstationTestObject.h"

#include <ser4cpp/util/HexConversions.h>

#include <catch.hpp>

#include <array>
#include <vector>

using namespace opendnp3;
using namespace ser4cpp;

namespace opendnp3
{
// Definition and enabling code exist ONLY in this unit-test translation unit.
// Neither this class nor a provisioning symbol is in the production library/API.
class AuthenticationRuntimeTestAccess final
{
public:
    static bool Provision(MContext& context, rseq_t key)
    {
        if (context.isOnline)
            return false;
        auto state = std::make_shared<MContext::AuthenticationState>(1, 16);
        const auto now = Now(context.executor);
        if (state->responder.SetSessionKey(1, key, now + 100000, now) != MasterResponder::Result::OK)
            return false;
        context.authentication = state;
        return true;
    }
    static bool Provision(OContext& context, rseq_t key)
    {
        if (context.isOnline)
            return false;
        auto state = std::make_shared<OContext::AuthenticationState>(1, 16);
        const auto now = Now(context.executor);
        if (state->challenger.SetSessionKey(1, key, now + 100000, now) != OutstationChallenger::Result::OK)
            return false;
        context.authentication = state;
        return true;
    }
    static bool MasterHasNoKeys(const MContext& context)
    {
        return context.authentication
            && context.authentication->responder.GetState() == MasterResponder::State::NO_SESSION_KEYS
            && !context.authentication->replyPending;
    }
    static bool OutstationHasNoKeys(const OContext& context)
    {
        return context.authentication
            && context.authentication->challenger.GetState() == OutstationChallenger::State::NO_SESSION_KEYS;
    }

private:
    static uint64_t Now(const std::shared_ptr<exe4cpp::IExecutor>& executor)
    {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
    }
};
} // namespace opendnp3

namespace
{
MasterParams MasterConfig()
{
    auto params = NoStartupTasks();
    params.ignoreRestartIIN = true;
    return params;
}

OutstationConfig OutstationConfigForTest()
{
    OutstationConfig config;
    config.params.allowUnsolicited = false;
    return config;
}

struct AuthenticationPair
{
    CommandCallbackQueue results; // callback storage outlives both runtime fixtures
    MasterTestFixture master{MasterConfig(), Addresses()};
    OutstationTestObject outstation{OutstationConfigForTest()};
    std::array<uint8_t, 32> key;
    std::string original;
    std::string challenge;
    std::string reply;

    explicit AuthenticationPair(bool enable = true)
    {
        key.fill(0x11); // public, test-only material, never a production default.
        if (enable)
        {
            REQUIRE(AuthenticationRuntimeTestAccess::Provision(*master.context, ReadKey()));
            REQUIRE(AuthenticationRuntimeTestAccess::Provision(outstation.context, ReadKey()));
        }
        REQUIRE(master.context->OnLowerLayerUp());
        master.exe->run_many();
        outstation.LowerLayerUp();
        REQUIRE(master.lower->HasNoData());
        REQUIRE(outstation.lower->HasNoData());
    }
    rseq_t ReadKey()
    {
        return rseq_t(key.data(), key.size());
    }

    void Start(bool direct = false, bool completeOriginalTx = true)
    {
        CommandSet commands({WithIndex(ControlRelayOutputBlock(OperationType::LATCH_ON), 3)});
        if (direct)
            master.context->DirectOperate(std::move(commands), results.Callback(), TaskConfig::Default());
        else
            master.context->SelectAndOperate(std::move(commands), results.Callback(), TaskConfig::Default());
        master.exe->run_many();
        REQUIRE(master.lower->NumWrites() == 1);
        original = master.lower->PopWriteAsHex();
        if (completeOriginalTx)
            REQUIRE(master.context->OnTxReady());
        outstation.SendToOutstation(original);
    }

    void MakeReply(bool completeChallengeTx = true)
    {
        REQUIRE(outstation.cmdHandler->NumInvocations() == 0);
        REQUIRE(outstation.lower->NumWrites() == 1);
        challenge = outstation.lower->PopWriteAsHex();
        HexSequence encoded(challenge);
        REQUIRE(encoded.ToRSeq()[1] == 0x83);
        if (completeChallengeTx)
            outstation.OnTxReady();
        REQUIRE(master.SendToMaster(challenge));
        REQUIRE(master.lower->NumWrites() == 1);
        reply = master.lower->PopWriteAsHex();
        HexSequence auth(reply);
        REQUIRE(auth.ToRSeq()[1] == 0x20);
        REQUIRE(master.context->OnTxReady());
    }

    void DeliverAuthorizedReply()
    {
        outstation.SendToOutstation(reply);
        REQUIRE(outstation.lower->NumWrites() == 1);
        auto response = outstation.lower->PopWriteAsHex();
        HexSequence encoded(response);
        REQUIRE(encoded.ToRSeq()[1] == 0x81);
        outstation.OnTxReady();
        REQUIRE(master.SendToMaster(response));
        master.exe->run_many();
    }
};
} // namespace

TEST_CASE("AuthenticationRuntime - authenticated SELECT OPERATE is one shot", "[sa5a]")
{
    AuthenticationPair pair;
    pair.Start();
    pair.MakeReply();
    pair.DeliverAuthorizedReply();
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
    REQUIRE(pair.results.values.empty());

    REQUIRE(pair.master.lower->NumWrites() == 1);
    auto operate = pair.master.lower->PopWriteAsHex();
    HexSequence op(operate);
    REQUIRE(op.ToRSeq()[1] == 0x04);
    REQUIRE(pair.master.context->OnTxReady());
    pair.outstation.SendToOutstation(operate);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 0);
    auto challenge = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(challenge));
    pair.reply = pair.master.lower->PopWriteAsHex();
    REQUIRE(pair.master.context->OnTxReady());
    pair.DeliverAuthorizedReply();
    REQUIRE(pair.outstation.cmdHandler->NumSelect() == 1);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);

    pair.outstation.SendToOutstation(pair.reply); // replay after success
    pair.outstation.SendToOutstation(pair.reply);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 2);
    REQUIRE(pair.outstation.lower->HasNoData());
}

TEST_CASE("AuthenticationRuntime - invalid MAC malformed Reply and replay never execute", "[sa5a]")
{
    AuthenticationPair pair;
    pair.Start(true);
    pair.MakeReply();
    HexSequence original(pair.reply);
    std::vector<uint8_t> invalid(static_cast<const uint8_t*>(original.ToRSeq()),
                                 static_cast<const uint8_t*>(original.ToRSeq()) + original.ToRSeq().length());
    SECTION("invalid MAC")
    {
        invalid.back() ^= 1;
    }
    SECTION("wrong application sequence")
    {
        invalid[0] ^= 1;
    }
    SECTION("extra object/header cannot release a request")
    {
        const auto copy = invalid;
        invalid.insert(invalid.end(), copy.begin() + 2, copy.end());
    }
    SECTION("unexpected authentication function")
    {
        invalid[1] = 0x21;
    }
    pair.outstation.SendToOutstation(HexConversions::to_hex(rseq_t(invalid.data(), invalid.size())));
    pair.outstation.SendToOutstation(pair.reply);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    REQUIRE(pair.outstation.lower->HasNoData());
}

TEST_CASE("AuthenticationRuntime - unauthenticated no ack broadcast and deferred paths are gated", "[sa5a]")
{
    AuthenticationPair pair;
    pair.Start(); // SELECT is pending; no Select callback yet.
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    // Direct Operate No Ack would normally bypass response/deferred handling.
    pair.outstation.SendToOutstation("C1 06 0C 01 17 01 03 03 01 64 00 00 00 00 00 00 00 00");
    pair.outstation.SendToOutstation("C1 05 0C 01 17 01 03 03 01 64 00 00 00 00 00 00 00 00");
    pair.outstation.BroadcastToOutstation(LinkBroadcastAddress::DontConfirm,
                                          "C1 06 0C 01 17 01 03 03 01 64 00 00 00 00 00 00 00 00");
    pair.outstation.OnTxReady();
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    REQUIRE(pair.outstation.lower->NumWrites() == 1); // original Challenge only
    pair.outstation.AdvanceTime(TimeDuration::Milliseconds(2000));
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("AuthenticationRuntime - valid Reply while Challenge tx is in flight defers only authenticated request",
          "[sa5a]")
{
    AuthenticationPair pair;
    pair.Start(true);
    pair.MakeReply(false);
    pair.outstation.SendToOutstation(pair.reply);
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    REQUIRE(pair.outstation.lower->HasNoData());
    pair.outstation.OnTxReady();
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    pair.outstation.SendToOutstation(pair.reply);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
}

TEST_CASE("AuthenticationRuntime - Master queues authentication Reply without changing in flight request", "[sa5a]")
{
    AuthenticationPair pair;
    pair.Start(true, false);
    const auto sent = pair.original;
    auto challenge = pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(challenge));
    REQUIRE(pair.master.lower->HasNoData()); // original transmission not completed
    SECTION("disconnect discards a queued authentication Reply")
    {
        REQUIRE(pair.master.context->OnLowerLayerDown());
        REQUIRE(AuthenticationRuntimeTestAccess::MasterHasNoKeys(*pair.master.context));
        REQUIRE(pair.master.context->OnLowerLayerUp());
        pair.master.exe->run_many();
        REQUIRE_FALSE(pair.master.context->OnTxReady());
        REQUIRE(pair.master.lower->HasNoData());
        REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
        return;
    }
    SECTION("complete original tx before sending authentication Reply") {}
    HexSequence original(sent);
    REQUIRE(pair.master.context->txBuffer.as_rslice().take(original.ToRSeq().length()).equals(original.ToRSeq()));
    REQUIRE(pair.master.context->OnTxReady());
    pair.reply = pair.master.lower->PopWriteAsHex();
    REQUIRE(pair.master.context->OnTxReady());
    pair.DeliverAuthorizedReply();
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
}

TEST_CASE("AuthenticationRuntime - authorization cannot be reused for a new operation", "[sa5a]")
{
    AuthenticationPair pair;
    pair.Start(true);
    pair.MakeReply();
    const auto previousReply = pair.reply;
    pair.DeliverAuthorizedReply();
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    // A different operation still needs a fresh challenge; old authorization is
    // not an association-wide permission or a reusable dispatcher bypass flag.
    pair.outstation.SendToOutstation("C1 05 0C 01 17 01 03 04 01 64 00 00 00 00 00 00 00 00");
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    REQUIRE(pair.outstation.lower->NumWrites() == 1);
    pair.outstation.lower->PopWriteAsHex();
    pair.outstation.OnTxReady();
    pair.outstation.SendToOutstation(previousReply);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    REQUIRE(pair.outstation.lower->HasNoData());
}

TEST_CASE("AuthenticationRuntime - timeout and disconnect discard authorization", "[sa5a]")
{
    AuthenticationPair pair;
    pair.Start(true);
    pair.MakeReply();
    SECTION("Reply timer expiry")
    {
        pair.outstation.AdvanceTime(TimeDuration::Milliseconds(2000));
        pair.outstation.SendToOutstation(pair.reply);
        REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
        REQUIRE(pair.outstation.lower->HasNoData());
    }
    SECTION("Outstation disconnect cannot fall back to unauthenticated execution")
    {
        pair.outstation.LowerLayerDown();
        REQUIRE(AuthenticationRuntimeTestAccess::OutstationHasNoKeys(pair.outstation.context));
        pair.outstation.LowerLayerUp();
        pair.outstation.SendToOutstation(pair.reply);
        pair.outstation.SendToOutstation(pair.original);
        REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
        REQUIRE(pair.outstation.lower->HasNoData());
    }
    SECTION("Master disconnect drops keys and pending authentication")
    {
        REQUIRE(pair.master.context->OnLowerLayerDown());
        REQUIRE(AuthenticationRuntimeTestAccess::MasterHasNoKeys(*pair.master.context));
        REQUIRE(pair.master.context->OnLowerLayerUp());
        pair.master.exe->run_many();
        REQUIRE(pair.master.SendToMaster(pair.challenge));
        REQUIRE(pair.master.lower->HasNoData());
        REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    }
}

TEST_CASE("AuthenticationRuntime - normal response cannot skip Master challenge phase", "[sa5a]")
{
    AuthenticationPair pair;
    pair.Start(true);
    REQUIRE(pair.master.SendToMaster("C0 81 00 00 0C 01 28 01 00 03 00 03 01 00 00 00 00 00 00 00 00 00"));
    REQUIRE(pair.results.values.empty());
    REQUIRE(pair.outstation.cmdHandler->NumInvocations() == 0);
    pair.master.exe->advance_time(pair.master.context->params.responseTimeout.value);
    pair.master.exe->run_many();
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary != TaskCompletion::SUCCESS);
    REQUIRE(AuthenticationRuntimeTestAccess::MasterHasNoKeys(*pair.master.context));
}

TEST_CASE("AuthenticationRuntime - production default remains non SA", "[sa5a]")
{
    AuthenticationPair pair(false);
    pair.Start(true);
    REQUIRE(pair.outstation.cmdHandler->NumOperate() == 1);
    auto response = pair.outstation.lower->PopWriteAsHex();
    HexSequence bytes(response);
    REQUIRE(bytes.ToRSeq()[1] == 0x81);
    pair.outstation.OnTxReady();
    REQUIRE(pair.master.SendToMaster(response));
    REQUIRE(pair.results.values.size() == 1);
    REQUIRE(pair.results.values.front().summary == TaskCompletion::SUCCESS);
}
