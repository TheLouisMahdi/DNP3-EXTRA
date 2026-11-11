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

#include "outstation/OutstationStates.h"

#include "logging/LogMacros.h"
#include "outstation/OutstationContext.h"

#include "opendnp3/logging/LogLevels.h"

namespace opendnp3
{

// ------------- StateIdle ----------------

StateIdle StateIdle::instance;

OutstationState& StateIdle::OnConfirm(OContext& ctx, const ParsedRequest& request)
{
    FORMAT_LOG_BLOCK(ctx.logger, flags::WARN, "unexpected confirm while IDLE with sequence: %u",
                     request.header.control.SEQ);
    return StateIdle::Inst();
}

OutstationState& StateIdle::OnConfirmTimeout(OContext& ctx)
{
    SIMPLE_LOG_BLOCK(ctx.logger, flags::WARN, "unexpected confirm timeout");
    return StateIdle::Inst();
}

OutstationState& StateIdle::OnNewReadRequest(OContext& ctx, const ParsedRequest& request)
{
    return ctx.RespondToReadRequest(request);
}

OutstationState& StateIdle::OnNewNonReadRequest(OContext& ctx, const ParsedRequest& request)
{
    return ctx.RespondToNonReadRequest(request);
}

OutstationState& StateIdle::OnRepeatNonReadRequest(OContext& ctx, const ParsedRequest& request)
{
    return ctx.RetransmitSolicitedResponse(request);
}

OutstationState& StateIdle::OnRepeatReadRequest(OContext& ctx, const ParsedRequest& request)
{
    return ctx.RetransmitSolicitedResponse(request);
}

OutstationState& StateIdle::OnBroadcastMessage(OContext& ctx, const ParsedRequest& request)
{
    ctx.AbandonSolicitedRead();
    ctx.ProcessBroadcastRequest(request);
    return *this;
}

// ------------- StateSolicitedConfirmWait ----------------

StateSolicitedConfirmWait StateSolicitedConfirmWait::instance;

OutstationState& StateSolicitedConfirmWait::OnConfirm(OContext& ctx, const ParsedRequest& request)
{
    ctx.solConfirm.Cancel();
    if (ctx.solicitedReadSelection)
        ctx.eventBuffer.ClearWritten();
    ctx.lastBroadcastMessageReceived.clear();

    // information the application about the confirm
    ctx.application->OnConfirmProcessed(
        false,
        ctx.eventBuffer.NumEvents(EventClass::EC1),
        ctx.eventBuffer.NumEvents(EventClass::EC2),
        ctx.eventBuffer.NumEvents(EventClass::EC3)
    );

    if (ctx.solicitedReadSelection && ctx.rspContext.HasSelection())
    {
        return ctx.ContinueMultiFragResponse(request.addresses, AppSeqNum(request.header.control.SEQ).Next());
    }

    if (ctx.solicitedReadSelection)
        ctx.history.Reset();
    ctx.solicitedReadSelection = false;
    return StateIdle::Inst();
}

OutstationState& StateSolicitedConfirmWait::OnConfirmTimeout(OContext& ctx)
{
    SIMPLE_LOG_BLOCK(ctx.logger, flags::WARN, "solicited confirm timeout");
    return StateIdle::Inst();
}

OutstationState& StateSolicitedConfirmWait::OnNewReadRequest(OContext& ctx, const ParsedRequest& request)
{
    ctx.solConfirm.Cancel();
    return ctx.RespondToReadRequest(request);
}

OutstationState& StateSolicitedConfirmWait::OnNewNonReadRequest(OContext& ctx, const ParsedRequest& request)
{
    ctx.solConfirm.Cancel();
    return ctx.RespondToNonReadRequest(request);
}

OutstationState& StateSolicitedConfirmWait::OnRepeatNonReadRequest(OContext& ctx, const ParsedRequest& request)
{
    return ctx.RetransmitSolicitedResponse(request);
}

OutstationState& StateSolicitedConfirmWait::OnRepeatReadRequest(OContext& ctx, const ParsedRequest& request)
{
    return ctx.RetransmitSolicitedResponse(request);
}

OutstationState& StateSolicitedConfirmWait::OnBroadcastMessage(OContext& ctx, const ParsedRequest& request)
{
    ctx.solConfirm.Cancel();
    ctx.AbandonSolicitedRead();
    ctx.ProcessBroadcastRequest(request);
    return StateIdle::Inst();
}

// ------------- StateUnsolicitedConfirmWait ----------------

StateUnsolicitedConfirmWait StateUnsolicitedConfirmWait::instance;

OutstationState& StateUnsolicitedConfirmWait::OnConfirm(OContext& ctx, const ParsedRequest& request)
{
    if (!request.header.control.UNS)
    {
        StateSolicitedConfirmWait::Inst().OnConfirm(ctx, request);
        return *this;
    }

    ctx.unsolConfirm.Cancel();
    ctx.lastBroadcastMessageReceived.clear();

    // information the application about the confirm
    ctx.application->OnConfirmProcessed(
        true,
        ctx.eventBuffer.NumEvents(EventClass::EC1),
        ctx.eventBuffer.NumEvents(EventClass::EC2),
        ctx.eventBuffer.NumEvents(EventClass::EC3)
    );

    if (ctx.unsol.completedNull)
    {
        ctx.eventBuffer.ClearWritten();
    }
    else
    {
        ctx.unsol.completedNull = true;
    }

    ctx.shouldCheckForUnsolicited = true;

    return ctx.solConfirm.active ? static_cast<OutstationState&>(StateSolicitedConfirmWait::Inst())
                                 : StateIdle::Inst();
}

OutstationState& StateUnsolicitedConfirmWait::OnConfirmTimeout(OContext& ctx)
{
    SIMPLE_LOG_BLOCK(ctx.logger, flags::WARN, "unsolicited confirm timeout");

    if (!ctx.CanTransmit())
    {
        // Process the expired wait after the other transmission relinquishes its buffer.
        ctx.unsolConfirm.timeoutPending = true;
        return *this;
    }

#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!ctx.unsol.completedNull && ctx.authentication && ctx.authentication->sessions
        && ctx.authentication->sessions->remote)
    {
        ctx.BeginRetransmitLastUnsolicitedResponse();
        ctx.RestartUnsolConfirmTimer();
        return *this;
    }
#endif
    if (ctx.unsol.completedNull)
    {
        auto shouldRetry = ctx.unsolRetries.Retry();
        if (shouldRetry && !ctx.deferred.IsSet())
        {
            ctx.BeginRetransmitLastUnsolicitedResponse();
            ctx.RestartUnsolConfirmTimer();
            return *this;
        }
        else
        {
            ctx.eventBuffer.Unselect();
        }
    }

    ctx.unsolConfirm.Cancel();
    return ctx.solConfirm.active ? static_cast<OutstationState&>(StateSolicitedConfirmWait::Inst())
                                 : StateIdle::Inst();
}

OutstationState& StateUnsolicitedConfirmWait::OnNewReadRequest(OContext& ctx, const ParsedRequest& request)
{
    ctx.solConfirm.Cancel();
    ctx.deferred.Set(request);
    return *this;
}

OutstationState& StateUnsolicitedConfirmWait::OnNewNonReadRequest(OContext& ctx, const ParsedRequest& request)
{
    ctx.deferred.Reset();
    ctx.RespondToNonReadRequest(request);
    return *this;
}

OutstationState& StateUnsolicitedConfirmWait::OnRepeatNonReadRequest(OContext& ctx, const ParsedRequest& request)
{
    ctx.deferred.Reset();
    return ctx.RetransmitSolicitedResponse(request);
}

OutstationState& StateUnsolicitedConfirmWait::OnRepeatReadRequest(OContext& ctx, const ParsedRequest& request)
{
    ctx.deferred.Set(request);
    return *this;
}

OutstationState& StateUnsolicitedConfirmWait::OnBroadcastMessage(OContext& ctx, const ParsedRequest& request)
{
    ctx.solConfirm.Cancel();
    ctx.deferred.Reset();
    ctx.ProcessBroadcastRequest(request);
    return *this;
}

// ------------- StateUnsolicitedConfirmWait ----------------

StateNullUnsolicitedConfirmWait StateNullUnsolicitedConfirmWait::instance;

OutstationState& StateNullUnsolicitedConfirmWait::OnNewReadRequest(OContext& ctx, const ParsedRequest& request)
{
    ctx.unsolConfirm.Cancel();
    return ctx.RespondToReadRequest(request);
}

} // namespace opendnp3
