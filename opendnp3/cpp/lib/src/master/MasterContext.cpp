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
#include "MasterContext.h"

#include "app/APDUBuilders.h"
#include "app/APDULogging.h"
#include "app/parsing/APDUHeaderParser.h"
#include "app/parsing/APDUParser.h"
#include "auth/AuthenticationError.h"
#include "crypto/CryptoProvider.h"
#include "gen/objects/Group12.h"
#include "gen/objects/Group41.h"
#include "logging/LogMacros.h"
#include "master/CommandTask.h"
#include "master/EmptyResponseTask.h"
#include "master/MeasurementHandler.h"
#include "master/RestartOperationTask.h"
#include "master/UserPollTask.h"
#ifdef OPENDNP3_USE_SA_CRYPTO
#include "master/UpdateKeyTask.h"
#endif

#include "opendnp3/logging/LogLevels.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace opendnp3
{
MContext::MContext(const Addresses& addresses,
                   const Logger& logger,
                   const std::shared_ptr<exe4cpp::IExecutor>& executor,
                   std::shared_ptr<ILowerLayer> lower,
                   const std::shared_ptr<ISOEHandler>& SOEHandler,
                   const std::shared_ptr<IMasterApplication>& application,
                   std::shared_ptr<IMasterScheduler> scheduler,
                   const MasterParams& params)
    : logger(logger),
      executor(executor),
      lower(std::move(lower)),
      addresses(addresses),
      params(params),
      SOEHandler(SOEHandler),
      application(application),
      scheduler(std::move(scheduler)),
      tasks(params, logger, *application, SOEHandler),
      txBuffer(params.maxTxFragSize),
      tstate(TaskState::IDLE)
{
    if (params.authentication.mode == AuthenticationConfig::Mode::REQUIRED)
    {
#ifdef OPENDNP3_USE_SA_CRYPTO
        authentication = std::make_shared<AuthenticationState>(params.authentication);
        authentication->sessions->statistics.SetLogger(&this->logger);
        const auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
        if (!authentication->sessions->Load(now))
            throw std::invalid_argument("SA credentials or policy unavailable");
#else
        throw std::invalid_argument("SA required but cryptography was disabled at build time");
#endif
    }
}

std::shared_ptr<MContext> MContext::Create(const Addresses& addresses,
                                           const Logger& logger,
                                           const std::shared_ptr<exe4cpp::IExecutor>& executor,
                                           std::shared_ptr<ILowerLayer> lower,
                                           const std::shared_ptr<ISOEHandler>& SOEHandler,
                                           const std::shared_ptr<IMasterApplication>& application,
                                           std::shared_ptr<IMasterScheduler> scheduler,
                                           const MasterParams& params)
{
    return std::shared_ptr<MContext>(
        new MContext(addresses, logger, executor, lower, SOEHandler, application, scheduler, params));
}

bool MContext::OnLowerLayerUp()
{
    if (isOnline)
    {
        return false;
    }

    isOnline = true;

    tasks.Initialize(*this->scheduler, *this);

    this->application->OnOpen();
    this->ServiceAuthentication();
    return true;
}

bool MContext::OnLowerLayerDown()
{
    if (!isOnline)
    {
        return false;
    }

    tstate = TaskState::IDLE;
    responseTimer.cancel();
    solSeq = unsolSeq = 0;
    isOnline = isSending = false;
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication)
    {
        authentication->replyInFlight = false;
        authentication->protectedTask = false;
        authentication->serviceTimer.cancel();
        authentication->wireInFlight = false;
        crypto::Clear(ser4cpp::wseq_t(authentication->pendingWire.data(), authentication->pendingWire.size()));
        authentication->pendingWireSize = 0;
        authentication->exchangeIndex = authentication->SessionCount();
        authentication->peerRestartAllowed = true;
        authentication->restartRecoveryPending = false;
        authentication->monitorWaiting = false;
        authentication->monitoring.Reset();
        DiscardEmbeddedConfirm(); // Settle the old session before disconnect invalidates it.
        if (authentication->sessions)
            authentication->sessions->Disconnect();
    }
#endif
    this->ResetAuthentication();
    this->confirmQueue.clear();
    activeTask.reset();

    this->scheduler->SetRunnerOffline(*this);
    this->application->OnClose();

    return true;
}

bool MContext::OnReceive(const Message& message)
{
    if (!this->isOnline)
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "Ignorning rx data while offline");
        return false;
    }

    if (message.addresses.destination != this->addresses.source)
    {
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Unknown destination address: %u", message.addresses.destination);
        return false;
    }

    if (message.addresses.source != this->addresses.destination)
    {
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Unexpected message source: %u", message.addresses.source);
        return false;
    }

    const auto result = APDUHeaderParser::ParseResponse(message.payload, &this->logger);
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication && authentication->sessions)
        authentication->sessions->statistics.Increment(SecurityStatistic::TOTAL_MESSAGES_RECEIVED);
#endif
    if (!result.success)
    {
#ifdef OPENDNP3_USE_SA_CRYPTO
        if (authentication && authentication->sessions)
            authentication->sessions->statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
#endif
        return true;
    }

    logging::LogHeader(this->logger, flags::APP_HEADER_RX, result.header);

#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication && authentication->sessions)
    {
        const auto now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            executor->get_time().time_since_epoch()).count());
        ServiceSecurityStatistics(now);
        auto& auth = *authentication;
        if (IsAuthenticatedNoResponseTask() && result.header.function == FunctionCode::RESPONSE)
        {
            auth.sessions->statistics.Unexpected();
            return true;
        }
        const bool normalResponse = (result.header.function == FunctionCode::RESPONSE && !result.header.control.UNS)
            || (result.header.function == FunctionCode::UNSOLICITED_RESPONSE && result.header.control.UNS);
        if (normalResponse)
        {
            const bool restart = result.header.IIN.IsSet(IINBit::DEVICE_RESTART);
            const bool rising = restart && !auth.restartIINSet;
            auth.restartIINSet = restart;
            if (rising && auth.established)
            {
                auto& statistics = auth.sessions->statistics;
                statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
                if (statistics.Exceeded(SecurityStatistic::RESTART_REKEYS)) return true;
                statistics.Increment(SecurityStatistic::RESTART_REKEYS);
                statistics.ResetMaximum(SecurityStatistic::REPLY_TIMEOUTS);
                for (size_t n = 0; n < auth.sessions->Size(); ++n) auth.sessions->At(n)->RequestPeerRestart(now);
                ResetAuthentication(); // Association restart; retain all transport-owned APDU bytes.
                crypto::Clear(ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()));
                auth.pendingWireSize = 0;
                if (auth.exchangeIndex < auth.SessionCount())
                {
                    auth.exchangeIndex = auth.SessionCount();
                    auth.exchangeSequence = (auth.exchangeSequence + 1) & 15;
                }
                auth.peerRestartAllowed = auth.restartRecoveryPending = true;
                if (activeTask && tstate == TaskState::WAIT_FOR_RESPONSE)
                {
                    responseTimer.cancel();
                    tstate = OnResponseTimeout_WaitForResponse();
                }
                ServiceAuthentication();
                return true; // Table 7-8 row 28 overrides ordinary response processing.
            }
        }
    }
#endif
    this->OnParsedHeader(message.payload, result.header, result.objects);
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication && authentication->sessions)
        ServiceSecurityStatistics(static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            executor->get_time().time_since_epoch()).count()));
#endif

    return true;
}

bool MContext::IsAuthenticatedNoResponseTask() const
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    return authentication && authentication->protectedTask && activeTask && !activeTask->ExpectsResponse()
        && (tstate == TaskState::WAIT_FOR_AUTH_REQUEST_TX || tstate == TaskState::WAIT_FOR_AUTH_CHALLENGE
            || tstate == TaskState::WAIT_FOR_AUTH_REPLY_TX || tstate == TaskState::WAIT_FOR_AGGRESSIVE_TX);
#else
    return false;
#endif
}

bool MContext::IsWaitingForNoResponseChallenge() const
{
    return IsAuthenticatedNoResponseTask()
        && (tstate == TaskState::WAIT_FOR_AUTH_REQUEST_TX || tstate == TaskState::WAIT_FOR_AUTH_CHALLENGE);
}

void MContext::CompleteAuthenticatedNoResponseTask(bool success)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!IsAuthenticatedNoResponseTask()) return;
    auto& auth = *authentication;
    // Release only this task's responder. Monitoring, queued CONFIRMs and
    // transport-owned reply/aggressive buffers have independent lifetimes.
    if (auth.responderUser == activeTask->AuthenticationUser())
    {
        auth.responder.Reset(); // Keep the responder's association-wide CSQ watermark.
        if (auth.replyPending)
        {
            auth.replyPending = false;
            auth.replySize = 0;
            crypto::Clear(ser4cpp::wseq_t(auth.reply.data(), auth.reply.size()));
        }
    }
    responseTimer.cancel();
    solSeq.Increment();
    if (success) activeTask->OnTransmitComplete(Timestamp(executor->get_time()));
    else activeTask->OnResponseTimeout(Timestamp(executor->get_time()));
    CompleteActiveTask();
    tstate = TaskState::IDLE;
#else
    (void)success;
#endif
}

bool MContext::OnTxReady()
{
    if (!this->isOnline || !this->isSending)
    {
        return false;
    }

    this->isSending = false;
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication)
    {
        auto& auth = *authentication;
        const bool replyCompleted = IsAuthenticatedNoResponseTask() && tstate == TaskState::WAIT_FOR_AUTH_REPLY_TX
            && auth.replyInFlight && auth.responderUser == activeTask->AuthenticationUser();
        const bool aggressiveCompleted = IsAuthenticatedNoResponseTask() && tstate == TaskState::WAIT_FOR_AGGRESSIVE_TX;
        if (replyCompleted || aggressiveCompleted)
        {
            const auto now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                executor->get_time().time_since_epoch()).count());
            auto* session = auth.sessions->Find(activeTask->AuthenticationUser());
            const bool valid = auth.replyIssued && session && executor->get_time() < responseTimer.expires_at()
                && (replyCompleted ? (now < auth.replyDeadline && session->Sequence() == auth.replyKSQ
                                      && (session->IsReady(now) || auth.replyCountExhausted))
                                   : (session->IsReady(now) && auth.errorAttempt.valid
                                      && session->Sequence() == auth.errorAttempt.ksq));
            CompleteAuthenticatedNoResponseTask(valid);
        }
        else if (IsAuthenticatedNoResponseTask() && tstate == TaskState::WAIT_FOR_AUTH_REQUEST_TX)
            tstate = TaskState::WAIT_FOR_AUTH_CHALLENGE;
        // The lower layer has released the previous APDU before any next TX starts.
        crypto::Clear(ser4cpp::wseq_t(authentication->aggressiveWire.data(), authentication->aggressiveWire.size()));
        if (authentication->replyInFlight)
        {
            authentication->replyInFlight = false;
            authentication->replyDeadline = authentication->replyKSQ = 0;
            authentication->replyCountExhausted = false;
            authentication->protectedConfirm = authentication->nativeConfirmQueued;
            crypto::Clear(ser4cpp::wseq_t(authentication->reply.data(), authentication->reply.size()));
        }
        if (authentication->replyPending)
        {
            this->TransmitAuthenticationReply();
            if (isSending)
                return true;
        }
        if (authentication->wireInFlight && authentication->wireSize >= 2
            && authentication->wire[1] == FunctionCodeSpec::to_type(FunctionCode::CONFIRM))
            authentication->protectedConfirm = false;
        authentication->wireInFlight = false;
        this->ServiceAuthentication();
        if (isSending)
            return true;
    }
#endif

    this->tstate = this->OnTransmitComplete();
    this->CheckConfirmTransmit();

    return true;
}

void MContext::OnResponseTimeout()
{
    if (isOnline)
    {
        if (IsAuthenticatedNoResponseTask())
        {
            CompleteAuthenticatedNoResponseTask(false);
            return;
        }
        if (!activeTask || !activeTask->IsAuthenticationTask()) this->ResetAuthentication();
        this->tstate = this->OnResponseTimeoutEvent();
    }
}

void MContext::CompleteActiveTask()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication)
    {
        authentication->protectedTask = false;
        authentication->allowUnkeyedCritical = false;
        authentication->userCritical = authentication->recoveringKeys = authentication->errorAttempt.valid = false;
        authentication->replyIssued = false;
    }
#endif
    if (this->activeTask)
    {
        this->activeTask.reset();
        this->scheduler->CompleteCurrentFor(*this);
    }
}

void MContext::OnParsedHeader(const ser4cpp::rseq_t& apdu,
                              const APDUResponseHeader& header,
                              const ser4cpp::rseq_t& objects)
{
    if (activeTask && activeTask->IsAuthenticationTask() && tstate == TaskState::WAIT_FOR_RESPONSE
        && activeTask->AcceptsAuthenticationResponse(header, objects))
    {
        InvalidateRemoteCredentials();
        ProcessResponse(header, objects);
        return;
    }
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication && authentication->sessions && authentication->sessions->remote
        && objects.length() >= 2 && objects[0] == 120
        && (objects[1] == 8 || (objects[1] >= 10 && objects[1] <= 15)))
    {
        // Remote-key Info objects have their own scheduled owner. Unowned or
        // malformed input must not enter ordinary Challenge/Reply reset paths.
        authentication->sessions->statistics.Unexpected();
        return;
    }
#endif
    if (this->RouteAuthentication(apdu, header))
        return;
    // Note: this looks silly, but OnParsedHeader() is virtual and can be overriden to do SA
    this->ProcessAPDU(header, objects);
}

/// --- command handlers ----
bool MContext::ChangeUpdateKey(const UpdateKeyRequest& request, const TaskConfig& config)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication || !authentication->sessions || !authentication->sessions->remote) return false;
    ScheduleAdhocTask(std::make_shared<UpdateKeyTask>(tasks.context, *application, logger, config,
        Timestamp(executor->get_time()) + params.taskStartTimeout, executor, authentication,
        *authentication->sessions->remote, request));
    return true;
#else
    return false;
#endif
}

void MContext::DirectOperate(CommandSet&& commands, const CommandResultCallbackT& callback, const TaskConfig& config)
{
    const auto timeout = Timestamp(this->executor->get_time()) + params.taskStartTimeout;
    this->ScheduleAdhocTask(CommandTask::CreateDirectOperate(this->tasks.context, std::move(commands),
                                                             this->params.controlQualifierMode, *application, callback,
                                                             timeout, config, logger));
}

bool MContext::DirectOperateNoAck(CommandSet&& commands,
                                  const CommandResultCallbackT& callback,
                                  const TaskConfig& config)
{
    const auto timeout = Timestamp(this->executor->get_time()) + params.taskStartTimeout;
    this->ScheduleAdhocTask(CommandTask::CreateDirectOperateNoAck(
        this->tasks.context, std::move(commands), this->params.controlQualifierMode, *application, callback, timeout,
        config, logger));
    return true;
}

void MContext::SelectAndOperate(CommandSet&& commands, const CommandResultCallbackT& callback, const TaskConfig& config)
{
    const auto timeout = Timestamp(this->executor->get_time()) + params.taskStartTimeout;
    this->ScheduleAdhocTask(CommandTask::CreateSelectAndOperate(this->tasks.context, std::move(commands),
                                                                this->params.controlQualifierMode, *application,
                                                                callback, timeout, config, logger));
}

void MContext::ProcessAPDU(const APDUResponseHeader& header, const ser4cpp::rseq_t& objects)
{
    switch (header.function)
    {
    case (FunctionCode::UNSOLICITED_RESPONSE):
        this->ProcessUnsolicitedResponse(header, objects);
        break;
    case (FunctionCode::RESPONSE):
        this->ProcessResponse(header, objects);
        break;
    default:
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Ignoring unsupported function code: %s",
                         FunctionCodeSpec::to_human_string(header.function));
#ifdef OPENDNP3_USE_SA_CRYPTO
        if (authentication && authentication->sessions) authentication->sessions->statistics.Unexpected();
#endif
        break;
    }
}

void MContext::ProcessIIN(const IINField& iin)
{
    if (iin.IsSet(IINBit::DEVICE_RESTART) && !this->params.ignoreRestartIIN)
    {
        this->tasks.OnRestartDetected();
        this->scheduler->Evaluate();
    }

    if (iin.IsSet(IINBit::EVENT_BUFFER_OVERFLOW) && this->params.integrityOnEventOverflowIIN)
    {
        if (this->tasks.DemandIntegrity())
            this->scheduler->Evaluate();
    }

    if (iin.IsSet(IINBit::NEED_TIME))
    {
        if (this->tasks.DemandTimeSync())
            this->scheduler->Evaluate();
    }

    if ((iin.IsSet(IINBit::CLASS1_EVENTS) && this->params.eventScanOnEventsAvailableClassMask.HasClass1())
        || (iin.IsSet(IINBit::CLASS2_EVENTS) && this->params.eventScanOnEventsAvailableClassMask.HasClass2())
        || (iin.IsSet(IINBit::CLASS3_EVENTS) && this->params.eventScanOnEventsAvailableClassMask.HasClass3()))
    {
        if (this->tasks.DemandEventScan())
            this->scheduler->Evaluate();
    }

    this->application->OnReceiveIIN(iin);
}

void MContext::ProcessUnsolicitedResponse(const APDUResponseHeader& header, const ser4cpp::rseq_t& objects)
{
    if (!header.control.UNS)
    {
        SIMPLE_LOG_BLOCK(logger, flags::WARN, "Ignoring unsolicited response without UNS bit set");
#ifdef OPENDNP3_USE_SA_CRYPTO
        if (authentication && authentication->sessions)
            authentication->sessions->statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
#endif
        return;
    }

    auto result = MeasurementHandler::ProcessMeasurements(header.as_response_info(), objects, logger, SOEHandler.get());
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (result != ParseResult::OK && authentication && authentication->sessions)
        authentication->sessions->statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
#endif

    if ((result == ParseResult::OK) && header.control.CON)
    {
        this->QueueConfirm(APDUHeader::UnsolicitedConfirm(header.control.SEQ));
    }

    this->ProcessIIN(header.IIN);
}

void MContext::ProcessResponse(const APDUResponseHeader& header, const ser4cpp::rseq_t& objects)
{
    this->tstate = this->OnResponseEvent(header, objects);
    this->ProcessIIN(header.IIN); // TODO - should we process IIN bits for unexpected responses?
}

void MContext::QueueConfirm(const APDUHeader& header)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication && authentication->deferredAuthenticationCount
        && !authentication->controlAggressive.HasPendingConfirm()
        && authentication->nativeConfirmControl == (header.control.SEQ | (header.control.UNS ? 0x10 : 0)))
    {
        auto& auth = *authentication;
        if (!auth.protectedConfirm && !auth.nativeConfirmQueued)
        {
            // Reserve the actual native-dispatch entry, ahead of unrelated queued CONFIRMs.
            confirmQueue.push_front(header);
            auth.nativeConfirmQueued = true;
            auth.protectedConfirm = true;
        }
        this->CheckConfirmTransmit();
        return;
    }
    // Embedded-response dispatch queues the CONFIRM already reserved at the front.
    if (authentication && authentication->controlAggressive.RequiresConfirm(header.control.SEQ, header.control.UNS))
    {
        this->CheckConfirmTransmit();
        return;
    }
#endif
    this->confirmQueue.push_back(header);
    this->CheckConfirmTransmit();
}

bool MContext::CheckConfirmTransmit()
{
    if (this->isSending || this->confirmQueue.empty())
    {
        return false;
    }

    auto confirm = this->confirmQueue.front();
    APDUWrapper wrapper(this->txBuffer.as_wslice());
    wrapper.SetFunction(confirm.function);
    wrapper.SetControl(confirm.control);
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication && authentication->sessions)
    {
        auto& auth = *authentication;
        const auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
        auto* session = auth.sessions->Find(1);
        if (auth.controlAggressive.RequiresConfirm(confirm.control.SEQ, confirm.control.UNS))
        {
            if (!session || !session->Ready(now) || now >= auth.confirmDeadline
                || (auth.deferredAuthenticationCount && session->Sequence() != auth.deferredAuthenticationKSQ))
            {
                DiscardEmbeddedConfirm();
                auth.protectedConfirm = false;
                return false;
            }
            if (auth.exchangeIndex < auth.SessionCount() || auth.pendingWireSize || auth.replyPending || auth.replyInFlight)
                return false;
            if (!auth.controlAggressive.Create(auth.association, 1, session->ControlKey(now), wrapper.ToRSeq(),
                                               ser4cpp::wseq_t(auth.wire.data(), auth.wire.size()), auth.wireSize))
            {
                DiscardEmbeddedConfirm();
                auth.protectedConfirm = false;
                return false;
            }
            auth.wireInFlight = true;
            auth.protectedConfirm = true;
            auth.controlEligible[0] = true; // This exception constitutes the Challenge Reply.
            this->Transmit(ser4cpp::rseq_t(auth.wire.data(), auth.wireSize));
            FinalizeAuthenticationCounts(); // The required MAC is complete and transmission has begun.
            session->CountAuthentication(now); // The distinct outgoing Aggressive CONFIRM ASDU.
            this->confirmQueue.pop_front();
            return true;
        }
        if (auth.nativeConfirmQueued && (!session || !session->Ready(now) || now >= auth.confirmDeadline
            || session->Sequence() != auth.deferredAuthenticationKSQ))
        {
            DiscardEmbeddedConfirm();
            auth.protectedConfirm = false;
            return false;
        }
        if ((auth.protectedConfirm && !auth.nativeConfirmQueued) || auth.exchangeIndex < auth.SessionCount() || auth.pendingWireSize
            || (auth.protectedTask && !auth.replyIssued
                && (tstate == TaskState::WAIT_FOR_RESPONSE || IsAuthenticatedNoResponseTask()))
            || !session || !session->Ready(now)
            || auth.responder.GetState() == MasterResponder::State::WAITING_FOR_CHALLENGE)
            return false;
        if (auth.responder.SetSessionKey(1, session->ControlKey(now), session->ValidUntil(), now)
                != MasterResponder::Result::OK
            || auth.responder.RetainRequest(auth.association, wrapper.ToRSeq(), now) != MasterResponder::Result::OK)
        {
            if (auth.nativeConfirmQueued)
            {
                DiscardEmbeddedConfirm();
                auth.protectedConfirm = false;
            }
            return false;
        }
        auth.responderUser = 1;
        auth.protectedConfirm = true;
        if (!auth.nativeConfirmQueued)
            auth.confirmDeadline = now + auth.sessions->config.replyTimeoutMs;
        auth.nativeConfirmQueued = false; // Ownership now resides in the retained CONFIRM request.
    }
#endif
    this->Transmit(wrapper.ToRSeq());
    this->confirmQueue.pop_front();
    return true;
}

void MContext::Transmit(const ser4cpp::rseq_t& data)
{
    logging::ParseAndLogRequestTx(this->logger, data);
    assert(!this->isSending);
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication && authentication->sessions && authentication->protectedTask && activeTask
        && !authentication->protectedConfirm && data.length() >= 12 && data[2] == 120)
    {
        auto& auth = *authentication;
        Group120Var2 reply;
        Group120Var3 aggressive;
        auto prefix = data.skip(6);
        const bool isReply = data[1] == 0x20 && data[3] == 2 && reply.Read(data.skip(8));
        const bool isAggressive = data[1] < 0x20 && data[3] == 3 && Group120Var3::Read(prefix, aggressive);
        const auto user = isReply ? reply.userNum : aggressive.userNum;
        auto* session = auth.sessions->Find(user);
        if ((isReply || isAggressive) && session && user == activeTask->AuthenticationUser()
            && (data[0] & 0x1F) == solSeq.Get())
        {
            auth.errorAttempt.csq = isReply ? reply.seqNum : aggressive.seqNum;
            auth.errorAttempt.ksq = session->Sequence();
            auth.errorAttempt.user = user;
            auth.errorAttempt.appSequence = data[0] & 0x0F;
            auth.errorAttempt.deadline = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                executor->get_time().time_since_epoch()).count())
                + static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    params.responseTimeout.value).count());
            auth.errorAttempt.valid = true;
        }
    }
#endif
    this->isSending = true;
    const bool started = this->lower->BeginTransmit(Message(this->addresses, data));
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (started && authentication && authentication->sessions)
    {
        if (authentication->sessions->remote) authentication->sessions->remote->Transmitted(data);
        auto& statistics = authentication->sessions->statistics;
        statistics.Increment(SecurityStatistic::TOTAL_MESSAGES_SENT);
        if (data.length() >= 4 && data[2] == 120)
        {
            if (data[1] == 0x20 && (data[3] == 4 || data[3] == 6) && authentication->exchangeIndex < authentication->SessionCount())
                authentication->sessions->At(authentication->exchangeIndex)->OnExchangeTransmit(data[3], data[0] & 15);
            if (data[1] == 0x20 && data[3] == 1) statistics.Increment(SecurityStatistic::CRITICAL_MESSAGES_RECEIVED);
            // P6-OPEN-02: Reply OR Aggressive/mandatory CONFIRM, never both.
            uint16_t user = 0;
            if ((data[1] == 0x20 && data[3] == 2)
                || (data[3] == 3 && AggressiveMode::InspectUser(data, false, user)))
                statistics.Increment(SecurityStatistic::CRITICAL_MESSAGES_SENT);
            if (data[1] == 0x21 && data[3] == 7) statistics.Increment(SecurityStatistic::ERROR_MESSAGES_SENT);
        }
    }
#else
    (void)started;
#endif
}

void MContext::StartResponseTimer()
{
    const auto owner = activeTask;
    auto timeout = [self = shared_from_this(), owner]() {
        if (owner && self->activeTask == owner) self->OnResponseTimeout();
    };
    const auto milliseconds = activeTask ? activeTask->ResponseTimeoutMs() : 0;
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (IsAuthenticatedNoResponseTask())
    {
        // Same bound as retained Challenge/Reply state, including zero's immediate expiry.
        this->responseTimer = executor->start(std::chrono::milliseconds(params.authentication.replyTimeoutMs), timeout);
        return;
    }
#endif
    this->responseTimer = this->executor->start(milliseconds ? std::chrono::milliseconds(milliseconds)
        : this->params.responseTimeout.value, timeout);
}

std::shared_ptr<IMasterTask> MContext::AddScan(TimeDuration period,
                                               const HeaderBuilderT& builder,
                                               std::shared_ptr<ISOEHandler> soe_handler,
                                               TaskConfig config)
{
    auto task = std::make_shared<UserPollTask>(
        this->tasks.context, builder,
        TaskBehavior::ImmediatePeriodic(period, params.taskRetryPeriod, params.maxTaskRetryPeriod), true, *application,
        soe_handler, logger, config);
    this->ScheduleRecurringPollTask(task);
    return task;
}

std::shared_ptr<IMasterTask> MContext::AddClassScan(const ClassField& field,
                                                    TimeDuration period,
                                                    std::shared_ptr<ISOEHandler> soe_handler,
                                                    TaskConfig config)
{
    auto build = [field](HeaderWriter& writer) -> bool { return build::WriteClassHeaders(writer, field); };
    return this->AddScan(period, build, soe_handler, config);
}

std::shared_ptr<IMasterTask> MContext::AddAllObjectsScan(GroupVariationID gvId,
                                                         TimeDuration period,
                                                         std::shared_ptr<ISOEHandler> soe_handler,
                                                         TaskConfig config)
{
    auto build = [gvId](HeaderWriter& writer) -> bool { return writer.WriteHeader(gvId, QualifierCode::ALL_OBJECTS); };
    return this->AddScan(period, build, soe_handler, config);
}

std::shared_ptr<IMasterTask> MContext::AddRangeScan(GroupVariationID gvId,
                                                    uint16_t start,
                                                    uint16_t stop,
                                                    TimeDuration period,
                                                    std::shared_ptr<ISOEHandler> soe_handler,
                                                    TaskConfig config)
{
    auto build = [gvId, start, stop](HeaderWriter& writer) -> bool {
        return writer.WriteRangeHeader<ser4cpp::UInt16>(QualifierCode::UINT16_START_STOP, gvId, start, stop);
    };
    return this->AddScan(period, build, soe_handler, config);
}

void MContext::Scan(const HeaderBuilderT& builder, std::shared_ptr<ISOEHandler> soe_handler, TaskConfig config)
{
    const auto timeout = Timestamp(this->executor->get_time()) + params.taskStartTimeout;

    auto task
        = std::make_shared<UserPollTask>(this->tasks.context, builder, TaskBehavior::SingleExecutionNoRetry(timeout),
                                         false, *application, soe_handler, logger, config);

    this->ScheduleAdhocTask(task);
}

void MContext::ScanClasses(const ClassField& field, std::shared_ptr<ISOEHandler> soe_handler, TaskConfig config)
{
    auto configure = [field](HeaderWriter& writer) -> bool { return build::WriteClassHeaders(writer, field); };
    this->Scan(configure, soe_handler, config);
}

void MContext::ScanAllObjects(GroupVariationID gvId, std::shared_ptr<ISOEHandler> soe_handler, TaskConfig config)
{
    auto configure
        = [gvId](HeaderWriter& writer) -> bool { return writer.WriteHeader(gvId, QualifierCode::ALL_OBJECTS); };
    this->Scan(configure, soe_handler, config);
}

void MContext::ScanRange(
    GroupVariationID gvId, uint16_t start, uint16_t stop, std::shared_ptr<ISOEHandler> soe_handler, TaskConfig config)
{
    auto configure = [gvId, start, stop](HeaderWriter& writer) -> bool {
        return writer.WriteRangeHeader<ser4cpp::UInt16>(QualifierCode::UINT16_START_STOP, gvId, start, stop);
    };
    this->Scan(configure, soe_handler, config);
}

void MContext::Write(const TimeAndInterval& value, uint16_t index, TaskConfig config)
{
    auto builder = [value, index](HeaderWriter& writer) -> bool {
        return writer.WriteSingleIndexedValue<ser4cpp::UInt16, TimeAndInterval>(QualifierCode::UINT16_CNT_UINT16_INDEX,
                                                                                Group50Var4::Inst(), value, index);
    };

    const auto timeout = Timestamp(this->executor->get_time()) + params.taskStartTimeout;
    auto task = std::make_shared<EmptyResponseTask>(this->tasks.context, *this->application, "WRITE TimeAndInterval",
                                                    FunctionCode::WRITE, builder, timeout, this->logger, config);
    this->ScheduleAdhocTask(task);
}

void MContext::Restart(RestartType op, const RestartOperationCallbackT& callback, TaskConfig config)
{
    const auto timeout = Timestamp(this->executor->get_time()) + params.taskStartTimeout;
    auto task = std::make_shared<RestartOperationTask>(this->tasks.context, *this->application, timeout, op, callback,
                                                       this->logger, config);
    this->ScheduleAdhocTask(task);
}

void MContext::PerformFunction(const std::string& name,
                               FunctionCode func,
                               const HeaderBuilderT& builder,
                               TaskConfig config)
{
    const auto timeout = Timestamp(this->executor->get_time()) + params.taskStartTimeout;
    auto task = std::make_shared<EmptyResponseTask>(this->tasks.context, *this->application, name, func, builder,
                                                    timeout, this->logger, config);
    this->ScheduleAdhocTask(task);
}

bool MContext::Run(const std::shared_ptr<IMasterTask>& task)
{
    if (this->activeTask || this->tstate != TaskState::IDLE)
        return false;

    this->tstate = TaskState::TASK_READY;
    this->activeTask = task;
    this->activeTask->OnStart();
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication && authentication->sessions)
    {
        auto& auth = *authentication;
        const auto now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            executor->get_time().time_since_epoch()).count());
        auto* session = auth.sessions->Find(task->AuthenticationUser());
        auth.userCritical = task->IsUserTask() && !task->IsRecurring() && session
            && auth.exchangeIndex == auth.SessionCount() && !auth.pendingWireSize && !auth.replyPending && !auth.replyInFlight
            && !auth.protectedConfirm && !auth.deferredAuthenticationCount && !auth.monitorWaiting
            && !auth.controlAggressive.HasPendingConfirm()
            && auth.responder.GetState() != MasterResponder::State::WAITING_FOR_CHALLENGE;
        auth.allowUnkeyedCritical = task->ExpectsResponse() && auth.userCritical && session->CanSendUnkeyedCritical(now);
        auth.errorAttempt.valid = auth.recoveringKeys = false;
    }
#endif
    FORMAT_LOG_BLOCK(logger, flags::INFO, "Begining task: %s", this->activeTask->Name());

    if (!this->isSending)
    {
        this->tstate = this->ResumeActiveTask();
    }

    return true;
}

/// ------ private helpers ----------

void MContext::ScheduleRecurringPollTask(const std::shared_ptr<IMasterTask>& task)
{
    this->tasks.BindTask(task);

    if (this->isOnline)
    {
        this->scheduler->Add(task, *this);
    }
}

void MContext::ScheduleAdhocTask(const std::shared_ptr<IMasterTask>& task)
{
    if (this->isOnline)
    {
        this->scheduler->Add(task, *this);
    }
    else
    {
        // can't run this task since we're offline so fail it immediately
        task->OnLowerLayerClose(Timestamp(this->executor->get_time()));
    }
}

MContext::TaskState MContext::ResumeActiveTask()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    bool unkeyedCritical = false;
    if (authentication && activeTask->IsAuthenticationTask()
        && (authentication->exchangeIndex < authentication->SessionCount() || authentication->pendingWireSize
            || authentication->replyPending || authentication->replyInFlight || authentication->protectedConfirm
            || authentication->monitorWaiting))
    {
        if (Timestamp(executor->get_time()) >= activeTask->StartExpirationTime())
        {
            activeTask->OnStartTimeout(Timestamp(executor->get_time()));
            CompleteActiveTask();
            return TaskState::IDLE;
        }
        return TaskState::TASK_READY;
    }
    if (authentication && authentication->sessions && !activeTask->IsAuthenticationTask())
    {
        const auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
        auto* session = authentication->sessions->Find(activeTask->AuthenticationUser());
        if (!session)
        {
            activeTask->OnMessageFormatError(Timestamp(executor->get_time()));
            CompleteActiveTask();
            return TaskState::IDLE;
        }
        auto& auth = *authentication;
        unkeyedCritical = auth.allowUnkeyedCritical && auth.exchangeIndex == auth.SessionCount() && !auth.pendingWireSize
            && !auth.replyPending && !auth.replyInFlight && !auth.protectedConfirm && !auth.deferredAuthenticationCount
            && !auth.monitorWaiting && !auth.controlAggressive.HasPendingConfirm()
            && auth.responder.GetState() != MasterResponder::State::WAITING_FOR_CHALLENGE
            && Timestamp(executor->get_time()) < activeTask->StartExpirationTime()
            && session->CanSendUnkeyedCritical(now);
        auth.allowUnkeyedCritical = false; // Consume admission once; a later timer cannot create it.
        if (unkeyedCritical)
            auth.responder.Reset(); // Never retain a stale cached signing key for this exceptional send.
        auto* common = authentication->sessions->Find(1);
        if (!unkeyedCritical && !authentication->protectedConfirm && !authentication->deferredAuthenticationCount)
        {
            if (common && common->Ready(now) && common->RemainingMessages() < (session->User() == 1 ? 4u : 2u))
                common->RequestRenewal(now);
            if (session->Ready(now) && session->RemainingMessages() < 2)
                session->RequestRenewal(now);
        }
        const bool allReady = authentication->sessions->remote
            ? (common && common->Ready(now) && session->Ready(now))
            : authentication->sessions->At(0)->Ready(now) && authentication->sessions->At(1)->Ready(now);
        if (!unkeyedCritical && (!allReady || authentication->exchangeIndex < authentication->SessionCount() || !session->Ready(now)
            || authentication->protectedConfirm || authentication->deferredAuthenticationCount))
        {
            if (Timestamp(executor->get_time()) >= activeTask->StartExpirationTime())
            {
                activeTask->OnStartTimeout(Timestamp(executor->get_time()));
                CompleteActiveTask();
                return TaskState::IDLE;
            }
            return TaskState::TASK_READY;
        }
        const auto index = authentication->sessions->Index(session->User());
        const bool fresh = authentication->keyEpoch[index] != session->Sequence();
        if (!unkeyedCritical && (fresh || authentication->responderUser != session->User()
            || authentication->responder.GetState() == MasterResponder::State::NO_SESSION_KEYS))
        {
            if (authentication->responder.SetSessionKey(session->User(), session->ControlKey(now),
                                                        session->ValidUntil(), now, fresh)
                != MasterResponder::Result::OK)
            {
                activeTask->OnMessageFormatError(Timestamp(executor->get_time()));
                CompleteActiveTask();
                return TaskState::IDLE;
            }
            authentication->keyEpoch[index] = session->Sequence();
            authentication->responderUser = session->User();
        }
    }
#endif
    APDURequest request(this->txBuffer.as_wslice());

    /// try to build a requst for the task
    if (!this->activeTask->BuildRequest(request, this->solSeq))
    {
        activeTask->OnRequestBuildFailure(Timestamp(executor->get_time()));
        this->CompleteActiveTask();
        return TaskState::IDLE;
    }

#ifdef OPENDNP3_USE_SA_CRYPTO
    if (unkeyedCritical)
    {
        // IEEE Table 7-7 mandatory critical functions. Optional functions, including
        // READ, retain the normal key gate and do not qualify for this exception.
        const auto function = FunctionCodeSpec::to_type(request.GetFunction());
        const bool critical = (function >= 0x02 && function <= 0x06)
            || (function >= 0x0D && function <= 0x0E) || (function >= 0x10 && function <= 0x15)
            || (function >= 0x18 && function <= 0x1F);
        if (!critical || request.GetControl().UNS)
            return TaskState::TASK_READY;
    }
#endif
    auto apdu = request.ToRSeq();
    auto nextState = activeTask->ExpectsResponse() ? TaskState::WAIT_FOR_RESPONSE : TaskState::WAIT_FOR_TX_COMPLETION;
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication)
    {
        // Test-mode policy protects all ordinary functions except READ/CONFIRM,
        // including every mandatory critical function in IEEE Table 7-7 (p252).
        authentication->protectedTask = !activeTask->IsAuthenticationTask() && request.GetFunction() != FunctionCode::CONFIRM
            && (authentication->sessions || request.GetFunction() != FunctionCode::READ);
        // Reuse the active protection policy for Code 1 (including configured
        // optional critical functions). The keyless exception above remains mandatory-only.
        authentication->userCritical = authentication->userCritical
            && authentication->protectedTask && !request.GetControl().UNS;
        authentication->replyIssued = false;
        authentication->errorAttempt.valid = false; // A later SELECT/OPERATE stage is a new attempt.
        bool aggressive = false;
        if (authentication->protectedTask && authentication->sessions && !unkeyedCritical)
        {
            auto& auth = *authentication;
            auto* session = auth.sessions->Find(activeTask->AuthenticationUser());
            const auto index = auth.sessions->Index(session->User());
            if (auth.sessions->config.aggressiveTransmit && auth.controlEligible[index]
                && auth.controlAggressive.HasChallenge(request.GetControl().UNS))
            {
                size_t size = 0;
                const auto now = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch())
                        .count());
                if (!auth.controlAggressive.Create(
                        auth.association, session->User(), session->ControlKey(now), apdu,
                        ser4cpp::wseq_t(auth.aggressiveWire.data(), auth.aggressiveWire.size()), size))
                {
                    responseTimer.cancel();
                    activeTask->OnMessageFormatError(Timestamp(executor->get_time()));
                    CompleteActiveTask();
                    return TaskState::IDLE;
                }
                apdu = ser4cpp::rseq_t(auth.aggressiveWire.data(), size);
                aggressive = true;
                auth.replyIssued = true;
                session->CountAuthentication(now);
            }
        }
        if (authentication->protectedTask && !activeTask->ExpectsResponse())
        {
            // FC6 never uses the keyless exception or silently downgrades a
            // configured Aggressive submission lacking a usable Challenge.
            if (unkeyedCritical || !authentication->sessions
                || (authentication->sessions->config.aggressiveTransmit && !aggressive))
            {
                activeTask->OnMessageFormatError(Timestamp(executor->get_time()));
                CompleteActiveTask();
                return TaskState::IDLE;
            }
            nextState = aggressive ? TaskState::WAIT_FOR_AGGRESSIVE_TX : TaskState::WAIT_FOR_AUTH_REQUEST_TX;
        }
        // 7.5.3.4(c): this normal transmission grants no trust. With no usable
        // key, do not create an Aggressive Request or require keyed request retention.
        if (authentication->protectedTask && !aggressive && !unkeyedCritical
            && authentication->responder.RetainRequest(
                   authentication->association, apdu,
                   static_cast<uint64_t>(
                       std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch())
                           .count()))
                != MasterResponder::Result::OK)
        {
            responseTimer.cancel();
            activeTask->OnMessageFormatError(Timestamp(executor->get_time()));
            this->CompleteActiveTask();
            return TaskState::IDLE;
        }
    }
#endif
    this->RecordLastRequest(apdu);
    tstate = nextState;
    this->StartResponseTimer(); // Also bounds waiting for lower-layer transmit completion.
    this->Transmit(apdu);

    return nextState;
}

//// --- State tables ---

MContext::TaskState MContext::OnTransmitComplete()
{
    switch (tstate)
    {
    case (TaskState::TASK_READY):
        return this->ResumeActiveTask();
    case (TaskState::WAIT_FOR_TX_COMPLETION):
        this->responseTimer.cancel();
        this->solSeq.Increment();
        this->activeTask->OnTransmitComplete(Timestamp(this->executor->get_time()));
        this->CompleteActiveTask();
        return TaskState::IDLE;
    default:
        return tstate;
    }
}

MContext::TaskState MContext::OnResponseEvent(const APDUResponseHeader& header, const ser4cpp::rseq_t& objects)
{
    switch (tstate)
    {
    case (TaskState::WAIT_FOR_RESPONSE):
        return OnResponse_WaitForResponse(header, objects);
    default:
        FORMAT_LOG_BLOCK(logger, flags::WARN, "Not expecting a response, sequence: %u", header.control.SEQ);
#ifdef OPENDNP3_USE_SA_CRYPTO
        if (authentication && authentication->sessions) authentication->sessions->statistics.Unexpected();
#endif
        return tstate;
    }
}

MContext::TaskState MContext::OnResponseTimeoutEvent()
{
    switch (tstate)
    {
    case (TaskState::WAIT_FOR_RESPONSE):
        return OnResponseTimeout_WaitForResponse();
    case (TaskState::WAIT_FOR_TX_COMPLETION):
        return OnResponseTimeout_WaitForTxCompletion();
    default:
        SIMPLE_LOG_BLOCK(logger, flags::ERR, "Unexpected response timeout");
        return tstate;
    }
}

//// --- State actions ----

MContext::TaskState MContext::StartTask_TaskReady()
{
    if (this->isSending)
    {
        return TaskState::TASK_READY;
    }

    return this->ResumeActiveTask();
}

MContext::TaskState MContext::OnResponse_WaitForResponse(const APDUResponseHeader& header,
                                                         const ser4cpp::rseq_t& objects)
{
    if (header.control.SEQ != this->solSeq)
    {
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Response with bad sequence: %u", header.control.SEQ);
#ifdef OPENDNP3_USE_SA_CRYPTO
        if (authentication && authentication->sessions) authentication->sessions->statistics.Unexpected();
#endif
        return TaskState::WAIT_FOR_RESPONSE;
    }

    this->responseTimer.cancel();

    this->solSeq.Increment();

    auto now = Timestamp(this->executor->get_time());

    auto result = this->activeTask->OnResponse(header, objects, now);
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (result == IMasterTask::ResponseResult::ERROR_BAD_RESPONSE && authentication && authentication->sessions)
        authentication->sessions->statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
#endif

    if (header.control.CON)
    {
        this->QueueConfirm(APDUHeader::SolicitedConfirm(header.control.SEQ));
    }

    switch (result)
    {
    case (IMasterTask::ResponseResult::OK_CONTINUE):
        this->StartResponseTimer();
        return TaskState::WAIT_FOR_RESPONSE;
    case (IMasterTask::ResponseResult::OK_REPEAT):
        return StartTask_TaskReady();
    default:
        // task completed or failed, either way go back to idle
        this->CompleteActiveTask();
        return TaskState::IDLE;
    }
}

MContext::TaskState MContext::OnResponseTimeout_WaitForResponse()
{
    if (activeTask->RetryOnResponseTimeout()) return StartTask_TaskReady();
    SIMPLE_LOG_BLOCK(logger, flags::WARN, "Timeout waiting for response");

    auto now = Timestamp(this->executor->get_time());
    this->activeTask->OnResponseTimeout(now);
    this->solSeq.Increment();
    this->CompleteActiveTask();
    return TaskState::IDLE;
}

MContext::TaskState MContext::OnResponseTimeout_WaitForTxCompletion()
{
    SIMPLE_LOG_BLOCK(logger, flags::WARN, "Timeout waiting for lower-layer transmit completion");
    const auto now = Timestamp(this->executor->get_time());
    this->activeTask->OnResponseTimeout(now);
    this->solSeq.Increment();
    this->CompleteActiveTask();
    return TaskState::IDLE;
}

void MContext::FinalizeAuthenticationCounts()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication)
        return;
    auto& auth = *authentication;
    const auto count = auth.deferredAuthenticationCount;
    const auto epoch = auth.deferredAuthenticationKSQ;
    auth.deferredAuthenticationCount = 0; // Consume once, including abort/reset paths.
    auth.deferredAuthenticationKSQ = 0;
    auth.nativeConfirmControl = 0;
    auto* session = auth.sessions ? auth.sessions->Find(1) : nullptr;
    if (!count || !session || session->Sequence() != epoch)
        return; // Never charge an exchange to replacement keys.
    const auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
    for (uint8_t i = 0; i < count; ++i)
        session->CountAuthentication(now);
#endif
}

void MContext::DiscardEmbeddedConfirm()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication)
        return;
    auto& aggressive = authentication->controlAggressive;
    const bool nativeReplyPending = authentication->protectedConfirm
        && authentication->replyPending && !authentication->replyInFlight && !authentication->nativeConfirmQueued
        && authentication->responderUser == 1 && !aggressive.HasPendingConfirm();
    if (authentication->nativeConfirmQueued)
    {
        if (!confirmQueue.empty()
            && authentication->nativeConfirmControl == (confirmQueue.front().control.SEQ
                | (confirmQueue.front().control.UNS ? 0x10 : 0)))
            confirmQueue.pop_front();
        authentication->nativeConfirmQueued = false;
    }
    // ProcessAuthenticatedResponse reserves exactly one owned entry at the front.
    // Older entries, even with identical SEQ/UNS, belong to other operations.
    if (!confirmQueue.empty()
        && aggressive.RequiresConfirm(confirmQueue.front().control.SEQ, confirmQueue.front().control.UNS))
        confirmQueue.pop_front();
    // A generated but unsent native-CONFIRM Reply belongs to this aborted exchange.
    // Never alter an authentication message already in flight.
    if (nativeReplyPending)
    {
        authentication->replyPending = false;
        authentication->replySize = 0;
        authentication->replyDeadline = authentication->replyKSQ = 0;
        authentication->replyCountExhausted = false;
        crypto::Clear(ser4cpp::wseq_t(authentication->reply.data(), authentication->reply.size()));
    }
    aggressive.DiscardPendingConfirms();
    FinalizeAuthenticationCounts();
#endif
}

void MContext::ProcessAuthenticatedResponse(const ser4cpp::rseq_t& wire, const ser4cpp::rseq_t& native, uint8_t count)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    auto& auth = *authentication;
    if (auth.controlAggressive.HasPendingConfirm() || auth.deferredAuthenticationCount)
    {
        auth.sessions->statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
        return;
    }
    auto* session = auth.sessions->Find(1);
    if (!session)
        return;
    auth.deferredAuthenticationCount = count;
    auth.deferredAuthenticationKSQ = session->Sequence();
    const auto original = APDUHeaderParser::ParseResponse(native);
    Group120Var1 challenge;
    size_t nativeSize = 0;
    if (!original.success || (auth.recoveringKeys && original.header.function == FunctionCode::RESPONSE)
        || !auth.controlAggressive.InspectEmbeddedChallenge(native, challenge, nativeSize))
    {
        auth.sessions->statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
        FinalizeAuthenticationCounts();
        return;
    }
    if (nativeSize != native.length())
    {
        const auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
        const auto& header = original.header;
        if (!session->Ready(now) || auth.exchangeIndex < auth.SessionCount() || auth.pendingWireSize
            || auth.protectedConfirm || auth.replyPending || auth.replyInFlight
            || (header.function == FunctionCode::RESPONSE
                && (!activeTask || tstate != TaskState::WAIT_FOR_RESPONSE || header.control.SEQ != solSeq)))
        {
            auth.sessions->statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
            FinalizeAuthenticationCounts();
            return;
        }
        if (!auth.responder.ObserveEmbeddedChallenge(auth.association, challenge, header.control.UNS, now)
            || !auth.controlAggressive.RememberChallenge(wire, header.control.UNS, true,
                    auth.monitoringAggressive.Algorithm(header.control.UNS)))
        {
            auth.sessions->statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
            FinalizeAuthenticationCounts();
            return;
        }
        // The full authenticated wire APDU is the Table A-9 seed. Strip only
        // G120V1 for native dispatch; reserve its own CONFIRM ahead of older entries.
        auth.keyEpoch[0] = session->Sequence();
        if (!(wire.length() >= 6 && wire[4] == 120 && wire[5] == 3))
            ++auth.deferredAuthenticationCount; // Distinct embedded Challenge ASDU, not an extra aggressive ASDU.
        // Only retain accounting when it would invalidate keys needed by this CONFIRM.
        if (session->RemainingMessages() > auth.deferredAuthenticationCount)
            FinalizeAuthenticationCounts();
        else
            while (session->RemainingMessages() > 1)
            {
                session->CountAuthentication(now);
                --auth.deferredAuthenticationCount;
            }
        auth.protectedConfirm = true;
        auth.confirmDeadline = now + auth.sessions->config.replyTimeoutMs;
        confirmQueue.push_front(header.control.UNS ? APDUHeader::UnsolicitedConfirm(header.control.SEQ)
                                                   : APDUHeader::SolicitedConfirm(header.control.SEQ));
    }
    else if (original.header.control.CON && session->RemainingMessages() <= count + 1u)
    {
        const auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
        if (!session->Ready(now) || auth.protectedConfirm || auth.replyPending || auth.replyInFlight
            || auth.exchangeIndex < auth.SessionCount() || auth.pendingWireSize)
        {
            auth.sessions->statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
            FinalizeAuthenticationCounts();
            return;
        }
        auth.nativeConfirmControl = original.header.control.SEQ | (original.header.control.UNS ? 0x10 : 0);
        auth.confirmDeadline = now + auth.sessions->config.replyTimeoutMs;
        // Keep accounting deferred through the native CONFIRM's incoming Challenge.
        while (session->RemainingMessages() > 1 && auth.deferredAuthenticationCount > 1)
        {
            session->CountAuthentication(now);
            --auth.deferredAuthenticationCount;
        }
    }
    else
        FinalizeAuthenticationCounts(); // Ordinary verified payloads survive count-only invalidation.
    const auto nativeObjects = original.objects.take(nativeSize - 4);
    // Native V7 events are data, not standalone authentication Errors. Count
    // validated objects (including mixed fragments), without applying recovery
    // or changing ordinary task/SOE dispatch. Reuse the existing object parser.
    class ErrorEvents final : public IAPDUHandler
    {
    public:
        uint32_t count = 0;
        bool IsAllowed(uint32_t, GroupVariation, QualifierCode) override { return true; }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var7>& values) override
        {
            values.ForeachItem([this](const Group120Var7& value) {
                if (ValidAuthenticationError(value)) ++count;
            });
            return IINField::Empty();
        }
    } errors;
    if (APDUParser::Parse(nativeObjects, errors, nullptr) == ParseResult::OK)
        for (uint32_t n = 0; n < errors.count; ++n)
            auth.sessions->statistics.Increment(SecurityStatistic::ERROR_MESSAGES_RECEIVED);
    this->ProcessAPDU(original.header, nativeObjects);
    // A native parser/task can decline the response without queueing a CONFIRM.
    if (auth.deferredAuthenticationCount && !auth.protectedConfirm && !auth.nativeConfirmQueued)
        FinalizeAuthenticationCounts();
    if (auth.controlAggressive.HasPendingConfirm())
        this->CheckConfirmTransmit();
#else
    (void)wire;
    (void)native;
    (void)count;
#endif
}

void MContext::ResetAuthentication()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication)
        return;
    // Only an unsent Key Change belongs to the exchange being cancelled here.
    // The separate wire buffer may still be borrowed by the lower layer.
    if (authentication->pendingWireSize >= 8
        && authentication->pendingWire[1] == FunctionCodeSpec::to_type(FunctionCode::AUTH_REQUEST)
        && authentication->pendingWire[2] == 120 && authentication->pendingWire[3] == 6)
    {
        if (authentication->sessions && authentication->exchangeIndex < authentication->SessionCount())
        {
            const auto now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                executor->get_time().time_since_epoch()).count());
            authentication->sessions->At(authentication->exchangeIndex)->CancelQueuedChange(now);
        }
        crypto::Clear(ser4cpp::wseq_t(authentication->pendingWire.data(), authentication->pendingWire.size()));
        authentication->pendingWireSize = 0;
        authentication->exchangeIndex = authentication->SessionCount();
        authentication->exchangeSequence = (authentication->exchangeSequence + 1) & 15;
    }
    authentication->allowUnkeyedCritical = false;
    authentication->responder.Reset();
    DiscardEmbeddedConfirm();
    // A task timeout can abort a CONFIRM that was delaying an already-owned
    // Code 1 recovery. Settle its counts first, then retain the required renewal.
    if (isOnline && authentication->recoveringKeys && authentication->errorAttempt.valid && authentication->sessions)
    {
        auto* owner = authentication->sessions->Find(authentication->errorAttempt.user);
        const auto now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            executor->get_time().time_since_epoch()).count());
        if (owner && owner->Sequence() == authentication->errorAttempt.ksq)
            owner->RequestRenewal(now);
    }
    authentication->userCritical = authentication->recoveringKeys = authentication->errorAttempt.valid = false;
    authentication->controlAggressive.Reset();
    authentication->monitoringAggressive.Reset();
    authentication->controlEligible.fill(false);
    authentication->monitoringEligible = false;
    // Authentication state resets immediately; an active TX still borrows these bytes.
    if (!isSending)
        crypto::Clear(ser4cpp::wseq_t(authentication->aggressiveWire.data(), authentication->aggressiveWire.size()));
    authentication->protectedConfirm = false;
    if (authentication->monitorWaiting)
        authentication->pendingWireSize = 0;
    authentication->monitoring.Reset();
    authentication->monitorWaiting = false;
    authentication->replyPending = false;
    authentication->replySize = 0;
    authentication->replyDeadline = authentication->replyKSQ = 0;
    authentication->replyCountExhausted = false;
    authentication->replyIssued = false;
    if (!authentication->replyInFlight)
        crypto::Clear(ser4cpp::wseq_t(authentication->reply.data(), authentication->reply.size()));
#endif
}

void MContext::CancelAuthenticationReply(bool rejectedChallenge)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    auto& auth = *authentication;
    if ((!auth.replyPending && !rejectedChallenge) || auth.replyInFlight)
        return;
    // A queued native CONFIRM can be independent of the task Reply being cancelled.
    const bool ownsConfirm = auth.protectedConfirm && !auth.nativeConfirmQueued
        && auth.responderUser == 1 && !auth.controlAggressive.HasPendingConfirm() && !IsAuthenticatedNoResponseTask();
    const bool ownsTask = !ownsConfirm && auth.protectedTask && activeTask
        && (tstate == TaskState::WAIT_FOR_RESPONSE || IsAuthenticatedNoResponseTask())
        && activeTask->AuthenticationUser() == auth.responderUser;
    auth.replyPending = false;
    auth.replySize = 0;
    auth.replyDeadline = auth.replyKSQ = 0;
    auth.replyCountExhausted = false;
    auth.replyIssued = false;
    crypto::Clear(ser4cpp::wseq_t(auth.reply.data(), auth.reply.size()));
    auth.responder.Reset(); // Retains its CSQ replay watermark; never touches monitoring state.
    if (ownsConfirm)
    {
        auth.protectedConfirm = false;
        FinalizeAuthenticationCounts();
    }
    else if (ownsTask)
    {
        // This task cannot authenticate its response without the cancelled Reply.
        // Complete only its timeout; monitoring, CONFIRMs and borrowed TX bytes have independent owners.
        responseTimer.cancel();
        if (IsAuthenticatedNoResponseTask())
            CompleteAuthenticatedNoResponseTask(false);
        else if (rejectedChallenge)
        {
            // Algorithm rejection is terminal for this request, even for tasks that retry timeouts.
            activeTask->OnResponseTimeout(Timestamp(executor->get_time()));
            solSeq.Increment();
            CompleteActiveTask();
            tstate = TaskState::IDLE;
        }
        else
            tstate = OnResponseTimeout_WaitForResponse();
    }
#endif
}

bool MContext::IsAuthenticationReplyValid(uint64_t now)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    auto& auth = *authentication;
    if (!auth.replyPending || auth.replyInFlight || !auth.replySize || now >= auth.replyDeadline)
        return false;
    auth.responder.Tick(now);
    if (auth.responder.LastAcceptedChallenge().is_empty())
        return false; // Reset/expiry removed the exchange that generated this Reply.
    if (!auth.sessions)
        return true;
    auto* session = auth.sessions->Find(auth.responderUser);
    // A precomputed MAC can finish after its own count increment, but not on
    // another KSQ or past the original key validity captured in replyDeadline.
    return session && session->Sequence() == auth.replyKSQ && (session->Ready(now) || auth.replyCountExhausted);
#else
    (void)now;
    return false;
#endif
}

void MContext::TransmitAuthenticationReply()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    const auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
    if (!IsAuthenticationReplyValid(now))
    {
        CancelAuthenticationReply();
        return;
    }
    authentication->replyPending = false;
    authentication->replyInFlight = true;
    authentication->replyIssued = true;
    this->Transmit(ser4cpp::rseq_t(authentication->reply.data(), authentication->replySize));
    if (authentication->sessions)
    {
        const auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
        auto* session = authentication->sessions->Find(authentication->responderUser);
        if (session)
        {
            const auto index = authentication->sessions->Index(session->User());
            if (authentication->controlAggressive.RememberChallenge(
                    authentication->responder.LastAcceptedChallenge(),
                    authentication->responder.LastChallengeWasUnsolicited()))
                authentication->controlEligible[index] = true;
            if (!authentication->nativeConfirmQueued && authentication->responderUser == 1)
                FinalizeAuthenticationCounts(); // Native CONFIRM's Challenge/Reply is now on the wire.
            if (authentication->deferredAuthenticationCount && session->User() == 1)
                ++authentication->deferredAuthenticationCount;
            else
                session->CountAuthentication(now);
        }
    }
#endif
}

void MContext::InvalidateRemoteCredentials()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication || !authentication->sessions || !authentication->sessions->remote) return;
    auto& auth = *authentication;
    while (const auto user = auth.sessions->remote->TakeInvalidatedUser())
    {
        const auto index = auth.sessions->Index(user);
        if (index < auth.controlEligible.size()) auth.controlEligible[index] = false;
        if (auth.responderUser == user)
        {
            CancelAuthenticationReply();
            auth.responder.Reset();
            auth.responderUser = 0;
        }
        if (user == 1)
        {
            auth.monitoring.CancelPending();
            auth.monitorWaiting = auth.monitoringEligible = false;
            auth.monitoringAggressive.Reset();
        }
    }
#endif
}
void MContext::ServiceSecurityStatistics(uint64_t now)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication || !authentication->sessions) return;
    auto& auth = *authentication;
    auto& statistics = auth.sessions->statistics;
    if (auth.sessions->remote)
    {
        auth.sessions->remote->Tick(now);
        InvalidateRemoteCredentials();
    }
    for (size_t n = 0; n < auth.sessions->Size(); ++n) auth.sessions->At(n)->Tick(now);
    auth.monitoring.Tick(now);
    if (auth.monitorWaiting && auth.monitoring.GetState() != OutstationChallenger::State::WAITING_FOR_REPLY)
    {
        auth.monitorWaiting = false;
        // One monitoring operation owns the queued G120V1. Other variations are
        // key exchange messages; wire is separate and may still be in flight.
        if (auth.pendingWireSize >= 8
            && auth.pendingWire[1] == FunctionCodeSpec::to_type(FunctionCode::AUTH_REQUEST)
            && auth.pendingWire[2] == 120 && auth.pendingWire[3] == 1
            && (auth.pendingWire[0] & 0x0F) == auth.monitorSequence)
        {
            crypto::Clear(ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWireSize));
            auth.pendingWireSize = 0;
        }
    }
    uint16_t exhaustedUser = 0;
    const bool keyTimeout = statistics.TakeKeyChangeTimeoutLimit(exhaustedUser);
    if (keyTimeout || statistics.Exceeded(SecurityStatistic::REPLY_TIMEOUTS))
    {
        auth.restartRecoveryPending = false;
        statistics.ResetMaximum(SecurityStatistic::REPLY_TIMEOUTS);
        for (size_t n = 0; n < auth.sessions->Size(); ++n)
            if (!keyTimeout || auth.sessions->At(n)->User() != exhaustedUser)
                auth.sessions->At(n)->CommunicationFailure(now);
        ResetAuthentication(); // All-user event, Table 7-8 row 8/Table 7-13 row 5.
        crypto::Clear(ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()));
        auth.pendingWireSize = 0; // Never overwrite auth.wire/reply/aggressiveWire while in flight.
        if (auth.exchangeIndex < auth.SessionCount())
        {
            auth.exchangeIndex = auth.SessionCount();
            auth.exchangeSequence = (auth.exchangeSequence + 1) & 15;
        }
    }
    if (!statistics.Exceeded(SecurityStatistic::AUTHENTICATION_FAILURES)) return;
    if (statistics.Exceeded(SecurityStatistic::AUTHENTICATION_REKEYS))
    {
        statistics.ResetMaximum(SecurityStatistic::AUTHENTICATION_FAILURES);
        auth.monitoring.CancelPending();
        // ServiceAuthentication's existing owner check drops an unsent V1;
        // retain monitorWaiting until that cleanup, never erase unrelated V4/V6.
        SIMPLE_LOG_BLOCK(logger, flags::WARN, "Authentication rekey limit exceeded");
        if (auth.closeTCPConnection) auth.closeTCPConnection(); // Native TCP-only, asynchronous close.
        return;
    }
    const auto user = statistics.RecoveryUser();
    auto* session = auth.sessions->Find(user);
    // An unverified received USR never populates RecoveryUser. An independent
    // key exchange continues; its eventual success may rearm the failure Max.
    if (!session || session->IsExchanging()) return;
    if (!session->Ready(now) && !session->NeedsExchange(now)) return; // Respect the existing retry backoff.
    if (!session->RequestAuthenticationRenewal(now)) return;
    if (user == 1)
    {
        auth.controlEligible[0] = auth.monitoringEligible = false;
        auth.monitoring.CancelPending();
        auth.monitorWaiting = false;
        auth.monitoringAggressive.Reset();
        if (auth.pendingWireSize >= 4 && auth.pendingWire[2] == 120 && auth.pendingWire[3] == 1)
        {
            crypto::Clear(ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWireSize));
            auth.pendingWireSize = 0;
        }
        DiscardEmbeddedConfirm();
        if (auth.responderUser == user)
        {
            CancelAuthenticationReply();
            auth.responder.Reset();
            auth.replyIssued = false;
        }
        if (activeTask && auth.protectedTask && activeTask->AuthenticationUser() == user
            && tstate == TaskState::WAIT_FOR_RESPONSE)
        {
            responseTimer.cancel();
            tstate = OnResponseTimeout_WaitForResponse(); // Abort only the owning task, no global reset.
        }
    }
#else
    (void)now;
#endif
}

void MContext::ServiceAuthentication()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication || !authentication->sessions || !isOnline)
        return;
    auto& auth = *authentication;
    auth.serviceTimer.cancel();
    const auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());

    // A no-response task can be admitted while an independent key exchange owns TX.
    // Its start deadline must not depend on that borrowed buffer being released.
    if (activeTask && !activeTask->ExpectsResponse() && tstate == TaskState::TASK_READY
        && Timestamp(executor->get_time()) >= activeTask->StartExpirationTime())
    {
        activeTask->OnStartTimeout(Timestamp(executor->get_time()));
        CompleteActiveTask();
        tstate = TaskState::IDLE;
    }
    if (auth.recoveringKeys && auth.errorAttempt.valid && !auth.protectedConfirm
        && !auth.deferredAuthenticationCount && !auth.replyPending && !auth.replyInFlight
        && (auth.errorAttempt.user != 1 || !auth.monitorWaiting))
    {
        auto* owner = auth.sessions->Find(auth.errorAttempt.user);
        if (owner && owner->Sequence() == auth.errorAttempt.ksq)
        {
            owner->RequestRenewal(now);
            auth.controlEligible[auth.sessions->Index(owner->User())] = false;
            if (auth.responderUser == owner->User()) auth.responder.Reset();
        }
        auth.errorAttempt.valid = false; // Applied once; a replacement KSQ needs no repeat renewal.
    }
    ServiceSecurityStatistics(now);
    if (auth.protectedConfirm && now >= auth.confirmDeadline && !auth.replyInFlight
        && !(auth.wireInFlight && auth.wireSize >= 2 && auth.wire[1] == 0))
    {
        DiscardEmbeddedConfirm();
        auth.protectedConfirm = false;
        auth.responder.Reset();
    }
    if (auth.replyPending && !auth.replyInFlight && !IsAuthenticationReplyValid(now))
        CancelAuthenticationReply();
    if (auth.exchangeIndex < auth.SessionCount() && !auth.sessions->At(auth.exchangeIndex)->IsExchanging())
    {
        auth.restartRecoveryPending = false;
        // V4/V6 are generated only by this exchange. Tick may have expired or
        // reset its session while TX still owned wire; never send its queued copy.
        // A queued monitoring Challenge is independently owned and must survive.
        if (auth.pendingWireSize >= 8
            && auth.pendingWire[1] == FunctionCodeSpec::to_type(FunctionCode::AUTH_REQUEST)
            && auth.pendingWire[2] == 120 && (auth.pendingWire[3] == 4 || auth.pendingWire[3] == 6))
        {
            crypto::Clear(ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()));
            auth.pendingWireSize = 0;
        }
        auth.exchangeIndex = auth.SessionCount();
        auth.exchangeSequence = (auth.exchangeSequence + 1) & 15;
    }
    if (!auth.pendingWireSize && auth.exchangeIndex == auth.SessionCount() && !auth.monitorWaiting && !auth.protectedConfirm
        && !(activeTask && activeTask->IsAuthenticationTask())
        // Key expiry must not bypass the deferred Code 1 recovery above while its Reply still owns TX.
        && !(auth.recoveringKeys && auth.errorAttempt.valid && (auth.replyPending || auth.replyInFlight))
        && !(auth.protectedTask && (tstate == TaskState::WAIT_FOR_RESPONSE || IsAuthenticatedNoResponseTask())
             && !auth.recoveringKeys))
    {
        // Immediate expiry must not let the first user consume every service tick.
        // Reuse the settled exchange sequence; recovery still selects its exact owner.
        const size_t first = auth.recoveringKeys ? auth.sessions->Index(auth.errorAttempt.user)
            : (auth.sessions->config.replyTimeoutMs == 0 && auth.sessions->Size()
                   ? auth.exchangeSequence % auth.sessions->Size() : 0);
        for (size_t offset = 0; offset < auth.sessions->Size(); ++offset)
        {
            const size_t n = (first + offset) % auth.sessions->Size();
            auto* session = auth.sessions->At(n);
            if (session->NeedsExchange(now))
            {
                if (session->Begin(auth.association, auth.exchangeSequence, now,
                                   ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()),
                                   auth.pendingWireSize)
                    == SessionKeys::Result::OK)
                {
                    auth.exchangeIndex = n;
                    if (auth.sessions->config.replyTimeoutMs == 0)
                    {
                        session->Tick(now);
                        if (!session->IsExchanging())
                        {
                            crypto::Clear(ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()));
                            auth.pendingWireSize = 0;
                            auth.exchangeIndex = auth.SessionCount();
                            auth.exchangeSequence = (auth.exchangeSequence + 1) & 15;
                        }
                    }
                }
                break;
            }
        }
    }
    if (!isSending && auth.pendingWireSize)
    {
        std::memcpy(auth.wire.data(), auth.pendingWire.data(), auth.pendingWireSize);
        auth.wireSize = auth.pendingWireSize;
        if (auth.exchangeIndex < auth.SessionCount())
            auth.sessions->At(auth.exchangeIndex)->SetChangeQueued(
                ser4cpp::rseq_t(auth.wire.data(), auth.wireSize), false);
        crypto::Clear(ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()));
        auth.pendingWireSize = 0;
        auth.wireInFlight = true;
        this->Transmit(ser4cpp::rseq_t(auth.wire.data(), auth.wireSize));
    }
    else if (!isSending && !auth.monitorWaiting && auth.exchangeIndex == auth.SessionCount() && activeTask
             && tstate == TaskState::TASK_READY)
        tstate = this->ResumeActiveTask();
    if (!isSending && !auth.protectedConfirm)
        this->CheckConfirmTransmit();
    auth.serviceTimer = executor->start(std::chrono::milliseconds(100), [this]() { this->ServiceAuthentication(); });
#endif
}

bool MContext::RouteAuthentication(const ser4cpp::rseq_t& apdu, const APDUResponseHeader& header)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication)
        return false;
    auto* statistics = authentication->sessions ? &authentication->sessions->statistics : nullptr;
    uint16_t aggressiveUser = 0;
    const bool aggressive = apdu.length() >= 6 && apdu[4] == 120 && apdu[5] == 3
        && AggressiveMode::InspectUser(apdu, true, aggressiveUser);
    if (statistics && aggressive) statistics->Increment(SecurityStatistic::CRITICAL_MESSAGES_RECEIVED);
    // Standalone errors are Info objects (Table 7-9); native V7 events retain
    // their ordinary RESPONSE/UNSOLICITED_RESPONSE processing path.
    if (apdu.length() >= 6 && apdu[4] == 120 && apdu[5] == 7
        && header.function != FunctionCode::RESPONSE && header.function != FunctionCode::UNSOLICITED_RESPONSE)
    {
        auto& auth = *authentication;
        if (header.function != FunctionCode::AUTH_RESPONSE)
        {
            if (statistics) statistics->Unexpected();
            return true;
        }
        class ErrorHandler final : public IAPDUHandler
        {
        public:
            Group120Var7 value;
            bool valid = false;
            bool IsAllowed(uint32_t n, GroupVariation gv, QualifierCode qc) override
            {
                return n == 0 && gv == GroupVariation::Group120Var7 && qc == QualifierCode::FREE_FORMAT;
            }
            IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var7>& values) override
            {
                valid = values.Count() == 1;
                if (valid)
                    values.ForeachItem([this](const Group120Var7& v) { value = v; });
                return IINField::Empty();
            }
        } error;
        if (!header.control.IsFirAndFin() || header.control.CON || header.control.UNS
            || APDUParser::Parse(apdu.skip(4), error, nullptr) != ParseResult::OK || !error.valid
            || error.value.associationId != auth.association
            || !ValidAuthenticationError(error.value))
        {
            if (statistics) statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
            return true;
        }
        FORMAT_LOG_BLOCK(logger, flags::WARN, "Authentication error received: code=%u user=%u sequence=%u",
                         error.value.errorCode, error.value.userNum, error.value.seqNum);
        if (statistics) statistics->Increment(SecurityStatistic::ERROR_MESSAGES_RECEIVED);
        // CancelOnError itself enforces the exact Challenge owner. Unknown
        // nonzero users cannot cancel it, but still reach logging/accounting.
        const auto now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            executor->get_time().time_since_epoch()).count());
        auto* owner = auth.sessions ? auth.sessions->Find(error.value.userNum) : nullptr;
        const auto& attempt = auth.errorAttempt;
        const bool ownsAttempt = attempt.valid
            && activeTask && (tstate == TaskState::WAIT_FOR_RESPONSE || IsAuthenticatedNoResponseTask())
            && now < attempt.deadline
            && owner && owner->LastKeyStatus() && owner->Sequence() == attempt.ksq
            && error.value.userNum == attempt.user && error.value.seqNum == attempt.csq
            && header.control.SEQ == attempt.appSequence && attempt.appSequence == solSeq.Get()
            && activeTask->AuthenticationUser() == attempt.user;
        const bool recover = error.value.errorCode == 1 && auth.userCritical && ownsAttempt;
        auth.monitoring.Tick(now);
        // Error has no direction field. If both independent common-user
        // exchanges match, it cannot safely identify either owner.
        const bool ambiguous = ownsAttempt && auth.monitorWaiting && auth.monitoring.MatchesError(error.value, header.control.SEQ);
        if (ambiguous)
            SIMPLE_LOG_BLOCK(logger, flags::WARN, "Ambiguous authentication Error ownership; ignored");
        const bool discarded = !ambiguous && auth.monitorWaiting
            && auth.monitoring.CancelOnError(error.value, header.control.SEQ, now);
        if (discarded)
        {
            auth.monitorWaiting = false;
            // Only this operation's unsent Challenge is discarded; wire may be in flight.
            if (auth.pendingWireSize >= 8 && auth.pendingWire[1] == 0x20
                && auth.pendingWire[2] == 120 && auth.pendingWire[3] == 1
                && (auth.pendingWire[0] & 0x0F) == auth.monitorSequence)
            {
                crypto::Clear(ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWireSize));
                auth.pendingWireSize = 0;
            }
        }
        if (!discarded && !ownsAttempt)
        {
            if (statistics) statistics->Unexpected();
            SIMPLE_LOG_BLOCK(logger, flags::WARN, "Challenger has no matching authentication Error exchange");
        }
        if (discarded && error.value.errorCode == 5)
            FORMAT_LOG_BLOCK(logger, flags::WARN, "Authentication MAC rejected; next Challenge algorithm=%u (0=no permitted alternative)",
                             auth.monitoring.MACAlgorithm());
        if (auth.sessions && auth.sessions->config.errorObserver)
        {
            try
            {
                auth.sessions->config.errorObserver->OnErrorReceived(auth.association, error.value.userNum,
                    error.value.seqNum, error.value.errorCode, discarded);
            }
            catch (...) {} // Diagnostics must never alter protocol/TX ownership.
        }
        if (!discarded && !ambiguous && ownsAttempt && IsAuthenticatedNoResponseTask())
        {
            CompleteAuthenticatedNoResponseTask(false); // FC6 never retries an owned authentication failure.
            return true;
        }
        if (!discarded && !ambiguous && recover)
        {
            // 7.5.3.4(c): recover keys, never retry or authorize the original ASDU.
            // Local key expiry is allowed here; no expired key is read or reused.
            auth.userCritical = false;
            auth.recoveringKeys = true;
            auth.replyIssued = false;
            // Retain the owned attempt until ServiceAuthentication can settle
            // an independent Reply/CONFIRM without invalidating its key budget.
            ServiceAuthentication(); // Existing V4/V5/V6 procedure and retry budget.
        }
        return true;
    }
    // Recovery never turns the old request's response into success, including
    // if an independent common-user CONFIRM later sets replyIssued.
    if (authentication->recoveringKeys && (header.function == FunctionCode::RESPONSE
        || (header.function == FunctionCode::AUTH_RESPONSE && !authentication->protectedConfirm
            && apdu.length() >= 6 && apdu[4] == 120 && apdu[5] == 1)))
    {
        if (statistics) statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
        return true;
    }
    if (authentication->sessions)
    {
        auto& auth = *authentication;
        const auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
        if (header.function == FunctionCode::AUTH_RESPONSE && apdu.length() >= 6 && apdu[4] == 120 && apdu[5] == 5)
        {
            if (auth.exchangeIndex >= auth.SessionCount() || auth.pendingWireSize)
            {
                if (statistics) statistics->Unexpected();
                return true;
            }
            class StatusHandler final : public IAPDUHandler
            {
            public:
                Group120Var5 value;
                bool valid = false;
                bool IsAllowed(uint32_t n, GroupVariation gv, QualifierCode qc) override
                {
                    return n == 0 && gv == GroupVariation::Group120Var5 && qc == QualifierCode::FREE_FORMAT;
                }
                IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var5>& values) override
                {
                    valid = values.Count() == 1;
                    if (valid)
                        values.ForeachItem([this](const Group120Var5& v) { value = v; });
                    return IINField::Empty();
                }
            } status;
            const bool validStatus = APDUParser::Parse(apdu.skip(4), status, nullptr) == ParseResult::OK && status.valid;
            if (!validStatus)
            {
                if (statistics) statistics->Unexpected();
                return true; // No decoded owner: do not fail a different pending key transaction.
            }
            if (!header.control.IsFirAndFin() || header.control.CON || header.control.UNS
                || header.control.SEQ != auth.exchangeSequence)
            {
                if (statistics) statistics->Unexpected();
                return true; // Stale/malformed envelope cannot consume the current transaction.
            }
            auto* expected = auth.sessions->At(auth.exchangeIndex);
            if (status.value.userNum != expected->User())
            {
                auto* other = auth.sessions->Find(status.value.userNum);
                if (statistics && expected->AwaitingKeyConfirmation() && (!other || !other->IsStatusAuthentic(status.value)))
                    statistics->AuthenticationFailed(); // No authenticated recovery owner is established.
                size_t ignored = 0;
                expected->Process(auth.association, apdu, now,
                                  ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()), ignored);
                return true; // The owned core applies Table 7-13 row 12; no foreign session is reset.
            }
            if (auth.established && auth.peerRestartAllowed
                && auth.sessions->At(auth.exchangeIndex)->HasMonitoringHistory()
                && header.IIN.IsSet(IINBit::DEVICE_RESTART) && header.control.IsFirAndFin() && !header.control.CON
                && !header.control.UNS && header.control.SEQ == auth.exchangeSequence
                && status.value.userNum == auth.sessions->At(auth.exchangeIndex)->User()
                && status.value.macAlgorithm == 0 && status.value.keyStatus == 2)
            {
                auth.peerRestartAllowed = false;
                statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
                const bool countedRestart = auth.restartRecoveryPending;
                auth.restartRecoveryPending = false;
                auth.restartIINSet = true;
                if (!countedRestart && statistics->Exceeded(SecurityStatistic::RESTART_REKEYS))
                    return true;
                if (!countedRestart) statistics->Increment(SecurityStatistic::RESTART_REKEYS);
                statistics->ResetMaximum(SecurityStatistic::REPLY_TIMEOUTS);
                for (size_t n = 0; n < auth.sessions->Size(); ++n)
                    auth.sessions->At(n)->PeerRestart(now);
                ResetAuthentication();
                auth.exchangeIndex = auth.SessionCount();
                auth.exchangeSequence = (auth.exchangeSequence + 1) & 15;
                ServiceAuthentication();
                return true;
            }
            size_t size = 0;
            const auto result = auth.sessions->At(auth.exchangeIndex)
                                    ->Process(auth.association, apdu, now,
                                              ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()), size);
            if (result == SessionKeys::Result::OK || result == SessionKeys::Result::INSTALLED)
            {
                auth.restartRecoveryPending = false;
                auth.restartIINSet = header.IIN.IsSet(IINBit::DEVICE_RESTART);
            }
            auth.pendingWireSize = size;
            if (size)
                auth.sessions->At(auth.exchangeIndex)->SetChangeQueued(
                    ser4cpp::rseq_t(auth.pendingWire.data(), size), true);
            if (result == SessionKeys::Result::INSTALLED)
            {
                auth.established = true;
                auth.controlEligible[auth.exchangeIndex] = false;
                auto* session = auth.sessions->At(auth.exchangeIndex);
                if (session->User() == 1)
                    auth.monitoringEligible = false;
                if (session->User() == 1)
                    auth.monitoring.SetSessionKey(1, session->MonitoringKey(now), session->ValidUntil(), now);
                auth.exchangeIndex = auth.SessionCount();
                auth.exchangeSequence = (auth.exchangeSequence + 1) & 15;
            }
            this->ServiceAuthentication();
            return true;
        }
        // Deferred budget belongs exclusively to the current authenticated exchange.
        const bool nativeConfirmChallenge = auth.deferredAuthenticationCount && auth.protectedConfirm
            && ((!auth.nativeConfirmQueued && auth.responderUser == 1)
                || (auth.nativeConfirmQueued && auth.responder.GetState() == MasterResponder::State::WAITING_FOR_CHALLENGE))
            && !auth.controlAggressive.HasPendingConfirm()
            && !auth.replyPending && !auth.replyInFlight && header.function == FunctionCode::AUTH_RESPONSE
            && apdu.length() >= 6 && apdu[4] == 120 && apdu[5] == 1;
        if ((auth.deferredAuthenticationCount && !nativeConfirmChallenge) || auth.controlAggressive.HasPendingConfirm())
        {
            if (statistics) statistics->Unexpected();
            return true;
        }
        if (header.function == FunctionCode::AUTH_RESPONSE && apdu.length() >= 6 && apdu[4] == 120 && apdu[5] == 2)
        {
            class Reply final : public IAPDUHandler
            {
            public:
                Group120Var2 value;
                bool valid = false;
                bool IsAllowed(uint32_t n, GroupVariation gv, QualifierCode qc) override
                {
                    return n == 0 && gv == GroupVariation::Group120Var2 && qc == QualifierCode::FREE_FORMAT;
                }
                IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var2>& values) override
                {
                    valid = values.Count() == 1;
                    if (valid)
                        values.ForeachItem([this](const Group120Var2& v) { value = v; });
                    return IINField::Empty();
                }
            } reply;
            size_t size = 0;
            const bool validReply = auth.monitorWaiting && header.control.IsFirAndFin()
                && !header.control.CON && !header.control.UNS && header.control.SEQ == auth.monitorSequence
                && APDUParser::Parse(apdu.skip(4), reply, nullptr) == ParseResult::OK && reply.valid
                && auth.sessions->Find(1)->Ready(now);
            if (!validReply) auth.monitoring.RejectReply(now);
            if (validReply
                && auth.monitoring.Reply(auth.association, reply.value, now,
                                         ser4cpp::wseq_t(auth.verifiedResponse.data(), auth.verifiedResponse.size()),
                                         size)
                    == OutstationChallenger::Result::AUTHENTICATED)
            {
                auth.monitorWaiting = false;
                if (auth.monitoringAggressive.RememberChallenge(auth.monitoring.LastAcceptedChallenge(),
                                                                auth.monitoring.LastChallengeWasUnsolicited()))
                    auth.monitoringEligible = true;
                const auto verified = ser4cpp::rseq_t(auth.verifiedResponse.data(), size);
                // Two distinct authentication ASDUs: our monitoring Challenge and its Reply.
                this->ProcessAuthenticatedResponse(verified, verified, 2);
            }
            else
            {
                auth.monitoring.CancelPending();
                // Use the existing V1 owner cleanup. A rejected monitoring Reply
                // must not cancel another user's pending V4/V6 or in-flight TX.
                ServiceAuthentication();
            }
            crypto::Clear(ser4cpp::wseq_t(auth.verifiedResponse.data(), auth.verifiedResponse.size()));
            return true;
        }
        if ((header.function == FunctionCode::RESPONSE || header.function == FunctionCode::UNSOLICITED_RESPONSE)
            && apdu.length() >= 6 && apdu[4] == 120 && apdu[5] == 3)
        {
            if (!auth.sessions->config.aggressiveReceive || !auth.monitoringEligible
                || (header.function == FunctionCode::RESPONSE && auth.protectedTask && !auth.replyIssued))
            {
                if (statistics)
                {
                    if (auth.sessions->config.aggressiveReceive) statistics->AuthenticationFailed(aggressive ? 1 : 0);
                    else statistics->Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
                    statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
                }
                return true;
            }
            const uint16_t user = aggressiveUser;
            auto* session = auth.sessions->Find(1);
            size_t size = 0;
            if (session && session->Ready(now) && aggressive && user == 1
                && auth.monitoringAggressive.Verify(
                    auth.association, user, session->MonitoringKey(now), apdu,
                    ser4cpp::wseq_t(auth.verifiedResponse.data(), auth.verifiedResponse.size()), size))
            {
                if (statistics) statistics->Increment(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);
                auth.monitoring.ObserveAggressiveSequence(auth.monitoringAggressive.Sequence());
                if (!header.control.UNS && auth.monitorWaiting && header.control.SEQ == auth.monitorSequence)
                {
                    auth.monitoring.CancelPending();
                    auth.monitorWaiting = false;
                }
                this->ProcessAuthenticatedResponse(apdu, ser4cpp::rseq_t(auth.verifiedResponse.data(), size), 1);
            }
            else if (statistics)
            {
                statistics->AuthenticationFailed(aggressive ? 1 : 0); // Monitoring Direction is legitimately user 1.
                statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
                if (auth.monitorWaiting) statistics->Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
            }
            crypto::Clear(ser4cpp::wseq_t(auth.verifiedResponse.data(), auth.verifiedResponse.size()));
            return true;
        }
        if (header.function == FunctionCode::RESPONSE || header.function == FunctionCode::UNSOLICITED_RESPONSE)
        {
            if (auth.protectedTask && !auth.replyIssued && header.function == FunctionCode::RESPONSE)
            {
                if (statistics) statistics->Unexpected();
                return true;
            }
            if (auth.monitorWaiting || auth.pendingWireSize || auth.controlAggressive.HasPendingConfirm())
            {
                if (statistics)
                {
                    if (auth.monitorWaiting) statistics->Increment(SecurityStatistic::CRITICAL_MESSAGES_RECEIVED);
                    statistics->Unexpected();
                }
                return true;
            }
            Group120Var1 embedded;
            size_t nativeSize = 0;
            if (!auth.controlAggressive.InspectEmbeddedChallenge(apdu, embedded, nativeSize))
            {
                if (statistics) statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
                return true;
            }
            auto* session = auth.sessions->Find(1);
            if (!session || !session->Ready(now))
            {
                if (statistics)
                {
                    statistics->Increment(SecurityStatistic::CRITICAL_MESSAGES_RECEIVED);
                    statistics->Unexpected();
                    if (session && session->IsExchanging()) statistics->AuthenticationFailed();
                }
                return true;
            }
            if (auth.monitoring.GetState() == OutstationChallenger::State::NO_SESSION_KEYS)
                auth.monitoring.SetSessionKey(1, session->MonitoringKey(now), session->ValidUntil(), now);
            size_t size = 0;
            if (auth.monitoring.Challenge(auth.association, apdu, IINField::Empty(), now,
                                          ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()), size)
                == OutstationChallenger::Result::OK)
            {
                auth.pendingWireSize = size;
                auth.monitorWaiting = true;
                auth.monitorSequence = header.control.SEQ;
                this->ServiceAuthentication();
            }
            else if (statistics) statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
            return true;
        }
    }
    if (header.function == FunctionCode::AUTH_RESPONSE)
    {
        const bool noResponseTask = IsAuthenticatedNoResponseTask();
        if (noResponseTask && (!IsWaitingForNoResponseChallenge() || header.control.SEQ != solSeq.Get()
            || apdu.length() < 6 || apdu[4] != 120 || apdu[5] != 1))
        {
            if (statistics) statistics->Unexpected();
            return true;
        }
        if (authentication->controlAggressive.HasPendingConfirm())
            return true;
        if ((!authentication->protectedConfirm
             && (!authentication->protectedTask || (tstate != TaskState::WAIT_FOR_RESPONSE && !noResponseTask)))
            || authentication->replyPending || authentication->replyInFlight)
        {
            if (statistics) statistics->Unexpected();
            this->ResetAuthentication();
            return true;
        }
        const auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
        const auto result = authentication->responder.Respond(
            authentication->association, apdu, now,
            ser4cpp::wseq_t(authentication->reply.data(), authentication->reply.size()), authentication->replySize);
        if (result != MasterResponder::Result::OK)
        {
            if (statistics) statistics->Unexpected();
            if (noResponseTask || result == MasterResponder::Result::UNSUPPORTED_ALGORITHM)
                CancelAuthenticationReply(true); // Only this responder's task or native CONFIRM owns the failure.
            else
                this->ResetAuthentication();
            return true;
        }
        authentication->replyPending = true;
        authentication->replyDeadline = now + params.authentication.replyTimeoutMs;
        authentication->replyKSQ = 0;
        authentication->replyCountExhausted = false;
        if (authentication->protectedConfirm && !authentication->nativeConfirmQueued
            && authentication->responderUser == 1)
            authentication->replyDeadline = std::min(authentication->replyDeadline, authentication->confirmDeadline);
        if (authentication->sessions)
        {
            auto* session = authentication->sessions->Find(authentication->responderUser);
            const auto now = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
            if (!session || !session->Ready(now)
                || (authentication->deferredAuthenticationCount && session->User() == 1
                    && (session->Sequence() != authentication->deferredAuthenticationKSQ
                        || now >= authentication->confirmDeadline)))
            {
                if (noResponseTask) CancelAuthenticationReply(true);
                else ResetAuthentication();
                return true;
            }
            authentication->replyKSQ = session->Sequence();
            authentication->replyDeadline = std::min(authentication->replyDeadline, session->ValidUntil());
            if (authentication->deferredAuthenticationCount && session->User() == 1)
                ++authentication->deferredAuthenticationCount; // Distinct Challenge using the reserved common session.
            else
            {
                authentication->replyCountExhausted = session->RemainingMessages() == 1;
                session->CountAuthentication(now);
            }
        }
        if (noResponseTask) tstate = TaskState::WAIT_FOR_AUTH_REPLY_TX;
        if (noResponseTask || !authentication->protectedConfirm)
        {
            responseTimer.cancel();
            this->StartResponseTimer();
        }
        if (!isSending)
            this->TransmitAuthenticationReply();
        return true;
    }
    // A normal response cannot bypass the Challenge/Reply phase of a protected task.
    if (header.function == FunctionCode::RESPONSE && authentication->protectedTask && !authentication->replyIssued)
        return true;
#else
    (void)apdu;
    (void)header;
#endif
    return false;
}
} // namespace opendnp3
