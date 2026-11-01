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
#include "crypto/CryptoProvider.h"
#include "gen/objects/Group12.h"
#include "gen/objects/Group41.h"
#include "logging/LogMacros.h"
#include "master/CommandTask.h"
#include "master/EmptyResponseTask.h"
#include "master/MeasurementHandler.h"
#include "master/RestartOperationTask.h"
#include "master/UserPollTask.h"

#include "opendnp3/logging/LogLevels.h"

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
        authentication->pendingWireSize = 0;
        authentication->exchangeIndex = 2;
        authentication->peerRestartAllowed = true;
        authentication->monitorWaiting = false;
        authentication->monitoring.Reset();
        if (authentication->sessions)
            authentication->sessions->Disconnect();
    }
#endif
    this->ResetAuthentication();
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
    if (!result.success)
    {
        return true;
    }

    logging::LogHeader(this->logger, flags::APP_HEADER_RX, result.header);

    this->OnParsedHeader(message.payload, result.header, result.objects);

    return true;
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
        if (authentication->replyInFlight)
        {
            authentication->replyInFlight = false;
            authentication->protectedConfirm = false;
            crypto::Clear(ser4cpp::wseq_t(authentication->reply.data(), authentication->reply.size()));
        }
        if (authentication->replyPending)
        {
            this->TransmitAuthenticationReply();
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
        this->ResetAuthentication();
        this->tstate = this->OnResponseTimeoutEvent();
    }
}

void MContext::CompleteActiveTask()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication)
    {
        authentication->protectedTask = false;
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
    if (this->RouteAuthentication(apdu, header))
        return;
    // Note: this looks silly, but OnParsedHeader() is virtual and can be overriden to do SA
    this->ProcessAPDU(header, objects);
}

/// --- command handlers ----

void MContext::DirectOperate(CommandSet&& commands, const CommandResultCallbackT& callback, const TaskConfig& config)
{
    const auto timeout = Timestamp(this->executor->get_time()) + params.taskStartTimeout;
    this->ScheduleAdhocTask(CommandTask::CreateDirectOperate(this->tasks.context, std::move(commands),
                                                             this->params.controlQualifierMode, *application, callback,
                                                             timeout, config, logger));
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
        return;
    }

    auto result = MeasurementHandler::ProcessMeasurements(header.as_response_info(), objects, logger, SOEHandler.get());

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
            if (!session || !session->Ready(now) || now >= auth.confirmDeadline)
            {
                DiscardEmbeddedConfirm();
                auth.protectedConfirm = false;
                return false;
            }
            if (auth.exchangeIndex < 2 || auth.pendingWireSize || auth.replyPending || auth.replyInFlight)
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
            session->CountAuthentication(now);
            this->Transmit(ser4cpp::rseq_t(auth.wire.data(), auth.wireSize));
            this->confirmQueue.pop_front();
            return true;
        }
        if (auth.protectedConfirm || auth.exchangeIndex < 2 || auth.pendingWireSize || !session || !session->Ready(now)
            || auth.responder.GetState() == MasterResponder::State::WAITING_FOR_CHALLENGE)
            return false;
        if (auth.responder.SetSessionKey(1, session->ControlKey(now), session->ValidUntil(), now)
                != MasterResponder::Result::OK
            || auth.responder.RetainRequest(auth.association, wrapper.ToRSeq(), now) != MasterResponder::Result::OK)
            return false;
        auth.responderUser = 1;
        auth.protectedConfirm = true;
        auth.confirmDeadline = now + auth.sessions->config.replyTimeoutMs;
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
    this->isSending = true;
    this->lower->BeginTransmit(Message(this->addresses, data));
}

void MContext::StartResponseTimer()
{
    auto timeout = [self = shared_from_this()]() { self->OnResponseTimeout(); };
    this->responseTimer = this->executor->start(this->params.responseTimeout.value, timeout);
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
    if (authentication && authentication->sessions)
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
        auto* common = authentication->sessions->Find(1);
        if (common && common->Ready(now) && common->RemainingMessages() < (session->User() == 1 ? 4u : 2u))
            common->RequestRenewal(now);
        if (session->Ready(now) && session->RemainingMessages() < 2)
            session->RequestRenewal(now);
        const bool allReady
            = authentication->sessions->At(0)->Ready(now) && authentication->sessions->At(1)->Ready(now);
        if (!allReady || authentication->exchangeIndex < 2 || !session->Ready(now) || authentication->protectedConfirm)
        {
            if (Timestamp(executor->get_time()) >= activeTask->StartExpirationTime())
            {
                activeTask->OnStartTimeout(Timestamp(executor->get_time()));
                CompleteActiveTask();
                return TaskState::IDLE;
            }
            return TaskState::TASK_READY;
        }
        const auto index = session->User() == authentication->sessions->config.users[0] ? 0u : 1u;
        const bool fresh = authentication->keyEpoch[index] != session->Sequence();
        if (fresh || authentication->responderUser != session->User()
            || authentication->responder.GetState() == MasterResponder::State::NO_SESSION_KEYS)
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
        activeTask->OnMessageFormatError(Timestamp(executor->get_time()));
        this->CompleteActiveTask();
        return TaskState::IDLE;
    }

    this->StartResponseTimer();
    auto apdu = request.ToRSeq();
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication)
    {
        // Test-mode policy protects all ordinary functions except READ/CONFIRM,
        // including every mandatory critical function in IEEE Table 7-7 (p252).
        authentication->protectedTask = request.GetFunction() != FunctionCode::CONFIRM
            && (authentication->sessions || request.GetFunction() != FunctionCode::READ);
        authentication->replyIssued = false;
        bool aggressive = false;
        if (authentication->protectedTask && authentication->sessions)
        {
            auto& auth = *authentication;
            auto* session = auth.sessions->Find(activeTask->AuthenticationUser());
            const auto index = session->User() == auth.sessions->config.users[0] ? 0u : 1u;
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
        if (authentication->protectedTask && !aggressive
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
    this->Transmit(apdu);

    return TaskState::WAIT_FOR_RESPONSE;
}

//// --- State tables ---

MContext::TaskState MContext::OnTransmitComplete()
{
    switch (tstate)
    {
    case (TaskState::TASK_READY):
        return this->ResumeActiveTask();
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
        return tstate;
    }
}

MContext::TaskState MContext::OnResponseTimeoutEvent()
{
    switch (tstate)
    {
    case (TaskState::WAIT_FOR_RESPONSE):
        return OnResponseTimeout_WaitForResponse();
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
        return TaskState::WAIT_FOR_RESPONSE;
    }

    this->responseTimer.cancel();

    this->solSeq.Increment();

    auto now = Timestamp(this->executor->get_time());

    auto result = this->activeTask->OnResponse(header, objects, now);

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
    SIMPLE_LOG_BLOCK(logger, flags::WARN, "Timeout waiting for response");

    auto now = Timestamp(this->executor->get_time());
    this->activeTask->OnResponseTimeout(now);
    this->solSeq.Increment();
    this->CompleteActiveTask();
    return TaskState::IDLE;
}

void MContext::DiscardEmbeddedConfirm()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication)
        return;
    auto& aggressive = authentication->controlAggressive;
    // ProcessAuthenticatedResponse reserves exactly one owned entry at the front.
    // Older entries, even with identical SEQ/UNS, belong to other operations.
    if (!confirmQueue.empty()
        && aggressive.RequiresConfirm(confirmQueue.front().control.SEQ, confirmQueue.front().control.UNS))
        confirmQueue.pop_front();
    aggressive.DiscardPendingConfirms();
#endif
}

void MContext::ProcessAuthenticatedResponse(const ser4cpp::rseq_t& wire, const ser4cpp::rseq_t& native)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    auto& auth = *authentication;
    if (auth.controlAggressive.HasPendingConfirm())
        return;
    const auto original = APDUHeaderParser::ParseResponse(native);
    Group120Var1 challenge;
    size_t nativeSize = 0;
    if (!original.success || !auth.controlAggressive.InspectEmbeddedChallenge(native, challenge, nativeSize))
        return;
    if (nativeSize != native.length())
    {
        const auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
        auto* session = auth.sessions->Find(1);
        const auto& header = original.header;
        if (!session || !session->Ready(now) || auth.exchangeIndex < 2 || auth.pendingWireSize
            || auth.protectedConfirm || auth.replyPending || auth.replyInFlight
            || (header.function == FunctionCode::RESPONSE
                && (!activeTask || tstate != TaskState::WAIT_FOR_RESPONSE || header.control.SEQ != solSeq)))
            return;
        if (!auth.responder.ObserveEmbeddedChallenge(auth.association, challenge, header.control.UNS, now)
            || !auth.controlAggressive.RememberChallenge(wire, header.control.UNS, true))
            return;
        // The full authenticated wire APDU is the Table A-9 seed. Strip only
        // G120V1 for native dispatch; reserve its own CONFIRM ahead of older entries.
        auth.keyEpoch[0] = session->Sequence();
        if (!(wire.length() >= 6 && wire[4] == 120 && wire[5] == 3))
            session->CountAuthentication(now); // Embedded Challenge is an authentication ASDU.
        if (!session->Ready(now))
        {
            // No queue entry has been reserved yet.
            auth.controlAggressive.DiscardPendingConfirms();
            return;
        }
        auth.protectedConfirm = true;
        auth.confirmDeadline = now + auth.sessions->config.replyTimeoutMs;
        confirmQueue.push_front(header.control.UNS ? APDUHeader::UnsolicitedConfirm(header.control.SEQ)
                                                   : APDUHeader::SolicitedConfirm(header.control.SEQ));
    }
    this->ProcessAPDU(original.header, original.objects.take(nativeSize - 4));
    if (auth.controlAggressive.HasPendingConfirm())
        this->CheckConfirmTransmit();
#else
    (void)wire;
    (void)native;
#endif
}

void MContext::ResetAuthentication()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication)
        return;
    authentication->responder.Reset();
    DiscardEmbeddedConfirm();
    authentication->controlAggressive.Reset();
    authentication->monitoringAggressive.Reset();
    authentication->controlEligible = {{false, false}};
    authentication->monitoringEligible = false;
    crypto::Clear(ser4cpp::wseq_t(authentication->aggressiveWire.data(), authentication->aggressiveWire.size()));
    authentication->protectedConfirm = false;
    if (authentication->monitorWaiting)
        authentication->pendingWireSize = 0;
    authentication->monitoring.Reset();
    authentication->monitorWaiting = false;
    authentication->replyPending = false;
    authentication->replySize = 0;
    authentication->replyIssued = false;
    if (!authentication->replyInFlight)
        crypto::Clear(ser4cpp::wseq_t(authentication->reply.data(), authentication->reply.size()));
#endif
}

void MContext::TransmitAuthenticationReply()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
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
            const auto index = session->User() == authentication->sessions->config.users[0] ? 0u : 1u;
            if (authentication->controlAggressive.RememberChallenge(
                    authentication->responder.LastAcceptedChallenge(),
                    authentication->responder.LastChallengeWasUnsolicited()))
                authentication->controlEligible[index] = true;
            session->CountAuthentication(now);
        }
    }
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
    if (auth.restartRekeys && now - auth.restartWindow >= auth.sessions->config.renewalIntervalMs)
        auth.restartRekeys = 0;
    for (size_t n = 0; n < 2; ++n)
        auth.sessions->At(n)->Tick(now);
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
    if (auth.protectedConfirm && now >= auth.confirmDeadline && !auth.replyInFlight
        && !(auth.wireInFlight && auth.wireSize >= 2 && auth.wire[1] == 0))
    {
        DiscardEmbeddedConfirm();
        auth.protectedConfirm = false;
        auth.responder.Reset();
    }
    if (auth.exchangeIndex < 2 && !auth.sessions->At(auth.exchangeIndex)->IsExchanging())
    {
        auth.exchangeIndex = 2;
        auth.exchangeSequence = (auth.exchangeSequence + 1) & 15;
    }
    if (!auth.pendingWireSize && auth.exchangeIndex == 2 && !auth.monitorWaiting && !auth.protectedConfirm
        && !(auth.protectedTask && tstate == TaskState::WAIT_FOR_RESPONSE))
    {
        for (size_t n = 0; n < 2; ++n)
        {
            auto* session = auth.sessions->At(n);
            if (session->NeedsExchange(now))
            {
                if (session->Begin(auth.association, auth.exchangeSequence, now,
                                   ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()),
                                   auth.pendingWireSize)
                    == SessionKeys::Result::OK)
                    auth.exchangeIndex = n;
                break;
            }
        }
    }
    if (!isSending && auth.pendingWireSize)
    {
        std::memcpy(auth.wire.data(), auth.pendingWire.data(), auth.pendingWireSize);
        auth.wireSize = auth.pendingWireSize;
        auth.pendingWireSize = 0;
        auth.wireInFlight = true;
        this->Transmit(ser4cpp::rseq_t(auth.wire.data(), auth.wireSize));
    }
    else if (!isSending && !auth.monitorWaiting && auth.exchangeIndex == 2 && activeTask
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
    if (authentication->sessions)
    {
        auto& auth = *authentication;
        const auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
        if (header.function == FunctionCode::AUTH_RESPONSE && apdu.length() >= 6 && apdu[4] == 120 && apdu[5] == 5)
        {
            if (auth.exchangeIndex >= 2 || auth.pendingWireSize)
                return true;
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
            if (auth.established && auth.peerRestartAllowed
                && auth.sessions->At(auth.exchangeIndex)->HasMonitoringHistory()
                && header.IIN.IsSet(IINBit::DEVICE_RESTART) && header.control.IsFirAndFin() && !header.control.CON
                && !header.control.UNS && APDUParser::Parse(apdu.skip(4), status, nullptr) == ParseResult::OK
                && status.valid && status.value.userNum == auth.sessions->At(auth.exchangeIndex)->User()
                && status.value.macAlgorithm == 0 && status.value.keyStatus == 2)
            {
                auth.peerRestartAllowed = false;
                if (auth.restartRekeys >= auth.sessions->config.maxRestartRekeys)
                    return true;
                ++auth.restartRekeys;
                auth.restartWindow = now;
                for (size_t n = 0; n < 2; ++n)
                    auth.sessions->At(n)->PeerRestart(now);
                ResetAuthentication();
                auth.exchangeIndex = 2;
                auth.exchangeSequence = (auth.exchangeSequence + 1) & 15;
                ServiceAuthentication();
                return true;
            }
            size_t size = 0;
            const auto result = auth.sessions->At(auth.exchangeIndex)
                                    ->Process(auth.association, apdu, now,
                                              ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()), size);
            auth.pendingWireSize = size;
            if (result == SessionKeys::Result::INSTALLED)
            {
                auth.established = true;
                auth.controlEligible[auth.exchangeIndex] = false;
                auto* session = auth.sessions->At(auth.exchangeIndex);
                if (session->User() == 1)
                    auth.monitoringEligible = false;
                if (session->User() == 1)
                    auth.monitoring.SetSessionKey(1, session->MonitoringKey(now), session->ValidUntil(), now);
                auth.exchangeIndex = 2;
                auth.exchangeSequence = (auth.exchangeSequence + 1) & 15;
            }
            this->ServiceAuthentication();
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
            if (auth.monitorWaiting && header.control.IsFirAndFin() && !header.control.CON && !header.control.UNS
                && header.control.SEQ == auth.monitorSequence
                && APDUParser::Parse(apdu.skip(4), reply, nullptr) == ParseResult::OK && reply.valid
                && auth.sessions->Find(1)->Ready(now)
                && auth.monitoring.Reply(auth.association, reply.value, now,
                                         ser4cpp::wseq_t(auth.verifiedResponse.data(), auth.verifiedResponse.size()),
                                         size)
                    == OutstationChallenger::Result::AUTHENTICATED)
            {
                auth.monitorWaiting = false;
                if (auth.monitoringAggressive.RememberChallenge(auth.monitoring.LastAcceptedChallenge(),
                                                                auth.monitoring.LastChallengeWasUnsolicited()))
                    auth.monitoringEligible = true;
                auth.sessions->Find(1)->CountAuthentication(now);
                auth.sessions->Find(1)->CountAuthentication(now);
                const auto verified = ser4cpp::rseq_t(auth.verifiedResponse.data(), size);
                this->ProcessAuthenticatedResponse(verified, verified);
            }
            else
                this->ResetAuthentication();
            crypto::Clear(ser4cpp::wseq_t(auth.verifiedResponse.data(), auth.verifiedResponse.size()));
            return true;
        }
        if ((header.function == FunctionCode::RESPONSE || header.function == FunctionCode::UNSOLICITED_RESPONSE)
            && apdu.length() >= 6 && apdu[4] == 120 && apdu[5] == 3)
        {
            if (!auth.sessions->config.aggressiveReceive || !auth.monitoringEligible
                || (header.function == FunctionCode::RESPONSE && auth.protectedTask && !auth.replyIssued))
                return true;
            uint16_t user = 0;
            auto* session = auth.sessions->Find(1);
            size_t size = 0;
            if (session && session->Ready(now) && AggressiveMode::InspectUser(apdu, true, user) && user == 1
                && auth.monitoringAggressive.Verify(
                    auth.association, user, session->MonitoringKey(now), apdu,
                    ser4cpp::wseq_t(auth.verifiedResponse.data(), auth.verifiedResponse.size()), size))
            {
                auth.monitoring.ObserveAggressiveSequence(auth.monitoringAggressive.Sequence());
                if (!header.control.UNS && auth.monitorWaiting && header.control.SEQ == auth.monitorSequence)
                {
                    auth.monitoring.CancelPending();
                    auth.monitorWaiting = false;
                }
                session->CountAuthentication(now);
                this->ProcessAuthenticatedResponse(apdu, ser4cpp::rseq_t(auth.verifiedResponse.data(), size));
            }
            crypto::Clear(ser4cpp::wseq_t(auth.verifiedResponse.data(), auth.verifiedResponse.size()));
            return true;
        }
        if (header.function == FunctionCode::RESPONSE || header.function == FunctionCode::UNSOLICITED_RESPONSE)
        {
            if (auth.protectedTask && !auth.replyIssued && header.function == FunctionCode::RESPONSE)
                return true;
            if (auth.monitorWaiting || auth.pendingWireSize || auth.controlAggressive.HasPendingConfirm())
                return true;
            Group120Var1 embedded;
            size_t nativeSize = 0;
            if (!auth.controlAggressive.InspectEmbeddedChallenge(apdu, embedded, nativeSize))
                return true;
            auto* session = auth.sessions->Find(1);
            if (!session || !session->Ready(now))
                return true;
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
            return true;
        }
    }
    if (header.function == FunctionCode::AUTH_RESPONSE)
    {
        if (authentication->controlAggressive.HasPendingConfirm())
            return true;
        if ((!authentication->protectedConfirm
             && (!authentication->protectedTask || tstate != TaskState::WAIT_FOR_RESPONSE))
            || authentication->replyPending || authentication->replyInFlight)
        {
            this->ResetAuthentication();
            return true;
        }
        const auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
        if (authentication->responder.Respond(
                authentication->association, apdu, now,
                ser4cpp::wseq_t(authentication->reply.data(), authentication->reply.size()), authentication->replySize)
            != MasterResponder::Result::OK)
        {
            this->ResetAuthentication();
            return true;
        }
        authentication->replyPending = true;
        if (authentication->sessions)
        {
            auto* session = authentication->sessions->Find(authentication->responderUser);
            const auto now = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
            if (!session || !session->Ready(now))
            {
                ResetAuthentication();
                return true;
            }
            session->CountAuthentication(now);
        }
        if (!authentication->protectedConfirm)
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
