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
#include "OutstationContext.h"

#include "app/APDUBuilders.h"
#include "app/APDULogging.h"
#include "app/Functions.h"
#include "app/parsing/APDUHeaderParser.h"
#include "app/parsing/APDUParser.h"
#include "auth/AuthenticationError.h"
#include "crypto/CryptoProvider.h"
#include "logging/LogMacros.h"
#include "outstation/AssignClassHandler.h"
#include "outstation/ClassBasedRequestHandler.h"
#include "outstation/CommandActionAdapter.h"
#include "outstation/CommandResponseHandler.h"
#include "outstation/ConstantCommandAction.h"
#include "outstation/FreezeRequestHandler.h"
#include "outstation/IINHelpers.h"
#include "outstation/ReadHandler.h"
#include "outstation/WriteHandler.h"

#include "opendnp3/logging/LogLevels.h"

#include <algorithm>

#include <cstring>
#include <stdexcept>
#include <utility>

namespace opendnp3
{

OContext::OContext(const Addresses& addresses,
                   const OutstationConfig& config,
                   const DatabaseConfig& db_config,
                   const Logger& logger,
                   const std::shared_ptr<exe4cpp::IExecutor>& executor,
                   std::shared_ptr<ILowerLayer> lower,
                   std::shared_ptr<ICommandHandler> commandHandler,
                   std::shared_ptr<IOutstationApplication> application)
    :

      addresses(addresses),
      logger(logger),
      executor(executor),
      lower(std::move(lower)),
      commandHandler(std::move(commandHandler)),
      application(std::move(application)),
      eventBuffer(config.eventBufferConfig),
      database(db_config, eventBuffer, *this->application, config.params.typesAllowedInClass0),
      rspContext(database, eventBuffer),
      params(config.params),
      isOnline(false),
      isTransmitting(false),
      staticIIN(IINBit::DEVICE_RESTART),
      deferred(config.params.maxRxFragSize),
      sol(config.params.maxTxFragSize),
      unsol(config.params.maxTxFragSize),
      unsolRetries(config.params.numUnsolRetries),
      shouldCheckForUnsolicited(false)
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

bool OContext::OnLowerLayerUp()
{
    if (isOnline)
    {
        SIMPLE_LOG_BLOCK(logger, flags::ERR, "already online");
        return false;
    }

    isOnline = true;
    this->shouldCheckForUnsolicited = true;
    this->CheckForTaskStart();
    return true;
}

bool OContext::OnLowerLayerDown()
{
    if (!isOnline)
    {
        SIMPLE_LOG_BLOCK(logger, flags::ERR, "already offline");
        return false;
    }

    this->state = &StateIdle::Inst();

    isOnline = false;
    isTransmitting = false;
    this->ResetAuthentication();
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication && authentication->sessions)
    {
        authentication->sessions->Disconnect();
        authentication->pendingWireSize = 0;
        authentication->selectUser = 0;
    }
#endif
    sol.Reset();
    unsol.Reset();
    history.Reset();
    deferred.Reset();
    eventBuffer.Unselect();
    rspContext.Reset();
    confirmTimer.cancel();

    return true;
}

bool OContext::OnTxReady()
{
    if (!isOnline || !isTransmitting)
    {
        return false;
    }

    this->isTransmitting = false;
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication)
    {
        crypto::Clear(ser4cpp::wseq_t(authentication->challenge.data(), authentication->challenge.size()));
        crypto::Clear(ser4cpp::wseq_t(authentication->aggressiveWire.data(), authentication->aggressiveWire.size()));
    }
#endif
    this->TransmitPendingAuthentication();
    if (!isTransmitting)
        this->CheckForTaskStart();
    return true;
}

bool OContext::OnReceive(const Message& message)
{
    if (!this->isOnline)
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::ERR, "ignoring received data while offline");
        return false;
    }

    this->ProcessMessage(message);

    this->CheckForTaskStart();

    return true;
}

OutstationState& OContext::OnReceiveSolRequest(const ParsedRequest& request)
{
    // analyze this request to see how it compares to the last request
    if (this->history.HasLastRequest())
    {
        if (this->sol.seq.num.Equals(request.header.control.SEQ))
        {
            if (this->history.FullyEqualsLastRequest(request.header, request.objects))
            {
                if (request.header.function == FunctionCode::READ)
                {
                    return this->state->OnRepeatReadRequest(*this, request);
                }

                return this->state->OnRepeatNonReadRequest(*this, request);
            }
            else // new operation with same SEQ
            {
                return this->ProcessNewRequest(request);
            }
        }
        else // completely new sequence #
        {
            return this->ProcessNewRequest(request);
        }
    }
    else
    {
        return this->ProcessNewRequest(request);
    }
}

OutstationState& OContext::ProcessNewRequest(const ParsedRequest& request)
{
    this->sol.seq.num = request.header.control.SEQ;

    if (request.header.function == FunctionCode::READ)
    {
        return this->state->OnNewReadRequest(*this, request);
    }

    return this->state->OnNewNonReadRequest(*this, request);
}

bool OContext::ProcessObjects(const ParsedRequest& request)
{
    if (request.addresses.IsBroadcast())
    {
        this->state = &this->state->OnBroadcastMessage(*this, request);
        return true;
    }

    if (Functions::IsNoAckFuncCode(request.header.function))
    {
        // this is the only request we process while we are transmitting
        // because it doesn't require a response of any kind
        return this->ProcessRequestNoAck(request);
    }

    if (this->isTransmitting)
    {
        this->deferred.Set(request);
        return true;
    }

    if (request.header.function == FunctionCode::CONFIRM)
    {
        return this->ProcessConfirm(request);
    }

    return this->ProcessRequest(request);
}

bool OContext::ProcessRequest(const ParsedRequest& request)
{
    if (request.header.control.UNS)
    {
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Ignoring unsol with invalid function code: %s",
                         FunctionCodeSpec::to_human_string(request.header.function));
        return false;
    }

    this->state = &this->OnReceiveSolRequest(request);
    return true;
}

bool OContext::ProcessConfirm(const ParsedRequest& request)
{
    this->state = &this->state->OnConfirm(*this, request);
    return true;
}

OutstationState& OContext::BeginResponseTx(uint16_t destination, APDUResponse& response)
{
    CheckForBroadcastConfirmation(response);

    const auto data = response.ToRSeq();
    this->sol.tx.Record(response.GetControl(), data);
    this->sol.seq.confirmNum = response.GetControl().SEQ;
    this->BeginTx(destination, data);

    if (response.GetControl().CON)
    {
        this->RestartSolConfirmTimer();
        return StateSolicitedConfirmWait::Inst();
    }

    return StateIdle::Inst();
}

void OContext::BeginRetransmitLastResponse(uint16_t destination)
{
    this->BeginTx(destination, this->sol.tx.GetLastResponse());
}

void OContext::BeginRetransmitLastUnsolicitedResponse()
{
    this->BeginTx(this->addresses.destination, this->unsol.tx.GetLastResponse());
}

void OContext::BeginUnsolTx(APDUResponse& response)
{
    CheckForBroadcastConfirmation(response);

    const auto data = response.ToRSeq();
    this->unsol.tx.Record(response.GetControl(), data);
    this->unsol.seq.confirmNum = this->unsol.seq.num;
    this->unsol.seq.num.Increment();
    this->BeginTx(this->addresses.destination, data);
}

void OContext::BeginTx(uint16_t destination, const ser4cpp::rseq_t& message)
{
    auto encoded = message;
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication && authentication->sessions && message.length() >= 4
        && (message[1] == 0x81 || message[1] == 0x82))
    {
        auto& auth = *authentication;
        const auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
        auto* session = auth.sessions->Find(1);
        if (!session || !session->Ready(now))
            return;
        if (auth.sessions->config.aggressiveTransmit && auth.monitoringEligible
            && auth.monitoringAggressive.HasChallenge((message[0] & 0x10) != 0))
        {
            size_t size = 0;
            if (!auth.monitoringAggressive.Create(
                    auth.association, 1, session->MonitoringKey(now), message,
                    ser4cpp::wseq_t(auth.aggressiveWire.data(), auth.aggressiveWire.size()), size))
                return;
            encoded = ser4cpp::rseq_t(auth.aggressiveWire.data(), size);
            session->CountAuthentication(now); // One outgoing aggressive-response ASDU (V3/native/V9).
        }
        else
        {
            if (auth.monitoring.SetSessionKey(1, session->MonitoringKey(now), session->ValidUntil(), now)
                    != MasterResponder::Result::OK
                || auth.monitoring.RetainRequest(auth.association, message, now) != MasterResponder::Result::OK)
                return;
            auth.monitoringPending = true;
            auth.monitoringTimer.cancel();
            auth.monitoringTimer
                = executor->start(std::chrono::milliseconds(auth.sessions->config.replyTimeoutMs), [this]() {
                      const auto time = static_cast<uint64_t>(
                          std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch())
                              .count());
                      if (authentication->pendingWireSize >= 6 && authentication->pendingWire[1] == 0x83
                          && authentication->pendingWire[4] == 120 && authentication->pendingWire[5] == 2)
                      {
                          this->ResetAuthentication(); // Expired, unsent monitoring Reply; preserve in-flight bytes.
                          this->CheckForTaskStart();
                          return;
                      }
                      this->FinalizeControlCounts(time);
                      authentication->monitoring.Tick(time);
                      authentication->monitoringPending = false;
                      this->CheckForTaskStart();
                  });
        }
    }
#endif
    logging::ParseAndLogResponseTx(this->logger, encoded);
    this->isTransmitting = true;
    const bool started = this->lower->BeginTransmit(Message(Addresses(this->addresses.source, destination), encoded));
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (started && authentication && authentication->sessions)
    {
        auto& statistics = authentication->sessions->statistics;
        statistics.Increment(SecurityStatistic::TOTAL_MESSAGES_SENT);
        if (encoded.length() >= 6 && encoded[4] == 120)
        {
            if (encoded[1] == 0x83 && encoded[5] == 1) statistics.Increment(SecurityStatistic::CRITICAL_MESSAGES_RECEIVED);
            uint16_t user = 0;
            if ((encoded[1] == 0x83 && encoded[5] == 2)
                || (encoded[5] == 3 && AggressiveMode::InspectUser(encoded, true, user)))
                statistics.Increment(SecurityStatistic::CRITICAL_MESSAGES_SENT);
            if (encoded[5] == 7) statistics.Increment(SecurityStatistic::ERROR_MESSAGES_SENT);
        }
    }
#else
    (void)started;
#endif
}

void OContext::CheckForTaskStart()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication && authentication->sessions
        && (authentication->monitoringPending || authentication->pendingWireSize))
        return;
#endif
    // do these checks in order of priority
    this->CheckForDeferredRequest();
    this->CheckForUnsolicitedNull();
    if (this->shouldCheckForUnsolicited)
    {
        this->CheckForUnsolicited();
    }
}

void OContext::CheckForDeferredRequest()
{
    if (this->CanTransmit() && this->deferred.IsSet())
    {
        auto handler = [this](const ParsedRequest& request) { return this->ProcessDeferredRequest(request); };
        this->deferred.Process(handler);
    }
}

void OContext::CheckForUnsolicitedNull()
{
    if (this->CanTransmit() && this->state->IsIdle() && this->params.allowUnsolicited)
    {
        if (!this->unsol.completedNull)
        {
            // send a NULL unsolcited message
            auto response = this->unsol.tx.Start();
            build::NullUnsolicited(response, this->unsol.seq.num, this->GetResponseIIN());
            this->RestartUnsolConfirmTimer();
            this->state = this->params.noDefferedReadDuringUnsolicitedNullResponse
                ? &StateNullUnsolicitedConfirmWait::Inst()
                : &StateUnsolicitedConfirmWait::Inst();
            this->BeginUnsolTx(response);
        }
    }
}

void OContext::CheckForUnsolicited()
{
    if (this->shouldCheckForUnsolicited && this->CanTransmit() && this->state->IsIdle()
        && this->params.allowUnsolicited)
    {
        this->shouldCheckForUnsolicited = false;

        if (this->unsol.completedNull)
        {
            // are there events to be reported?
            if (this->params.unsolClassMask.Intersects(this->eventBuffer.UnwrittenClassField()))
            {

                auto response = this->unsol.tx.Start();
                auto writer = response.GetWriter();

                this->unsolRetries.Reset();
                this->eventBuffer.Unselect();
                this->eventBuffer.SelectAllByClass(this->params.unsolClassMask);
                this->eventBuffer.Load(writer);

                build::NullUnsolicited(response, this->unsol.seq.num, this->GetResponseIIN());
                this->RestartUnsolConfirmTimer();
                this->state = &StateUnsolicitedConfirmWait::Inst();
                this->BeginUnsolTx(response);
            }
        }
    }
}

bool OContext::ProcessDeferredRequest(const ParsedRequest& request)
{
    if (request.header.function == FunctionCode::CONFIRM)
    {
        this->ProcessConfirm(request);
        return true;
    }

    if (request.header.function == FunctionCode::READ)
    {
        if (this->state->IsIdle())
        {
            this->ProcessRequest(request);
            return true;
        }

        return false;
    }
    else
    {
        this->ProcessRequest(request);
        return true;
    }
}

void OContext::RestartSolConfirmTimer()
{
    auto timeout = [&]() {
        this->state = &this->state->OnConfirmTimeout(*this);
        this->CheckForTaskStart();
    };

    this->confirmTimer.cancel();
    this->confirmTimer = this->executor->start(this->params.solConfirmTimeout.value, timeout);
}

void OContext::RestartUnsolConfirmTimer()
{
    auto timeout = [&]() {
        this->state = &this->state->OnConfirmTimeout(*this);
        this->CheckForTaskStart();
    };

    this->confirmTimer.cancel();
    this->confirmTimer = this->executor->start(this->params.unsolConfirmTimeout.value, timeout);
}

OutstationState& OContext::RespondToNonReadRequest(const ParsedRequest& request)
{
    this->history.RecordLastProcessedRequest(request.header, request.objects);

    auto response = this->sol.tx.Start();
    auto writer = response.GetWriter();
    response.SetFunction(FunctionCode::RESPONSE);
    response.SetControl(AppControlField(true, true, false, false, request.header.control.SEQ));
    auto iin = this->HandleNonReadResponse(request.header, request.objects, writer);
    response.SetIIN(iin | this->GetResponseIIN());
    return this->BeginResponseTx(request.addresses.source, response);
}

OutstationState& OContext::RespondToReadRequest(const ParsedRequest& request)
{
    this->history.RecordLastProcessedRequest(request.header, request.objects);

    auto response = this->sol.tx.Start();
    auto writer = response.GetWriter();
    response.SetFunction(FunctionCode::RESPONSE);
    auto result = this->HandleRead(request.objects, writer);
    result.second.SEQ = request.header.control.SEQ;
    response.SetControl(result.second);
    response.SetIIN(result.first | this->GetResponseIIN());

    return this->BeginResponseTx(request.addresses.source, response);
}

OutstationState& OContext::ContinueMultiFragResponse(const Addresses& addresses, const AppSeqNum& seq)
{
    auto response = this->sol.tx.Start();
    auto writer = response.GetWriter();
    response.SetFunction(FunctionCode::RESPONSE);
    auto control = this->rspContext.LoadResponse(writer);
    control.SEQ = seq;
    response.SetControl(control);
    response.SetIIN(this->GetResponseIIN());

    return this->BeginResponseTx(addresses.source, response);
}

bool OContext::CanTransmit() const
{
    return isOnline && !isTransmitting;
}

IINField OContext::GetResponseIIN()
{
    return this->staticIIN | this->GetDynamicIIN() | this->application->GetApplicationIIN().ToIIN();
}

IINField OContext::GetDynamicIIN()
{
    auto classField = this->eventBuffer.UnwrittenClassField();

    IINField ret;
    ret.SetBitToValue(IINBit::CLASS1_EVENTS, classField.HasClass1());
    ret.SetBitToValue(IINBit::CLASS2_EVENTS, classField.HasClass2());
    ret.SetBitToValue(IINBit::CLASS3_EVENTS, classField.HasClass3());
    ret.SetBitToValue(IINBit::EVENT_BUFFER_OVERFLOW, this->eventBuffer.IsOverflown());

    return ret;
}

void OContext::UpdateLastBroadcastMessageReceived(uint16_t destination)
{
    switch (destination)
    {
    case LinkBroadcastAddress::DontConfirm:
        lastBroadcastMessageReceived.set(LinkBroadcastAddress::DontConfirm);
        break;
    case LinkBroadcastAddress::ShallConfirm:
        lastBroadcastMessageReceived.set(LinkBroadcastAddress::ShallConfirm);
        break;
    case LinkBroadcastAddress::OptionalConfirm:
        lastBroadcastMessageReceived.set(LinkBroadcastAddress::OptionalConfirm);
        break;
    default:
        lastBroadcastMessageReceived.clear();
    }
}

void OContext::CheckForBroadcastConfirmation(APDUResponse& response)
{
    if (lastBroadcastMessageReceived.is_set())
    {
        response.SetIIN(response.GetIIN() | IINField(IINBit::BROADCAST));

        if (lastBroadcastMessageReceived.get() != LinkBroadcastAddress::ShallConfirm)
        {
            lastBroadcastMessageReceived.clear();
        }
        else
        {
            // The broadcast address requested a confirmation
            auto control = response.GetControl();
            control.CON = true;
            response.SetControl(control);
        }
    }
}

bool OContext::ProcessMessage(const Message& message)
{
    // is the message addressed to this outstation
    if (message.addresses.destination != this->addresses.source && !message.addresses.IsBroadcast())
    {
        return false;
    }

    // is the message coming from the expected master?
    if (!this->params.respondToAnyMaster && (message.addresses.source != this->addresses.destination))
    {
        return false;
    }
#ifdef OPENDNP3_USE_SA_CRYPTO
    // Test authentication is bound to this association. Broadcasts and the
    // respondToAnyMaster exception must never create an authentication bypass.
    if (authentication && message.addresses != this->addresses.Reverse())
        return false;
    if (authentication && authentication->sessions)
        authentication->sessions->statistics.Increment(SecurityStatistic::TOTAL_MESSAGES_RECEIVED);
#endif

    FORMAT_HEX_BLOCK(this->logger, flags::APP_HEX_RX, message.payload, 18, 18);

    if (message.addresses.IsBroadcast())
    {
        UpdateLastBroadcastMessageReceived(message.addresses.destination);
    }

    const auto result = APDUHeaderParser::ParseRequest(message.payload, &this->logger);
    if (!result.success)
    {
#ifdef OPENDNP3_USE_SA_CRYPTO
        if (authentication && authentication->sessions)
            authentication->sessions->statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
#endif
        return false;
    }

    logging::LogHeader(this->logger, flags::APP_HEADER_RX, result.header);

    if (!result.header.control.IsFirAndFin())
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::WARN, "Ignoring fragment. Requests must have FIR/FIN == 1");
#ifdef OPENDNP3_USE_SA_CRYPTO
        if (authentication && authentication->sessions)
            authentication->sessions->statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
#endif
        return false;
    }

    if (result.header.control.CON)
    {
        SIMPLE_LOG_BLOCK(this->logger, flags::WARN, "Ignoring fragment. Requests cannot request confirmation");
#ifdef OPENDNP3_USE_SA_CRYPTO
        if (authentication && authentication->sessions)
            authentication->sessions->statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
#endif
        return false;
    }

#ifdef OPENDNP3_USE_SA_CRYPTO
    if (authentication && authentication->sessions)
        ServiceSecurityStatistics(static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            executor->get_time().time_since_epoch()).count()));
#endif
    if (this->RouteAuthentication(message, result.header, result.objects))
    {
#ifdef OPENDNP3_USE_SA_CRYPTO
        if (authentication && authentication->sessions)
            ServiceSecurityStatistics(static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                executor->get_time().time_since_epoch()).count()));
#endif
        return true;
    }
    return this->ProcessObjects(ParsedRequest(message.addresses, result.header, result.objects));
}

void OContext::HandleNewEvents()
{
    this->shouldCheckForUnsolicited = true;
    this->CheckForTaskStart();
}

void OContext::SetRestartIIN()
{
    this->staticIIN.SetBit(IINBit::DEVICE_RESTART);
}

IUpdateHandler& OContext::GetUpdateHandler()
{
    return this->database;
}

//// ----------------------------- function handlers -----------------------------

bool OContext::ProcessBroadcastRequest(const ParsedRequest& request)
{
    switch (request.header.function)
    {
    case (FunctionCode::WRITE):
        this->HandleWrite(request.objects);
        return true;
    case (FunctionCode::DIRECT_OPERATE_NR):
        this->HandleDirectOperate(request.objects, OperateType::DirectOperateNoAck, nullptr);
        return true;
    case (FunctionCode::IMMED_FREEZE_NR):
        this->HandleFreeze(request.objects);
        return true;
    case (FunctionCode::FREEZE_CLEAR_NR):
        this->HandleFreezeAndClear(request.objects);
        return true;
    case (FunctionCode::ASSIGN_CLASS): {
        if (this->application->SupportsAssignClass())
        {
            this->HandleAssignClass(request.objects);
            return true;
        }
        else
        {
            return false;
        }
    }
    case (FunctionCode::RECORD_CURRENT_TIME): {
        if (request.objects.is_not_empty())
        {
            this->HandleRecordCurrentTime();
            return true;
        }
        else
        {
            return false;
        }
    }
    case (FunctionCode::DISABLE_UNSOLICITED): {
        if (this->params.allowUnsolicited)
        {
            this->HandleDisableUnsolicited(request.objects, nullptr);
            return true;
        }
        else
        {
            return false;
        }
    }
    case (FunctionCode::ENABLE_UNSOLICITED): {
        if (this->params.allowUnsolicited)
        {
            this->HandleEnableUnsolicited(request.objects, nullptr);
            return true;
        }
        else
        {
            return false;
        }
    }
    default:
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Ignoring broadcast on function code: %s",
                         FunctionCodeSpec::to_string(request.header.function));
        return false;
    }
}

bool OContext::ProcessRequestNoAck(const ParsedRequest& request)
{
    switch (request.header.function)
    {
    case (FunctionCode::DIRECT_OPERATE_NR):
        this->HandleDirectOperate(request.objects, OperateType::DirectOperateNoAck,
                                  nullptr); // no object writer, this is a no ack code
        return true;
    case (FunctionCode::IMMED_FREEZE_NR):
        this->HandleFreeze(request.objects);
        return true;
    case (FunctionCode::FREEZE_CLEAR_NR):
        this->HandleFreezeAndClear(request.objects);
        return true;
    default:
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Ignoring NR function code: %s",
                         FunctionCodeSpec::to_human_string(request.header.function));
        return false;
    }
}

IINField OContext::HandleNonReadResponse(const APDUHeader& header, const ser4cpp::rseq_t& objects, HeaderWriter& writer)
{
    switch (header.function)
    {
    case (FunctionCode::WRITE):
        return this->HandleWrite(objects);
    case (FunctionCode::SELECT):
        return this->HandleSelect(objects, writer);
    case (FunctionCode::OPERATE):
        return this->HandleOperate(objects, writer);
    case (FunctionCode::DIRECT_OPERATE):
        return this->HandleDirectOperate(objects, OperateType::DirectOperate, &writer);
    case (FunctionCode::COLD_RESTART):
        return this->HandleRestart(objects, false, &writer);
    case (FunctionCode::WARM_RESTART):
        return this->HandleRestart(objects, true, &writer);
    case (FunctionCode::ASSIGN_CLASS):
        return this->HandleAssignClass(objects);
    case (FunctionCode::DELAY_MEASURE):
        return this->HandleDelayMeasure(objects, writer);
    case (FunctionCode::RECORD_CURRENT_TIME):
        return objects.is_empty() ? this->HandleRecordCurrentTime() : IINField(IINBit::PARAM_ERROR);
    case (FunctionCode::DISABLE_UNSOLICITED):
        return this->params.allowUnsolicited ? this->HandleDisableUnsolicited(objects, &writer)
                                             : IINField(IINBit::FUNC_NOT_SUPPORTED);
    case (FunctionCode::ENABLE_UNSOLICITED):
        return this->params.allowUnsolicited ? this->HandleEnableUnsolicited(objects, &writer)
                                             : IINField(IINBit::FUNC_NOT_SUPPORTED);
    case (FunctionCode::IMMED_FREEZE):
        return this->HandleFreeze(objects);
    case (FunctionCode::FREEZE_CLEAR):
        return this->HandleFreezeAndClear(objects);
    default:
        return IINField(IINBit::FUNC_NOT_SUPPORTED);
    }
}

ser4cpp::Pair<IINField, AppControlField> OContext::HandleRead(const ser4cpp::rseq_t& objects, HeaderWriter& writer)
{
    this->rspContext.Reset();
    this->eventBuffer.Unselect(); // always un-select any previously selected points when we start a new read request
    this->database.Unselect();

    ReadHandler handler(this->database, this->eventBuffer);
    auto result = APDUParser::Parse(objects, handler, &this->logger,
                                    ParserSettings::NoContents()); // don't expect range/count context on a READ
    if (result == ParseResult::OK)
    {
        this->database.SetReadIIN(this->GetResponseIIN());
        auto control = this->rspContext.LoadResponse(writer);
        return ser4cpp::Pair<IINField, AppControlField>(handler.Errors(), control);
    }

    this->rspContext.Reset();
    return ser4cpp::Pair<IINField, AppControlField>(IINFromParseResult(result),
                                                    AppControlField(true, true, false, false));
}

IINField OContext::HandleWrite(const ser4cpp::rseq_t& objects)
{
    WriteHandler handler(*this->application, this->time, this->sol.seq.num, Timestamp(this->executor->get_time()),
                         &this->staticIIN);
    auto result = APDUParser::Parse(objects, handler, &this->logger);
    return (result == ParseResult::OK) ? handler.Errors() : IINFromParseResult(result);
}

IINField OContext::HandleDirectOperate(const ser4cpp::rseq_t& objects, OperateType opType, HeaderWriter* pWriter)
{
    // since we're echoing, make sure there's enough size before beginning
    if (pWriter && (objects.length() > pWriter->Remaining()))
    {
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Igonring command request due to oversized payload size of %zu",
                         objects.length());
        return IINField(IINBit::PARAM_ERROR);
    }

    CommandActionAdapter adapter(*this->commandHandler, false, this->database, opType);
    CommandResponseHandler handler(this->params.maxControlsPerRequest, &adapter, pWriter);
    auto result = APDUParser::Parse(objects, handler, &this->logger);
    this->shouldCheckForUnsolicited = true;
    return (result == ParseResult::OK) ? handler.Errors() : IINFromParseResult(result);
}

IINField OContext::HandleSelect(const ser4cpp::rseq_t& objects, HeaderWriter& writer)
{
    // since we're echoing, make sure there's enough size before beginning
    if (objects.length() > writer.Remaining())
    {
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Igonring command request due to oversized payload size of %zu",
                         objects.length());
        return IINField(IINBit::PARAM_ERROR);
    }

    // the 'OperateType' is just ignored  since it's a select
    CommandActionAdapter adapter(*this->commandHandler, true, this->database, OperateType::DirectOperate);
    CommandResponseHandler handler(this->params.maxControlsPerRequest, &adapter, &writer);
    auto result = APDUParser::Parse(objects, handler, &this->logger);
    if (result == ParseResult::OK)
    {
        if (handler.AllCommandsSuccessful())
        {
            this->control.Select(this->sol.seq.num, Timestamp(this->executor->get_time()), objects);
        }

        return handler.Errors();
    }

    return IINFromParseResult(result);
}

IINField OContext::HandleOperate(const ser4cpp::rseq_t& objects, HeaderWriter& writer)
{
    // since we're echoing, make sure there's enough size before beginning
    if (objects.length() > writer.Remaining())
    {
        FORMAT_LOG_BLOCK(this->logger, flags::WARN, "Igonring command request due to oversized payload size of %zu",
                         objects.length());
        return IINField(IINBit::PARAM_ERROR);
    }

    auto now = Timestamp(this->executor->get_time());
    auto result = this->control.ValidateSelection(this->sol.seq.num, now, this->params.selectTimeout, objects);

    if (result == CommandStatus::SUCCESS)
    {
        CommandActionAdapter adapter(*this->commandHandler, false, this->database, OperateType::SelectBeforeOperate);
        CommandResponseHandler handler(this->params.maxControlsPerRequest, &adapter, &writer);
        auto result = APDUParser::Parse(objects, handler, &this->logger);
        this->shouldCheckForUnsolicited = true;
        return (result == ParseResult::OK) ? handler.Errors() : IINFromParseResult(result);
    }
    else
    {
        this->control.Unselect();
    }

    return this->HandleCommandWithConstant(objects, writer, result);
}

IINField OContext::HandleDelayMeasure(const ser4cpp::rseq_t& objects, HeaderWriter& writer)
{
    if (objects.is_empty())
    {
        Group52Var2 value;
        value.time = 0; // respond with 0 time delay
        writer.WriteSingleValue<ser4cpp::UInt8, Group52Var2>(QualifierCode::UINT8_CNT, value);
        return IINField::Empty();
    }

    // there shouldn't be any trailing headers in delay measure request, no need to even parse
    return IINField(IINBit::PARAM_ERROR);
}

IINField OContext::HandleRecordCurrentTime()
{
    this->time.RecordCurrentTime(this->sol.seq.num, Timestamp(this->executor->get_time()));
    return IINField::Empty();
}

IINField OContext::HandleRestart(const ser4cpp::rseq_t& objects, bool isWarmRestart, HeaderWriter* pWriter)
{
    if (objects.is_not_empty())
        return IINField(IINBit::PARAM_ERROR);

    auto mode = isWarmRestart ? this->application->WarmRestartSupport() : this->application->ColdRestartSupport();

    switch (mode)
    {
    case (RestartMode::UNSUPPORTED):
        return IINField(IINBit::FUNC_NOT_SUPPORTED);
    case (RestartMode::SUPPORTED_DELAY_COARSE): {
        auto delay = isWarmRestart ? this->application->WarmRestart() : this->application->ColdRestart();
        if (pWriter)
        {
            Group52Var1 coarse;
            coarse.time = delay;
            pWriter->WriteSingleValue<ser4cpp::UInt8>(QualifierCode::UINT8_CNT, coarse);
        }
        return IINField::Empty();
    }
    default: {
        auto delay = isWarmRestart ? this->application->WarmRestart() : this->application->ColdRestart();
        if (pWriter)
        {
            Group52Var2 fine;
            fine.time = delay;
            pWriter->WriteSingleValue<ser4cpp::UInt8>(QualifierCode::UINT8_CNT, fine);
        }
        return IINField::Empty();
    }
    }
}

IINField OContext::HandleAssignClass(const ser4cpp::rseq_t& objects)
{
    if (this->application->SupportsAssignClass())
    {
        AssignClassHandler handler(*this->application, this->database);
        auto result = APDUParser::Parse(objects, handler, &this->logger, ParserSettings::NoContents());
        return (result == ParseResult::OK) ? handler.Errors() : IINFromParseResult(result);
    }

    return IINField(IINBit::FUNC_NOT_SUPPORTED);
}

IINField OContext::HandleDisableUnsolicited(const ser4cpp::rseq_t& objects, HeaderWriter* /*writer*/)
{
    ClassBasedRequestHandler handler;
    auto result = APDUParser::Parse(objects, handler, &this->logger);
    if (result == ParseResult::OK)
    {
        this->params.unsolClassMask.Clear(handler.GetClassField());
        return handler.Errors();
    }

    return IINFromParseResult(result);
}

IINField OContext::HandleEnableUnsolicited(const ser4cpp::rseq_t& objects, HeaderWriter* /*writer*/)
{
    ClassBasedRequestHandler handler;
    auto result = APDUParser::Parse(objects, handler, &this->logger);
    if (result == ParseResult::OK)
    {
        this->params.unsolClassMask.Set(handler.GetClassField());
        this->shouldCheckForUnsolicited = true;
        return handler.Errors();
    }

    return IINFromParseResult(result);
}

IINField OContext::HandleCommandWithConstant(const ser4cpp::rseq_t& objects, HeaderWriter& writer, CommandStatus status)
{
    ConstantCommandAction constant(status);
    CommandResponseHandler handler(this->params.maxControlsPerRequest, &constant, &writer);
    auto result = APDUParser::Parse(objects, handler, &this->logger);
    return IINFromParseResult(result);
}

IINField OContext::HandleFreeze(const ser4cpp::rseq_t& objects)
{
    FreezeRequestHandler handler(false, database);
    auto result = APDUParser::Parse(objects, handler, &this->logger, ParserSettings::NoContents());
    return IINFromParseResult(result);
}

IINField OContext::HandleFreezeAndClear(const ser4cpp::rseq_t& objects)
{
    FreezeRequestHandler handler(true, database);
    auto result = APDUParser::Parse(objects, handler, &this->logger, ParserSettings::NoContents());
    return IINFromParseResult(result);
}

void OContext::CountControlAuthentication(uint16_t user, uint8_t count, uint64_t now)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    auto& auth = *authentication;
    auto* session = auth.sessions->Find(user);
    // Only the common user's already-dispatched operation can exhaust the key
    // still needed to authenticate its retained normal response.
    if (user == 1 && auth.monitoringPending && session->Ready(now) && session->RemainingMessages() <= count)
    {
        auth.deferredControlCount = count;
        auth.deferredControlKSQ = session->Sequence();
        while (session->RemainingMessages() > 1)
        {
            session->CountAuthentication(now);
            --auth.deferredControlCount;
        }
        return;
    }
    for (uint8_t i = 0; i < count; ++i)
        session->CountAuthentication(now);
#else
    (void)user;
    (void)count;
    (void)now;
#endif
}

void OContext::FinalizeControlCounts(uint64_t now)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    auto& auth = *authentication;
    const auto count = auth.deferredControlCount;
    const auto epoch = auth.deferredControlKSQ;
    auth.deferredControlCount = 0;
    auth.deferredControlKSQ = 0;
    auto* session = auth.sessions ? auth.sessions->Find(1) : nullptr;
    if (session && session->Sequence() == epoch)
        for (uint8_t i = 0; i < count; ++i)
            session->CountAuthentication(now);
#else
    (void)now;
#endif
}

void OContext::ResetAuthentication()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication)
        return;
    const auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
    FinalizeControlCounts(now);
    authentication->replyTimer.cancel();
    authentication->challenger.Reset();
    authentication->controlAggressive.Reset();
    authentication->monitoringAggressive.Reset();
    authentication->controlEligible = {{false, false}};
    authentication->monitoringEligible = false;
    if (!isTransmitting)
        crypto::Clear(ser4cpp::wseq_t(authentication->aggressiveWire.data(), authentication->aggressiveWire.size()));
    // Only the queued G120V2 belongs to the aborted monitoring exchange. V5 key-status traffic is independent.
    if (authentication->pendingWireSize >= 6 && authentication->pendingWire[1] == 0x83
        && authentication->pendingWire[4] == 120 && authentication->pendingWire[5] == 2)
    {
        crypto::Clear(ser4cpp::wseq_t(authentication->pendingWire.data(), authentication->pendingWireSize));
        authentication->pendingWireSize = 0;
    }
    authentication->pendingReplyKSQ = 0;
    authentication->pendingReplyCreated = authentication->pendingReplyExpires = 0;
    authentication->monitoring.Reset();
    authentication->monitoringPending = false;
    authentication->monitoringTimer.cancel();
    crypto::Clear(ser4cpp::wseq_t(authentication->authorized.data(), authentication->authorized.size()));
    if (!isTransmitting)
        crypto::Clear(ser4cpp::wseq_t(authentication->challenge.data(), authentication->challenge.size()));
#endif
}

void OContext::ServiceSecurityStatistics(uint64_t now)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication || !authentication->sessions) return;
    auto& auth = *authentication;
    auto& statistics = auth.sessions->statistics;
    auth.challenger.Tick(now);
    if (statistics.Exceeded(SecurityStatistic::REPLY_TIMEOUTS))
    {
        statistics.ResetMaximum(SecurityStatistic::REPLY_TIMEOUTS);
        ResetAuthentication();
        for (size_t n = 0; n < 2; ++n) auth.sessions->At(n)->CommunicationFailure(now);
        // This event explicitly affects ALL users. A queued old Status is now
        // obsolete, but the transport-owned wire buffer remains untouched.
        crypto::Clear(ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()));
        auth.pendingWireSize = 0;
    }
    if (statistics.Exceeded(SecurityStatistic::AUTHENTICATION_FAILURES)
        && statistics.Exceeded(SecurityStatistic::AUTHENTICATION_REKEYS))
    {
        statistics.ResetMaximum(SecurityStatistic::AUTHENTICATION_FAILURES);
        auth.challenger.CancelPending();
        auth.replyTimer.cancel();
        SIMPLE_LOG_BLOCK(logger, flags::WARN, "Authentication rekey limit exceeded");
        if (auth.closeTCPConnection) auth.closeTCPConnection();
    }
    // P6-OPEN-03: Control Challenges use USR=0. Failure totals/Max stay
    // association-scoped; do not invent a user or invalidate unrelated keys.
#else
    (void)now;
#endif
}

void OContext::SendAuthorizationError(uint32_t sequence, uint16_t user, uint8_t appSequence)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    auto& auth = *authentication;
    if (!auth.sessions)
        return;
    auth.sessions->statistics.Increment(SecurityStatistic::AUTHORIZATION_FAILURES);
    auth.sessions->statistics.Increment(SecurityStatistic::DISCARDED_MESSAGES);
    FORMAT_LOG_BLOCK(logger, flags::WARN, "Authorization failed: user=%u sequence=%u", user, sequence);
    if (auth.sessions->config.errorObserver)
    {
        try { auth.sessions->config.errorObserver->OnAuthorizationFailure(auth.association, user, sequence); }
        catch (...) {} // Diagnostics cannot authorize the denied operation.
    }
    // 7.5.2.4 permits suppressing Errors. Never evict an independent queued
    // authentication message, interrupt a responder, or overwrite borrowed TX bytes.
    if (auth.sessions->config.suppressAuthenticationErrors
        || auth.sessions->statistics.Exceeded(SecurityStatistic::ERROR_MESSAGES_SENT)
        || !CanTransmit() || auth.pendingWireSize || auth.monitoringPending)
        return;
    DNPTime time;
    IINField iin;
    try { time = application->Now(); iin = GetResponseIIN(); }
    catch (...) { return; }
    if (time.quality == TimestampQuality::INVALID || time.value > 0xFFFFFFFFFFFFULL)
    {
        SIMPLE_LOG_BLOCK(logger, flags::WARN, "Authorization Error suppressed: valid DNP time unavailable");
        return;
    }
    // Provisional Annex A.45.7 assignment; P4-OPEN-01 records the conflicting
    // code in 7.5.5.7. Code 5 remains exclusively MAC Algorithm Not Supported.
    Group120Var7 error(sequence, user, auth.association, 7, time, ser4cpp::rseq_t());
    APDUResponse response(ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()));
    response.SetFunction(FunctionCode::AUTH_RESPONSE);
    response.SetControl(AppControlField::Request(appSequence));
    response.SetIIN(iin);
    auto writer = response.GetWriter();
    if (!writer.WriteFreeFormat(&error, 1))
        return;
    auth.pendingWireSize = response.Size();
    TransmitPendingAuthentication();
#else
    (void)sequence;
    (void)user;
    (void)appSequence;
#endif
}

void OContext::TransmitPendingAuthentication()
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication || !authentication->sessions || !authentication->pendingWireSize || !CanTransmit())
        return;
    auto& auth = *authentication;
    const bool reply = auth.pendingWireSize >= 6 && auth.pendingWire[1] == 0x83
        && auth.pendingWire[4] == 120 && auth.pendingWire[5] == 2;
    const auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
    auto* session = reply ? auth.sessions->Find(1) : nullptr;
    if (reply)
    {
        if (session)
            session->Tick(now);
        // MAC was generated while the key was valid. Count-only invalidation may
        // complete this precomputed Reply, but never past its original validity or on replacement keys.
        if (!session || session->Sequence() != auth.pendingReplyKSQ || now < auth.pendingReplyCreated
            || now >= auth.pendingReplyExpires)
        {
            ResetAuthentication();
            return;
        }
    }
    const bool error = auth.pendingWireSize >= 10 && auth.pendingWire[1] == 0x83
        && auth.pendingWire[4] == 120 && auth.pendingWire[5] == 7;
    const auto size = auth.pendingWireSize;
    std::memcpy(auth.wire.data(), auth.pendingWire.data(), size);
    auth.pendingWireSize = 0;
    BeginTx(addresses.destination, ser4cpp::rseq_t(auth.wire.data(), size));
    if (error && auth.sessions->config.errorObserver)
    {
        Group120Var7 value;
        if (value.Read(ser4cpp::rseq_t(auth.wire.data(), size).skip(10)))
        {
            try { auth.sessions->config.errorObserver->OnErrorSent(auth.association, value.userNum, value.seqNum, value.errorCode); }
            catch (...) {}
        }
    }
    if (reply)
    {
        auth.monitoringTimer.cancel();
        auth.pendingReplyKSQ = 0;
        auth.pendingReplyCreated = auth.pendingReplyExpires = 0;
        session->CountAuthentication(now); // The outgoing G120V2 is counted only when transmission begins.
    }
#endif
}

bool OContext::RouteAuthentication(const Message& message, const APDUHeader& header, const ser4cpp::rseq_t& objects)
{
#ifdef OPENDNP3_USE_SA_CRYPTO
    if (!authentication)
        return false;
    auto* statistics = authentication->sessions ? &authentication->sessions->statistics : nullptr;
    uint16_t aggressiveUser = 0;
    const bool aggressive = objects.length() >= 2 && objects[0] == 120 && objects[1] == 3
        && AggressiveMode::InspectUser(message.payload, false, aggressiveUser);
    if (statistics && aggressive) statistics->Increment(SecurityStatistic::CRITICAL_MESSAGES_RECEIVED);
    const auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch()).count());
    if (objects.length() >= 2 && objects[0] == 120 && objects[1] == 7)
    {
        auto& auth = *authentication;
        if (header.function != FunctionCode::AUTH_REQUEST_NO_ACK)
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
            || APDUParser::Parse(objects, error, nullptr) != ParseResult::OK || !error.valid
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
        const bool discarded = auth.challenger.CancelOnError(error.value, header.control.SEQ, now);
        if (discarded)
            auth.replyTimer.cancel();
        if (!discarded)
        {
            // A valid but unowned Error is unexpected and discarded. Do not
            // cancel another exchange, invalidate keys, or lose its diagnostic.
            if (statistics) statistics->Unexpected();
            SIMPLE_LOG_BLOCK(logger, flags::WARN, "Challenger has no matching authentication Error exchange");
        }
        if (discarded && error.value.errorCode == 5)
            FORMAT_LOG_BLOCK(logger, flags::WARN, "Authentication MAC rejected; next Challenge algorithm=%u (0=no permitted alternative)",
                             auth.challenger.MACAlgorithm());
        if (auth.sessions && auth.sessions->config.errorObserver)
        {
            try
            {
                auth.sessions->config.errorObserver->OnErrorReceived(auth.association, error.value.userNum,
                    error.value.seqNum, error.value.errorCode, discarded);
            }
            catch (...) {}
        }
        // No retry or broad ResetAuthentication: monitoring, key exchange and
        // transmitted buffers have independent owners.
        return true;
    }
    authentication->challenger.Tick(now);
    if (header.control.UNS && header.function != FunctionCode::CONFIRM)
    {
        if (statistics) statistics->Unexpected();
        this->ResetAuthentication();
        return true;
    }
    if (authentication->sessions && header.function == FunctionCode::AUTH_REQUEST && objects.length() >= 2
        && objects[0] == 120)
    {
        auto& auth = *authentication;
        if (objects[1] == 4 || objects[1] == 6)
        {
            class UserHandler final : public IAPDUHandler
            {
            public:
                uint16_t user = 0;
                bool valid = false;
                bool IsAllowed(uint32_t n, GroupVariation gv, QualifierCode qc) override
                {
                    return n == 0
                        && ((gv == GroupVariation::Group120Var4 && qc == QualifierCode::UINT8_CNT)
                            || (gv == GroupVariation::Group120Var6 && qc == QualifierCode::FREE_FORMAT));
                }
                IINField ProcessHeader(const CountHeader&, const ICollection<Group120Var4>& values) override
                {
                    valid = values.Count() == 1;
                    if (valid)
                        values.ForeachItem([this](const Group120Var4& v) { user = v.userNum; });
                    return IINField::Empty();
                }
                IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var6>& values) override
                {
                    valid = values.Count() == 1;
                    if (valid)
                        values.ForeachItem([this](const Group120Var6& v) { user = v.userNum; });
                    return IINField::Empty();
                }
            } value;
            if (!CanTransmit() || auth.pendingWireSize
                || (objects[1] == 4 && auth.challenger.GetState() == OutstationChallenger::State::WAITING_FOR_REPLY)
                || APDUParser::Parse(objects, value, nullptr) != ParseResult::OK || !value.valid)
            {
                if (statistics) statistics->Unexpected();
                return true;
            }
            auto* session = auth.sessions->Find(value.user);
            if (!session)
            {
                if (statistics) statistics->Unexpected();
                return true;
            }
            if (auth.deferredControlCount && session->User() == 1)
                ResetAuthentication(); // Settle the owning common-user exchange before session replacement.
            size_t size = 0;
            const auto result = session->Process(auth.association, message.payload, now,
                                                 ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()),
                                                 size, GetResponseIIN());
            if (result == SessionKeys::Result::INSTALLED)
            {
                const auto index = session->User() == auth.sessions->config.users[0] ? 0u : 1u;
                auth.controlEligible[index] = false;
                if (session->User() == 1)
                    auth.monitoringEligible = false;
                auth.challenger.SetSessionKey(session->User(), session->ControlKey(now), session->ValidUntil(), now);
                if (session->User() == 1)
                {
                    auth.monitoring.SetSessionKey(1, session->MonitoringKey(now), session->ValidUntil(), now, true);
                    auth.monitoringPending = false;
                    auth.monitoringTimer.cancel();
                }
                auth.replyTimer.cancel();
                // A completed SELECT keeps its native timeout and user binding
                // across session renewal. OPERATE still requires a fresh MAC.
            }
            auth.pendingWireSize = size;
            TransmitPendingAuthentication();
            return true;
        }
        if (objects[1] == 1)
        {
            if (!auth.monitoringPending || auth.pendingWireSize)
            {
                if (statistics) statistics->Unexpected();
                return true;
            }
            auto* session = auth.sessions->Find(1);
            if (!session || !session->Ready(now)
                || (auth.deferredControlCount && session->Sequence() != auth.deferredControlKSQ))
            {
                if (statistics) statistics->Unexpected();
                ResetAuthentication();
                return true;
            }
            size_t size = 0;
            if (auth.monitoring.Respond(auth.association, message.payload, now,
                                        ser4cpp::wseq_t(auth.pendingWire.data(), auth.pendingWire.size()), size,
                                        GetResponseIIN())
                == MasterResponder::Result::OK)
            {
                auth.monitoringPending = false;
                // Keep the existing timeout active until a queued Reply actually starts transmission.
                if (auth.monitoringAggressive.RememberChallenge(auth.monitoring.LastAcceptedChallenge(),
                                                                auth.monitoring.LastChallengeWasUnsolicited()))
                    auth.monitoringEligible = true;
                auth.pendingWireSize = size;
                auth.pendingReplyKSQ = session->Sequence();
                auth.pendingReplyCreated = now;
                auth.pendingReplyExpires = std::min(session->ValidUntil(), now + auth.sessions->config.replyTimeoutMs);
                FinalizeControlCounts(now); // The response's MAC no longer needs the old key.
                session->CountAuthentication(now); // Incoming monitoring G120V1; outgoing V2 is counted at BeginTx.
                TransmitPendingAuthentication();
            }
            else
            {
                if (statistics) statistics->Unexpected();
                ResetAuthentication();
            }
            return true;
        }
    }
    // Held common-key counts belong only to the retained response. Its monitoring
    // Challenge and key replacement were handled above; no new operation may use this budget.
    if (authentication->sessions && authentication->deferredControlCount)
    {
        if (statistics) statistics->Unexpected();
        return true;
    }
    if (header.function == FunctionCode::AUTH_REQUEST)
    {
        if (objects.length() < 2 || objects[0] != 120 || objects[1] != 2)
        {
            if (statistics) statistics->Unexpected();
            return true; // Table 7-8 row 2: not a Reply; preserve the pending Challenge.
        }
        // Parsing is side-effect free. Only a single, well-framed G120V2 may
        // consume pending authentication and release the exact queued request.
        class ReplyHandler final : public IAPDUHandler
        {
        public:
            Group120Var2 reply;
            bool valid = false;
            bool IsAllowed(uint32_t count, GroupVariation gv, QualifierCode qc) override
            {
                return count == 0 && gv == GroupVariation::Group120Var2 && qc == QualifierCode::FREE_FORMAT;
            }
            IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var2>& values) override
            {
                valid = values.Count() == 1;
                if (valid)
                    values.ForeachItem([this](const Group120Var2& value) { reply = value; });
                return IINField::Empty();
            }
        } handler;
        if (header.control.SEQ != authentication->sequence
            || APDUParser::Parse(objects, handler, nullptr) != ParseResult::OK || !handler.valid)
        {
            authentication->challenger.RejectReply(now);
            authentication->replyTimer.cancel();
            return true;
        }
        size_t size = 0;
        if (authentication->sessions)
        {
            auto* session = authentication->sessions->Find(handler.reply.userNum);
            if (!session || !session->Ready(now))
            {
                authentication->challenger.RejectReply(now);
                authentication->replyTimer.cancel();
                return true;
            }
        }
        const auto result = authentication->challenger.Reply(
            authentication->association, handler.reply, now,
            ser4cpp::wseq_t(authentication->authorized.data(), authentication->authorized.size()), size);
        authentication->replyTimer.cancel();
        if (result == OutstationChallenger::Result::AUTHENTICATED)
        {
            const auto original
                = APDUHeaderParser::ParseRequest(ser4cpp::rseq_t(authentication->authorized.data(), size));
            bool permitted = original.success;
            bool authorizationDenied = false;
            if (authentication->sessions)
            {
                auto& auth = *authentication;
                const auto index = handler.reply.userNum == auth.sessions->config.users[0] ? 0u : 1u;
                if (auth.controlAggressive.RememberChallenge(auth.challenger.LastAcceptedChallenge(),
                                                             auth.challenger.LastChallengeWasUnsolicited()))
                    auth.controlEligible[index] = true;
            }
            if (permitted && authentication->sessions)
            {
                auto& auth = *authentication;
                permitted = auth.sessions->Authorize(handler.reply.userNum,
                                                     FunctionCodeSpec::to_type(original.header.function), now,
                                                     ser4cpp::rseq_t(auth.authorized.data(), size));
                authorizationDenied = !permitted; // Keep policy denial separate from SELECT/OPERATE binding.
                if (original.header.function == FunctionCode::OPERATE)
                {
                    permitted = permitted && auth.selectUser == handler.reply.userNum;
                    auth.selectUser = 0;
                }
                else if (original.header.function == FunctionCode::SELECT && permitted)
                    auth.selectUser = handler.reply.userNum;
            }
            if (permitted)
            {
                // One-shot release directly into the original dispatcher. No
                // reusable "authenticated" flag and no recursive OnReceive.
                this->ProcessObjects(ParsedRequest(message.addresses, original.header, original.objects));
            }
            else if (authorizationDenied)
                SendAuthorizationError(handler.reply.seqNum, handler.reply.userNum, original.header.control.SEQ);
            else if (statistics) statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
            if (authentication->sessions)
            {
                // Two distinct ASDUs: outgoing control Challenge and incoming verified Reply.
                CountControlAuthentication(handler.reply.userNum, 2, now);
            }
        }
        crypto::Clear(ser4cpp::wseq_t(authentication->authorized.data(), authentication->authorized.size()));
        return true;
    }
    if (authentication->sessions && objects.length() >= 2 && objects[0] == 120 && objects[1] == 3)
    {
        auto& auth = *authentication;
        if (!auth.sessions->config.aggressiveReceive)
        {
            if (statistics) statistics->Unexpected();
            return true;
        }
        const uint16_t user = aggressiveUser;
        if (!aggressive)
        {
            if (statistics)
            {
                statistics->AuthenticationFailed();
                statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
            }
            return true;
        }
        auto* session = auth.sessions->Find(user);
        const auto index = user == auth.sessions->config.users[0] ? 0u : 1u;
        size_t size = 0;
        if (!session || !session->Ready(now) || !auth.controlEligible[index]
            || !auth.controlAggressive.Verify(auth.association, user, session->ControlKey(now), message.payload,
                                              ser4cpp::wseq_t(auth.authorized.data(), auth.authorized.size()), size))
        {
            if (statistics)
            {
                statistics->AuthenticationFailed(); // Parsed USR is NOT an authenticated owner.
                statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
                if (auth.challenger.GetState() == OutstationChallenger::State::WAITING_FOR_REPLY)
                    statistics->Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
            }
            return true;
        }
        if (statistics) statistics->Increment(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);
        auth.challenger.ObserveAggressiveSequence(auth.controlAggressive.Sequence());
        if (header.function != FunctionCode::CONFIRM)
        {
            if (statistics && auth.challenger.GetState() == OutstationChallenger::State::WAITING_FOR_REPLY)
            {
                statistics->Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
                statistics->ResetMaximum(SecurityStatistic::REPLY_TIMEOUTS);
            }
            auth.challenger.CancelPending();
            auth.replyTimer.cancel();
        }
        const auto original = APDUHeaderParser::ParseRequest(ser4cpp::rseq_t(auth.authorized.data(), size));
        bool allowed = original.success
            && auth.sessions->Authorize(user, FunctionCodeSpec::to_type(original.header.function), now,
                                        ser4cpp::rseq_t(auth.authorized.data(), size));
        const bool authorizationDenied = original.success && !allowed;
        if (original.header.function == FunctionCode::OPERATE)
        {
            allowed = allowed && auth.selectUser == user;
            auth.selectUser = 0;
        }
        else if (original.header.function == FunctionCode::SELECT && allowed)
            auth.selectUser = user;
        if (allowed)
            ProcessObjects(ParsedRequest(message.addresses, original.header, original.objects));
        else if (authorizationDenied)
        {
            // Use this verified ASDU's CSQ, not the helper's cross-category high-water mark.
            Group120Var3 authenticated;
            auto prefix = objects.skip(4);
            if (Group120Var3::Read(prefix, authenticated))
                SendAuthorizationError(authenticated.seqNum, user, original.header.control.SEQ);
        }
        else if (statistics) statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
        CountControlAuthentication(user, 1, now); // One incoming authenticated V3/native/V9 ASDU, after dispatch.
        crypto::Clear(ser4cpp::wseq_t(auth.authorized.data(), auth.authorized.size()));
        return true;
    }
    // Unexpected authentication messages cannot reach ordinary request handlers.
    if (header.function == FunctionCode::AUTH_REQUEST_NO_ACK || FunctionCodeSpec::to_type(header.function) >= 0x80)
    {
        if (statistics) statistics->Unexpected();
        this->ResetAuthentication();
        return true;
    }
    // Table 7-8 (IEEE PDF p257): discard new critical/non-critical messages while
    // waiting. Authentication never uses the normal deferred-request bypass.
    if (authentication->challenger.GetState() == OutstationChallenger::State::WAITING_FOR_REPLY)
    {
        if (statistics)
        {
            statistics->Increment(SecurityStatistic::CRITICAL_MESSAGES_RECEIVED);
            statistics->Unexpected();
        }
        return true;
    }
    if (!authentication->sessions
        && (header.function == FunctionCode::READ || header.function == FunctionCode::CONFIRM))
        return false;
    if (authentication->sessions)
    {
        if (authentication->monitoringPending)
        {
            if (statistics) statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
            return true;
        }
        if (authentication->challenger.GetState() == OutstationChallenger::State::NO_SESSION_KEYS)
            for (size_t n = 0; n < 2; ++n)
            {
                auto* session = authentication->sessions->At(n);
                if (session->Ready(now))
                    authentication->challenger.SetSessionKey(session->User(), session->ControlKey(now),
                                                             session->ValidUntil(), now);
            }
    }

    // Test policy additionally protects optional ordinary requests. If the normal
    // response state is busy, discard rather than admitting an unauthenticated
    // operation to the broadcast/no-ack/deferred execution paths.
    if (!this->CanTransmit() || (!this->state->IsIdle() && header.function != FunctionCode::CONFIRM))
    {
        if (statistics) statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
        return true;
    }
    size_t size = 0;
    authentication->replyTimer.cancel();
    if (authentication->challenger.Challenge(
            authentication->association, message.payload, this->GetResponseIIN(), now,
            ser4cpp::wseq_t(authentication->challenge.data(), authentication->challenge.size()), size)
        == OutstationChallenger::Result::OK)
    {
        authentication->sequence = header.control.SEQ;
        authentication->replyTimer = executor->start(
            std::chrono::milliseconds(authentication->sessions ? authentication->sessions->config.replyTimeoutMs
                                                               : 2000),
            [this]() {
                const auto time = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time().time_since_epoch())
                        .count());
                authentication->challenger.Tick(time);
                this->ServiceSecurityStatistics(time);
            });
        this->BeginTx(message.addresses.source, ser4cpp::rseq_t(authentication->challenge.data(), size));
    }
    else if (statistics) statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
    return true;
#else
    (void)message;
    (void)header;
    (void)objects;
    return false;
#endif
}

} // namespace opendnp3
