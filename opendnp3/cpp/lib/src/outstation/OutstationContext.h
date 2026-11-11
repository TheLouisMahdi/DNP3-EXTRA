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
#ifndef OPENDNP3_OUTSTATIONCONTEXT_H
#define OPENDNP3_OUTSTATIONCONTEXT_H

#include "LayerInterfaces.h"
#include "auth/AggressiveMode.h"
#include "auth/AuthenticationSession.h"
#include "link/LinkLayerConstants.h"
#include "master/MasterResponder.h"
#include "outstation/ControlState.h"
#include "outstation/Database.h"
#include "outstation/DeferredRequest.h"
#include "outstation/OutstationChallenger.h"
#include "outstation/OutstationChannelStates.h"
#include "outstation/OutstationSeqNum.h"
#include "outstation/OutstationStates.h"
#include "outstation/ParsedRequest.h"
#include "outstation/RequestHistory.h"
#include "outstation/ResponseContext.h"
#include "outstation/SecurityStatEventPublisher.h"
#include "outstation/TimeSyncState.h"
#include "outstation/event/EventBuffer.h"

#include "opendnp3/link/Addresses.h"
#include "opendnp3/logging/Logger.h"
#include "opendnp3/outstation/ICommandHandler.h"
#include "opendnp3/outstation/IOutstationApplication.h"
#include "opendnp3/outstation/OutstationConfig.h"

#include <ser4cpp/container/Pair.h>
#include <ser4cpp/container/Settable.h>

#include <exe4cpp/IExecutor.h>
#include <functional>

namespace opendnp3
{

///
/// Represent all of the mutable state in an outstation
///
class OContext : public IUpperLayer
{
    friend class StateIdle;
    friend class StateSolicitedConfirmWait;
    friend class StateUnsolicitedConfirmWait;
    friend class StateNullUnsolicitedConfirmWait;

public:
    OContext(const Addresses& addresses,
             const OutstationConfig& config,
             const DatabaseConfig& db_config,
             const Logger& logger,
             const std::shared_ptr<exe4cpp::IExecutor>& executor,
             std::shared_ptr<ILowerLayer> lower,
             std::shared_ptr<ICommandHandler> commandHandler,
             std::shared_ptr<IOutstationApplication> application);
    ~OContext();

    /// ----- Implement IUpperLayer ------

    virtual bool OnLowerLayerUp() override;

    virtual bool OnLowerLayerDown() override;

    virtual bool OnTxReady() override final;

    virtual bool OnReceive(const Message& message) override final;

    /// --- Other public members ----

    void HandleNewEvents();

    IUpdateHandler& GetUpdateHandler();

    void SetRestartIIN();

private:
    // Manual session-key injection is test-only. Production obtains its session
    // state through configured credentials and the normal protocol exchange.
    friend class AuthenticationRuntimeTestAccess;
    friend class ProductionAuthenticationTestAccess;
    friend class RemoteUpdateKeyTestAccess;
    friend class SecurityStatEventTestAccess;
    friend class OutstationStack;
    struct AuthenticationState
    {
        AuthenticationState(uint16_t association, size_t tagLength)
            : monitoring(association, tagLength, 2000, true),
              controlAggressive(association, tagLength, false),
              monitoringAggressive(association, tagLength, true),
              association(association),
              challenger(association, tagLength)
        {
        }
        ~AuthenticationState()
        {
            replyTimer.cancel();
            monitoringTimer.cancel();
            remoteTimer.cancel();
            certificateTimer.cancel();
            challenger.SetStatistics(nullptr);
        }
        explicit AuthenticationState(const AuthenticationConfig& config)
            : monitoring(config.association, config.tagLength, config.replyTimeoutMs, true, config.macAlgorithm),
              controlAggressive(config.association, config.tagLength, false, config.macAlgorithm),
              monitoringAggressive(config.association, config.tagLength, true, config.macAlgorithm),
              sessions(new AuthenticationSession(SessionKeys::Role::OUTSTATION, config)),
              association(config.association),
              challenger(association, config.tagLength, config.replyTimeoutMs, false, config.macAlgorithm)
        {
            monitoring.ConfigureMACs(config);
            controlAggressive.ConfigureMACs(config);
            monitoringAggressive.ConfigureMACs(config);
            challenger.ConfigureMACs(config);
            challenger.SetStatistics(&sessions->statistics);
        }
        MasterResponder monitoring;
        AggressiveMode controlAggressive, monitoringAggressive;
        std::array<bool, 16> controlEligible{};
        bool monitoringEligible = false;
        std::array<uint8_t, SessionKeys::MAX_APDU> aggressiveWire{};
        std::unique_ptr<AuthenticationSession> sessions;
        std::array<uint8_t, SessionKeys::MAX_APDU> wire{}, pendingWire{};
        size_t pendingWireSize = 0;
        std::array<uint8_t, 8> startupKeyStatusRequest{};
        bool startupKeyStatusQueued = false;
        bool remoteResponsePending = false;
        exe4cpp::Timer remoteTimer;
        exe4cpp::Timer certificateTimer;
        std::function<void()> closeTCPConnection;
        uint8_t deferredControlCount = 0;
        uint32_t deferredControlKSQ = 0;
        uint32_t pendingReplyKSQ = 0;
        uint64_t pendingReplyCreated = 0;
        uint64_t pendingReplyExpires = 0;
        uint16_t selectUser = 0;
        bool monitoringPending = false;
        exe4cpp::Timer monitoringTimer;
        const uint16_t association;
        OutstationChallenger challenger;
        std::array<uint8_t, OutstationChallenger::CHALLENGE_SIZE> challenge{};
        std::array<uint8_t, OutstationChallenger::MAX_REQUEST_SIZE> authorized{};
        uint8_t sequence = 0;
        exe4cpp::Timer replyTimer;
    };
    std::shared_ptr<AuthenticationState> authentication; // null only in explicit compatibility mode
    std::unique_ptr<SecurityStatEventPublisher> securityStatPublisher;
    std::shared_ptr<bool> securityEventLifetime = std::make_shared<bool>(true);
    bool securityEventNotificationPosted = false;
    void ScheduleSecurityEvents();
    void CountControlAuthentication(uint16_t user, uint8_t count);
    void FinalizeControlCounts(uint64_t now);
    void ResetAuthentication();
    void ServiceSecurityStatistics(uint64_t now);
    void ScheduleCertificateCheck();
    void InvalidateRemoteCredentials();
    void TransmitPendingAuthentication();
    void SendAuthorizationError(uint32_t sequence, uint16_t user, uint8_t appSequence);
    bool RouteAuthentication(const Message& message, const APDUHeader& header, const ser4cpp::rseq_t& objects);

    /// ---- Helper functions that operate on the current state, and may return a new state ----

    OutstationState& ContinueMultiFragResponse(const Addresses& addresses, const AppSeqNum& seq);

    OutstationState& RespondToReadRequest(const ParsedRequest& request);

    OutstationState& ProcessNewRequest(const ParsedRequest& request);

    OutstationState& OnReceiveSolRequest(const ParsedRequest& request);

    OutstationState& RespondToNonReadRequest(const ParsedRequest& request);

    // ---- Processing functions --------

    bool ProcessMessage(const Message& message);

    bool ProcessObjects(const ParsedRequest& request);

    bool ProcessRequest(const ParsedRequest& request);

    bool ProcessBroadcastRequest(const ParsedRequest& request);

    bool ProcessRequestNoAck(const ParsedRequest& request);
    bool ProcessDirectOperateNoAck(const ParsedRequest& request);

    bool ProcessConfirm(const ParsedRequest& request);

    // ---- common helper methods ----

    OutstationState& BeginResponseTx(uint16_t destination, APDUResponse& response, bool readResponse);

    OutstationState& RetransmitSolicitedResponse(const ParsedRequest& request);

    void AbandonSolicitedRead();

    void BeginRetransmitLastUnsolicitedResponse();

    void BeginUnsolTx(APDUResponse& response);

    void BeginTx(uint16_t destination, const ser4cpp::rseq_t& message, bool authenticationResponse = false);

    void CheckForTaskStart();

    void CheckForDeferredRequest();

    void CheckForUnsolicitedNull();

    void CheckForUnsolicited();

    bool ProcessDeferredRequest(const ParsedRequest& request);

    void RestartSolConfirmTimer();

    void RestartUnsolConfirmTimer();

    struct ConfirmWait
    {
        exe4cpp::Timer timer;
        bool active = false;
        bool startOnTxReady = false;
        bool timeoutPending = false;
        bool queued = false;

        void Cancel()
        {
            timer.cancel();
            active = startOnTxReady = timeoutPending = queued = false;
        }
    };

    void RestartConfirmTimer(bool unsolicited);

    void CheckForDeferredConfirms();

    bool CanTransmit() const;

    IINField GetResponseIIN();

    IINField GetDynamicIIN();

    void UpdateLastBroadcastMessageReceived(uint16_t destination);

    void CheckForBroadcastConfirmation(APDUResponse& response);

    /// --- methods for handling app-layer functions ---

    /// Handles non-read function codes that require a response. builds the response using the supplied writer.
    /// @return An IIN field indicating the validity of the request, and to be returned in the response.
    IINField HandleNonReadResponse(const ParsedRequest& request, HeaderWriter& writer);
    IINField HandleFileInfo(const ParsedRequest& request, HeaderWriter& writer);

    /// Handles read function codes. May trigger an unsolicited response
    /// @return an IIN field and a partial AppControlField (missing sequence info)
    AppControlField LoadSolicitedFragment(HeaderWriter& writer, IINField& iin);
    ser4cpp::Pair<IINField, AppControlField> HandleRead(const ser4cpp::rseq_t& objects, HeaderWriter& writer);

    // ------ Function Handlers ------

    IINField HandleWrite(const ParsedRequest& request);
    IINField HandleSelect(const ser4cpp::rseq_t& objects, HeaderWriter& writer);
    IINField HandleOperate(const ser4cpp::rseq_t& objects, HeaderWriter& writer);
    IINField HandleDirectOperate(const ser4cpp::rseq_t& objects, OperateType opType, HeaderWriter* pWriter);
    IINField HandleDelayMeasure(const ser4cpp::rseq_t& objects, HeaderWriter& writer);
    IINField HandleRecordCurrentTime(const ParsedRequest& request);
    IINField HandleRestart(const ser4cpp::rseq_t& objects, bool isWarmRestart, HeaderWriter* pWriter);
    IINField HandleAssignClass(const ser4cpp::rseq_t& objects);
    IINField HandleDisableUnsolicited(const ser4cpp::rseq_t& objects, HeaderWriter* writer);
    IINField HandleEnableUnsolicited(const ser4cpp::rseq_t& objects, HeaderWriter* writer);
    IINField HandleCommandWithConstant(const ser4cpp::rseq_t& objects, HeaderWriter& writer, CommandStatus status);
    IINField HandleFreeze(const ser4cpp::rseq_t& objects);
    IINField HandleFreezeAndClear(const ser4cpp::rseq_t& objects);

    // ------ resources --------
    const Addresses addresses;
    Logger logger;
    const std::shared_ptr<exe4cpp::IExecutor> executor;
    const std::shared_ptr<ILowerLayer> lower;
    const std::shared_ptr<ICommandHandler> commandHandler;
    const std::shared_ptr<IOutstationApplication> application;

    // ------ Database, event buffer, and response tracking
    EventBuffer eventBuffer;
    Database database;
    ResponseContext rspContext;

    // ------ Static configuration -------
    OutstationParams params;

    // ------ Shared dynamic state --------
    bool isOnline;
    bool isTransmitting;
    IINField staticIIN;
    ConfirmWait solConfirm;
    ConfirmWait unsolConfirm;
    bool solicitedReadSelection = false;
    uint16_t solResponseSource = 0;
    RequestHistory history;
    RequestHistory noAckHistory;
    Addresses noAckPeer;
    DeferredRequest deferred;

    // ------ Dynamic state related to controls ------
    ControlState control;

    // ------ Dynamic state related to time synchronization ------
    TimeSyncState time;

    // ------ Dynamic state related to solicited and unsolicited modes ------
    OutstationSolState sol;
    OutstationUnsolState unsol;
    NumRetries unsolRetries;
    bool shouldCheckForUnsolicited;
    OutstationState* state = &StateIdle::Inst();

    // ------ Dynamic state related to broadcast messages ------
    ser4cpp::Settable<LinkBroadcastAddress> lastBroadcastMessageReceived;
};

} // namespace opendnp3

#endif
