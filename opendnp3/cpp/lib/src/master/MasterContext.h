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
#ifndef OPENDNP3_MASTERCONTEXT_H
#define OPENDNP3_MASTERCONTEXT_H

#include "LayerInterfaces.h"
#include "app/AppSeqNum.h"
#include "auth/AggressiveMode.h"
#include "auth/AuthenticationSession.h"
#include "master/HeaderBuilder.h"
#include "master/IMasterScheduler.h"
#include "master/MasterResponder.h"
#include "master/MasterTasks.h"
#include "outstation/OutstationChallenger.h"

#include "opendnp3/app/MeasurementTypes.h"
#include "opendnp3/gen/RestartType.h"
#include "opendnp3/logging/Logger.h"
#include "opendnp3/master/CommandResultCallbackT.h"
#include "opendnp3/master/CommandSet.h"
#include "opendnp3/master/IMasterApplication.h"
#include "opendnp3/master/RestartOperationResult.h"

#include <ser4cpp/container/Buffer.h>

#include <exe4cpp/Timer.h>
#include <exe4cpp/asio/StrandExecutor.h>

#include <deque>
#include <memory>

namespace opendnp3
{
/*
    All of the mutable state and configuration for a master
*/
class MContext final : public IUpperLayer,
                       public std::enable_shared_from_this<MContext>,
                       private IMasterTaskRunner,
                       private Uncopyable
{
private:
    MContext(const Addresses& addresses,
             const Logger& logger,
             const std::shared_ptr<exe4cpp::IExecutor>& executor,
             std::shared_ptr<ILowerLayer> lower,
             const std::shared_ptr<ISOEHandler>& SOEHandler,
             const std::shared_ptr<IMasterApplication>& application,
             std::shared_ptr<IMasterScheduler> scheduler,
             const MasterParams& params);

public:
    enum class TaskState
    {
        IDLE,
        TASK_READY,
        WAIT_FOR_RESPONSE
    };

    static std::shared_ptr<MContext> Create(const Addresses& addresses,
                                            const Logger& logger,
                                            const std::shared_ptr<exe4cpp::IExecutor>& executor,
                                            std::shared_ptr<ILowerLayer> lower,
                                            const std::shared_ptr<ISOEHandler>& SOEHandler,
                                            const std::shared_ptr<IMasterApplication>& application,
                                            std::shared_ptr<IMasterScheduler> scheduler,
                                            const MasterParams& params);

    Logger logger;
    const std::shared_ptr<exe4cpp::IExecutor> executor;
    const std::shared_ptr<ILowerLayer> lower;

    // ------- configuration --------
    const Addresses addresses;
    const MasterParams params;
    const std::shared_ptr<ISOEHandler> SOEHandler;
    const std::shared_ptr<IMasterApplication> application;
    const std::shared_ptr<IMasterScheduler> scheduler;

    // ------- dynamic state ---------
    bool isOnline = false;
    bool isSending = false;
    AppSeqNum solSeq;
    AppSeqNum unsolSeq;
    std::shared_ptr<IMasterTask> activeTask;
    exe4cpp::Timer responseTimer;

    MasterTasks tasks;
    std::deque<APDUHeader> confirmQueue;
    ser4cpp::Buffer txBuffer;
    TaskState tstate;

    // --- implement  IUpperLayer ------

    bool OnLowerLayerUp() final;

    bool OnLowerLayerDown() final;

    bool OnReceive(const Message& message) final;

    bool OnTxReady() final;

    // additional virtual methods that can be overriden to implement secure authentication

    virtual void OnParsedHeader(const ser4cpp::rseq_t& apdu,
                                const APDUResponseHeader& header,
                                const ser4cpp::rseq_t& objects);

    virtual void RecordLastRequest(const ser4cpp::rseq_t& apdu) {}

    // methods for initiating command sequences

    void DirectOperate(CommandSet&& commands, const CommandResultCallbackT& callback, const TaskConfig& config);

    void SelectAndOperate(CommandSet&& commands, const CommandResultCallbackT& callback, const TaskConfig& config);

    // -----  public methods used to add tasks -----

    std::shared_ptr<IMasterTask> AddScan(TimeDuration period,
                                         const HeaderBuilderT& builder,
                                         std::shared_ptr<ISOEHandler> soe_handler,
                                         TaskConfig config = TaskConfig::Default());

    std::shared_ptr<IMasterTask> AddAllObjectsScan(GroupVariationID gvId,
                                                   TimeDuration period,
                                                   std::shared_ptr<ISOEHandler> soe_handler,
                                                   TaskConfig config = TaskConfig::Default());

    std::shared_ptr<IMasterTask> AddClassScan(const ClassField& field,
                                              TimeDuration period,
                                              std::shared_ptr<ISOEHandler> soe_handler,
                                              TaskConfig config = TaskConfig::Default());

    std::shared_ptr<IMasterTask> AddRangeScan(GroupVariationID gvId,
                                              uint16_t start,
                                              uint16_t stop,
                                              TimeDuration period,
                                              std::shared_ptr<ISOEHandler> soe_handler,
                                              TaskConfig config = TaskConfig::Default());

    // ---- Single shot immediate scans ----

    void Scan(const HeaderBuilderT& builder,
              std::shared_ptr<ISOEHandler> soe_handler,
              TaskConfig config = TaskConfig::Default());

    void ScanAllObjects(GroupVariationID gvId,
                        std::shared_ptr<ISOEHandler> soe_handler,
                        TaskConfig config = TaskConfig::Default());

    void ScanClasses(const ClassField& field,
                     std::shared_ptr<ISOEHandler> soe_handler,
                     TaskConfig config = TaskConfig::Default());

    void ScanRange(GroupVariationID gvId,
                   uint16_t start,
                   uint16_t stop,
                   std::shared_ptr<ISOEHandler> soe_handler,
                   TaskConfig config = TaskConfig::Default());

    /// ---- Write tasks -----

    void Write(const TimeAndInterval& value, uint16_t index, TaskConfig config = TaskConfig::Default());

    void Restart(RestartType op, const RestartOperationCallbackT& callback, TaskConfig config = TaskConfig::Default());

    void PerformFunction(const std::string& name,
                         FunctionCode func,
                         const HeaderBuilderT& builder,
                         TaskConfig config = TaskConfig::Default());

    /// public state manipulation actions

    TaskState ResumeActiveTask();

    void CompleteActiveTask();

    void QueueConfirm(const APDUHeader& header);

    void StartResponseTimer();

    void ProcessAPDU(const APDUResponseHeader& header, const ser4cpp::rseq_t& objects);

    bool CheckConfirmTransmit();

    void ProcessResponse(const APDUResponseHeader& header, const ser4cpp::rseq_t& objects);

    void ProcessUnsolicitedResponse(const APDUResponseHeader& header, const ser4cpp::rseq_t& objects);

    void Transmit(const ser4cpp::rseq_t& data);

private:
    // Manual session-key injection friend exists only in unit tests. Production
    // uses configured credential retrieval and the authenticated session exchange.
    friend class AuthenticationRuntimeTestAccess;
    friend class ProductionAuthenticationTestAccess;
    struct AuthenticationState
    {
        AuthenticationState(uint16_t association, size_t tagLength)
            : monitoring(association, tagLength, 2000, true),
              controlAggressive(association, tagLength, false),
              monitoringAggressive(association, tagLength, true),
              association(association),
              responder(association, tagLength)
        {
        }
        explicit AuthenticationState(const AuthenticationConfig& config)
            : monitoring(config.association, config.tagLength, config.replyTimeoutMs, true, config.macAlgorithm),
              controlAggressive(config.association, config.tagLength, false, config.macAlgorithm),
              monitoringAggressive(config.association, config.tagLength, true, config.macAlgorithm),
              sessions(new AuthenticationSession(SessionKeys::Role::MASTER, config)),
              association(config.association),
              responder(association, config.tagLength, config.replyTimeoutMs, false, config.macAlgorithm)
        {
        }
        ~AuthenticationState()
        {
            serviceTimer.cancel();
        }
        OutstationChallenger monitoring;
        AggressiveMode controlAggressive, monitoringAggressive;
        std::array<bool, 2> controlEligible{{false, false}};
        bool monitoringEligible = false;
        std::array<uint8_t, SessionKeys::MAX_APDU> aggressiveWire{};
        std::unique_ptr<AuthenticationSession> sessions;
        exe4cpp::Timer serviceTimer;
        std::array<uint8_t, SessionKeys::MAX_APDU> wire{}, pendingWire{}, verifiedResponse{};
        std::array<uint32_t, 2> keyEpoch{{0, 0}};
        size_t wireSize = 0, pendingWireSize = 0;
        size_t exchangeIndex = 2;
        uint8_t exchangeSequence = 0;
        uint16_t responderUser = 0;
        bool wireInFlight = false;
        bool established = false;
        bool peerRestartAllowed = true;
        uint32_t restartRekeys = 0;
        uint64_t restartWindow = 0;
        bool protectedConfirm = false;
        uint8_t deferredAuthenticationCount = 0;
        uint32_t deferredAuthenticationKSQ = 0;
        bool nativeConfirmQueued = false;
        uint8_t nativeConfirmControl = 0;
        uint64_t confirmDeadline = 0;
        bool monitorWaiting = false;
        uint8_t monitorSequence = 0;
        const uint16_t association;
        MasterResponder responder;
        std::array<uint8_t, 30> reply{};
        size_t replySize = 0;
        uint64_t replyDeadline = 0;
        uint32_t replyKSQ = 0;
        bool replyCountExhausted = false;
        bool replyPending = false;
        bool replyInFlight = false;
        bool protectedTask = false;
        bool allowUnkeyedCritical = false; // Admission for this task only; never armed by a timer.
        bool replyIssued = false;
    };
    std::shared_ptr<AuthenticationState> authentication; // null only in explicit compatibility mode
    void ResetAuthentication();
    bool RouteAuthentication(const ser4cpp::rseq_t& apdu, const APDUResponseHeader& header);
    bool IsAuthenticationReplyValid(uint64_t now);
    void CancelAuthenticationReply();
    void TransmitAuthenticationReply();
    void ServiceAuthentication();
    void ProcessAuthenticatedResponse(const ser4cpp::rseq_t& wire, const ser4cpp::rseq_t& native, uint8_t count);
    void FinalizeAuthenticationCounts();
    void DiscardEmbeddedConfirm();

    // --- implement  IMasterTaskRunner ------

    virtual bool Run(const std::shared_ptr<IMasterTask>& task) override;

    void ScheduleRecurringPollTask(const std::shared_ptr<IMasterTask>& task);

    void ProcessIIN(const IINField& iin);

    void OnResponseTimeout();

protected:
    void ScheduleAdhocTask(const std::shared_ptr<IMasterTask>& task);

    // state switch lookups

    TaskState OnTransmitComplete();
    TaskState OnResponseEvent(const APDUResponseHeader& header, const ser4cpp::rseq_t& objects);
    TaskState OnResponseTimeoutEvent();

    // --- state handling functions ----
    TaskState StartTask_TaskReady();
    TaskState OnResponse_WaitForResponse(const APDUResponseHeader& header, const ser4cpp::rseq_t& objects);
    TaskState OnResponseTimeout_WaitForResponse();
};

} // namespace opendnp3

#endif
