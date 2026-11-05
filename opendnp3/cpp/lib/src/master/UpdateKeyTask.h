// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_UPDATEKEYTASK_H
#define OPENDNP3_UPDATEKEYTASK_H
#include "auth/RemoteUpdateKeys.h"
#include "master/IMasterTask.h"
#include "master/TaskPriority.h"

namespace opendnp3
{
// Native scheduled task. The shared runtime lifetime keeps the engine alive
// through task completion; neither the authority nor RX views own wire buffers.
class UpdateKeyTask final : public IMasterTask
{
public:
    UpdateKeyTask(const std::shared_ptr<TaskContext>& context, IMasterApplication& app,
                  const Logger& logger, const TaskConfig& config, Timestamp expiration,
                  std::shared_ptr<exe4cpp::IExecutor> executor, std::shared_ptr<void> lifetime,
                  RemoteUpdateKeys& engine, const UpdateKeyRequest& request);
    char const* Name() const override { return "Update Key"; }
    int Priority() const override { return priority::COMMAND; }
    bool IsRecurring() const override { return false; }
    bool IsAuthenticationTask() const override { return true; }
    bool BuildRequest(APDURequest& request, uint8_t sequence) override;
    void OnRequestBuildFailure(Timestamp now) override;
    bool AcceptsAuthenticationResponse(const APDUResponseHeader& header, const ser4cpp::rseq_t& objects) override;
    bool RetryOnResponseTimeout() override { return started && engine.Retry(Now()); }
    uint32_t ResponseTimeoutMs() const override { return engine.TimeoutMs(); }
private:
    uint64_t Now() const;
    bool BlocksLowerPriority() const override { return false; }
    MasterTaskType GetTaskType() const override { return MasterTaskType::USER_TASK; }
    ResponseResult ProcessResponse(const APDUResponseHeader&, const ser4cpp::rseq_t&) override;
    void OnTaskComplete(TaskCompletion, Timestamp) override;
    std::shared_ptr<exe4cpp::IExecutor> executor;
    std::shared_ptr<void> lifetime;
    RemoteUpdateKeys& engine;
    UpdateKeyRequest request;
    RemoteUpdateKeys::Result result = RemoteUpdateKeys::Result::IGNORED;
    bool started = false;
};
}
#endif
