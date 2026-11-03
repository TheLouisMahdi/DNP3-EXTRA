// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "master/UpdateKeyTask.h"

namespace opendnp3
{
UpdateKeyTask::UpdateKeyTask(const std::shared_ptr<TaskContext>& context, IMasterApplication& app,
    const Logger& logger, const TaskConfig& config, Timestamp expiration,
    std::shared_ptr<exe4cpp::IExecutor> executor_, std::shared_ptr<void> lifetime_,
    RemoteUpdateKeys& engine_, const UpdateKeyRequest& request_)
    : IMasterTask(context, app, TaskBehavior::SingleExecutionNoRetry(expiration), logger, config),
      executor(std::move(executor_)), lifetime(std::move(lifetime_)), engine(engine_), request(request_)
{
}
uint64_t UpdateKeyTask::Now() const
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        executor->get_time().time_since_epoch()).count());
}
bool UpdateKeyTask::BuildRequest(APDURequest& apdu, uint8_t sequence)
{
    if (!started)
    {
        if (!engine.Begin(request, Now())) return false;
        started = true;
    }
    return engine.Build(apdu, sequence, Now());
}
bool UpdateKeyTask::AcceptsAuthenticationResponse(const APDUResponseHeader& header, const ser4cpp::rseq_t& objects)
{
    if (!started) return false;
    result = engine.Response(header, objects, Now());
    return result != RemoteUpdateKeys::Result::IGNORED;
}
IMasterTask::ResponseResult UpdateKeyTask::ProcessResponse(const APDUResponseHeader&, const ser4cpp::rseq_t&)
{
    switch (result)
    {
    case RemoteUpdateKeys::Result::CONTINUE: return ResponseResult::OK_REPEAT;
    case RemoteUpdateKeys::Result::COMPLETE: return ResponseResult::OK_FINAL;
    default: return ResponseResult::ERROR_BAD_RESPONSE;
    }
}
void UpdateKeyTask::OnTaskComplete(TaskCompletion, Timestamp)
{
    if (started) engine.Cancel();
    started = false;
    request = UpdateKeyRequest();
}
}
