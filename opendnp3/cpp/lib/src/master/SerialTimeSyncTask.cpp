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
#include "SerialTimeSyncTask.h"

#include "app/APDUBuilders.h"
#include "app/parsing/APDUParser.h"
#include "gen/objects/Group50.h"
#include "master/TimeSyncHandler.h"

#include <ser4cpp/serialization/LittleEndian.h>

namespace opendnp3
{

SerialTimeSyncTask::SerialTimeSyncTask(const std::shared_ptr<TaskContext>& context,
                                       IMasterApplication& app,
                                       const Logger& logger,
                                       const std::shared_ptr<exe4cpp::IExecutor>& executor)
    : IMasterTask(context, app, TaskBehavior::ReactsToIINOnly(), logger, TaskConfig::Default()),
      delay(-1), executor(executor)
{
}

void SerialTimeSyncTask::Initialize()
{
    delay = -1;
}

bool SerialTimeSyncTask::BuildRequest(APDURequest& request, uint8_t seq)
{
    if (delay < 0)
    {
        start = executor->get_time();
        build::MeasureDelay(request, seq);
    }
    else
    {
        constexpr uint64_t maxTime = 0xFFFFFFFFFFFFULL;
        const auto now = this->application->Now().msSinceEpoch;
        if (now > maxTime || static_cast<uint64_t>(delay) > maxTime - now)
            return false;
        Group50Var1 time;
        time.time = DNPTime(now + delay);
        request.SetFunction(FunctionCode::WRITE);
        request.SetControl(AppControlField::Request(seq));
        auto writer = request.GetWriter();
        writer.WriteSingleValue<ser4cpp::UInt8, Group50Var1>(QualifierCode::UINT8_CNT, time);
    }

    return true;
}

IMasterTask::ResponseResult SerialTimeSyncTask::ProcessResponse(const APDUResponseHeader& response,
                                                                const ser4cpp::rseq_t& objects)
{
    return (delay < 0) ? OnResponseDelayMeas(response, objects) : OnResponseWriteTime(response, objects);
}

IMasterTask::ResponseResult SerialTimeSyncTask::OnResponseDelayMeas(const APDUResponseHeader& response,
                                                                    const ser4cpp::rseq_t& objects)
{
    if (ValidateSingleResponse(response) && ValidateInternalIndications(response))
    {
        TimeSyncHandler handler;
        auto result = APDUParser::Parse(objects, handler, &logger);
        if (result == ParseResult::OK)
        {
            uint16_t rtuTurnAroundTime;
            if (handler.GetTimeDelay(rtuTurnAroundTime))
            {
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(executor->get_time() - start);
                delay = elapsed.count() >= rtuTurnAroundTime ? (elapsed.count() - rtuTurnAroundTime) / 2 : 0;

                return ResponseResult::OK_REPEAT;
            }

            return ResponseResult::ERROR_BAD_RESPONSE;
        }
        else
        {
            return ResponseResult::ERROR_BAD_RESPONSE;
        }
    }
    else
    {
        return ResponseResult::ERROR_BAD_RESPONSE;
    }
}

IMasterTask::ResponseResult SerialTimeSyncTask::OnResponseWriteTime(const APDUResponseHeader& header,
                                                                    const ser4cpp::rseq_t& objects)
{
    return ValidateNullResponse(header, objects) ? ResponseResult::OK_FINAL : ResponseResult::ERROR_BAD_RESPONSE;
}

} // namespace opendnp3
