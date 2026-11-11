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

#include "Functions.h"
#include "app/parsing/APDUParser.h"

namespace opendnp3
{
bool Functions::IsNoAckFuncCode(FunctionCode code)
{
    switch (code)
    {
    case (FunctionCode::DIRECT_OPERATE_NR):
    case (FunctionCode::IMMED_FREEZE_NR):
    case (FunctionCode::FREEZE_AT_TIME_NR):
    case (FunctionCode::FREEZE_CLEAR_NR):
        return true;
    default:
        return false;
    }
}
bool Functions::IsTimeSynchronizationRequest(FunctionCode code, const ser4cpp::rseq_t& objects)
{
    if (code == FunctionCode::DELAY_MEASURE || code == FunctionCode::RECORD_CURRENT_TIME)
        return true;
    if (code != FunctionCode::WRITE)
        return false;

    struct TimeWrite final : IWhiteList
    {
        bool IsAllowed(uint32_t, GroupVariation gv, QualifierCode) override
        {
            containsClock = containsClock || gv == GroupVariation::Group50Var1 || gv == GroupVariation::Group50Var3;
            return true;
        }
        bool containsClock = false;
    } write;
    APDUParser::ParseSinglePass(objects, nullptr, nullptr, &write, ParserSettings::Default());
    return write.containsClock;
}
} // namespace opendnp3
