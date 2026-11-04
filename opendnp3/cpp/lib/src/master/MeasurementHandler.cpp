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
#include "MeasurementHandler.h"

#include "app/parsing/APDUParser.h"
#include "logging/LogMacros.h"

namespace opendnp3
{

ParseResult MeasurementHandler::ProcessMeasurements(ResponseInfo info,
                                                    const ser4cpp::rseq_t& objects,
                                                    Logger& logger,
                                                    ISOEHandler* pHandler)
{
    MeasurementHandler handler(info, logger, pHandler);
    return APDUParser::Parse(objects, handler, &logger);
}

MeasurementHandler::MeasurementHandler(ResponseInfo info, const Logger& logger, ISOEHandler* pSOEHandler)
    : info(info),
      logger(logger),
      txInitiated(false),
      pSOEHandler(pSOEHandler),
      commonTimeOccurence(0, TimestampQuality::INVALID)
{
}

MeasurementHandler::~MeasurementHandler()
{
    if (txInitiated && pSOEHandler)
    {
        this->pSOEHandler->EndFragment(this->info);
    }
}

bool MeasurementHandler::IsAllowed(uint32_t, GroupVariation gv, QualifierCode qc)
{
    // Table 12-63 response qualifiers. Keep request parsing and other types unchanged.
    const bool prefix = qc == QualifierCode::UINT8_CNT_UINT8_INDEX || qc == QualifierCode::UINT16_CNT_UINT16_INDEX;
    const auto id = GroupVariationSpec::to_type(gv);
    if ((id >> 8) == 13 || (id >> 8) == 43)
        return prefix && (id & 0xFF) != 0;
    switch (gv)
    {
    case GroupVariation::Group34Var0:
        return false;
    case GroupVariation::Group34Var1:
    case GroupVariation::Group34Var2:
    case GroupVariation::Group34Var3:
        return qc == QualifierCode::UINT8_START_STOP || qc == QualifierCode::UINT16_START_STOP;
    case GroupVariation::Group121Var1:
        return prefix || qc == QualifierCode::UINT8_START_STOP || qc == QualifierCode::UINT16_START_STOP;
    case GroupVariation::Group122Var1:
    case GroupVariation::Group122Var2:
        return prefix;
    case GroupVariation::Group121Var0:
    case GroupVariation::Group122Var0:
        return false;
    default:
        return true;
    }
}

TimestampQuality MeasurementHandler::ModeFromType(GroupVariation gv)
{
    return HasAbsoluteTime(gv) ? TimestampQuality::SYNCHRONIZED : TimestampQuality::INVALID;
}

IINField MeasurementHandler::ProcessHeader(const RangeHeader& header,
                                           const ICollection<Indexed<AnalogDeadband>>& values)
{
    return this->LoadValues(header, TimestampQuality::INVALID, values);
}

void MeasurementHandler::CheckForTxStart()
{
    if (!txInitiated && pSOEHandler)
    {
        txInitiated = true;
        this->pSOEHandler->BeginFragment(this->info);
    }
}

IINField MeasurementHandler::ProcessHeader(const CountHeader& header, const ICollection<Group50Var1>& values)
{
    this->CheckForTxStart();

    auto transform = [](const Group50Var1& input) -> DNPTime { return input.time; };

    auto collection = Map<Group50Var1, DNPTime>(values, transform);

    HeaderInfo info(header.enumeration, header.GetQualifierCode(), TimestampQuality::INVALID, header.headerIndex);
    this->pSOEHandler->Process(info, collection);

    return IINField();
}

IINField MeasurementHandler::ProcessHeader(const CountHeader& /*header*/, const ICollection<Group51Var1>& values)
{
    Group51Var1 cto;
    if (values.ReadOnlyValue(cto))
    {
        cto.time.quality = TimestampQuality::SYNCHRONIZED;
        commonTimeOccurence = cto.time;
    }
    return IINField::Empty();
}

IINField MeasurementHandler::ProcessHeader(const CountHeader& /*header*/, const ICollection<Group51Var2>& values)
{
    Group51Var2 cto;
    if (values.ReadOnlyValue(cto))
    {
        cto.time.quality = TimestampQuality::UNSYNCHRONIZED;
        commonTimeOccurence = cto.time;
    }

    return IINField::Empty();
}

IINField MeasurementHandler::ProcessHeader(const RangeHeader& header, const ICollection<Indexed<Binary>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const RangeHeader& header,
                                           const ICollection<Indexed<DoubleBitBinary>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const RangeHeader& header,
                                           const ICollection<Indexed<BinaryOutputStatus>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const RangeHeader& header, const ICollection<Indexed<Counter>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const RangeHeader& header, const ICollection<Indexed<FrozenCounter>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const RangeHeader& header, const ICollection<Indexed<Analog>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const RangeHeader& header,
                                           const ICollection<Indexed<AnalogOutputStatus>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const RangeHeader& header, const ICollection<Indexed<OctetString>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const RangeHeader& header,
                                           const ICollection<Indexed<TimeAndInterval>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const PrefixHeader& header, const ICollection<Indexed<Binary>>& values)
{
    if (header.enumeration == GroupVariation::Group2Var3)
    {
        return this->ProcessWithCTO(header, values);
    }

    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const PrefixHeader& header,
                                           const ICollection<Indexed<BinaryOutputStatus>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const PrefixHeader& header,
                                           const ICollection<Indexed<DoubleBitBinary>>& values)
{
    if (header.enumeration == GroupVariation::Group4Var3)
    {
        return this->ProcessWithCTO(header, values);
    }

    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const PrefixHeader& header, const ICollection<Indexed<Counter>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const PrefixHeader& header,
                                           const ICollection<Indexed<FrozenCounter>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const PrefixHeader& header, const ICollection<Indexed<Analog>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const PrefixHeader& header,
                                           const ICollection<Indexed<AnalogOutputStatus>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const PrefixHeader& header, const ICollection<Indexed<OctetString>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const PrefixHeader& header,
                                           const ICollection<Indexed<BinaryCommandEvent>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const PrefixHeader& header,
                                           const ICollection<Indexed<AnalogCommandEvent>>& values)
{
    return this->LoadValues(header, ModeFromType(header.enumeration), values);
}

IINField MeasurementHandler::ProcessHeader(const RangeHeader& header,
                                           const ICollection<Indexed<SecurityStat>>& values)
{
    return LoadSecurityStatistics(header, values);
}

IINField MeasurementHandler::ProcessHeader(const PrefixHeader& header,
                                           const ICollection<Indexed<SecurityStat>>& values)
{
    return LoadSecurityStatistics(header, values);
}

IINField MeasurementHandler::LoadSecurityStatistics(const HeaderRecord& header,
                                                    const ICollection<Indexed<SecurityStat>>& values)
{
    if (header.enumeration != GroupVariation::Group122Var2)
        return LoadValues(header, TimestampQuality::INVALID, values);

    // Absolute time does not prove synchronization (4.5.5, A.47.2). G122 has
    // no time-quality bit; preserve the raw occurrence value without promising
    // accuracy or using the current fragment's NEED_TIME to reinterpret history.
    auto transform = [](const Indexed<SecurityStat>& input) -> Indexed<SecurityStat> {
        auto copy = input;
        copy.value.time.quality = TimestampQuality::UNSYNCHRONIZED;
        return copy;
    };
    auto collection = Map<Indexed<SecurityStat>, Indexed<SecurityStat>>(values, transform);
    return LoadValues(header, TimestampQuality::UNSYNCHRONIZED, collection);
}

IINField MeasurementHandler::ProcessHeader(const RangeHeader& header,
                                           const ICollection<Indexed<DeviceAttribute>>& values)
{
    return LoadValues(header, TimestampQuality::INVALID, values);
}

IINField MeasurementHandler::ProcessHeader(const PrefixHeader& header,
                                           const ICollection<Indexed<DeviceAttribute>>& values)
{
    return LoadValues(header, TimestampQuality::INVALID, values);
}

} // namespace opendnp3
