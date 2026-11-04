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
#include "opendnp3/master/HeaderTypes.h"

#include "app/HeaderWriter.h"
#include "gen/objects/Group34.h"

#include <cmath>
#include <limits>
#include <type_traits>
#include <utility>

namespace opendnp3
{

namespace
{
template<class Number> bool FitsDeadband(double value)
{
    if (std::is_floating_point<Number>::value)
        return !std::isnan(value) && (std::isinf(value) || std::abs(value) <= std::numeric_limits<Number>::max());
    return value >= 0 && value <= std::numeric_limits<Number>::max() && std::trunc(value) == value;
}

template<class Index, class Variation>
bool WriteDeadbandValues(HeaderWriter& writer, QualifierCode qualifier, bool range,
                         const std::vector<Indexed<AnalogDeadband>>& values)
{
    if (values.empty() || (!range && values.size() > Index::max_value))
        return false;
    uint32_t expected = values.front().index;
    for (const auto& item : values)
    {
        if (item.index > Index::max_value || (range && item.index != expected)
            || !FitsDeadband<typename Variation::ValueType>(item.value.value))
            return false;
        ++expected;
    }
    if (range)
    {
        auto iter = writer.IterateOverRange<Index>(qualifier, Variation::Inst(),
                                                  static_cast<typename Index::type_t>(values.front().index));
        for (const auto& item : values)
            if (!iter.Write(item.value)) return false;
    }
    else
    {
        auto iter = writer.IterateOverCountWithPrefix<Index>(qualifier, Variation::Inst());
        for (const auto& item : values)
            if (!iter.Write(item.value, static_cast<typename Index::type_t>(item.index))) return false;
    }
    return true;
}

template<class Variation>
bool WriteDeadbandValues(HeaderWriter& writer, QualifierCode qualifier,
                         const std::vector<Indexed<AnalogDeadband>>& values)
{
    switch (qualifier)
    {
    case QualifierCode::UINT8_START_STOP:
        return WriteDeadbandValues<ser4cpp::UInt8, Variation>(writer, qualifier, true, values);
    case QualifierCode::UINT16_START_STOP:
        return WriteDeadbandValues<ser4cpp::UInt16, Variation>(writer, qualifier, true, values);
    case QualifierCode::UINT8_CNT_UINT8_INDEX:
        return WriteDeadbandValues<ser4cpp::UInt8, Variation>(writer, qualifier, false, values);
    case QualifierCode::UINT16_CNT_UINT16_INDEX:
        return WriteDeadbandValues<ser4cpp::UInt16, Variation>(writer, qualifier, false, values);
    default:
        return false;
    }
}
} // namespace

Header Header::AllObjects(uint8_t group, uint8_t variation)
{
    return Header(group, variation);
}

Header Header::From(PointClass pc)
{
    switch (pc)
    {
    case (PointClass::Class0):
        return Header::AllObjects(60, 1);
    case (PointClass::Class1):
        return Header::AllObjects(60, 2);
    case (PointClass::Class2):
        return Header::AllObjects(60, 3);
    default:
        return Header::AllObjects(60, 4);
    }
}

Header Header::Range8(uint8_t group, uint8_t variation, uint8_t start, uint8_t stop)
{
    return Header(group, variation, start, stop);
}

Header Header::Range16(uint8_t group, uint8_t variation, uint16_t start, uint16_t stop)
{
    return Header(group, variation, start, stop);
}

Header Header::Count8(uint8_t group, uint8_t variation, uint8_t count)
{
    return Header(group, variation, count);
}

Header Header::Count16(uint8_t group, uint8_t variation, uint16_t count)
{
    return Header(group, variation, count);
}

Header::Header(uint8_t group, uint8_t var) : id(group, var), type(HeaderType::AllObjects) {}

Header::Header(uint8_t group, uint8_t var, uint8_t start, uint8_t stop) : id(group, var), type(HeaderType::Ranged8)
{
    value.range8 = {start, stop};
}

Header::Header(uint8_t group, uint8_t var, uint16_t start, uint16_t stop) : id(group, var), type(HeaderType::Ranged16)
{
    value.range16 = {start, stop};
}

Header::Header(uint8_t group, uint8_t var, uint8_t count) : id(group, var), type(HeaderType::LimitedCount8)
{
    value.count8.value = count;
}

Header::Header(uint8_t group, uint8_t var, uint16_t count) : id(group, var), type(HeaderType::LimitedCount16)
{
    value.count16.value = count;
}

bool Header::WriteTo(HeaderWriter& writer) const
{
    switch (type)
    {
    case (HeaderType::AllObjects):
        return writer.WriteHeader(id, QualifierCode::ALL_OBJECTS);
    case (HeaderType::Ranged8):
        return writer.WriteRangeHeader<ser4cpp::UInt8>(QualifierCode::UINT8_START_STOP, id, value.range8.start,
                                                       value.range8.stop);
    case (HeaderType::Ranged16):
        return writer.WriteRangeHeader<ser4cpp::UInt16>(QualifierCode::UINT16_START_STOP, id, value.range16.start,
                                                        value.range16.stop);
    case (HeaderType::LimitedCount8):
        return writer.WriteCountHeader<ser4cpp::UInt8>(QualifierCode::UINT8_CNT, id, value.count8.value);
    case (HeaderType::LimitedCount16):
        return writer.WriteCountHeader<ser4cpp::UInt16>(QualifierCode::UINT16_CNT, id, value.count16.value);
    case HeaderType::AnalogDeadbandWrite:
        switch (static_cast<AnalogDeadbandVariation>(id.variation))
        {
        case AnalogDeadbandVariation::UInt16:
            return WriteDeadbandValues<Group34Var1>(writer, deadbandWrite->qualifier, deadbandWrite->values);
        case AnalogDeadbandVariation::UInt32:
            return WriteDeadbandValues<Group34Var2>(writer, deadbandWrite->qualifier, deadbandWrite->values);
        case AnalogDeadbandVariation::Float32:
            return WriteDeadbandValues<Group34Var3>(writer, deadbandWrite->qualifier, deadbandWrite->values);
        default:
            return false;
        }
    default:
        return false;
    }
}

Header Header::WriteAnalogDeadbands(AnalogDeadbandVariation variation,
                                    QualifierCode qualifier,
                                    std::vector<Indexed<AnalogDeadband>> values)
{
    Header header(34, static_cast<uint8_t>(variation));
    header.type = HeaderType::AnalogDeadbandWrite;
    header.deadbandWrite = std::make_shared<DeadbandWrite>(DeadbandWrite{qualifier, std::move(values)});
    return header;
}
} // namespace opendnp3
