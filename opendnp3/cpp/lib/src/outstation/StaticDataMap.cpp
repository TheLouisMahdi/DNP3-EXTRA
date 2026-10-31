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

#include "StaticDataMap.h"

#include "opendnp3/gen/AnalogQuality.h"
#include "opendnp3/gen/DoubleBitBinaryQuality.h"

namespace opendnp3
{

bool convert_to_event_class(PointClass pc, EventClass& ec)
{
    switch (pc)
    {
    case (PointClass::Class1):
        ec = EventClass::EC1;
        return true;
    case (PointClass::Class2):
        ec = EventClass::EC2;
        return true;
    case (PointClass::Class3):
        ec = EventClass::EC3;
        return true;
    default:
        return false;
    }
}

template<>
bool StaticDataMap<TimeAndIntervalSpec>::update(const TimeAndInterval& value,
                                                uint16_t index,
                                                EventMode /*mode*/,
                                                IEventReceiver& /*receiver*/)
{
    const auto iter = this->map.find(index);
    if (iter == this->map.end())
    {
        return false;
    }

    iter->second.value = value;

    return true;
}

template<> StaticBinaryVariation check_for_promotion<BinarySpec>(const Binary& value, StaticBinaryVariation variation)
{
    if (variation == StaticBinaryVariation::Group1Var1)
    {
        return BinarySpec::IsQualityOnlineOnly(value) ? variation : StaticBinaryVariation::Group1Var2;
    }

    return variation;
}

template<>
StaticDoubleBinaryVariation check_for_promotion<DoubleBitBinarySpec>(const DoubleBitBinary& value,
                                                                    StaticDoubleBinaryVariation variation)
{
    const auto state_mask = static_cast<uint8_t>(DoubleBitBinaryQuality::STATE1)
        | static_cast<uint8_t>(DoubleBitBinaryQuality::STATE2);
    const auto quality = value.flags.value & ~state_mask;
    if (variation == StaticDoubleBinaryVariation::Group3Var1
        && quality != static_cast<uint8_t>(DoubleBitBinaryQuality::ONLINE))
    {
        return StaticDoubleBinaryVariation::Group3Var2;
    }
    return variation;
}

template<> StaticAnalogVariation check_for_promotion<AnalogSpec>(const Analog& value, StaticAnalogVariation variation)
{
    if (value.flags.value == static_cast<uint8_t>(AnalogQuality::ONLINE))
    {
        return variation;
    }

    switch (variation)
    {
    case (StaticAnalogVariation::Group30Var3):
        return StaticAnalogVariation::Group30Var1;
    case (StaticAnalogVariation::Group30Var4):
        return StaticAnalogVariation::Group30Var2;
    default:
        return variation;
    }
}

} // namespace opendnp3
