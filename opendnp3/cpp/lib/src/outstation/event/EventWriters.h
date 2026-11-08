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

#ifndef OPENDNP3_EVENTWRITERS_H
#define OPENDNP3_EVENTWRITERS_H

#include "IEventWriteHandler.h"
#include "app/DNP3Serializer.h"
#include "app/HeaderWriter.h"
#include "gen/objects/Group51.h"

#include <ser4cpp/serialization/LittleEndian.h>

namespace opendnp3
{

class EventWriters
{

public:
    template<class T>
    static uint16_t Write(HeaderWriter& writer, IEventCollection<T>& items, const DNP3Serializer<T>& serializer,
                          bool prefer8Bit = false)
    {
        if (prefer8Bit && items.FirstIndex() <= ser4cpp::UInt8::max_value)
        {
            BasicEventWriter<T, ser4cpp::UInt8> handler(writer, serializer, QualifierCode::UINT8_CNT_UINT8_INDEX);
            return items.WriteSome(handler);
        }
        BasicEventWriter<T, ser4cpp::UInt16> handler(writer, serializer, QualifierCode::UINT16_CNT_UINT16_INDEX);
        return items.WriteSome(handler);
    }

    template<class T>
    static uint16_t WriteWithCTO(const DNPTime& cto,
                                 HeaderWriter& writer,
                                 IEventCollection<T>& items,
                                 const DNP3Serializer<T>& serializer,
                                 bool prefer8Bit = false)
    {
        if (cto.quality == TimestampQuality::SYNCHRONIZED)
        {
            Group51Var1 value;
            value.time = cto;
            return WriteWithCTOValue(value, writer, items, serializer, prefer8Bit);
        }
        else
        {
            Group51Var2 value;
            value.time = cto;
            return WriteWithCTOValue(value, writer, items, serializer, prefer8Bit);
        }
    }

    static uint16_t Write(uint8_t firstSize, HeaderWriter& writer, IEventCollection<OctetString>& items);

private:
    template<class T, class Index> class BasicEventWriter final : public IEventWriter<T>
    {
        PrefixedWriteIterator<Index, T> iterator;

    public:
        BasicEventWriter(HeaderWriter& writer, const DNP3Serializer<T>& serializer, QualifierCode qualifier)
            : iterator(writer.IterateOverCountWithPrefix<Index, T>(qualifier, serializer))
        {
        }

        bool Write(const T& meas, uint16_t index) override
        {
            return index <= Index::max_value && iterator.Write(meas, static_cast<typename Index::type_t>(index));
        }
    };

    template<class T, class U, class Index> class CTOEventWriter final : public IEventWriter<T>
    {
        const DNPTime cto;
        PrefixedWriteIterator<Index, T> iterator;

    public:
        CTOEventWriter(const U& cto, HeaderWriter& writer, const DNP3Serializer<T>& serializer, QualifierCode qualifier)
            : cto(cto.time),
              iterator(writer.IterateOverCountWithPrefixAndCTO<Index, T, U>(qualifier, serializer, cto))
        {
        }

        bool Write(const T& meas, uint16_t index) override
        {
            if (!iterator.IsValid() || index > Index::max_value)
                return false;

            // Check that the quality of the measurement fits with the CTO variation
            if (this->cto.quality == TimestampQuality::SYNCHRONIZED)
            {
                if (meas.time.quality != TimestampQuality::SYNCHRONIZED)
                    return false;
            }
            else
            {
                if (meas.time.quality == TimestampQuality::SYNCHRONIZED)
                    return false;
            }

            // can't encode timestamps that go backwards
            if (meas.time.value < this->cto.value)
                return false;

            const auto diff = meas.time.value - this->cto.value;

            // can't encode timestamps where the diff is greater than uint16_t
            if (diff > ser4cpp::UInt16::max_value)
                return false;

            auto copy = meas;
            copy.time = DNPTime(diff);

            return iterator.Write(copy, static_cast<typename Index::type_t>(index));
        }
    };

    template<class T, class U>
    static uint16_t WriteWithCTOValue(const U& cto, HeaderWriter& writer, IEventCollection<T>& items,
                                      const DNP3Serializer<T>& serializer, bool prefer8Bit)
    {
        if (prefer8Bit && items.FirstIndex() <= ser4cpp::UInt8::max_value)
        {
            CTOEventWriter<T, U, ser4cpp::UInt8> handler(cto, writer, serializer, QualifierCode::UINT8_CNT_UINT8_INDEX);
            return items.WriteSome(handler);
        }
        CTOEventWriter<T, U, ser4cpp::UInt16> handler(cto, writer, serializer, QualifierCode::UINT16_CNT_UINT16_INDEX);
        return items.WriteSome(handler);
    }
};

} // namespace opendnp3

#endif
