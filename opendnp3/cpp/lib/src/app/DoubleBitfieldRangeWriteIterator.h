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
#ifndef OPENDNP3_DOUBLEBITFIELDRANGEWRITEITERATOR_H
#define OPENDNP3_DOUBLEBITFIELDRANGEWRITEITERATOR_H

#include "opendnp3/gen/DoubleBit.h"

#include <ser4cpp/serialization/LittleEndian.h>

namespace opendnp3
{

template<class IndexType> class DoubleBitfieldRangeWriteIterator
{
public:
    static DoubleBitfieldRangeWriteIterator Null()
    {
        auto buffer = ser4cpp::wseq_t::empty();
        return DoubleBitfieldRangeWriteIterator(0, buffer);
    }

    DoubleBitfieldRangeWriteIterator(typename IndexType::type_t start_, ser4cpp::wseq_t& position_)
        : start(start_),
          count(0),
          maxCount(0),
          isValid(position_.length() >= (2 * IndexType::size + 1)),
          range(position_),
          pPosition(&position_)
    {
        if (isValid)
        {
            IndexType::write_to(range, start);
            pPosition->advance(2 * IndexType::size);
            maxCount = pPosition->length() * 4;
        }
    }

    DoubleBitfieldRangeWriteIterator(const DoubleBitfieldRangeWriteIterator&) = delete;
    DoubleBitfieldRangeWriteIterator& operator=(const DoubleBitfieldRangeWriteIterator&) = delete;

    DoubleBitfieldRangeWriteIterator(DoubleBitfieldRangeWriteIterator&& other)
        : start(other.start), count(other.count), maxCount(other.maxCount), isValid(other.isValid),
          range(other.range), pPosition(other.pPosition)
    {
        other.isValid = false;
    }

    ~DoubleBitfieldRangeWriteIterator()
    {
        if (isValid && count > 0)
        {
            IndexType::write_to(range, static_cast<typename IndexType::type_t>(start + count - 1));
            pPosition->advance((count + 3) / 4);
        }
    }

    bool Write(DoubleBit value)
    {
        if (!isValid || count >= maxCount)
        {
            return false;
        }

        const auto byte = count / 4;
        const auto shift = 2 * (count % 4);
        if (shift == 0)
        {
            (*pPosition)[byte] = 0; // also zero unused states in the final byte
        }
        (*pPosition)[byte] |= (static_cast<uint8_t>(value) & 0x03) << shift;
        ++count;
        return true;
    }

private:
    typename IndexType::type_t start;
    uint32_t count;
    size_t maxCount;
    bool isValid;
    ser4cpp::wseq_t range;
    ser4cpp::wseq_t* pPosition;
};

} // namespace opendnp3

#endif
