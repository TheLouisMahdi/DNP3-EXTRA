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
#include "FreeFormatParser.h"
#include "app/AuthObjectValidation.h"
#include <ser4cpp/serialization/LittleEndian.h>

namespace opendnp3
{
namespace
{
bool ValidUTF8(const ser4cpp::rseq_t& text)
{
    const uint8_t* p = text;
    size_t i = 0;
    while (i < text.length())
    {
        const auto first = p[i++];
        if (first < 0x80) continue;
        uint32_t value;
        uint32_t minimum;
        size_t trailing;
        if (first >= 0xC2 && first <= 0xDF) { value = first & 0x1F; minimum = 0x80; trailing = 1; }
        else if (first >= 0xE0 && first <= 0xEF) { value = first & 0x0F; minimum = 0x800; trailing = 2; }
        else if (first >= 0xF0 && first <= 0xF4) { value = first & 7; minimum = 0x10000; trailing = 3; }
        else return false;
        if (text.length() - i < trailing) return false;
        while (trailing--)
        {
            const auto next = p[i++];
            if ((next & 0xC0) != 0x80) return false;
            value = (value << 6) | (next & 0x3F);
        }
        if (value < minimum || value > 0x10FFFF || (value >= 0xD800 && value <= 0xDFFF)) return false;
    }
    return true;
}

// Views borrow the validated APDU. Callbacks must copy any data retained after dispatch.
template<class T> class FreeFormatCollection final : public ICollection<T>
{
public:
    FreeFormatCollection(ser4cpp::rseq_t data_, uint8_t count_) : data(data_), count(count_) {}
    size_t Count() const override { return count; }
    void Foreach(IVisitor<T>& visitor) const override
    {
        auto input = data;
        for (uint16_t i = 0; i < count; ++i)
        {
            uint16_t length;
            ser4cpp::UInt16::read_from(input, length);
            T value;
            if (!value.Read(input.take(length))) return;
            input.advance(length);
            visitor.OnValue(value);
        }
    }
private:
    ser4cpp::rseq_t data;
    uint8_t count;
};

template<class T> ParseResult ParseObjects(ser4cpp::rseq_t& buffer, const HeaderRecord& record,
                                         IAPDUHandler* handler)
{
    auto input = buffer;
    if (input.length() < 1) return ParseResult::NOT_ENOUGH_DATA_FOR_RANGE;
    uint8_t count;
    ser4cpp::UInt8::read_from(input, count);
    if (!count) return ParseResult::COUNT_OF_ZERO;
    const auto start = input;
    for (uint16_t i = 0; i < count; ++i)
    {
        if (input.length() < 2) return ParseResult::NOT_ENOUGH_DATA_FOR_OBJECTS;
        uint16_t length;
        ser4cpp::UInt16::read_from(input, length);
        if (input.length() < length) return ParseResult::NOT_ENOUGH_DATA_FOR_OBJECTS;
        T value;
        if (!value.Read(input.take(length)) || !IsValidAuthObject(value)) return ParseResult::INVALID_OBJECT;
        input.advance(length);
    }
    if (handler)
    {
        FreeFormatCollection<T> values(start.take(start.length() - input.length()), count);
        handler->OnHeader(FreeFormatHeader(record, count), values);
    }
    buffer = input;
    return ParseResult::OK;
}
}

bool IsValidAuthObject(const Group120Var1& value) { return value.challengeData.length() >= 4; }
// MAC length is selected by the challenge's algorithm and checked by the future SA state machine.
bool IsValidAuthObject(const Group120Var2& value) { return value.hmacValue.length() != 0; }
bool IsValidAuthObject(const Group120Var7& value)
{
    return value.time.value <= 0xFFFFFFFFFFFFULL &&
           (value.errorCode < 128 || value.errorText.length() != 0) && ValidUTF8(value.errorText);
}

// Known MAL values prescribe exact tag lengths. Reserved/vendor algorithms remain
// opaque at the wire layer; algorithm selection belongs to the authentication engine.
bool IsValidAuthObject(const Group120Var5& value)
{
    static const size_t lengths[] = {0, 4, 10, 8, 16, 8, 12};
    return value.challengeData.length() >= 4 &&
           (value.macAlgorithm >= sizeof(lengths) / sizeof(lengths[0]) ||
            value.hmacValue.length() == lengths[value.macAlgorithm]);
}
bool IsValidAuthObject(const Group120Var6& value) { return value.keyWrapData.length() != 0; }
bool IsValidAuthObject(const Group120Var8& value) { return value.certificate.length() != 0; }
bool IsValidAuthObject(const Group120Var9& value) { return value.hmacValue.length() != 0; }
bool IsValidAuthObject(const Group120Var10& value)
{
    return value.userName.length() != 0 && value.certificationData.length() != 0 &&
           (value.keyChangeMethod >= 64 || value.userPublicKey.length() == 0);
}
bool IsValidAuthObject(const Group120Var11& value)
{
    return value.userName.length() != 0 &&
           (value.keyChangeMethod >= 64 || value.challengeData.length() >= 4);
}
bool IsValidAuthObject(const Group120Var12& value) { return value.challengeData.length() >= 4; }
bool IsValidAuthObject(const Group120Var13& value) { return value.encryptedUpdateKey.length() != 0; }
bool IsValidAuthObject(const Group120Var14& value) { return value.digitalSignature.length() != 0; }
bool IsValidAuthObject(const Group120Var15& value) { return value.hmacValue.length() != 0; }

ParseResult FreeFormatParser::Parse(ser4cpp::rseq_t& buffer, const HeaderRecord& record,
                                    const ParserSettings& settings, IAPDUHandler* handler)
{
    if (!settings.ExpectsContents()) return ParseResult::INVALID_OBJECT_QUALIFIER;
    switch (record.enumeration)
    {
    case GroupVariation::Group120Var1: return ParseObjects<Group120Var1>(buffer, record, handler);
    case GroupVariation::Group120Var2: return ParseObjects<Group120Var2>(buffer, record, handler);
    case GroupVariation::Group120Var5: return ParseObjects<Group120Var5>(buffer, record, handler);
    case GroupVariation::Group120Var6: return ParseObjects<Group120Var6>(buffer, record, handler);
    case GroupVariation::Group120Var8: return ParseObjects<Group120Var8>(buffer, record, handler);
    case GroupVariation::Group120Var9: return ParseObjects<Group120Var9>(buffer, record, handler);
    case GroupVariation::Group120Var10: return ParseObjects<Group120Var10>(buffer, record, handler);
    case GroupVariation::Group120Var11: return ParseObjects<Group120Var11>(buffer, record, handler);
    case GroupVariation::Group120Var12: return ParseObjects<Group120Var12>(buffer, record, handler);
    case GroupVariation::Group120Var13: return ParseObjects<Group120Var13>(buffer, record, handler);
    case GroupVariation::Group120Var14: return ParseObjects<Group120Var14>(buffer, record, handler);
    case GroupVariation::Group120Var15: return ParseObjects<Group120Var15>(buffer, record, handler);
    case GroupVariation::Group120Var7: return ParseObjects<Group120Var7>(buffer, record, handler);
    default: return ParseResult::INVALID_OBJECT_QUALIFIER;
    }
}
}
