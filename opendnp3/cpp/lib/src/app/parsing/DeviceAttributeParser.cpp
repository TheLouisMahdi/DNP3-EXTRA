// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "DeviceAttributeParser.h"
#include "app/parsing/BufferedCollection.h"
#include <ser4cpp/serialization/LittleEndian.h>

namespace opendnp3
{
namespace
{
bool Read(ser4cpp::rseq_t& input, uint8_t variation, DeviceAttribute& value)
{
    uint8_t length;
    if (!ser4cpp::UInt8::read_from(input, value.dataType)
        || !ser4cpp::UInt8::read_from(input, length)) return false;
    const size_t size = size_t(length) + (value.dataType == 255 ? 256 : 0);
    if (input.length() < size) return false;
    value.value = input.take(size);
    input.advance(size);
    return value.IsValid(variation);
}
}

ParseResult DeviceAttributeParser::Parse(ser4cpp::rseq_t& buffer, const HeaderRecord& record,
                                        uint16_t count, bool indexed, uint16_t start, IAPDUHandler* handler)
{
    auto input = buffer;
    for (uint16_t i = 0; i < count; ++i)
    {
        uint8_t index;
        DeviceAttribute value;
        if ((indexed && !ser4cpp::UInt8::read_from(input, index)) || !Read(input, record.variation, value))
            return ParseResult::INVALID_OBJECT;
    }
    if (handler)
    {
        auto read = [=](ser4cpp::rseq_t& data, uint32_t pos) -> Indexed<DeviceAttribute> {
            uint8_t index = 0;
            if (indexed) ser4cpp::UInt8::read_from(data, index);
            DeviceAttribute value;
            Read(data, record.variation, value);
            return WithIndex(value, indexed ? uint16_t(index) : uint16_t(start + pos));
        };
        auto values = CreateBufferedCollection<Indexed<DeviceAttribute>>(
            buffer.take(buffer.length() - input.length()), count, read);
        if (indexed) handler->OnHeader(PrefixHeader(record, count), values);
        else handler->OnHeader(RangeHeader(record, Range::From(start, uint16_t(start + count - 1))), values);
    }
    buffer = input;
    return ParseResult::OK;
}
} // namespace opendnp3
