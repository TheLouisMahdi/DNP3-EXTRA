// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_DEVICEATTRIBUTE_H
#define OPENDNP3_DEVICEATTRIBUTE_H

#include <ser4cpp/container/SequenceTypes.h>
#include <cstdint>

namespace opendnp3
{
// A borrowed IEEE 1815 section 5.5 type/length/value. Copy value bytes before
// returning from an SOE callback. The Indexed index is an attribute SET, not
// a security-statistic point index or an Association ID; set zero is standard.
struct DeviceAttribute
{
    uint8_t dataType = 2;
    ser4cpp::rseq_t value;

    // Preserve arbitrary UINTn on the wire; conversion fails without truncation
    // if the caller's uint64_t cannot represent the received value.
    bool GetUnsigned(uint64_t& result) const
    {
        if (dataType != 2 || value.is_empty()) return false;
        const uint8_t* bytes = value;
        uint64_t number = 0;
        for (size_t i = 0; i < value.length(); ++i)
        {
            if (i < 8) number |= uint64_t(bytes[i]) << (8 * i);
            else if (bytes[i]) return false;
        }
        result = number;
        return true;
    }

    bool IsValid(uint8_t variation) const
    {
        switch (variation)
        {
        case 255:
            return (value.length() % 2) == 0
                && ((dataType == 254 && value.length() <= 255)
                    || (dataType == 255 && value.length() >= 256 && value.length() <= 511));
        case 211:
            if (dataType == 254) return value.is_empty();
            if (value.is_empty()) return false;
            return IsVisibleString();
        case 242: case 243: case 245: case 246: case 247: case 248: case 249: case 250: case 252:
            return IsVisibleString();
        case 219: case 222: case 225: case 226: case 227: case 230: case 231: case 234: case 237:
            return dataType == 3 && value.length() > 0 && value.length() <= 255;
        default:
            return variation >= 209 && variation <= 241
                && dataType == 2 && value.length() > 0 && value.length() <= 255;
        }
    }

private:
    bool IsVisibleString() const
    {
        if (dataType != 1 || value.length() > 255) return false;
        const uint8_t* bytes = value;
        for (size_t i = 0; i < value.length(); ++i)
            if (bytes[i] < 0x20 || bytes[i] > 0x7E) return false;
        return true;
    }
};
} // namespace opendnp3
#endif
