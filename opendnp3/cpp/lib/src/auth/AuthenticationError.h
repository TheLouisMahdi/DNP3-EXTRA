// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_AUTHENTICATIONERROR_H
#define OPENDNP3_AUTHENTICATIONERROR_H
#include "gen/objects/Group120.h"
namespace opendnp3
{
inline bool ValidAuthenticationError(const Group120Var7& error)
{
    if (!error.errorCode || error.errorCode == 2 || error.errorCode == 3
        || (error.errorCode >= 13 && error.errorCode < 128)
        || (error.errorCode >= 128 && error.errorText.is_empty()))
        return false;
    // A.45.7 / RFC 3629: reject overlong encodings, surrogates, out-of-range
    // scalar values and incomplete UTF-8. Empty standard-code text is allowed.
    auto text = error.errorText;
    if (text.length() && !static_cast<const uint8_t*>(text)) return false;
    while (!text.is_empty())
    {
        const auto lead = text[0];
        text = text.skip(1);
        if (lead < 0x80) continue;
        size_t count = 0;
        uint32_t scalar = 0, minimum = 0;
        if (lead >= 0xC2 && lead <= 0xDF) { count = 1; scalar = lead & 0x1F; minimum = 0x80; }
        else if (lead >= 0xE0 && lead <= 0xEF) { count = 2; scalar = lead & 0x0F; minimum = 0x800; }
        else if (lead >= 0xF0 && lead <= 0xF4) { count = 3; scalar = lead & 0x07; minimum = 0x10000; }
        else return false;
        if (text.length() < count) return false;
        for (size_t n = 0; n < count; ++n)
        {
            if ((text[0] & 0xC0) != 0x80) return false;
            scalar = (scalar << 6) | (text[0] & 0x3F);
            text = text.skip(1);
        }
        if (scalar < minimum || scalar > 0x10FFFF || (scalar >= 0xD800 && scalar <= 0xDFFF)) return false;
    }
    return true;
}
} // namespace opendnp3
#endif
