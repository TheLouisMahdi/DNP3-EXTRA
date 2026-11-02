// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_SECURITYSTAT_H
#define OPENDNP3_SECURITYSTAT_H

#include "opendnp3/app/Flags.h"

namespace opendnp3
{
// A reported value, never an independently incremented protocol counter.
struct SecurityStat
{
    SecurityStat() = default;
    SecurityStat(uint32_t value_, Flags flags_, uint16_t associationId_)
        : value(value_), flags(flags_), associationId(associationId_)
    {
    }

    uint32_t value = 0;
    Flags flags;
    uint16_t associationId = 0;
};
} // namespace opendnp3
#endif
