// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_SECURITYSTAT_H
#define OPENDNP3_SECURITYSTAT_H

#include "opendnp3/app/Flags.h"
#include "opendnp3/app/DNPTime.h"

namespace opendnp3
{
// A reported value, never an independently incremented protocol counter.
struct SecurityStat
{
    SecurityStat() = default;
    SecurityStat(uint32_t value_, Flags flags_, uint16_t associationId_, DNPTime time_ = DNPTime())
        : value(value_), flags(flags_), associationId(associationId_), time(time_)
    {
    }

    uint32_t value = 0;
    Flags flags;
    uint16_t associationId = 0;
    DNPTime time;

    // UNSYNCHRONIZED still denotes an absolute clock, with uncertain accuracy.
    // INVALID denotes no meaningful occurrence time and must never be encoded as V2.
    bool HasTime() const
    {
        return (time.quality == TimestampQuality::SYNCHRONIZED || time.quality == TimestampQuality::UNSYNCHRONIZED)
            && time.value <= 0xFFFFFFFFFFFFULL;
    }
};
} // namespace opendnp3
#endif
