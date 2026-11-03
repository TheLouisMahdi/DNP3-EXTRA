// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_DEVICEATTRIBUTEPARSER_H
#define OPENDNP3_DEVICEATTRIBUTEPARSER_H

#include "app/parsing/IAPDUHandler.h"
#include "app/parsing/ParseResult.h"

namespace opendnp3
{
class DeviceAttributeParser
{
public:
    static ParseResult Parse(ser4cpp::rseq_t& buffer, const HeaderRecord& record,
                             uint16_t count, bool indexed, uint16_t start, IAPDUHandler* handler);
};
} // namespace opendnp3
#endif
