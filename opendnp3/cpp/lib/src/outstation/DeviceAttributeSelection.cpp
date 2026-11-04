// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "DeviceAttributeSelection.h"
#include <ser4cpp/serialization/LittleEndian.h>

namespace opendnp3
{
namespace
{
// Only attributes with a value known to this stack. Product data is not synthesized.
constexpr uint8_t supported[] = {210, 211, 212, 213, 214, 215, 230};
constexpr size_t supportedCount = sizeof(supported) / sizeof(supported[0]);
}

IINField DeviceAttributeSelection::Select(uint8_t variation, uint32_t statisticsPerAssociation)
{
    count = statisticsPerAssociation;
    if (variation == 254) selected = (1u << supportedCount) - 1;
    else if (variation == 255) listSelected = true;
    else
    {
        for (size_t i = 0; i < supportedCount; ++i)
        {
            if (variation != supported[i]) continue;
            selected |= 1u << i;
            return IINField::Empty();
        }
        // Includes G0V209: report no SA version until the complete protocol is verified.
        return IINBit::OBJECT_UNKNOWN;
    }
    return IINField::Empty();
}

bool DeviceAttributeSelection::Load(HeaderWriter& writer)
{
    for (size_t i = 0; i < supportedCount; ++i)
    {
        const auto mask = 1u << i;
        if (!(selected & mask)) continue;
        const auto variation = supported[i];
        uint8_t bytes[4] = {};
        DeviceAttribute attribute;
        if (variation == 210)
        {
            auto output = ser4cpp::wseq_t(bytes, sizeof(bytes));
            ser4cpp::UInt32::write_to(output, count);
            attribute.value = ser4cpp::rseq_t(bytes, count <= 0xFF ? 1 : count <= 0xFFFF ? 2 : 4);
        }
        else if (variation == 211)
            attribute.dataType = 254; // Annex A.1.3: empty list, no private attribute sets.
        else
        {
            attribute.dataType = variation == 230 ? 3 : 2;
            attribute.value = ser4cpp::rseq_t(bytes, 1);
        }
        if (!writer.WriteAttribute(variation, 0, attribute)) return false;
        selected &= ~mask;
    }
    if (listSelected)
    {
        uint8_t list[2 * supportedCount] = {};
        for (size_t i = 0; i < supportedCount; ++i) list[2 * i] = supported[i]; // All read-only.
        DeviceAttribute attribute;
        attribute.dataType = 254;
        attribute.value = ser4cpp::rseq_t(list, sizeof(list));
        if (!writer.WriteAttribute(255, 0, attribute, QualifierCode::UINT8_CNT_UINT8_INDEX)) return false;
        listSelected = false;
    }
    return true;
}
} // namespace opendnp3
