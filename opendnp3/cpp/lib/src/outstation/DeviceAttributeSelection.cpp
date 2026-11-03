// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "DeviceAttributeSelection.h"
#include <ser4cpp/serialization/LittleEndian.h>

namespace opendnp3
{
IINField DeviceAttributeSelection::Select(uint8_t variation, uint32_t statisticsPerAssociation)
{
    // G0V209 is deliberately unavailable: the current implementation does not
    // yet support a complete SA version. Never invent version zero or claim 5.
    if (variation == 209) return IINBit::OBJECT_UNKNOWN;
    if (variation == 210 || variation == 254)
    {
        count = statisticsPerAssociation;
        countSelected = true;
    }
    else if (variation == 255) listSelected = true;
    else return IINBit::OBJECT_UNKNOWN;
    return IINField::Empty();
}

bool DeviceAttributeSelection::Load(HeaderWriter& writer)
{
    if (countSelected)
    {
        uint8_t bytes[4];
        auto output = ser4cpp::wseq_t(bytes, sizeof(bytes));
        ser4cpp::UInt32::write_to(output, count);
        DeviceAttribute attribute;
        attribute.value = ser4cpp::rseq_t(bytes, count <= 0xFF ? 1 : count <= 0xFFFF ? 2 : 4);
        if (!writer.WriteAttribute(210, 0, attribute)) return false;
        countSelected = false;
    }
    if (listSelected)
    {
        const uint8_t list[] = {210, 0}; // V210 is read-only; omit unsupported SA and discovery variations.
        DeviceAttribute attribute;
        attribute.dataType = 254;
        attribute.value = ser4cpp::rseq_t(list, sizeof(list));
        if (!writer.WriteAttribute(255, 0, attribute, QualifierCode::UINT8_CNT_UINT8_INDEX)) return false;
        listSelected = false;
    }
    return true;
}
} // namespace opendnp3
