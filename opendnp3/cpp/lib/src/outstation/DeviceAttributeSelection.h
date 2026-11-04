// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_DEVICEATTRIBUTESELECTION_H
#define OPENDNP3_DEVICEATTRIBUTESELECTION_H

#include "app/HeaderWriter.h"
#include "opendnp3/app/IINField.h"

namespace opendnp3
{
// Bounded standard-attribute selection, owned by the native static response.
// No authentication state or independently configured capability constants.
class DeviceAttributeSelection
{
public:
    IINField Select(uint8_t variation, uint32_t statisticsPerAssociation);
    bool HasSelection() const { return selected || listSelected; }
    void Reset() { selected = 0; listSelected = false; }
    bool Load(HeaderWriter& writer);
private:
    uint32_t count = 0;
    uint8_t selected = 0;
    bool listSelected = false;
};
} // namespace opendnp3
#endif
