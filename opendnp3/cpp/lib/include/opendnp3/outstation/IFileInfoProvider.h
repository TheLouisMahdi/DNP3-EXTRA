// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_IFILEINFOPROVIDER_H
#define OPENDNP3_IFILEINFOPROVIDER_H

#include "opendnp3/app/DNPTime.h"
#include "opendnp3/link/Addresses.h"

#include <cstddef>

namespace opendnp3
{
struct FileInfo
{
    uint16_t type = 0; // 0: directory, 1: regular file
    uint32_t size = 0; // directory entry count or regular file size in bytes
    DNPTime creationTime;
    uint16_t permissions = 0;
};

class IFileInfoProvider
{
public:
    virtual ~IFileInfoProvider() = default;

    // Called synchronously on the authorized stack strand. Treat name as a
    // logical protocol name, not a trusted OS path. Expose allowlisted metadata
    // from bounded storage. False means missing or not exposed to this peer.
    // The name bytes are borrowed for this call only.
    virtual bool Lookup(const Addresses& peer, const uint8_t* name, size_t length, FileInfo& info) = 0;
};
} // namespace opendnp3

#endif
