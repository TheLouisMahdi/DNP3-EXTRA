// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_FILEOBJECTS_H
#define OPENDNP3_FILEOBJECTS_H

#include "app/IVariableLength.h"
#include "gen/objects/Group70.h"
#include "opendnp3/app/DNPTime.h"

namespace opendnp3
{
// IEEE 1815-2012 Annex A.27.2–A.27.8. Variable byte fields borrow the
// object buffer. Copy only the fields needed after the parser callback.
template<class Id> struct FileWireObject : IVariableLength
{
    static GroupVariationID ID() { return Id::ID(); }
    GroupVariationID InstanceID() const override final { return ID(); }
};

struct FileAuthentication final : FileWireObject<Group70Var2>
{
    uint32_t key = 0;
    ser4cpp::rseq_t user, password;
    size_t Size() const override;
    bool Read(const ser4cpp::rseq_t&) override;
    bool Write(ser4cpp::wseq_t&) const override;
    bool IsValid() const;
};

struct FileCommand final : FileWireObject<Group70Var3>
{
    DNPTime creationTime;
    uint16_t permissions = 0;
    uint32_t key = 0, fileSize = 0;
    uint16_t mode = 0, maxBlockSize = 0, requestId = 0;
    ser4cpp::rseq_t name;
    size_t Size() const override;
    bool Read(const ser4cpp::rseq_t&) override;
    bool Write(ser4cpp::wseq_t&) const override;
    bool IsValid() const;
};

struct FileCommandStatus final : FileWireObject<Group70Var4>
{
    uint32_t handle = 0, fileSize = 0;
    uint16_t maxBlockSize = 0, requestId = 0;
    uint8_t status = 0;
    ser4cpp::rseq_t text;
    size_t Size() const override;
    bool Read(const ser4cpp::rseq_t&) override;
    bool Write(ser4cpp::wseq_t&) const override;
    bool IsValid() const;
};

struct FileTransport final : FileWireObject<Group70Var5>
{
    uint32_t handle = 0, blockNumber = 0;
    bool last = false;
    ser4cpp::rseq_t data;
    size_t Size() const override;
    bool Read(const ser4cpp::rseq_t&) override;
    bool Write(ser4cpp::wseq_t&) const override;
    bool IsValid() const;
};

struct FileTransportStatus final : FileWireObject<Group70Var6>
{
    uint32_t handle = 0, blockNumber = 0;
    bool last = false;
    uint8_t status = 0;
    ser4cpp::rseq_t text;
    size_t Size() const override;
    bool Read(const ser4cpp::rseq_t&) override;
    bool Write(ser4cpp::wseq_t&) const override;
    bool IsValid() const;
};

struct FileDescriptor final : FileWireObject<Group70Var7>
{
    uint16_t type = 0;
    uint32_t fileSize = 0;
    DNPTime creationTime;
    uint16_t permissions = 0, requestId = 0;
    ser4cpp::rseq_t name;
    size_t Size() const override;
    bool Read(const ser4cpp::rseq_t&) override;
    bool Write(ser4cpp::wseq_t&) const override;
    bool IsValid() const;
};

struct FileSpecification final : FileWireObject<Group70Var8>
{
    ser4cpp::rseq_t name;
    size_t Size() const override;
    bool Read(const ser4cpp::rseq_t&) override;
    bool Write(ser4cpp::wseq_t&) const override;
    bool IsValid() const;
};
// Select the file wire validator without adding file semantics to SA.
inline bool IsValidFreeFormatObject(const FileAuthentication& value) { return value.IsValid(); }
inline bool IsValidFreeFormatObject(const FileCommand& value) { return value.IsValid(); }
inline bool IsValidFreeFormatObject(const FileCommandStatus& value) { return value.IsValid(); }
inline bool IsValidFreeFormatObject(const FileTransport& value) { return value.IsValid(); }
inline bool IsValidFreeFormatObject(const FileTransportStatus& value) { return value.IsValid(); }
inline bool IsValidFreeFormatObject(const FileDescriptor& value) { return value.IsValid(); }
inline bool IsValidFreeFormatObject(const FileSpecification& value) { return value.IsValid(); }
} // namespace opendnp3

#endif
