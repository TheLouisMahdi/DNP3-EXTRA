// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/FileObjects.h"
#include "app/parsing/DNPTimeParsing.h"
#include <ser4cpp/serialization/LittleEndian.h>

namespace opendnp3
{
namespace
{
using ser4cpp::LittleEndian;
using ser4cpp::rseq_t;
using ser4cpp::wseq_t;

constexpr uint16_t MAX_OBJECT = 65535;
constexpr uint16_t AUTH_FIXED = 12;
constexpr uint16_t COMMAND_FIXED = 26;
constexpr uint16_t COMMAND_STATUS_FIXED = 13;
constexpr uint16_t TRANSPORT_FIXED = 8;
constexpr uint16_t TRANSPORT_STATUS_FIXED = 9;
constexpr uint16_t DESCRIPTOR_FIXED = 20;
constexpr uint32_t LAST_BLOCK = 0x80000000u;

bool Fits(uint16_t fixed, const rseq_t& tail)
{
    return tail.length() <= static_cast<size_t>(MAX_OBJECT - fixed);
}
bool ContainsNoNul(const rseq_t& data)
{
    for (size_t i = 0; i < data.length(); ++i)
        if (!data[i]) return false;
    return true;
}
bool ValidPermissions(uint16_t permissions, DNPTime time)
{
    return (permissions & 0xFE00) == 0 && time.value <= 0xFFFFFFFFFFFFULL;
}
bool ReadName(const rseq_t& object, uint16_t fixed, uint16_t offset, uint16_t count, rseq_t& name)
{
    if (offset != fixed || object.length() != static_cast<size_t>(fixed) + count) return false;
    auto tail = object;
    tail.advance(fixed);
    name = tail;
    return ContainsNoNul(name);
}
bool ReadField(const rseq_t& object, uint16_t offset, uint16_t size, rseq_t& value)
{
    if (!size) return offset == 0 || (offset >= AUTH_FIXED && offset <= object.length());
    if (offset < AUTH_FIXED || offset > object.length() || size > object.length() - offset) return false;
    auto tail = object;
    tail.advance(offset);
    value = tail.take(size);
    return true;
}
bool InputFits(const rseq_t& input, uint16_t fixed)
{
    return input.length() >= fixed && input.length() <= MAX_OBJECT;
}
uint16_t Length(const rseq_t& field)
{
    return static_cast<uint16_t>(field.length());
}
} // namespace

size_t FileAuthentication::Size() const { return AUTH_FIXED + user.length() + password.length(); }
bool FileAuthentication::IsValid() const
{
    return Fits(AUTH_FIXED, user) && password.length() <= MAX_OBJECT - AUTH_FIXED - user.length()
        && ((!user.length() && !password.length()) || key == 0);
}
bool FileAuthentication::Read(const rseq_t& input)
{
    if (!InputFits(input, AUTH_FIXED)) return false;
    FileAuthentication value;
    uint16_t userOffset, userSize, passwordOffset, passwordSize;
    auto cursor = input;
    LittleEndian::read(cursor, userOffset, userSize, passwordOffset, passwordSize, value.key);
    if (!ReadField(input, userOffset, userSize, value.user)
        || !ReadField(input, passwordOffset, passwordSize, value.password)
        || input.length() != value.Size() || !value.IsValid()) return false;
    if (userSize && passwordSize
        && static_cast<uint32_t>(userOffset) + userSize > passwordOffset
        && static_cast<uint32_t>(passwordOffset) + passwordSize > userOffset) return false;
    // Authentication responses must not echo credential offsets or payloads.
    if (!userSize && !passwordSize && (userOffset || passwordOffset)) return false;
    *this = value;
    return true;
}
bool FileAuthentication::Write(wseq_t& output) const
{
    if (!IsValid() || output.length() < Size()) return false;
    const uint16_t userOffset = user.length() ? AUTH_FIXED : 0;
    const uint16_t passwordOffset = password.length() ? static_cast<uint16_t>(AUTH_FIXED + user.length()) : 0;
    LittleEndian::write(output, userOffset, Length(user), passwordOffset, Length(password), key);
    output.copy_from(user);
    output.copy_from(password);
    return true;
}

size_t FileCommand::Size() const { return COMMAND_FIXED + name.length(); }
bool FileCommand::IsValid() const
{
    return Fits(COMMAND_FIXED, name) && ContainsNoNul(name) && ValidPermissions(permissions, creationTime);
}
bool FileCommand::Read(const rseq_t& input)
{
    if (!InputFits(input, COMMAND_FIXED)) return false;
    FileCommand value;
    uint16_t offset, count;
    auto cursor = input;
    LittleEndian::read(cursor, offset, count, value.creationTime, value.permissions, value.key,
                       value.fileSize, value.mode, value.maxBlockSize, value.requestId);
    if (!ReadName(input, COMMAND_FIXED, offset, count, value.name) || !value.IsValid()) return false;
    *this = value;
    return true;
}
bool FileCommand::Write(wseq_t& output) const
{
    if (!IsValid() || output.length() < Size()) return false;
    LittleEndian::write(output, COMMAND_FIXED, Length(name), creationTime, permissions, key,
                        fileSize, mode, maxBlockSize, requestId);
    output.copy_from(name);
    return true;
}

size_t FileCommandStatus::Size() const { return COMMAND_STATUS_FIXED + text.length(); }
bool FileCommandStatus::IsValid() const { return Fits(COMMAND_STATUS_FIXED, text); }
bool FileCommandStatus::Read(const rseq_t& input)
{
    if (!InputFits(input, COMMAND_STATUS_FIXED)) return false;
    auto cursor = input;
    LittleEndian::read(cursor, handle, fileSize, maxBlockSize, requestId, status);
    text = cursor;
    return true;
}
bool FileCommandStatus::Write(wseq_t& output) const
{
    if (!IsValid() || output.length() < Size()) return false;
    LittleEndian::write(output, handle, fileSize, maxBlockSize, requestId, status);
    output.copy_from(text);
    return true;
}

size_t FileTransport::Size() const { return TRANSPORT_FIXED + data.length(); }
bool FileTransport::IsValid() const { return Fits(TRANSPORT_FIXED, data) && blockNumber < LAST_BLOCK; }
bool FileTransport::Read(const rseq_t& input)
{
    if (!InputFits(input, TRANSPORT_FIXED)) return false;
    auto cursor = input;
    uint32_t encoded;
    LittleEndian::read(cursor, handle, encoded);
    blockNumber = encoded & (LAST_BLOCK - 1);
    last = (encoded & LAST_BLOCK) != 0;
    data = cursor;
    return true;
}
bool FileTransport::Write(wseq_t& output) const
{
    if (!IsValid() || output.length() < Size()) return false;
    LittleEndian::write(output, handle, blockNumber | (last ? LAST_BLOCK : 0));
    output.copy_from(data);
    return true;
}

size_t FileTransportStatus::Size() const { return TRANSPORT_STATUS_FIXED + text.length(); }
bool FileTransportStatus::IsValid() const
{
    return Fits(TRANSPORT_STATUS_FIXED, text) && blockNumber < LAST_BLOCK;
}
bool FileTransportStatus::Read(const rseq_t& input)
{
    if (!InputFits(input, TRANSPORT_STATUS_FIXED)) return false;
    auto cursor = input;
    uint32_t encoded;
    LittleEndian::read(cursor, handle, encoded, status);
    blockNumber = encoded & (LAST_BLOCK - 1);
    last = (encoded & LAST_BLOCK) != 0;
    text = cursor;
    return true;
}
bool FileTransportStatus::Write(wseq_t& output) const
{
    if (!IsValid() || output.length() < Size()) return false;
    LittleEndian::write(output, handle, blockNumber | (last ? LAST_BLOCK : 0), status);
    output.copy_from(text);
    return true;
}

size_t FileDescriptor::Size() const { return DESCRIPTOR_FIXED + name.length(); }
bool FileDescriptor::IsValid() const
{
    return Fits(DESCRIPTOR_FIXED, name) && ContainsNoNul(name) && ValidPermissions(permissions, creationTime);
}
bool FileDescriptor::Read(const rseq_t& input)
{
    if (!InputFits(input, DESCRIPTOR_FIXED)) return false;
    FileDescriptor value;
    uint16_t offset, count;
    auto cursor = input;
    LittleEndian::read(cursor, offset, count, value.type, value.fileSize, value.creationTime,
                       value.permissions, value.requestId);
    if (!ReadName(input, DESCRIPTOR_FIXED, offset, count, value.name) || !value.IsValid()) return false;
    *this = value;
    return true;
}
bool FileDescriptor::Write(wseq_t& output) const
{
    if (!IsValid() || output.length() < Size()) return false;
    LittleEndian::write(output, DESCRIPTOR_FIXED, Length(name), type, fileSize, creationTime, permissions, requestId);
    output.copy_from(name);
    return true;
}

size_t FileSpecification::Size() const { return name.length(); }
bool FileSpecification::IsValid() const { return name.length() && Fits(0, name) && ContainsNoNul(name); }
bool FileSpecification::Read(const rseq_t& input)
{
    if (!InputFits(input, 1) || !ContainsNoNul(input)) return false;
    name = input;
    return true;
}
bool FileSpecification::Write(wseq_t& output) const
{
    if (!IsValid() || output.length() < Size()) return false;
    output.copy_from(name);
    return true;
}
} // namespace opendnp3
