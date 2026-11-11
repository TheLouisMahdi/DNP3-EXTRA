// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "opendnp3/auth/WindowsAuthenticationCredentials.h"
#ifdef _WIN32
#include "crypto/CryptoProvider.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
// wincred.h requires the Windows base types above.
#include <wincred.h>

#include <cstring>
#include <memory>
#include <utility>
#include <array>
#include <ser4cpp/serialization/LittleEndian.h>

namespace opendnp3
{
namespace
{
    constexpr uint8_t legacyRecordMagic[] = {'D','N','P','3','U','K','0','1'};
    constexpr uint8_t previousRecordMagic[] = {'D','N','P','3','U','K','0','2'};
    constexpr uint8_t identityRecordMagic[] = {'D','N','P','3','U','K','0','3'};
    constexpr uint8_t recordMagic[] = {'D','N','P','3','U','K','0','4'};
    constexpr uint8_t commitMagic[] = {'D','N','P','3','U','C','0','1'};
    struct Blob
    {
        std::array<uint8_t, 2048> bytes{};
        size_t size = 0;
        ~Blob() { crypto::Clear({bytes.data(), bytes.size()}); }
        ser4cpp::rseq_t Read() const { return {bytes.data(), size}; }
        ser4cpp::wseq_t Write() { return {bytes.data(), bytes.size()}; }
    };
    bool ReadBlob(const std::wstring& target, Blob& output, bool& missing)
    {
        PCREDENTIALW value = nullptr;
        missing = false;
        if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &value))
        { missing = GetLastError() == ERROR_NOT_FOUND; return false; }
        const bool valid = value->CredentialBlob && value->CredentialBlobSize <= output.bytes.size();
        if (valid)
        {
            output.size = value->CredentialBlobSize;
            std::memcpy(output.bytes.data(), value->CredentialBlob, output.size);
        }
        if (value->CredentialBlob) SecureZeroMemory(value->CredentialBlob, value->CredentialBlobSize);
        CredFree(value);
        return valid;
    }
    bool WriteBlob(const std::wstring& target, ser4cpp::rseq_t blob)
    {
        CREDENTIALW value{};
        value.Type = CRED_TYPE_GENERIC;
        value.TargetName = const_cast<wchar_t*>(target.c_str());
        value.CredentialBlob = const_cast<uint8_t*>(static_cast<const uint8_t*>(blob));
        value.CredentialBlobSize = static_cast<DWORD>(blob.length());
        value.Persist = CRED_PERSIST_LOCAL_MACHINE;
        if (!CredWriteW(&value, 0)) return false;
        Blob verify;
        bool missing = false;
        return ReadBlob(target, verify, missing) && crypto::ConstantTimeEqual(blob, verify.Read());
    }
    constexpr size_t bindingSize = 32 + 20 + 8 + 8 + 1;
    void EncodeBinding(ser4cpp::wseq_t& dest, const UserCertificateBinding& binding)
    {
        dest.copy_from({binding.issuer.data(), binding.issuer.size()});
        dest.copy_from({binding.serial.data(), binding.serial.size()});
        ser4cpp::LittleEndian::write(dest, binding.beginsUnixMs, binding.expiresUnixMs, static_cast<uint8_t>(binding.revoked));
    }
    bool DecodeBinding(ser4cpp::rseq_t& input, UserCertificateBinding& binding)
    {
        std::memcpy(binding.issuer.data(), input, binding.issuer.size()); input.advance(binding.issuer.size());
        std::memcpy(binding.serial.data(), input, binding.serial.size()); input.advance(binding.serial.size());
        uint8_t revoked = 0;
        if (!ser4cpp::LittleEndian::read(input, binding.beginsUnixMs, binding.expiresUnixMs, revoked) || revoked > 1)
            return false;
        binding.revoked = revoked != 0;
        return binding.expiresUnixMs ? binding.beginsUnixMs < binding.expiresUnixMs : !binding.beginsUnixMs && !revoked;
    }
    bool Encode(const UpdateKeyUser& user, uint16_t association, uint64_t generation, Blob& output)
    {
        if (user.nameSize == 0 || user.nameSize > user.name.size() || user.certificationSize > user.certification.size()
            || user.publicKeySize > user.publicKey.size() || (user.method != 4 && user.method != 68)
            || user.certificateRevision > 256) return false;
        auto dest = output.Write();
        const bool certificate = user.certificateRevision < 256;
        const bool bindings = certificate && (user.identity.expiresUnixMs || user.pendingIdentity.expiresUnixMs
            || user.attribute.expiresUnixMs || user.pendingAttribute.expiresUnixMs || user.roleMask || user.pendingRoleMask);
        dest.copy_from({bindings ? recordMagic : (certificate ? identityRecordMagic : previousRecordMagic), sizeof(recordMagic)});
        const uint8_t flags = (user.active ? 1 : 0) | (user.pending ? 2 : 0)
            | (user.haveStatusSequence ? 4 : 0) | (user.havePendingKey ? 8 : 0);
        ser4cpp::LittleEndian::write(dest, generation, association, user.user, user.nameSize,
            user.statusSequence, flags, user.role, user.pendingRole, user.expiresUnixMs, user.pendingExpiresUnixMs,
            user.statusOperation, user.statusExpiryDays, user.certificationSize);
        dest.copy_from({user.certification.data(), user.certification.size()});
        dest.copy_from({user.certificationKeyFingerprint.data(), user.certificationKeyFingerprint.size()});
        dest.copy_from({user.name.data(), user.name.size()});
        dest.copy_from({user.updateKey.data(), user.updateKey.size()});
        dest.copy_from({user.pendingUpdateKey.data(), user.pendingUpdateKey.size()});
        ser4cpp::LittleEndian::write(dest, user.method, user.publicKeySize);
        dest.copy_from({user.publicKey.data(), user.publicKey.size()});
        if (certificate)
        {
            ser4cpp::UInt16::write_to(dest, user.certificateRevision);
            dest.copy_from({user.certificateSubject.data(), user.certificateSubject.size()});
        }
        if (bindings)
        {
            EncodeBinding(dest, user.identity);
            EncodeBinding(dest, user.pendingIdentity);
            EncodeBinding(dest, user.attribute);
            EncodeBinding(dest, user.pendingAttribute);
            ser4cpp::LittleEndian::write(dest, user.roleMask, user.pendingRoleMask);
        }
        output.size = output.bytes.size() - dest.length();
        return true;
    }
    bool Decode(ser4cpp::rseq_t input, uint16_t association, uint64_t generation, UpdateKeyUser& user)
    {
        UpdateKeyUser blank;
        blank.nameSize = 1;
        blank.certificateRevision = 0;
        Blob sizeCheck;
        Encode(blank, association, generation, sizeCheck);
        const bool legacy = input.length() == 291 && input.take(8).equals({legacyRecordMagic, sizeof(legacyRecordMagic)});
        const bool previous = input.length() == sizeCheck.size - 34
            && input.take(8).equals({previousRecordMagic, sizeof(previousRecordMagic)});
        const bool identity = input.length() == sizeCheck.size
            && input.take(8).equals({identityRecordMagic, sizeof(identityRecordMagic)});
        const bool bindings = input.length() == sizeCheck.size + 4 * bindingSize + 2
            && input.take(8).equals({recordMagic, sizeof(recordMagic)});
        if (!legacy && !previous && !identity && !bindings) return false;
        input.advance(8);
        uint64_t storedGeneration = 0;
        uint16_t storedAssociation = 0;
        uint8_t flags = 0;
        ser4cpp::LittleEndian::read(input, storedGeneration, storedAssociation, user.user, user.nameSize,
            user.statusSequence, flags, user.role, user.pendingRole, user.expiresUnixMs, user.pendingExpiresUnixMs,
            user.statusOperation, user.statusExpiryDays, user.certificationSize);
        if (storedGeneration != generation || storedAssociation != association || flags > 15
            || user.nameSize == 0 || user.nameSize > user.name.size()
            || user.certificationSize > (legacy ? 16u : user.certification.size())) return false;
        user.active = (flags & 1) != 0;
        user.pending = (flags & 2) != 0;
        user.haveStatusSequence = (flags & 4) != 0;
        user.havePendingKey = (flags & 8) != 0;
        const auto certificationSize = legacy ? 16u : user.certification.size();
        std::memcpy(user.certification.data(), input, certificationSize); input.advance(certificationSize);
        std::memcpy(user.certificationKeyFingerprint.data(), input, user.certificationKeyFingerprint.size()); input.advance(user.certificationKeyFingerprint.size());
        std::memcpy(user.name.data(), input, user.name.size()); input.advance(user.name.size());
        std::memcpy(user.updateKey.data(), input, user.updateKey.size()); input.advance(user.updateKey.size());
        std::memcpy(user.pendingUpdateKey.data(), input, user.pendingUpdateKey.size()); input.advance(user.pendingUpdateKey.size());
        if (!legacy)
        {
            ser4cpp::LittleEndian::read(input, user.method, user.publicKeySize);
            if (user.publicKeySize > user.publicKey.size() || (user.method != 4 && user.method != 68)) return false;
            std::memcpy(user.publicKey.data(), input, user.publicKey.size());
            input.advance(user.publicKey.size());
            if (!previous)
            {
                if (!ser4cpp::UInt16::read_from(input, user.certificateRevision)
                    || user.certificateRevision > 256) return false;
                std::memcpy(user.certificateSubject.data(), input, user.certificateSubject.size());
                input.advance(user.certificateSubject.size());
            }
        }
        if (bindings && (!DecodeBinding(input, user.identity) || !DecodeBinding(input, user.pendingIdentity)
            || !DecodeBinding(input, user.attribute) || !DecodeBinding(input, user.pendingAttribute)
            || !ser4cpp::LittleEndian::read(input, user.roleMask, user.pendingRoleMask)
            || user.roleMask > 0x7F || user.pendingRoleMask > 0x7F)) return false;
        return true;
    }
    bool Marker(ser4cpp::rseq_t marker, uint8_t& slot, uint64_t& generation, ser4cpp::rseq_t& hash)
    {
        if (marker.length() != 49 || !marker.take(8).equals({commitMagic, sizeof(commitMagic)})) return false;
        marker.advance(8);
        ser4cpp::LittleEndian::read(marker, slot, generation);
        hash = marker;
        return slot < 2 && generation != 0;
    }
}
WindowsAuthenticationCredentials::WindowsAuthenticationCredentials(std::wstring prefix,
    std::function<bool(uint64_t&)> clock)
    : targetPrefix(std::move(prefix)), trustedTime(std::move(clock))
{
}
bool WindowsAuthenticationCredentials::TrustedUnixTimeMs(uint64_t& now)
{
    now = 0;
    try { return trustedTime && trustedTime(now); } catch (...) { return false; }
}
bool WindowsAuthenticationCredentials::ReadUser(uint16_t association, size_t slot, UpdateKeyUser& user)
{
    std::lock_guard<std::mutex> lock(mutex);
    user = UpdateKeyUser();
    if (slot >= MAX_AUTHENTICATION_USERS || targetPrefix.empty()) return false;
    const auto target = targetPrefix + L"/" + std::to_wstring(association) + L"/" + std::to_wstring(slot + 1);
    Blob marker;
    bool missing = false;
    if (!ReadBlob(target, marker, missing)) return missing;
    uint8_t active = 0;
    uint64_t generation = 0;
    ser4cpp::rseq_t hash;
    if (!Marker(marker.Read(), active, generation, hash)) return false; // Explicit provisioning required for legacy blobs.
    Blob record;
    std::array<uint8_t, 32> digest{};
    if (!ReadBlob(target + L"/remote" + std::to_wstring(active), record, missing)
        || crypto::SHA256(record.Read(), {digest.data(), digest.size()}) != crypto::Result::OK
        || !crypto::ConstantTimeEqual({digest.data(), digest.size()}, hash)
        || !Decode(record.Read(), association, generation, user) || user.user != slot + 1)
    { user = UpdateKeyUser(); return false; }
    return true;
}
bool WindowsAuthenticationCredentials::WriteUser(uint16_t association, size_t slot, const UpdateKeyUser& user)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (slot >= MAX_AUTHENTICATION_USERS || user.user != slot + 1 || targetPrefix.empty()) return false;
    const auto target = targetPrefix + L"/" + std::to_wstring(association) + L"/" + std::to_wstring(slot + 1);
    Blob old;
    bool missing = false;
    uint8_t active = 1;
    uint64_t generation = 0;
    ser4cpp::rseq_t previousHash;
    if (ReadBlob(target, old, missing))
    {
        // An explicitly provisioned legacy key may be replaced, but a corrupt
        // remote marker requires administrative repair; never silently roll back.
        if (!Marker(old.Read(), active, generation, previousHash) && old.size != 16 && old.size != 32) return false;
    }
    else if (!missing) return false;
    if (generation == UINT64_MAX) return false;
    ++generation;
    active ^= 1;
    Blob record;
    std::array<uint8_t, 32> digest{};
    if (!Encode(user, association, generation, record)
        || crypto::SHA256(record.Read(), {digest.data(), digest.size()}) != crypto::Result::OK
        || !WriteBlob(target + L"/remote" + std::to_wstring(active), record.Read())) return false;
    Blob marker;
    auto dest = marker.Write();
    dest.copy_from({commitMagic, sizeof(commitMagic)});
    ser4cpp::LittleEndian::write(dest, active, generation);
    dest.copy_from({digest.data(), digest.size()});
    marker.size = marker.bytes.size() - dest.length();
    return WriteBlob(target, marker.Read());
}
bool WindowsAuthenticationCredentials::ReadUpdateKey(
    uint16_t association, uint16_t user, uint8_t* output, size_t capacity, uint64_t& validForMs)
{
    validForMs = 0;
    if (output)
        crypto::Clear(ser4cpp::wseq_t(output, capacity));
    if (!output || (capacity != 16 && capacity != 32) || targetPrefix.empty() || !user)
        return false;
    const auto target = targetPrefix + L"/" + std::to_wstring(association) + L"/" + std::to_wstring(user);
    PCREDENTIALW raw = nullptr;
    if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &raw))
        return false;
    struct FreeCredential
    {
        void operator()(CREDENTIALW* c) const
        {
            if (!c)
                return;
            if (c->CredentialBlob)
                SecureZeroMemory(c->CredentialBlob, c->CredentialBlobSize);
            CredFree(c);
        }
    };
    std::unique_ptr<CREDENTIALW, FreeCredential> credential(raw);
    if (credential->CredentialBlobSize == 49)
    {
        UpdateKeyUser record;
        uint64_t now = 0;
        if (capacity != 32 || !ReadUser(association, user - 1, record) || !record.active
            || !TrustedUnixTimeMs(now) || now >= record.expiresUnixMs) return false;
        std::memcpy(output, record.updateKey.data(), capacity);
        validForMs = record.expiresUnixMs - now;
        return true;
    }
    if (credential->CredentialBlobSize != capacity || !credential->CredentialBlob)
        return false;
    uint64_t expiry = 0;
    bool haveExpiry = false;
    for (DWORD n = 0; n < credential->AttributeCount; ++n)
    {
        const auto& attribute = credential->Attributes[n];
        if (attribute.Keyword && std::wcscmp(attribute.Keyword, L"DNP3_EXPIRES_UNIX_MS") == 0)
        {
            if (haveExpiry || attribute.ValueSize != 8 || !attribute.Value)
                return false;
            for (size_t j = 0; j < 8; ++j)
                expiry |= static_cast<uint64_t>(attribute.Value[j]) << (8 * j);
            haveExpiry = true;
        }
    }
    FILETIME time;
    GetSystemTimeAsFileTime(&time);
    ULARGE_INTEGER ticks;
    ticks.LowPart = time.dwLowDateTime;
    ticks.HighPart = time.dwHighDateTime;
    constexpr uint64_t unixEpoch = 116444736000000000ULL;
    if (!haveExpiry || ticks.QuadPart < unixEpoch)
        return false;
    const auto now = (ticks.QuadPart - unixEpoch) / 10000;
    if (expiry <= now)
        return false;
    std::memcpy(output, credential->CredentialBlob, capacity);
    validForMs = expiry - now;
    return true;
}
} // namespace opendnp3
#endif
