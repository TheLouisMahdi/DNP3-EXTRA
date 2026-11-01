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

namespace opendnp3
{
WindowsAuthenticationCredentials::WindowsAuthenticationCredentials(std::wstring prefix)
    : targetPrefix(std::move(prefix))
{
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
