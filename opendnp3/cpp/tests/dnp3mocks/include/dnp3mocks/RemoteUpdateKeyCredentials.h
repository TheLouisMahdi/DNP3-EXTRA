// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_TEST_REMOTEUPDATEKEYCREDENTIALS_H
#define OPENDNP3_TEST_REMOTEUPDATEKEYCREDENTIALS_H
#include "auth/UpdateKeyFunctions.h"
#include "crypto/CryptoProvider.h"
#include "opendnp3/auth/UpdateKeyConfig.h"
#include <catch.hpp>
#include <algorithm>
#include <array>
#include <string>
#include <cstring>
namespace remote_update_test
{
using namespace opendnp3;
using ser4cpp::rseq_t;
using ser4cpp::wseq_t;
template<size_t N> rseq_t R(const std::array<uint8_t, N>& a) { return {a.data(), a.size()}; }
template<size_t N> wseq_t W(std::array<uint8_t, N>& a) { return {a.data(), a.size()}; }
struct RemoteCredentials final : IUpdateKeyCredentials
{
    std::array<UpdateKeyUser, 16> users{};
    uint64_t utc = 1700000000000ULL;
    bool trustedTime = true, failWrite = false;
    size_t writes = 0;
    size_t attempts = 0, failOnWrite = 0;
    bool uncertainWrite = false;
    RemoteCredentials()
    {
        const uint8_t common[] = {'C','o','m','m','o','n',0};
        std::copy(std::begin(common), std::end(common), users[0].name.begin());
        users[0].nameSize = sizeof(common);
        users[1].name[0] = 'A';
        users[1].nameSize = 1;
        for (size_t n = 0; n < 2; ++n)
        {
            users[n].user = static_cast<uint16_t>(n + 1);
            users[n].active = true;
            users[n].role = n == 0 ? 0 : 1;
            users[n].expiresUnixMs = utc + 864000000;
            users[n].updateKey.fill(static_cast<uint8_t>(n + 1));
        }
    }
    bool ReadUpdateKey(uint16_t association, uint16_t user, uint8_t* out, size_t size, uint64_t& duration) override
    {
        if (association != 7 || !user || user > users.size() || size != 32 || !users[user-1].active) return false;
        std::copy(users[user-1].updateKey.begin(), users[user-1].updateKey.end(), out);
        duration = users[user-1].expiresUnixMs - utc;
        return true;
    }
    bool TrustedUnixTimeMs(uint64_t& value) override { value = utc; return trustedTime; }
    bool ReadUser(uint16_t association, size_t slot, UpdateKeyUser& value) override
    {
        if (association != 7 || slot >= users.size()) return false;
        value = users[slot];
        return true;
    }
    bool WriteUser(uint16_t association, size_t slot, const UpdateKeyUser& value) override
    {
        if (failWrite || association != 7 || slot >= users.size()) return false;
        const bool fail = ++attempts == failOnWrite;
        if (fail && !uncertainWrite) return false;
        users[slot] = value;
        ++writes;
        return !fail;
    }
};
struct RemotePolicy final : IAuthenticationAuthorization
{
    bool allow = true;
    bool IsAuthorized(uint16_t association, uint16_t, uint8_t, const uint8_t*, size_t) const override
    { return association == 7 && allow; }
};
// Test-only authority. Production Master interfaces expose no Certification Key.
struct RemoteAuthority final : IUpdateKeyTrust, IUpdateKeySource
{
    std::array<uint8_t, 32> certificationKey{}, nextKey{};
    bool corruptCiphertext = false;
    RemoteAuthority() { certificationKey.fill(0x55); nextKey.fill(0x66); }
    ~RemoteAuthority() { crypto::Clear(W(certificationKey)); crypto::Clear(W(nextKey)); }
    bool ReadCertificationKey(uint16_t association, uint8_t* output, size_t capacity) override
    {
        if (association != 7 || capacity != certificationKey.size()) return false;
        std::copy(certificationKey.begin(), certificationKey.end(), output);
        return true;
    }
    bool GetKey(uint16_t association, const uint8_t* name, size_t nameSize, const uint8_t*,
                const uint8_t* challenge, uint32_t, uint16_t, uint8_t* key, uint8_t* encrypted,
                size_t capacity, size_t& size) override
    {
        if (association != 7) return false;
        std::array<uint8_t, 200> plain{};
        size_t plainSize = 0;
        if (!updatekeys::KeyData({name, nameSize}, R(nextKey), {challenge, 32}, W(plain), plainSize)
            || capacity < plainSize + 8) return false;
        size = plainSize + 8;
        const bool wrapped = crypto::AES256KeyWrap(R(certificationKey), {plain.data(), plainSize}, {encrypted, size}) == crypto::Result::OK;
        crypto::Clear(W(plain));
        if (!wrapped) return false;
        std::copy(nextKey.begin(), nextKey.end(), key);
        if (corruptCiphertext) encrypted[0] ^= 1;
        return true;
    }
    UpdateKeyRequest Status(uint8_t operation, uint32_t sequence, const std::string& name, uint16_t role = 1)
    {
        UpdateKeyRequest result;
        REQUIRE(name.size() <= result.name.size());
        std::copy(name.begin(), name.end(), result.name.begin());
        result.nameSize = static_cast<uint16_t>(name.size());
        result.operation = operation;
        result.statusSequence = sequence;
        result.role = role;
        result.expiryDays = 5;
        result.certificationSize = 16;
        Group120Var10 status(4, operation, sequence, role, result.expiryDays,
            {result.name.data(), result.nameSize}, {}, {});
        std::array<uint8_t, 256> message{};
        size_t size = 0;
        REQUIRE(updatekeys::CertificationData(status, W(message), size));
        REQUIRE(crypto::ComputeHMACSHA256(R(certificationKey), {message.data(), size}, W(result.certification)) == crypto::Result::OK);
        return result;
    }
};
AuthenticationConfig RemoteSettings(const std::shared_ptr<RemoteCredentials>& credentials,
                                    const std::shared_ptr<RemotePolicy>& policy,
                                    const std::shared_ptr<RemoteAuthority>& authority, size_t capacity)
{
    AuthenticationConfig config;
    config.association = 7;
    config.credentials = credentials;
    config.authorization = policy;
    config.remoteUpdateKeys = true;
    config.userCapacity = static_cast<uint16_t>(capacity);
    config.outstationName[0] = 'B';
    config.outstationNameSize = 1;
    config.updateKeyTrust = authority;
    return config;
}
}
#endif
