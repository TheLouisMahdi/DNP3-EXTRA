// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_TEST_ASYMMETRICUPDATEKEYCREDENTIALS_H
#define OPENDNP3_TEST_ASYMMETRICUPDATEKEYCREDENTIALS_H
#include "dnp3mocks/RemoteUpdateKeyCredentials.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
namespace remote_update_test
{
struct AsymmetricMaterial
{
    std::array<uint8_t, 2048> authorityPrivate{}, userPrivate{}, outstationPrivate{};
    std::array<uint8_t, 1024> authorityPublic{}, userPublic{}, outstationPublic{};
    size_t authorityPrivateSize = 0, userPrivateSize = 0, outstationPrivateSize = 0;
    size_t authorityPublicSize = 0, userPublicSize = 0, outstationPublicSize = 0;
    using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using Context = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    static void Encode(EVP_PKEY* key, std::array<uint8_t, 2048>& secret, size_t& secretSize,
                       std::array<uint8_t, 1024>& publicKey, size_t& publicSize)
    {
        const auto a = i2d_PrivateKey(key, nullptr), b = i2d_PUBKEY(key, nullptr);
        REQUIRE(a > 0); REQUIRE(a <= secret.size()); REQUIRE(b > 0); REQUIRE(b <= publicKey.size());
        auto* p = secret.data(); auto* q = publicKey.data();
        REQUIRE(i2d_PrivateKey(key, &p) == a); REQUIRE(i2d_PUBKEY(key, &q) == b);
        secretSize = a; publicSize = b;
    }
    AsymmetricMaterial()
    {
        Context generator(EVP_PKEY_CTX_new_from_name(nullptr, "DSA", nullptr), EVP_PKEY_CTX_free);
        REQUIRE(generator); REQUIRE(EVP_PKEY_paramgen_init(generator.get()) > 0);
        unsigned pbits = 2048, qbits = 256;
        OSSL_PARAM params[] = {OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_FFC_PBITS, &pbits),
            OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_FFC_QBITS, &qbits), OSSL_PARAM_construct_end()};
        REQUIRE(EVP_PKEY_CTX_set_params(generator.get(), params) > 0);
        EVP_PKEY* raw = nullptr;
        REQUIRE(EVP_PKEY_paramgen(generator.get(), &raw) > 0);
        Key domain(raw, EVP_PKEY_free);
        Context keys(EVP_PKEY_CTX_new_from_pkey(nullptr, domain.get(), nullptr), EVP_PKEY_CTX_free);
        REQUIRE(keys); REQUIRE(EVP_PKEY_keygen_init(keys.get()) > 0);
        raw = nullptr; REQUIRE(EVP_PKEY_keygen(keys.get(), &raw) > 0);
        Key authority(raw, EVP_PKEY_free);
        Encode(authority.get(), authorityPrivate, authorityPrivateSize, authorityPublic, authorityPublicSize);
        raw = nullptr; REQUIRE(EVP_PKEY_keygen(keys.get(), &raw) > 0);
        Key user(raw, EVP_PKEY_free);
        Encode(user.get(), userPrivate, userPrivateSize, userPublic, userPublicSize);
        Context rsa(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
        REQUIRE(rsa); REQUIRE(EVP_PKEY_keygen_init(rsa.get()) > 0);
        REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(rsa.get(), 2048) > 0);
        raw = nullptr; REQUIRE(EVP_PKEY_keygen(rsa.get(), &raw) > 0);
        Key outstation(raw, EVP_PKEY_free);
        Encode(outstation.get(), outstationPrivate, outstationPrivateSize, outstationPublic, outstationPublicSize);
    }
    ~AsymmetricMaterial()
    {
        crypto::Clear(W(authorityPrivate)); crypto::Clear(W(userPrivate)); crypto::Clear(W(outstationPrivate));
    }
};
inline std::shared_ptr<AsymmetricMaterial> Method68Material()
{
    static auto material = std::make_shared<AsymmetricMaterial>();
    return material; // Test process only; never a production credential/default.
}
struct AsymmetricAuthority final : RemoteAuthority
{
    std::shared_ptr<AsymmetricMaterial> material = Method68Material();
    bool wrongAuthority = false, wrongUser = false, unavailable = false;
    AsymmetricAuthority() { method68 = true; }
    static bool Copy(uint16_t association, rseq_t input, uint8_t* output, size_t capacity, size_t& size)
    {
        size = 0;
        if (association != 7 || !output || capacity < input.length()) return false;
        std::memcpy(output, input, input.length()); size = input.length(); return true;
    }
    bool ReadAuthorityPublicKey(uint16_t a, uint8_t* o, size_t c, size_t& s) override
    { return !unavailable && Copy(a, wrongAuthority ? rseq_t(material->userPublic.data(), material->userPublicSize)
        : rseq_t(material->authorityPublic.data(), material->authorityPublicSize), o, c, s); }
    bool ReadOutstationPrivateKey(uint16_t a, uint8_t* o, size_t c, size_t& s) override
    { return !unavailable && Copy(a, {material->outstationPrivate.data(), material->outstationPrivateSize}, o, c, s); }
    bool GetAsymmetricKey(uint16_t a, const uint8_t*, size_t, uint8_t* key,
        uint8_t* secret, size_t capacity, size_t& size, uint8_t* pub, size_t pc, size_t& ps) override
    {
        if (unavailable || !Copy(a, wrongUser ? rseq_t(material->authorityPrivate.data(), material->authorityPrivateSize)
                : rseq_t(material->userPrivate.data(), material->userPrivateSize), secret, capacity, size)
            || !Copy(a, {material->outstationPublic.data(), material->outstationPublicSize}, pub, pc, ps)) return false;
        std::copy(nextKey.begin(), nextKey.end(), key); return true;
    }
    UpdateKeyRequest Status(uint8_t operation, uint32_t sequence, const std::string& name, uint16_t role = 1) override
    {
        UpdateKeyRequest result;
        REQUIRE(name.size() <= result.name.size());
        std::copy(name.begin(), name.end(), result.name.begin());
        result.nameSize = static_cast<uint16_t>(name.size()); result.method = 68;
        result.operation = operation; result.statusSequence = sequence; result.role = role; result.expiryDays = 5;
        result.publicKey = material->userPublic;
        result.publicKeySize = static_cast<uint16_t>(material->userPublicSize);
        Group120Var10 status(68, operation, sequence, role, result.expiryDays, {result.name.data(), result.nameSize},
            {result.publicKey.data(), result.publicKeySize}, {});
        std::array<uint8_t, 1200> transcript{};
        size_t size = 0, signedSize = 0;
        REQUIRE(updatekeys::CertificationData(status, W(transcript), size));
        REQUIRE(crypto::DSASHA256Sign({material->authorityPrivate.data(), material->authorityPrivateSize},
            {transcript.data(), size}, W(result.certification), signedSize) == crypto::Result::OK);
        result.certificationSize = static_cast<uint8_t>(signedSize);
        return result;
    }
};
}
#endif
