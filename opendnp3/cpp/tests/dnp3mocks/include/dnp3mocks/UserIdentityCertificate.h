// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_TEST_USERIDENTITYCERTIFICATE_H
#define OPENDNP3_TEST_USERIDENTITYCERTIFICATE_H

#include "dnp3mocks/AsymmetricUpdateKeyCredentials.h"
#include <openssl/x509v3.h>
#include <ctime>

namespace remote_update_test
{
class IdentityCertificatePolicy final : public IUserCertificatePolicy
{
public:
    UserCertificateTrust trust;
    UserAttributeCertificateTrust attributeTrust;
    std::vector<uint8_t> subject;
    uint64_t pkiTime = 0;
    bool ReadPKIValidationTime(uint16_t association, uint64_t& utc) override
    {
        utc = pkiTime;
        return association == 7 && utc != 0;
    }
    bool ReadTrust(uint16_t association, UserCertificateTrust& result) override
    {
        if (association != 7) return false;
        result = trust;
        return true;
    }
    bool ReadAttributeTrust(uint16_t association, UserAttributeCertificateTrust& result) override
    {
        if (association != 7 || attributeTrust.authority.empty()) return false;
        result = attributeTrust;
        return true;
    }
    bool ResolveUser(uint16_t association, const uint8_t* name, size_t length,
                     uint8_t* output, size_t capacity, size_t& size) override
    {
        if (association != 7 || capacity < 1 || length != subject.size()
            || !std::equal(subject.begin(), subject.end(), name)) return false;
        output[0] = 'A';
        size = 1;
        return true;
    }
};

class SignedIdentity final
{
public:
    std::shared_ptr<IdentityCertificatePolicy> policy = std::make_shared<IdentityCertificatePolicy>();
    std::vector<uint8_t> der;
    static constexpr std::time_t epoch = 1700000000;

    explicit SignedIdentity(const AsymmetricMaterial& material, uint8_t scs = 1, uint8_t revision = 1,
                            uint8_t operation = 3, bool expired = false, bool revoked = false,
                            size_t extraBytes = 0)
    {
        const auto* issuerDER = material.authorityPrivate.data();
        const auto* userDER = material.userPrivate.data();
        AsymmetricMaterial::Key caKey(d2i_AutoPrivateKey(nullptr, &issuerDER, static_cast<long>(material.authorityPrivateSize)),
                                      EVP_PKEY_free);
        AsymmetricMaterial::Key userKey(d2i_AutoPrivateKey(nullptr, &userDER, static_cast<long>(material.userPrivateSize)),
                                        EVP_PKEY_free);
        REQUIRE(caKey);
        REQUIRE(userKey);
        auto ca = Certificate("Certificate authority", 1, caKey.get(), epoch + 86400);
        REQUIRE(X509_set_issuer_name(ca.get(), X509_get_subject_name(ca.get())) == 1);
        Extension(ca.get(), ca.get(), NID_basic_constraints, "critical,CA:TRUE");
        Extension(ca.get(), ca.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
        Extension(ca.get(), ca.get(), NID_subject_key_identifier, "hash");
        REQUIRE(X509_sign(ca.get(), caKey.get(), EVP_sha256()) > 0);

        auto leaf = Certificate("A", 2, userKey.get(), expired ? epoch - 10 : epoch + 7200);
        REQUIRE(X509_set_issuer_name(leaf.get(), X509_get_subject_name(ca.get())) == 1);
        Extension(leaf.get(), ca.get(), NID_basic_constraints, "critical,CA:FALSE");
        Extension(leaf.get(), ca.get(), NID_key_usage, "critical,digitalSignature");
        Extension(leaf.get(), ca.get(), NID_authority_key_identifier, "keyid:always");
        const uint8_t role[] = {0x30, 0x17, 0x30, 0x15, 0x30, 3, 2, 1, 1, 0x0C, 5, 'r','t','u','-','1',
                                2, 1, revision, 0x0A, 1, operation, 2, 1, scs};
        std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> oid(
            OBJ_txt2obj("1.2.840.10070.8.1", 1), ASN1_OBJECT_free);
        std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> data(
            ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free);
        REQUIRE(oid);
        REQUIRE(data);
        REQUIRE(ASN1_OCTET_STRING_set(data.get(), role, sizeof(role)) == 1);
        std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext(
            X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 0, data.get()), X509_EXTENSION_free);
        REQUIRE(ext);
        REQUIRE(X509_add_ext(leaf.get(), ext.get(), -1) == 1);
        if (extraBytes)
        {
            // An uninterpreted, noncritical extension makes a real signed
            // certificate span several transport segments and exceed 2048.
            std::vector<uint8_t> payload(extraBytes, 0xA5);
            REQUIRE(ASN1_OCTET_STRING_set(data.get(), payload.data(), static_cast<int>(payload.size())) == 1);
            const auto encoded = Encode(data.get(), i2d_ASN1_OCTET_STRING);
            REQUIRE(ASN1_OCTET_STRING_set(data.get(), encoded.data(), static_cast<int>(encoded.size())) == 1);
            oid.reset(OBJ_txt2obj("1.3.6.1.4.1.32473.1", 1));
            REQUIRE(oid);
            ext.reset(X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 0, data.get()));
            REQUIRE(ext);
            REQUIRE(X509_add_ext(leaf.get(), ext.get(), -1) == 1);
        }
        REQUIRE(X509_sign(leaf.get(), caKey.get(), EVP_sha256()) > 0);

        std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> crl(X509_CRL_new(), X509_CRL_free);
        std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> start(ASN1_TIME_set(nullptr, epoch - 120), ASN1_TIME_free);
        std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> end(ASN1_TIME_set(nullptr, epoch + 3600), ASN1_TIME_free);
        REQUIRE(crl);
        REQUIRE(start);
        REQUIRE(end);
        REQUIRE(X509_CRL_set_version(crl.get(), 1) == 1);
        REQUIRE(X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(ca.get())) == 1);
        REQUIRE(X509_CRL_set1_lastUpdate(crl.get(), start.get()) == 1);
        REQUIRE(X509_CRL_set1_nextUpdate(crl.get(), end.get()) == 1);
        if (revoked)
        {
            std::unique_ptr<X509_REVOKED, decltype(&X509_REVOKED_free)> entry(X509_REVOKED_new(), X509_REVOKED_free);
            REQUIRE(entry);
            REQUIRE(X509_REVOKED_set_serialNumber(entry.get(), X509_get_serialNumber(leaf.get())) == 1);
            REQUIRE(X509_REVOKED_set_revocationDate(entry.get(), start.get()) == 1);
            REQUIRE(X509_CRL_add0_revoked(crl.get(), entry.get()) == 1);
            entry.release();
            REQUIRE(X509_CRL_sort(crl.get()) == 1);
        }
        REQUIRE(X509_CRL_sign(crl.get(), caKey.get(), EVP_sha256()) > 0);
        policy->trust.authority = Encode(ca.get(), i2d_X509);
        policy->trust.revocationList = Encode(crl.get(), i2d_X509_CRL);
        policy->trust.areaOfResponsibility = "rtu-1";
        policy->subject = Encode(X509_get_subject_name(leaf.get()), i2d_X509_NAME);
        der = Encode(leaf.get(), i2d_X509);
    }

    UpdateKeyRequest Request(std::shared_ptr<IUpdateKeySource> source) const
    {
        UpdateKeyRequest request;
        request.method = 68;
        request.certificate = der;
        request.source = std::move(source);
        return request;
    }

private:
    friend class SignedAttribute;
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    static X509Ptr Certificate(const char* cn, long serial, EVP_PKEY* key, std::time_t expiry)
    {
        X509Ptr certificate(X509_new(), X509_free);
        REQUIRE(certificate);
        REQUIRE(X509_set_version(certificate.get(), 2) == 1);
        REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) == 1);
        REQUIRE(ASN1_TIME_set(X509_getm_notBefore(certificate.get()), epoch - 600));
        REQUIRE(ASN1_TIME_set(X509_getm_notAfter(certificate.get()), expiry));
        REQUIRE(X509_set_pubkey(certificate.get(), key) == 1);
        REQUIRE(X509_NAME_add_entry_by_txt(X509_get_subject_name(certificate.get()), "CN", MBSTRING_ASC,
                                          reinterpret_cast<const uint8_t*>(cn), -1, -1, 0) == 1);
        return certificate;
    }

    static void Extension(X509* certificate, X509* issuer, int nid, const char* value)
    {
        X509V3_CTX ctx;
        X509V3_set_ctx(&ctx, issuer, certificate, nullptr, nullptr, 0);
        std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension(
            X509V3_EXT_conf_nid(nullptr, &ctx, nid, value), X509_EXTENSION_free);
        REQUIRE(extension);
        REQUIRE(X509_add_ext(certificate, extension.get(), -1) == 1);
    }

    template<class T> static std::vector<uint8_t> Encode(const T* value, int (*encode)(const T*, uint8_t**))
    {
        const int size = encode(value, nullptr);
        REQUIRE(size > 0);
        std::vector<uint8_t> result(static_cast<size_t>(size));
        auto* out = result.data();
        REQUIRE(encode(value, &out) == size);
        return result;
    }
};

class SignedAttribute final
{
    using Bytes = std::vector<uint8_t>;
    static Bytes TLV(uint8_t tag, const Bytes& value)
    {
        Bytes output{tag};
        const auto size = value.size();
        REQUIRE(size <= MAX_USER_CERTIFICATE_SIZE);
        if (size < 128) output.push_back(static_cast<uint8_t>(size));
        else if (size < 256) output.insert(output.end(), {0x81, static_cast<uint8_t>(size)});
        else output.insert(output.end(), {0x82, static_cast<uint8_t>(size >> 8), static_cast<uint8_t>(size)});
        output.insert(output.end(), value.begin(), value.end());
        return output;
    }
    static Bytes Join(std::initializer_list<Bytes> items)
    {
        Bytes output;
        for (const auto& item : items) output.insert(output.end(), item.begin(), item.end());
        return output;
    }

public:
    Bytes der;
    Bytes revokedList;
    explicit SignedAttribute(const AsymmetricMaterial& material, SignedIdentity& identity,
                             uint8_t scs = 2, uint8_t revision = 2, uint8_t operation = 3,
                             uint8_t holderSerial = 2, bool expired = false, bool duplicate = false,
                             std::string area = "rtu-1")
    {
        auto& trust = identity.policy->attributeTrust;
        const uint8_t* keyData = material.authorityPrivate.data();
        AsymmetricMaterial::Key caKey(d2i_AutoPrivateKey(nullptr, &keyData, static_cast<long>(material.authorityPrivateSize)),
                                      EVP_PKEY_free);
        REQUIRE(caKey);
        AsymmetricMaterial::Context generator(EVP_PKEY_CTX_new_from_pkey(nullptr, caKey.get(), nullptr), EVP_PKEY_CTX_free);
        REQUIRE(generator);
        REQUIRE(EVP_PKEY_keygen_init(generator.get()) > 0);
        EVP_PKEY* raw = nullptr;
        REQUIRE(EVP_PKEY_keygen(generator.get(), &raw) > 0);
        AsymmetricMaterial::Key aaKey(raw, EVP_PKEY_free);
        const uint8_t* caDer = identity.policy->trust.authority.data();
        SignedIdentity::X509Ptr ca(d2i_X509(nullptr, &caDer, static_cast<long>(identity.policy->trust.authority.size())), X509_free);
        REQUIRE(ca);
        auto aa = SignedIdentity::Certificate("Attribute authority", 4, aaKey.get(), SignedIdentity::epoch + 86400);
        REQUIRE(X509_set_issuer_name(aa.get(), X509_get_subject_name(ca.get())) == 1);
        SignedIdentity::Extension(aa.get(), ca.get(), NID_basic_constraints, "critical,CA:FALSE");
        SignedIdentity::Extension(aa.get(), ca.get(), NID_key_usage, "critical,digitalSignature,cRLSign");
        SignedIdentity::Extension(aa.get(), ca.get(), NID_authority_key_identifier, "keyid:always");
        REQUIRE(X509_sign(aa.get(), caKey.get(), EVP_sha256()) > 0);
        trust.authority = SignedIdentity::Encode(aa.get(), i2d_X509);
        trust.issuer = identity.policy->trust.authority;
        trust.issuerRevocationList = identity.policy->trust.revocationList;

        auto makeCRL = [&](bool revoked) {
            std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> list(X509_CRL_new(), X509_CRL_free);
            std::unique_ptr<ISSUING_DIST_POINT, decltype(&ISSUING_DIST_POINT_free)> scope(
                ISSUING_DIST_POINT_new(), ISSUING_DIST_POINT_free);
            std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> start(ASN1_TIME_set(nullptr, SignedIdentity::epoch - 60), ASN1_TIME_free);
            std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> end(ASN1_TIME_set(nullptr, SignedIdentity::epoch + 60), ASN1_TIME_free);
            REQUIRE(list); REQUIRE(scope); REQUIRE(start); REQUIRE(end);
            scope->onlyattr = 0xFF;
            REQUIRE(X509_CRL_set_version(list.get(), 1) == 1);
            REQUIRE(X509_CRL_set_issuer_name(list.get(), X509_get_subject_name(aa.get())) == 1);
            REQUIRE(X509_CRL_set1_lastUpdate(list.get(), start.get()) == 1);
            REQUIRE(X509_CRL_set1_nextUpdate(list.get(), end.get()) == 1);
            REQUIRE(X509_CRL_add1_ext_i2d(list.get(), NID_issuing_distribution_point, scope.get(), 1, 0) == 1);
            if (revoked)
            {
                std::unique_ptr<X509_REVOKED, decltype(&X509_REVOKED_free)> entry(X509_REVOKED_new(), X509_REVOKED_free);
                std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)> serial(ASN1_INTEGER_new(), ASN1_INTEGER_free);
                REQUIRE(entry); REQUIRE(serial);
                REQUIRE(ASN1_INTEGER_set(serial.get(), scs) == 1);
                REQUIRE(X509_REVOKED_set_serialNumber(entry.get(), serial.get()) == 1);
                REQUIRE(X509_REVOKED_set_revocationDate(entry.get(), start.get()) == 1);
                REQUIRE(X509_CRL_add0_revoked(list.get(), entry.get()) == 1);
                entry.release();
            }
            REQUIRE(X509_CRL_sign(list.get(), aaKey.get(), EVP_sha256()) > 0);
            return SignedIdentity::Encode(list.get(), i2d_X509_CRL);
        };
        trust.revocationList = makeCRL(false);
        revokedList = makeCRL(true);
        auto name = [](X509* certificate) {
            return TLV(0xA4, SignedIdentity::Encode(X509_get_subject_name(certificate), i2d_X509_NAME));
        };
        auto time = [](std::time_t date) {
            std::unique_ptr<ASN1_GENERALIZEDTIME, decltype(&ASN1_GENERALIZEDTIME_free)> utc(
                ASN1_GENERALIZEDTIME_set(nullptr, date), ASN1_GENERALIZEDTIME_free);
            REQUIRE(utc);
            return SignedIdentity::Encode(utc.get(), i2d_ASN1_GENERALIZEDTIME);
        };
        const auto holder = TLV(0x30, TLV(0xA0, Join({TLV(0x30, name(ca.get())), TLV(2, {holderSerial})})));
        const auto issuer = TLV(0xA0, TLV(0x30, name(aa.get())));
        const auto algorithm = TLV(0x30, {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x02});
        const auto period = TLV(0x30, Join({time(SignedIdentity::epoch - 120), time(SignedIdentity::epoch + (expired ? -1 : 600))}));
        const auto attribute = TLV(0x30, Join({{0x06,3,0x55,0x04,3}, TLV(0x31, TLV(0x0C, {'A'}))}));
        const auto attributes = TLV(0x30, duplicate ? Join({attribute, attribute}) : attribute);
        const auto roles = TLV(0x30, TLV(0x30, Join({TLV(0x30, Join({TLV(2, {0}), TLV(2, {2})})),
            TLV(0x0C, Bytes(area.begin(), area.end())), TLV(2, {revision}), TLV(0x0A, {operation}), TLV(2, {scs})})));
        const auto extension = TLV(0x30, TLV(0x30, Join({{0x06,7,0x2A,0x86,0x48,0xCE,0x56,0x08,0x01}, TLV(4, roles)})));
        const auto info = TLV(0x30, Join({TLV(2, {1}), holder, issuer, algorithm, TLV(2, {scs}), period, attributes, extension}));
        std::array<uint8_t, 2048> privateKey{};
        std::array<uint8_t, 1024> publicKey{};
        size_t privateSize = 0, publicSize = 0, size = 0;
        AsymmetricMaterial::Encode(aaKey.get(), privateKey, privateSize, publicKey, publicSize);
        std::array<uint8_t, 72> signature{};
        const auto result = crypto::DSASHA256Sign({privateKey.data(), privateSize}, {info.data(), info.size()}, W(signature), size);
        crypto::Clear(W(privateKey));
        REQUIRE(result == crypto::Result::OK);
        Bytes bits{0};
        bits.insert(bits.end(), signature.begin(), signature.begin() + size);
        der = TLV(0x30, Join({info, algorithm, TLV(3, bits)}));
    }

    UpdateKeyRequest Request(std::shared_ptr<IUpdateKeySource> source) const
    {
        UpdateKeyRequest request;
        request.method = 68;
        request.certificateType = 2;
        request.certificate = der;
        request.source = std::move(source);
        return request;
    }
};
}
#endif
