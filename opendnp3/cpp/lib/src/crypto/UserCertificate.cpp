// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "UserCertificate.h"
#include "CryptoProvider.h"
#include "auth/UpdateKeyFunctions.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <ctime>
#include <limits>
#include <set>
#include <tuple>

namespace opendnp3
{
namespace crypto
{
namespace
{
using ser4cpp::rseq_t;
using ser4cpp::wseq_t;
template<class T, void (*Free)(T*)> using OpenSSLPtr = std::unique_ptr<T, decltype(Free)>;

// The bounded IECUserRoles extension uses definite-length DER with primitive
// INTEGER, ENUMERATED and UTF8String values.
bool ReadValue(rseq_t& input, uint8_t tag, rseq_t& value)
{
    if (input.length() < 2 || input[0] != tag) return false;
    size_t length = input[1];
    input.advance(2);
    if (length & 0x80)
    {
        const auto octets = length & 0x7F;
        if (!octets || octets > 2 || input.length() < octets || input[0] == 0) return false;
        length = 0;
        for (size_t i = 0; i < octets; ++i) length = (length << 8) | input[i];
        if (length < 128) return false;
        input.advance(octets);
    }
    if (length > input.length()) return false;
    value = input.take(length);
    input.advance(length);
    return true;
}

bool ReadNumber(rseq_t& input, uint8_t tag, uint32_t& number)
{
    rseq_t bytes;
    if (!ReadValue(input, tag, bytes) || bytes.is_empty() || bytes.length() > 5
        || (bytes[0] & 0x80) || (bytes.length() > 1 && !bytes[0] && !(bytes[1] & 0x80))
        || (bytes.length() == 5 && bytes[0])) return false;
    number = 0;
    for (size_t i = 0; i < bytes.length(); ++i) number = (number << 8) | bytes[i];
    return true;
}

bool ReadRoles(rseq_t input, const std::string& aor, UserCertificate& result)
{
    if (aor.empty() || aor.size() > 64) return false;
    rseq_t entries;
    if (!ReadValue(input, 0x30, entries) || input.is_not_empty()) return false;
    const uint8_t roleDefinition[] = {'I','E','C','6','2','3','5','1','-','8'};
    const rseq_t selectedArea(reinterpret_cast<const uint8_t*>(aor.data()), aor.size());
    while (entries.is_not_empty())
    {
        rseq_t entry, roles, area, definition;
        uint32_t revision = 0, operation = 0, scs = 0;
        if (!ReadValue(entries, 0x30, entry) || !ReadValue(entry, 0x30, roles) || roles.is_empty()
            || !ReadValue(entry, 0x0C, area) || area.is_empty() || area.length() > 64
            || !ReadNumber(entry, 0x02, revision) || revision > 255) return false;
        if (entry.is_not_empty() && entry[0] == 0x0C
            && (!ReadValue(entry, 0x0C, definition) || !definition.equals({roleDefinition, sizeof(roleDefinition)})))
            return false;
        if (!ReadNumber(entry, 0x0A, operation) || operation < 1 || operation > 3
            || !ReadNumber(entry, 0x02, scs) || entry.is_not_empty()) return false;
        uint8_t mask = 0;
        uint32_t first = 0;
        while (roles.is_not_empty())
        {
            uint32_t role = 0;
            if (!ReadNumber(roles, 0x02, role) || role > 6 || (mask & (1u << role))) return false;
            if (!mask) first = role;
            mask |= static_cast<uint8_t>(1u << role);
        }
        if (!area.equals(selectedArea)) continue;
        auto& status = result.status;
        if (status.certificateRoleMask && (status.operation != operation || result.revision != revision
            || status.statusSequence != scs || (status.certificateRoleMask & mask))) return false;
        if (!status.certificateRoleMask) status.role = static_cast<uint16_t>(first);
        status.certificateRoleMask |= mask;
        status.operation = static_cast<uint8_t>(operation);
        status.statusSequence = scs;
        result.revision = static_cast<uint8_t>(revision);
    }
    return result.status.certificateRoleMask != 0;
}

bool ReadRolesExtension(X509_EXTENSION* extension, const std::string& aor, UserCertificate& result)
{
    if (!extension || X509_EXTENSION_get_critical(extension)) return false;
    const auto* data = X509_EXTENSION_get_data(extension);
    const auto size = ASN1_STRING_length(data);
    return size > 0 && ReadRoles({ASN1_STRING_get0_data(data), static_cast<size_t>(size)}, aor, result);
}

bool ReadRole(X509* certificate, const std::string& aor, UserCertificate& result)
{
    OpenSSLPtr<ASN1_OBJECT, ASN1_OBJECT_free> oid(OBJ_txt2obj("1.2.840.10070.8.1", 1), ASN1_OBJECT_free);
    if (!oid) return false;
    const int position = X509_get_ext_by_OBJ(certificate, oid.get(), -1);
    return position >= 0 && X509_get_ext_by_OBJ(certificate, oid.get(), position) < 0
        && ReadRolesExtension(X509_get_ext(certificate, position), aor, result);
}

bool ToUnixMilliseconds(const ASN1_TIME* time, uint64_t& value)
{
    if (!time) return false;
    OpenSSLPtr<ASN1_TIME, ASN1_TIME_free> epoch(ASN1_TIME_set(nullptr, 0), ASN1_TIME_free);
    int days = 0, seconds = 0;
    if (!epoch || ASN1_TIME_diff(&days, &seconds, epoch.get(), time) != 1 || days < 0 || seconds < 0) return false;
    value = (uint64_t(days) * 86400 + seconds) * 1000;
    return true;
}

bool WithinThreeYears(const ASN1_TIME* notBefore, const ASN1_TIME* notAfter)
{
    std::tm from{}, to{};
    if (!ASN1_TIME_to_tm(notBefore, &from) || !ASN1_TIME_to_tm(notAfter, &to)) return false;
    from.tm_year += 3;
    if (from.tm_mon == 1 && from.tm_mday == 29) from.tm_mday = 28;
    const auto key = [](const std::tm& t) {
        return std::make_tuple(t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
    };
    return key(to) <= key(from);
}

OpenSSLPtr<X509, X509_free> ReadCertificate(rseq_t der)
{
    if (der.is_empty() || der.length() > MAX_USER_CERTIFICATE_SIZE) return {nullptr, X509_free};
    const uint8_t* cursor = der;
    const auto* end = cursor + der.length();
    OpenSSLPtr<X509, X509_free> result(d2i_X509(nullptr, &cursor, static_cast<long>(der.length())), X509_free);
    if (cursor != end) result.reset();
    return result;
}

bool ReadSerial(rseq_t bytes, std::array<uint8_t, 20>& serial)
{
    if (bytes.is_empty() || bytes.length() > serial.size() || (bytes[0] & 0x80)
        || (bytes[0] == 0 && (bytes.length() == 1 || !(bytes[1] & 0x80)))) return false;
    std::memcpy(serial.data() + serial.size() - bytes.length(), bytes, bytes.length());
    return true;
}

bool ReadSerial(const ASN1_INTEGER* integer, std::array<uint8_t, 20>& serial)
{
    std::array<uint8_t, 22> der{};
    const int size = i2d_ASN1_INTEGER(integer, nullptr);
    auto* ptr = der.data();
    if (size < 3 || static_cast<size_t>(size) > der.size() || i2d_ASN1_INTEGER(integer, &ptr) != size) return false;
    return ReadSerial({der.data() + 2, static_cast<size_t>(size - 2)}, serial);
}

OpenSSLPtr<X509_CRL, X509_CRL_free> ReadCRL(const std::vector<uint8_t>& bytes, uint64_t utc)
{
    if (bytes.empty() || bytes.size() > 1024 * 1024) return {nullptr, X509_CRL_free};
    const uint8_t* cursor = bytes.data();
    OpenSSLPtr<X509_CRL, X509_CRL_free> crl(d2i_X509_CRL(nullptr, &cursor, static_cast<long>(bytes.size())), X509_CRL_free);
    uint64_t begin = 0, end = 0;
    if (!crl || cursor != bytes.data() + bytes.size()
        || !ToUnixMilliseconds(X509_CRL_get0_lastUpdate(crl.get()), begin)
        || !ToUnixMilliseconds(X509_CRL_get0_nextUpdate(crl.get()), end)
        || utc < begin || utc >= end) crl.reset();
    return crl;
}

bool VerifyPKC(X509* certificate, X509* authority, X509_CRL* crl, uint64_t utc, bool checkLeafTime = true)
{
    if (!crl || !authority || !X509_check_ca(authority)
        || utc / 1000 > static_cast<uint64_t>(std::numeric_limits<std::time_t>::max())) return false;
    OpenSSLPtr<X509_STORE, X509_STORE_free> store(X509_STORE_new(), X509_STORE_free);
    OpenSSLPtr<X509_STORE_CTX, X509_STORE_CTX_free> ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    if (!store || !ctx || X509_STORE_add_cert(store.get(), authority) != 1
        || X509_STORE_add_crl(store.get(), crl) != 1
        || X509_STORE_CTX_init(ctx.get(), store.get(), certificate, nullptr) != 1) return false;
    auto* param = X509_STORE_CTX_get0_param(ctx.get());
    if (X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT | X509_V_FLAG_CRL_CHECK) != 1) return false;
    X509_VERIFY_PARAM_set_time(param, static_cast<std::time_t>(utc / 1000));
    if (!checkLeafTime)
    {
        X509_STORE_CTX_set_verify_cb(ctx.get(), [](int ok, X509_STORE_CTX* context) {
            if (ok || X509_STORE_CTX_get_error_depth(context) != 0) return ok;
            const auto error = X509_STORE_CTX_get_error(context);
            if (error != X509_V_ERR_CERT_NOT_YET_VALID && error != X509_V_ERR_CERT_HAS_EXPIRED) return 0;
            X509_STORE_CTX_set_error(context, X509_V_OK);
            return 1;
        });
    }
    return X509_verify_cert(ctx.get()) == 1;
}

bool Fingerprint(const std::vector<uint8_t>& der, std::array<uint8_t, 32>& out)
{
    return SHA256({der.data(), der.size()}, {out.data(), out.size()}) == Result::OK;
}

CertificateBindingResult CheckSerial(X509_CRL* crl, X509* signer, const std::array<uint8_t, 20>& serial, bool attribute)
{
    constexpr auto invalid = CertificateBindingResult::INVALID;
    if (!crl || !signer || X509_CRL_get_version(crl) != 1
        || !(X509_get_key_usage(signer) & KU_CRL_SIGN)
        || X509_NAME_cmp(X509_CRL_get_issuer(crl), X509_get_subject_name(signer)) != 0
        || X509_CRL_verify(crl, X509_get0_pubkey(signer)) != 1
        || X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) >= 0) return invalid;
    int critical = -1;
    OpenSSLPtr<ISSUING_DIST_POINT, ISSUING_DIST_POINT_free> scope(
        static_cast<ISSUING_DIST_POINT*>(X509_CRL_get_ext_d2i(crl, NID_issuing_distribution_point, &critical, nullptr)),
        ISSUING_DIST_POINT_free);
    if (critical == -2 || (critical >= 0 && !scope) || (attribute && (!scope || !critical || !scope->onlyattr))
        || (scope && (scope->distpoint || scope->onlyCA || scope->indirectCRL || scope->onlysomereasons
                     || (attribute ? scope->onlyuser : scope->onlyattr)))) return invalid;
    for (int i = 0; i < X509_CRL_get_ext_count(crl); ++i)
    {
        auto* ext = X509_CRL_get_ext(crl, i);
        if (X509_EXTENSION_get_critical(ext)
            && OBJ_obj2nid(X509_EXTENSION_get_object(ext)) != NID_issuing_distribution_point) return invalid;
    }
    auto* revoked = X509_CRL_get_REVOKED(crl);
    bool listed = false;
    for (int i = 0; i < sk_X509_REVOKED_num(revoked); ++i)
    {
        auto* entry = sk_X509_REVOKED_value(revoked, i);
        std::array<uint8_t, 20> value{};
        if (!ReadSerial(X509_REVOKED_get0_serialNumber(entry), value)) return invalid;
        if (value == serial) listed = true;
        for (int n = 0; n < X509_REVOKED_get_ext_count(entry); ++n)
            if (X509_EXTENSION_get_critical(X509_REVOKED_get_ext(entry, n))) return invalid;
    }
    return listed ? CertificateBindingResult::REVOKED : CertificateBindingResult::VALID;
}

bool ReadEncoded(rseq_t& input, uint8_t tag, rseq_t& encoded)
{
    const auto original = input;
    rseq_t value;
    if (!ReadValue(input, tag, value)) return false;
    encoded = original.take(original.length() - input.length());
    return true;
}

bool ReadDirectoryName(rseq_t names, const X509_NAME* expected)
{
    rseq_t name;
    if (!ReadValue(names, 0xA4, name) || names.is_not_empty() || name.is_empty()) return false;
    const uint8_t* cursor = name;
    OpenSSLPtr<X509_NAME, X509_NAME_free> decoded(d2i_X509_NAME(nullptr, &cursor, static_cast<long>(name.length())),
                                                 X509_NAME_free);
    return decoded && cursor == static_cast<const uint8_t*>(name) + name.length()
        && X509_NAME_entry_count(decoded.get()) > 0 && X509_NAME_cmp(expected, decoded.get()) == 0;
}

bool ReadGeneralizedTime(rseq_t& input, OpenSSLPtr<ASN1_GENERALIZEDTIME, ASN1_GENERALIZEDTIME_free>& time)
{
    rseq_t value;
    if (!ReadValue(input, 0x18, value) || value.length() != 15 || value[14] != 'Z') return false;
    char text[16]{};
    for (size_t i = 0; i < 14; ++i)
        if (value[i] < '0' || value[i] > '9') return false;
    std::memcpy(text, value, 15);
    return time && ASN1_GENERALIZEDTIME_set_string(time.get(), text) == 1;
}

bool ReadAttributeExtensions(rseq_t attributes, rseq_t extensions, const std::string& aor, UserCertificate& cert)
{
    // RFC 5755 requires attributes, but IEEE Table A-8 takes DNP roles
    // exclusively from IECUserRoles in the AC extensions.
    if (attributes.is_empty()) return false;
    std::set<std::string> types;
    while (attributes.is_not_empty())
    {
        rseq_t encoded;
        if (!ReadEncoded(attributes, 0x30, encoded)) return false;
        const uint8_t* cursor = encoded;
        OpenSSLPtr<X509_ATTRIBUTE, X509_ATTRIBUTE_free> attribute(
            d2i_X509_ATTRIBUTE(nullptr, &cursor, static_cast<long>(encoded.length())), X509_ATTRIBUTE_free);
        if (!attribute || cursor != static_cast<const uint8_t*>(encoded) + encoded.length()
            || X509_ATTRIBUTE_count(attribute.get()) <= 0) return false;
        char oid[128];
        const auto size = OBJ_obj2txt(oid, sizeof(oid), X509_ATTRIBUTE_get0_object(attribute.get()), 1);
        if (size <= 0 || size >= static_cast<int>(sizeof(oid)) || !types.emplace(oid, size).second) return false;
    }
    while (extensions.is_not_empty())
    {
        rseq_t encoded;
        if (!ReadEncoded(extensions, 0x30, encoded)) return false;
        const uint8_t* cursor = encoded;
        OpenSSLPtr<X509_EXTENSION, X509_EXTENSION_free> extension(
            d2i_X509_EXTENSION(nullptr, &cursor, static_cast<long>(encoded.length())), X509_EXTENSION_free);
        if (!extension || cursor != static_cast<const uint8_t*>(encoded) + encoded.length()
            || X509_EXTENSION_get_critical(extension.get())) return false;
        char oid[128];
        const auto size = OBJ_obj2txt(oid, sizeof(oid), X509_EXTENSION_get_object(extension.get()), 1);
        if (size <= 0 || size >= static_cast<int>(sizeof(oid)) || !types.emplace("ext:" + std::string(oid, size)).second)
            return false;
        const std::string name(oid, size);
        if (name == "1.2.840.10070.8.1" && !ReadRolesExtension(extension.get(), aor, cert)) return false;
        // Do not accept a token that instructs the relying party not to
        // check revocation or that restricts its target without enforcing it.
        if (name == "2.5.29.56" || name == "2.5.29.55") return false;
    }
    return cert.status.certificateRoleMask && cert.status.operation != 1;
}

OpenSSLPtr<X509, X509_free> VerifiedAttributeAuthority(const UserAttributeCertificateTrust& trust, uint64_t utc)
{
    auto aa = ReadCertificate({trust.authority.data(), trust.authority.size()});
    auto issuer = ReadCertificate({trust.issuer.data(), trust.issuer.size()});
    auto crl = ReadCRL(trust.issuerRevocationList, utc);
    if (!aa || X509_check_ca(aa.get()) || !(X509_get_key_usage(aa.get()) & KU_DIGITAL_SIGNATURE)
        || !VerifyPKC(aa.get(), issuer.get(), crl.get(), utc)) aa.reset();
    return aa;
}
}

CertificateResult VerifyUserIdentity(IUserCertificatePolicy& policy, uint16_t association,
                                     rseq_t der, CertificateTime time, UserCertificate& output)
{
    constexpr auto invalid = CertificateResult::INVALID_DATA;
    const auto utc = time.utc;
    if (der.is_empty() || der.length() > MAX_USER_CERTIFICATE_SIZE
        || utc / 1000 > static_cast<uint64_t>(std::numeric_limits<std::time_t>::max())) return invalid;
    UserCertificateTrust trust;
    if (!policy.ReadTrust(association, trust) || trust.authority.empty() || trust.authority.size() > MAX_USER_CERTIFICATE_SIZE
        || trust.revocationList.empty() || trust.revocationList.size() > 1024 * 1024) return invalid;
    auto certificate = ReadCertificate(der);
    auto authority = ReadCertificate({trust.authority.data(), trust.authority.size()});
    if (!certificate || !authority || !X509_check_ca(authority.get())
        || X509_get_version(certificate.get()) != 2 || X509_check_ca(certificate.get())
        || !(X509_get_key_usage(certificate.get()) & KU_DIGITAL_SIGNATURE)
        || X509_get_signature_nid(certificate.get()) != NID_dsa_with_SHA256) return invalid;
    if (X509_verify(certificate.get(), X509_get0_pubkey(authority.get())) != 1)
        return CertificateResult::INVALID_SIGNATURE;

    auto crl = ReadCRL(trust.revocationList, utc);
    if (!VerifyPKC(certificate.get(), authority.get(), crl.get(), utc, time.secure)) return invalid;

    UserCertificate result;
    uint64_t begins = 0;
    const auto* notBefore = X509_get0_notBefore(certificate.get());
    const auto* notAfter = X509_get0_notAfter(certificate.get());
    if (!ToUnixMilliseconds(notBefore, begins) || !ToUnixMilliseconds(notAfter, result.expiresUnixMs)
        || begins >= result.expiresUnixMs || (time.secure && (utc < begins || utc >= result.expiresUnixMs))
        || !WithinThreeYears(notBefore, notAfter)
        || !ReadRole(certificate.get(), trust.areaOfResponsibility, result)
        || !ReadSerial(X509_get0_serialNumber(certificate.get()), result.binding.serial)) return invalid;

    auto& status = result.status;
    auto* key = X509_get_X509_PUBKEY(certificate.get());
    const auto keySize = i2d_X509_PUBKEY(key, nullptr);
    uint8_t* encoded = status.publicKey.data();
    if (keySize <= 0 || static_cast<size_t>(keySize) > status.publicKey.size()
        || i2d_X509_PUBKEY(key, &encoded) != keySize
        || !ValidateMethod68PublicKey({status.publicKey.data(), static_cast<size_t>(keySize)}, false)) return invalid;
    status.publicKeySize = static_cast<uint16_t>(keySize);
    status.method = 68;
    auto* subject = X509_get_subject_name(certificate.get());
    const int subjectSize = i2d_X509_NAME(subject, nullptr);
    if (subjectSize <= 0 || X509_NAME_entry_count(subject) == 0) return invalid;
    std::vector<uint8_t> name(static_cast<size_t>(subjectSize));
    encoded = name.data();
    size_t mappedSize = 0;
    if (i2d_X509_NAME(subject, &encoded) != subjectSize
        || !policy.ResolveUser(association, name.data(), name.size(), status.name.data(), status.name.size(), mappedSize)
        || !mappedSize || mappedSize > 126
        || SHA256({name.data(), name.size()}, {result.subject.data(), result.subject.size()}) != Result::OK
        || SHA256({trust.authority.data(), trust.authority.size()}, {result.issuer.data(), result.issuer.size()}) != Result::OK
        || SHA256(der, {status.certification.data(), 32}) != Result::OK) return invalid;
    status.nameSize = static_cast<uint16_t>(mappedSize);
    status.certificationSize = 32;
    result.binding.issuer = result.issuer;
    result.binding.beginsUnixMs = begins;
    result.binding.expiresUnixMs = result.expiresUnixMs;
    output = std::move(result);
    return CertificateResult::VALID;
}

CertificateResult VerifyUserAttribute(IUserCertificatePolicy& policy, uint16_t association,
                                      rseq_t der, CertificateTime time, UserCertificate& output)
{
    constexpr auto invalid = CertificateResult::INVALID_DATA;
    const auto utc = time.utc;
    if (der.is_empty() || der.length() > MAX_USER_CERTIFICATE_SIZE) return invalid;
    UserCertificateTrust identityTrust;
    UserAttributeCertificateTrust trust;
    if (!policy.ReadTrust(association, identityTrust) || !policy.ReadAttributeTrust(association, trust)) return invalid;
    auto holderIssuer = ReadCertificate({identityTrust.authority.data(), identityTrust.authority.size()});
    auto aa = VerifiedAttributeAuthority(trust, utc);
    if (!aa || !holderIssuer) return invalid;

    UserCertificate result;
    uint32_t version = 0;
    rseq_t envelope, signedInfo, info, innerAlgorithm, outerAlgorithm, signature, holder, base,
        names, issuer, serial, validity, attributes, extensions;
    const uint8_t dsaSha256[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x02};
    auto input = der;
    if (!ReadValue(input, 0x30, envelope) || input.is_not_empty()
        || !ReadEncoded(envelope, 0x30, signedInfo) || !ReadValue(envelope, 0x30, outerAlgorithm)
        || !outerAlgorithm.equals({dsaSha256, sizeof(dsaSha256)}) || !ReadValue(envelope, 0x03, signature)
        || envelope.is_not_empty() || signature.length() < 2 || signature[0]) return invalid;
    auto encoded = signedInfo;
    if (!ReadValue(encoded, 0x30, info) || !ReadNumber(info, 0x02, version) || version != 1
        || !ReadValue(info, 0x30, holder) || !ReadValue(holder, 0xA0, base) || holder.is_not_empty()
        || !ReadValue(base, 0x30, names) || !ReadDirectoryName(names, X509_get_subject_name(holderIssuer.get()))
        || !ReadValue(base, 0x02, serial) || !ReadSerial(serial, result.holder.serial) || base.is_not_empty()
        || !ReadValue(info, 0xA0, issuer) || !ReadValue(issuer, 0x30, names) || issuer.is_not_empty()
        || !ReadDirectoryName(names, X509_get_subject_name(aa.get()))
        || !ReadValue(info, 0x30, innerAlgorithm) || !innerAlgorithm.equals(outerAlgorithm)
        || !ReadValue(info, 0x02, serial) || !ReadSerial(serial, result.binding.serial)
        || !ReadValue(info, 0x30, validity) || !ReadValue(info, 0x30, attributes)
        || !ReadValue(info, 0x30, extensions) || info.is_not_empty()) return invalid;

    auto* key = X509_get_X509_PUBKEY(aa.get());
    const int keySize = i2d_X509_PUBKEY(key, nullptr);
    std::array<uint8_t, 1024> spki{};
    uint8_t* dest = spki.data();
    if (keySize <= 0 || static_cast<size_t>(keySize) > spki.size() || i2d_X509_PUBKEY(key, &dest) != keySize
        || DSASHA256Verify({spki.data(), static_cast<size_t>(keySize)}, signedInfo, signature.skip(1)) != Result::OK)
        return CertificateResult::INVALID_SIGNATURE;
    OpenSSLPtr<ASN1_GENERALIZEDTIME, ASN1_GENERALIZEDTIME_free> begin(ASN1_GENERALIZEDTIME_new(), ASN1_GENERALIZEDTIME_free),
        end(ASN1_GENERALIZEDTIME_new(), ASN1_GENERALIZEDTIME_free);
    auto crl = ReadCRL(trust.revocationList, utc);
    if (!ReadGeneralizedTime(validity, begin) || !ReadGeneralizedTime(validity, end) || validity.is_not_empty()
        || !ToUnixMilliseconds(begin.get(), result.binding.beginsUnixMs)
        || !ToUnixMilliseconds(end.get(), result.binding.expiresUnixMs)
        || result.binding.beginsUnixMs >= result.binding.expiresUnixMs
        || (time.secure && (utc < result.binding.beginsUnixMs || utc >= result.binding.expiresUnixMs))
        || !WithinThreeYears(begin.get(), end.get())
        || !ReadAttributeExtensions(attributes, extensions, identityTrust.areaOfResponsibility, result)
        || CheckSerial(crl.get(), aa.get(), result.binding.serial, true) != CertificateBindingResult::VALID
        || !Fingerprint(identityTrust.authority, result.holder.issuer) || !Fingerprint(trust.authority, result.issuer)
        || SHA256(der, {result.status.certification.data(), 32}) != Result::OK) return invalid;
    result.status.method = 68;
    result.status.certificateType = 2;
    result.status.certificationSize = 32;
    result.binding.issuer = result.issuer;
    result.expiresUnixMs = result.binding.expiresUnixMs;
    output = std::move(result);
    return CertificateResult::VALID;
}

bool SameCertificate(const UserCertificateBinding& lhs, const UserCertificateBinding& rhs)
{
    return lhs.issuer == rhs.issuer && lhs.serial == rhs.serial;
}

CertificateBindingResult CheckUserCertificateBinding(IUserCertificatePolicy& policy, uint16_t association,
                                                      const UserCertificateBinding& binding, bool attribute, CertificateTime time)
{
    constexpr auto invalid = CertificateBindingResult::INVALID;
    const auto utc = time.utc;
    if (binding.revoked) return CertificateBindingResult::REVOKED;
    if (binding.beginsUnixMs >= binding.expiresUnixMs
        || (time.secure && (utc < binding.beginsUnixMs || utc >= binding.expiresUnixMs))) return invalid;
    std::array<uint8_t, 32> fingerprint{};
    if (attribute)
    {
        UserAttributeCertificateTrust trust;
        if (!policy.ReadAttributeTrust(association, trust) || !Fingerprint(trust.authority, fingerprint)
            || binding.issuer != fingerprint) return invalid;
        auto aa = VerifiedAttributeAuthority(trust, utc);
        auto list = ReadCRL(trust.revocationList, utc);
        return CheckSerial(list.get(), aa.get(), binding.serial, true);
    }
    UserCertificateTrust trust;
    if (!policy.ReadTrust(association, trust) || !Fingerprint(trust.authority, fingerprint)
        || binding.issuer != fingerprint) return invalid;
    auto authority = ReadCertificate({trust.authority.data(), trust.authority.size()});
    auto list = ReadCRL(trust.revocationList, utc);
    uint64_t begin = 0, end = 0;
    if (!authority || !X509_check_ca(authority.get()) || !ToUnixMilliseconds(X509_get0_notBefore(authority.get()), begin)
        || !ToUnixMilliseconds(X509_get0_notAfter(authority.get()), end) || utc < begin || utc >= end) return invalid;
    return CheckSerial(list.get(), authority.get(), binding.serial, false);
}
}
}
