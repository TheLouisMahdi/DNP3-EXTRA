// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "Security.h"
#include <stdexcept>
#include <iostream>
#if defined(CLI_SA) && defined(CLI_TLS)
#include <windows.h>
#include <sddl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <memory>
#include <vector>
#endif
namespace diagnostic
{
int ProvisionTLS(const Options& options)
{
#if defined(CLI_SA) && defined(CLI_TLS)
    if (!options.testOnly || options.directory.empty()) throw std::runtime_error("test-tls requires --test-only --directory <new-local-directory>");
    if (options.intermediateTestCA && options.selfSignedTestCertificate)
        throw std::runtime_error("An intermediate test CA requires CA-signed leaves");
    // Create a new directory with a protected DACL for current user and SYSTEM.
    // No existing directory, certificate or key is overwritten.
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) throw std::runtime_error("Cannot obtain TLS directory owner");
    DWORD size = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<uint8_t> buffer(size);
    const bool obtained = GetTokenInformation(token, TokenUser, buffer.data(), size, &size) != 0;
    CloseHandle(token);
    LPWSTR sid = nullptr;
    if (!obtained || !ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid))
        throw std::runtime_error("Cannot determine TLS directory owner");
    const std::wstring acl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + std::wstring(sid) + L")";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
        throw std::runtime_error("Cannot protect TLS directory");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    const int wideSize = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, options.directory.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> wide(static_cast<size_t>(wideSize));
    const bool decoded = wideSize > 0 && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, options.directory.c_str(), -1, wide.data(), wideSize) > 0;
    const bool created = decoded && CreateDirectoryW(wide.data(), &attributes);
    LocalFree(descriptor);
    if (!created) throw std::runtime_error("TLS directory must be new and its parent must exist");
    using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;
    auto extension = [](X509* certificate, X509* issuer, int nid, const char* value) {
        X509V3_CTX context{}; X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
        std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext(
            X509V3_EXT_conf_nid(nullptr, &context, nid, const_cast<char*>(value)), X509_EXTENSION_free);
        if (!ext || X509_add_ext(certificate, ext.get(), -1) != 1) throw std::runtime_error("Test certificate extension failed");
    };
    auto make = [&](EVP_PKEY* key, X509* issuer, EVP_PKEY* signer, const char* name, unsigned serial, bool ca) {
        Certificate cert(X509_new(), X509_free);
        if (!cert || X509_set_version(cert.get(), 2) != 1 || ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial) != 1
            || !X509_gmtime_adj(X509_getm_notBefore(cert.get()), options.expiredTestCertificate && !ca ? -172800 : -60)
            || !X509_gmtime_adj(X509_getm_notAfter(cert.get()), options.expiredTestCertificate && !ca ? -86400 : 86400)
            || X509_set_pubkey(cert.get(), key) != 1) throw std::runtime_error("Test certificate creation failed");
        auto* subject = X509_get_subject_name(cert.get());
        if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(name), -1, -1, 0) != 1
            || X509_set_issuer_name(cert.get(), issuer ? X509_get_subject_name(issuer) : subject) != 1)
            throw std::runtime_error("Test certificate identity failed");
        const auto constraints = !ca ? "critical,CA:FALSE"
            : options.intermediateTestCA && !issuer ? "critical,CA:TRUE,pathlen:1" : "critical,CA:TRUE,pathlen:0";
        extension(cert.get(), issuer ? issuer : cert.get(), NID_basic_constraints, constraints);
        extension(cert.get(), issuer ? issuer : cert.get(), NID_key_usage, ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature,keyEncipherment");
        extension(cert.get(), issuer ? issuer : cert.get(), NID_subject_key_identifier, "hash");
        if (issuer) extension(cert.get(), issuer, NID_authority_key_identifier, "keyid:always");
        if (!ca)
        {
            const std::string san = std::string("DNS:") + name + ",IP:127.0.0.1";
            extension(cert.get(), issuer, NID_subject_alt_name, san.c_str());
            extension(cert.get(), issuer, NID_ext_key_usage, serial == 2 ? "serverAuth" : "clientAuth");
        }
        if (X509_sign(cert.get(), signer, EVP_sha256()) <= 0) throw std::runtime_error("Test certificate signing failed");
        return cert;
    };
    auto write = [&](const char* name, X509* cert, EVP_PKEY* key) {
        const std::wstring path = std::wstring(wide.data()) + L"/" + std::wstring(name, name + std::char_traits<char>::length(name));
        FILE* raw = nullptr;
        if (_wfopen_s(&raw, path.c_str(), L"wbx") != 0 || !raw) throw std::runtime_error("Cannot create TEST TLS material");
        std::unique_ptr<FILE, decltype(&fclose)> file(raw, fclose);
        // Encode within OpenSSL and write with this process's CRT. Passing an
        // MSVC FILE* across the OpenSSL DLL boundary requires its applink shim.
        std::unique_ptr<BIO, decltype(&BIO_free)> pem(BIO_new(BIO_s_mem()), BIO_free);
        if (!pem) throw std::runtime_error("TEST TLS PEM allocation failed");
        const int ok = cert ? PEM_write_bio_X509(pem.get(), cert)
                            : PEM_write_bio_PrivateKey(pem.get(), key, nullptr, nullptr, 0, nullptr, nullptr);
        char* bytes = nullptr;
        const auto size = BIO_get_mem_data(pem.get(), &bytes);
        const bool written = ok == 1 && size > 0 && fwrite(bytes, 1, static_cast<size_t>(size), file.get()) == static_cast<size_t>(size);
        if (key && size > 0) OPENSSL_cleanse(bytes, static_cast<size_t>(size));
        if (!written || fflush(file.get()) != 0) throw std::runtime_error("TEST TLS material write failed");
    };
    Key ca(EVP_RSA_gen(2048), EVP_PKEY_free), server(EVP_RSA_gen(2048), EVP_PKEY_free), client(EVP_RSA_gen(2048), EVP_PKEY_free);
    if (!ca || !server || !client) throw std::runtime_error("Test RSA provider unavailable");
    auto caCert = make(ca.get(), nullptr, ca.get(), "DNP3-EXTRA TEST CA", 1, true);
    Key intermediate(nullptr, EVP_PKEY_free);
    Certificate intermediateCert(nullptr, X509_free);
    if (options.intermediateTestCA)
    {
        intermediate.reset(EVP_RSA_gen(2048));
        if (!intermediate) throw std::runtime_error("Test intermediate RSA provider unavailable");
        intermediateCert = make(intermediate.get(), caCert.get(), ca.get(), "DNP3-EXTRA TEST Intermediate", 4, true);
        write("intermediate.pem", intermediateCert.get(), nullptr);
    }
    auto* issuer = intermediateCert ? intermediateCert.get() : caCert.get();
    auto* signer = intermediate ? intermediate.get() : ca.get();
    auto serverCert = make(server.get(), options.selfSignedTestCertificate ? nullptr : issuer,
        options.selfSignedTestCertificate ? server.get() : signer, "outstation.test", 2, false);
    auto clientCert = make(client.get(), options.selfSignedTestCertificate ? nullptr : issuer,
        options.selfSignedTestCertificate ? client.get() : signer, "master.test", 3, false);
    write("ca.pem", caCert.get(), nullptr); write("server.pem", serverCert.get(), nullptr); write("client.pem", clientCert.get(), nullptr);
    write("server-key.pem", nullptr, server.get()); write("client-key.pem", nullptr, client.get());
    std::cout << "TEST TLS files created with current-user/SYSTEM ACL; CA private key was not persisted. Validity: 24 hours.\n";
    return 0;
#else
    throw std::runtime_error("TLS test provisioning requires Windows SA crypto and DNP3_TLS");
#endif
}
}
