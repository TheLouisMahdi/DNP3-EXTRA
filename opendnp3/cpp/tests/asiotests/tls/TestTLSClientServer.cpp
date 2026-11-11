/*
 * Copyright 2013-2020 Automatak, LLC
 *
 * Licensed to Green Energy Corp (www.greenenergycorp.com) and Automatak
 * LLC (www.automatak.com) under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership. Green Energy Corp and Automatak LLC license
 * this file to you under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License. You may obtain
 * a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "mocks/MockTLSPair.h"

#include <catch.hpp>

#include <fstream>
#include <iostream>
#include <cstdio>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

using namespace opendnp3;

#define SUITE(name) "TLS client/server suite - " name

template<class F> void WithIO(const F& fun)
{
    auto io = std::make_shared<MockIO>();
    fun(io);
    io->RunUntilOutOfWork();
}

bool exists(const std::string& file)
{
    std::ifstream infile(file);
    return infile.good();
}

namespace
{
struct TLSRevocationFixture
{
    using Cert = std::unique_ptr<X509, decltype(&X509_free)>;
    using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using File = std::unique_ptr<BIO, decltype(&BIO_free)>;
    std::string ca, leaf, key, crl;
    Key issuer = GenerateKey(), peer = GenerateKey();
    Cert root = Certificate("CRL test authority", 1, issuer.get(), nullptr, issuer.get());
    Cert endpoint = Certificate("CRL test endpoint", 2, peer.get(), root.get(), issuer.get());

    TLSRevocationFixture()
    {
        uint8_t random[8]{};
        REQUIRE(RAND_bytes(random, sizeof(random)) == 1);
        std::string prefix = "tls-revocation-";
        for (auto b : random) prefix += std::to_string(b) + "-";
        ca = prefix + "ca.pem"; leaf = prefix + "leaf.pem"; key = prefix + "key.pem"; crl = prefix + "crl.pem";
        File caFile(BIO_new_file(ca.c_str(), "wb"), BIO_free), leafFile(BIO_new_file(leaf.c_str(), "wb"), BIO_free),
             keyFile(BIO_new_file(key.c_str(), "wb"), BIO_free);
        REQUIRE(caFile); REQUIRE(leafFile); REQUIRE(keyFile);
        REQUIRE(PEM_write_bio_X509(caFile.get(), root.get()) == 1);
        REQUIRE(PEM_write_bio_X509(leafFile.get(), endpoint.get()) == 1);
        REQUIRE(PEM_write_bio_PrivateKey(keyFile.get(), peer.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1);
    }
    ~TLSRevocationFixture()
    {
        for (const auto& path : {ca, leaf, key, crl}) std::remove(path.c_str());
    }
    void List(bool revoked, bool expired = false) const
    {
        std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> list(X509_CRL_new(), X509_CRL_free);
        std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> start(X509_gmtime_adj(nullptr, -300), ASN1_TIME_free),
            end(X509_gmtime_adj(nullptr, expired ? -100 : 3600), ASN1_TIME_free);
        REQUIRE(list); REQUIRE(start); REQUIRE(end);
        REQUIRE(X509_CRL_set_version(list.get(), 1) == 1);
        REQUIRE(X509_CRL_set_issuer_name(list.get(), X509_get_subject_name(root.get())) == 1);
        REQUIRE(X509_CRL_set1_lastUpdate(list.get(), start.get()) == 1);
        REQUIRE(X509_CRL_set1_nextUpdate(list.get(), end.get()) == 1);
        if (revoked)
        {
            std::unique_ptr<X509_REVOKED, decltype(&X509_REVOKED_free)> entry(X509_REVOKED_new(), X509_REVOKED_free);
            REQUIRE(entry);
            REQUIRE(X509_REVOKED_set_serialNumber(entry.get(), X509_get_serialNumber(endpoint.get())) == 1);
            REQUIRE(X509_REVOKED_set_revocationDate(entry.get(), start.get()) == 1);
            REQUIRE(X509_CRL_add0_revoked(list.get(), entry.get()) == 1);
            entry.release();
        }
        REQUIRE(X509_CRL_sign(list.get(), issuer.get(), EVP_sha256()) > 0);
        File file(BIO_new_file(crl.c_str(), "wb"), BIO_free);
        REQUIRE(file);
        REQUIRE(PEM_write_bio_X509_CRL(file.get(), list.get()) == 1);
    }

    static Key GenerateKey()
    {
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> gen(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
        REQUIRE(gen);
        REQUIRE(EVP_PKEY_keygen_init(gen.get()) == 1);
        REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(gen.get(), 2048) == 1);
        EVP_PKEY* key = nullptr;
        REQUIRE(EVP_PKEY_keygen(gen.get(), &key) == 1);
        return Key(key, EVP_PKEY_free);
    }
    static Cert Certificate(const char* cn, long serial, EVP_PKEY* key, X509* issuer, EVP_PKEY* signer)
    {
        Cert cert(X509_new(), X509_free);
        REQUIRE(cert);
        REQUIRE(X509_set_version(cert.get(), 2) == 1);
        REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial) == 1);
        REQUIRE(X509_gmtime_adj(X509_getm_notBefore(cert.get()), -600));
        REQUIRE(X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600));
        REQUIRE(X509_set_pubkey(cert.get(), key) == 1);
        auto* subject = X509_get_subject_name(cert.get());
        REQUIRE(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
            reinterpret_cast<const uint8_t*>(cn), -1, -1, 0) == 1);
        REQUIRE(X509_set_issuer_name(cert.get(), issuer ? X509_get_subject_name(issuer) : subject) == 1);
        X509V3_CTX context;
        X509V3_set_ctx(&context, issuer ? issuer : cert.get(), cert.get(), nullptr, nullptr, 0);
        auto add = [&](int nid, const char* text) {
            std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext(
                X509V3_EXT_conf_nid(nullptr, &context, nid, text), X509_EXTENSION_free);
            REQUIRE(ext);
            REQUIRE(X509_add_ext(cert.get(), ext.get(), -1) == 1);
        };
        add(NID_basic_constraints, issuer ? "critical,CA:FALSE" : "critical,CA:TRUE");
        add(NID_key_usage, issuer ? "critical,digitalSignature,keyEncipherment" : "critical,keyCertSign,cRLSign");
        REQUIRE(X509_sign(cert.get(), signer, EVP_sha256()) > 0);
        return cert;
    }
};
}

TEST_CASE(SUITE("CRL reload keeps established TCP until verified revocation and rejects fresh handshakes"),
          "[tls-crl-recheck]")
{
    using Stream = asio::ssl::stream<asio::ip::tcp::socket>;
    TLSRevocationFixture fixture;
    fixture.List(false);
    auto io = MockIO::Create();
    MockLogHandler log;
    std::error_code ec;
    TLSConfig config(fixture.ca, fixture.leaf, fixture.key);
    auto server = MockTLSServer::Create(log.logger, io->GetExecutor(), IPEndpoint::Localhost(0), config, ec);
    REQUIRE(server);
    config.crlFilePath = fixture.crl;
    REQUIRE(config.crlCheckIntervalHours == 12);
    auto executor = io->GetExecutor();
    auto client = TLSClient::Create(log.logger, executor, "127.0.0.1", config, ec);
    REQUIRE(client); REQUIRE_FALSE(ec);
    const auto remote = IPEndpoint::Localhost(server->GetBoundPort());
    std::shared_ptr<Stream> peer;
    std::shared_ptr<IAsyncChannel> channel;
    REQUIRE(client->BeginConnect(remote, [&](const auto& exec, const auto& stream, const auto& error) {
        ec = error;
        if (!ec)
        {
            peer = stream;
            channel = TLSStreamChannel::Create(exec, stream, config, std::chrono::milliseconds(15));
        }
    }));
    io->CompleteInMaxXIterations(60, [&] { return peer || ec; });
    REQUIRE(peer);
    auto stillOpen = [&]() {
        bool checked = false;
        auto timer = executor->start(std::chrono::milliseconds(45), [&] { checked = true; });
        io->CompleteInMaxXIterations(60, [&] { return checked; });
        REQUIRE(peer->lowest_layer().is_open());
    };
    REQUIRE(std::remove(fixture.crl.c_str()) == 0);
    stillOpen();
    { std::ofstream corrupt(fixture.crl); corrupt << "not a CRL"; }
    stillOpen();
    fixture.List(true, true);
    stillOpen();
    fixture.List(true);
    io->CompleteInMaxXIterations(60, [&] { return !peer->lowest_layer().is_open(); });
    bool finished = false;
    REQUIRE(client->BeginConnect(remote, [&](const auto&, const auto&, const auto& error) { ec = error; finished = true; }));
    io->CompleteInMaxXIterations(60, [&] { return finished; });
    REQUIRE(ec);
    client->Cancel();
    server->Shutdown();
    io->RunUntilOutOfWork();
}

TEST_CASE(SUITE("client and server can connect using self-signed certificate and peer certifcate for verification"))
{
    const auto key1 = "certs/self_signed/entity1_key.pem";
    const auto key2 = "certs/self_signed/entity2_key.pem";
    const auto cert1 = "certs/self_signed/entity1_cert.pem";
    const auto cert2 = "certs/self_signed/entity2_cert.pem";

    const auto all_certs_found = exists(key1) && exists(key2) && exists(cert1) && exists(cert2);
    REQUIRE(all_certs_found);

    auto iteration = [=]() {
        auto test = [=](const std::shared_ptr<MockIO>& io) {
            TLSConfig cfg1(cert2, cert1, key1);
            TLSConfig cfg2(cert1, cert2, key2);

            MockTLSPair pair(io, cfg1, cfg2);

            pair.Connect(1);
        };

        WithIO(test);
    };

    // run multiple times to ensure the test is cleaning up after itself in terms of system resources
    for (int i = 0; i < 5; ++i)
    {
        iteration();
    }
}

TEST_CASE(SUITE("client and server can connect using certificates signed by common CA"))
{
    const auto key1 = "certs/ca_chain/entity1_key.pem";
    const auto key2 = "certs/ca_chain/entity2_key.pem";
    const auto cert1 = "certs/ca_chain/entity1_cert.pem";
    const auto cert2 = "certs/ca_chain/entity2_cert.pem";
    const auto ca_cert = "certs/ca_chain/ca_cert.pem";

    const auto all_certs_found = exists(key1) && exists(key2) && exists(cert1) && exists(cert2) && exists(ca_cert);
    REQUIRE(all_certs_found);

    auto iteration = [=]() {
        auto test = [=](const std::shared_ptr<MockIO>& io) {
            TLSConfig cfg1(ca_cert, cert1, key1);
            TLSConfig cfg2(ca_cert, cert2, key2);

            MockTLSPair pair(io, cfg1, cfg2);

            pair.Connect(1);
        };

        WithIO(test);
    };

    // run multiple times to ensure the test is cleaning up after itself in terms of system resources
    for (int i = 0; i < 5; ++i)
    {
        iteration();
    }
}
