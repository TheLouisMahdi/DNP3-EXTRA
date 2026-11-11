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

#include "channel/tls/SSLContext.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include "logging/LogMacros.h"

#include "opendnp3/logging/LogLevels.h"

namespace opendnp3
{
SSLContext::SSLContext(const Logger& logger, bool server, const TLSConfig& config, std::error_code& ec)
    : value(server ? asio::ssl::context_base::sslv23_server : asio::ssl::context_base::sslv23_client),
      config(config), logger(logger)
{
    this->ApplyConfig(config, server, ec);
}

namespace
{
using PeerStore = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;

bool LoadCRLs(X509_STORE* store, const std::string& path)
{
    if (!store) return false;
    std::unique_ptr<BIO, decltype(&BIO_free)> file(BIO_new_file(path.c_str(), "rb"), BIO_free);
    auto release = [](STACK_OF(X509_INFO)* info) { sk_X509_INFO_pop_free(info, X509_INFO_free); };
    auto noPassword = [](char*, int, int, void*) { return 0; };
    std::unique_ptr<STACK_OF(X509_INFO), decltype(release)> list(
        file ? PEM_X509_INFO_read_bio(file.get(), nullptr, noPassword, nullptr) : nullptr, release);
    if (!list) { ERR_clear_error(); return false; }
    bool loaded = false;
    for (int i = 0; i < sk_X509_INFO_num(list.get()); ++i)
    {
        auto* crl = sk_X509_INFO_value(list.get(), i)->crl;
        if (!crl || !X509_CRL_get0_lastUpdate(crl) || !X509_CRL_get0_nextUpdate(crl)
            || X509_cmp_current_time(X509_CRL_get0_lastUpdate(crl)) != -1
            || X509_cmp_current_time(X509_CRL_get0_nextUpdate(crl)) != 1) continue;
        if (X509_STORE_add_crl(store, crl) != 1) { ERR_clear_error(); return false; }
        loaded = true;
    }
    return loaded && X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) == 1;
}

PeerStore FreshPeerStore(const TLSConfig& config)
{
    PeerStore store(X509_STORE_new(), X509_STORE_free);
    if (!store || X509_STORE_load_locations(store.get(), config.peerCertFilePath.c_str(), nullptr) != 1
        || !LoadCRLs(store.get(), config.crlFilePath)) store.reset();
    return store;
}
}

bool SSLContext::RefreshPeerStore(SSL* ssl, const TLSConfig& config)
{
    if (config.crlFilePath.empty()) return true;
    auto store = FreshPeerStore(config);
    return store && SSL_set1_verify_cert_store(ssl, store.get()) == 1;
}

bool SSLContext::PeerIsRevoked(SSL* ssl, const TLSConfig& config)
{
    if (config.crlFilePath.empty()) return false;
    auto store = FreshPeerStore(config);
    auto* chain = SSL_get0_verified_chain(ssl);
    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> verify(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    if (!store || !chain || sk_X509_num(chain) < 1 || !verify
        || X509_STORE_CTX_init(verify.get(), store.get(), sk_X509_value(chain, 0), chain) != 1) return false;
    // An established peer's certificate lifetime is not a revocation decision
    // (§7.8.7.4.4). CRL validity/freshness checks remain enabled.
    X509_STORE_CTX_set_verify_cb(verify.get(), [](int ok, X509_STORE_CTX* ctx) {
        if (ok) return ok;
        const auto error = X509_STORE_CTX_get_error(ctx);
        if (error != X509_V_ERR_CERT_HAS_EXPIRED && error != X509_V_ERR_CERT_NOT_YET_VALID) return 0;
        X509_STORE_CTX_set_error(ctx, X509_V_OK);
        return 1;
    });
    return X509_verify_cert(verify.get()) == 0 && X509_STORE_CTX_get_error(verify.get()) == X509_V_ERR_CERT_REVOKED;
}

int SSLContext::GetVerifyMode(bool server)
{
    return server ? (asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert) : asio::ssl::verify_peer;
}

std::error_code SSLContext::ApplyConfig(const TLSConfig& config, bool server, std::error_code& ec)
{
    // turn off session caching completely
    SSL_CTX_set_session_cache_mode(value.native_handle(), SSL_SESS_CACHE_OFF);

    auto options = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TICKET;

    if (!config.allowTLSv10)
    {
        options |= SSL_OP_NO_TLSv1;
    }

    if (!config.allowTLSv11)
    {
        options |= SSL_OP_NO_TLSv1_1;
    }

    if (!config.allowTLSv12)
    {
        options |= SSL_OP_NO_TLSv1_2;
    }

    if (!config.allowTLSv13)
    {
        options |= SSL_OP_NO_TLSv1_3;
    }

    // Avoid narrowing OpenSSL's option mask through old Asio's Windows long.
    if ((SSL_CTX_set_options(value.native_handle(), options) & options) != options)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        SIMPLE_LOG_BLOCK(logger, flags::ERR, "Unable to set TLS protocol options");
        return ec;
    }

    // optionally, configure the cipher-list
    if (!config.cipherList.empty())
    {
        if (SSL_CTX_set_cipher_list(value.native_handle(), config.cipherList.c_str()) == 0)
        {
            ec = std::make_error_code(std::errc::invalid_argument);
            FORMAT_LOG_BLOCK(logger, flags::ERR, "Error calling ssl::context::set_cipher_list(..): %s",
                             ec.message().c_str());
            return ec;
        }
    }

    if ((!config.cipherSuites.empty() && SSL_CTX_set_ciphersuites(value.native_handle(), config.cipherSuites.c_str()) != 1)
        || (!config.allowTLSv10 && !config.allowTLSv11 && !config.allowTLSv12 && !config.allowTLSv13))
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return ec;
    }
    if (!config.peerName.empty())
    {
        auto* parameters = SSL_CTX_get0_param(value.native_handle());
        asio::error_code addressError;
        asio::ip::address::from_string(config.peerName, addressError);
        const int ok = addressError ? X509_VERIFY_PARAM_set1_host(parameters, config.peerName.c_str(), config.peerName.size())
                                    : X509_VERIFY_PARAM_set1_ip_asc(parameters, config.peerName.c_str());
        X509_VERIFY_PARAM_set_hostflags(parameters, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT | X509_CHECK_FLAG_NO_WILDCARDS);
        if (ok != 1) { ec = std::make_error_code(std::errc::invalid_argument); return ec; }
    }

    // verify the peer certificate
    if (value.set_verify_mode(GetVerifyMode(server), ec))
    {
        FORMAT_LOG_BLOCK(logger, flags::ERR, "Error calling ssl::context::set_verify_mode(..): %s",
                         ec.message().c_str());
        return ec;
    }

    // The public certificate file used to verify the peer
    if (value.load_verify_file(config.peerCertFilePath, ec))
    {
        FORMAT_LOG_BLOCK(logger, flags::ERR, "Error calling ssl::context::load_verify_file(..): %s",
                         ec.message().c_str());
        return ec;
    }

    if (!config.crlFilePath.empty())
    {
        if (!config.crlCheckIntervalHours || !LoadCRLs(SSL_CTX_get_cert_store(value.native_handle()), config.crlFilePath))
        {
            ec = std::make_error_code(std::errc::invalid_argument);
            SIMPLE_LOG_BLOCK(logger, flags::ERR, "Unable to load TLS CRL bundle");
            return ec;
        }
    }

    // the certificate we present to the server + the private key we use are placed into the same file
    if (value.use_certificate_chain_file(config.localCertFilePath, ec))
    {
        FORMAT_LOG_BLOCK(logger, flags::ERR, "Error calling ssl::context::use_certificate_chain_file(..): %s",
                         ec.message().c_str());
        return ec;
    }

    if (value.use_private_key_file(config.privateKeyFilePath, asio::ssl::context_base::file_format::pem, ec))
    {
        FORMAT_LOG_BLOCK(logger, flags::ERR, "Error calling ssl::context::use_private_key_file(..): %s",
                         ec.message().c_str());
    }

    if (!ec && SSL_CTX_check_private_key(value.native_handle()) != 1)
        ec = std::make_error_code(std::errc::invalid_argument);
    return ec;
}
} // namespace opendnp3
