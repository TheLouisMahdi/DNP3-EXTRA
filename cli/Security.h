// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef DNP3_CLI_SECURITY_H
#define DNP3_CLI_SECURITY_H
#include <opendnp3/app/AppConstants.h>
#include <opendnp3/auth/AuthenticationConfig.h>
#include <opendnp3/auth/UpdateKeyConfig.h>
#include <opendnp3/link/LinkConfig.h>
#include <string>
namespace diagnostic
{
struct Options
{
    std::string role, host = "127.0.0.1", auth = "compat", profile, credentials;
    std::string ca, cert, key, peerName, tlsVersion = "both", ciphers, suites, directory, crl;
    uint16_t port = 20000, local = 0, remote = 0, association = 7, user = 2;
    uint32_t responseMs = 2000, replyMs = 2000, renewalMs = 900000, messageCount = 1000;
    uint32_t rxFragmentBytes = opendnp3::DEFAULT_MAX_APDU_SIZE;
    uint32_t txFragmentBytes = opendnp3::DEFAULT_MAX_APDU_SIZE;
    opendnp3::LinkConfirmMode linkConfirmMode = opendnp3::LinkConfirmMode::Never;
    uint8_t linkRetries = 0, unsolRetries = 0;
    uint32_t linkTimeoutMs = 0, rxFragmentTimeoutMs = 0, completeResponseMs = 0;
    uint32_t solConfirmMs = 0, unsolConfirmMs = 0;
    bool relativeBinaryTime = false;
    bool prefer8BitEventQualifiers = false, prefer8BitControlQualifiers = false;
    bool aggressive = false, trustedTime = false, testOnly = false, denyControls = false;
    bool unsolicited = false, trace = false, tls = false;
    bool commandEvents = false;
    bool rtuIoProfile = false;
    bool expiredTestCertificate = false, selfSignedTestCertificate = false;
};
Options ParseOptions(int argc, char** argv);
opendnp3::AuthenticationConfig Authentication(const Options& options, bool master);
opendnp3::UpdateKeyRequest AuthorizedRequest(const Options& options, const std::string& operation,
                                            const std::string& name, uint32_t scs, uint16_t role, uint16_t days);
void PrintUsers(const Options& options, bool master);
int Provision(const Options& options);
int AuthorityWorker(const Options& options);
int ProvisionTLS(const Options& options);
}
#endif
