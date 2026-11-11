// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_UPDATEKEYCONFIG_H
#define OPENDNP3_UPDATEKEYCONFIG_H

#include "opendnp3/auth/AuthenticationConfig.h"

#include <array>
#include <string>
#include <vector>

namespace opendnp3
{
// Fixed bounds apply before parsing/copying received identities or credentials.
constexpr size_t MAX_AUTHENTICATION_USERS = 16;
constexpr size_t MAX_AUTHENTICATION_NAME = 128;
constexpr size_t MAX_USER_CERTIFICATE_SIZE = 8192;

// Association-local trust for a directly issuing CA. All values are provisioned
// out of band. The CRL must cover the issuer and be valid at trusted UTC.
struct UserCertificateTrust
{
    std::vector<uint8_t> authority;
    std::vector<uint8_t> revocationList;
    std::string areaOfResponsibility;
};

// RFC 5755 AA is a non-CA signing certificate. Its issuer's PKC CRL and
// the AA's attribute-only CRL have different scopes and are not interchangeable.
struct UserAttributeCertificateTrust
{
    std::vector<uint8_t> authority;
    std::vector<uint8_t> issuer;
    std::vector<uint8_t> issuerRevocationList;
    std::vector<uint8_t> revocationList;
};

class IUserCertificatePolicy
{
public:
    virtual ~IUserCertificatePolicy() = default;
    virtual bool ReadTrust(uint16_t association, UserCertificateTrust& trust) = 0;
    virtual bool ReadAttributeTrust(uint16_t, UserAttributeCertificateTrust&) { return false; }
    // Optional external PKI time evidence for CA/AA and CRL/ACRL validation
    // while DNP secure time is unavailable. Supply current authenticated UTC
    // or return false. This never establishes secure DNP time.
    virtual bool ReadPKIValidationTime(uint16_t, uint64_t&) { return false; }
    // Map a validated DER subject Name to a configured, unique DNP user name.
    virtual bool ResolveUser(uint16_t association, const uint8_t* subject, size_t subjectSize,
                             uint8_t* name, size_t capacity, size_t& size) = 0;
};

// Durable binding to the previously validated certificate. Serial is a
// positive, zero-padded, big-endian integer; expiry==0 denotes no binding.
struct UserCertificateBinding
{
    std::array<uint8_t, 32> issuer{};
    std::array<uint8_t, 20> serial{};
    uint64_t beginsUnixMs = 0;
    uint64_t expiresUnixMs = 0;
    bool revoked = false;
};

// Durable authority decision and active credential for one association-local
// identity. Pending role/expiry are deliberately separate from the active role.
// Deleted identities retain their SCS tombstone; receive paths never evict it.
struct UpdateKeyUser
{
    ~UpdateKeyUser()
    {
        volatile uint8_t* p = updateKey.data();
        for (size_t n = 0; n < updateKey.size(); ++n) p[n] = 0;
        p = pendingUpdateKey.data();
        for (size_t n = 0; n < pendingUpdateKey.size(); ++n) p[n] = 0;
    }
    std::array<uint8_t, MAX_AUTHENTICATION_NAME> name{};
    uint16_t nameSize = 0;
    uint16_t user = 0;
    uint32_t statusSequence = 0;
    uint8_t statusOperation = 0;
    uint16_t statusExpiryDays = 0;
    uint8_t method = 4;
    std::array<uint8_t, 1024> publicKey{}; // Authority-certified DSA SPKI for Method 68.
    uint16_t publicKeySize = 0;
    std::array<uint8_t, 72> certification{};
    uint8_t certificationSize = 0;
    std::array<uint8_t, 32> certificationKeyFingerprint{}; // Outstation audit evidence; never resets SCS.
    bool haveStatusSequence = false;
    bool active = false;
    bool pending = false;
    uint16_t role = 0;
    uint16_t pendingRole = 0;
    uint64_t expiresUnixMs = 0; // For certificate records, zero means a process-local relative expiry.
    uint64_t pendingExpiresUnixMs = 0;
    uint16_t certificateRevision = 256; // 256 means the identity has no certificate history.
    std::array<uint8_t, 32> certificateSubject{};
    UserCertificateBinding identity, pendingIdentity;
    UserCertificateBinding attribute, pendingAttribute;
    uint8_t roleMask = 0, pendingRoleMask = 0; // Zero denotes a legacy single DNP role.
    std::array<uint8_t, 32> updateKey{};
    bool havePendingKey = false; // Master crash recovery; never authorizes commands.
    std::array<uint8_t, 32> pendingUpdateKey{};
};

// This extends the existing credential boundary; the same object is supplied as
// AuthenticationConfig::credentials. No second credential database is created.
class IUpdateKeyCredentials : public IAuthenticationCredentials
{
public:
    // Return false if no trusted wall clock is available. Protocol deadlines use
    // monotonic time; this clock is ONLY for durable expiry/restart validation.
    virtual bool TrustedUnixTimeMs(uint64_t& now) = 0;
    // Empty slots return true with nameSize==0. Failure is fail-closed.
    virtual bool ReadUser(uint16_t association, size_t slot, UpdateKeyUser& user) = 0;
    // Commit the complete record, including tombstone, pending authority decision
    // and active key. On an uncertain I/O failure the caller disables this user
    // until reload; a torn commit must fail closed rather than revive an old key.
    // Implementations must provide durable, confidential, authenticated storage.
    virtual bool WriteUser(uint16_t association, size_t slot, const UpdateKeyUser& user) = 0;
};

// Outstation-only authority trust. Never supplied to a Master operation.
class IUpdateKeyTrust
{
public:
    virtual ~IUpdateKeyTrust() = default;
    virtual bool ReadCertificationKey(uint16_t association, uint8_t* output, size_t capacity) = 0;
    // Optional Method 68. Pinned authority DSA SPKI and Outstation RSA private
    // DER are provisioned separately. Neither is supplied by a received ASDU.
    virtual bool ReadAuthorityPublicKey(uint16_t, uint8_t*, size_t, size_t&) { return false; }
    virtual bool ReadOutstationPrivateKey(uint16_t, uint8_t*, size_t, size_t&) { return false; }
};

// Trusted integration with the external authority. The Master has neither its
// Certification Key nor a local substitute for the authority's decision.
class IUpdateKeySource
{
public:
    virtual ~IUpdateKeySource() = default;
    // Supply the new key to the Master and forward the authority's RFC3394
    // ciphertext unchanged. All inputs belong to the received V12 exchange.
    // Implementations may fail closed while external authority data is absent.
    virtual bool GetKey(uint16_t association, const uint8_t* name, size_t nameSize,
                        const uint8_t* masterChallenge, const uint8_t* outstationChallenge,
                        uint32_t sequence, uint16_t user, uint8_t* updateKey,
                        uint8_t* ciphertext, size_t capacity, size_t& size) = 0;
    // Method 68 Master credentials: user's DSA private DER and independently
    // trusted Outstation RSA SPKI. The authority private key never crosses this
    // boundary. Supply a fresh 32-byte Update Key; outputs are caller-owned/wiped.
    virtual bool GetAsymmetricKey(uint16_t, const uint8_t*, size_t, uint8_t*,
                                  uint8_t*, size_t, size_t&, uint8_t*, size_t, size_t&) { return false; }
};

// Owns all request bytes across asynchronous scheduling. Certification must be
// produced externally. A zero certificationSize means omit V10, not self-certify.
struct UpdateKeyRequest
{
    std::array<uint8_t, MAX_AUTHENTICATION_NAME> name{};
    uint16_t nameSize = 0;
    uint8_t operation = 0;
    uint32_t statusSequence = 0;
    uint16_t role = 0;
    uint16_t expiryDays = 0;
    uint8_t method = 4;
    std::array<uint8_t, 1024> publicKey{};
    uint16_t publicKeySize = 0;
    std::array<uint8_t, 72> certification{};
    uint8_t certificationSize = 0;
    bool verifyOnly = false;
    std::shared_ptr<IUpdateKeySource> source;
    // Optional authority-issued DER ID certificate for FC32/G120V8.
    // The authenticated certificate supplies identity, role, operation and expiry.
    std::vector<uint8_t> certificate;
    uint8_t certificateType = 1; // IEEE A.45.8: 1 = ID, 2 = Attribute.
    uint8_t certificateRoleMask = 0; // Derived from the signed certificate, never accepted from callers.
};
}
#endif
