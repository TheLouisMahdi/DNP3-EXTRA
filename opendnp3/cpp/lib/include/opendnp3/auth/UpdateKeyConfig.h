// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_UPDATEKEYCONFIG_H
#define OPENDNP3_UPDATEKEYCONFIG_H

#include "opendnp3/auth/AuthenticationConfig.h"

#include <array>

namespace opendnp3
{
// Fixed bounds apply before parsing/copying received identities or credentials.
constexpr size_t MAX_AUTHENTICATION_USERS = 16;
constexpr size_t MAX_AUTHENTICATION_NAME = 128;

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
    std::array<uint8_t, 16> certification{};
    uint8_t certificationSize = 0;
    std::array<uint8_t, 32> certificationKeyFingerprint{}; // Outstation-local trust epoch; never supplied by Master.
    bool haveStatusSequence = false;
    bool active = false;
    bool pending = false;
    uint16_t role = 0;
    uint16_t pendingRole = 0;
    uint64_t expiresUnixMs = 0;
    uint64_t pendingExpiresUnixMs = 0;
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
    std::array<uint8_t, 16> certification{};
    uint8_t certificationSize = 0;
    bool verifyOnly = false;
    std::shared_ptr<IUpdateKeySource> source;
};
}
#endif
