// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_REMOTEUPDATEKEYS_H
#define OPENDNP3_REMOTEUPDATEKEYS_H

#include "auth/SessionKeys.h"
#include "app/APDURequest.h"
#include "app/APDUHeader.h"
#include "auth/UpdateKeyFunctions.h"
#include "opendnp3/auth/UpdateKeyConfig.h"

namespace opendnp3
{
namespace crypto { struct UserCertificate; struct CertificateTime; enum class CertificateResult; enum class CertificateBindingResult; }
class AuthenticationSession;
// Serialized, association-owned remote credential lifecycle. No transport or
// borrowed receive views survive a call. All receive-side storage is bounded.
class RemoteUpdateKeys final
{
public:
    explicit RemoteUpdateKeys(AuthenticationSession& owner, SessionKeys::Role role);
    ~RemoteUpdateKeys();
    bool Load(uint64_t now);
    bool Authorize(uint16_t user, uint8_t function, uint64_t now) const;
    bool Begin(const UpdateKeyRequest& request, uint64_t now);
    bool Build(APDURequest& request, uint8_t sequence, uint64_t now);
    enum class BuildFailure { OTHER, TIMEOUT };
    BuildFailure LastBuildFailure() const { return buildFailure; }
    enum class Result { IGNORED, CONTINUE, COMPLETE, FAILED };
    Result Response(const APDUResponseHeader& header, ser4cpp::rseq_t objects, uint64_t now);
    bool Request(const APDUHeader& header, ser4cpp::rseq_t objects, uint64_t now,
                 ser4cpp::wseq_t output, size_t& size, IINField iin, DNPTime time);
    void Transmitted(ser4cpp::rseq_t apdu);
    void Tick(uint64_t now);
    void RecheckCertificates(uint64_t now);
    void Cancel();
    bool Retry(uint64_t now);
    bool CancelOnError(const Group120Var7& error, uint8_t sequence, uint64_t now);
    uint32_t TimeoutMs() const;
    uint32_t ExchangeWindowMs() const;
    uint64_t Deadline() const { return deadline; }
    bool Busy() const { return phase != Phase::IDLE; }
    uint16_t Owner() const { return user; }
    // Contexts invalidate only this user's cached authorization after a durable
    // deletion/key replacement. Zero means no pending invalidation.
    uint16_t TakeInvalidatedUser();

private:
    enum class Phase { IDLE, STATUS, REPLY, CONFIRM, OUTSTATION_REPLY };
    bool Commit(size_t index, const UpdateKeyUser& value);
    bool Install(ser4cpp::rseq_t key, uint64_t now);
    size_t Find(ser4cpp::rseq_t name) const;
    bool Confirmation(bool fromMaster, ser4cpp::rseq_t key, ser4cpp::wseq_t output);
    bool AsymmetricChange(const UpdateKeyUser& record);
    bool VerifyCertification(const Group120Var10& status, ser4cpp::wseq_t certifier);
    bool ReadAsymmetricChange(const Group120Var13& change, const Group120Var14& signature);
    bool MethodAllowed(uint8_t method) const;
    bool ReadCertificateTime(crypto::CertificateTime& time) const;
    crypto::CertificateResult VerifyCertificate(uint8_t type, ser4cpp::rseq_t der, crypto::CertificateTime& time,
                                                crypto::UserCertificate& certificate);
    bool VerifyBinding(const UserCertificateBinding& binding, bool attribute, const crypto::CertificateTime& time) const;
    crypto::CertificateBindingResult CheckBinding(const UserCertificateBinding& binding, bool attribute,
                                                 const crypto::CertificateTime& time) const;
    bool CheckActiveBindings(size_t index, const crypto::CertificateTime& time);
    void RefreshBindings(uint64_t now, const crypto::CertificateTime* time);
    void ReevaluateCertificateTimes(uint64_t now, uint64_t utc);
    bool ResolveAttributeHolder(crypto::UserCertificate& certificate, const crypto::CertificateTime& time,
                                uint64_t now) const;
    bool ReceiveCertificate(const Group120Var8& object, uint8_t sequence, uint64_t now,
                         ser4cpp::wseq_t output, size_t& size, IINField iin);
    bool Error(uint8_t code, uint32_t sequence, uint16_t errorUser, uint8_t appSequence,
               ser4cpp::wseq_t output, size_t& size, IINField iin);
    void ClearExchange();
    void Failure();
    void Expire();
    AuthenticationSession& owner;
    const SessionKeys::Role role;
    std::shared_ptr<IUpdateKeyCredentials> credentials;
    std::array<UpdateKeyUser, MAX_AUTHENTICATION_USERS> users{};
    std::array<uint64_t, MAX_AUTHENTICATION_USERS> expires{}, pendingExpires{};
    std::array<uint64_t, MAX_AUTHENTICATION_USERS> identityDeadlines{}, pendingIdentityDeadlines{};
    std::array<bool, MAX_AUTHENTICATION_USERS> certificateUsable{};
    uint64_t lastCertificateCheck = 0;
    UpdateKeyRequest operation;
    uint16_t certificateRevision = 256;
    std::array<uint8_t, 32> certificateSubject{}, certificateIssuer{};
    UserCertificateBinding certificateBinding;
    std::array<uint8_t, 32> masterChallenge{}, outstationChallenge{}, candidate{};
    std::array<uint8_t, 256> ciphertext{};
    std::array<uint8_t, 72> signature{};
    size_t signatureSize = 0;
    size_t cipherSize = 0, slot = 0;
    uint32_t ksq = 0;
    uint16_t user = 0;
    uint32_t invalidated = 0;
    uint8_t appSequence = 0;
    uint64_t deadline = 0;
    BuildFailure buildFailure = BuildFailure::OTHER;
    uint64_t requestedExpiryUnix = 0, requestedExpiry = 0;
    uint64_t requestedIdentityDeadline = 0;
    uint8_t retries = 0;
    Phase phase = Phase::IDLE;
    bool transmitted = false, everTransmitted = false, changed = false, confirmationReady = false;
    std::array<uint8_t, 512> completedRequest{};
    std::array<uint8_t, 32> completedResponse{};
    size_t completedRequestSize = 0, completedResponseSize = 0;
    uint16_t completedUser = 0;
    uint64_t completedUntil = 0;
    uint64_t lastTime = 0;
    DNPTime errorTime;
    bool loaded = false, haveTrustedTime = false, secureClockAvailable = false, clockFailed = false;
};
}
#endif
