// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/RemoteUpdateKeys.h"

#include "app/APDUResponse.h"
#include "app/parsing/APDUParser.h"
#include "auth/AuthenticationSession.h"
#include "auth/AuthenticationError.h"
#include "crypto/CryptoProvider.h"
#include "crypto/UserCertificate.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace opendnp3
{
namespace
{
    template<size_t N> ser4cpp::rseq_t Read(const std::array<uint8_t, N>& a) { return {a.data(), a.size()}; }
    template<size_t N> ser4cpp::wseq_t Write(std::array<uint8_t, N>& a) { return {a.data(), a.size()}; }
    ser4cpp::rseq_t Name(const UpdateKeyUser& u) { return {u.name.data(), u.nameSize}; }
    // Objects are consumed synchronously. The engine copies only validated,
    // bounded identities/challenges; this parser owns no retained wire views.
    class Objects final : public IAPDUHandler
    {
    public:
        Group120Var8 identity;
        Group120Var10 status;
        Group120Var11 request;
        Group120Var12 reply;
        Group120Var13 change;
        Group120Var14 signature;
        Group120Var15 confirm;
        Group120Var7 error;
        uint8_t first = 0, second = 0;
        bool changeHeader = false;
        bool IsAllowed(uint32_t n, GroupVariation gv, QualifierCode qc) override
        {
            if (qc != QualifierCode::FREE_FORMAT) return false;
            // Native whitelist runs before callbacks, on its own parser pass.
            if (n == 0) changeHeader = gv == GroupVariation::Group120Var13;
            return n == 0 ? (gv == GroupVariation::Group120Var8 || gv == GroupVariation::Group120Var10 || gv == GroupVariation::Group120Var11
                || gv == GroupVariation::Group120Var12 || gv == GroupVariation::Group120Var13
                || gv == GroupVariation::Group120Var15 || gv == GroupVariation::Group120Var7)
                : (n == 1 && changeHeader && (gv == GroupVariation::Group120Var15 || gv == GroupVariation::Group120Var14));
        }
        template<class T> IINField Accept(const ICollection<T>& values, T& value, uint8_t variation)
        {
            if (values.Count() != 1) return IINField(IINBit::PARAM_ERROR);
            values.ForeachItem([&](const T& v) { value = v; });
            if (!first) first = variation; else second = variation;
            return IINField::Empty();
        }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var8>& v) override { return Accept(v, identity, 8); }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var10>& v) override { return Accept(v, status, 10); }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var11>& v) override { return Accept(v, request, 11); }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var12>& v) override { return Accept(v, reply, 12); }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var13>& v) override { return Accept(v, change, 13); }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var14>& v) override { return Accept(v, signature, 14); }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var15>& v) override { return Accept(v, confirm, 15); }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var7>& v) override { return Accept(v, error, 7); }
    };
    template<class T> bool WriteObject(HeaderWriter& writer, const T& value)
    {
        return writer.WriteFreeFormat(&value, 1);
    }
    bool Framed(const APDUHeader& h)
    {
        return h.control.IsFirAndFin() && !h.control.CON && !h.control.UNS;
    }
    uint64_t RemainingDeadline(uint64_t expiry, uint64_t utc, uint64_t monotonic)
    {
        if (expiry <= utc || expiry - utc > std::numeric_limits<uint64_t>::max() - monotonic) return 0;
        return monotonic + (expiry - utc);
    }
}

RemoteUpdateKeys::RemoteUpdateKeys(AuthenticationSession& owner_, SessionKeys::Role role_)
    : owner(owner_), role(role_), credentials(std::dynamic_pointer_cast<IUpdateKeyCredentials>(owner.config.credentials))
{
}
RemoteUpdateKeys::~RemoteUpdateKeys() { ClearExchange(); }
bool RemoteUpdateKeys::MethodAllowed(uint8_t method) const
{
    return method == (owner.config.allowMethod68 ? 68 : 4);
}

bool RemoteUpdateKeys::Load(uint64_t now)
{
    ClearExchange();
    loaded = false;
    invalidated = 0;
    lastTime = now;
    clockFailed = false;
    for (auto& entry : users) entry = UpdateKeyUser();
    expires.fill(0);
    pendingExpires.fill(0);
    identityDeadlines.fill(0);
    pendingIdentityDeadlines.fill(0);
    certificateUsable.fill(true);
    lastCertificateCheck = now;
    const auto& config = owner.config;
    if (!credentials || config.keyWrapAlgorithm != 2 || config.userCapacity < 2
        || config.userCapacity > MAX_AUTHENTICATION_USERS || config.maxUpdateKeyRetries > 10
        || config.users[0] != 1 || config.users[1] != 2
        || !updatekeys::ValidName({config.outstationName.data(), config.outstationNameSize})
        || (config.tagLength != 8 && config.tagLength != 16)
        || (config.transport == AuthenticationConfig::Transport::NETWORK && config.tagLength != 16)
        || (role == SessionKeys::Role::OUTSTATION && !config.updateKeyTrust)
        || (role == SessionKeys::Role::MASTER && config.updateKeyTrust)) return false;
    uint64_t utc = 0;
    bool haveTime = false;
    try
    {
        haveTime = credentials->TrustedUnixTimeMs(utc);
        haveTrustedTime = haveTime;
        secureClockAvailable = haveTime;
        for (size_t n = 0; n < owner.Size(); ++n)
        {
            UpdateKeyUser value;
            if (!credentials->ReadUser(config.association, n, value)) return false;
            if (value.nameSize == 0) continue;
            if (!updatekeys::ValidName(Name(value)) || value.user != n + 1
                || updatekeys::IsCommon(Name(value)) != (value.user == 1)
                || !updatekeys::ValidRole(value.role) || !updatekeys::ValidRole(value.pendingRole)
                // Stored keys and replay state may predate the selected remote method.
                || (value.method != 4 && value.method != 68) || value.publicKeySize > value.publicKey.size()
                || value.certificateRevision > 256
                || (value.certificateRevision < 256
                    && (!config.userCertificatePolicy || value.method != 68 || !value.haveStatusSequence))
                || (value.method == 4 ? value.publicKeySize != 0
                    : !crypto::ValidateMethod68PublicKey({value.publicKey.data(), value.publicKeySize}, false))) return false;
            for (size_t j = 0; j < n; ++j)
                if (Name(users[j]).equals(Name(value)) || (users[j].active && value.active
                    && crypto::ConstantTimeEqual(Read(users[j].updateKey), Read(value.updateKey)))) return false;
            users[n] = value;
            if (value.identity.expiresUnixMs)
            {
                certificateUsable[n] = haveTime && value.expiresUnixMs && CheckActiveBindings(n, {utc, true});
                if (haveTime && value.expiresUnixMs)
                    identityDeadlines[n] = RemainingDeadline(value.identity.expiresUnixMs, utc, now);
            }
            if (haveTime && value.pendingExpiresUnixMs && value.pendingIdentity.expiresUnixMs)
                pendingIdentityDeadlines[n] = RemainingDeadline(value.pendingIdentity.expiresUnixMs, utc, now);
            expires[n] = haveTime ? RemainingDeadline(value.expiresUnixMs, utc, now) : 0;
            pendingExpires[n] = haveTime ? RemainingDeadline(value.pendingExpiresUnixMs, utc, now) : 0;
            // The legacy Common exception cannot bypass the stricter
            // validity policy of a certificate-bound credential.
            if (!haveTime && value.user == 1 && value.active && value.certificateRevision == 256)
                expires[n] = std::numeric_limits<uint64_t>::max();
            if (users[n].active && certificateUsable[n] && expires[n] > now
                && owner.At(n)->Configure(Read(value.updateKey), expires[n], now) != SessionKeys::Result::OK) return false;
        }
    }
    catch (...) { return false; }
    loaded = true;
    return true;
}

size_t RemoteUpdateKeys::Find(ser4cpp::rseq_t name) const
{
    for (size_t n = 0; n < owner.Size(); ++n)
        if (users[n].nameSize && Name(users[n]).equals(name)) return n;
    return owner.Size();
}
bool RemoteUpdateKeys::Commit(size_t index, const UpdateKeyUser& value)
{
    if (index >= owner.Size()) return false;
    bool saved = false;
    try
    {
        saved = credentials->WriteUser(owner.config.association, index, value);
    }
    catch (...) {}
    if (saved) { users[index] = value; return true; }
    // An uncertain persistent write cannot leave cached authorization active.
    // Reload must validate the commit marker before this identity can be used.
    users[index].active = false;
    owner.At(index)->Revoke();
    invalidated |= 1u << index;
    return false;
}
bool RemoteUpdateKeys::Authorize(uint16_t number, uint8_t function, uint64_t now) const
{
    if (!loaded || clockFailed || !number || number > owner.Size()) return false;
    const auto n = number - 1;
    const auto& value = users[n];
    if (!value.active || !certificateUsable[n] || now >= expires[n]) return false;
    // Table 7-12 capability gate for native operations. The explicit application
    // policy additionally restricts points/content. Native file/code/security
    // configuration APIs do not exist: do not grant a coarse file permission
    // that would let SECAUD write or RBACMNT read. Private roles require policy.
    if (value.role >= 32768 && !value.roleMask) return true;
    const uint8_t roles = value.roleMask ? value.roleMask
        : (value.role <= 6 ? static_cast<uint8_t>(1u << value.role) : 0);
    if (function == 0) return true; // Native application CONFIRM, after exact-owner authentication.
    if (function == 1 || function == 23) return (roles & ~(1u << 4)) != 0; // Monitoring/delay measurement.
    if (function >= 3 && function <= 12) return (roles & (1u << 1)) != 0; // Controls/counter freezing.
    if (function == 2 || function == 13 || function == 14 || (function >= 20 && function <= 22)
        || function == 24 || function == 31) return (roles & ((1u << 2) | (1u << 3) | (1u << 6))) != 0;
    return false; // Unsupported file/code operations and separately certified authority procedures.
}
void RemoteUpdateKeys::ClearExchange()
{
    crypto::Clear(Write(masterChallenge));
    crypto::Clear(Write(outstationChallenge));
    crypto::Clear(Write(candidate));
    crypto::Clear(Write(ciphertext));
    crypto::Clear(Write(signature));
    signatureSize = 0;
    operation = UpdateKeyRequest();
    certificateRevision = 256;
    certificateBinding = {};
    phase = Phase::IDLE;
    cipherSize = 0;
    deadline = 0;
    requestedExpiryUnix = requestedExpiry = 0;
    requestedIdentityDeadline = 0;
    retries = 0;
    user = 0;
    transmitted = everTransmitted = changed = confirmationReady = false;
}
void RemoteUpdateKeys::Failure()
{
    if (everTransmitted) owner.statistics.Increment(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES);
    ClearExchange();
}
void RemoteUpdateKeys::Expire()
{
    if (!Busy()) return;
    // Preserve nonzero accounting; an unsent zero-duration stage also expires.
    if (TimeoutMs() == 0) owner.statistics.Increment(SecurityStatistic::REPLY_TIMEOUTS);
    Failure();
}
void RemoteUpdateKeys::Cancel()
{
    Failure();
    crypto::Clear(Write(completedRequest));
    crypto::Clear(Write(completedResponse));
    completedRequestSize = completedResponseSize = 0;
    completedUser = 0;
}
uint32_t RemoteUpdateKeys::TimeoutMs() const { return owner.config.replyTimeoutMs; }
uint32_t RemoteUpdateKeys::ExchangeWindowMs() const
{
    return TimeoutMs() * (1u + owner.config.maxUpdateKeyRetries);
}
bool RemoteUpdateKeys::Retry(uint64_t now)
{
    if (role != SessionKeys::Role::MASTER || !Busy() || !transmitted) return false;
    owner.statistics.Increment(SecurityStatistic::REPLY_TIMEOUTS);
    if (TimeoutMs() == 0 && now >= deadline) { Failure(); return false; }
    if (retries >= owner.config.maxUpdateKeyRetries) { Failure(); return false; }
    ++retries;
    deadline = now + TimeoutMs();
    return true;
}
bool RemoteUpdateKeys::CancelOnError(const Group120Var7& error, uint8_t sequence, uint64_t now)
{
    Tick(now);
    if (role != SessionKeys::Role::OUTSTATION || phase != Phase::OUTSTATION_REPLY || !transmitted
        || !ValidAuthenticationError(error) || error.associationId != owner.config.association
        || error.userNum != user || error.seqNum != ksq || sequence != appSequence) return false;
    Failure();
    return true;
}
void RemoteUpdateKeys::Tick(uint64_t now)
{
    if (!loaded) return;
    if (now < lastTime)
    {
        clockFailed = true;
        Failure();
        for (size_t n = 0; n < owner.Size(); ++n)
        {
            owner.At(n)->Revoke();
            users[n].active = false;
            invalidated |= 1u << n;
        }
    }
    lastTime = now;
    if (clockFailed) return;
    const auto interval = owner.config.userCertificateRecheckIntervalMs;
    const bool recheck = interval && now - lastCertificateCheck >= interval;
    if (!haveTrustedTime || recheck || owner.config.userCertificatePolicy)
    {
        crypto::CertificateTime time{};
        const auto haveTime = ReadCertificateTime(time);
        const bool acquired = haveTime && time.secure && !haveTrustedTime;
        const bool synchronized = haveTime && time.secure && !secureClockAvailable;
        secureClockAvailable = haveTime && time.secure;
        if (acquired)
        {
            haveTrustedTime = true;
            for (size_t n = 0; n < owner.Size(); ++n)
            {
                if (!users[n].pendingIdentity.expiresUnixMs)
                    pendingExpires[n] = RemainingDeadline(users[n].pendingExpiresUnixMs, time.utc, now);
                if (users[n].identity.expiresUnixMs) continue;
                expires[n] = RemainingDeadline(users[n].expiresUnixMs, time.utc, now);
                if (users[n].active && now < expires[n])
                {
                    owner.At(n)->ReplaceUpdateKey(Read(users[n].updateKey), expires[n], now);
                    invalidated |= 1u << n;
                }
            }
        }
        if (haveTime && time.secure && owner.config.userCertificatePolicy)
            ReevaluateCertificateTimes(now, time.utc);
        if (synchronized || recheck) RefreshBindings(now, haveTime ? &time : nullptr);
    }
    // The native Master response timer owns retries/completion. A periodic
    // session service must not consume its timeout before that timer fires.
    if (role == SessionKeys::Role::OUTSTATION && Busy() && now >= deadline) Expire();
    for (size_t n = 0; n < owner.Size(); ++n)
        if (users[n].active && (haveTrustedTime || expires[n]) && now >= expires[n])
        {
            if (users[n].identity.expiresUnixMs)
            {
                auto expired = users[n];
                expired.active = false;
                Commit(n, expired);
            }
            else users[n].active = false;
            owner.At(n)->Revoke();
            invalidated |= 1u << n;
        }
}
uint16_t RemoteUpdateKeys::TakeInvalidatedUser()
{
    for (size_t n = 0; n < owner.Size(); ++n)
        if (invalidated & (1u << n))
        {
            invalidated &= ~(1u << n);
            return owner.At(n)->User();
        }
    return 0;
}
bool RemoteUpdateKeys::Confirmation(bool fromMaster, ser4cpp::rseq_t key, ser4cpp::wseq_t output)
{
    std::array<uint8_t, updatekeys::MAX_NAME + 70> data{};
    size_t size = 0;
    return updatekeys::ConfirmationData(fromMaster,
        {owner.config.outstationName.data(), owner.config.outstationNameSize}, Name(users[slot]),
        Read(masterChallenge), Read(outstationChallenge), ksq, user, Write(data), size)
        && crypto::ComputeHMACSHA256(key, {data.data(), size}, output) == crypto::Result::OK;
}
bool RemoteUpdateKeys::Install(ser4cpp::rseq_t key, uint64_t now)
{
    if (slot >= owner.Size() || key.length() != 32) return false;
    auto next = users[slot];
    const auto expiry = next.pending ? pendingExpires[slot] : expires[slot];
    if (now >= expiry) return false;
    if (!next.pending && !certificateUsable[slot]) return false;
    if (!changed) return next.active && !next.pending; // V15-only verification does not replace Session Keys.
    if (changed)
    {
        // Distinct users must not share an Update Key, and a changed role must
        // not be activated using the previous Update Key.
        for (size_t n = 0; n < owner.Size(); ++n)
            if ((users[n].active || n == slot) && crypto::ConstantTimeEqual(Read(users[n].updateKey), key)) return false;
        std::memcpy(next.updateKey.data(), key, 32);
    }
    if (next.pending)
    {
        if (!changed) return false;
        if (next.pendingIdentity.expiresUnixMs || next.pendingAttribute.expiresUnixMs)
        {
            crypto::CertificateTime time{};
            if (!ReadCertificateTime(time) || now >= pendingIdentityDeadlines[slot]
                || !VerifyBinding(next.pendingIdentity, false, time)
                || (next.pendingAttribute.expiresUnixMs && !VerifyBinding(next.pendingAttribute, true, time))) return false;
            next.identity = next.pendingIdentity;
            next.attribute = next.pendingAttribute;
            next.pendingIdentity = {};
            next.pendingAttribute = {};
        }
        next.role = next.pendingRole;
        next.roleMask = next.pendingRoleMask;
        next.expiresUnixMs = next.pendingExpiresUnixMs;
        next.pending = false;
    }
    next.active = true;
    next.havePendingKey = false;
    crypto::Clear(Write(next.pendingUpdateKey));
    if (!Commit(slot, next)) return false;
    expires[slot] = expiry;
    if (pendingIdentityDeadlines[slot] && next.identity.expiresUnixMs && !next.pending)
    {
        identityDeadlines[slot] = pendingIdentityDeadlines[slot];
        pendingIdentityDeadlines[slot] = 0;
    }
    certificateUsable[slot] = true;
    if (owner.At(slot)->ReplaceUpdateKey(Read(next.updateKey), expiry, now) != SessionKeys::Result::OK) return false;
    invalidated |= 1u << slot;
    return true;
}

bool RemoteUpdateKeys::ReadCertificateTime(crypto::CertificateTime& time) const
{
    try
    {
        time.secure = credentials->TrustedUnixTimeMs(time.utc);
        return time.secure || (owner.config.userCertificatePolicy
            && owner.config.userCertificatePolicy->ReadPKIValidationTime(owner.config.association, time.utc));
    }
    catch (...) { return false; }
}

crypto::CertificateResult RemoteUpdateKeys::VerifyCertificate(uint8_t type, ser4cpp::rseq_t der, crypto::CertificateTime& time,
                                                              crypto::UserCertificate& certificate)
{
    try
    {
        if (owner.config.userCertificatePolicy && ReadCertificateTime(time))
        {
            if (type == 1)
                return crypto::VerifyUserIdentity(*owner.config.userCertificatePolicy, owner.config.association,
                                                  der, time, certificate);
            if (type == 2)
                return crypto::VerifyUserAttribute(*owner.config.userCertificatePolicy, owner.config.association,
                                                   der, time, certificate);
        }
    }
    catch (...) {} // Provider failures never grant access.
    return crypto::CertificateResult::INVALID_DATA;
}

crypto::CertificateBindingResult RemoteUpdateKeys::CheckBinding(const UserCertificateBinding& binding, bool attribute,
                                                               const crypto::CertificateTime& time) const
{
    try
    {
        if (owner.config.userCertificatePolicy)
            return crypto::CheckUserCertificateBinding(*owner.config.userCertificatePolicy, owner.config.association,
                                                       binding, attribute, time);
    }
    catch (...) {}
    return crypto::CertificateBindingResult::INVALID;
}

bool RemoteUpdateKeys::VerifyBinding(const UserCertificateBinding& binding, bool attribute,
                                    const crypto::CertificateTime& time) const
{
    return CheckBinding(binding, attribute, time) == crypto::CertificateBindingResult::VALID;
}

bool RemoteUpdateKeys::CheckActiveBindings(size_t index, const crypto::CertificateTime& time)
{
    auto value = users[index];
    using Check = crypto::CertificateBindingResult;
    const auto id = CheckBinding(value.identity, false, time);
    const auto ac = value.attribute.expiresUnixMs ? CheckBinding(value.attribute, true, time) : Check::VALID;
    const bool revokeID = id == Check::REVOKED && !value.identity.revoked;
    const bool revokeAC = ac == Check::REVOKED && !value.attribute.revoked;
    if (revokeID || revokeAC)
    {
        value.identity.revoked |= revokeID;
        value.attribute.revoked |= revokeAC;
        Commit(index, value);
    }
    return id == Check::VALID && ac == Check::VALID;
}

void RemoteUpdateKeys::RefreshBindings(uint64_t now, const crypto::CertificateTime* time)
{
    lastCertificateCheck = now;
    for (size_t i = 0; i < owner.Size(); ++i)
    {
        const auto& value = users[i];
        if (!value.active || !value.identity.expiresUnixMs) continue;
        const bool usable = time && now < expires[i] && CheckActiveBindings(i, *time);
        if (certificateUsable[i] == usable) continue;
        certificateUsable[i] = usable;
        if (!usable)
        {
            owner.At(i)->Revoke();
            invalidated |= 1u << i;
        }
        else if (now < expires[i])
        {
            if (owner.At(i)->ReplaceUpdateKey(Read(value.updateKey), expires[i], now) == SessionKeys::Result::OK)
                invalidated |= 1u << i;
            else
                certificateUsable[i] = false;
        }
    }
}

void RemoteUpdateKeys::ReevaluateCertificateTimes(uint64_t now, uint64_t utc)
{
    for (size_t i = 0; i < owner.Size(); ++i)
    {
        const auto& userRecord = users[i];
        if (!(userRecord.active && userRecord.identity.expiresUnixMs)
            && !(userRecord.pending && userRecord.pendingIdentity.expiresUnixMs)) continue;
        auto record = userRecord;
        bool save = false;
        auto bound = [&](UserCertificateBinding& id, const UserCertificateBinding& attribute,
                         uint64_t& unixExpiry, uint64_t& deadline, uint64_t& idDeadline) {
            const bool relative = unixExpiry == 0;
            if (relative && !deadline) return false; // A previous process's monotonic deadline is unavailable.
            const auto end = attribute.expiresUnixMs ? std::min(id.expiresUnixMs, attribute.expiresUnixMs)
                                                     : id.expiresUnixMs;
            const auto start = std::max(id.beginsUnixMs, attribute.beginsUnixMs);
            const auto absolute = utc >= start ? RemainingDeadline(relative ? end : std::min(unixExpiry, end), utc, now) : 0;
            if (!absolute || (deadline && deadline <= now))
            {
                deadline = 0;
                return false;
            }
            deadline = deadline ? std::min(deadline, absolute) : absolute;
            const auto absoluteID = RemainingDeadline(id.expiresUnixMs, utc, now);
            idDeadline = idDeadline ? std::min(idDeadline, absoluteID) : absoluteID;
            if (relative)
            {
                // Both sums are bounded by the signed absolute ends above.
                unixExpiry = utc + (deadline - now);
                id.expiresUnixMs = utc + (idDeadline - now);
                save = true;
            }
            return true;
        };
        if (record.active && record.identity.expiresUnixMs
            && !bound(record.identity, record.attribute, record.expiresUnixMs, expires[i], identityDeadlines[i]))
        {
            record.active = false;
            owner.At(i)->Revoke();
            invalidated |= 1u << i;
            save = true;
        }
        if (record.pending && record.pendingIdentity.expiresUnixMs
            && (record.pendingExpiresUnixMs || pendingExpires[i])
            && !bound(record.pendingIdentity, record.pendingAttribute, record.pendingExpiresUnixMs,
                      pendingExpires[i], pendingIdentityDeadlines[i]))
        {
            record.pendingExpiresUnixMs = 0;
            record.havePendingKey = false;
            crypto::Clear(Write(record.pendingUpdateKey));
            save = true;
        }
        if (save) Commit(i, record);
    }
}

void RemoteUpdateKeys::RecheckCertificates(uint64_t now)
{
    if (!loaded || !owner.config.userCertificatePolicy) return;
    Tick(now);
    if (clockFailed) return;
    crypto::CertificateTime time{};
    RefreshBindings(now, ReadCertificateTime(time) ? &time : nullptr);
}

bool RemoteUpdateKeys::ResolveAttributeHolder(crypto::UserCertificate& certificate, const crypto::CertificateTime& time,
                                             uint64_t now) const
{
    const UpdateKeyUser* holder = nullptr;
    for (size_t i = 0; i < owner.Size(); ++i)
    {
        const auto& record = users[i];
        if (!record.identity.expiresUnixMs || !crypto::SameCertificate(record.identity, certificate.holder)) continue;
        if (holder || now >= identityDeadlines[i]) return false;
        holder = &record;
    }
    if (!holder || holder->method != 68 || !VerifyBinding(holder->identity, false, time)) return false;
    auto& status = certificate.status;
    const bool retransmission = holder->certification == status.certification;
    if (holder->pending && (!holder->pendingAttribute.expiresUnixMs || !retransmission)) return false;
    if (holder->statusOperation == 2 && !(status.operation == 2 && retransmission)) return false;
    certificate.subject = holder->certificateSubject;
    certificate.holder = holder->identity;
    certificate.expiresUnixMs = std::min(certificate.expiresUnixMs, holder->identity.expiresUnixMs);
    status.name = holder->name;
    status.nameSize = holder->nameSize;
    status.publicKey = holder->publicKey;
    status.publicKeySize = holder->publicKeySize;
    return true;
}

bool RemoteUpdateKeys::Begin(const UpdateKeyRequest& request, uint64_t now)
{
    Tick(now);
    if (!loaded || clockFailed || role != SessionKeys::Role::MASTER || Busy() || !credentials
        || request.certificateRoleMask) return false;
    const bool usesCertificate = !request.certificate.empty();
    crypto::UserCertificate identity;
    crypto::CertificateTime time{};
    if (usesCertificate && (request.method != 68 || !MethodAllowed(68) || request.verifyOnly
        || request.certificationSize || request.nameSize || request.publicKeySize || request.operation
        || VerifyCertificate(request.certificateType, {request.certificate.data(), request.certificate.size()}, time, identity)
            != crypto::CertificateResult::VALID || (request.certificateType == 2 && !ResolveAttributeHolder(identity, time, now))))
        return false;
    if (usesCertificate) identity.status.source = request.source;
    const auto& value = usesCertificate ? identity.status : request;
    if (!updatekeys::ValidName({value.name.data(), value.nameSize})
        || !MethodAllowed(value.method) || (value.method == 68 && value.nameSize > 126)
        || value.publicKeySize > value.publicKey.size() || value.certificationSize > value.certification.size()
        || (!value.certificationSize && value.operation != 0)
        || (value.certificationSize && value.verifyOnly)
        || (value.certificationSize && (value.method == 4 ? value.certificationSize != owner.config.tagLength
            : (value.certificationSize < 8 || !crypto::ValidateMethod68PublicKey({value.publicKey.data(), value.publicKeySize}, false))))
        || (value.method == 4 && value.publicKeySize)
        || (value.certificationSize && (value.operation < 1 || value.operation > 3 || !updatekeys::ValidRole(value.role)))
        || (!value.verifyOnly && value.operation != 2 && !value.source)) return false;
    operation = value;
    slot = Find({value.name.data(), value.nameSize});
    if (usesCertificate)
    {
        const auto* previousBinding = slot == owner.Size() ? nullptr
            : (value.certificateType == 1 ? &users[slot].identity : &users[slot].attribute);
        if ((slot < owner.Size() && users[slot].certificateRevision < 256
             && (users[slot].certificateSubject != identity.subject
                 || value.statusSequence <= users[slot].statusSequence
                 || identity.revision <= users[slot].certificateRevision))
            || (previousBinding && previousBinding->revoked && crypto::SameCertificate(*previousBinding, identity.binding))
            || (value.operation == 2 && slot == owner.Size()))
        {
            ClearExchange();
            return false;
        }
        operation.certificate = request.certificate;
        certificateRevision = identity.revision;
        certificateSubject = identity.subject;
        certificateIssuer = identity.issuer;
        certificateBinding = identity.binding;
    }
    else if (value.certificationSize && slot < owner.Size() && users[slot].certificateRevision < 256)
    {
        ClearExchange();
        return false;
    }
    if (value.certificationSize && value.operation != 2)
    {
        if (!usesCertificate && (!ReadCertificateTime(time) || !time.secure)) { ClearExchange(); return false; }
        const auto start = time.secure ? time.utc : identity.binding.beginsUnixMs;
        const auto end = time.secure ? identity.expiresUnixMs : identity.binding.expiresUnixMs;
        const uint64_t lifetime = usesCertificate ? end - start : uint64_t(value.expiryDays) * 86400000;
        if ((time.secure && time.utc > std::numeric_limits<uint64_t>::max() - lifetime)
            || now > std::numeric_limits<uint64_t>::max() - lifetime) { ClearExchange(); return false; }
        requestedExpiryUnix = time.secure ? time.utc + lifetime : 0;
        requestedExpiry = now + lifetime;
        if (usesCertificate)
        {
            requestedIdentityDeadline = value.certificateType == 1 ? requestedExpiry : identityDeadlines[slot];
            requestedExpiry = std::min(requestedExpiry, requestedIdentityDeadline);
            if (time.secure) requestedExpiryUnix = time.utc + (requestedExpiry - now);
        }
    }
    if (!value.certificationSize && slot == owner.Size()) { ClearExchange(); return false; }
    if (!value.certificationSize && users[slot].method != value.method) { ClearExchange(); return false; }
    if (!value.certificationSize && !users[slot].pending && !certificateUsable[slot]) { ClearExchange(); return false; }
    phase = value.certificationSize ? Phase::STATUS : Phase::REPLY;
    deadline = now + owner.config.replyTimeoutMs;
    if (crypto::GenerateUpdateKeyChallenge(Write(masterChallenge)) != crypto::Result::OK) { ClearExchange(); return false; }
    return true;
}
bool RemoteUpdateKeys::Build(APDURequest& request, uint8_t sequence, uint64_t now)
{
    buildFailure = BuildFailure::OTHER;
    Tick(now);
    if (Busy() && now >= deadline)
    {
        Expire();
        buildFailure = BuildFailure::TIMEOUT;
        return false;
    }
    if (!loaded || clockFailed || !Busy() || role != SessionKeys::Role::MASTER) return false;
    request.SetControl(AppControlField::Request(sequence));
    request.SetFunction(FunctionCode::AUTH_REQUEST);
    appSequence = sequence;
    auto writer = request.GetWriter();
    const ser4cpp::rseq_t name(operation.name.data(), operation.nameSize);
    if (phase == Phase::STATUS && !operation.certificate.empty())
        return WriteObject(writer, Group120Var8(operation.method, operation.certificateType,
            {operation.certificate.data(), operation.certificate.size()}));
    if (phase == Phase::STATUS)
        return WriteObject(writer, Group120Var10(operation.method, operation.operation, operation.statusSequence, operation.role,
            operation.expiryDays, name, {operation.publicKey.data(), operation.publicKeySize}, {operation.certification.data(), operation.certificationSize}));
    if (phase == Phase::REPLY)
        return WriteObject(writer, Group120Var11(operation.method, name, Read(masterChallenge)));
    if (phase != Phase::CONFIRM) return false;
    if (!operation.verifyOnly && operation.method == 68)
        return WriteObject(writer, Group120Var13(ksq, user, {ciphertext.data(), cipherSize}))
            && WriteObject(writer, Group120Var14({signature.data(), signatureSize}));
    std::array<uint8_t, 16> mac{};
    if (!Confirmation(true, Read(candidate), {mac.data(), owner.config.tagLength})) return false;
    if (!operation.verifyOnly && !WriteObject(writer, Group120Var13(ksq, user, {ciphertext.data(), cipherSize}))) return false;
    return WriteObject(writer, Group120Var15({mac.data(), owner.config.tagLength}));
}

RemoteUpdateKeys::Result RemoteUpdateKeys::Response(const APDUResponseHeader& header, ser4cpp::rseq_t objects, uint64_t now)
{
    Tick(now);
    if (Busy() && now >= deadline) { Expire(); return Result::IGNORED; }
    if (!loaded || clockFailed || !Busy() || role != SessionKeys::Role::MASTER || !transmitted || !Framed(header)
        || header.control.SEQ != appSequence) return Result::IGNORED;
    Objects value;
    if (!objects.is_empty() && (APDUParser::Parse(objects, value, nullptr) != ParseResult::OK || value.Errors().Any()))
        return Result::IGNORED;
    if (value.first == 7)
    {
        if (header.function != FunctionCode::AUTH_RESPONSE || !ValidAuthenticationError(value.error)
            || value.error.associationId != owner.config.association || value.error.userNum != user
            || (value.error.seqNum != (phase == Phase::STATUS ? operation.statusSequence : ksq)
                && !(phase == Phase::STATUS && !operation.certificate.empty()
                     && !value.error.seqNum && value.error.errorCode >= 8 && value.error.errorCode <= 10))) return Result::IGNORED;
        Failure();
        owner.statistics.Increment(SecurityStatistic::ERROR_MESSAGES_RECEIVED);
        if (owner.config.errorObserver)
        {
            try { owner.config.errorObserver->OnErrorReceived(owner.config.association, value.error.userNum,
                value.error.seqNum, value.error.errorCode, true); }
            catch (...) {} // Diagnostics cannot change the completed exchange.
        }
        return Result::FAILED;
    }
    if (phase == Phase::STATUS)
    {
        const auto expected = operation.certificate.empty() ? FunctionCode::RESPONSE : FunctionCode::AUTH_RESPONSE;
        if (header.function != expected || !objects.is_empty()) return Result::IGNORED;
        if (header.IIN.HasRequestError()) { Failure(); return Result::FAILED; }
        if (operation.operation == 2)
        {
            if (slot < owner.Size())
            {
                auto record = users[slot];
                record.active = record.pending = record.havePendingKey = false;
                record.statusSequence = operation.statusSequence;
                record.haveStatusSequence = true;
                if (!operation.certificate.empty())
                {
                    record.method = operation.method;
                    record.publicKey = operation.publicKey;
                    record.publicKeySize = operation.publicKeySize;
                    record.certificateRevision = certificateRevision;
                    record.certificateSubject = certificateSubject;
                    record.certificationKeyFingerprint = certificateIssuer;
                    record.statusOperation = operation.operation;
                    record.certification = operation.certification;
                    record.certificationSize = operation.certificationSize;
                    record.pendingIdentity = {};
                    record.pendingAttribute = {};
                }
                crypto::Clear(Write(record.updateKey));
                crypto::Clear(Write(record.pendingUpdateKey));
                if (!Commit(slot, record)) { Failure(); return Result::FAILED; }
                owner.At(slot)->Revoke();
                invalidated |= 1u << slot;
            }
            ClearExchange();
            return Result::COMPLETE;
        }
        phase = Phase::REPLY;
        retries = 0;
        transmitted = false;
        deadline = now + owner.config.replyTimeoutMs;
        return Result::CONTINUE;
    }
    if (header.function != FunctionCode::AUTH_RESPONSE || header.IIN.HasRequestError()) return Result::IGNORED;
    if (phase == Phase::REPLY && value.first == 12 && !value.second)
    {
        if (value.reply.challengeData.length() != 32 || value.reply.userNum == 0 || value.reply.userNum > owner.Size()) return Result::IGNORED;
        const auto number = value.reply.userNum;
        const auto index = number - 1;
        if ((slot < owner.Size() && slot != index)
            || (users[index].nameSize && !Name(users[index]).equals({operation.name.data(), operation.nameSize}))
            || updatekeys::IsCommon({operation.name.data(), operation.nameSize}) != (number == 1)) return Result::IGNORED;
        user = number;
        ksq = value.reply.seqNum;
        std::memcpy(outstationChallenge.data(), value.reply.challengeData, 32);
        slot = index;
        auto record = users[slot];
        record.user = user;
        record.name = operation.name;
        record.nameSize = operation.nameSize;
        if (operation.certificationSize)
        {
            record.method = operation.method;
            record.publicKey = operation.publicKey;
            record.publicKeySize = operation.publicKeySize;
        }
        if (operation.verifyOnly)
        {
            if (record.havePendingKey) { candidate = record.pendingUpdateKey; changed = true; }
            else if (record.active) candidate = record.updateKey;
            else { Failure(); return Result::FAILED; }
        }
        else
        {
            bool provided = false;
            try
            {
                provided = operation.method == 68 ? AsymmetricChange(record)
                    : operation.source->GetKey(owner.config.association, operation.name.data(), operation.nameSize,
                        masterChallenge.data(), outstationChallenge.data(), ksq, user, candidate.data(),
                        ciphertext.data(), ciphertext.size(), cipherSize);
            }
            catch (...) {}
            if (!provided || (operation.method == 68 ? cipherSize != 256 : (cipherSize < 24 || cipherSize > 208 || cipherSize % 8)))
            { Failure(); return Result::FAILED; }
            record.havePendingKey = true;
            record.pendingUpdateKey = candidate;
            changed = true;
        }
        if (operation.certificationSize)
        {
            record.haveStatusSequence = true;
            record.statusSequence = operation.statusSequence;
            record.statusOperation = operation.operation;
            record.statusExpiryDays = operation.expiryDays;
            record.certification = operation.certification;
            record.certificationSize = operation.certificationSize;
            record.pending = true;
            record.pendingRole = operation.role;
            record.pendingRoleMask = operation.certificateRoleMask;
            record.pendingExpiresUnixMs = requestedExpiryUnix;
            pendingExpires[slot] = requestedExpiry;
            pendingIdentityDeadlines[slot] = requestedIdentityDeadline;
            if (!operation.certificate.empty())
            {
                record.certificateRevision = certificateRevision;
                record.certificateSubject = certificateSubject;
                record.certificationKeyFingerprint = certificateIssuer;
                record.pendingIdentity = operation.certificateType == 1 ? certificateBinding : record.identity;
                record.pendingAttribute = operation.certificateType == 2 ? certificateBinding : UserCertificateBinding{};
            }
        }
        if (!Commit(slot, record)) { Failure(); return Result::FAILED; }
        phase = Phase::CONFIRM;
        retries = 0;
        transmitted = false;
        deadline = now + owner.config.replyTimeoutMs;
        return Result::CONTINUE;
    }
    if (phase == Phase::CONFIRM && value.first == 15 && !value.second)
    {
        std::array<uint8_t, 16> expected{};
        const bool authenticated = value.confirm.hmacValue.length() == owner.config.tagLength
            && Confirmation(false, Read(candidate), {expected.data(), owner.config.tagLength})
            && crypto::ConstantTimeEqual({expected.data(), owner.config.tagLength}, value.confirm.hmacValue);
        if (!authenticated)
        {
            owner.statistics.AuthenticationFailed(user);
            Failure();
            return Result::FAILED;
        }
        if (!Install(Read(candidate), now)) { Failure(); return Result::FAILED; }
        owner.statistics.Increment(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);
        if (changed) owner.statistics.Increment(SecurityStatistic::UPDATE_KEY_CHANGES);
        ClearExchange();
        return Result::COMPLETE;
    }
    return Result::IGNORED;
}

bool RemoteUpdateKeys::AsymmetricChange(const UpdateKeyUser& record)
{
    struct Material
    {
        std::array<uint8_t, 2048> privateKey{};
        std::array<uint8_t, 1024> outstationKey{};
        std::array<uint8_t, 200> plain{};
        ~Material() { crypto::Clear(Write(privateKey)); crypto::Clear(Write(plain)); }
    } material;
    size_t privateSize = 0, publicSize = 0, plainSize = 0, transcriptSize = 0;
    bool supplied = false;
    try { supplied = operation.source->GetAsymmetricKey(owner.config.association, operation.name.data(), operation.nameSize,
        candidate.data(), material.privateKey.data(), material.privateKey.size(), privateSize,
        material.outstationKey.data(), material.outstationKey.size(), publicSize); } catch (...) {}
    std::array<uint8_t, 512> transcript{};
    if (!supplied || privateSize > material.privateKey.size() || publicSize > material.outstationKey.size()
        || !updatekeys::KeyData(Name(record), Read(candidate), Read(outstationChallenge), Write(material.plain), plainSize, false)
        || crypto::RSAOAEP2048Encrypt({material.outstationKey.data(), publicSize}, {material.plain.data(), plainSize}, Write(ciphertext)) != crypto::Result::OK
        || !updatekeys::SignatureData({owner.config.outstationName.data(), owner.config.outstationNameSize}, Name(record),
            Read(masterChallenge), Read(outstationChallenge), ksq, user, Read(ciphertext), Write(transcript), transcriptSize)
        || crypto::DSASHA256Sign({material.privateKey.data(), privateSize}, {transcript.data(), transcriptSize}, Write(signature), signatureSize) != crypto::Result::OK
        || crypto::DSASHA256Verify({record.publicKey.data(), record.publicKeySize}, {transcript.data(), transcriptSize},
            {signature.data(), signatureSize}) != crypto::Result::OK) return false;
    cipherSize = ciphertext.size();
    return true;
}
bool RemoteUpdateKeys::VerifyCertification(const Group120Var10& status, ser4cpp::wseq_t certifier)
{
    std::array<uint8_t, 1200> message{};
    size_t length = 0;
    if (status.keyChangeMethod == 68 && status.userName.length() > 126) return false;
    if (!updatekeys::CertificationData(status, Write(message), length)) return false;
    bool trusted = false, authenticated = false, fingerprint = false;
    if (status.keyChangeMethod == 4)
    {
        std::array<uint8_t, 32> key{};
        try { trusted = owner.config.updateKeyTrust->ReadCertificationKey(owner.config.association, key.data(), key.size()); } catch (...) {}
        authenticated = trusted && status.certificationData.length() == owner.config.tagLength
            && updatekeys::VerifyMAC(Read(key), {message.data(), length}, status.certificationData);
        if (authenticated) fingerprint = crypto::SHA256(Read(key), certifier) == crypto::Result::OK;
        crypto::Clear(Write(key));
    }
    else
    {
        std::array<uint8_t, 1024> key{};
        size_t size = 0;
        try { trusted = owner.config.updateKeyTrust->ReadAuthorityPublicKey(owner.config.association, key.data(), key.size(), size); } catch (...) {}
        trusted = trusted && size <= key.size() && crypto::ValidateMethod68PublicKey({key.data(), size}, false);
        authenticated = trusted && crypto::DSASHA256Verify({key.data(), size}, {message.data(), length}, status.certificationData) == crypto::Result::OK;
        if (authenticated) fingerprint = crypto::ValidateMethod68PublicKey(status.userPublicKey, false)
            && crypto::SHA256({key.data(), size}, certifier) == crypto::Result::OK;
    }
    if (trusted && !authenticated) owner.statistics.AuthenticationFailed(0);
    return authenticated && fingerprint;
}
bool RemoteUpdateKeys::ReadAsymmetricChange(const Group120Var13& change, const Group120Var14& proof)
{
    std::array<uint8_t, 512> transcript{};
    size_t transcriptSize = 0;
    if (!updatekeys::SignatureData({owner.config.outstationName.data(), owner.config.outstationNameSize}, Name(users[slot]),
        Read(masterChallenge), Read(outstationChallenge), ksq, user, change.encryptedUpdateKey, Write(transcript), transcriptSize)
        || crypto::DSASHA256Verify({users[slot].publicKey.data(), users[slot].publicKeySize}, {transcript.data(), transcriptSize},
            proof.digitalSignature) != crypto::Result::OK) return false;
    struct Material
    {
        std::array<uint8_t, 2048> privateKey{};
        std::array<uint8_t, 200> plain{};
        ~Material() { crypto::Clear(Write(privateKey)); crypto::Clear(Write(plain)); }
    } material;
    size_t keySize = 0, plainSize = 0;
    bool trusted = false;
    try { trusted = owner.config.updateKeyTrust->ReadOutstationPrivateKey(owner.config.association, material.privateKey.data(), material.privateKey.size(), keySize); } catch (...) {}
    return trusted && keySize <= material.privateKey.size()
        && crypto::RSAOAEP2048Decrypt({material.privateKey.data(), keySize}, change.encryptedUpdateKey, Write(material.plain), plainSize) == crypto::Result::OK
        && updatekeys::ReadKeyData({material.plain.data(), plainSize}, Name(users[slot]), Read(outstationChallenge), Write(candidate), false);
}

bool RemoteUpdateKeys::Error(uint8_t code, uint32_t sequence, uint16_t errorUser, uint8_t sequenceAPDU,
                            ser4cpp::wseq_t output, size_t& size, IINField iin)
{
    size = 0;
    if (owner.config.suppressAuthenticationErrors || owner.statistics.Exceeded(SecurityStatistic::ERROR_MESSAGES_SENT)
        || errorTime.quality == TimestampQuality::INVALID || errorTime.value > 0xFFFFFFFFFFFFULL) return false;
    APDUResponse response(output);
    response.SetFunction(FunctionCode::AUTH_RESPONSE);
    response.SetControl(AppControlField(true, true, false, false, sequenceAPDU));
    response.SetIIN(iin);
    auto writer = response.GetWriter();
    if (!WriteObject(writer, Group120Var7(sequence, errorUser, owner.config.association, code, errorTime, {}))) return false;
    size = response.Size();
    return true;
}

bool RemoteUpdateKeys::ReceiveCertificate(const Group120Var8& object, uint8_t sequence, uint64_t now,
                                       ser4cpp::wseq_t output, size_t& size, IINField iin)
{
    if (object.keyChangeMethod != 68 || !MethodAllowed(68))
        return Error(8, 0, 0, sequence, output, size, iin);
    if (object.certificateType != 1 && object.certificateType != 2)
        return Error(10, 0, 0, sequence, output, size, iin);
    crypto::UserCertificate identity;
    crypto::CertificateTime time{};
    const auto verified = VerifyCertificate(object.certificateType, object.certificate, time, identity);
    if (verified != crypto::CertificateResult::VALID)
        return Error(verified == crypto::CertificateResult::INVALID_SIGNATURE ? 9 : 10, 0, 0,
                     sequence, output, size, iin);
    if (object.certificateType == 2 && !ResolveAttributeHolder(identity, time, now))
        return Error(10, identity.status.statusSequence, 0, sequence, output, size, iin);
    const auto& status = identity.status;
    const ser4cpp::rseq_t name(status.name.data(), status.nameSize);
    auto index = Find(name);
    if (index == owner.Size() && status.operation == 1)
    {
        const size_t first = updatekeys::IsCommon(name) ? 0 : 1;
        const size_t end = updatekeys::IsCommon(name) ? 1 : owner.Size();
        for (size_t n = first; n < end; ++n)
            if (!users[n].nameSize) { index = n; break; }
    }
    if (index == owner.Size()) return Error(10, status.statusSequence, 0, sequence, output, size, iin);

    const auto& previous = users[index];
    const auto& previousBinding = object.certificateType == 1 ? previous.identity : previous.attribute;
    if (previousBinding.revoked && crypto::SameCertificate(previousBinding, identity.binding))
        return Error(10, status.statusSequence, 0, sequence, output, size, iin);
    const bool duplicate = previous.certificateRevision == identity.revision
        && previous.statusSequence == status.statusSequence && previous.certification == status.certification
        && previous.certificateSubject == identity.subject && previous.certificationKeyFingerprint == identity.issuer
        && (previous.pending || previous.statusOperation == 2);
    if (duplicate && previous.pending && now >= pendingExpires[index])
        return Error(10, status.statusSequence, 0, sequence, output, size, iin);
    if (!duplicate)
    {
        const auto start = time.secure ? time.utc : identity.binding.beginsUnixMs;
        const auto end = time.secure ? identity.expiresUnixMs : identity.binding.expiresUnixMs;
        const auto remaining = end - start;
        if ((previous.haveStatusSequence && status.statusSequence <= previous.statusSequence)
            || (previous.certificateRevision < 256 && (identity.revision <= previous.certificateRevision
                || previous.certificateSubject != identity.subject))
            || (status.operation == 1 ? previous.active : !previous.nameSize)
            || remaining > std::numeric_limits<uint64_t>::max() - now)
            return Error(10, status.statusSequence, 0, sequence, output, size, iin);
        auto next = previous;
        next.name = status.name;
        next.nameSize = status.nameSize;
        next.user = static_cast<uint16_t>(index + 1);
        next.method = 68;
        next.publicKey = status.publicKey;
        next.publicKeySize = status.publicKeySize;
        next.haveStatusSequence = true;
        next.statusSequence = status.statusSequence;
        next.statusOperation = status.operation;
        next.statusExpiryDays = 0;
        next.certification = status.certification;
        next.certificationSize = status.certificationSize;
        next.certificationKeyFingerprint = identity.issuer;
        next.certificateRevision = identity.revision;
        next.certificateSubject = identity.subject;
        next.pending = status.operation != 2;
        next.pendingRole = status.role;
        next.pendingRoleMask = status.certificateRoleMask;
        const auto idDeadline = object.certificateType == 1 ? now + remaining : identityDeadlines[index];
        const auto roleDeadline = std::min(now + remaining, idDeadline);
        next.pendingExpiresUnixMs = time.secure ? time.utc + (roleDeadline - now) : 0;
        next.pendingIdentity = object.certificateType == 1 ? identity.binding : identity.holder;
        next.pendingAttribute = object.certificateType == 2 ? identity.binding : UserCertificateBinding{};
        if (!next.pending)
        {
            next.active = next.havePendingKey = false;
            crypto::Clear(Write(next.updateKey));
            crypto::Clear(Write(next.pendingUpdateKey));
            next.pendingIdentity = {};
            next.pendingAttribute = {};
        }
        if (!Commit(index, next)) return false;
        if (Busy() && user == next.user) Failure();
        pendingExpires[index] = next.pending ? roleDeadline : 0;
        pendingIdentityDeadlines[index] = next.pending ? idDeadline : 0;
        if (!next.pending)
        {
            if (completedUser == next.user) completedRequestSize = completedResponseSize = 0;
            owner.At(index)->Revoke();
            invalidated |= 1u << index;
        }
    }
    APDUResponse response(output);
    response.SetFunction(FunctionCode::AUTH_RESPONSE);
    response.SetControl(AppControlField(true, true, false, false, sequence));
    response.SetIIN(iin);
    size = response.Size();
    return true;
}

bool RemoteUpdateKeys::Request(const APDUHeader& header, ser4cpp::rseq_t objects, uint64_t now,
                              ser4cpp::wseq_t output, size_t& size, IINField iin, DNPTime time)
{
    size = 0;
    errorTime = time;
    Tick(now);
    if (!loaded || clockFailed || role != SessionKeys::Role::OUTSTATION || header.function != FunctionCode::AUTH_REQUEST || !Framed(header)
        || !static_cast<uint8_t*>(output) || output.length() < 4) return false;
    Objects value;
    if (APDUParser::Parse(objects, value, nullptr) != ParseResult::OK || value.Errors().Any()) return false;
    if (value.first == 8 && !value.second)
        return ReceiveCertificate(value.identity, header.control.SEQ, now, output, size, iin);
    // Retransmitting an already verified, byte-identical change can repeat its
    // confirmation, but cannot reinstall credentials or increment statistics.
    if (completedRequestSize && now < completedUntil && completedUser && completedUser <= owner.Size()
        && users[completedUser - 1].active && certificateUsable[completedUser - 1] && now < expires[completedUser - 1]
        && objects.equals({completedRequest.data(), completedRequestSize})
        && header.control.SEQ == (completedResponse[0] & 15) && output.length() >= completedResponseSize)
    {
        std::memcpy(output, completedResponse.data(), completedResponseSize);
        size = completedResponseSize;
        return true;
    }
    if (value.first == 10 && !value.second)
    {
        const auto& status = value.status;
        if (!MethodAllowed(status.keyChangeMethod)) return Error(8, status.seqNum, 0, header.control.SEQ, output, size, iin);
        std::array<uint8_t, 32> certifier{};
        if (!VerifyCertification(status, Write(certifier))) return Error(10, status.seqNum, 0, header.control.SEQ, output, size, iin);
        auto index = Find(status.userName);
        if (index < owner.Size() && users[index].certificateRevision < 256)
            return Error(10, status.seqNum, 0, header.control.SEQ, output, size, iin);
        if (index < owner.Size() && users[index].haveStatusSequence && status.seqNum == users[index].statusSequence
            && users[index].statusOperation == status.operation && users[index].pendingRole == status.userRole
            && users[index].statusExpiryDays == status.userRoleExpiryDays
            && users[index].method == status.keyChangeMethod
            && ser4cpp::rseq_t(users[index].publicKey.data(), users[index].publicKeySize).equals(status.userPublicKey)
            && users[index].certificationSize == status.certificationData.length()
            && crypto::ConstantTimeEqual({users[index].certification.data(), users[index].certificationSize}, status.certificationData))
        {
            APDUResponse response(output);
            response.SetFunction(FunctionCode::RESPONSE);
            response.SetControl(AppControlField(true, true, false, false, header.control.SEQ));
            response.SetIIN(iin);
            size = response.Size();
            return true; // Lost V10 acknowledgement, not a new authority decision.
        }
        if (index == owner.Size() && status.operation == 1)
        {
            const size_t first = updatekeys::IsCommon(status.userName) ? 0 : 1;
            for (size_t n = first; n < owner.Size(); ++n)
                if (users[n].nameSize == 0)
                { index = n; break; }
        }
        // 7.5.5.5 requires strictly newer SCS. Algorithm/key changes cannot
        // reset this watermark: another configured authority method could still
        // validate historical certifications. Named tombstones are never evicted.
        // RUK-OPEN-01 records the conflicting A.45.10 wrap requirement.
        if (index >= owner.Size() || (users[index].haveStatusSequence
            && status.seqNum <= users[index].statusSequence)
            || (status.operation == 1 && users[index].active)
            || (status.operation != 1 && !users[index].nameSize)) return Error(10, status.seqNum, 0, header.control.SEQ, output, size, iin);
        uint64_t utc = 0;
        uint64_t lifetime = 0;
        if (status.operation != 2)
        {
            try { if (!credentials->TrustedUnixTimeMs(utc)) return false; }
            catch (...) { return false; }
            lifetime = uint64_t(status.userRoleExpiryDays) * 86400000;
            if (utc > std::numeric_limits<uint64_t>::max() - lifetime || now > std::numeric_limits<uint64_t>::max() - lifetime) return false;
        } // An authenticated DELETE revokes immediately, even without trusted UTC.
        auto next = users[index];
        if (!Name(next).equals(status.userName)) next = UpdateKeyUser();
        std::memcpy(next.name.data(), status.userName, status.userName.length());
        next.nameSize = static_cast<uint16_t>(status.userName.length());
        next.user = static_cast<uint16_t>(index + 1);
        next.method = status.keyChangeMethod;
        next.publicKeySize = static_cast<uint16_t>(status.userPublicKey.length());
        next.publicKey.fill(0);
        if (next.publicKeySize) std::memcpy(next.publicKey.data(), status.userPublicKey, next.publicKeySize);
        next.haveStatusSequence = true;
        next.statusSequence = status.seqNum;
        next.certificationKeyFingerprint = certifier;
        next.statusOperation = status.operation;
        next.statusExpiryDays = status.userRoleExpiryDays;
        next.certificationSize = static_cast<uint8_t>(status.certificationData.length());
        std::memcpy(next.certification.data(), status.certificationData, next.certificationSize);
        next.pending = status.operation != 2;
        next.pendingRole = status.userRole;
        next.pendingExpiresUnixMs = utc + lifetime;
        if (status.operation == 2)
        {
            if (completedUser == next.user) completedRequestSize = completedResponseSize = 0;
            next.active = false;
            next.havePendingKey = false;
            crypto::Clear(Write(next.updateKey));
            crypto::Clear(Write(next.pendingUpdateKey));
        }
        if (!Commit(index, next)) return false;
        if (Busy() && user == index + 1) Failure(); // Only the now-obsolete authority decision's exchange.
        pendingExpires[index] = now + lifetime;
        if (status.operation == 2)
        {
            owner.At(index)->Revoke();
            invalidated |= 1u << index;
        }
        APDUResponse response(output);
        response.SetFunction(FunctionCode::RESPONSE);
        response.SetControl(AppControlField(true, true, false, false, header.control.SEQ));
        response.SetIIN(iin);
        size = response.Size();
        return true;
    }
    if (value.first == 11 && !value.second)
    {
        if (!MethodAllowed(value.request.keyChangeMethod)) return Error(8, 0, 0, header.control.SEQ, output, size, iin);
        if (Busy())
        {
            if (phase != Phase::OUTSTATION_REPLY || value.request.keyChangeMethod != users[slot].method
                || !Name(users[slot]).equals(value.request.userName)
                || !Read(masterChallenge).equals(value.request.challengeData)) return false;
            APDUResponse response(output);
            response.SetFunction(FunctionCode::AUTH_RESPONSE);
            response.SetControl(AppControlField(true, true, false, false, header.control.SEQ));
            response.SetIIN(iin);
            auto writer = response.GetWriter();
            if (!WriteObject(writer, Group120Var12(ksq, user, Read(outstationChallenge)))) return false;
            appSequence = header.control.SEQ;
            size = response.Size();
            return true;
        }
        const auto index = Find(value.request.userName);
        if (index >= owner.Size() || value.request.challengeData.length() != 32
            || now >= (users[index].pending ? pendingExpires[index] : expires[index])
            || (!users[index].pending && !certificateUsable[index]))
            return Error(11, 0, 0, header.control.SEQ, output, size, iin);
        if (users[index].method != value.request.keyChangeMethod) return Error(8, 0, 0, header.control.SEQ, output, size, iin);
        if (!owner.At(index)->NextUpdateKeySequence(ksq)) return false;
        slot = index;
        user = users[index].user;
        std::memcpy(masterChallenge.data(), value.request.challengeData, 32);
        if (crypto::GenerateUpdateKeyChallenge(Write(outstationChallenge)) != crypto::Result::OK) { ClearExchange(); return false; }
        APDUResponse response(output);
        response.SetFunction(FunctionCode::AUTH_RESPONSE);
        response.SetControl(AppControlField(true, true, false, false, header.control.SEQ));
        response.SetIIN(iin);
        auto writer = response.GetWriter();
        if (!WriteObject(writer, Group120Var12(ksq, user, Read(outstationChallenge)))) { ClearExchange(); return false; }
        phase = Phase::OUTSTATION_REPLY;
        appSequence = header.control.SEQ;
        deadline = now + ExchangeWindowMs();
        size = response.Size();
        return true;
    }
    if (phase != Phase::OUTSTATION_REPLY || !transmitted || (value.first != 13 && value.first != 15)
        || header.control.SEQ != ((appSequence + 1) & 15)) return false;
    const bool changing = value.first == 13;
    const bool asymmetric = users[slot].method == 68;
    if (changing && (value.second != (asymmetric ? 14 : 15) || value.change.seqNum != ksq || value.change.userNum != user)) return false;
    if (!changing && value.second) return false;
    bool keyOK = true;
    if (changing && asymmetric) keyOK = ReadAsymmetricChange(value.change, value.signature);
    else if (changing)
    {
        std::array<uint8_t, 32> authorityKey{};
        std::array<uint8_t, 200> plain{};
        const auto encrypted = value.change.encryptedUpdateKey;
        bool trusted = false;
        try { trusted = owner.config.updateKeyTrust->ReadCertificationKey(owner.config.association, authorityKey.data(), authorityKey.size()); }
        catch (...) {}
        keyOK = trusted && encrypted.length() >= 24 && encrypted.length() <= 208 && encrypted.length() % 8 == 0
            && crypto::AES256KeyUnwrap(Read(authorityKey), encrypted, {plain.data(), encrypted.length() - 8}) == crypto::Result::OK
            && updatekeys::ReadKeyData({plain.data(), encrypted.length() - 8}, Name(users[slot]), Read(outstationChallenge), Write(candidate));
        crypto::Clear(Write(authorityKey));
        crypto::Clear(Write(plain));
    }
    else if (users[slot].active && now < expires[slot] && !users[slot].pending) candidate = users[slot].updateKey;
    else keyOK = false;
    std::array<uint8_t, 16> expected{};
    const bool authenticated = keyOK && ((changing && asymmetric)
        || (value.confirm.hmacValue.length() == owner.config.tagLength
            && Confirmation(true, Read(candidate), {expected.data(), owner.config.tagLength})
            && crypto::ConstantTimeEqual({expected.data(), owner.config.tagLength}, value.confirm.hmacValue)));
    if (!authenticated)
    {
        const auto failedSequence = ksq;
        const auto failedUser = user;
        Failure();
        owner.statistics.AuthenticationFailed(failedUser);
        return Error(1, failedSequence, failedUser, header.control.SEQ, output, size, iin);
    }
    changed = changing;
    if (output.length() < 10u + owner.config.tagLength) return false;
    if (!Confirmation(false, Read(candidate), {expected.data(), owner.config.tagLength}) || !Install(Read(candidate), now))
    { Failure(); return false; }
    APDUResponse response(output);
    response.SetFunction(FunctionCode::AUTH_RESPONSE);
    response.SetControl(AppControlField(true, true, false, false, header.control.SEQ));
    response.SetIIN(iin);
    auto writer = response.GetWriter();
    if (!WriteObject(writer, Group120Var15({expected.data(), owner.config.tagLength}))) { Failure(); return false; }
    confirmationReady = true;
    size = response.Size();
    if (objects.length() <= completedRequest.size() && size <= completedResponse.size())
    {
        std::memcpy(completedRequest.data(), objects, objects.length());
        completedRequestSize = objects.length();
        std::memcpy(completedResponse.data(), static_cast<uint8_t*>(output), size);
        completedResponseSize = size;
        completedUser = user;
        completedUntil = std::min(now + ExchangeWindowMs(), expires[slot]);
    }
    return true;
}
void RemoteUpdateKeys::Transmitted(ser4cpp::rseq_t apdu)
{
    const auto offset = role == SessionKeys::Role::MASTER ? 2u : 4u;
    if (apdu.length() < offset + 2 || apdu[offset] != 120) return;
    if (Busy()) transmitted = everTransmitted = true;
    if (role == SessionKeys::Role::OUTSTATION && confirmationReady && apdu[offset + 1] == 15)
    {
        owner.statistics.Increment(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);
        if (changed) owner.statistics.Increment(SecurityStatistic::UPDATE_KEY_CHANGES);
        ClearExchange();
    }
}
}
