// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/RemoteUpdateKeys.h"

#include "app/APDUResponse.h"
#include "app/parsing/APDUParser.h"
#include "auth/AuthenticationSession.h"
#include "auth/AuthenticationError.h"
#include "crypto/CryptoProvider.h"

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
        Group120Var10 status;
        Group120Var11 request;
        Group120Var12 reply;
        Group120Var13 change;
        Group120Var15 confirm;
        Group120Var7 error;
        uint8_t first = 0, second = 0;
        bool changeHeader = false;
        bool IsAllowed(uint32_t n, GroupVariation gv, QualifierCode qc) override
        {
            if (qc != QualifierCode::FREE_FORMAT) return false;
            // Native whitelist runs before callbacks, on its own parser pass.
            if (n == 0) changeHeader = gv == GroupVariation::Group120Var13;
            return n == 0 ? (gv == GroupVariation::Group120Var10 || gv == GroupVariation::Group120Var11
                || gv == GroupVariation::Group120Var12 || gv == GroupVariation::Group120Var13
                || gv == GroupVariation::Group120Var15 || gv == GroupVariation::Group120Var7)
                : (n == 1 && changeHeader && gv == GroupVariation::Group120Var15);
        }
        template<class T> IINField Accept(const ICollection<T>& values, T& value, uint8_t variation)
        {
            if (values.Count() != 1) return IINField(IINBit::PARAM_ERROR);
            values.ForeachItem([&](const T& v) { value = v; });
            if (!first) first = variation; else second = variation;
            return IINField::Empty();
        }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var10>& v) override { return Accept(v, status, 10); }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var11>& v) override { return Accept(v, request, 11); }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var12>& v) override { return Accept(v, reply, 12); }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var13>& v) override { return Accept(v, change, 13); }
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
        return monotonic + expiry - utc;
    }
}

RemoteUpdateKeys::RemoteUpdateKeys(AuthenticationSession& owner_, SessionKeys::Role role_)
    : owner(owner_), role(role_), credentials(std::dynamic_pointer_cast<IUpdateKeyCredentials>(owner.config.credentials))
{
}
RemoteUpdateKeys::~RemoteUpdateKeys() { ClearExchange(); }

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
        for (size_t n = 0; n < owner.Size(); ++n)
        {
            UpdateKeyUser value;
            if (!credentials->ReadUser(config.association, n, value)) return false;
            if (value.nameSize == 0) continue;
            if (!updatekeys::ValidName(Name(value)) || value.user != n + 1
                || updatekeys::IsCommon(Name(value)) != (value.user == 1)
                || !updatekeys::ValidRole(value.role) || !updatekeys::ValidRole(value.pendingRole)) return false;
            for (size_t j = 0; j < n; ++j)
                if (Name(users[j]).equals(Name(value)) || (users[j].active && value.active
                    && crypto::ConstantTimeEqual(Read(users[j].updateKey), Read(value.updateKey)))) return false;
            users[n] = value;
            expires[n] = haveTime ? RemainingDeadline(value.expiresUnixMs, utc, now) : 0;
            pendingExpires[n] = haveTime ? RemainingDeadline(value.pendingExpiresUnixMs, utc, now) : 0;
            // 7.5.5.7 permits only Common until trusted time is available.
            if (!haveTime && value.user == 1 && value.active) expires[n] = std::numeric_limits<uint64_t>::max();
            if (value.active && expires[n] > now
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
    if (!value.active || now >= expires[n]) return false;
    // Table 7-12 assigns capabilities; point/file/security policy remains in
    // IAuthenticationAuthorization. Private roles require that explicit policy.
    if (value.role >= 32768) return true;
    if (function == 0) return true; // Native application CONFIRM, after exact-owner authentication.
    if (function == 1) return value.role != 4; // Monitoring
    if (function >= 3 && function <= 6) return value.role == 1; // Controls
    if (function >= 25 && function <= 30)
        return value.role == 2 || value.role == 3 || value.role == 5 || value.role == 6; // Further restricted by policy.
    if (function == 32 || function == 33) return false; // Authority protocols never gain ordinary role authorization.
    return value.role == 2 || value.role == 3 || value.role == 4 || value.role == 6;
}
void RemoteUpdateKeys::ClearExchange()
{
    crypto::Clear(Write(masterChallenge));
    crypto::Clear(Write(outstationChallenge));
    crypto::Clear(Write(candidate));
    crypto::Clear(Write(ciphertext));
    operation = UpdateKeyRequest();
    phase = Phase::IDLE;
    cipherSize = 0;
    deadline = 0;
    requestedExpiryUnix = requestedExpiry = 0;
    retries = 0;
    user = 0;
    transmitted = everTransmitted = changed = confirmationReady = false;
}
void RemoteUpdateKeys::Failure()
{
    if (everTransmitted) owner.statistics.Increment(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES);
    ClearExchange();
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
    if (!haveTrustedTime)
    {
        uint64_t utc = 0;
        try { haveTrustedTime = credentials->TrustedUnixTimeMs(utc); } catch (...) {}
        if (haveTrustedTime)
            for (size_t n = 0; n < owner.Size(); ++n)
            {
                expires[n] = RemainingDeadline(users[n].expiresUnixMs, utc, now);
                pendingExpires[n] = RemainingDeadline(users[n].pendingExpiresUnixMs, utc, now);
                if (users[n].active && now < expires[n])
                {
                    owner.At(n)->ReplaceUpdateKey(Read(users[n].updateKey), expires[n], now);
                    invalidated |= 1u << n;
                }
            }
    }
    // The native Master response timer owns retries/completion. A periodic
    // session service must not consume its timeout before that timer fires.
    if (role == SessionKeys::Role::OUTSTATION && Busy() && now >= deadline) Failure();
    for (size_t n = 0; n < owner.Size(); ++n)
        if (haveTrustedTime && users[n].active && now >= expires[n])
        {
            users[n].active = false;
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
        next.role = next.pendingRole;
        next.expiresUnixMs = next.pendingExpiresUnixMs;
        next.pending = false;
    }
    next.active = true;
    next.havePendingKey = false;
    crypto::Clear(Write(next.pendingUpdateKey));
    if (!Commit(slot, next)) return false;
    expires[slot] = expiry;
    if (owner.At(slot)->ReplaceUpdateKey(Read(next.updateKey), expiry, now) != SessionKeys::Result::OK) return false;
    invalidated |= 1u << slot;
    return true;
}

bool RemoteUpdateKeys::Begin(const UpdateKeyRequest& value, uint64_t now)
{
    Tick(now);
    if (!loaded || clockFailed || role != SessionKeys::Role::MASTER || Busy() || !credentials
        || !updatekeys::ValidName({value.name.data(), value.nameSize})
        || (!value.certificationSize && value.operation != 0)
        || (value.certificationSize && value.verifyOnly)
        || (value.certificationSize && value.certificationSize != owner.config.tagLength)
        || (value.certificationSize && (value.operation < 1 || value.operation > 3 || !updatekeys::ValidRole(value.role)))
        || (!value.verifyOnly && value.operation != 2 && !value.source)) return false;
    operation = value;
    if (value.certificationSize && value.operation != 2)
    {
        uint64_t utc = 0;
        bool trusted = false;
        try { trusted = credentials->TrustedUnixTimeMs(utc); } catch (...) {}
        const uint64_t lifetime = uint64_t(value.expiryDays) * 86400000;
        if (!trusted || utc > std::numeric_limits<uint64_t>::max() - lifetime
            || now > std::numeric_limits<uint64_t>::max() - lifetime) { ClearExchange(); return false; }
        requestedExpiryUnix = utc + lifetime;
        requestedExpiry = now + lifetime;
    }
    slot = Find({value.name.data(), value.nameSize});
    if (!value.certificationSize && slot == owner.Size()) { ClearExchange(); return false; }
    phase = value.certificationSize ? Phase::STATUS : Phase::REPLY;
    deadline = now + owner.config.replyTimeoutMs;
    if (crypto::GenerateUpdateKeyChallenge(Write(masterChallenge)) != crypto::Result::OK) { ClearExchange(); return false; }
    return true;
}
bool RemoteUpdateKeys::Build(APDURequest& request, uint8_t sequence, uint64_t now)
{
    Tick(now);
    if (Busy() && now >= deadline) { Failure(); return false; }
    if (!loaded || clockFailed || !Busy() || role != SessionKeys::Role::MASTER) return false;
    request.SetControl(AppControlField::Request(sequence));
    request.SetFunction(FunctionCode::AUTH_REQUEST);
    appSequence = sequence;
    auto writer = request.GetWriter();
    const ser4cpp::rseq_t name(operation.name.data(), operation.nameSize);
    if (phase == Phase::STATUS)
        return WriteObject(writer, Group120Var10(4, operation.operation, operation.statusSequence, operation.role,
            operation.expiryDays, name, {}, {operation.certification.data(), operation.certificationSize}));
    if (phase == Phase::REPLY)
        return WriteObject(writer, Group120Var11(4, name, Read(masterChallenge)));
    if (phase != Phase::CONFIRM) return false;
    std::array<uint8_t, 16> mac{};
    if (!Confirmation(true, Read(candidate), {mac.data(), owner.config.tagLength})) return false;
    if (!operation.verifyOnly && !WriteObject(writer, Group120Var13(ksq, user, {ciphertext.data(), cipherSize}))) return false;
    return WriteObject(writer, Group120Var15({mac.data(), owner.config.tagLength}));
}

RemoteUpdateKeys::Result RemoteUpdateKeys::Response(const APDUResponseHeader& header, ser4cpp::rseq_t objects, uint64_t now)
{
    Tick(now);
    if (Busy() && now >= deadline) { Failure(); return Result::IGNORED; }
    if (!loaded || clockFailed || !Busy() || role != SessionKeys::Role::MASTER || !transmitted || !Framed(header)
        || header.control.SEQ != appSequence) return Result::IGNORED;
    Objects value;
    if (!objects.is_empty() && (APDUParser::Parse(objects, value, nullptr) != ParseResult::OK || value.Errors().Any()))
        return Result::IGNORED;
    if (value.first == 7)
    {
        if (header.function != FunctionCode::AUTH_RESPONSE || !ValidAuthenticationError(value.error)
            || value.error.associationId != owner.config.association || value.error.userNum != user
            || value.error.seqNum != (phase == Phase::STATUS ? operation.statusSequence : ksq)) return Result::IGNORED;
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
        if (header.function != FunctionCode::RESPONSE || !objects.is_empty()) return Result::IGNORED;
        if (header.IIN.HasRequestError()) { Failure(); return Result::FAILED; }
        if (operation.operation == 2)
        {
            if (slot < owner.Size())
            {
                auto record = users[slot];
                record.active = record.pending = record.havePendingKey = false;
                record.statusSequence = operation.statusSequence;
                record.haveStatusSequence = true;
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
                provided = operation.source->GetKey(owner.config.association, operation.name.data(), operation.nameSize,
                    masterChallenge.data(), outstationChallenge.data(), ksq, user, candidate.data(),
                    ciphertext.data(), ciphertext.size(), cipherSize);
            }
            catch (...) {}
            if (!provided || cipherSize < 24 || cipherSize > ciphertext.size() || cipherSize % 8)
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
            record.pendingExpiresUnixMs = requestedExpiryUnix;
            pendingExpires[slot] = requestedExpiry;
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
    // Retransmitting an already verified, byte-identical change can repeat its
    // confirmation, but cannot reinstall credentials or increment statistics.
    if (completedRequestSize && now < completedUntil && completedUser && completedUser <= owner.Size()
        && users[completedUser - 1].active && now < expires[completedUser - 1]
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
        if (status.keyChangeMethod != 4) return Error(8, status.seqNum, 0, header.control.SEQ, output, size, iin);
        std::array<uint8_t, 1200> message{};
        std::array<uint8_t, 32> certificationKey{};
        std::array<uint8_t, 32> certifier{};
        size_t length = 0;
        bool trusted = false;
        try { trusted = owner.config.updateKeyTrust->ReadCertificationKey(owner.config.association, certificationKey.data(), certificationKey.size()); }
        catch (...) {}
        const bool canonical = updatekeys::CertificationData(status, Write(message), length);
        const bool authenticated = trusted && canonical && status.certificationData.length() == owner.config.tagLength
            && updatekeys::VerifyMAC(Read(certificationKey), {message.data(), length}, status.certificationData);
        const bool valid = authenticated
            && crypto::SHA256(Read(certificationKey), Write(certifier)) == crypto::Result::OK;
        crypto::Clear(Write(certificationKey));
        if (trusted && canonical && !authenticated) owner.statistics.AuthenticationFailed(0);
        if (!valid) return Error(10, status.seqNum, 0, header.control.SEQ, output, size, iin);
        auto index = Find(status.userName);
        if (index < owner.Size() && users[index].haveStatusSequence && status.seqNum == users[index].statusSequence
            && users[index].statusOperation == status.operation && users[index].pendingRole == status.userRole
            && users[index].statusExpiryDays == status.userRoleExpiryDays
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
                if (users[n].nameSize == 0 || (!users[n].active && !users[n].pending
                    && !crypto::ConstantTimeEqual(Read(users[n].certificationKeyFingerprint), Read(certifier))))
                { index = n; break; }
        }
        // A.45.10 permits wrap, but 7.5.5.5 requires strictly newer SCS. Same-key
        // wrap would revalidate recorded historical certificates. A verified,
        // administratively rotated authority key establishes a new trust epoch.
        // RUK-OPEN-01 records the interoperability boundary of this fail-closed rule.
        if (index >= owner.Size() || (users[index].haveStatusSequence
            && crypto::ConstantTimeEqual(Read(users[index].certificationKeyFingerprint), Read(certifier))
            && status.seqNum <= users[index].statusSequence)
            || (status.operation == 1 && users[index].active)
            || (status.operation != 1 && !users[index].nameSize)) return Error(10, status.seqNum, 0, header.control.SEQ, output, size, iin);
        uint64_t utc = 0;
        try { if (!credentials->TrustedUnixTimeMs(utc)) return false; }
        catch (...) { return false; }
        const uint64_t lifetime = uint64_t(status.userRoleExpiryDays) * 86400000;
        if (utc > std::numeric_limits<uint64_t>::max() - lifetime || now > std::numeric_limits<uint64_t>::max() - lifetime) return false;
        auto next = users[index];
        if (!Name(next).equals(status.userName)) next = UpdateKeyUser();
        std::memcpy(next.name.data(), status.userName, status.userName.length());
        next.nameSize = static_cast<uint16_t>(status.userName.length());
        next.user = static_cast<uint16_t>(index + 1);
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
        if (Busy())
        {
            if (phase != Phase::OUTSTATION_REPLY || value.request.keyChangeMethod != 4
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
        if (value.request.keyChangeMethod != 4) return Error(8, 0, 0, header.control.SEQ, output, size, iin);
        const auto index = Find(value.request.userName);
        if (index >= owner.Size() || value.request.challengeData.length() != 32
            || now >= (users[index].pending ? pendingExpires[index] : expires[index]))
            return Error(11, 0, 0, header.control.SEQ, output, size, iin);
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
    if (changing && (value.second != 15 || value.change.seqNum != ksq || value.change.userNum != user)) return false;
    if (!changing && value.second) return false;
    bool keyOK = true;
    if (changing)
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
    const bool authenticated = keyOK && value.confirm.hmacValue.length() == owner.config.tagLength
        && Confirmation(true, Read(candidate), {expected.data(), owner.config.tagLength})
        && crypto::ConstantTimeEqual({expected.data(), owner.config.tagLength}, value.confirm.hmacValue);
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
