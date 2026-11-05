// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/SessionKeys.h"

#include "app/APDURequest.h"
#include "app/APDUResponse.h"
#include "app/parsing/APDUHeaderParser.h"
#include "app/parsing/APDUParser.h"
#include "auth/AuthenticationMAC.h"
#include "auth/AuthenticationStatistics.h"
#include "crypto/CryptoProvider.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace opendnp3
{
namespace
{
    template<size_t N> struct Secret
    {
        std::array<uint8_t, N> bytes{};
        ~Secret()
        {
            crypto::Clear(ser4cpp::wseq_t(bytes.data(), bytes.size()));
        }
    };
    struct OutputGuard
    {
        ser4cpp::wseq_t output;
        bool committed = false;
        ~OutputGuard()
        {
            if (!committed)
                crypto::Clear(output);
        }
    };
    bool Overlaps(ser4cpp::rseq_t input, ser4cpp::wseq_t output)
    {
        if (!input.length() || !output.length())
            return false;
        const auto a = reinterpret_cast<uintptr_t>(static_cast<const uint8_t*>(input));
        const auto b = reinterpret_cast<uintptr_t>(static_cast<uint8_t*>(output));
        return a <= b ? b - a < input.length() : a - b < output.length();
    }
    class KeyHandler final : public IAPDUHandler
    {
    public:
        Group120Var4 request;
        Group120Var5 status;
        Group120Var6 change;
        uint8_t variation = 0;
        bool valid = false;
        bool IsAllowed(uint32_t index, GroupVariation gv, QualifierCode qc) override
        {
            return index == 0
                && ((gv == GroupVariation::Group120Var4 && qc == QualifierCode::UINT8_CNT)
                    || ((gv == GroupVariation::Group120Var5 || gv == GroupVariation::Group120Var6)
                        && qc == QualifierCode::FREE_FORMAT));
        }

    private:
        IINField ProcessHeader(const CountHeader&, const ICollection<Group120Var4>& v) override
        {
            valid = v.Count() == 1;
            if (valid)
                v.ForeachItem([this](const Group120Var4& x) { request = x; });
            variation = 4;
            return IINField::Empty();
        }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var5>& v) override
        {
            valid = v.Count() == 1;
            if (valid)
                v.ForeachItem([this](const Group120Var5& x) { status = x; });
            variation = 5;
            return IINField::Empty();
        }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var6>& v) override
        {
            valid = v.Count() == 1;
            if (valid)
                v.ForeachItem([this](const Group120Var6& x) { change = x; });
            variation = 6;
            return IINField::Empty();
        }
    };
} // namespace

SessionKeys::SessionKeys(Role role_, uint16_t association_, uint16_t user_, const Config& config_)
    : role(role_),
      association(association_),
      user(user_),
      config(config_),
      macAlgorithm(ResolveAuthenticationMAC(config_.macAlgorithm, config_.tagLength))
{
}
SessionKeys::~SessionKeys()
{
    statistics = nullptr;
    Reset();
}
bool SessionKeys::ValidConfig() const
{
    return user != 0
        && (config.intervalMs == 0
            || (config.intervalMs >= 1000 && config.intervalMs <= 7200000 && config.intervalMs % 1000 == 0))
        && config.messageLimit >= 1 && config.messageLimit <= 0x7FFFFFFF
        && config.replyTimeoutMs <= 120000 && config.replyTimeoutMs % 100 == 0
        && ValidAuthenticationMAC(macAlgorithm, config.tagLength)
        && (config.keyWrapAlgorithm == 1 || config.keyWrapAlgorithm == 2);
}
void SessionKeys::ClearPending()
{
    crypto::Clear(ser4cpp::wseq_t(candidate.data(), candidate.size()));
    crypto::Clear(ser4cpp::wseq_t(statusBytes.data(), statusBytes.size()));
    crypto::Clear(ser4cpp::wseq_t(pendingChange.data(), pendingChange.size()));
    statusSize = pendingChangeSize = 0;
    changeQueued = false;
    awaitingChange = false;
    deadline = 0;
    phase = Phase::IDLE;
}
void SessionKeys::RetainRecovery()
{
    // The outstation may have installed V6 although its confirmation was lost.
    // Retain exactly one proposed Monitoring key for V5 verification ONLY.
    if (phase != Phase::CONFIRM || !pendingChangeSize || changeQueued)
        return;
    crypto::Clear(ser4cpp::wseq_t(recoveryMonitoring.data(), recoveryMonitoring.size()));
    crypto::Clear(ser4cpp::wseq_t(recoveryChange.data(), recoveryChange.size()));
    std::memcpy(recoveryMonitoring.data(), candidate.data() + 32, 32);
    std::memcpy(recoveryChange.data(), pendingChange.data(), pendingChangeSize);
    recoverySize = pendingChangeSize;
}
void SessionKeys::Invalidate()
{
    invalidStatus = 2;
    valid = false;
    validUntil = 0;
    messages = 0;
    crypto::Clear(ser4cpp::wseq_t(control.data(), control.size()));
    // A.45.5: retain the last Monitoring key ONLY for authenticating V5 status,
    // even when session keys have expired. MonitoringKey() never exposes it then.
}
void SessionKeys::Reset()
{
    if (statistics) statistics->CancelRecovery(user);
    cappedRetry = false;
    failureRenewalPending = false;
    Invalidate();
    ClearPending();
    crypto::Clear(ser4cpp::wseq_t(update.data(), update.size()));
    crypto::Clear(ser4cpp::wseq_t(monitoring.data(), monitoring.size()));
    crypto::Clear(ser4cpp::wseq_t(lastChange.data(), lastChange.size()));
    crypto::Clear(ser4cpp::wseq_t(recoveryMonitoring.data(), recoveryMonitoring.size()));
    crypto::Clear(ser4cpp::wseq_t(recoveryChange.data(), recoveryChange.size()));
    recoverySize = 0;
    updateSize = 0;
    configured = haveMonitoring = haveKSQ = false;
    lastKeyStatus = 0;
    keySize = lastChangeSize = 0;
    credentialExpiry = 0;
    ksq = 0;
    attempts = 0;
    nextAttempt = 0;
}
bool SessionKeys::Observe(uint64_t now)
{
    if (now < lastTime || now > std::numeric_limits<uint64_t>::max() - 7320000)
    {
        Reset();
        return false;
    }
    lastTime = now;
    if (configured && now >= credentialExpiry)
    {
        Reset();
        return false;
    }
    return true;
}
SessionKeys::Result SessionKeys::Configure(ser4cpp::rseq_t key, uint64_t expiry, uint64_t now)
{
    Reset();
    if (!Observe(now) || !ValidConfig() || key.length() != (config.keyWrapAlgorithm == 1 ? 16u : 32u)
        || !static_cast<const uint8_t*>(key) || expiry <= now)
        return Result::INVALID;
    updateSize = key.length();
    std::memcpy(update.data(), key, updateSize);
    configured = true;
    credentialExpiry = expiry;
    return Result::OK;
}
void SessionKeys::Revoke()
{
    const auto previousSequence = ksq;
    const auto previousHaveSequence = haveKSQ;
    Reset();
    ksq = previousSequence;
    haveKSQ = previousHaveSequence;
}
SessionKeys::Result SessionKeys::ReplaceUpdateKey(ser4cpp::rseq_t key, uint64_t expiry, uint64_t now)
{
    const auto previousSequence = ksq;
    const auto previousHaveSequence = haveKSQ;
    const auto result = Configure(key, expiry, now);
    ksq = previousSequence;
    haveKSQ = previousHaveSequence;
    return result;
}
bool SessionKeys::NextUpdateKeySequence(uint32_t& sequence)
{
    if (role != Role::OUTSTATION || IsExchanging() || awaitingChange) return false;
    sequence = ++ksq;
    haveKSQ = true;
    return true;
}
ser4cpp::rseq_t SessionKeys::UpdateKey(uint64_t now)
{
    return Observe(now) && configured ? ser4cpp::rseq_t(update.data(), updateSize) : ser4cpp::rseq_t();
}
void SessionKeys::PeerRestart(uint64_t now)
{
    if (!Observe(now) || !configured || role != Role::MASTER)
        return;
    if (statistics) statistics->CancelRecovery(user);
    failureRenewalPending = false;
    cappedRetry = false;
    Invalidate();
    ClearPending();
    crypto::Clear(ser4cpp::wseq_t(monitoring.data(), monitoring.size()));
    crypto::Clear(ser4cpp::wseq_t(lastChange.data(), lastChange.size()));
    crypto::Clear(ser4cpp::wseq_t(recoveryMonitoring.data(), recoveryMonitoring.size()));
    crypto::Clear(ser4cpp::wseq_t(recoveryChange.data(), recoveryChange.size()));
    haveMonitoring = haveKSQ = false;
    lastKeyStatus = 0;
    ksq = 0;
    keySize = lastChangeSize = recoverySize = 0;
    attempts = 0;
    nextAttempt = now;
}
void SessionKeys::RequestPeerRestart(uint64_t now)
{
    if (role != Role::MASTER || !Observe(now) || !configured) return;
    if (statistics) statistics->CancelRecovery(user);
    failureRenewalPending = cappedRetry = false;
    RetainRecovery();
    Invalidate();
    ClearPending();
    lastKeyStatus = 0;
    attempts = 0;
    nextAttempt = now;
    // A restart IIN is not proof that the peer lost keys. Keep the old V5 MAC
    // evidence; the existing bounded NOT_INIT/no-MAC path confirms that case.
}
void SessionKeys::Disconnect()
{
    if (statistics) statistics->CancelRecovery(user);
    cappedRetry = false;
    failureRenewalPending = false;
    if (statistics && role == Role::MASTER && phase != Phase::IDLE)
        statistics->Increment(SecurityStatistic::FAILED_SESSION_KEY_CHANGES);
    lastKeyStatus = 0;
    RetainRecovery();
    Invalidate();
    ClearPending();
    attempts = 0;
    nextAttempt = lastTime;
    if (role == Role::OUTSTATION) invalidStatus = 4;
}
void SessionKeys::CommunicationFailure(uint64_t now)
{
    if (!Observe(now)) return;
    Disconnect(); // Preserves sent-V6 recovery material, credentials and KSQ.
    nextAttempt = now;
}
void SessionKeys::SetChangeQueued(ser4cpp::rseq_t change, bool queued)
{
    // Only the owner of the exact current V6 can report its transmission state.
    // Queued candidates must not replace recovery from an earlier, sent V6.
    if (phase == Phase::CONFIRM && pendingChangeSize && pendingChangeSize == change.length()
        && crypto::ConstantTimeEqual(ser4cpp::rseq_t(pendingChange.data(), pendingChangeSize), change))
        changeQueued = queued;
}
void SessionKeys::CancelQueuedChange(uint64_t now)
{
    Tick(now);
    if (phase == Phase::CONFIRM && changeQueued)
        Fail(Result::INVALID, now); // Preserve the existing retry delay and attempt budget.
}
void SessionKeys::Tick(uint64_t now)
{
    if (!Observe(now))
        return;
    if (cappedRetry && now >= nextAttempt)
    {
        cappedRetry = false;
        if (statistics && role == Role::MASTER && config.intervalMs)
            statistics->ResetMaximum(SecurityStatistic::RESTART_REKEYS);
    }
    if (valid && now >= validUntil)
    {
        if (statistics && role == Role::MASTER) statistics->ResetMaximum(SecurityStatistic::RESTART_REKEYS);
        Invalidate();
    }
    // Phase/ownership arms the timer: an immediate deadline can equal zero.
    if ((phase != Phase::IDLE || awaitingChange) && now >= deadline)
    {
        failureRenewalPending = false;
        bool exhausted = attempts >= 3;
        if (statistics && role == Role::MASTER)
        {
            statistics->Increment(SecurityStatistic::REPLY_TIMEOUTS);
            exhausted = statistics->Exceeded(SecurityStatistic::REPLY_TIMEOUTS);
            if (exhausted)
            {
                statistics->KeyChangeTimeoutLimit(user);
            }
        }
        RetainRecovery();
        ClearPending();
        Invalidate();
        // Literal zero does not disable expiry. Only recovery is deferred by
        // one 100 ms configuration quantum to avoid same-tick retry storms.
        uint64_t retryDelay = config.replyTimeoutMs ? 0 : 100;
        if (exhausted)
            retryDelay = config.intervalMs ? config.intervalMs
                                           : (config.replyTimeoutMs ? config.replyTimeoutMs : 100);
        nextAttempt = now + retryDelay;
        cappedRetry = exhausted;
        if (exhausted)
            attempts = 0;
    }
}
bool SessionKeys::Ready(uint64_t now)
{
    Tick(now);
    return configured && valid;
}
ser4cpp::rseq_t SessionKeys::ControlKey(uint64_t now)
{
    return Ready(now) ? ser4cpp::rseq_t(control.data(), keySize) : ser4cpp::rseq_t();
}
ser4cpp::rseq_t SessionKeys::MonitoringKey(uint64_t now)
{
    return Ready(now) ? ser4cpp::rseq_t(monitoring.data(), keySize) : ser4cpp::rseq_t();
}
void SessionKeys::CountAuthentication(uint64_t now)
{
    Tick(now);
    if (valid && ++messages >= config.messageLimit)
    {
        if (statistics && role == Role::MASTER) statistics->ResetMaximum(SecurityStatistic::RESTART_REKEYS);
        Invalidate();
    }
}
void SessionKeys::RequestRenewal(uint64_t now)
{
    Tick(now);
    if (role == Role::MASTER && configured && phase == Phase::IDLE)
    {
        if (statistics) statistics->CancelRecovery(user);
        failureRenewalPending = false;
        cappedRetry = false;
        Invalidate();
        nextAttempt = now;
    }
}
bool SessionKeys::RequestAuthenticationRenewal(uint64_t now)
{
    Tick(now);
    if (role != Role::MASTER || !configured || phase != Phase::IDLE || failureRenewalPending) return false;
    Invalidate();
    nextAttempt = now;
    failureRenewalPending = true;
    cappedRetry = false;
    return true;
}
void SessionKeys::OnExchangeTransmit(uint8_t variation, uint8_t sequence)
{
    if (!failureRenewalPending || sequence != appSequence
        || !((variation == 4 && phase == Phase::STATUS) || (variation == 6 && phase == Phase::CONFIRM))) return;
    failureRenewalPending = false;
    if (statistics) statistics->AuthenticationRekeyStarted();
}
bool SessionKeys::CanSendUnkeyedCritical(uint64_t now)
{
    Tick(now);
    // Table 7-13's exhausted-attempt path resets attempts and waits for the
    // next Key Change interval. Ordinary inter-attempt retries do not qualify.
    return role == Role::MASTER && configured && !valid && phase == Phase::IDLE
        && lastKeyStatus >= 2 && lastKeyStatus <= 4 && attempts == 0 && now < nextAttempt;
}
bool SessionKeys::NeedsExchange(uint64_t now)
{
    Tick(now);
    return role == Role::MASTER && configured && !valid && phase == Phase::IDLE && now >= nextAttempt;
}
SessionKeys::Result SessionKeys::Fail(Result result, uint64_t now)
{
    failureRenewalPending = false;
    if (statistics && role == Role::MASTER && phase != Phase::IDLE && attempts >= 3)
    {
        statistics->Increment(SecurityStatistic::FAILED_SESSION_KEY_CHANGES);
        statistics->CancelRecovery(user);
    }
    RetainRecovery();
    ClearPending();
    Invalidate();
    // Invalid traffic cannot accelerate the retry loop.
    // Zero expires immediately, but recovery waits one configuration quantum.
    uint64_t retryDelay = config.replyTimeoutMs ? config.replyTimeoutMs : 100;
    if (attempts >= 3 && config.intervalMs)
        retryDelay = config.intervalMs;
    nextAttempt = now + retryDelay;
    cappedRetry = attempts >= 3;
    if (attempts >= 3)
        attempts = 0;
    return result;
}
SessionKeys::Result SessionKeys::Begin(uint16_t assoc, uint8_t seq, uint64_t now, ser4cpp::wseq_t output, size_t& size)
{
    size = 0;
    OutputGuard guard{output};
    if (assoc != association)
        return Result::WRONG_ASSOCIATION;
    Tick(now);
    if (!configured)
        return Result::NO_CREDENTIAL;
    if (role != Role::MASTER || seq > 15 || !static_cast<uint8_t*>(output) || output.length() < 8)
        return Result::INVALID;
    if (phase != Phase::IDLE || now < nextAttempt)
        return Result::BUSY;
    ClearPending();
    Invalidate();
    APDURequest request(output);
    request.ConfigureHeader(FunctionCode::AUTH_REQUEST, seq);
    Group120Var4 value;
    value.userNum = user;
    auto writer = request.GetWriter();
    if (!writer.WriteSingleValue<ser4cpp::UInt8>(QualifierCode::UINT8_CNT, value))
        return Result::INVALID;
    appSequence = seq;
    phase = Phase::STATUS;
    deadline = now + config.replyTimeoutMs;
    if (attempts < 255) ++attempts;
    size = request.ToRSeq().length();
    guard.committed = true;
    return Result::OK;
}
bool SessionKeys::CheckStatusMAC(const Group120Var5& value, ser4cpp::rseq_t key, ser4cpp::rseq_t transcript) const
{
    return value.macAlgorithm == macAlgorithm && value.hmacValue.length() == config.tagLength
        && transcript.length() != 0
        && VerifyAuthenticationMAC(macAlgorithm, key, transcript, value.hmacValue) == crypto::Result::OK;
}
bool SessionKeys::IsStatusAuthentic(const Group120Var5& value) const
{
    if (role != Role::MASTER || value.userNum != user) return false;
    return (haveMonitoring && CheckStatusMAC(value, ser4cpp::rseq_t(monitoring.data(), keySize),
                                            ser4cpp::rseq_t(lastChange.data(), lastChangeSize)))
        || (recoverySize && CheckStatusMAC(value, ser4cpp::rseq_t(recoveryMonitoring.data(), 32),
                                          ser4cpp::rseq_t(recoveryChange.data(), recoverySize)));
}
bool SessionKeys::MakeStatus(
    uint8_t seq, uint8_t status, uint64_t now, ser4cpp::wseq_t output, size_t& size, IINField iin)
{
    if (output.length() < 69)
        return false;
    Secret<32> nonce;
    Secret<16> mac;
    if (crypto::GenerateRandom(ser4cpp::wseq_t(nonce.bytes.data(), 32)) != crypto::Result::OK)
        return false;
    Group120Var5 value(++ksq, user, config.keyWrapAlgorithm, status, 0, ser4cpp::rseq_t(nonce.bytes.data(), 32),
                       ser4cpp::rseq_t());
    haveKSQ = true;
    auto raw = ser4cpp::wseq_t(statusBytes.data(), statusBytes.size());
    if (!value.Write(raw))
        return false;
    statusSize = value.Size();
    if (haveMonitoring)
    {
        value.macAlgorithm = macAlgorithm;
        if (ComputeAuthenticationMAC(macAlgorithm, ser4cpp::rseq_t(monitoring.data(), keySize),
                                     ser4cpp::rseq_t(lastChange.data(), lastChangeSize),
                                     ser4cpp::wseq_t(mac.bytes.data(), config.tagLength))
            != crypto::Result::OK)
            return false;
        value.hmacValue = ser4cpp::rseq_t(mac.bytes.data(), config.tagLength);
        // Wrapped status includes MAL, but excludes only the MAC bytes.
        raw = ser4cpp::wseq_t(statusBytes.data(), statusBytes.size());
        if (!value.Write(raw))
            return false;
        statusSize = value.Size() - value.hmacValue.length();
    }
    APDUResponse response(output);
    response.SetFunction(FunctionCode::AUTH_RESPONSE);
    response.SetControl(AppControlField(true, true, false, false, seq));
    response.SetIIN(iin);
    auto writer = response.GetWriter();
    if (!writer.WriteFreeFormat(&value, 1))
        return false;
    size = response.ToRSeq().length();
    appSequence = seq;
    awaitingChange = true;
    deadline = now + config.replyTimeoutMs;
    return true;
}
SessionKeys::Result SessionKeys::Process(
    uint16_t assoc, ser4cpp::rseq_t apdu, uint64_t now, ser4cpp::wseq_t output, size_t& size, IINField iin)
{
    size = 0;
    OutputGuard guard{output};
    if (assoc != association)
        return Result::WRONG_ASSOCIATION;
    Tick(now);
    if (!configured)
        return Result::NO_CREDENTIAL;
    if (!static_cast<const uint8_t*>(apdu) || !static_cast<uint8_t*>(output) || apdu.length() > MAX_APDU
        || Overlaps(apdu, output))
        return Fail(Result::INVALID, now);
    const auto header = APDUHeaderParser::ParseRequest(apdu);
    if (!header.success || !header.header.control.IsFirAndFin() || header.header.control.CON
        || header.header.control.UNS
        || header.header.function != (role == Role::MASTER ? FunctionCode::AUTH_RESPONSE : FunctionCode::AUTH_REQUEST))
        return Fail(Result::INVALID, now);
    const auto seq = header.header.control.SEQ;
    auto objects = header.objects;
    if (role == Role::MASTER)
    {
        const auto response = APDUHeaderParser::ParseResponse(apdu);
        if (!response.success)
            return Fail(Result::INVALID, now);
        objects = response.objects;
    }
    KeyHandler handler;
    if (APDUParser::Parse(objects, handler, nullptr) != ParseResult::OK || !handler.valid)
    {
        if (statistics) statistics->Unexpected();
        return Fail(Result::INVALID, now);
    }
    if (role == Role::OUTSTATION)
    {
        if (handler.variation == 4)
        {
            if (handler.request.userNum != user)
                return Result::INVALID;
            ClearPending();
            if (!MakeStatus(seq, valid ? 1 : invalidStatus, now, output, size, iin))
                return Fail(Result::CRYPTO_ERROR, now);
            guard.committed = true;
            return Result::OK;
        }
        if (handler.variation != 6 || handler.change.userNum != user || !awaitingChange || handler.change.seqNum != ksq
            || seq != appSequence)
        {
            if (statistics) statistics->Unexpected();
            return Fail(Result::INVALID, now);
        }
        const auto wrapped = handler.change.keyWrapData;
        if (wrapped.length() < 24 || wrapped.length() > MAX_APDU || wrapped.length() % 8)
        {
            if (statistics) statistics->Increment(SecurityStatistic::FAILED_SESSION_KEY_CHANGES);
            return Fail(Result::INVALID, now);
        }
        Secret<MAX_APDU> plaintext;
        if (WrapAuthenticationKeys(config.keyWrapAlgorithm, true, ser4cpp::rseq_t(update.data(), updateSize), wrapped,
                                   ser4cpp::wseq_t(plaintext.bytes.data(), wrapped.length() - 8))
            != crypto::Result::OK)
        {
            if (statistics) statistics->Increment(SecurityStatistic::FAILED_SESSION_KEY_CHANGES);
            return Fail(Result::CRYPTO_ERROR, now);
        }
        auto input = ser4cpp::rseq_t(plaintext.bytes.data(), wrapped.length() - 8);
        uint16_t length = 0;
        ser4cpp::UInt16::read_from(input, length);
        const size_t expected = 2 + 2 * static_cast<size_t>(length) + statusSize;
        if ((length != 16 && length != 32) || expected > wrapped.length() - 8
            || (expected + 7) / 8 * 8 != wrapped.length() - 8
            || !crypto::ConstantTimeEqual(input.skip(2 * length).take(statusSize),
                                          ser4cpp::rseq_t(statusBytes.data(), statusSize))
            || crypto::ConstantTimeEqual(input.take(length), input.skip(length).take(length)))
        {
            if (statistics) statistics->Increment(SecurityStatistic::FAILED_SESSION_KEY_CHANGES);
            return Fail(Result::INVALID, now);
        }
        Invalidate();
        crypto::Clear(ser4cpp::wseq_t(monitoring.data(), monitoring.size()));
        std::memcpy(control.data(), input, length);
        std::memcpy(monitoring.data(), input.skip(length), length);
        keySize = length;
        haveMonitoring = true;
        valid = true;
        validUntil = config.intervalMs ? std::min(credentialExpiry, now + config.intervalMs) : credentialExpiry;
        crypto::Clear(ser4cpp::wseq_t(lastChange.data(), lastChange.size()));
        std::memcpy(lastChange.data(), apdu, apdu.length());
        lastChangeSize = apdu.length();
        ClearPending();
        if (!MakeStatus(seq, 1, now, output, size, iin))
        {
            if (statistics) statistics->Increment(SecurityStatistic::FAILED_SESSION_KEY_CHANGES);
            return Fail(Result::CRYPTO_ERROR, now);
        }
        // Confirmation V5 is not a new invitation to re-use the completed V6.
        awaitingChange = false;
        deadline = 0;
        guard.committed = true;
        if (statistics) statistics->SessionKeysChanged();
        return Result::INSTALLED;
    }
    if (handler.variation != 5 || phase == Phase::IDLE || seq != appSequence || handler.status.userNum != user)
    {
        if (statistics) statistics->Unexpected();
        if (handler.variation == 5 && phase != Phase::IDLE && handler.status.userNum != user)
        {
            if (phase == Phase::CONFIRM)
            {
                // Table 7-13 row 12: return to Wait for Key Status without
                // restarting the Reply Timer. A sent V6 may already be installed.
                const auto expires = deadline;
                RetainRecovery();
                ClearPending();
                phase = Phase::STATUS;
                deadline = expires;
            }
            return Result::INVALID; // Never fail the foreign user's transaction.
        }
        return Fail(Result::INVALID, now);
    }
    const auto& status = handler.status;
    if (status.keyWrapAlgorithm != config.keyWrapAlgorithm || status.keyStatus < 1 || status.keyStatus > 4
        || status.challengeData.length() > MAX_STATUS - 11)
    {
        if (statistics) statistics->Unexpected();
        return Fail(Result::INVALID, now);
    }
    if (phase == Phase::CONFIRM)
    {
        if (status.seqNum != static_cast<uint32_t>(ksq + 1)
            || !CheckStatusMAC(status, ser4cpp::rseq_t(candidate.data() + 32, 32),
                               ser4cpp::rseq_t(pendingChange.data(), pendingChangeSize)))
        {
            if (statistics)
            {
                statistics->Unexpected();
                statistics->Increment(SecurityStatistic::AUTHENTICATION_FAILURES);
            }
            return Fail(Result::INVALID, now);
        }
        lastKeyStatus = status.keyStatus;
        if (status.keyStatus != 1)
        {
            // Table 7-13 row 2: unexpected, but remain waiting for the owned
            // confirmation. Do not restart its timer or count a failed change.
            if (statistics) statistics->Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
            return Result::INVALID;
        }
        crypto::Clear(ser4cpp::wseq_t(control.data(), control.size()));
        crypto::Clear(ser4cpp::wseq_t(monitoring.data(), monitoring.size()));
        std::memcpy(control.data(), candidate.data(), 32);
        std::memcpy(monitoring.data(), candidate.data() + 32, 32);
        keySize = 32;
        haveMonitoring = valid = true;
        ksq = status.seqNum;
        haveKSQ = true;
        validUntil = config.intervalMs ? std::min(credentialExpiry, now + config.intervalMs) : credentialExpiry;
        messages = 0;
        attempts = 0;
        nextAttempt = 0;
        crypto::Clear(ser4cpp::wseq_t(lastChange.data(), lastChange.size()));
        std::memcpy(lastChange.data(), pendingChange.data(), pendingChangeSize);
        lastChangeSize = pendingChangeSize;
        ClearPending();
        crypto::Clear(ser4cpp::wseq_t(recoveryMonitoring.data(), recoveryMonitoring.size()));
        crypto::Clear(ser4cpp::wseq_t(recoveryChange.data(), recoveryChange.size()));
        recoverySize = 0;
        guard.committed = true;
        if (statistics) statistics->SessionKeysChanged();
        return Result::INSTALLED;
    }
    const uint32_t advance = status.seqNum - ksq;
    const bool existingMAC = haveMonitoring
        && CheckStatusMAC(status, ser4cpp::rseq_t(monitoring.data(), keySize),
                          ser4cpp::rseq_t(lastChange.data(), lastChangeSize));
    const bool recoveryMAC = recoverySize
        && CheckStatusMAC(status, ser4cpp::rseq_t(recoveryMonitoring.data(), 32),
                          ser4cpp::rseq_t(recoveryChange.data(), recoverySize));
    const bool initialStatus = !haveMonitoring && !recoverySize && status.keyStatus != 1 && status.macAlgorithm == 0
        && !status.hmacValue.length();
    if ((haveKSQ && (!advance || advance >= 0x80000000u)) || (!existingMAC && !recoveryMAC && !initialStatus))
    {
        if (statistics)
        {
            statistics->Unexpected();
            statistics->Increment(SecurityStatistic::AUTHENTICATION_FAILURES);
        }
        return Fail(Result::INVALID, now);
    }
    lastKeyStatus = status.keyStatus; // Only after existing user, sequence and MAC/initial-status validation.
    const size_t rawSize = status.Size() - status.hmacValue.length();
    auto raw = ser4cpp::wseq_t(statusBytes.data(), statusBytes.size());
    if (!status.Write(raw))
        return Fail(Result::INVALID, now);
    statusSize = rawSize;
    if (crypto::GenerateRandom(ser4cpp::wseq_t(candidate.data(), candidate.size())) != crypto::Result::OK
        || crypto::ConstantTimeEqual(ser4cpp::rseq_t(candidate.data(), 32), ser4cpp::rseq_t(candidate.data() + 32, 32)))
        return Fail(Result::CRYPTO_ERROR, now);
    Secret<MAX_APDU> plaintext;
    auto dest = ser4cpp::wseq_t(plaintext.bytes.data(), plaintext.bytes.size());
    ser4cpp::UInt16::write_to(dest, 32);
    dest.copy_from(ser4cpp::rseq_t(candidate.data(), 64));
    dest.copy_from(ser4cpp::rseq_t(statusBytes.data(), statusSize));
    const size_t padded = (2 + 64 + statusSize + 7) / 8 * 8;
    Secret<MAX_APDU> wrapped;
    if (WrapAuthenticationKeys(config.keyWrapAlgorithm, false, ser4cpp::rseq_t(update.data(), updateSize),
                               ser4cpp::rseq_t(plaintext.bytes.data(), padded),
                               ser4cpp::wseq_t(wrapped.bytes.data(), padded + 8))
        != crypto::Result::OK)
        return Fail(Result::CRYPTO_ERROR, now);
    if (output.length() < 8)
        return Fail(Result::INVALID, now);
    APDURequest request(output);
    request.ConfigureHeader(FunctionCode::AUTH_REQUEST, seq);
    Group120Var6 change(status.seqNum, user, ser4cpp::rseq_t(wrapped.bytes.data(), padded + 8));
    auto writer = request.GetWriter();
    if (!writer.WriteFreeFormat(&change, 1))
        return Fail(Result::INVALID, now);
    size = request.ToRSeq().length();
    if (size > pendingChange.size())
    {
        size = 0;
        return Fail(Result::INVALID, now);
    }
    std::memcpy(pendingChange.data(), output, size);
    pendingChangeSize = size;
    ksq = status.seqNum;
    haveKSQ = true;
    phase = Phase::CONFIRM;
    deadline = now + config.replyTimeoutMs;
    guard.committed = true;
    return Result::OK;
}
} // namespace opendnp3
