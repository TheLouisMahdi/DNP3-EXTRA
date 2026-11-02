// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "outstation/OutstationChallenger.h"
#include "auth/AuthenticationStatistics.h"

#include "app/APDURequest.h"
#include "app/APDUResponse.h"
#include "auth/AuthenticationMAC.h"
#include "crypto/CryptoProvider.h"

#include <cstring>

namespace opendnp3
{
namespace
{
    bool Overlaps(ser4cpp::rseq_t input, ser4cpp::wseq_t output)
    {
        if (!input.length() || !output.length())
            return false;
        const auto a = reinterpret_cast<uintptr_t>(static_cast<const uint8_t*>(input));
        const auto b = reinterpret_cast<uintptr_t>(static_cast<uint8_t*>(output));
        return a <= b ? b - a < input.length() : a - b < output.length();
    }
} // namespace

OutstationChallenger::OutstationChallenger(uint16_t associationId_,
                                           size_t tagLength_,
                                           uint32_t replyTimeoutMs_,
                                           bool monitoringDirection_,
                                           uint8_t macAlgorithm_)
    : monitoringDirection(monitoringDirection_),
      associationId(associationId_),
      tagLength(tagLength_),
      macAlgorithm(ResolveAuthenticationMAC(macAlgorithm_, tagLength_)),
      macPolicy(ResolveAuthenticationMAC(macAlgorithm_, tagLength_)),
      replyTimeoutMs(replyTimeoutMs_)
{
}

OutstationChallenger::~OutstationChallenger()
{
    statistics = nullptr;
    Reset();
}

void OutstationChallenger::ClearUser(User& user)
{
    crypto::Clear(ser4cpp::wseq_t(user.key.data(), user.key.size()));
    user.number = 0;
    user.keySize = 0;
    user.validUntil = 0;
}

void OutstationChallenger::ClearPending(bool discarded)
{
    if (requestSize && discarded && statistics) statistics->Increment(SecurityStatistic::DISCARDED_MESSAGES);
    crypto::Clear(ser4cpp::wseq_t(transcript.data(), transcript.size()));
    requestSize = 0;
    challengeTime = 0;
    challengeSize = 0;
}

void OutstationChallenger::Reset()
{
    ClearPending();
    crypto::Clear(ser4cpp::wseq_t(acceptedChallenge.data(), acceptedChallenge.size()));
    acceptedSize = 0;
    for (auto& user : users)
        ClearUser(user);
}

bool OutstationChallenger::ObserveTime(uint64_t nowMs)
{
    if (nowMs < lastTime)
    {
        // A broken monotonic clock must never extend a key or reply lifetime.
        Reset();
        return false;
    }
    lastTime = nowMs;
    for (auto& user : users)
        if (user.number && nowMs >= user.validUntil)
            ClearUser(user);
    return true;
}

void OutstationChallenger::Tick(uint64_t nowMs)
{
    if (ObserveTime(nowMs) && requestSize && nowMs - challengeTime >= replyTimeoutMs)
    {
        if (statistics) statistics->Increment(SecurityStatistic::REPLY_TIMEOUTS);
        ClearPending();
    }
}
void OutstationChallenger::RejectReply(uint64_t nowMs)
{
    Tick(nowMs);
    if (statistics)
    {
        if (requestSize)
        {
            statistics->AuthenticationFailed(monitoringDirection ? 1 : 0);
            statistics->ResetMaximum(SecurityStatistic::REPLY_TIMEOUTS);
        }
        else statistics->Unexpected();
    }
    ClearPending();
}

bool OutstationChallenger::MatchesError(const Group120Var7& error, uint8_t appSequence) const
{
    return error.associationId == associationId && error.userNum == (monitoringDirection ? 1 : 0)
        && requestSize && error.seqNum == pendingSequence && (transcript[0] & 0x0F) == appSequence;
}

bool OutstationChallenger::CancelOnError(const Group120Var7& error, uint8_t appSequence, uint64_t nowMs)
{
    // A.45.7: echo the user of the challenged operation. Our standalone
    // Challenges carry USR=0 in Control Direction and USR=1 in Monitoring Direction.
    // Table 7-8 row 13 applies to any valid Error belonging to this exchange;
    // code-specific recovery and MAC algorithm reselection are separate.
    if (error.associationId != associationId || error.userNum != (monitoringDirection ? 1 : 0))
        return false;
    Tick(nowMs);
    if (!MatchesError(error, appSequence))
        return false;
    ClearPending(); // Never publish the challenged ASDU, invalidate keys or reset CSQ.
    if (statistics) statistics->ResetMaximum(SecurityStatistic::REPLY_TIMEOUTS);
    if (error.errorCode == 5)
    {
        macAlgorithm = macPolicy.Reject(macAlgorithm);
        tagLength = AuthenticationTagLength(macAlgorithm);
        // Zero disables new Challenges until configuration is corrected. Never
        // retry immediately or fall back to an unapproved/previously rejected MAC.
    }
    return true;
}

bool OutstationChallenger::HasKeys() const
{
    for (const auto& user : users)
        if (user.number)
            return true;
    return false;
}

void OutstationChallenger::ObserveAggressiveSequence(uint32_t value)
{
    const uint32_t delta = value - sequence;
    if (delta && delta < 0x80000000u)
        sequence = value;
}

OutstationChallenger::User* OutstationChallenger::FindUser(uint16_t number)
{
    if (number)
        for (auto& user : users)
            if (user.number == number)
                return &user;
    return nullptr;
}

OutstationChallenger::State OutstationChallenger::GetState() const
{
    if (requestSize)
        return State::WAITING_FOR_REPLY;
    return HasKeys() ? State::IDLE : State::NO_SESSION_KEYS;
}

OutstationChallenger::Result OutstationChallenger::SetSessionKey(uint16_t number,
                                                                 ser4cpp::rseq_t key,
                                                                 uint64_t validUntilMs,
                                                                 uint64_t nowMs)
{
    if (!ObserveTime(nowMs) || !number || !static_cast<const uint8_t*>(key)
        || (key.length() != 16 && key.length() != 32) || validUntilMs <= nowMs)
        return Result::INVALID_INPUT;
    auto user = FindUser(number);
    if (!user)
        for (auto& candidate : users)
            if (!candidate.number)
            {
                user = &candidate;
                break;
            }
    if (!user)
        return Result::BUSY;
    if (requestSize && statistics) statistics->ResetMaximum(SecurityStatistic::REPLY_TIMEOUTS);
    ClearPending();
    ClearUser(*user);
    std::memcpy(user->key.data(), key, key.length());
    user->number = number;
    user->keySize = key.length();
    user->validUntil = validUntilMs;
    return Result::OK;
}

OutstationChallenger::Result OutstationChallenger::Challenge(uint16_t association,
                                                             ser4cpp::rseq_t request,
                                                             IINField iin,
                                                             uint64_t nowMs,
                                                             ser4cpp::wseq_t output,
                                                             size_t& outputSize)
{
    outputSize = 0;
    const bool overlapping = Overlaps(request, output);
    crypto::Clear(output);
    if (association != associationId)
        return Result::WRONG_ASSOCIATION;
    if (!ObserveTime(nowMs))
        return Result::INVALID_INPUT;
    Tick(nowMs);
    if (requestSize)
    {
        // Table 7-8 row 3: a new critical ASDU cannot replace the owned
        // pending ASDU. Context callers reject before reaching this path.
        if (statistics)
        {
            statistics->Increment(SecurityStatistic::CRITICAL_MESSAGES_RECEIVED);
            statistics->Unexpected(); // Exactly one unexpected and one discarded.
        }
        return Result::BUSY;
    }
    if (!macPolicy.Allows(macAlgorithm) || !ValidAuthenticationMAC(macAlgorithm, tagLength) || replyTimeoutMs < 100 || replyTimeoutMs > 120000
        || replyTimeoutMs % 100 != 0 || overlapping || !static_cast<const uint8_t*>(request) || request.length() < 2
        || request.length() > MAX_REQUEST_SIZE)
        return Result::INVALID_INPUT;
    // Table 7-8, row 3: an Outstation challenges even when its Session Keys are invalid.
    if (monitoringDirection && !HasKeys())
        return Result::NO_SESSION_KEYS;
    if (!static_cast<uint8_t*>(output) || output.length() < (monitoringDirection ? CHALLENGE_SIZE - 2 : CHALLENGE_SIZE))
        return Result::OUTPUT_TOO_SMALL;

    std::array<uint8_t, CHALLENGE_DATA_SIZE> nonce{};
    if (crypto::GenerateRandom(ser4cpp::wseq_t(nonce.data(), nonce.size())) != crypto::Result::OK)
        return Result::CRYPTO_ERROR;

    const auto nextSequence = static_cast<uint32_t>(sequence + 1u);
    Group120Var1 challenge(nextSequence, monitoringDirection ? 1 : 0, macAlgorithm, 1,
                           ser4cpp::rseq_t(nonce.data(), nonce.size()));
    challengeSize = monitoringDirection ? CHALLENGE_SIZE - 2 : CHALLENGE_SIZE;
    const uint8_t* requestBytes = request;
    bool written = false;
    if (monitoringDirection)
    {
        APDURequest message(ser4cpp::wseq_t(transcript.data(), challengeSize));
        message.ConfigureHeader(FunctionCode::AUTH_REQUEST, requestBytes[0] & 0x0F);
        auto writer = message.GetWriter();
        written = writer.WriteFreeFormat(&challenge, 1) && message.Size() == challengeSize;
    }
    else
    {
        APDUResponse message(ser4cpp::wseq_t(transcript.data(), challengeSize));
        message.SetControl(AppControlField(true, true, false, false, requestBytes[0] & 0x0F));
        message.SetFunction(FunctionCode::AUTH_RESPONSE);
        message.SetIIN(iin);
        auto writer = message.GetWriter();
        written = writer.WriteFreeFormat(&challenge, 1) && message.Size() == challengeSize;
    }
    crypto::Clear(ser4cpp::wseq_t(nonce.data(), nonce.size()));
    if (!written)
    {
        ClearPending();
        return Result::CRYPTO_ERROR;
    }
    std::memcpy(transcript.data() + challengeSize, request, request.length());
    std::memcpy(output, transcript.data(), challengeSize);
    sequence = pendingSequence = nextSequence;
    requestSize = request.length();
    pendingUnsolicited = (requestBytes[0] & 0x10) != 0;
    challengeTime = nowMs;
    outputSize = challengeSize;
    return Result::OK; // challenge produced, NEVER an authorization verdict.
}

OutstationChallenger::Result OutstationChallenger::Reply(
    uint16_t association, const Group120Var2& reply, uint64_t nowMs, ser4cpp::wseq_t output, size_t& outputSize)
{
    outputSize = 0;
    const bool overlapping = Overlaps(reply.hmacValue, output);
    crypto::Clear(output);
    if (association != associationId)
        return Result::WRONG_ASSOCIATION;
    if (!ObserveTime(nowMs))
        return Result::INVALID_INPUT;
    if (!requestSize)
    {
        if (statistics) statistics->Unexpected();
        return Result::UNEXPECTED_REPLY;
    }
    Result result = Result::INVALID_MAC;
    if (nowMs - challengeTime >= replyTimeoutMs)
        result = Result::EXPIRED;
    else if (reply.seqNum != pendingSequence)
        result = Result::INVALID_SEQUENCE;
    else if (auto user = FindUser(reply.userNum))
    {
        if (!overlapping && reply.hmacValue.length() == tagLength)
        {
            // IEEE A.45.2.2.2 / Table A-3 (PDF p765, printed p723): the exact
            // Challenge APDU followed by the exact challenged APDU. The key is
            // the selected user's CONTROL Direction Session Key.
            const auto verified = VerifyAuthenticationMAC(
                macAlgorithm, ser4cpp::rseq_t(user->key.data(), user->keySize),
                ser4cpp::rseq_t(transcript.data(), challengeSize + requestSize), reply.hmacValue);
            if (verified == crypto::Result::OK)
            {
                if (!static_cast<uint8_t*>(output) || output.length() < requestSize)
                    result = Result::OUTPUT_TOO_SMALL;
                else
                {
                    if (statistics) statistics->Increment(SecurityStatistic::SUCCESSFUL_AUTHENTICATIONS);
                    std::memcpy(output, transcript.data() + challengeSize, requestSize);
                    outputSize = requestSize;
                    std::memcpy(acceptedChallenge.data(), transcript.data(), challengeSize);
                    acceptedSize = challengeSize;
                    acceptedUnsolicited = pendingUnsolicited;
                    result = Result::AUTHENTICATED;
                }
            }
            else if (verified == crypto::Result::CRYPTO_ERROR)
                result = Result::CRYPTO_ERROR;
        }
    }
    else
        result = Result::INVALID_USER;

    // Table 7-8 rows 5..7: valid/invalid Reply or timeout always consumes pending
    // state. No retry with the same challenge, even after an invalid MAC/user/CSQ.
    if (statistics)
    {
        if (result == Result::EXPIRED) statistics->Increment(SecurityStatistic::REPLY_TIMEOUTS);
        else
        {
            statistics->ResetMaximum(SecurityStatistic::REPLY_TIMEOUTS);
            if (result == Result::INVALID_MAC || result == Result::INVALID_USER || result == Result::INVALID_SEQUENCE)
                statistics->AuthenticationFailed(monitoringDirection ? 1 : 0);
        }
    }
    ClearPending(result != Result::AUTHENTICATED);
    return result;
}

} // namespace opendnp3
