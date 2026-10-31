// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "master/MasterResponder.h"

#include "app/APDURequest.h"
#include "app/parsing/APDUHeaderParser.h"
#include "app/parsing/APDUParser.h"
#include "crypto/CryptoProvider.h"

#include <cstring>

namespace opendnp3
{
namespace
{
    class ChallengeHandler final : public IAPDUHandler
    {
    public:
        bool valid = false;
        Group120Var1 challenge;
        bool IsAllowed(uint32_t count, GroupVariation gv, QualifierCode qc) override
        {
            return count == 0 && gv == GroupVariation::Group120Var1 && qc == QualifierCode::FREE_FORMAT;
        }

    private:
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var1>& values) override
        {
            valid = values.Count() == 1;
            if (valid)
                values.ForeachItem([this](const Group120Var1& value) { challenge = value; });
            return IINField::Empty();
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
} // namespace

MasterResponder::MasterResponder(uint16_t associationId_, size_t tagLength_, uint32_t pendingTimeoutMs_)
    : associationId(associationId_), tagLength(tagLength_), pendingTimeoutMs(pendingTimeoutMs_)
{
}

MasterResponder::~MasterResponder()
{
    Reset();
}

void MasterResponder::ClearRequest()
{
    crypto::Clear(ser4cpp::wseq_t(transcript.data(), transcript.size()));
    requestSize = 0;
    requestTime = 0;
}

void MasterResponder::Reset()
{
    ClearRequest();
    crypto::Clear(ser4cpp::wseq_t(key.data(), key.size()));
    keySize = 0;
    user = 0;
    validUntil = 0;
}

MasterResponder::Result MasterResponder::Fail(Result result)
{
    Reset();
    return result;
}

bool MasterResponder::ObserveTime(uint64_t nowMs)
{
    if (nowMs < lastTime)
    {
        Reset();
        return false;
    }
    lastTime = nowMs;
    return true;
}

bool MasterResponder::Expired(uint64_t nowMs) const
{
    return (keySize && nowMs >= validUntil) || (requestSize && nowMs - requestTime >= pendingTimeoutMs);
}

void MasterResponder::Tick(uint64_t nowMs)
{
    if (ObserveTime(nowMs) && Expired(nowMs))
        Reset();
}

MasterResponder::State MasterResponder::GetState() const
{
    if (!keySize)
        return State::NO_SESSION_KEYS;
    return requestSize ? State::WAITING_FOR_CHALLENGE : State::IDLE;
}

MasterResponder::Result MasterResponder::SetSessionKey(uint16_t number,
                                                       ser4cpp::rseq_t material,
                                                       uint64_t validUntilMs,
                                                       uint64_t nowMs)
{
    Reset();
    if (!ObserveTime(nowMs) || !number || !static_cast<const uint8_t*>(material)
        || (material.length() != 16 && material.length() != 32) || validUntilMs <= nowMs)
        return Result::INVALID_INPUT;
    std::memcpy(key.data(), material, material.length());
    keySize = material.length();
    user = number;
    validUntil = validUntilMs;
    return Result::OK;
}

MasterResponder::Result MasterResponder::RetainRequest(uint16_t association, ser4cpp::rseq_t request, uint64_t nowMs)
{
    if (association != associationId)
        return Result::WRONG_ASSOCIATION;
    if (!ObserveTime(nowMs))
        return Result::INVALID_INPUT;
    if (Expired(nowMs))
        return Fail(Result::EXPIRED);
    if (requestSize)
        return Result::BUSY;
    if (!keySize)
        return Result::NO_SESSION_KEYS;
    if ((tagLength != 8 && tagLength != 16) || pendingTimeoutMs < 100 || pendingTimeoutMs > 120000
        || pendingTimeoutMs % 100 != 0 || !static_cast<const uint8_t*>(request)
        || request.length() < APDUHeader::REQUEST_SIZE || request.length() > MAX_REQUEST_SIZE)
        return Fail(Result::INVALID_INPUT);
    const auto parsed = APDUHeaderParser::ParseRequest(request);
    if (!parsed.success || !parsed.header.control.IsFirAndFin() || parsed.header.control.CON
        || parsed.header.control.UNS || parsed.header.function == FunctionCode::UNKNOWN
        || FunctionCodeSpec::to_type(parsed.header.function) >= 0x20)
        return Fail(Result::INVALID_INPUT);
    std::memcpy(transcript.data() + MAX_CHALLENGE_SIZE, request, request.length());
    requestSize = request.length();
    requestTime = nowMs;
    return Result::OK;
}

MasterResponder::Result MasterResponder::Respond(
    uint16_t association, ser4cpp::rseq_t fragment, uint64_t nowMs, ser4cpp::wseq_t output, size_t& outputSize)
{
    outputSize = 0;
    const bool overlapping = Overlaps(fragment, output);
    crypto::Clear(output);
    if (association != associationId)
        return Result::WRONG_ASSOCIATION;
    if (!ObserveTime(nowMs))
        return Result::INVALID_INPUT;
    if (Expired(nowMs))
        return Fail(Result::EXPIRED);
    if (!keySize)
        return Result::NO_SESSION_KEYS;
    if (!requestSize)
        return Fail(Result::UNEXPECTED_CHALLENGE);
    if (overlapping || !static_cast<const uint8_t*>(fragment) || fragment.length() < APDUHeader::RESPONSE_SIZE
        || fragment.length() > MAX_CHALLENGE_SIZE)
        return Fail(Result::INVALID_CHALLENGE);

    const auto parsed = APDUHeaderParser::ParseResponse(fragment);
    if (!parsed.success || parsed.header.function != FunctionCode::AUTH_RESPONSE || !parsed.header.control.IsFirAndFin()
        || parsed.header.control.CON || parsed.header.control.UNS)
        return Fail(Result::INVALID_CHALLENGE);
    const AppControlField original(transcript[MAX_CHALLENGE_SIZE]);
    // IEEE 7.5.1.3 (PDF p234): Challenge and Reply echo the critical ASDU's SEQ.
    if (parsed.header.control.SEQ != original.SEQ)
        return Fail(Result::INVALID_SEQUENCE);
    ChallengeHandler handler;
    if (APDUParser::Parse(parsed.objects, handler, nullptr) != ParseResult::OK || !handler.valid)
        return Fail(Result::INVALID_CHALLENGE);
    const auto& challenge = handler.challenge;
    if (challenge.reason != 1)
        return Fail(Result::INVALID_CHALLENGE);
    // A.45.1.2.2 (PDF p762): Outstation-issued challenge has unknown USR=0.
    if (challenge.userNum != 0)
        return Fail(Result::INVALID_USER);
    if (challenge.macAlgorithm != (tagLength == 8 ? 3 : 4))
        return Fail(Result::UNSUPPORTED_ALGORITHM);

    // Association-wide, independent of user (7.5.2.3.3, PDF p253). Engineering
    // replay policy: accept only forward CSQs within a half-range window, allowing
    // loss/gaps and UINT32 rollover, but rejecting duplicates and backward values.
    const uint32_t delta = challenge.seqNum - lastSequence;
    if (haveSequence && (delta == 0 || delta >= 0x80000000u))
        return Fail(Result::INVALID_SEQUENCE);
    const size_t required = 2 + 6 + 6 + tagLength;
    if (!static_cast<uint8_t*>(output) || output.length() < required)
        return Fail(Result::OUTPUT_TOO_SMALL);

    // A.45.2.2.2 / Table A-3 (PDF p765): exact full Challenge APDU followed by
    // exact original critical APDU; no addresses or application-added padding.
    std::memmove(transcript.data() + fragment.length(), transcript.data() + MAX_CHALLENGE_SIZE, requestSize);
    std::memcpy(transcript.data(), fragment, fragment.length());
    std::array<uint8_t, 16> tag{};
    const auto computed = crypto::ComputeHMACSHA256(ser4cpp::rseq_t(key.data(), keySize),
                                                    ser4cpp::rseq_t(transcript.data(), fragment.length() + requestSize),
                                                    ser4cpp::wseq_t(tag.data(), tagLength));
    if (computed != crypto::Result::OK)
    {
        crypto::Clear(ser4cpp::wseq_t(tag.data(), tag.size()));
        return Fail(Result::CRYPTO_ERROR);
    }
    Group120Var2 reply(challenge.seqNum, user, ser4cpp::rseq_t(tag.data(), tagLength));
    APDURequest response(output);
    response.ConfigureHeader(FunctionCode::AUTH_REQUEST, original.SEQ);
    auto writer = response.GetWriter();
    const bool written = writer.WriteFreeFormat(&reply, 1);
    crypto::Clear(ser4cpp::wseq_t(tag.data(), tag.size()));
    if (!written || response.Size() != required)
    {
        crypto::Clear(output);
        return Fail(Result::CRYPTO_ERROR);
    }
    outputSize = required;
    lastSequence = challenge.seqNum;
    haveSequence = true;
    ClearRequest();
    return Result::OK;
}

} // namespace opendnp3
