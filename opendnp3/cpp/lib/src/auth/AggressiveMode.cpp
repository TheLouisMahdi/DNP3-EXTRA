// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/AggressiveMode.h"

#include "app/APDURequest.h"
#include "app/APDUResponse.h"
#include "app/parsing/APDUHeaderParser.h"
#include "app/parsing/APDUParser.h"
#include "crypto/CryptoProvider.h"

#include <cstring>

namespace opendnp3
{
namespace
{
    struct Guard
    {
        ser4cpp::wseq_t output, scratch;
        bool committed = false;
        ~Guard()
        {
            crypto::Clear(scratch);
            if (!committed)
                crypto::Clear(output);
        }
    };
    bool Overlap(ser4cpp::rseq_t a, ser4cpp::wseq_t b)
    {
        if (!a.length() || !b.length())
            return false;
        const auto x = reinterpret_cast<uintptr_t>(static_cast<const uint8_t*>(a));
        const auto y = reinterpret_cast<uintptr_t>(static_cast<uint8_t*>(b));
        return x <= y ? y - x < a.length() : x - y < b.length();
    }
    class Prefix final : public IAPDUHandler
    {
    public:
        Group120Var3 value;
        bool valid = false;
        bool IsAllowed(uint32_t n, GroupVariation gv, QualifierCode qc) override
        {
            return n == 0 && gv == GroupVariation::Group120Var3 && qc == QualifierCode::UINT8_CNT;
        }
        IINField ProcessHeader(const CountHeader&, const ICollection<Group120Var3>& values) override
        {
            valid = values.Count() == 1;
            if (valid)
                values.ForeachItem([this](const Group120Var3& v) { value = v; });
            return IINField::Empty();
        }
    };
    class Suffix final : public IAPDUHandler
    {
    public:
        Group120Var9 value;
        bool valid = false;
        bool IsAllowed(uint32_t n, GroupVariation gv, QualifierCode qc) override
        {
            return n == 0 && gv == GroupVariation::Group120Var9 && qc == QualifierCode::FREE_FORMAT;
        }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var9>& values) override
        {
            valid = values.Count() == 1;
            if (valid)
                values.ForeachItem([this](const Group120Var9& v) { value = v; });
            return IINField::Empty();
        }
    };
    class Native final : public IAPDUHandler
    {
    public:
        bool IsAllowed(uint32_t, GroupVariation gv, QualifierCode) override
        {
            return (GroupVariationSpec::to_type(gv) >> 8) != 120;
        }
    };
    class Challenge final : public IAPDUHandler
    {
    public:
        Group120Var1 value;
        bool valid = false;
        bool IsAllowed(uint32_t n, GroupVariation gv, QualifierCode qc) override
        {
            return n == 0 && gv == GroupVariation::Group120Var1 && qc == QualifierCode::FREE_FORMAT;
        }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var1>& values) override
        {
            valid = values.Count() == 1;
            if (valid)
                values.ForeachItem([this](const Group120Var1& v) { value = v; });
            return IINField::Empty();
        }
    };
    bool ValidFragment(ser4cpp::rseq_t apdu, bool monitoring)
    {
        if (!static_cast<const uint8_t*>(apdu) || apdu.length() < (monitoring ? 4u : 2u)
            || apdu.length() > AggressiveMode::MAX_APDU)
            return false;
        const auto header = APDUHeaderParser::ParseRequest(apdu);
        if (!header.success || header.header.function == FunctionCode::UNKNOWN)
            return false;
        if (monitoring)
            return (header.header.function == FunctionCode::RESPONSE
                    || header.header.function == FunctionCode::UNSOLICITED_RESPONSE)
                && (header.header.control.UNS == (header.header.function == FunctionCode::UNSOLICITED_RESPONSE));
        return header.header.control.IsFirAndFin() && !header.header.control.CON
            && (!header.header.control.UNS || header.header.function == FunctionCode::CONFIRM)
            && FunctionCodeSpec::to_type(header.header.function) < 0x20;
    }
} // namespace
AggressiveMode::AggressiveMode(uint16_t association_, size_t tagLength_, bool monitoring_)
    : association(association_), tagLength(tagLength_), monitoringDirection(monitoring_)
{
}
AggressiveMode::~AggressiveMode()
{
    Reset();
}
void AggressiveMode::Reset()
{
    for (auto& h : history)
    {
        crypto::Clear(ser4cpp::wseq_t(h.apdu.data(), h.apdu.size()));
        h.size = 0;
    }
    crypto::Clear(ser4cpp::wseq_t(scratch.data(), scratch.size()));
    sequence = 0;
    haveSequence = false;
}
bool AggressiveMode::RememberChallenge(ser4cpp::rseq_t apdu, bool unsolicited)
{
    const size_t headerSize = monitoringDirection ? 2 : 4;
    if (!static_cast<const uint8_t*>(apdu) || apdu.length() < headerSize || apdu.length() > MAX_APDU
        || (tagLength != 8 && tagLength != 16))
        return false;
    const auto header = APDUHeaderParser::ParseRequest(apdu);
    if (!header.success
        || header.header.function != (monitoringDirection ? FunctionCode::AUTH_REQUEST : FunctionCode::AUTH_RESPONSE)
        || !header.header.control.IsFirAndFin() || header.header.control.UNS || header.header.control.CON)
        return false;
    Challenge challenge;
    if (APDUParser::Parse(apdu.skip(headerSize), challenge, nullptr) != ParseResult::OK || !challenge.valid
        || challenge.value.reason != 1 || challenge.value.userNum != (monitoringDirection ? 1 : 0)
        || challenge.value.macAlgorithm != (tagLength == 8 ? 3 : 4))
        return false;
    auto& h = history[unsolicited ? 1 : 0];
    const uint32_t delta = challenge.value.seqNum - h.challengeSequence;
    if (h.size && (!delta || delta >= 0x80000000u))
        return false;
    crypto::Clear(ser4cpp::wseq_t(h.apdu.data(), h.apdu.size()));
    std::memcpy(h.apdu.data(), apdu, apdu.length());
    h.size = apdu.length();
    h.sequence = h.challengeSequence = challenge.value.seqNum;
    const uint32_t advance = challenge.value.seqNum - sequence;
    if (!haveSequence || (advance && advance < 0x80000000u))
        sequence = challenge.value.seqNum;
    haveSequence = true;
    return true;
}
bool AggressiveMode::HasChallenge(bool unsolicited) const
{
    return history[unsolicited ? 1 : 0].size != 0;
}
bool AggressiveMode::InspectUser(ser4cpp::rseq_t apdu, bool monitoring, uint16_t& user)
{
    user = 0;
    const size_t headerSize = monitoring ? 4 : 2;
    if (!ValidFragment(apdu, monitoring) || apdu.length() < headerSize + 10)
        return false;
    Prefix prefix;
    if (APDUParser::Parse(apdu.skip(headerSize).take(10), prefix, nullptr) != ParseResult::OK || !prefix.valid
        || !prefix.value.userNum)
        return false;
    user = prefix.value.userNum;
    return true;
}
bool AggressiveMode::Create(
    uint16_t assoc, uint16_t user, ser4cpp::rseq_t key, ser4cpp::rseq_t original, ser4cpp::wseq_t output, size_t& size)
{
    size = 0;
    Guard guard{output, ser4cpp::wseq_t(scratch.data(), scratch.size())};
    if (assoc != association || !user || !ValidFragment(original, monitoringDirection)
        || !static_cast<const uint8_t*>(key) || (key.length() != 16 && key.length() != 32)
        || !static_cast<uint8_t*>(output) || Overlap(original, output) || Overlap(key, output)
        || (tagLength != 8 && tagLength != 16))
        return false;
    const AppControlField control(original[0]);
    const auto& h = history[control.UNS ? 1 : 0];
    if (!h.size)
        return false;
    const size_t headerSize = monitoringDirection ? 4 : 2;
    const size_t required = original.length() + 10 + 6 + tagLength;
    if (required > MAX_APDU || output.length() < required)
        return false;
    Native native;
    const auto settings = original[1] == 1 ? ParserSettings::NoContents() : ParserSettings::Default();
    if (APDUParser::Parse(original.skip(headerSize), native, nullptr, settings) != ParseResult::OK)
        return false;
    Group120Var3 prefix;
    prefix.seqNum = sequence + 1;
    prefix.userNum = user;
    uint8_t placeholder[16] = {};
    Group120Var9 suffix(ser4cpp::rseq_t(placeholder, tagLength));
    auto write = [&](APDUWrapper& apdu) {
        auto writer = apdu.GetWriter();
        return writer.WriteSingleValue<ser4cpp::UInt8>(QualifierCode::UINT8_CNT, prefix)
            && apdu.AppendObjects(original.skip(headerSize)) && writer.WriteFreeFormat(&suffix, 1);
    };
    bool written = false;
    if (monitoringDirection)
    {
        APDUResponse apdu(output);
        apdu.SetFunction(FunctionCodeSpec::from_type(original[1]));
        apdu.SetControl(control);
        apdu.SetIIN(IINField(original[2], original[3]));
        written = write(apdu);
    }
    else
    {
        APDURequest apdu(output);
        apdu.SetFunction(FunctionCodeSpec::from_type(original[1]));
        apdu.SetControl(control);
        written = write(apdu);
    }
    if (!written)
        return false;
    // Table A-9: exact saved Challenge APDU, then the full current APDU through
    // the G120V9 header and length prefix, excluding ONLY the MAC value itself.
    const size_t authenticated = required - tagLength;
    std::memcpy(scratch.data(), h.apdu.data(), h.size);
    std::memcpy(scratch.data() + h.size, output, authenticated);
    if (crypto::ComputeHMACSHA256(key, ser4cpp::rseq_t(scratch.data(), h.size + authenticated),
                                  output.skip(authenticated).take(tagLength))
        != crypto::Result::OK)
        return false;
    history[control.UNS ? 1 : 0].sequence = prefix.seqNum;
    sequence = prefix.seqNum;
    size = required;
    guard.committed = true;
    return true;
}
bool AggressiveMode::Verify(
    uint16_t assoc, uint16_t user, ser4cpp::rseq_t key, ser4cpp::rseq_t apdu, ser4cpp::wseq_t output, size_t& size)
{
    size = 0;
    Guard guard{output, ser4cpp::wseq_t(scratch.data(), scratch.size())};
    const size_t headerSize = monitoringDirection ? 4 : 2;
    if (assoc != association || !user || !ValidFragment(apdu, monitoringDirection)
        || (tagLength != 8 && tagLength != 16) || apdu.length() < headerSize + 10 + 6 + tagLength
        || !static_cast<const uint8_t*>(key) || (key.length() != 16 && key.length() != 32)
        || !static_cast<uint8_t*>(output) || Overlap(apdu, output) || Overlap(key, output))
        return false;
    const auto& h = history[(apdu[0] & 0x10) ? 1 : 0];
    if (!h.size)
        return false;
    Prefix prefix;
    Suffix suffix;
    Native native;
    const size_t suffixStart = apdu.length() - 6 - tagLength;
    const size_t nativeSize = suffixStart - headerSize - 10;
    if (output.length() < headerSize + nativeSize
        || APDUParser::Parse(apdu.skip(headerSize).take(10), prefix, nullptr) != ParseResult::OK || !prefix.valid
        || prefix.value.userNum != user || APDUParser::Parse(apdu.skip(suffixStart), suffix, nullptr) != ParseResult::OK
        || !suffix.valid || suffix.value.hmacValue.length() != tagLength
        || APDUParser::Parse(apdu.skip(headerSize + 10).take(nativeSize), native, nullptr,
                             apdu[1] == 1 ? ParserSettings::NoContents() : ParserSettings::Default())
            != ParseResult::OK)
        return false;
    const uint32_t delta = prefix.value.seqNum - h.sequence;
    if (!delta || delta >= 0x80000000u)
        return false;
    const size_t authenticated = apdu.length() - tagLength;
    std::memcpy(scratch.data(), h.apdu.data(), h.size);
    std::memcpy(scratch.data() + h.size, apdu, authenticated);
    if (crypto::VerifyHMACSHA256(key, ser4cpp::rseq_t(scratch.data(), h.size + authenticated), suffix.value.hmacValue)
        != crypto::Result::OK)
        return false;
    std::memcpy(output, apdu, headerSize);
    std::memcpy(static_cast<uint8_t*>(output) + headerSize, apdu.skip(headerSize + 10), nativeSize);
    history[(apdu[0] & 0x10) ? 1 : 0].sequence = prefix.value.seqNum;
    const uint32_t advance = prefix.value.seqNum - sequence;
    if (advance && advance < 0x80000000u)
        sequence = prefix.value.seqNum;
    size = headerSize + nativeSize;
    guard.committed = true;
    return true;
}
} // namespace opendnp3
