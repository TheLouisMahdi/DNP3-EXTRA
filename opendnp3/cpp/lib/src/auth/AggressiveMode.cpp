// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/AggressiveMode.h"

#include "app/APDURequest.h"
#include "app/APDUResponse.h"
#include "app/parsing/APDUHeaderParser.h"
#include "app/parsing/APDUParser.h"
#include "auth/AuthenticationMAC.h"
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
        explicit Native(bool allowChallenge_ = false) : allowChallenge(allowChallenge_) {}
        bool valid = true, found = false;
        Group120Var1 challenge;
        bool IsAllowed(uint32_t, GroupVariation gv, QualifierCode qc) override
        {
            if (found)
                return false; // G120V1 must follow all native objects.
            if (allowChallenge && gv == GroupVariation::Group120Var1 && qc == QualifierCode::FREE_FORMAT)
            {
                found = true;
                return true;
            }
            return (gv == GroupVariation::Group120Var7 && qc == QualifierCode::FREE_FORMAT)
                || (GroupVariationSpec::to_type(gv) >> 8) != 120;
        }
        IINField ProcessHeader(const FreeFormatHeader&, const ICollection<Group120Var1>& values) override
        {
            valid = values.Count() == 1;
            if (valid)
                values.ForeachItem([this](const Group120Var1& value) { challenge = value; });
            return IINField::Empty();
        }
    private:
        const bool allowChallenge;
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
AggressiveMode::AggressiveMode(uint16_t association_, size_t tagLength_, bool monitoring_, uint8_t macAlgorithm_)
    : association(association_),
      tagLength(tagLength_),
      macAlgorithm(ResolveAuthenticationMAC(macAlgorithm_, tagLength_)),
      macPolicy(ResolveAuthenticationMAC(macAlgorithm_, tagLength_)),
      monitoringDirection(monitoring_)
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
        h.algorithm = 0;
        h.haveChallenge = h.confirmPending = false;
    }
    crypto::Clear(ser4cpp::wseq_t(scratch.data(), scratch.size()));
    sequence = 0;
    haveSequence = false;
}
bool AggressiveMode::InspectEmbeddedChallenge(
    ser4cpp::rseq_t apdu, Group120Var1& value, size_t& nativeSize, uint8_t envelopeAlgorithm) const
{
    nativeSize = apdu.length();
    if (monitoringDirection || !ValidFragment(apdu, true) || !ValidAuthenticationMAC(macAlgorithm, tagLength))
        return false;
    const auto envelopeTagLength = AuthenticationTagLength(envelopeAlgorithm ? envelopeAlgorithm : macAlgorithm);
    size_t begin = 4, end = apdu.length();
    if (apdu.length() >= 6 && apdu[4] == 120 && apdu[5] == 3)
    {
        if (!envelopeTagLength || apdu.length() < 4 + 10 + 6 + envelopeTagLength)
            return false;
        Prefix prefix;
        Suffix suffix;
        begin += 10;
        end -= 6 + envelopeTagLength;
        if (APDUParser::Parse(apdu.skip(4).take(10), prefix, nullptr) != ParseResult::OK || !prefix.valid
            || prefix.value.userNum != 1
            || APDUParser::Parse(apdu.skip(end), suffix, nullptr) != ParseResult::OK || !suffix.valid
            || suffix.value.hmacValue.length() != envelopeTagLength)
            return false;
    }
    Native native(true);
    if (APDUParser::Parse(apdu.skip(begin).take(end - begin), native, nullptr) != ParseResult::OK || !native.valid)
        return false;
    if (!native.found)
        return true;
    const AppControlField control(apdu[0]);
    value = native.challenge;
    if (!control.CON || value.userNum != 0 || value.reason != 1 || !macPolicy.Allows(value.macAlgorithm))
        return false;
    for (const auto& previous : history)
    {
        const uint32_t delta = value.seqNum - previous.challengeSequence;
        if (previous.haveChallenge && (!delta || delta >= 0x80000000u))
            return false;
    }
    // The existing codec borrows Challenge Data from this validated fragment.
    // Subtract the object header/prefix (6) and fixed G120V1 fields (8).
    nativeSize = static_cast<const uint8_t*>(value.challengeData) - static_cast<const uint8_t*>(apdu) - 14;
    return nativeSize >= begin && nativeSize < end;
}
bool AggressiveMode::RememberChallenge(ser4cpp::rseq_t apdu, bool unsolicited, bool embedded, uint8_t envelopeAlgorithm)
{
    const size_t headerSize = monitoringDirection ? 2 : 4;
    if (!static_cast<const uint8_t*>(apdu) || apdu.length() < headerSize || apdu.length() > MAX_APDU
        || !ValidAuthenticationMAC(macAlgorithm, tagLength) || HasPendingConfirm())
        return false;
    Challenge challenge;
    if (embedded)
    {
        size_t nativeSize = 0;
        if (!InspectEmbeddedChallenge(apdu, challenge.value, nativeSize, envelopeAlgorithm) || nativeSize == apdu.length()
            || ((apdu[0] & 0x10) != 0) != unsolicited)
            return false;
    }
    else
    {
        const auto header = APDUHeaderParser::ParseRequest(apdu);
        if (!header.success
            || header.header.function != (monitoringDirection ? FunctionCode::AUTH_REQUEST : FunctionCode::AUTH_RESPONSE)
            || !header.header.control.IsFirAndFin() || header.header.control.UNS || header.header.control.CON
            || APDUParser::Parse(apdu.skip(headerSize), challenge, nullptr) != ParseResult::OK || !challenge.valid
            || challenge.value.reason != 1 || challenge.value.userNum != (monitoringDirection ? 1 : 0)
            || !macPolicy.Allows(challenge.value.macAlgorithm))
            return false;
    }
    for (const auto& previous : history)
    {
        const uint32_t delta = challenge.value.seqNum - previous.challengeSequence;
        if (previous.haveChallenge && (!delta || delta >= 0x80000000u))
            return false;
    }
    auto& h = history[unsolicited ? 1 : 0];
    crypto::Clear(ser4cpp::wseq_t(h.apdu.data(), h.apdu.size()));
    std::memcpy(h.apdu.data(), apdu, apdu.length());
    h.size = apdu.length();
    h.algorithm = challenge.value.macAlgorithm;
    h.sequence = h.challengeSequence = challenge.value.seqNum;
    // Only the latest accepted Challenge owns the shared CSQ watermark. Retain
    // both cached transcripts and their per-category MAC/CONFIRM sequence state.
    for (auto& previous : history)
        previous.haveChallenge = false;
    h.haveChallenge = true;
    h.confirmPending = embedded;
    const uint32_t advance = challenge.value.seqNum - sequence;
    if (!haveSequence || (advance && advance < 0x80000000u))
        sequence = challenge.value.seqNum;
    haveSequence = true;
    return true;
}
bool AggressiveMode::HasPendingConfirm() const
{
    return history[0].confirmPending || history[1].confirmPending;
}
bool AggressiveMode::RequiresConfirm(uint8_t appSequence, bool unsolicited) const
{
    const auto& h = history[unsolicited ? 1 : 0];
    return h.confirmPending && h.size >= 4 && (h.apdu[0] & 0x0F) == appSequence;
}
void AggressiveMode::DiscardPendingConfirms()
{
    for (auto& h : history)
        if (h.confirmPending)
        {
            crypto::Clear(ser4cpp::wseq_t(h.apdu.data(), h.apdu.size()));
            h.size = 0;
            h.confirmPending = false; // Retain the CSQ watermark against replay.
        }
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
        || !ValidAuthenticationMAC(macAlgorithm, tagLength))
        return false;
    const AppControlField control(original[0]);
    const auto& h = history[control.UNS ? 1 : 0];
    const auto selectedAlgorithm = h.algorithm;
    const auto selectedTagLength = AuthenticationTagLength(selectedAlgorithm);
    if (!macPolicy.Allows(selectedAlgorithm) || !h.size || (HasPendingConfirm() && !h.confirmPending)
        || (h.confirmPending && (monitoringDirection || user != 1 || original.length() != 2 || original[1] != 0
                                || !RequiresConfirm(control.SEQ, control.UNS))))
        return false;
    const size_t headerSize = monitoringDirection ? 4 : 2;
    const size_t required = original.length() + 10 + 6 + selectedTagLength;
    if (required > MAX_APDU || output.length() < required)
        return false;
    Native native(monitoringDirection && control.CON);
    const auto settings = original[1] == 1 ? ParserSettings::NoContents() : ParserSettings::Default();
    if (APDUParser::Parse(original.skip(headerSize), native, nullptr, settings) != ParseResult::OK || !native.valid)
        return false;
    Group120Var3 prefix;
    prefix.seqNum = h.confirmPending ? h.challengeSequence : sequence + 1;
    prefix.userNum = user;
    uint8_t placeholder[16] = {};
    Group120Var9 suffix(ser4cpp::rseq_t(placeholder, selectedTagLength));
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
    const size_t authenticated = required - selectedTagLength;
    std::memcpy(scratch.data(), h.apdu.data(), h.size);
    std::memcpy(scratch.data() + h.size, output, authenticated);
    if (ComputeAuthenticationMAC(selectedAlgorithm, key, ser4cpp::rseq_t(scratch.data(), h.size + authenticated),
                                 output.skip(authenticated).take(selectedTagLength))
        != crypto::Result::OK)
        return false;
    history[control.UNS ? 1 : 0].sequence = prefix.seqNum;
    history[control.UNS ? 1 : 0].confirmPending = false;
    const uint32_t advance = prefix.seqNum - sequence;
    if (advance && advance < 0x80000000u)
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
    if (!ValidFragment(apdu, monitoringDirection)) return false;
    const auto& h = history[(apdu[0] & 0x10) ? 1 : 0];
    const auto selectedAlgorithm = h.algorithm;
    const auto selectedTagLength = AuthenticationTagLength(selectedAlgorithm);
    if (assoc != association || !user
        || !macPolicy.Allows(selectedAlgorithm) || apdu.length() < headerSize + 10 + 6 + selectedTagLength
        || !static_cast<const uint8_t*>(key) || (key.length() != 16 && key.length() != 32)
        || !static_cast<uint8_t*>(output) || Overlap(apdu, output) || Overlap(key, output))
        return false;
    if (!h.size)
        return false;
    Prefix prefix;
    Suffix suffix;
    Native native(monitoringDirection && (apdu[0] & 0x20) != 0);
    const size_t suffixStart = apdu.length() - 6 - selectedTagLength;
    const size_t nativeSize = suffixStart - headerSize - 10;
    if (output.length() < headerSize + nativeSize
        || APDUParser::Parse(apdu.skip(headerSize).take(10), prefix, nullptr) != ParseResult::OK || !prefix.valid
        || prefix.value.userNum != user || APDUParser::Parse(apdu.skip(suffixStart), suffix, nullptr) != ParseResult::OK
        || !suffix.valid || suffix.value.hmacValue.length() != selectedTagLength
        || APDUParser::Parse(apdu.skip(headerSize + 10).take(nativeSize), native, nullptr,
                             apdu[1] == 1 ? ParserSettings::NoContents() : ParserSettings::Default())
            != ParseResult::OK || !native.valid)
        return false;
    const uint32_t delta = prefix.value.seqNum - h.sequence;
    const bool confirm = !monitoringDirection && h.confirmPending && user == 1 && apdu.length() == 2 + 10 + 6 + selectedTagLength
        && apdu[1] == 0 && RequiresConfirm(apdu[0] & 0x0F, (apdu[0] & 0x10) != 0)
        && prefix.value.seqNum == h.challengeSequence;
    if (h.confirmPending ? !confirm : (!delta || delta >= 0x80000000u))
        return false;
    const size_t authenticated = apdu.length() - selectedTagLength;
    std::memcpy(scratch.data(), h.apdu.data(), h.size);
    std::memcpy(scratch.data() + h.size, apdu, authenticated);
    if (VerifyAuthenticationMAC(selectedAlgorithm, key, ser4cpp::rseq_t(scratch.data(), h.size + authenticated),
                                suffix.value.hmacValue)
        != crypto::Result::OK)
        return false;
    std::memcpy(output, apdu, headerSize);
    std::memcpy(static_cast<uint8_t*>(output) + headerSize, apdu.skip(headerSize + 10), nativeSize);
    history[(apdu[0] & 0x10) ? 1 : 0].sequence = prefix.value.seqNum;
    history[(apdu[0] & 0x10) ? 1 : 0].confirmPending = false;
    const uint32_t advance = prefix.value.seqNum - sequence;
    if (advance && advance < 0x80000000u)
        sequence = prefix.value.seqNum;
    size = headerSize + nativeSize;
    guard.committed = true;
    return true;
}
} // namespace opendnp3
