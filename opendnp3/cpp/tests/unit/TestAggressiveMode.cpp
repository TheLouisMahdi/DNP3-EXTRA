// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/APDURequest.h"
#include "app/APDUResponse.h"
#include "app/parsing/APDUParser.h"
#include "auth/AggressiveMode.h"
#include "auth/AuthenticationMAC.h"
#include "crypto/CryptoProvider.h"
#include "utils/BufferHelpers.h"

#include <ser4cpp/util/HexConversions.h>

#include <catch.hpp>
#include <openssl/crypto.h>
#include <openssl/provider.h>

#include <algorithm>
#include <array>
#include <memory>
#include <vector>

using namespace opendnp3;
using namespace ser4cpp;
namespace
{
struct AggressiveKey
{
    std::array<uint8_t, 32> bytes{};
    AggressiveKey()
    {
        REQUIRE(crypto::GenerateRandom(wseq_t(bytes.data(), bytes.size())) == crypto::Result::OK);
    }
    ~AggressiveKey()
    {
        crypto::Clear(wseq_t(bytes.data(), bytes.size()));
    }
    rseq_t Read() const
    {
        return rseq_t(bytes.data(), bytes.size());
    }
};
std::vector<uint8_t> Seed(uint32_t sequence, bool monitoring, size_t tag = 16, uint8_t algorithm = 0)
{
    std::array<uint8_t, 32> nonce{};
    nonce.fill(static_cast<uint8_t>(sequence));
    std::vector<uint8_t> bytes(monitoring ? 48 : 50);
    Group120Var1 value(sequence, monitoring ? 1 : 0, ResolveAuthenticationMAC(algorithm, tag), 1,
                       rseq_t(nonce.data(), nonce.size()));
    if (monitoring)
    {
        APDURequest apdu(wseq_t(bytes.data(), bytes.size()));
        apdu.ConfigureHeader(FunctionCode::AUTH_REQUEST, 0);
        auto writer = apdu.GetWriter();
        REQUIRE(writer.WriteFreeFormat(&value, 1));
    }
    else
    {
        APDUResponse apdu(wseq_t(bytes.data(), bytes.size()));
        apdu.SetFunction(FunctionCode::AUTH_RESPONSE);
        apdu.SetControl(AppControlField::Request(0));
        apdu.SetIIN(IINField::Empty());
        auto writer = apdu.GetWriter();
        REQUIRE(writer.WriteFreeFormat(&value, 1));
    }
    return bytes;
}
rseq_t Read(const std::vector<uint8_t>& bytes)
{
    return rseq_t(bytes.data(), bytes.size());
}
} // namespace
TEST_CASE("AggressiveMode - exact READ wire and independent Table A9 transcript", "[aggressive]")
{
    const auto tag = GENERATE(8, 16);
    AggressiveKey key;
    AggressiveMode sender(7, tag, false), receiver(7, tag, false);
    auto challenge = Seed(1, false, tag);
    REQUIRE(sender.RememberChallenge(Read(challenge), false));
    REQUIRE(receiver.RememberChallenge(Read(challenge), false));
    HexSequence original("C0 01 3C 01 06");
    std::array<uint8_t, 2048> wire{}, decoded{};
    size_t size = 0, nativeSize = 0;
    REQUIRE(sender.Create(7, 2, key.Read(), original.ToRSeq(), wseq_t(wire.data(), wire.size()), size));
    const std::string prefix
        = std::string("C0 01 78 03 07 01 02 00 00 00 02 00 3C 01 06 78 09 5B 01 ") + (tag == 8 ? "08" : "10") + " 00";
    HexSequence expected(prefix);
    REQUIRE(rseq_t(wire.data(), size - tag).equals(expected.ToRSeq()));
    auto transcript = challenge;
    transcript.insert(transcript.end(), static_cast<const uint8_t*>(expected.ToRSeq()),
                      static_cast<const uint8_t*>(expected.ToRSeq()) + expected.ToRSeq().length());
    std::array<uint8_t, 16> mac{};
    REQUIRE(crypto::ComputeHMACSHA256(key.Read(), Read(transcript), wseq_t(mac.data(), tag)) == crypto::Result::OK);
    REQUIRE(crypto::ConstantTimeEqual(rseq_t(mac.data(), tag), rseq_t(wire.data() + size - tag, tag)));
    uint16_t user = 0;
    REQUIRE(AggressiveMode::InspectUser(rseq_t(wire.data(), size), false, user));
    REQUIRE(user == 2);
    REQUIRE(receiver.Verify(7, 2, key.Read(), rseq_t(wire.data(), size), wseq_t(decoded.data(), decoded.size()),
                            nativeSize));
    REQUIRE(rseq_t(decoded.data(), nativeSize).equals(original.ToRSeq()));
    REQUIRE_FALSE(receiver.Verify(7, 2, key.Read(), rseq_t(wire.data(), size), wseq_t(decoded.data(), decoded.size()),
                                  nativeSize));
    REQUIRE(nativeSize == 0);
    for (auto b : decoded)
        REQUIRE(b == 0);
    struct Handler final : IAPDUHandler
    {
        bool IsAllowed(uint32_t, GroupVariation, QualifierCode) override
        {
            return true;
        }
    } handler;
    REQUIRE(APDUParser::Parse(rseq_t(wire.data() + 2, size - 2), handler, nullptr, ParserSettings::NoContents())
            == ParseResult::OK);
}
TEST_CASE("AggressiveMode - no challenge and wrong associations cannot authenticate", "[aggressive]")
{
    AggressiveKey key;
    AggressiveMode sender(7, 16, false), receiver(7, 16, false);
    HexSequence original("C0 01 3C 01 06");
    std::array<uint8_t, 2048> wire{}, out{};
    size_t size = 0, n = 0;
    REQUIRE_FALSE(sender.Create(7, 2, key.Read(), original.ToRSeq(), wseq_t(wire.data(), wire.size()), size));
    auto challenge = Seed(1, false);
    REQUIRE(sender.RememberChallenge(Read(challenge), false));
    REQUIRE(sender.Create(7, 2, key.Read(), original.ToRSeq(), wseq_t(wire.data(), wire.size()), size));
    REQUIRE_FALSE(receiver.Verify(7, 2, key.Read(), rseq_t(wire.data(), size), wseq_t(out.data(), out.size()), n));
    REQUIRE(receiver.RememberChallenge(Read(challenge), false));
    REQUIRE_FALSE(receiver.Verify(8, 2, key.Read(), rseq_t(wire.data(), size), wseq_t(out.data(), out.size()), n));
    REQUIRE(receiver.Verify(7, 2, key.Read(), rseq_t(wire.data(), size), wseq_t(out.data(), out.size()), n));
    receiver.Reset();
    REQUIRE_FALSE(receiver.HasChallenge(false));
    REQUIRE_FALSE(receiver.Verify(7, 2, key.Read(), rseq_t(wire.data(), size), wseq_t(out.data(), out.size()), n));
}
TEST_CASE("AggressiveMode - malformed tampered truncated and wrong user messages are rejected", "[aggressive]")
{
    AggressiveKey key;
    AggressiveMode sender(7, 16, false);
    auto challenge = Seed(1, false);
    REQUIRE(sender.RememberChallenge(Read(challenge), false));
    HexSequence original("C0 01 3C 01 06");
    std::array<uint8_t, 2048> wire{}, decoded{};
    size_t size = 0, n = 0;
    REQUIRE(sender.Create(7, 2, key.Read(), original.ToRSeq(), wseq_t(wire.data(), wire.size()), size));
    for (size_t length = 0; length < size; ++length)
    {
        AggressiveMode receiver(7, 16, false);
        REQUIRE(receiver.RememberChallenge(Read(challenge), false));
        REQUIRE_FALSE(
            receiver.Verify(7, 2, key.Read(), rseq_t(wire.data(), length), wseq_t(decoded.data(), decoded.size()), n));
        REQUIRE(n == 0);
    }
    for (size_t index = 0; index < size; ++index)
    {
        AggressiveMode receiver(7, 16, false);
        REQUIRE(receiver.RememberChallenge(Read(challenge), false));
        wire[index] ^= 1;
        REQUIRE_FALSE(
            receiver.Verify(7, 2, key.Read(), rseq_t(wire.data(), size), wseq_t(decoded.data(), decoded.size()), n));
        REQUIRE(n == 0);
        wire[index] ^= 1;
        REQUIRE(
            receiver.Verify(7, 2, key.Read(), rseq_t(wire.data(), size), wseq_t(decoded.data(), decoded.size()), n));
    }
}
TEST_CASE("AggressiveMode - Monitoring IIN and unsolicited context are authenticated", "[aggressive]")
{
    const auto unsolicited = GENERATE(false, true);
    AggressiveKey key;
    AggressiveMode sender(7, 16, true), receiver(7, 16, true);
    auto challenge = Seed(1, true);
    REQUIRE(sender.RememberChallenge(Read(challenge), unsolicited));
    REQUIRE(receiver.RememberChallenge(Read(challenge), unsolicited));
    HexSequence original(unsolicited ? "F0 82 80 00" : "E0 81 80 00");
    std::array<uint8_t, 2048> wire{}, decoded{};
    size_t size = 0, n = 0;
    REQUIRE(sender.Create(7, 1, key.Read(), original.ToRSeq(), wseq_t(wire.data(), wire.size()), size));
    wire[2] ^= 1;
    REQUIRE_FALSE(
        receiver.Verify(7, 1, key.Read(), rseq_t(wire.data(), size), wseq_t(decoded.data(), decoded.size()), n));
    wire[2] ^= 1;
    REQUIRE(receiver.Verify(7, 1, key.Read(), rseq_t(wire.data(), size), wseq_t(decoded.data(), decoded.size()), n));
    REQUIRE(rseq_t(decoded.data(), n).equals(original.ToRSeq()));
}
TEST_CASE("AggressiveMode - independent challenge histories and CSQ rollover", "[aggressive]")
{
    AggressiveKey key;
    AggressiveMode sender(7, 16, true), receiver(7, 16, true);
    auto sol = Seed(0xFFFFFFFD, true), unsol = Seed(0xFFFFFFFE, true);
    REQUIRE(sender.RememberChallenge(Read(sol), false));
    REQUIRE(receiver.RememberChallenge(Read(sol), false));
    REQUIRE(sender.RememberChallenge(Read(unsol), true));
    REQUIRE(receiver.RememberChallenge(Read(unsol), true));
    std::array<uint8_t, 2048> wire{}, out{};
    size_t size = 0, n = 0;
    for (const auto& hex : std::vector<std::string>{"C0 81 80 00", "D0 82 80 00", "C1 81 00 00"})
    {
        HexSequence original(hex);
        REQUIRE(sender.Create(7, 1, key.Read(), original.ToRSeq(), wseq_t(wire.data(), wire.size()), size));
        REQUIRE(receiver.Verify(7, 1, key.Read(), rseq_t(wire.data(), size), wseq_t(out.data(), out.size()), n));
        REQUIRE(rseq_t(out.data(), n).equals(original.ToRSeq()));
        REQUIRE_FALSE(receiver.Verify(7, 1, key.Read(), rseq_t(wire.data(), size), wseq_t(out.data(), out.size()), n));
    }
    REQUIRE(sender.Sequence() == 1);
}
TEST_CASE("AggressiveMode - bounds invalid algorithms and native authentication nesting", "[aggressive]")
{
    APDUWrapper invalidWrapper;
    REQUIRE_FALSE(invalidWrapper.AppendObjects(rseq_t()));
    uint8_t header[2] = {};
    APDURequest empty(wseq_t(header, 2));
    REQUIRE(empty.AppendObjects(rseq_t()));
    REQUIRE_FALSE(empty.AppendObjects(rseq_t(header, 1)));
    REQUIRE(empty.Size() == 2);

    AggressiveKey key;
    AggressiveMode sender(7, 16, false);
    auto challenge = Seed(1, false);
    REQUIRE(sender.RememberChallenge(Read(challenge), false));
    HexSequence original("C0 01 3C 01 06"), nested("C0 01 78 04 07 01 01 00");
    std::array<uint8_t, 2048> wire{};
    size_t size = 0;
    REQUIRE_FALSE(sender.Create(7, 2, key.Read(), original.ToRSeq(), wseq_t(wire.data(), 8), size));
    REQUIRE(size == 0);
    REQUIRE_FALSE(sender.Create(7, 2, key.Read(), rseq_t(wire.data(), 2049), wseq_t(wire.data(), wire.size()), size));
    REQUIRE_FALSE(sender.Create(7, 2, key.Read(), nested.ToRSeq(), wseq_t(wire.data(), wire.size()), size));
    REQUIRE_FALSE(sender.Create(7, 0, key.Read(), original.ToRSeq(), wseq_t(wire.data(), wire.size()), size));
    REQUIRE_FALSE(sender.Create(7, 2, rseq_t(), original.ToRSeq(), wseq_t(wire.data(), wire.size()), size));
    AggressiveMode invalid(7, 12, false);
    REQUIRE_FALSE(invalid.RememberChallenge(Read(challenge), false));
    challenge[16] = 3;
    REQUIRE_FALSE(sender.RememberChallenge(Read(challenge), false));
}

TEST_CASE("AggressiveMode - unavailable cryptography never releases data or consumes a valid token", "[aggressive]")
{
    AggressiveKey key;
    AggressiveMode sender(7, 16, false), receiver(7, 16, false);
    auto challenge = Seed(1, false);
    REQUIRE(sender.RememberChallenge(Read(challenge), false));
    REQUIRE(receiver.RememberChallenge(Read(challenge), false));
    HexSequence original("C0 01 3C 01 06");
    std::array<uint8_t, 2048> wire{}, decoded{};
    size_t size = 0, n = 0;
    REQUIRE(sender.Create(7, 2, key.Read(), original.ToRSeq(), wseq_t(wire.data(), wire.size()), size));
    struct Unavailable
    {
        std::unique_ptr<OSSL_LIB_CTX, decltype(&OSSL_LIB_CTX_free)> context{OSSL_LIB_CTX_new(), OSSL_LIB_CTX_free};
        std::unique_ptr<OSSL_PROVIDER, decltype(&OSSL_PROVIDER_unload)> provider{nullptr, OSSL_PROVIDER_unload};
        OSSL_LIB_CTX* previous = nullptr;
        Unavailable()
        {
            REQUIRE(context != nullptr);
            provider.reset(OSSL_PROVIDER_load(context.get(), "null"));
            REQUIRE(provider != nullptr);
            previous = OSSL_LIB_CTX_set0_default(context.get());
        }
        ~Unavailable()
        {
            OSSL_LIB_CTX_set0_default(previous);
        }
    };
    {
        Unavailable failure;
        REQUIRE_FALSE(
            receiver.Verify(7, 2, key.Read(), rseq_t(wire.data(), size), wseq_t(decoded.data(), decoded.size()), n));
        REQUIRE(n == 0);
        size_t failedSize = 0;
        REQUIRE_FALSE(
            sender.Create(7, 2, key.Read(), original.ToRSeq(), wseq_t(decoded.data(), decoded.size()), failedSize));
        REQUIRE(failedSize == 0);
        REQUIRE(sender.Sequence() == 2);
    }
    REQUIRE(receiver.Verify(7, 2, key.Read(), rseq_t(wire.data(), size), wseq_t(decoded.data(), decoded.size()), n));
    REQUIRE(rseq_t(decoded.data(), n).equals(original.ToRSeq()));
}

TEST_CASE("AggressiveMode - explicit IEEE legacy MAC options", "[aggressive]")
{
    const auto algorithm = GENERATE(2, 5);
    const size_t tag = algorithm == 2 ? 10 : 8;
    const bool monitoring = GENERATE(false, true);
    AggressiveKey key;
    AggressiveMode sender(7, tag, monitoring, algorithm), receiver(7, tag, monitoring, algorithm);
    auto challenge = Seed(1, monitoring, tag, algorithm);
    REQUIRE(sender.RememberChallenge(Read(challenge), false));
    REQUIRE(receiver.RememberChallenge(Read(challenge), false));
    HexSequence original(monitoring ? "C0 81 80 00" : "C0 01 3C 01 06");
    std::array<uint8_t, 2048> wire{}, out{};
    size_t size = 0, n = 0;
    const uint16_t user = monitoring ? 1 : 2;
    REQUIRE(sender.Create(7, user, key.Read(), original.ToRSeq(), wseq_t(wire.data(), wire.size()), size));
    wire[size - 1] ^= 1;
    REQUIRE_FALSE(receiver.Verify(7, user, key.Read(), rseq_t(wire.data(), size), wseq_t(out.data(), out.size()), n));
    REQUIRE(n == 0);
    wire[size - 1] ^= 1;
    REQUIRE(receiver.Verify(7, user, key.Read(), rseq_t(wire.data(), size), wseq_t(out.data(), out.size()), n));
    REQUIRE(rseq_t(out.data(), n).equals(original.ToRSeq()));
    REQUIRE_FALSE(receiver.Verify(7, user, key.Read(), rseq_t(wire.data(), size), wseq_t(out.data(), out.size()), n));
}

TEST_CASE("AggressiveMode - embedded Challenge produces exact first Aggressive Confirm transcript", "[aggressive]")
{
    const auto tag = GENERATE(8u, 16u);
    const bool unsolicited = GENERATE(false, true);
    AggressiveKey key, wrong;
    AggressiveMode sender(7, tag, false), receiver(7, tag, false);
    auto embedded = Seed(41, false, tag);
    embedded[0] = unsolicited ? 0xF5 : 0xE5;
    embedded[1] = unsolicited ? 0x82 : 0x81;
    Group120Var1 challenge;
    size_t nativeSize = 0;
    REQUIRE(sender.InspectEmbeddedChallenge(Read(embedded), challenge, nativeSize));
    REQUIRE(nativeSize == 4);
    REQUIRE_FALSE(sender.RememberChallenge(Read(embedded), unsolicited)); // Not a standalone APDU.
    REQUIRE(sender.RememberChallenge(Read(embedded), unsolicited, true));
    REQUIRE(receiver.RememberChallenge(Read(embedded), unsolicited, true));
    REQUIRE(sender.RequiresConfirm(5, unsolicited));
    auto newer = embedded;
    newer[10] = 42; // A second Challenge must not replace the pending transcript.
    REQUIRE_FALSE(sender.RememberChallenge(Read(newer), unsolicited, true));
    newer[0] = unsolicited ? 0xE5 : 0xF5;
    newer[1] = unsolicited ? 0x81 : 0x82;
    REQUIRE_FALSE(sender.RememberChallenge(Read(newer), !unsolicited, true));
    REQUIRE(sender.RequiresConfirm(5, unsolicited));
    REQUIRE_FALSE(sender.RequiresConfirm(5, !unsolicited));
    HexSequence confirm(unsolicited ? "D5 00" : "C5 00");
    std::array<uint8_t, 2048> wire{}, native{};
    size_t size = 0, decoded = 0;
    REQUIRE(sender.Create(7, 1, key.Read(), confirm.ToRSeq(), wseq_t(wire.data(), wire.size()), size));
    const std::string prefix = std::string(unsolicited ? "D5" : "C5")
        + " 00 78 03 07 01 29 00 00 00 01 00 78 09 5B 01 " + (tag == 8 ? "08" : "10") + " 00";
    HexSequence expected(prefix);
    REQUIRE(rseq_t(wire.data(), size - tag).equals(expected.ToRSeq()));
    auto transcript = embedded;
    transcript.insert(transcript.end(), wire.data(), wire.data() + size - tag);
    std::array<uint8_t, 16> mac{};
    REQUIRE(crypto::ComputeHMACSHA256(key.Read(), Read(transcript), wseq_t(mac.data(), tag)) == crypto::Result::OK);
    REQUIRE(crypto::ConstantTimeEqual(rseq_t(mac.data(), tag), rseq_t(wire.data() + size - tag, tag)));
    REQUIRE_FALSE(sender.RequiresConfirm(5, unsolicited));
    REQUIRE_FALSE(receiver.Verify(7, 1, wrong.Read(), rseq_t(wire.data(), size), wseq_t(native.data(), native.size()), decoded));
    REQUIRE(decoded == 0);
    REQUIRE(receiver.Verify(7, 1, key.Read(), rseq_t(wire.data(), size), wseq_t(native.data(), native.size()), decoded));
    REQUIRE(rseq_t(native.data(), decoded).equals(confirm.ToRSeq()));
    REQUIRE_FALSE(receiver.Verify(7, 1, key.Read(), rseq_t(wire.data(), size), wseq_t(native.data(), native.size()), decoded));
    REQUIRE_FALSE(sender.RememberChallenge(Read(embedded), unsolicited, true));
}

TEST_CASE("AggressiveMode - embedded Challenge ordering fields and cancellation fail closed", "[aggressive]")
{
    AggressiveKey key;
    AggressiveMode engine(7, 16, false);
    auto embedded = Seed(41, false);
    embedded[0] = 0xE5;
    embedded[1] = 0x81;
    const auto fault = GENERATE(0, 1, 2, 3, 4, 5, 6, 7);
    if (fault == 0) embedded[0] &= ~0x20; // CON required.
    if (fault == 1) embedded[14] = 1;     // Outstation Challenge must use unknown USR.
    if (fault == 2) embedded[16] = 3;     // Algorithm/tag mismatch.
    if (fault == 3) embedded[17] = 0;     // Invalid reason.
    if (fault == 4) embedded[6] = 0x07;   // Wrong qualifier.
    if (fault == 5) embedded.push_back(0); // Trailing malformed object.
    if (fault == 6) embedded.insert(embedded.end(), {1, 2, 0, 0, 0, 1}); // Native data after G120V1.
    if (fault == 7) embedded[0] |= 0x10;  // RESPONSE/UNS mismatch.
    Group120Var1 challenge;
    size_t nativeSize = 0;
    REQUIRE_FALSE(engine.InspectEmbeddedChallenge(Read(embedded), challenge, nativeSize));
    REQUIRE_FALSE(engine.RememberChallenge(Read(embedded), false, true));
    REQUIRE_FALSE(engine.HasPendingConfirm());
    auto valid = Seed(42, false);
    valid[0] = 0xE5; valid[1] = 0x81;
    REQUIRE(engine.RememberChallenge(Read(valid), false, true));
    HexSequence confirm("C5 00"), wrongSequence("C4 00"), request("C5 01 3C 01 06");
    std::array<uint8_t, 2048> output{};
    size_t size = 0;
    REQUIRE_FALSE(engine.Create(8, 1, key.Read(), confirm.ToRSeq(), wseq_t(output.data(), output.size()), size));
    REQUIRE_FALSE(engine.Create(7, 2, key.Read(), confirm.ToRSeq(), wseq_t(output.data(), output.size()), size));
    REQUIRE_FALSE(engine.Create(7, 1, rseq_t(), confirm.ToRSeq(), wseq_t(output.data(), output.size()), size));
    REQUIRE_FALSE(engine.Create(7, 1, key.Read(), wrongSequence.ToRSeq(), wseq_t(output.data(), output.size()), size));
    REQUIRE_FALSE(engine.Create(7, 1, key.Read(), request.ToRSeq(), wseq_t(output.data(), output.size()), size));
    REQUIRE(size == 0);
    engine.DiscardPendingConfirms();
    REQUIRE_FALSE(engine.HasPendingConfirm());
    REQUIRE_FALSE(engine.Create(7, 1, key.Read(), confirm.ToRSeq(), wseq_t(output.data(), output.size()), size));
    REQUIRE_FALSE(engine.RememberChallenge(Read(valid), false, true)); // Watermark survives cancellation.
}

TEST_CASE("AggressiveMode - V3 native V1 V9 response uses full incoming MAC in Confirm seed", "[aggressive]")
{
    const bool unsolicited = GENERATE(false, true);
    AggressiveKey monitoring, control;
    AggressiveMode peer(7, 16, true), verifier(7, 16, true), master(7, 16, false);
    auto monitorChallenge = Seed(1, true);
    REQUIRE(peer.RememberChallenge(Read(monitorChallenge), unsolicited));
    REQUIRE(verifier.RememberChallenge(Read(monitorChallenge), unsolicited));
    auto embedded = Seed(41, false);
    embedded[0] = unsolicited ? 0xF5 : 0xE5;
    embedded[1] = unsolicited ? 0x82 : 0x81;
    std::array<uint8_t, 2048> wire{}, native{}, confirm{};
    size_t size = 0, nativeSize = 0, confirmSize = 0;
    REQUIRE(peer.Create(7, 1, monitoring.Read(), Read(embedded), wseq_t(wire.data(), wire.size()), size));
    wire[size - 1] ^= 1;
    REQUIRE_FALSE(verifier.Verify(7, 1, monitoring.Read(), rseq_t(wire.data(), size), wseq_t(native.data(), native.size()), nativeSize));
    REQUIRE(nativeSize == 0);
    wire[size - 1] ^= 1;
    REQUIRE(verifier.Verify(7, 1, monitoring.Read(), rseq_t(wire.data(), size), wseq_t(native.data(), native.size()), nativeSize));
    REQUIRE(rseq_t(native.data(), nativeSize).equals(Read(embedded)));
    REQUIRE(master.RememberChallenge(rseq_t(wire.data(), size), unsolicited, true));
    HexSequence original(unsolicited ? "D5 00" : "C5 00");
    REQUIRE(master.Create(7, 1, control.Read(), original.ToRSeq(), wseq_t(confirm.data(), confirm.size()), confirmSize));
    std::vector<uint8_t> transcript(wire.data(), wire.data() + size); // Includes incoming G120V9 MAC bytes.
    transcript.insert(transcript.end(), confirm.data(), confirm.data() + confirmSize - 16);
    std::array<uint8_t, 16> expected{};
    REQUIRE(crypto::ComputeHMACSHA256(control.Read(), Read(transcript), wseq_t(expected.data(), expected.size())) == crypto::Result::OK);
    REQUIRE(crypto::ConstantTimeEqual(rseq_t(expected.data(), expected.size()), rseq_t(confirm.data() + confirmSize - 16, 16)));
}

TEST_CASE("AggressiveMode - native authentication Error remains native with strict embedded framing", "[aggressive]")
{
    const bool unsolicited = GENERATE(false, true);
    const bool confirm = GENERATE(false, true);
    AggressiveKey key;
    AggressiveMode inspector(7, 16, false), sender(7, 16, true), receiver(7, 16, true);
    const auto seed = Seed(1, true);
    REQUIRE(sender.RememberChallenge(Read(seed), unsolicited));
    REQUIRE(receiver.RememberChallenge(Read(seed), unsolicited));
    std::array<uint8_t, 2048> native{}, wire{}, decoded{};
    APDUResponse response(wseq_t(native.data(), native.size()));
    response.SetFunction(unsolicited ? FunctionCode::UNSOLICITED_RESPONSE : FunctionCode::RESPONSE);
    response.SetControl(AppControlField(static_cast<uint8_t>(0xC5 | (unsolicited ? 0x10 : 0) | (confirm ? 0x20 : 0))));
    response.SetIIN(IINField::Empty());
    Group120Var7 error;
    error.seqNum = 1;
    error.userNum = 1;
    error.associationId = 7;
    error.errorCode = 1;
    auto writer = response.GetWriter();
    REQUIRE(writer.WriteFreeFormat(&error, 1));
    const auto errorSize = response.Size();
    Group120Var1 challenge;
    size_t nativeSize = 0, wireSize = 0, decodedSize = 0;
    REQUIRE(inspector.InspectEmbeddedChallenge(response.ToRSeq(), challenge, nativeSize));
    REQUIRE(nativeSize == errorSize); // G120V7 is not an embedded Challenge.
    REQUIRE_FALSE(inspector.HasPendingConfirm());
    REQUIRE(sender.Create(7, 1, key.Read(), response.ToRSeq(), wseq_t(wire.data(), wire.size()), wireSize));
    REQUIRE(receiver.Verify(7, 1, key.Read(), rseq_t(wire.data(), wireSize),
                            wseq_t(decoded.data(), decoded.size()), decodedSize));
    REQUIRE(rseq_t(decoded.data(), decodedSize).equals(response.ToRSeq()));
    REQUIRE(inspector.InspectEmbeddedChallenge(rseq_t(wire.data(), wireSize), challenge, nativeSize));
    REQUIRE(nativeSize == wireSize);
    // Existing codecs must still reject a malformed V7 qualifier or truncated body.
    native[6] = 0x07;
    REQUIRE_FALSE(inspector.InspectEmbeddedChallenge(response.ToRSeq(), challenge, nativeSize));
    native[6] = 0x5B;
    REQUIRE_FALSE(inspector.InspectEmbeddedChallenge(response.ToRSeq().take(errorSize - 1), challenge, nativeSize));
    if (confirm)
    {
        const auto embedded = Seed(41, false);
        REQUIRE(challenge.Read(Read(embedded).skip(10)));
        REQUIRE(writer.WriteFreeFormat(&challenge, 1));
        REQUIRE(inspector.InspectEmbeddedChallenge(response.ToRSeq(), challenge, nativeSize));
        REQUIRE(nativeSize == errorSize); // V7 before V1 is valid native content.
        std::vector<uint8_t> reversed(native.data(), native.data() + 4);
        reversed.insert(reversed.end(), embedded.begin() + 4, embedded.end());
        reversed.insert(reversed.end(), native.data() + 4, native.data() + errorSize);
        REQUIRE_FALSE(inspector.InspectEmbeddedChallenge(Read(reversed), challenge, nativeSize));
    }
}

TEST_CASE("AggressiveMode - association Challenge watermark spans UNS categories and preserves forward gaps", "[aggressive]")
{
    const auto mode = GENERATE(0, 1, 2); // Control, monitoring, embedded Control Challenge.
    const bool monitoring = mode == 1;
    const bool embedded = mode == 2;
    AggressiveMode engine(7, 16, monitoring);
    auto challenge = [&](uint32_t sequence, bool unsolicited) {
        auto bytes = Seed(sequence, monitoring);
        if (embedded)
        {
            bytes[0] = unsolicited ? 0xF5 : 0xE5;
            bytes[1] = unsolicited ? 0x82 : 0x81;
        }
        return bytes;
    };
    auto accept = [&](uint32_t sequence, bool unsolicited) {
        const auto bytes = challenge(sequence, unsolicited);
        REQUIRE(engine.RememberChallenge(Read(bytes), unsolicited, embedded));
        if (embedded)
            engine.DiscardPendingConfirms(); // Cancellation must retain the shared watermark.
    };
    auto reject = [&](uint32_t sequence, bool unsolicited) {
        const auto bytes = challenge(sequence, unsolicited);
        if (embedded)
        {
            Group120Var1 value;
            size_t nativeSize = 0;
            REQUIRE_FALSE(engine.InspectEmbeddedChallenge(Read(bytes), value, nativeSize));
        }
        REQUIRE_FALSE(engine.RememberChallenge(Read(bytes), unsolicited, embedded));
    };
    accept(0xFFFFFFFEu, true);
    reject(0xFFFFFFFDu, false);
    reject(0xFFFFFFFEu, false);
    accept(0, false); // UINT32 rollover across UNS categories.
    reject(0xFFFFFFFFu, true);
    reject(0, true);
    accept(0x60000000u, true);
    accept(0xC0000000u, true); // The older solicited transcript must not constrain the current watermark.
    accept(0x20000000u, false);
    reject(0xC0000000u, true);
}

TEST_CASE("AggressiveMode - each transcript retains its selected MAC after Code 5", "[aggressive][auth-error]")
{
    const bool monitoring = GENERATE(false, true);
    AuthenticationConfig config;
    config.permittedMACAlgorithms = {{4, 2, 0, 0}};
    AggressiveKey key;
    AggressiveMode sender(7, 16, monitoring), receiver(7, 16, monitoring);
    REQUIRE(sender.ConfigureMACs(config));
    REQUIRE(receiver.ConfigureMACs(config));
    const auto first = Seed(1, monitoring);
    REQUIRE(sender.RememberChallenge(Read(first), false));
    REQUIRE(receiver.RememberChallenge(Read(first), false));
    const auto next = Seed(2, monitoring, 10, 2);
    REQUIRE(sender.RememberChallenge(Read(next), true));
    REQUIRE(receiver.RememberChallenge(Read(next), true));
    HexSequence solicited(monitoring ? "C0 81 00 00" : "C0 02");
    HexSequence unsolicited(monitoring ? "D0 82 00 00" : "D0 00");
    std::array<uint8_t, 2048> wire{}, output{};
    size_t size = 0, nativeSize = 0;
    for (const auto& original : {solicited.ToRSeq(), unsolicited.ToRSeq()})
    {
        REQUIRE(sender.Create(7, 1, key.Read(), original, wseq_t(wire.data(), wire.size()), size));
        const auto expectedTag = (original[0] & 0x10) ? 10u : 16u;
        REQUIRE(size == original.length() + 16 + expectedTag);
        REQUIRE(receiver.Verify(7, 1, key.Read(), rseq_t(wire.data(), size), wseq_t(output.data(), output.size()), nativeSize));
        REQUIRE(rseq_t(output.data(), nativeSize).equals(original));
        REQUIRE_FALSE(receiver.Verify(7, 1, key.Read(), rseq_t(wire.data(), size), wseq_t(output.data(), output.size()), nativeSize));
    }
}


TEST_CASE("AggressiveMode - B07 signed CSQ half-window boundaries do not consume rejected tokens", "[aggressive][sa-b07]")
{
    const bool monitoring = GENERATE(false, true);
    const uint32_t delta = GENERATE(uint32_t(0), uint32_t(0x7FFFFFFF), uint32_t(0x80000000),
                                    uint32_t(0x80000001), uint32_t(0xFFFFFFFF));
    CAPTURE(monitoring, delta);
    AggressiveKey key;
    AggressiveMode sender(7, 16, monitoring), receiver(7, 16, monitoring);
    const auto seed = Seed(1, monitoring);
    REQUIRE(sender.RememberChallenge(Read(seed), false));
    REQUIRE(receiver.RememberChallenge(Read(seed), false));
    HexSequence native(monitoring ? "C0 81 00 00" : "C0 01 3C 01 06");
    std::array<uint8_t, 2048> original{}, changed{}, output{};
    size_t size = 0, decoded = 0;
    const uint16_t user = monitoring ? 1 : 2;
    REQUIRE(sender.Create(7, user, key.Read(), native.ToRSeq(), wseq_t(original.data(), original.size()), size));
    std::copy(original.begin(), original.end(), changed.begin());
    const size_t csqOffset = monitoring ? 8 : 6;
    const uint32_t sequence = uint32_t(1) + delta;
    for (size_t i = 0; i < 4; ++i) changed[csqOffset + i] = static_cast<uint8_t>(sequence >> (8 * i));
    auto transcript = seed;
    transcript.insert(transcript.end(), changed.begin(), changed.begin() + size - 16);
    // Give the changed CSQ a genuine valid MAC: rejection must be replay policy,
    // not merely an integrity failure caused by flipping an authenticated byte.
    REQUIRE(crypto::ComputeHMACSHA256(key.Read(), Read(transcript), wseq_t(changed.data() + size - 16, 16)) == crypto::Result::OK);
    const bool forward = delta != 0 && delta < 0x80000000u;
    REQUIRE(receiver.Verify(7, user, key.Read(), rseq_t(changed.data(), size), wseq_t(output.data(), output.size()), decoded) == forward);
    if (forward)
    {
        REQUIRE(rseq_t(output.data(), decoded).equals(native.ToRSeq()));
        REQUIRE_FALSE(receiver.Verify(7, user, key.Read(), rseq_t(changed.data(), size), wseq_t(output.data(), output.size()), decoded));
    }
    else
    {
        REQUIRE(decoded == 0);
        REQUIRE(receiver.Sequence() == 1);
        for (auto byte : output) REQUIRE(byte == 0);
        REQUIRE(receiver.Verify(7, user, key.Read(), rseq_t(original.data(), size), wseq_t(output.data(), output.size()), decoded));
        REQUIRE(rseq_t(output.data(), decoded).equals(native.ToRSeq()));
    }
}
