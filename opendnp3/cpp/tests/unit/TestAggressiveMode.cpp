// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/APDURequest.h"
#include "app/APDUResponse.h"
#include "app/parsing/APDUParser.h"
#include "auth/AggressiveMode.h"
#include "crypto/CryptoProvider.h"
#include "utils/BufferHelpers.h"

#include <ser4cpp/util/HexConversions.h>

#include <catch.hpp>
#include <openssl/crypto.h>
#include <openssl/provider.h>

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
std::vector<uint8_t> Seed(uint32_t sequence, bool monitoring, size_t tag = 16)
{
    std::array<uint8_t, 32> nonce{};
    nonce.fill(static_cast<uint8_t>(sequence));
    std::vector<uint8_t> bytes(monitoring ? 48 : 50);
    Group120Var1 value(sequence, monitoring ? 1 : 0, tag == 8 ? 3 : 4, 1, rseq_t(nonce.data(), nonce.size()));
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
    APDUWrapper invalidWrapper; REQUIRE_FALSE(invalidWrapper.AppendObjects(rseq_t()));
    uint8_t header[2]={}; APDURequest empty(wseq_t(header,2));
    REQUIRE(empty.AppendObjects(rseq_t())); REQUIRE_FALSE(empty.AppendObjects(rseq_t(header,1))); REQUIRE(empty.Size()==2);

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
