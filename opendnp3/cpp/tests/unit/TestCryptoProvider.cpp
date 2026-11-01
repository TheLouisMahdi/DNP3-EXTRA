// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "crypto/CryptoProvider.h"
#include "utils/BufferHelpers.h"

#include <catch.hpp>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#include <algorithm>
#include <array>
#include <climits>
#include <memory>
#include <vector>

using namespace opendnp3::crypto;
using namespace ser4cpp;

namespace
{
template<size_t N> wseq_t Write(std::array<uint8_t, N>& value)
{
    return wseq_t(value.data(), value.size());
}
template<size_t N> rseq_t Read(const std::array<uint8_t, N>& value)
{
    return rseq_t(value.data(), value.size());
}
bool Zero(rseq_t value)
{
    const uint8_t* begin = value;
    return std::all_of(begin, begin + value.length(), [](uint8_t v) { return v == 0; });
}

void CheckHMAC(rseq_t key, rseq_t message, const char* expectedHex)
{
    HexSequence expected(expectedHex);
    std::array<uint8_t, 32> output;
    REQUIRE(ComputeHMACSHA256(key, message, Write(output)) == Result::OK);
    REQUIRE(Read(output).equals(expected.ToRSeq()));
    for (size_t length : {8u, 16u})
    {
        output.fill(0xCC);
        REQUIRE(ComputeHMACSHA256(key, message, wseq_t(output.data(), length)) == Result::OK);
        REQUIRE(Read(output).take(length).equals(expected.ToRSeq().take(length)));
        REQUIRE(output[length] == 0xCC);
        REQUIRE(VerifyHMACSHA256(key, message, Read(output).take(length)) == Result::OK);
        // Every tag position must participate in verification.
        for (size_t i = 0; i < length; ++i)
        {
            output[i] ^= 1;
            REQUIRE(VerifyHMACSHA256(key, message, Read(output).take(length)) == Result::AUTHENTICATION_FAILED);
            output[i] ^= 1;
        }
    }
}

// Fresh context containing only the null provider: real OpenSSL algorithm/RNG
// failures, without replacing the production RNG or altering global configuration.
class NullProviderScope final
{
public:
    NullProviderScope()
        : context(OSSL_LIB_CTX_new(), OSSL_LIB_CTX_free),
          provider(context ? OSSL_PROVIDER_load(context.get(), "null") : nullptr, OSSL_PROVIDER_unload)
    {
        REQUIRE(context);
        REQUIRE(provider);
        previous = OSSL_LIB_CTX_set0_default(context.get());
        REQUIRE(previous);
    }
    ~NullProviderScope()
    {
        OSSL_LIB_CTX_set0_default(previous);
        OPENSSL_thread_stop_ex(context.get());
        ERR_clear_error();
    }

private:
    std::unique_ptr<OSSL_LIB_CTX, decltype(&OSSL_LIB_CTX_free)> context;
    std::unique_ptr<OSSL_PROVIDER, decltype(&OSSL_PROVIDER_unload)> provider;
    OSSL_LIB_CTX* previous = nullptr;
};
} // namespace

TEST_CASE("CryptoProvider - RFC4231 HMAC-SHA256 full and truncated", "[crypto]")
{
    // RFC 4231 sections 4.2, 4.3, 4.7 (includes a key longer than SHA256's block).
    std::array<uint8_t, 20> key1;
    key1.fill(0x0B);
    HexSequence message1("4869205468657265");
    CheckHMAC(Read(key1), message1.ToRSeq(), "B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7");
    HexSequence key2("4A656665");
    HexSequence message2("7768617420646F2079612077616E7420666F72206E6F7468696E673F");
    CheckHMAC(key2.ToRSeq(), message2.ToRSeq(), "5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843");
    std::array<uint8_t, 131> key6;
    key6.fill(0xAA);
    const std::string message6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    CheckHMAC(Read(key6), rseq_t(reinterpret_cast<const uint8_t*>(message6.data()), message6.size()),
              "60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54");
}

TEST_CASE("CryptoProvider - RFC4231 explicitly truncated vector", "[crypto]")
{
    // RFC 4231 section 4.6, Test Case 5 specifies a 128-bit result only.
    std::array<uint8_t, 20> key;
    key.fill(0x0C);
    HexSequence message("546573742057697468205472756E636174696F6E");
    HexSequence expected("A3B6167473100EE06E0C796C2955552B");
    std::array<uint8_t, 16> output;
    REQUIRE(ComputeHMACSHA256(Read(key), message.ToRSeq(), Write(output)) == Result::OK);
    REQUIRE(Read(output).equals(expected.ToRSeq()));
}

TEST_CASE("CryptoProvider - HMAC validation and failure clearing", "[crypto]")
{
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 40> output;
    for (size_t length = 0; length <= output.size(); ++length)
    {
        output.fill(0xCC);
        const auto result = ComputeHMACSHA256(Read(key), rseq_t(), wseq_t(output.data(), length));
        if (length == 8 || length == 16 || length == 32)
            REQUIRE(result == Result::OK);
        else
        {
            REQUIRE(result == Result::INVALID_OUTPUT_SIZE);
            REQUIRE(Zero(Read(output).take(length)));
        }
        if (length < output.size())
            REQUIRE(output[length] == 0xCC);
        const auto verify = VerifyHMACSHA256(Read(key), rseq_t(), Read(output).take(length));
        if (length == 8 || length == 16)
            REQUIRE(verify == Result::OK);
        else
            REQUIRE(verify == Result::INVALID_INPUT);
    }
    output.fill(0xCC);
    REQUIRE(ComputeHMACSHA256(rseq_t(), rseq_t(), Write(output).take(32)) == Result::INVALID_INPUT);
    REQUIRE(Zero(Read(output).take(32)));
    REQUIRE(ComputeHMACSHA256(rseq_t(nullptr, 32), rseq_t(), Write(output).take(32)) == Result::INVALID_INPUT);
    output.fill(0xCC);
    REQUIRE(ComputeHMACSHA256(Read(key), rseq_t(nullptr, 1), Write(output).take(32)) == Result::INVALID_INPUT);
    REQUIRE(Zero(Read(output).take(32)));
    REQUIRE(ComputeHMACSHA256(Read(key), rseq_t(), wseq_t(nullptr, 32)) == Result::INVALID_OUTPUT_SIZE);
    REQUIRE(VerifyHMACSHA256(Read(key), rseq_t(), rseq_t(nullptr, 8)) == Result::INVALID_INPUT);
    REQUIRE(ComputeHMACSHA256(Read(key), rseq_t(), Write(key)) == Result::INVALID_INPUT);
    REQUIRE(Zero(Read(key)));
}

TEST_CASE("CryptoProvider - RFC3394 AES256 wrapping vectors and integrity", "[crypto]")
{
    // RFC 3394 sections 4.3, 4.5 and 4.6: 256-bit KEK, 128/192/256-bit key data.
    HexSequence key("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    const char* plaintexts[] = {"00112233445566778899AABBCCDDEEFF", "00112233445566778899AABBCCDDEEFF0001020304050607",
                                "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"};
    const char* ciphertexts[] = {"64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
                                 "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
                                 "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"};
    for (size_t i = 0; i < 3; ++i)
    {
        HexSequence plaintext(plaintexts[i]);
        HexSequence expected(ciphertexts[i]);
        std::vector<uint8_t> wrapped(expected.ToRSeq().length());
        std::vector<uint8_t> recovered(plaintext.ToRSeq().length());
        REQUIRE(AES256KeyWrap(key.ToRSeq(), plaintext.ToRSeq(), wseq_t(wrapped.data(), wrapped.size())) == Result::OK);
        REQUIRE(rseq_t(wrapped.data(), wrapped.size()).equals(expected.ToRSeq()));
        REQUIRE(AES256KeyUnwrap(key.ToRSeq(), expected.ToRSeq(), wseq_t(recovered.data(), recovered.size()))
                == Result::OK);
        REQUIRE(rseq_t(recovered.data(), recovered.size()).equals(plaintext.ToRSeq()));
        for (size_t j = 0; j < wrapped.size(); ++j)
        {
            wrapped[j] ^= 1;
            std::fill(recovered.begin(), recovered.end(), 0xCC);
            REQUIRE(AES256KeyUnwrap(key.ToRSeq(), rseq_t(wrapped.data(), wrapped.size()),
                                    wseq_t(recovered.data(), recovered.size()))
                    == Result::CRYPTO_ERROR);
            REQUIRE(Zero(rseq_t(recovered.data(), recovered.size())));
            wrapped[j] ^= 1;
        }
        std::array<uint8_t, 32> wrongKey{};
        REQUIRE(AES256KeyUnwrap(Read(wrongKey), expected.ToRSeq(), wseq_t(recovered.data(), recovered.size()))
                == Result::CRYPTO_ERROR);
        REQUIRE(Zero(rseq_t(recovered.data(), recovered.size())));
    }
}

TEST_CASE("CryptoProvider - wrap input and output bounds", "[crypto]")
{
    std::array<uint8_t, 40> key{};
    std::array<uint8_t, 48> input{};
    std::array<uint8_t, 56> output;
    for (size_t length = 0; length <= key.size(); ++length)
    {
        if (length == 32)
            continue;
        output.fill(0xCC);
        REQUIRE(AES256KeyWrap(Read(key).take(length), Read(input).take(16), Write(output).take(24))
                == Result::INVALID_INPUT);
        REQUIRE(Zero(Read(output).take(24)));
        output.fill(0xCC);
        REQUIRE(AES256KeyUnwrap(Read(key).take(length), Read(input).take(24), Write(output).take(16))
                == Result::INVALID_INPUT);
        REQUIRE(Zero(Read(output).take(16)));
    }
    for (size_t length = 0; length <= input.size(); ++length)
    {
        if (length >= 16 && length % 8 == 0)
            continue;
        output.fill(0xCC);
        REQUIRE(AES256KeyWrap(Read(key).take(32), Read(input).take(length), Write(output)) == Result::INVALID_INPUT);
        REQUIRE(Zero(Read(output)));
    }
    for (size_t length = 0; length <= input.size(); ++length)
    {
        if (length >= 24 && length % 8 == 0)
            continue;
        REQUIRE(AES256KeyUnwrap(Read(key).take(32), Read(input).take(length), Write(output)) == Result::INVALID_INPUT);
    }
    for (size_t length : {0u, 15u, 17u, 23u, 25u, 56u})
    {
        output.fill(0xCC);
        REQUIRE(AES256KeyWrap(Read(key).take(32), Read(input).take(16), Write(output).take(length))
                == Result::INVALID_OUTPUT_SIZE);
        REQUIRE(Zero(Read(output).take(length)));
        if (length < output.size())
            REQUIRE(output[length] == 0xCC);
        REQUIRE(AES256KeyUnwrap(Read(key).take(32), Read(input).take(24), Write(output).take(length))
                == Result::INVALID_OUTPUT_SIZE);
    }
    REQUIRE(AES256KeyWrap(rseq_t(nullptr, 32), Read(input).take(16), Write(output).take(24)) == Result::INVALID_INPUT);
    REQUIRE(AES256KeyWrap(Read(key).take(32), rseq_t(nullptr, 16), Write(output).take(24)) == Result::INVALID_INPUT);
    REQUIRE(AES256KeyWrap(Read(key).take(32), Read(input).take(16), wseq_t(nullptr, 24))
            == Result::INVALID_OUTPUT_SIZE);
    // Oversized views are rejected before dereferencing input or allocating memory.
    REQUIRE(AES256KeyWrap(Read(key).take(32), rseq_t(input.data(), static_cast<size_t>(INT_MAX) + 1), Write(output))
            == Result::INVALID_INPUT);
    REQUIRE(AES256KeyWrap(Read(key).take(32), Read(input).take(16), wseq_t(input.data(), 24)) == Result::INVALID_INPUT);
    REQUIRE(AES256KeyWrap(Read(key).take(32), Read(input).take(16), wseq_t(key.data(), 24)) == Result::INVALID_INPUT);
}

TEST_CASE("CryptoProvider - secure random and explicit clear", "[crypto]")
{
    std::array<uint8_t, 66> first;
    std::array<uint8_t, 64> second;
    first.fill(0xCC);
    REQUIRE(GenerateRandom(wseq_t(first.data() + 1, 64)) == Result::OK);
    REQUIRE(first.front() == 0xCC);
    REQUIRE(first.back() == 0xCC);
    REQUIRE(GenerateRandom(Write(second)) == Result::OK);
    // Smoke check only, not an entropy estimate or statistical certification.
    REQUIRE_FALSE(rseq_t(first.data() + 1, 64).equals(Read(second)));
    REQUIRE(GenerateRandom(wseq_t()) == Result::OK);
    REQUIRE(GenerateRandom(wseq_t(nullptr, 1)) == Result::INVALID_INPUT);
    Clear(Write(first));
    Clear(Write(second));
    Clear(wseq_t());
    REQUIRE(Zero(Read(first)));
    REQUIRE(Zero(Read(second)));
}

TEST_CASE("CryptoProvider - unavailable provider fails closed and recovers", "[crypto]")
{
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 24> input{};
    std::array<uint8_t, 32> output;
    {
        NullProviderScope unavailable;
        output.fill(0xCC);
        REQUIRE(GenerateRandom(Write(output)) == Result::CRYPTO_ERROR);
        REQUIRE(Zero(Read(output)));
        output.fill(0xCC);
        REQUIRE(ComputeHMACSHA256(Read(key), Read(input), Write(output)) == Result::CRYPTO_ERROR);
        REQUIRE(Zero(Read(output)));
        REQUIRE(VerifyHMACSHA256(Read(key), Read(input), Read(input).take(8)) == Result::CRYPTO_ERROR);
        output.fill(0xCC);
        REQUIRE(AES256KeyWrap(Read(key), Read(input), Write(output)) == Result::CRYPTO_ERROR);
        REQUIRE(Zero(Read(output)));
        output.fill(0xCC);
        REQUIRE(AES256KeyUnwrap(Read(key), Read(input), Write(output).take(16)) == Result::CRYPTO_ERROR);
        REQUIRE(Zero(Read(output).take(16)));
        REQUIRE(output[16] == 0xCC);
    }
    REQUIRE(GenerateRandom(Write(output)) == Result::OK);
    REQUIRE(ComputeHMACSHA256(Read(key), Read(input), Write(output)) == Result::OK);
    Clear(Write(output));
}

TEST_CASE("CryptoProvider - RFC2202 SHA1 full and IEEE truncated tags", "[crypto]")
{
    std::array<uint8_t, 20> first;
    first.fill(0x0B);
    HexSequence second("4A656665");
    HexSequence message1("4869205468657265"), message2("7768617420646F2079612077616E7420666F72206E6F7468696E673F");
    HexSequence expected1("B617318655057264E28BC0B6FB378C8EF146BE00"),
        expected2("EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79");
    const auto vector = GENERATE(0, 1);
    auto key = vector ? second.ToRSeq() : Read(first);
    auto message = vector ? message2.ToRSeq() : message1.ToRSeq();
    auto expected = vector ? expected2.ToRSeq() : expected1.ToRSeq();
    std::array<uint8_t, 21> output;
    for (size_t length : {8u, 10u, 20u})
    {
        output.fill(0xCC);
        REQUIRE(ComputeHMACSHA1(key, message, Write(output).take(length)) == Result::OK);
        REQUIRE(Read(output).take(length).equals(expected.take(length)));
        REQUIRE(output[length] == 0xCC);
        if (length == 20)
        {
            REQUIRE(VerifyHMACSHA1(key, message, Read(output).take(length)) == Result::INVALID_INPUT);
            continue;
        }
        REQUIRE(VerifyHMACSHA1(key, message, Read(output).take(length)) == Result::OK);
        for (size_t i = 0; i < length; ++i)
        {
            output[i] ^= 1;
            REQUIRE(VerifyHMACSHA1(key, message, Read(output).take(length)) == Result::AUTHENTICATION_FAILED);
            output[i] ^= 1;
        }
    }
}
TEST_CASE("CryptoProvider - SHA1 validation and AES128 RFC3394 integrity", "[crypto]")
{
    HexSequence kek("000102030405060708090A0B0C0D0E0F"), plain("00112233445566778899AABBCCDDEEFF");
    HexSequence cipher("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
    std::array<uint8_t, 32> key{}, output;
    std::array<uint8_t, 24> wrapped;
    REQUIRE(AES128KeyWrap(kek.ToRSeq(), plain.ToRSeq(), Write(wrapped)) == Result::OK);
    REQUIRE(Read(wrapped).equals(cipher.ToRSeq()));
    REQUIRE(AES128KeyUnwrap(kek.ToRSeq(), Read(wrapped), Write(output).take(16)) == Result::OK);
    REQUIRE(Read(output).take(16).equals(plain.ToRSeq()));
    for (size_t i = 0; i < wrapped.size(); ++i)
    {
        wrapped[i] ^= 1;
        output.fill(0xCC);
        REQUIRE(AES128KeyUnwrap(kek.ToRSeq(), Read(wrapped), Write(output).take(16)) == Result::CRYPTO_ERROR);
        REQUIRE(Zero(Read(output).take(16)));
        wrapped[i] ^= 1;
    }
    for (size_t length = 0; length <= 32; ++length)
    {
        output.fill(0xCC);
        const auto result = ComputeHMACSHA1(Read(key), rseq_t(), Write(output).take(length));
        if (length == 8 || length == 10 || length == 20)
            REQUIRE(result == Result::OK);
        else
        {
            REQUIRE(result == Result::INVALID_OUTPUT_SIZE);
            REQUIRE(Zero(Read(output).take(length)));
        }
        output.fill(0xCC);
        if (length != 16)
        {
            REQUIRE(AES128KeyWrap(Read(key).take(length), plain.ToRSeq(), Write(wrapped)) == Result::INVALID_INPUT);
            REQUIRE(Zero(Read(wrapped)));
        }
    }
    REQUIRE(ComputeHMACSHA1(rseq_t(), plain.ToRSeq(), Write(output).take(10)) == Result::INVALID_INPUT);
    REQUIRE(ComputeHMACSHA1(Read(key), rseq_t(nullptr, 1), Write(output).take(10)) == Result::INVALID_INPUT);
    REQUIRE(ComputeHMACSHA1(Read(key), rseq_t(), wseq_t(nullptr, 10)) == Result::INVALID_OUTPUT_SIZE);
    REQUIRE(VerifyHMACSHA1(Read(key), rseq_t(), rseq_t(nullptr, 10)) == Result::INVALID_INPUT);
    REQUIRE(ComputeHMACSHA1(Read(key), rseq_t(), Write(key).take(10)) == Result::INVALID_INPUT);
    REQUIRE(Zero(Read(key).take(10)));
    REQUIRE(AES128KeyWrap(kek.ToRSeq(), rseq_t(nullptr, 16), Write(wrapped)) == Result::INVALID_INPUT);
    REQUIRE(AES128KeyWrap(kek.ToRSeq(), plain.ToRSeq(), Write(output).take(23)) == Result::INVALID_OUTPUT_SIZE);
    REQUIRE(AES128KeyWrap(Read(key).take(16), plain.ToRSeq(), Write(key).take(24)) == Result::INVALID_INPUT);
    REQUIRE(Zero(Read(key).take(24)));
    {
        NullProviderScope unavailable;
        output.fill(0xCC);
        REQUIRE(ComputeHMACSHA1(Read(key), plain.ToRSeq(), Write(output).take(10)) == Result::CRYPTO_ERROR);
        REQUIRE(Zero(Read(output).take(10)));
        REQUIRE(VerifyHMACSHA1(Read(key), plain.ToRSeq(), cipher.ToRSeq().take(10)) == Result::CRYPTO_ERROR);
        REQUIRE(AES128KeyWrap(kek.ToRSeq(), plain.ToRSeq(), Write(wrapped)) == Result::CRYPTO_ERROR);
        REQUIRE(Zero(Read(wrapped)));
        REQUIRE(AES128KeyUnwrap(kek.ToRSeq(), cipher.ToRSeq(), Write(output).take(16)) == Result::CRYPTO_ERROR);
        REQUIRE(Zero(Read(output).take(16)));
    }
}
