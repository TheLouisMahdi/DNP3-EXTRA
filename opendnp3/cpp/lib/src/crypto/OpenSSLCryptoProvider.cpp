// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "crypto/CryptoProvider.h"
#include <openssl/sha.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <climits>
#include <cstring>
#include <memory>

namespace opendnp3
{
namespace crypto
{
    namespace
    {

        bool Valid(ser4cpp::rseq_t input)
        {
            return input.length() == 0 || static_cast<const uint8_t*>(input) != nullptr;
        }

        bool Overlaps(ser4cpp::rseq_t input, ser4cpp::wseq_t output)
        {
            if (!input.length() || !output.length())
                return false;
            const auto a = reinterpret_cast<uintptr_t>(static_cast<const uint8_t*>(input));
            const auto b = reinterpret_cast<uintptr_t>(static_cast<uint8_t*>(output));
            return a <= b ? b - a < input.length() : a - b < output.length();
        }

        // Includes provider errors and validation failures; success must explicitly commit.
        class OutputGuard final
        {
        public:
            explicit OutputGuard(ser4cpp::wseq_t output_) : output(output_) {}
            ~OutputGuard()
            {
                if (!committed)
                    Clear(output);
            }
            void Commit()
            {
                committed = true;
            }
            OutputGuard(const OutputGuard&) = delete;
            OutputGuard& operator=(const OutputGuard&) = delete;

        private:
            ser4cpp::wseq_t output;
            bool committed = false;
        };

        class Digest final
        {
        public:
            std::array<uint8_t, 32> bytes{};
            ~Digest()
            {
                OPENSSL_cleanse(bytes.data(), bytes.size());
            }
        };

        // OpenSSL may write plaintext before reporting an unwrap integrity failure.
        class SecretBuffer final
        {
        public:
            explicit SecretBuffer(size_t size_) : size(size_), data(static_cast<uint8_t*>(OPENSSL_malloc(size))) {}
            ~SecretBuffer()
            {
                OPENSSL_clear_free(data, size);
            }
            SecretBuffer(const SecretBuffer&) = delete;
            SecretBuffer& operator=(const SecretBuffer&) = delete;
            const size_t size;
            uint8_t* const data;
        };

        Result KeyWrap(bool encrypt, size_t keySize, ser4cpp::rseq_t key, ser4cpp::rseq_t input, ser4cpp::wseq_t output)
        {
            OutputGuard guard(output);
            if (!Valid(key) || !Valid(input) || key.length() != keySize || input.length() < (encrypt ? 16u : 24u)
                || input.length() % 8 != 0 || input.length() > static_cast<size_t>(INT_MAX - 16)
                || Overlaps(key, output) || Overlaps(input, output))
                return Result::INVALID_INPUT;

            const auto expected = encrypt ? input.length() + 8 : input.length() - 8;
            if (!static_cast<uint8_t*>(output) || output.length() != expected)
                return Result::INVALID_OUTPUT_SIZE;

            SecretBuffer temporary(input.length() + 8 + EVP_MAX_BLOCK_LENGTH);
            using Context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
            Context context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
            if (!temporary.data || !context)
                return Result::CRYPTO_ERROR;
            EVP_CIPHER_CTX_set_flags(context.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
            if (EVP_CipherInit_ex2(context.get(), (keySize == 16 ? EVP_aes_128_wrap() : EVP_aes_256_wrap()), key,
                                   nullptr, encrypt ? 1 : 0, nullptr)
                != 1)
                return Result::CRYPTO_ERROR;
            int written = 0;
            int final = 0;
            if (EVP_CipherUpdate(context.get(), temporary.data, &written, input, static_cast<int>(input.length())) != 1
                || written < 0 || static_cast<size_t>(written) > temporary.size - EVP_MAX_BLOCK_LENGTH
                || EVP_CipherFinal_ex(context.get(), temporary.data + written, &final) != 1 || final < 0
                || static_cast<size_t>(written) + static_cast<size_t>(final) != expected)
                return Result::CRYPTO_ERROR;

            std::memcpy(output, temporary.data, expected);
            guard.Commit();
            return Result::OK;
        }

    } // namespace

    void Clear(ser4cpp::wseq_t output)
    {
        if (static_cast<uint8_t*>(output) && output.length())
            OPENSSL_cleanse(output, output.length());
    }

    bool ConstantTimeEqual(ser4cpp::rseq_t first, ser4cpp::rseq_t second)
    {
        return Valid(first) && Valid(second) && first.length() == second.length()
            && (first.length() == 0 || CRYPTO_memcmp(first, second, first.length()) == 0);
    }

    Result GenerateRandom(ser4cpp::wseq_t output)
    {
        OutputGuard guard(output);
        if (!output.length())
        {
            guard.Commit();
            return Result::OK;
        }
        if (!static_cast<uint8_t*>(output))
            return Result::INVALID_INPUT;
        if (RAND_bytes_ex(nullptr, output, output.length(), 256) != 1)
            return Result::CRYPTO_ERROR;
        guard.Commit();
        return Result::OK;
    }

    Result SHA256(ser4cpp::rseq_t message, ser4cpp::wseq_t output)
    {
        OutputGuard guard(output);
        if (!Valid(message) || Overlaps(message, output)) return Result::INVALID_INPUT;
        if (!static_cast<uint8_t*>(output) || output.length() != 32) return Result::INVALID_OUTPUT_SIZE;
        size_t size = 0;
        if (EVP_Q_digest(nullptr, "SHA256", nullptr, message, message.length(), output, &size) != 1 || size != 32)
            return Result::CRYPTO_ERROR;
        guard.Commit();
        return Result::OK;
    }
    Result ExpandUpdateKeyChallenge(ser4cpp::rseq_t seed, ser4cpp::wseq_t output)
    {
        OutputGuard guard(output);
        if (!Valid(seed) || seed.length() < 20 || seed.length() > 64 || Overlaps(seed, output)) return Result::INVALID_INPUT;
        if (!static_cast<uint8_t*>(output) || output.length() != 32) return Result::INVALID_OUTPUT_SIZE;
        struct State
        {
            std::array<uint8_t, 64> key{}, block{};
            std::array<uint8_t, 20> digest{};
            std::array<uint32_t, 5> words{};
            SHA_CTX hash{};
            ~State()
            {
                OPENSSL_cleanse(key.data(), key.size());
                OPENSSL_cleanse(block.data(), block.size());
                OPENSSL_cleanse(digest.data(), digest.size());
                OPENSSL_cleanse(words.data(), sizeof(words));
                OPENSSL_cleanse(&hash, sizeof(hash));
            }
        } state;
        std::memcpy(state.key.data(), seed, seed.length());
        for (size_t round = 0; round < 2; ++round)
        {
            // G(t,c) is one SHA-1 compression block, zero-padded, WITHOUT
            // the SHA-1 message-length padding. EVP_Digest would be incorrect.
            state.block.fill(0);
            std::memcpy(state.block.data(), state.key.data(), seed.length());
            if (SHA1_Init(&state.hash) != 1) return Result::CRYPTO_ERROR;
            SHA1_Transform(&state.hash, state.block.data());
            state.words = {{state.hash.h0, state.hash.h1, state.hash.h2, state.hash.h3, state.hash.h4}};
            for (size_t n = 0; n < 20; ++n)
                state.digest[n] = static_cast<uint8_t>(state.words[n / 4] >> (24 - 8 * (n % 4)));
            const size_t count = round == 0 ? 20 : 12;
            std::memcpy(static_cast<uint8_t*>(output) + round * 20, state.digest.data(), count);
            // XKEY = (1 + XKEY + x_j) mod 2^b, big-endian b-bit integer.
            unsigned carry = 1;
            for (size_t n = 0; n < seed.length(); ++n)
            {
                const size_t i = seed.length() - 1 - n;
                const unsigned sum = state.key[i] + (n < 20 ? state.digest[19 - n] : 0) + carry;
                state.key[i] = static_cast<uint8_t>(sum);
                carry = sum >> 8;
            }
        }
        guard.Commit();
        return Result::OK;
    }
    Result GenerateUpdateKeyChallenge(ser4cpp::wseq_t output)
    {
        OutputGuard guard(output);
        Digest seed;
        if (!static_cast<uint8_t*>(output) || output.length() != 32) return Result::INVALID_OUTPUT_SIZE;
        const auto result = GenerateRandom({seed.bytes.data(), seed.bytes.size()});
        if (result != Result::OK) return result;
        const auto expanded = ExpandUpdateKeyChallenge({seed.bytes.data(), seed.bytes.size()}, output);
        if (expanded == Result::OK) guard.Commit();
        return expanded;
    }
    Result ComputeHMACSHA256(ser4cpp::rseq_t key, ser4cpp::rseq_t message, ser4cpp::wseq_t output)
    {
        OutputGuard guard(output);
        if (!Valid(key) || !key.length() || !Valid(message) || Overlaps(key, output) || Overlaps(message, output))
            return Result::INVALID_INPUT;
        if (!static_cast<uint8_t*>(output) || (output.length() != 8 && output.length() != 16 && output.length() != 32))
            return Result::INVALID_OUTPUT_SIZE;

        Digest digest;
        size_t size = 0;
        if (!EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, key, key.length(), message, message.length(),
                       digest.bytes.data(), digest.bytes.size(), &size)
            || size != digest.bytes.size())
            return Result::CRYPTO_ERROR;
        std::memcpy(output, digest.bytes.data(), output.length());
        guard.Commit();
        return Result::OK;
    }

    Result VerifyHMACSHA256(ser4cpp::rseq_t key, ser4cpp::rseq_t message, ser4cpp::rseq_t tag)
    {
        if (!Valid(tag) || (tag.length() != 8 && tag.length() != 16))
            return Result::INVALID_INPUT;
        Digest digest;
        const auto result = ComputeHMACSHA256(key, message, ser4cpp::wseq_t(digest.bytes.data(), digest.bytes.size()));
        if (result != Result::OK)
            return result;
        return CRYPTO_memcmp(digest.bytes.data(), tag, tag.length()) == 0 ? Result::OK : Result::AUTHENTICATION_FAILED;
    }

    Result ComputeHMACSHA1(ser4cpp::rseq_t key, ser4cpp::rseq_t message, ser4cpp::wseq_t output)
    {
        OutputGuard guard(output);
        if (!Valid(key) || !key.length() || !Valid(message) || Overlaps(key, output) || Overlaps(message, output))
            return Result::INVALID_INPUT;
        if (!static_cast<uint8_t*>(output) || (output.length() != 8 && output.length() != 10 && output.length() != 20))
            return Result::INVALID_OUTPUT_SIZE;
        Digest digest;
        size_t size = 0;
        if (!EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA1", nullptr, key, key.length(), message, message.length(),
                       digest.bytes.data(), digest.bytes.size(), &size)
            || size != 20)
            return Result::CRYPTO_ERROR;
        std::memcpy(output, digest.bytes.data(), output.length());
        guard.Commit();
        return Result::OK;
    }
    Result VerifyHMACSHA1(ser4cpp::rseq_t key, ser4cpp::rseq_t message, ser4cpp::rseq_t tag)
    {
        if (!Valid(tag) || (tag.length() != 8 && tag.length() != 10))
            return Result::INVALID_INPUT;
        Digest digest;
        const auto result = ComputeHMACSHA1(key, message, ser4cpp::wseq_t(digest.bytes.data(), 20));
        if (result != Result::OK)
            return result;
        return CRYPTO_memcmp(digest.bytes.data(), tag, tag.length()) == 0 ? Result::OK : Result::AUTHENTICATION_FAILED;
    }
    Result AES128KeyWrap(ser4cpp::rseq_t key, ser4cpp::rseq_t plaintext, ser4cpp::wseq_t output)
    {
        return KeyWrap(true, 16, key, plaintext, output);
    }
    Result AES128KeyUnwrap(ser4cpp::rseq_t key, ser4cpp::rseq_t wrapped, ser4cpp::wseq_t output)
    {
        return KeyWrap(false, 16, key, wrapped, output);
    }

    Result AES256KeyWrap(ser4cpp::rseq_t key, ser4cpp::rseq_t plaintext, ser4cpp::wseq_t output)
    {
        return KeyWrap(true, 32, key, plaintext, output);
    }

    Result AES256KeyUnwrap(ser4cpp::rseq_t key, ser4cpp::rseq_t wrapped, ser4cpp::wseq_t output)
    {
        return KeyWrap(false, 32, key, wrapped, output);
    }

} // namespace crypto
} // namespace opendnp3
