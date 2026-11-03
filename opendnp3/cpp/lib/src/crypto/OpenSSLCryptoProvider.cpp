// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "crypto/CryptoProvider.h"
#include <openssl/sha.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>

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

    namespace
    {
        using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
        using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
        Key Method68Key(ser4cpp::rseq_t der, bool privateKey, bool rsa)
        {
            Key key(nullptr, EVP_PKEY_free);
            if (!Valid(der) || der.is_empty() || der.length() > (privateKey ? 2048u : 1024u)) return key;
            const auto* cursor = static_cast<const uint8_t*>(der);
            key.reset(privateKey ? d2i_AutoPrivateKey_ex(nullptr, &cursor, static_cast<long>(der.length()), nullptr, nullptr)
                                 : d2i_PUBKEY_ex(nullptr, &cursor, static_cast<long>(der.length()), nullptr, nullptr));
            if (!key || cursor != static_cast<const uint8_t*>(der) + der.length()
                || EVP_PKEY_is_a(key.get(), rsa ? "RSA" : "DSA") != 1 || EVP_PKEY_get_bits(key.get()) != 2048)
                return Key(nullptr, EVP_PKEY_free);
            if (!privateKey)
            {
                std::array<uint8_t, 1024> canonical{};
                const int size = i2d_PUBKEY(key.get(), nullptr);
                auto* dest = canonical.data();
                if (size != der.length() || size > canonical.size() || i2d_PUBKEY(key.get(), &dest) != size
                    || !ConstantTimeEqual(der, {canonical.data(), static_cast<size_t>(size)})) return Key(nullptr, EVP_PKEY_free);
            }
            if (!rsa)
            {
                BIGNUM* raw = nullptr;
                const bool valid = EVP_PKEY_get_bn_param(key.get(), OSSL_PKEY_PARAM_FFC_Q, &raw) == 1
                    && raw && BN_num_bits(raw) == 256;
                BN_free(raw);
                if (!valid) return Key(nullptr, EVP_PKEY_free);
            }
            KeyContext context(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr), EVP_PKEY_CTX_free);
            if (!context || (!rsa && EVP_PKEY_param_check(context.get()) != 1)
                || EVP_PKEY_public_check(context.get()) != 1
                || (privateKey && (EVP_PKEY_private_check(context.get()) != 1
                    || EVP_PKEY_pairwise_check(context.get()) != 1))) return Key(nullptr, EVP_PKEY_free);
            return key;
        }
        bool OAEP(EVP_PKEY_CTX* context)
        {
            return EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING) > 0
                && EVP_PKEY_CTX_set_rsa_oaep_md_name(context, "SHA256", nullptr) > 0
                && EVP_PKEY_CTX_set_rsa_mgf1_md_name(context, "SHA256", nullptr) > 0;
        }
    }
    bool ValidateMethod68PublicKey(ser4cpp::rseq_t key, bool rsa)
    {
        return bool(Method68Key(key, false, rsa));
    }
    Result RSAOAEP2048Encrypt(ser4cpp::rseq_t publicKey, ser4cpp::rseq_t plaintext, ser4cpp::wseq_t output)
    {
        OutputGuard guard(output);
        if (!Valid(plaintext) || plaintext.is_empty() || plaintext.length() > 190
            || Overlaps(publicKey, output) || Overlaps(plaintext, output)) return Result::INVALID_INPUT;
        if (!static_cast<uint8_t*>(output) || output.length() != 256) return Result::INVALID_OUTPUT_SIZE;
        auto key = Method68Key(publicKey, false, true);
        KeyContext context(key ? EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr) : nullptr, EVP_PKEY_CTX_free);
        size_t size = output.length();
        if (!context || EVP_PKEY_encrypt_init(context.get()) <= 0 || !OAEP(context.get())
            || EVP_PKEY_encrypt(context.get(), output, &size, plaintext, plaintext.length()) <= 0 || size != 256)
            return Result::CRYPTO_ERROR;
        guard.Commit();
        return Result::OK;
    }
    Result RSAOAEP2048Decrypt(ser4cpp::rseq_t privateKey, ser4cpp::rseq_t ciphertext,
                             ser4cpp::wseq_t output, size_t& size)
    {
        size = 0;
        OutputGuard guard(output);
        if (!Valid(ciphertext) || ciphertext.length() != 256 || Overlaps(privateKey, output)
            || Overlaps(ciphertext, output)) return Result::INVALID_INPUT;
        if (!static_cast<uint8_t*>(output) || output.length() < 190) return Result::INVALID_OUTPUT_SIZE;
        auto key = Method68Key(privateKey, true, true);
        KeyContext context(key ? EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr) : nullptr, EVP_PKEY_CTX_free);
        SecretBuffer plain(256);
        size_t length = plain.size;
        if (!context || !plain.data || EVP_PKEY_decrypt_init(context.get()) <= 0 || !OAEP(context.get())
            || EVP_PKEY_decrypt(context.get(), plain.data, &length, ciphertext, ciphertext.length()) <= 0
            || length > 190 || !length) return Result::CRYPTO_ERROR;
        Clear(output);
        std::memcpy(output, plain.data, length);
        size = length;
        guard.Commit();
        return Result::OK;
    }
    Result DSASHA256Sign(ser4cpp::rseq_t privateKey, ser4cpp::rseq_t message, ser4cpp::wseq_t output, size_t& size)
    {
        size = 0;
        OutputGuard guard(output);
        if (!Valid(message) || Overlaps(privateKey, output) || Overlaps(message, output)) return Result::INVALID_INPUT;
        if (!static_cast<uint8_t*>(output) || output.length() < 72) return Result::INVALID_OUTPUT_SIZE;
        auto key = Method68Key(privateKey, true, false);
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        size_t length = output.length();
        if (!key || !context || EVP_DigestSignInit_ex(context.get(), nullptr, "SHA256", nullptr, nullptr, key.get(), nullptr) <= 0
            || EVP_DigestSign(context.get(), output, &length, message, message.length()) <= 0 || length > 72)
            return Result::CRYPTO_ERROR;
        size = length;
        guard.Commit();
        return Result::OK;
    }
    Result DSASHA256Verify(ser4cpp::rseq_t publicKey, ser4cpp::rseq_t message, ser4cpp::rseq_t signature)
    {
        if (!Valid(message) || !Valid(signature) || signature.length() < 8 || signature.length() > 72)
            return Result::INVALID_INPUT;
        const auto* cursor = static_cast<const uint8_t*>(signature);
        std::unique_ptr<DSA_SIG, decltype(&DSA_SIG_free)> decoded(
            d2i_DSA_SIG(nullptr, &cursor, static_cast<long>(signature.length())), DSA_SIG_free);
        std::array<uint8_t, 72> canonical{};
        auto* dest = canonical.data();
        if (!decoded || cursor != static_cast<const uint8_t*>(signature) + signature.length()
            || i2d_DSA_SIG(decoded.get(), &dest) != signature.length()
            || !ConstantTimeEqual(signature, {canonical.data(), signature.length()})) return Result::AUTHENTICATION_FAILED;
        auto key = Method68Key(publicKey, false, false);
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!key || !context || EVP_DigestVerifyInit_ex(context.get(), nullptr, "SHA256", nullptr, nullptr, key.get(), nullptr) <= 0)
            return Result::CRYPTO_ERROR;
        return EVP_DigestVerify(context.get(), signature, signature.length(), message, message.length()) == 1
            ? Result::OK : Result::AUTHENTICATION_FAILED;
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
