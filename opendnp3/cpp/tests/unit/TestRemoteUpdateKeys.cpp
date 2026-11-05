// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/UpdateKeyFunctions.h"
#include "crypto/CryptoProvider.h"
#include "auth/RemoteUpdateKeys.h"
#include "app/parsing/APDUHeaderParser.h"
#include "utils/MasterTestFixture.h"
#include "utils/OutstationTestObject.h"
#include "dnp3mocks/MockTaskCallback.h"
#include "dnp3mocks/RemoteUpdateKeyCredentials.h"
#include "dnp3mocks/AsymmetricUpdateKeyCredentials.h"
#include "utils/BufferHelpers.h"

#include <ser4cpp/util/HexConversions.h>
#include <catch.hpp>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#include <array>
#include <algorithm>
#include <cstring>
#include <vector>
#ifdef _WIN32
#include "opendnp3/auth/WindowsAuthenticationCredentials.h"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincred.h>
#endif

using namespace opendnp3;
using namespace ser4cpp;

namespace opendnp3
{
class RemoteUpdateKeyTestAccess
{
public:
    static AuthenticationSession& Sessions(MContext& c) { return *c.authentication->sessions; }
    static AuthenticationSession& Sessions(OContext& c) { return *c.authentication->sessions; }
    static uint32_t Events(OContext& c) { return c.eventBuffer.NumEvents(EventClass::EC1); }
};
}
namespace
{
using namespace remote_update_test;
MasterParams RemoteMasterSettings(AuthenticationConfig config, uint32_t replyTimeoutMs = 2000)
{
    auto p = NoStartupTasks();
    config.updateKeyTrust.reset(); // The Master never receives BC.
    config.replyTimeoutMs = replyTimeoutMs;
    p.authentication = config;
    p.ignoreRestartIIN = true;
    return p;
}
OutstationConfig RemoteOutSettings(const AuthenticationConfig& config, uint32_t replyTimeoutMs = 2000)
{
    OutstationConfig c;
    c.params.authentication = config;
    c.params.authentication.replyTimeoutMs = replyTimeoutMs;
    c.params.allowUnsolicited = false;
    c.eventBufferConfig.maxSecurityStatEvents = 32;
    return c;
}
struct RemotePair
{
    std::shared_ptr<RemoteCredentials> masterCredentials = std::make_shared<RemoteCredentials>();
    std::shared_ptr<RemoteCredentials> outCredentials = std::make_shared<RemoteCredentials>();
    std::shared_ptr<RemotePolicy> policy = std::make_shared<RemotePolicy>();
    std::shared_ptr<RemoteAuthority> authority = std::make_shared<RemoteAuthority>();
    MasterTestFixture master;
    OutstationTestObject out;
    std::vector<std::string> masterWire, outWire;
    uint8_t dropOutVariation = 0;
    bool dropStatus = false, dropAll = false;
    int finalFault = -1, replyFault = -1;
    std::string originalFinal;
    static std::shared_ptr<RemoteCredentials> Credentials(bool common)
    {
        auto value = std::make_shared<RemoteCredentials>();
        if (!common) value->users[0] = UpdateKeyUser();
        return value;
    }
    RemotePair(size_t capacity = 2, bool common = true,
               std::shared_ptr<RemoteAuthority> authority_ = std::make_shared<RemoteAuthority>(),
               uint32_t masterTimeoutMs = 2000, uint32_t outstationTimeoutMs = 2000)
        : masterCredentials(Credentials(common)), outCredentials(Credentials(common)),
          authority(std::move(authority_)),
          master(RemoteMasterSettings(RemoteSettings(masterCredentials, policy, authority, capacity), masterTimeoutMs), Addresses()),
          out(RemoteOutSettings(RemoteSettings(outCredentials, policy, authority, capacity), outstationTimeoutMs))
    {
        out.application->currentTime = DNPTime(1700000000000ULL);
        out.LowerLayerUp();
        REQUIRE(master.context->OnLowerLayerUp());
        master.exe->run_many();
        Pump();
        if (masterTimeoutMs && outstationTimeoutMs)
        {
            REQUIRE(Master().Find(1)->Ready(0) == common);
            REQUIRE(Master().Find(2)->Ready(0));
        }
        else
        {
            REQUIRE_FALSE(Master().Find(1)->Ready(0));
            REQUIRE_FALSE(Master().Find(2)->Ready(0));
        }
    }
    AuthenticationSession& Master() { return RemoteUpdateKeyTestAccess::Sessions(*master.context); }
    AuthenticationSession& Out() { return RemoteUpdateKeyTestAccess::Sessions(out.context); }
    void Pump()
    {
        size_t steps = 0;
        while (master.lower->NumWrites() || out.lower->NumWrites())
        {
            REQUIRE(++steps < 100);
            if (master.lower->NumWrites())
            {
                auto hex = master.lower->PopWriteAsHex();
                masterWire.push_back(hex);
                REQUIRE(master.context->OnTxReady());
                HexSequence packet(hex);
                if (finalFault >= 0 && packet.ToRSeq().length() > 14 && packet.ToRSeq()[2] == 120 && packet.ToRSeq()[3] == 13)
                {
                    originalFinal = hex;
                    std::vector<uint8_t> bytes(static_cast<const uint8_t*>(packet.ToRSeq()),
                        static_cast<const uint8_t*>(packet.ToRSeq()) + packet.ToRSeq().length());
                    switch (finalFault)
                    {
                    case 0: bytes.pop_back(); break;
                    case 1: bytes[4] = 7; break;
                    case 2: bytes[5] = 2; break;
                    case 3: bytes.push_back(0); break;
                    case 4: bytes[12] ^= 3; break;
                    case 5: bytes[8] ^= 1; break;
                    case 6: bytes[0] ^= 1; break;
                    case 7: bytes.back() ^= 1; break;
                    case 8: bytes[16] ^= 1; break; // G13's encrypted-data UINT16 length precedes the ciphertext.
                    }
                    finalFault = -1;
                    hex = HexConversions::to_hex({bytes.data(), bytes.size()});
                }
                out.SendToOutstation(hex);
            }
            if (out.lower->NumWrites())
            {
                const auto hex = out.lower->PopWriteAsHex();
                outWire.push_back(hex);
                out.OnTxReady();
                HexSequence bytes(hex);
                const auto view = bytes.ToRSeq();
                if (replyFault >= 0 && view.length() > 15 && view[4] == 120 && view[5] == 12)
                {
                    std::vector<uint8_t> forged(static_cast<const uint8_t*>(view), static_cast<const uint8_t*>(view) + view.length());
                    switch (replyFault)
                    {
                    case 0: forged[14] ^= 3; break;
                    case 1: forged[0] ^= 1; break;
                    case 2: forged[0] |= 0x20; break;
                    case 3: forged[0] |= 0x10; break;
                    case 4: forged[1] = 0x81; break;
                    case 5: forged.pop_back(); break;
                    }
                    replyFault = -1;
                    REQUIRE(master.SendToMaster(HexConversions::to_hex({forged.data(), forged.size()})));
                    master.exe->run_many();
                }
                if (dropAll) continue;
                if (dropStatus && view.length() == 4 && view[1] == 0x81) { dropStatus = false; continue; }
                if (dropOutVariation && view.length() > 5 && view[4] == 120 && view[5] == dropOutVariation)
                { dropOutVariation = 0; continue; }
                REQUIRE(master.SendToMaster(hex));
                master.exe->run_many();
            }
        }
    }
    std::shared_ptr<MockTaskCallback> Start(UpdateKeyRequest request)
    {
        if (!request.verifyOnly && request.operation != 2) request.source = authority;
        auto result = std::make_shared<MockTaskCallback>();
        REQUIRE(master.context->ChangeUpdateKey(request, TaskConfig::With(result)));
        master.exe->run_many();
        return result;
    }
};
}

TEST_CASE("RemoteUpdateKeys - Table A-10 certification excludes envelope and certification fields", "[remote-update-keys]")
{
    HexSequence name("41 6C 69 63 65");
    std::array<uint8_t, 256> bytes{};
    size_t size = 0;
    Group120Var10 value(4, 1, 0x04030201, 1, 2, name.ToRSeq(), rseq_t(), rseq_t());
    REQUIRE(updatekeys::CertificationData(value, wseq_t(bytes.data(), bytes.size()), size));
    REQUIRE(HexConversions::to_hex(rseq_t(bytes.data(), size)) == "01 01 02 03 04 01 00 02 00 05 00 41 6C 69 63 65");
    for (const auto role : {uint16_t(7), uint16_t(32767)})
    {
        value.userRole = role;
        REQUIRE_FALSE(updatekeys::CertificationData(value, wseq_t(bytes.data(), bytes.size()), size));
        REQUIRE(size == 0);
        for (auto b : bytes) REQUIRE(b == 0);
    }
    value.userRole = 1;
    value.keyChangeMethod = 3;
    REQUIRE_FALSE(updatekeys::CertificationData(value, wseq_t(bytes.data(), bytes.size()), size));
}

TEST_CASE("RemoteUpdateKeys - Method 68 provider enforces exact algorithms and authenticated outputs", "[remote-update-keys][remote-update-crypto]")
{
    const auto m = Method68Material();
    const rseq_t dsa(m->userPublic.data(), m->userPublicSize), rsa(m->outstationPublic.data(), m->outstationPublicSize);
    REQUIRE(crypto::ValidateMethod68PublicKey(dsa, false));
    REQUIRE_FALSE(crypto::ValidateMethod68PublicKey(dsa, true));
    REQUIRE(crypto::ValidateMethod68PublicKey(rsa, true));
    REQUIRE_FALSE(crypto::ValidateMethod68PublicKey(rsa, false));
    std::array<uint8_t, 190> message{}, recovered{};
    std::array<uint8_t, 256> encrypted{};
    std::array<uint8_t, 73> signature{};
    size_t size = 0;
    REQUIRE(crypto::RSAOAEP2048Encrypt(rsa, R(message), W(encrypted)) == crypto::Result::OK);
    REQUIRE(crypto::RSAOAEP2048Decrypt({m->outstationPrivate.data(), m->outstationPrivateSize}, R(encrypted), W(recovered), size) == crypto::Result::OK);
    REQUIRE(size == message.size()); REQUIRE(recovered == message);
    encrypted[0] ^= 1;
    recovered.fill(0xAA);
    REQUIRE(crypto::RSAOAEP2048Decrypt({m->outstationPrivate.data(), m->outstationPrivateSize}, R(encrypted), W(recovered), size) != crypto::Result::OK);
    REQUIRE(size == 0);
    REQUIRE(std::all_of(recovered.begin(), recovered.end(), [](uint8_t b) { return b == 0; }));
    REQUIRE(crypto::DSASHA256Sign({m->userPrivate.data(), m->userPrivateSize}, R(message), W(signature), size) == crypto::Result::OK);
    REQUIRE(size <= 72);
    REQUIRE(crypto::DSASHA256Verify(dsa, R(message), {signature.data(), size}) == crypto::Result::OK);
    REQUIRE(crypto::DSASHA256Verify({m->authorityPublic.data(), m->authorityPublicSize}, R(message), {signature.data(), size}) != crypto::Result::OK);
    signature[size] = 0;
    REQUIRE(crypto::DSASHA256Verify(dsa, R(message), {signature.data(), size + 1}) != crypto::Result::OK);
    signature[size - 1] ^= 1;
    REQUIRE(crypto::DSASHA256Verify(dsa, R(message), {signature.data(), size}) != crypto::Result::OK);
}

TEST_CASE("RemoteUpdateKeys - Method 68 provider absence cannot publish partial secret outputs", "[remote-update-keys][remote-update-crypto]")
{
    auto material = Method68Material();
    struct Unavailable
    {
        std::unique_ptr<OSSL_LIB_CTX, decltype(&OSSL_LIB_CTX_free)> context{OSSL_LIB_CTX_new(), OSSL_LIB_CTX_free};
        std::unique_ptr<OSSL_PROVIDER, decltype(&OSSL_PROVIDER_unload)> provider{
            context ? OSSL_PROVIDER_load(context.get(), "null") : nullptr, OSSL_PROVIDER_unload};
        OSSL_LIB_CTX* previous = nullptr;
        Unavailable()
        {
            REQUIRE(context); REQUIRE(provider);
            previous = OSSL_LIB_CTX_set0_default(context.get()); REQUIRE(previous);
        }
        ~Unavailable()
        {
            OSSL_LIB_CTX_set0_default(previous); OPENSSL_thread_stop_ex(context.get()); ERR_clear_error();
        }
    } unavailable;
    std::array<uint8_t, 256> encrypted{};
    std::array<uint8_t, 200> plain{};
    std::array<uint8_t, 72> signature{};
    size_t size = 0;
    encrypted.fill(0xCC); plain.fill(0xAA); signature.fill(0xBB);
    REQUIRE(crypto::RSAOAEP2048Encrypt({material->outstationPublic.data(), material->outstationPublicSize},
        {plain.data(), 32}, W(encrypted)) != crypto::Result::OK);
    REQUIRE(std::all_of(encrypted.begin(), encrypted.end(), [](uint8_t b) { return b == 0; }));
    REQUIRE(crypto::RSAOAEP2048Decrypt({material->outstationPrivate.data(), material->outstationPrivateSize},
        R(encrypted), W(plain), size) != crypto::Result::OK);
    REQUIRE(size == 0); REQUIRE(std::all_of(plain.begin(), plain.end(), [](uint8_t b) { return b == 0; }));
    REQUIRE(crypto::DSASHA256Sign({material->userPrivate.data(), material->userPrivateSize}, R(plain), W(signature), size) != crypto::Result::OK);
    REQUIRE(size == 0); REQUIRE(std::all_of(signature.begin(), signature.end(), [](uint8_t b) { return b == 0; }));
    REQUIRE_FALSE(crypto::ValidateMethod68PublicKey({material->userPublic.data(), material->userPublicSize}, false));
}

TEST_CASE("RemoteUpdateKeys - Method 68 DSA verifies independent RFC6979 Appendix A.2.2 vector", "[remote-update-keys][remote-update-crypto]")
{
    // Published DSA2048/N256/SHA256 vector, message="sample". Only verification
    // is deterministic; production signing uses the provider's secure nonce.
    const char* values[] = {
        "9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48"
        "C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F"
        "FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5"
        "B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2"
        "35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41"
        "F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE"
        "92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15"
        "3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B",
        "F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F",
        "5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613"
        "D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4"
        "6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472"
        "085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5"
        "AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA"
        "3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71"
        "BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0"
        "DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7",
        "667098C654426C78D7F8201EAC6C203EF030D43605032C2F1FA937E5237DBD94"
        "9F34A0A2564FE126DC8B715C5141802CE0979C8246463C40E6B6BDAA2513FA61"
        "1728716C2E4FD53BC95B89E69949D96512E873B9C8F8DFD499CC312882561ADE"
        "CB31F658E934C0C197F2C4D96B05CBAD67381E7B768891E4DA3843D24D94CDFB"
        "5126E9B8BF21E8358EE0E0A30EF13FD6A664C0DCE3731F7FB49A4845A4FD8254"
        "687972A2D382599C9BAC4E0ED7998193078913032558134976410B89D2C171D1"
        "23AC35FD977219597AA7D15C1A9A428E59194F75C721EBCBCFAE44696A499AFA"
        "74E04299F132026601638CB87AB79190D4A0986315DA8EEC6561C938996BEADF"};
    const char* names[] = {OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_Q, OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_PUB_KEY};
    std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> builder(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
    REQUIRE(builder);
    std::vector<std::unique_ptr<BIGNUM, decltype(&BN_free)>> numbers;
    for (size_t n = 0; n < 4; ++n)
    {
        BIGNUM* raw = nullptr;
        REQUIRE(BN_hex2bn(&raw, values[n]) > 0);
        numbers.emplace_back(raw, BN_free);
        REQUIRE(OSSL_PARAM_BLD_push_BN(builder.get(), names[n], raw) > 0);
    }
    std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(OSSL_PARAM_BLD_to_param(builder.get()), OSSL_PARAM_free);
    AsymmetricMaterial::Context context(EVP_PKEY_CTX_new_from_name(nullptr, "DSA", nullptr), EVP_PKEY_CTX_free);
    REQUIRE(params); REQUIRE(context); REQUIRE(EVP_PKEY_fromdata_init(context.get()) > 0);
    EVP_PKEY* raw = nullptr;
    REQUIRE(EVP_PKEY_fromdata(context.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) > 0);
    AsymmetricMaterial::Key key(raw, EVP_PKEY_free);
    std::array<uint8_t, 1024> publicKey{};
    auto* dest = publicKey.data();
    const int length = i2d_PUBKEY(key.get(), &dest);
    REQUIRE(length > 0); REQUIRE(length <= publicKey.size());
    HexSequence signature("30 45 02 21 00 EA CE 8B DB BE 35 3C 43 2A 79 5D 9E C5 56 C6 D0 21 F7 A0 3F 42 C3 6E 9B C8 7E 4A C7 93 2C C8 09 02 20 70 81 E1 75 45 5F 92 47 B8 12 B7 45 83 E9 E9 4F 9E A7 9B D6 40 DC 96 25 33 B0 68 07 93 A3 8D 53");
    const uint8_t message[] = {'s','a','m','p','l','e'};
    REQUIRE(crypto::DSASHA256Verify({publicKey.data(), static_cast<size_t>(length)}, {message, sizeof(message)}, signature.ToRSeq()) == crypto::Result::OK);
}

TEST_CASE("RemoteUpdateKeys - Method 68 native mutual proof installs the key and preserves independent users", "[remote-update-keys][remote-update-runtime]")
{
    auto authority = std::make_shared<AsymmetricAuthority>();
    RemotePair pair(2, true, authority);
    const auto independent = pair.Master().Find(1)->Sequence();
    const auto lost = GENERATE(uint8_t(0), uint8_t(12), uint8_t(15));
    pair.dropOutVariation = lost;
    auto completed = pair.Start(authority->Status(3, 1, "A"));
    pair.Pump();
    if (lost)
    {
        pair.master.exe->advance_time(std::chrono::milliseconds(2000));
        pair.master.exe->run_many();
        pair.Pump();
    }
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    REQUIRE(pair.masterCredentials->users[1].updateKey == authority->nextKey);
    REQUIRE(pair.outCredentials->users[1].updateKey == authority->nextKey);
    REQUIRE(pair.Master().Find(1)->Sequence() == independent);
    const uint64_t now = lost ? 2000 : 0;
    REQUIRE(pair.Master().Find(1)->Ready(now));
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    pair.master.exe->advance_time(std::chrono::milliseconds(100));
    pair.master.exe->run_many(); pair.Pump();
    REQUIRE(pair.Master().Find(2)->ControlKey(now + 100).equals(pair.Out().Find(2)->ControlKey(0)));
    UpdateKeyRequest verify;
    verify.name[0] = 'A'; verify.nameSize = 1; verify.method = 68; verify.verifyOnly = true;
    auto verified = pair.Start(verify); pair.Pump();
    REQUIRE(verified->results.size() == 1);
    REQUIRE(verified->results.front() == TaskCompletion::SUCCESS);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
}

TEST_CASE("RemoteUpdateKeys - Method 68 remains disabled without explicit configuration", "[remote-update-keys][remote-update-runtime]")
{
    RemotePair pair;
    auto authority = std::make_shared<AsymmetricAuthority>();
    auto request = authority->Status(3, 1, "A");
    const auto before = pair.masterWire.size();
    auto completed = pair.Start(request); pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() != TaskCompletion::SUCCESS);
    REQUIRE(pair.masterWire.size() == before);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 0);
    std::array<uint8_t, 2048> bytes{};
    APDURequest apdu(W(bytes)); apdu.ConfigureHeader(FunctionCode::AUTH_REQUEST, 9);
    auto writer = apdu.GetWriter();
    Group120Var10 status(68, 3, 1, 1, 5, {request.name.data(), request.nameSize},
        {request.publicKey.data(), request.publicKeySize}, {request.certification.data(), request.certificationSize});
    REQUIRE(writer.WriteFreeFormat(&status, 1));
    pair.out.SendToOutstation(HexConversions::to_hex(apdu.ToRSeq()));
    REQUIRE(pair.out.lower->NumWrites() == 1);
    HexSequence response(pair.out.lower->PopWriteAsHex()); pair.out.OnTxReady();
    const auto parsed = APDUHeaderParser::ParseResponse(response.ToRSeq());
    REQUIRE(parsed.success); REQUIRE(parsed.header.function == FunctionCode::AUTH_RESPONSE);
    Group120Var7 error;
    REQUIRE(error.Read(parsed.objects.skip(6))); REQUIRE(error.errorCode == 8);
    REQUIRE(pair.outCredentials->users[1].method == 4); REQUIRE_FALSE(pair.outCredentials->users[1].pending);
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - Method 68 rejects tampered proof and unrelated authority or user keys", "[remote-update-keys][remote-update-runtime]")
{
    const int fault = GENERATE(0, 1, 2, 3);
    CAPTURE(fault);
    auto authority = std::make_shared<AsymmetricAuthority>();
    RemotePair pair(2, true, authority);
    const auto old = pair.outCredentials->users[1].updateKey;
    auto request = authority->Status(3, 1, "A", 0);
    if (fault == 0) authority->wrongAuthority = true;
    if (fault == 1) authority->wrongUser = true;
    if (fault == 2) pair.finalFault = 7;
    if (fault == 3) pair.finalFault = 8;
    auto completed = pair.Start(request); pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() != TaskCompletion::SUCCESS);
    REQUIRE(pair.outCredentials->users[1].updateKey == old);
    REQUIRE(pair.outCredentials->users[1].role == 1);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - FIPS186-2 challenge expansion matches RFC4186 Appendix A", "[remote-update-keys]")
{
    // RFC4186 Appendix A, MK -> K_encr || K_aut. Independent published vector
    // for the same FIPS186-2 general-purpose G/seed-update construction.
    HexSequence seed("E5 76 D5 CA 33 2E 99 30 01 8B F1 BA EE 27 63 C7 95 B3 C7 12");
    std::array<uint8_t, 32> output{};
    REQUIRE(crypto::ExpandUpdateKeyChallenge(seed.ToRSeq(), W(output)) == crypto::Result::OK);
    REQUIRE(HexConversions::to_hex(R(output)) == "53 6E 5E BC 44 65 58 2A A6 A8 EC 99 86 EB B6 20 25 AF 19 42 EF CB F4 BC 72 B3 94 34 21 F2 A9 74");
    REQUIRE(crypto::ExpandUpdateKeyChallenge(seed.ToRSeq().take(19), W(output)) != crypto::Result::OK);
    REQUIRE(std::all_of(output.begin(), output.end(), [](uint8_t b) { return b == 0; }));
    std::array<uint8_t, 32> second{};
    REQUIRE(crypto::GenerateUpdateKeyChallenge(W(output)) == crypto::Result::OK);
    REQUIRE(crypto::GenerateUpdateKeyChallenge(W(second)) == crypto::Result::OK);
    REQUIRE_FALSE(R(output).equals(R(second)));
}

#ifdef _WIN32
TEST_CASE("RemoteUpdateKeys - Windows credential journal recovers committed state and rejects torn storage", "[remote-update-keys][remote-update-windows]")
{
    std::array<uint8_t, 8> random{};
    REQUIRE(crypto::GenerateRandom(W(random)) == crypto::Result::OK);
    const auto suffix = HexConversions::to_hex(R(random));
    const auto prefix = L"DNP3-EXTRA/UnitTests/" + std::to_wstring(GetCurrentProcessId())
        + L"/" + std::wstring(suffix.begin(), suffix.end());
    const auto target = prefix + L"/7/2";
    struct Cleanup
    {
        std::wstring target;
        ~Cleanup()
        {
            CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0);
            CredDeleteW((target + L"/remote0").c_str(), CRED_TYPE_GENERIC, 0);
            CredDeleteW((target + L"/remote1").c_str(), CRED_TYPE_GENERIC, 0);
        }
    } cleanup{target};
    uint64_t now = 1700000000000ULL;
    WindowsAuthenticationCredentials storage(prefix, [&](uint64_t& t) { t = now; return true; });
    UpdateKeyUser loaded;
    REQUIRE(storage.ReadUser(7, 1, loaded));
    REQUIRE(loaded.nameSize == 0);
    RemoteCredentials fixture;
    auto user = fixture.users[1];
    REQUIRE(storage.WriteUser(7, 1, user));
    REQUIRE(storage.ReadUser(7, 1, loaded));
    REQUIRE(loaded.updateKey == user.updateKey);
    REQUIRE(loaded.name == user.name);
    REQUIRE(loaded.role == user.role);
    // Save the first commit marker. Simulate loss of power after writing a new
    // inactive snapshot but before changing the marker: old verified key wins.
    PCREDENTIALW first = nullptr;
    REQUIRE(CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &first));
    std::vector<uint8_t> marker(first->CredentialBlob, first->CredentialBlob + first->CredentialBlobSize);
    SecureZeroMemory(first->CredentialBlob, first->CredentialBlobSize);
    CredFree(first);
    user.pending = user.havePendingKey = true;
    user.pendingRole = 0;
    user.pendingUpdateKey.fill(0x77);
    user.pendingExpiresUnixMs = user.expiresUnixMs;
    REQUIRE(storage.WriteUser(7, 1, user));
    REQUIRE(storage.ReadUser(7, 1, loaded));
    REQUIRE(loaded.havePendingKey);
    REQUIRE(loaded.pendingUpdateKey == user.pendingUpdateKey);
    CREDENTIALW previous{};
    previous.Type = CRED_TYPE_GENERIC;
    previous.TargetName = const_cast<wchar_t*>(target.c_str());
    previous.Persist = CRED_PERSIST_LOCAL_MACHINE;
    previous.CredentialBlob = marker.data();
    previous.CredentialBlobSize = static_cast<DWORD>(marker.size());
    REQUIRE(CredWriteW(&previous, 0));
    REQUIRE(storage.ReadUser(7, 1, loaded));
    REQUIRE_FALSE(loaded.havePendingKey);
    REQUIRE(loaded.updateKey == fixture.users[1].updateKey);
    uint64_t remaining = 0;
    std::array<uint8_t, 32> key{};
    REQUIRE(storage.ReadUpdateKey(7, 2, key.data(), key.size(), remaining));
    REQUIRE(key == fixture.users[1].updateKey);
    REQUIRE(remaining == user.expiresUnixMs - now);
    // Migrate a checkpoint-v1 record. The first 51 header bytes and fixed
    // fields are unchanged; v2 expands Certification and appends Method/SPKI.
    const auto activeTarget = target + L"/remote" + std::to_wstring(marker[8]);
    PCREDENTIALW snapshot = nullptr;
    REQUIRE(CredReadW(activeTarget.c_str(), CRED_TYPE_GENERIC, 0, &snapshot));
    REQUIRE(snapshot->CredentialBlobSize == 1374);
    std::vector<uint8_t> legacy(snapshot->CredentialBlob, snapshot->CredentialBlob + 67);
    legacy.insert(legacy.end(), snapshot->CredentialBlob + 123, snapshot->CredentialBlob + 347);
    SecureZeroMemory(snapshot->CredentialBlob, snapshot->CredentialBlobSize); CredFree(snapshot);
    REQUIRE(legacy.size() == 291);
    legacy[7] = '1';
    CREDENTIALW oldRecord{};
    oldRecord.Type = CRED_TYPE_GENERIC; oldRecord.Persist = CRED_PERSIST_LOCAL_MACHINE;
    oldRecord.TargetName = const_cast<wchar_t*>(activeTarget.c_str());
    oldRecord.CredentialBlob = legacy.data(); oldRecord.CredentialBlobSize = static_cast<DWORD>(legacy.size());
    REQUIRE(CredWriteW(&oldRecord, 0));
    std::array<uint8_t, 32> digest{};
    REQUIRE(crypto::SHA256({legacy.data(), legacy.size()}, W(digest)) == crypto::Result::OK);
    std::copy(digest.begin(), digest.end(), marker.begin() + 17);
    REQUIRE(CredWriteW(&previous, 0));
    REQUIRE(storage.ReadUser(7, 1, loaded));
    REQUIRE(loaded.method == 4); REQUIRE(loaded.publicKeySize == 0);
    REQUIRE(loaded.updateKey == fixture.users[1].updateKey);
    REQUIRE(storage.WriteUser(7, 1, loaded)); // Next verified commit upgrades the record.
    REQUIRE(storage.ReadUser(7, 1, loaded));
    // Restore the v1 commit marker before testing its missing referenced record.
    REQUIRE(CredWriteW(&previous, 0));
    crypto::Clear({legacy.data(), legacy.size()});
    // A valid marker pointing to a missing/corrupt record fails closed; never
    // fall back to the other snapshot, even if it contains a well-formed key.
    REQUIRE(marker.size() == 49);
    REQUIRE(CredDeleteW(activeTarget.c_str(), CRED_TYPE_GENERIC, 0));
    REQUIRE_FALSE(storage.ReadUser(7, 1, loaded));
    REQUIRE_FALSE(loaded.active);
    REQUIRE_FALSE(storage.ReadUpdateKey(7, 2, key.data(), key.size(), remaining));
    REQUIRE(std::all_of(key.begin(), key.end(), [](uint8_t b) { return b == 0; }));
    marker[0] ^= 1;
    REQUIRE(CredWriteW(&previous, 0));
    REQUIRE_FALSE(storage.ReadUser(7, 1, loaded));
    REQUIRE_FALSE(storage.WriteUser(7, 1, user)); // Administrative repair required.
    REQUIRE(storage.ReadUser(8, 1, loaded));
    REQUIRE(loaded.nameSize == 0);
    REQUIRE_FALSE(storage.WriteUser(7, 2, user)); // Association-local user-number binding.
}
#endif

TEST_CASE("RemoteUpdateKeys - native Method 4 changes one user's key and applies the certified role", "[remote-update-keys][remote-update-runtime]")
{
    RemotePair pair;
    const auto commonSequence = pair.Master().Find(1)->Sequence();
    auto request = pair.authority->Status(3, 1, "A", 0);
    auto completed = pair.Start(request);
    pair.Pump();
    CAPTURE(pair.masterWire, pair.outWire);
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    REQUIRE(pair.masterCredentials->users[1].updateKey == pair.authority->nextKey);
    REQUIRE(pair.outCredentials->users[1].updateKey == pair.authority->nextKey);
    REQUIRE(pair.outCredentials->users[1].role == 0);
    REQUIRE_FALSE(pair.outCredentials->users[1].pending);
    REQUIRE(pair.Master().Find(1)->Ready(0));
    REQUIRE(pair.Master().Find(1)->Sequence() == commonSequence);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    pair.master.exe->advance_time(std::chrono::milliseconds(100));
    pair.master.exe->run_many();
    pair.Pump();
    REQUIRE(pair.Master().Find(2)->Ready(100));
    REQUIRE(pair.Out().Find(2)->Ready(0));
    REQUIRE(pair.Master().Find(2)->ControlKey(100).equals(pair.Out().Find(2)->ControlKey(0)));
    REQUIRE_FALSE(pair.Out().Authorize(2, 5, 0)); // Authority changed OPERATOR to VIEWER.
    REQUIRE(pair.Out().Authorize(2, 1, 0));
}

TEST_CASE("RemoteUpdateKeys - V15-only native verification retains keys and does not count a change", "[remote-update-keys][remote-update-runtime]")
{
    RemotePair pair;
    UpdateKeyRequest request;
    request.name[0] = 'A';
    request.nameSize = 1;
    request.verifyOnly = true;
    auto completed = pair.Start(request);
    pair.Pump();
    CAPTURE(pair.masterWire, pair.outWire);
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    REQUIRE(pair.Master().Find(2)->Ready(0));
    REQUIRE(pair.Out().Find(2)->Ready(0));
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
}

TEST_CASE("RemoteUpdateKeys - invalid authority and tampered ciphertext cannot activate credentials", "[remote-update-keys][remote-update-runtime]")
{
    const bool invalidCertificate = GENERATE(false, true);
    RemotePair pair;
    const auto old = pair.outCredentials->users[1].updateKey;
    auto request = pair.authority->Status(3, 1, "A", 0);
    if (invalidCertificate) request.certification[0] ^= 1;
    else pair.authority->corruptCiphertext = true;
    auto completed = pair.Start(request);
    pair.Pump();
    CAPTURE(pair.masterWire, pair.outWire);
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() != TaskCompletion::SUCCESS);
    REQUIRE(pair.outCredentials->users[1].updateKey == old);
    REQUIRE(pair.outCredentials->users[1].role == 1);
    REQUIRE(pair.masterCredentials->users[1].updateKey == old);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(pair.Master().Find(1)->Ready(0));
    REQUIRE(pair.Out().Find(1)->Ready(0));
}

TEST_CASE("RemoteUpdateKeys - configurable capacity adds and deletes an association-local user", "[remote-update-keys][remote-update-runtime]")
{
    RemotePair pair(3);
    auto request = pair.authority->Status(1, 0, "C");
    auto completed = pair.Start(request);
    pair.Pump();
    CAPTURE(pair.masterWire, pair.outWire);
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    REQUIRE(pair.outCredentials->users[2].user == 3);
    REQUIRE(pair.outCredentials->users[2].active);
    REQUIRE(pair.masterCredentials->users[2].active);
    request = pair.authority->Status(2, 1, "C");
    completed = pair.Start(request);
    pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    REQUIRE_FALSE(pair.outCredentials->users[2].active);
    REQUIRE_FALSE(pair.masterCredentials->users[2].active);
    REQUIRE(pair.outCredentials->users[2].statusSequence == 1);
    REQUIRE(pair.Out().Find(3)->UpdateKey(0).is_empty());
    REQUIRE(pair.Master().Find(3)->UpdateKey(0).is_empty());
    REQUIRE(pair.Out().Find(1)->Ready(0));
    REQUIRE(pair.Out().Find(2)->Ready(0));
}

TEST_CASE("RemoteUpdateKeys - certified DELETE revokes immediately when trusted time is unavailable", "[remote-update-keys][remote-update-runtime]")
{
    const bool asymmetric = GENERATE(false, true);
    const bool common = GENERATE(false, true);
    std::shared_ptr<RemoteAuthority> authority = asymmetric ? std::make_shared<AsymmetricAuthority>() : std::make_shared<RemoteAuthority>();
    RemotePair pair(2, true, authority);
    pair.masterCredentials->trustedTime = pair.outCredentials->trustedTime = false;
    const std::string name = common ? std::string("Common\0", 7) : "A";
    auto completed = pair.Start(authority->Status(2, 1, name)); pair.Pump();
    REQUIRE(completed->results.size() == 1); REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    const size_t slot = common ? 0 : 1;
    REQUIRE_FALSE(pair.outCredentials->users[slot].active); REQUIRE_FALSE(pair.masterCredentials->users[slot].active);
    REQUIRE(pair.Out().Find(static_cast<uint16_t>(slot + 1))->UpdateKey(0).is_empty());
    REQUIRE(pair.Master().Find(static_cast<uint16_t>(slot + 1))->UpdateKey(0).is_empty());
    REQUIRE_FALSE(pair.Out().Find(static_cast<uint16_t>(2 - slot))->UpdateKey(0).is_empty());
    REQUIRE_FALSE(pair.Out().Authorize(static_cast<uint16_t>(slot + 1), 5, 0));
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - certified standard roles gate native operations before application policy", "[remote-update-keys][remote-update-runtime]")
{
    const uint16_t role = GENERATE(uint16_t(0), uint16_t(1), uint16_t(2), uint16_t(3), uint16_t(4),
        uint16_t(5), uint16_t(6), uint16_t(32768), uint16_t(65000));
    CAPTURE(role);
    RemotePair pair;
    auto completed = pair.Start(pair.authority->Status(3, 1, "A", role)); pair.Pump();
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    pair.master.exe->advance_time(std::chrono::milliseconds(100)); pair.master.exe->run_many(); pair.Pump();
    REQUIRE(pair.Out().Find(2)->Ready(0));
    REQUIRE(pair.Out().Authorize(2, 1, 0) == (role != 4));
    REQUIRE(pair.Out().Authorize(2, 5, 0) == (role == 1 || role >= 32768));
    REQUIRE(pair.Out().Authorize(2, 2, 0) == (role == 2 || role == 3 || role == 6 || role >= 32768));
    if (role < 32768)
    {
        REQUIRE_FALSE(pair.Out().Authorize(2, 25, 0)); // No native file-mode authorization API.
        REQUIRE_FALSE(pair.Out().Authorize(2, 29, 0));
    }
    pair.policy->allow = false;
    REQUIRE_FALSE(pair.Out().Authorize(2, 1, 0)); REQUIRE_FALSE(pair.Out().Authorize(2, 5, 0));
}

TEST_CASE("RemoteUpdateKeys - independent Common renewal survives while another user's remote exchange owns KSQ", "[remote-update-keys][remote-update-runtime]")
{
    const bool asymmetric = GENERATE(false, true);
    std::shared_ptr<RemoteAuthority> authority = asymmetric ? std::make_shared<AsymmetricAuthority>() : std::make_shared<RemoteAuthority>();
    RemotePair pair(2, true, authority);
    pair.dropOutVariation = 12;
    auto completed = pair.Start(authority->Status(3, 1, "A")); pair.Pump();
    REQUIRE(pair.Out().remote->Busy()); REQUIRE(pair.Out().remote->Owner() == 2);
    const auto sequence = pair.Out().Find(2)->Sequence();
    std::array<uint8_t, 2048> a{}, b{};
    APDURequest wrong(W(a)); wrong.ConfigureHeader(FunctionCode::AUTH_REQUEST, 7);
    auto writer = wrong.GetWriter();
    Group120Var4 statusRequest;
    statusRequest.userNum = 2;
    REQUIRE(writer.WriteSingleValue<ser4cpp::UInt8>(QualifierCode::UINT8_CNT, statusRequest));
    pair.out.SendToOutstation(HexConversions::to_hex(wrong.ToRSeq()));
    REQUIRE(pair.out.lower->HasNoData()); REQUIRE(pair.Out().Find(2)->Sequence() == sequence);
    APDURequest error(W(a)); error.ConfigureHeader(FunctionCode::AUTH_REQUEST_NO_ACK, 7);
    auto errorWriter = error.GetWriter();
    Group120Var7 foreign(sequence, 2, 8, 1, DNPTime(1700000000000ULL), {});
    REQUIRE(errorWriter.WriteFreeFormat(&foreign, 1));
    pair.out.SendToOutstation(HexConversions::to_hex(error.ToRSeq()));
    REQUIRE(pair.Out().remote->Busy()); REQUIRE(pair.Out().remote->Owner() == 2);
    REQUIRE_FALSE(pair.master.context->OnReceive(Message(Addresses(1, 0), error.ToRSeq())));
    auto* common = pair.Master().Find(1);
    size_t size = 0;
    REQUIRE(common->Begin(7, 9, 0, W(a), size) == SessionKeys::Result::OK);
    pair.out.SendToOutstation(HexConversions::to_hex({a.data(), size}));
    REQUIRE(pair.out.lower->NumWrites() == 1);
    HexSequence status(pair.out.lower->PopWriteAsHex()); pair.out.OnTxReady();
    REQUIRE(common->Process(7, status.ToRSeq(), 0, W(b), size) == SessionKeys::Result::OK);
    pair.out.SendToOutstation(HexConversions::to_hex({b.data(), size}));
    REQUIRE(pair.out.lower->NumWrites() == 1);
    HexSequence confirmation(pair.out.lower->PopWriteAsHex()); pair.out.OnTxReady();
    REQUIRE(common->Process(7, confirmation.ToRSeq(), 0, W(a), size) == SessionKeys::Result::INSTALLED);
    const auto commonSequence = common->Sequence();
    REQUIRE(pair.Out().Find(2)->Sequence() == sequence);
    REQUIRE(pair.Out().remote->Busy());
    pair.master.exe->advance_time(std::chrono::milliseconds(2000)); pair.master.exe->run_many(); pair.Pump();
    REQUIRE(completed->results.size() == 1); REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    REQUIRE(pair.Out().Find(1)->Sequence() == commonSequence);
    REQUIRE(pair.Out().Find(1)->ControlKey(0).equals(common->ControlKey(2000)));
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - each lost response retries the owned native exchange exactly once", "[remote-update-keys][remote-update-runtime][sa-zero-runtime]")
{
    const auto response = GENERATE(uint8_t(0), uint8_t(12), uint8_t(15));
    const auto timeout = GENERATE(100u, 2000u, 120000u);
    RemotePair pair(2, true, std::make_shared<RemoteAuthority>(), timeout, timeout);
    pair.dropStatus = response == 0;
    pair.dropOutVariation = response;
    auto completed = pair.Start(pair.authority->Status(3, 1, "A"));
    pair.Pump();
    REQUIRE(completed->results.empty());
    pair.master.exe->advance_time(std::chrono::milliseconds(timeout));
    pair.master.exe->run_many();
    pair.Pump();
    CAPTURE(response, pair.masterWire.back(), pair.outWire.back());
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 0);
    REQUIRE(pair.masterCredentials->users[1].updateKey == pair.outCredentials->users[1].updateKey);
}

TEST_CASE("RemoteUpdateKeys - native retry exhaustion retains the usable key and counts one failure", "[remote-update-keys][remote-update-runtime]")
{
    RemotePair pair;
    const auto old = pair.masterCredentials->users[1].updateKey;
    pair.dropAll = true;
    auto completed = pair.Start(pair.authority->Status(3, 1, "A"));
    pair.Pump();
    for (size_t n = 0; n < 3; ++n)
    {
        pair.master.exe->advance_time(std::chrono::milliseconds(2000));
        pair.master.exe->run_many();
        pair.Pump();
    }
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(pair.masterCredentials->users[1].updateKey == old);
    REQUIRE(pair.outCredentials->users[1].updateKey == old);
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - every transmitted stage disconnects without reusing old authorization", "[remote-update-keys][remote-update-runtime]")
{
    const bool asymmetric = GENERATE(false, true);
    const uint8_t stage = GENERATE(uint8_t(0), uint8_t(1), uint8_t(2));
    CAPTURE(asymmetric, stage);
    std::shared_ptr<RemoteAuthority> authority = asymmetric ? std::make_shared<AsymmetricAuthority>() : std::make_shared<RemoteAuthority>();
    RemotePair pair(2, true, authority);
    const auto old = pair.masterCredentials->users[1].updateKey;
    pair.dropStatus = stage == 0;
    pair.dropOutVariation = stage == 1 ? 12 : (stage == 2 ? 15 : 0);
    auto completed = pair.Start(authority->Status(3, 1, "A")); pair.Pump();
    REQUIRE(completed->results.empty());
    const auto lateRequest = pair.masterWire.back(), lateResponse = pair.outWire.back();
    REQUIRE(pair.master.context->OnLowerLayerDown()); pair.out.LowerLayerDown();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::FAILURE_NO_COMMS);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == (stage == 1 ? 1 : 0));
    REQUIRE_FALSE(pair.Master().remote->Busy()); REQUIRE_FALSE(pair.Out().remote->Busy());
    pair.out.LowerLayerUp(); REQUIRE(pair.master.context->OnLowerLayerUp());
    REQUIRE_FALSE(pair.Master().Find(2)->Ready(0)); REQUIRE_FALSE(pair.Out().Find(2)->Ready(0));
    REQUIRE(pair.master.SendToMaster(lateResponse));
    if (stage == 2)
    {
        pair.out.SendToOutstation(lateRequest); // Old V13/V14 or V13/V15 has no exchange owner.
        REQUIRE(pair.out.lower->HasNoData());
    }
    REQUIRE(pair.masterCredentials->users[1].updateKey == old);
    REQUIRE_FALSE(pair.Master().Find(2)->Ready(0));
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == (stage == 2 ? 1 : 0));
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - expired Outstation exchange rejects otherwise valid late proof", "[remote-update-keys][remote-update-runtime]")
{
    const bool asymmetric = GENERATE(false, true);
    std::shared_ptr<RemoteAuthority> authority = asymmetric ? std::make_shared<AsymmetricAuthority>() : std::make_shared<RemoteAuthority>();
    RemotePair pair(2, true, authority);
    const auto old = pair.outCredentials->users[1].updateKey;
    pair.dropOutVariation = 12;
    auto completed = pair.Start(authority->Status(3, 1, "A", 0)); pair.Pump();
    const auto reply = pair.outWire.back();
    REQUIRE(pair.Out().remote->Busy());
    pair.out.AdvanceTime(TimeDuration::Milliseconds(6000));
    REQUIRE_FALSE(pair.Out().remote->Busy());
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.master.SendToMaster(reply)); pair.master.exe->run_many(); pair.Pump();
    REQUIRE(completed->results.empty());
    REQUIRE(pair.masterCredentials->users[1].havePendingKey);
    REQUIRE(pair.masterCredentials->users[1].updateKey == old);
    REQUIRE(pair.outCredentials->users[1].updateKey == old);
    REQUIRE(pair.outCredentials->users[1].role == 1);
    REQUIRE(pair.Out().Authorize(2, 5, 6000)); // The old verified role/session survives; late proof grants nothing.
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - later-stage retry exhaustion retains pending recovery without duplicate installation", "[remote-update-keys][remote-update-runtime]")
{
    const bool asymmetric = GENERATE(false, true);
    const uint8_t lost = GENERATE(uint8_t(12), uint8_t(15));
    CAPTURE(asymmetric, lost);
    std::shared_ptr<RemoteAuthority> authority = asymmetric ? std::make_shared<AsymmetricAuthority>() : std::make_shared<RemoteAuthority>();
    RemotePair pair(2, true, authority);
    const auto old = pair.masterCredentials->users[1].updateKey;
    pair.dropOutVariation = lost;
    auto completed = pair.Start(authority->Status(3, 1, "A")); pair.Pump(); pair.dropAll = true;
    for (size_t n = 0; n < 3; ++n)
    {
        pair.master.exe->advance_time(std::chrono::milliseconds(2000)); pair.master.exe->run_many(); pair.Pump();
    }
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    REQUIRE(pair.masterCredentials->users[1].updateKey == old);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == (lost == 15 ? 1 : 0));
    REQUIRE(pair.masterCredentials->users[1].havePendingKey == (lost == 15));
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - a certified Common bootstrap needs no preexisting Common key", "[remote-update-keys][remote-update-runtime]")
{
    RemotePair pair(2, false);
    auto request = pair.authority->Status(1, 0, std::string("Common\0", 7), 0);
    auto completed = pair.Start(request);
    pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    REQUIRE(pair.masterCredentials->users[0].updateKey == pair.authority->nextKey);
    REQUIRE(pair.outCredentials->users[0].updateKey == pair.authority->nextKey);
    pair.master.exe->advance_time(std::chrono::milliseconds(100));
    pair.master.exe->run_many();
    pair.Pump();
    REQUIRE(pair.Master().Find(1)->Ready(100));
    REQUIRE(pair.Out().Find(1)->Ready(0));
    REQUIRE(pair.Master().Find(2)->Ready(100));
}

TEST_CASE("RemoteUpdateKeys - malformed and unowned final requests preserve the valid exchange", "[remote-update-keys][remote-update-runtime]")
{
    const auto fault = GENERATE(0, 1, 2, 3, 4, 5, 6);
    RemotePair pair;
    pair.finalFault = fault;
    const auto old = pair.outCredentials->users[1].updateKey;
    auto completed = pair.Start(pair.authority->Status(3, 1, "A", 0));
    pair.Pump();
    CAPTURE(fault);
    REQUIRE(completed->results.empty());
    REQUIRE(pair.outCredentials->users[1].updateKey == old);
    REQUIRE(pair.outCredentials->users[1].role == 1);
    REQUIRE(pair.Out().remote->Busy());
    REQUIRE(pair.Out().Find(1)->Ready(0));
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
    REQUIRE_FALSE(pair.originalFinal.empty());
    pair.out.SendToOutstation(pair.originalFinal);
    pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - unowned or malformed replies cannot replace the scheduled Master owner", "[remote-update-keys][remote-update-runtime]")
{
    const auto fault = GENERATE(0, 1, 2, 3, 4, 5);
    RemotePair pair;
    pair.replyFault = fault;
    auto completed = pair.Start(pair.authority->Status(3, 1, "A"));
    pair.Pump();
    CAPTURE(fault);
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 0);
    REQUIRE(pair.Master().Find(1)->Ready(0));
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - SCS wrap remains rejected across authority-key changes", "[remote-update-keys][remote-update-runtime]")
{
    RemotePair pair;
    const auto historical = pair.authority->Status(3, 0xFFFFFFFFu, "A");
    auto completed = pair.Start(historical);
    pair.Pump();
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    pair.authority->nextKey.fill(0x77);
    auto wrapped = pair.authority->Status(3, 0, "A", 0);
    completed = pair.Start(wrapped);
    pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() != TaskCompletion::SUCCESS);
    REQUIRE(pair.outCredentials->users[1].statusSequence == 0xFFFFFFFFu);
    REQUIRE(pair.outCredentials->users[1].role == 1);
    pair.authority->certificationKey[0] ^= 1; // Explicit trusted authority-key provisioning.
    wrapped = pair.authority->Status(3, 0, "A", 0);
    completed = pair.Start(wrapped);
    pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() != TaskCompletion::SUCCESS);
    REQUIRE(pair.outCredentials->users[1].statusSequence == 0xFFFFFFFFu);
    REQUIRE(pair.outCredentials->users[1].role == 1);
    completed = pair.Start(historical);
    pair.Pump();
    // The existing Error budget may now suppress another Error. Suppression
    // cannot authorize anything; native bounded timeout still completes it.
    for (size_t n = 0; n < 3 && completed->results.empty(); ++n)
    {
        pair.master.exe->advance_time(std::chrono::milliseconds(2000)); pair.master.exe->run_many(); pair.Pump();
    }
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() != TaskCompletion::SUCCESS);
    REQUIRE(pair.outCredentials->users[1].role == 1);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
}

TEST_CASE("RemoteUpdateKeys - SCS and tombstones cannot be reset by changing certification methods", "[remote-update-keys][remote-update-runtime]")
{
    auto authority = std::make_shared<AsymmetricAuthority>();
    RemotePair pair(3, true, authority);
    const auto status68 = authority->Status(3, 5, "A");
    auto completed = pair.Start(status68); pair.Pump();
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    auto old4 = authority->RemoteAuthority::Status(3, 0, "A", 0);
    completed = pair.Start(old4); pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() != TaskCompletion::SUCCESS);
    REQUIRE(pair.outCredentials->users[1].statusSequence == 5);
    authority->nextKey.fill(0x77);
    auto newer4 = authority->RemoteAuthority::Status(3, 6, "A");
    completed = pair.Start(newer4); pair.Pump();
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    completed = pair.Start(status68); pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() != TaskCompletion::SUCCESS);
    REQUIRE(pair.outCredentials->users[1].statusSequence == 6);
    REQUIRE(pair.outCredentials->users[1].method == 4);
    REQUIRE(pair.outCredentials->users[1].updateKey == authority->nextKey);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 2);
}

TEST_CASE("RemoteUpdateKeys - a different certification method cannot evict a deleted identity's replay watermark", "[remote-update-keys][remote-update-runtime]")
{
    auto authority = std::make_shared<AsymmetricAuthority>();
    RemotePair pair(3, true, authority);
    auto completed = pair.Start(authority->Status(1, 0, "C")); pair.Pump();
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    completed = pair.Start(authority->Status(2, 1, "C")); pair.Pump();
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    completed = pair.Start(authority->RemoteAuthority::Status(1, 0, "D")); pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() != TaskCompletion::SUCCESS);
    REQUIRE_FALSE(pair.outCredentials->users[2].active);
    REQUIRE(pair.outCredentials->users[2].statusSequence == 1);
    REQUIRE(pair.outCredentials->users[2].name[0] == 'C');
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - real key-change statistics publish through native G121 G122 and CONFIRM", "[remote-update-keys][remote-update-runtime]")
{
    RemotePair pair;
    auto completed = pair.Start(pair.authority->Status(3, 1, "A"));
    pair.Pump();
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    pair.master.exe->advance_time(std::chrono::milliseconds(100));
    pair.master.exe->run_many();
    pair.Pump();
    pair.master.context->ScanRange(GroupVariationID(121, 1), 15, 16, pair.master.meas, TaskConfig::Default());
    pair.master.exe->run_many();
    pair.Pump();
    bool success = false, failure = false;
    for (const auto& item : pair.master.meas->securityStatSOE)
        if (!item.info.isEventVariation)
        {
            REQUIRE(item.meas.value.associationId == 0); // Reporting association, per 7.5.2.2.
            if (item.meas.index == 15) { REQUIRE(item.meas.value.value == 1); success = true; }
            if (item.meas.index == 16) { REQUIRE(item.meas.value.value == 0); failure = true; }
        }
    REQUIRE(success);
    REQUIRE(failure);
    pair.master.context->ScanAllObjects(GroupVariationID(122, 1), pair.master.meas, TaskConfig::Default());
    pair.master.exe->run_many();
    pair.Pump();
    bool event = false;
    for (const auto& item : pair.master.meas->securityStatSOE)
        if (item.info.isEventVariation && item.meas.index == 15)
        {
            REQUIRE(item.meas.value.associationId == 0);
            REQUIRE(item.meas.value.value == 1);
            event = true;
        }
    REQUIRE(event);
    REQUIRE(RemoteUpdateKeyTestAccess::Events(pair.out.context) == 0);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    pair.master.meas->securityStatSOE.clear();
    pair.authority->corruptCiphertext = true;
    completed = pair.Start(pair.authority->Status(3, 2, "A")); pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() != TaskCompletion::SUCCESS);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 1);
    pair.master.context->ScanRange(GroupVariationID(121, 1), 16, 16, pair.master.meas, TaskConfig::Default());
    pair.master.exe->run_many(); pair.Pump();
    pair.master.context->ScanAllObjects(GroupVariationID(122, 1), pair.master.meas, TaskConfig::Default());
    pair.master.exe->run_many(); pair.Pump();
    bool failedStatic = false, failedEvent = false;
    for (const auto& item : pair.master.meas->securityStatSOE)
        if (item.meas.index == 16)
        {
            REQUIRE(item.meas.value.associationId == 0); REQUIRE(item.meas.value.value == 1);
            if (item.info.isEventVariation) failedEvent = true; else failedStatic = true;
        }
    REQUIRE(failedStatic); REQUIRE(failedEvent);
    REQUIRE(RemoteUpdateKeyTestAccess::Events(pair.out.context) == 0);
}

TEST_CASE("RemoteUpdateKeys - failure to persist an authority decision cannot activate the pending role", "[remote-update-keys][remote-update-runtime]")
{
    RemotePair pair;
    pair.outCredentials->failWrite = true;
    const auto old = pair.outCredentials->users[1].updateKey;
    auto completed = pair.Start(pair.authority->Status(3, 1, "A", 0));
    pair.Pump();
    REQUIRE(completed->results.empty());
    REQUIRE(pair.outCredentials->users[1].role == 1);
    REQUIRE_FALSE(pair.outCredentials->users[1].pending);
    REQUIRE(pair.outCredentials->users[1].updateKey == old);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - authentication Errors require real DNP time", "[remote-update-keys][remote-update-runtime]")
{
    RemotePair pair;
    const auto time = GENERATE(DNPTime(), DNPTime(0x1000000000000ULL));
    pair.out.application->currentTime = time;
    auto request = pair.authority->Status(3, 1, "A");
    request.certification[0] ^= 1;
    const auto before = pair.outWire.size();
    pair.Start(request);
    pair.Pump();
    REQUIRE(pair.outWire.size() == before);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::AUTHENTICATION_FAILURES) == 1);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::ERROR_MESSAGES_SENT) == 0);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE_FALSE(pair.outCredentials->users[1].pending);
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - each critical persistence failure disables uncertain authorization", "[remote-update-keys][remote-update-runtime]")
{
    const auto step = GENERATE(0, 1, 2, 3); // Outstation status, Master candidate, Outstation install, Master install.
    const bool uncertain = GENERATE(false, true);
    RemotePair pair;
    const auto old = pair.masterCredentials->users[1].updateKey;
    auto& failed = step == 0 || step == 2 ? *pair.outCredentials : *pair.masterCredentials;
    failed.failOnWrite = step < 2 ? 1 : 2;
    failed.uncertainWrite = uncertain;
    auto completed = pair.Start(pair.authority->Status(3, 1, "A", 0));
    pair.Pump();
    CAPTURE(step, uncertain);
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
    auto& session = step == 0 || step == 2 ? pair.Out() : pair.Master();
    REQUIRE(session.Find(2)->UpdateKey(0).is_empty());
    REQUIRE_FALSE(session.Authorize(2, 5, 0));
    if (!completed->results.empty()) REQUIRE(completed->results.front() != TaskCompletion::SUCCESS);
    if (step < 2)
    {
        REQUIRE(pair.outCredentials->users[1].role == 1);
        REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    }
    AuthenticationSession restarted(step == 0 || step == 2 ? SessionKeys::Role::OUTSTATION : SessionKeys::Role::MASTER,
        step == 0 || step == 2 ? RemoteSettings(pair.outCredentials, pair.policy, pair.authority, 2)
            : RemoteMasterSettings(RemoteSettings(pair.masterCredentials, pair.policy, pair.authority, 2)).authentication);
    REQUIRE(restarted.Load(0));
    if (step < 2 || !uncertain)
        REQUIRE(restarted.Find(2)->UpdateKey(0).equals(R(old)));
    REQUIRE_FALSE(restarted.Find(2)->Ready(0)); // Session Keys are never durable credentials.
}

TEST_CASE("RemoteUpdateKeys - startup waits for trusted expiry validation and ignores DNP clock changes", "[remote-update-keys][remote-update-runtime]")
{
    auto source = std::make_shared<RemoteCredentials>();
    auto policy = std::make_shared<RemotePolicy>();
    auto authority = std::make_shared<RemoteAuthority>();
    source->trustedTime = false;
    AuthenticationSession session(SessionKeys::Role::OUTSTATION, RemoteSettings(source, policy, authority, 2));
    REQUIRE(session.Load(0));
    REQUIRE_FALSE(session.Find(1)->UpdateKey(0).is_empty());
    REQUIRE(session.Find(2)->UpdateKey(0).is_empty());
    source->trustedTime = true;
    session.remote->Tick(100);
    REQUIRE(session.Find(2)->UpdateKey(100).equals(R(source->users[1].updateKey)));
    REQUIRE_FALSE(session.Find(2)->Ready(100));
    RemotePair pair;
    auto completed = pair.Start(pair.authority->Status(3, 1, "A"));
    pair.Pump();
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    std::string late;
    for (const auto& wire : pair.masterWire)
    {
        HexSequence packet(wire);
        if (packet.ToRSeq().length() >= 4 && packet.ToRSeq()[2] == 120 && packet.ToRSeq()[3] == 13) late = wire;
    }
    REQUIRE_FALSE(late.empty());
    pair.out.application->currentTime = DNPTime(0xFFFFFFFFFFFFULL);
    const uint64_t expiry = uint64_t(5) * 86400000;
    pair.out.AdvanceTime(TimeDuration::Milliseconds(expiry));
    pair.out.application->currentTime = DNPTime(0);
    pair.out.SendToOutstation(late); // Replay of the old V13/V15 after role expiry.
    REQUIRE(pair.Out().Find(2)->UpdateKey(expiry).is_empty());
    REQUIRE_FALSE(pair.Out().Authorize(2, 5, expiry));
    REQUIRE_FALSE(pair.Out().Find(1)->UpdateKey(expiry).is_empty());
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - restart loads only verified active credentials and preserves pending recovery", "[remote-update-keys][remote-update-runtime][sa-zero-runtime]")
{
    const bool asymmetric = GENERATE(false, true);
    std::shared_ptr<RemoteAuthority> authority
        = asymmetric ? std::make_shared<AsymmetricAuthority>() : std::make_shared<RemoteAuthority>();
    RemotePair pair(2, true, authority);
    const auto masterCommonKSQ = pair.Master().Find(1)->Sequence();
    const auto outCommonKSQ = pair.Out().Find(1)->Sequence();
    pair.dropOutVariation = 15;
    auto completed = pair.Start(pair.authority->Status(3, 1, "A", 0));
    pair.Pump();
    REQUIRE(completed->results.empty());
    REQUIRE(pair.masterCredentials->users[1].havePendingKey);
    REQUIRE(pair.masterCredentials->users[1].role == 1);
    REQUIRE(pair.outCredentials->users[1].role == 0);
    REQUIRE(pair.Master().Find(1)->Ready(1));
    REQUIRE(pair.Out().Find(1)->Ready(1));
    REQUIRE(pair.Master().Find(1)->Sequence() == masterCommonKSQ);
    REQUIRE(pair.Out().Find(1)->Sequence() == outCommonKSQ);
    const auto& oldChange = pair.masterWire.back();
    const HexSequence oldPacket(oldChange);
    REQUIRE(oldPacket.ToRSeq().length() >= 4);
    REQUIRE(oldPacket.ToRSeq()[3] == 13);
    REQUIRE(pair.master.context->OnLowerLayerDown());
    auto restartConfig = RemoteMasterSettings(RemoteSettings(pair.masterCredentials, pair.policy, pair.authority, 2)).authentication;
    restartConfig.replyTimeoutMs = 0;
    AuthenticationSession restarted(SessionKeys::Role::MASTER, restartConfig);
    REQUIRE(restarted.Load(0));
    REQUIRE_FALSE(restarted.Find(2)->Ready(0));
    REQUIRE(restarted.Find(2)->UpdateKey(0).equals(R(pair.masterCredentials->users[1].updateKey)));
    REQUIRE_FALSE(restarted.Find(2)->UpdateKey(0).equals(R(pair.masterCredentials->users[1].pendingUpdateKey)));
    pair.out.LowerLayerDown();
    OutstationTestObject restartedOut(RemoteOutSettings(RemoteSettings(pair.outCredentials, pair.policy, authority, 2)));
    restartedOut.application->currentTime = DNPTime(pair.outCredentials->utc);
    restartedOut.LowerLayerUp();
    auto& outSession = RemoteUpdateKeyTestAccess::Sessions(restartedOut.context);
    REQUIRE_FALSE(outSession.Find(2)->Ready(0));
    const auto recoveredKSQ = outSession.Find(2)->Sequence();
    const auto commonKSQ = outSession.Find(1)->Sequence();
    const auto outWrites = pair.outCredentials->writes;
    restartedOut.SendToOutstation(oldChange);
    REQUIRE(restartedOut.lower->NumWrites() == 0);
    REQUIRE(pair.outCredentials->writes == outWrites);
    REQUIRE(outSession.Find(2)->Sequence() == recoveredKSQ);
    REQUIRE(pair.masterCredentials->users[1].havePendingKey);
    UpdateKeyRequest verify;
    verify.name[0] = 'A';
    verify.nameSize = 1;
    verify.method = asymmetric ? 68 : 4;
    verify.verifyOnly = true;
    const auto pendingKey = pair.masterCredentials->users[1].pendingUpdateKey;
    const auto journalWrites = pair.masterCredentials->writes;
    REQUIRE(restarted.remote->Begin(verify, 0));
    std::array<uint8_t, 1024> expiredBuffer{};
    APDURequest expired(W(expiredBuffer));
    REQUIRE_FALSE(restarted.remote->Build(expired, 9, 0));
    REQUIRE(pair.masterCredentials->users[1].havePendingKey);
    REQUIRE(pair.masterCredentials->users[1].pendingUpdateKey == pendingKey);
    REQUIRE(pair.masterCredentials->writes == journalWrites);
    restartConfig.replyTimeoutMs = 2000;
    AuthenticationSession recovery(SessionKeys::Role::MASTER, restartConfig);
    REQUIRE(recovery.Load(0));
    REQUIRE(recovery.remote->Begin(verify, 0));
    // Only a fresh V15 proof activates the durable pending Update Key.
    uint64_t now = 0;
    for (uint8_t sequence = 9; sequence <= 10; ++sequence)
    {
        ++now;
        std::array<uint8_t, 1024> buffer{};
        APDURequest apdu(W(buffer));
        REQUIRE(recovery.remote->Build(apdu, sequence, now));
        const rseq_t wire(buffer.data(), apdu.Size());
        recovery.remote->Transmitted(wire);
        restartedOut.AdvanceTime(TimeDuration::Milliseconds(1));
        restartedOut.SendToOutstation(HexConversions::to_hex(wire));
        REQUIRE(restartedOut.lower->NumWrites() == 1);
        HexSequence response(restartedOut.lower->PopWriteAsHex());
        restartedOut.OnTxReady();
        const auto parsed = APDUHeaderParser::ParseResponse(response.ToRSeq());
        REQUIRE(parsed.success);
        REQUIRE(recovery.remote->Response(parsed.header, parsed.objects, now)
            == (sequence == 9 ? RemoteUpdateKeys::Result::CONTINUE : RemoteUpdateKeys::Result::COMPLETE));
    }
    REQUIRE_FALSE(pair.masterCredentials->users[1].havePendingKey);
    REQUIRE(pair.masterCredentials->users[1].updateKey == pair.outCredentials->users[1].updateKey);
    REQUIRE(recovery.Find(2)->UpdateKey(now).equals(R(pair.outCredentials->users[1].updateKey)));
    REQUIRE_FALSE(recovery.Find(2)->Ready(now));
    REQUIRE_FALSE(outSession.Find(2)->Ready(now));
    REQUIRE(outSession.Find(2)->Sequence() == recoveredKSQ + 1);
    REQUIRE(outSession.Find(1)->Sequence() == commonKSQ);
    REQUIRE(pair.outCredentials->writes == outWrites);
    REQUIRE(recovery.statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    REQUIRE(outSession.statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(restartedOut.cmdHandler->NumInvocations() == 0);
}

TEST_CASE("RemoteUpdateKeys - Table A-13 direction-specific transcript and known MAC", "[remote-update-keys]")
{
    std::array<uint8_t, 32> master{}, outstation{}, key{};
    key.fill(0x11);
    for (size_t n = 0; n < 32; ++n)
    {
        master[n] = static_cast<uint8_t>(n);
        outstation[n] = static_cast<uint8_t>(n + 32);
    }
    const uint8_t userName = 'U', outstationName = 'B';
    std::array<uint8_t, 256> transcript{};
    std::array<uint8_t, 32> mac{};
    size_t size = 0;
    const bool fromMaster = GENERATE(false, true);
    REQUIRE(updatekeys::ConfirmationData(fromMaster, rseq_t(&outstationName, 1), rseq_t(&userName, 1),
        rseq_t(master.data(), master.size()), rseq_t(outstation.data(), outstation.size()),
        0x04030201, 0x0605, wseq_t(transcript.data(), transcript.size()), size));
    REQUIRE(size == 71);
    REQUIRE(crypto::ComputeHMACSHA256(rseq_t(key.data(), key.size()), rseq_t(transcript.data(), size),
        wseq_t(mac.data(), mac.size())) == crypto::Result::OK);
    REQUIRE(HexConversions::to_hex(rseq_t(mac.data(), mac.size())) == (fromMaster
        ? "59 D9 C7 9E FF 31 EB 5A 83 EB A3 FC FD 9F FC F3 1D F2 D1 F9 67 5A 6F 3E 4C 11 AF 1E 95 9C 7D EA"
        : "A7 5E 01 E1 60 FF 9B 95 2A D5 34 7C 9A EC 57 2D 65 B6 26 E4 81 2A 83 07 84 62 48 72 52 E0 00 73"));
    REQUIRE(updatekeys::VerifyMAC(rseq_t(key.data(), key.size()), rseq_t(transcript.data(), size), rseq_t(mac.data(), 16)));
    mac[0] ^= 1;
    REQUIRE_FALSE(updatekeys::VerifyMAC(rseq_t(key.data(), key.size()), rseq_t(transcript.data(), size), rseq_t(mac.data(), 16)));
    REQUIRE_FALSE(updatekeys::VerifyMAC(rseq_t(key.data(), key.size()), rseq_t(transcript.data(), size), rseq_t(mac.data(), 32)));
    transcript[0] ^= 1;
    mac[0] ^= 1;
    REQUIRE_FALSE(updatekeys::VerifyMAC(rseq_t(key.data(), key.size()), rseq_t(transcript.data(), size), rseq_t(mac.data(), 16)));
}

TEST_CASE("RemoteUpdateKeys - Table A-11 identity challenge and padding bind unwrapped key", "[remote-update-keys]")
{
    HexSequence name("43 6F 6D 6D 6F 6E 00");
    REQUIRE(updatekeys::IsCommon(name.ToRSeq()));
    REQUIRE_FALSE(updatekeys::IsCommon(name.ToRSeq().take(6)));
    std::array<uint8_t, 32> key{}, challenge{}, recovered{}, authority{};
    key.fill(0x11);
    challenge.fill(0x22);
    authority.fill(0x33);
    std::array<uint8_t, 128> plain{}, decoded{}, ciphertext{};
    size_t size = 0;
    REQUIRE(updatekeys::KeyData(name.ToRSeq(), rseq_t(key.data(), key.size()), rseq_t(challenge.data(), challenge.size()),
        wseq_t(plain.data(), plain.size()), size));
    REQUIRE(size == 72);
    REQUIRE(crypto::AES256KeyWrap(rseq_t(authority.data(), authority.size()), rseq_t(plain.data(), size),
        wseq_t(ciphertext.data(), size + 8)) == crypto::Result::OK);
    REQUIRE(crypto::AES256KeyUnwrap(rseq_t(authority.data(), authority.size()), rseq_t(ciphertext.data(), size + 8),
        wseq_t(decoded.data(), size)) == crypto::Result::OK);
    REQUIRE(updatekeys::ReadKeyData(rseq_t(decoded.data(), size), name.ToRSeq(), rseq_t(challenge.data(), challenge.size()),
        wseq_t(recovered.data(), recovered.size())));
    REQUIRE(crypto::ConstantTimeEqual(rseq_t(key.data(), key.size()), rseq_t(recovered.data(), recovered.size())));
    for (const auto offset : {size_t(0), size_t(39)})
    {
        decoded[offset] ^= 1;
        REQUIRE_FALSE(updatekeys::ReadKeyData(rseq_t(decoded.data(), size), name.ToRSeq(), rseq_t(challenge.data(), challenge.size()),
            wseq_t(recovered.data(), recovered.size())));
        for (auto b : recovered) REQUIRE(b == 0);
        decoded[offset] ^= 1;
    }
    decoded[71] = 0xA5; // Authority padding has no prescribed byte value (Table A-11).
    REQUIRE(updatekeys::ReadKeyData(rseq_t(decoded.data(), size), name.ToRSeq(), rseq_t(challenge.data(), challenge.size()),
        wseq_t(recovered.data(), recovered.size())));
    REQUIRE_FALSE(updatekeys::ReadKeyData(rseq_t(decoded.data(), size - 1), name.ToRSeq(), rseq_t(challenge.data(), challenge.size()),
        wseq_t(recovered.data(), recovered.size())));
}

TEST_CASE("RemoteUpdateKeys - zero build expires once before transmit and reports task timeout", "[sa-zero-runtime]")
{
    RemotePair pair(2, true, std::make_shared<RemoteAuthority>(), 0, 0);
    const auto key = pair.Master().Find(2)->Sequence();
    UpdateKeyRequest request;
    request.name[0] = 'A'; request.nameSize = 1; request.verifyOnly = true;
    const auto before = pair.Master().statistics.Value(SecurityStatistic::REPLY_TIMEOUTS);
    const auto writes = pair.masterWire.size();
    auto callback = pair.Start(request);
    pair.Pump();
    REQUIRE(callback->results.size() == 1);
    REQUIRE(callback->results.front() == TaskCompletion::FAILURE_RESPONSE_TIMEOUT);
    REQUIRE(pair.masterWire.size() == writes);
    REQUIRE_FALSE(pair.Master().remote->Busy());
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::REPLY_TIMEOUTS) == before + 1);
    REQUIRE(pair.Master().Find(2)->Sequence() == key);
    pair.master.context->OnLowerLayerDown();
    pair.master.exe->advance_time(std::chrono::milliseconds(100));
    pair.master.exe->run_many();
    REQUIRE(callback->results.size() == 1);
    REQUIRE_FALSE(pair.master.context->OnTxReady());
    REQUIRE(callback->results.size() == 1);
}

TEST_CASE("RemoteUpdateKeys - zero Begin Build writes no APDU and rejects same-time or late proof", "[sa-zero-runtime]")
{
    const auto now = GENERATE(uint64_t(0), uint64_t(1));
    RemotePair pair;
    UpdateKeyRequest request;
    request.name[0] = 'A'; request.nameSize = 1; request.verifyOnly = true;
    auto completed = pair.Start(request);
    pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    HexSequence proof(pair.outWire.back());
    const auto parsed = APDUHeaderParser::ParseResponse(proof.ToRSeq());
    REQUIRE(parsed.success);
    const auto key = pair.masterCredentials->users[1].updateKey;
    const auto writes = pair.masterCredentials->writes;
    auto config = RemoteMasterSettings(RemoteSettings(pair.masterCredentials, pair.policy, pair.authority, 2), 0).authentication;
    AuthenticationSession zero(SessionKeys::Role::MASTER, config);
    REQUIRE(zero.Load(0));
    auto& engine = *zero.remote;
    REQUIRE(engine.Begin(request, 0));
    REQUIRE(engine.Deadline() == 0);
    std::array<uint8_t, 2048> bytes{};
    APDURequest apdu(W(bytes));
    const auto size = apdu.Size();
    REQUIRE_FALSE(engine.Build(apdu, 0, 0));
    REQUIRE(engine.LastBuildFailure() == RemoteUpdateKeys::BuildFailure::TIMEOUT);
    REQUIRE(apdu.Size() == size);
    REQUIRE(engine.Response(parsed.header, parsed.objects, now) == RemoteUpdateKeys::Result::IGNORED);
    REQUIRE_FALSE(engine.Busy());
    REQUIRE(pair.masterCredentials->users[1].updateKey == key);
    REQUIRE(pair.masterCredentials->writes == writes);
}

TEST_CASE("RemoteUpdateKeys - zero retry terminates and late responses cannot install", "[sa-zero-runtime]")
{
    RemotePair pair(2, true, std::make_shared<RemoteAuthority>(), 0, 0);
    auto& engine = *pair.Master().remote;
    UpdateKeyRequest request;
    request.name[0] = 'A'; request.nameSize = 1; request.verifyOnly = true;
    REQUIRE(engine.Begin(request, 0));
    std::array<uint8_t, 2048> bytes{};
    APDURequest apdu(W(bytes));
    const auto before = pair.Master().statistics.Value(SecurityStatistic::REPLY_TIMEOUTS);
    const auto size = apdu.Size();
    REQUIRE_FALSE(engine.Build(apdu, 0, 0));
    REQUIRE(apdu.Size() == size);
    // Zero expires before transmission; retries cannot resurrect that stage.
    REQUIRE_FALSE(engine.Retry(2000));
    REQUIRE_FALSE(engine.Retry(2000));
    REQUIRE_FALSE(engine.Busy());
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::REPLY_TIMEOUTS) == before + 1);
    APDUResponseHeader response;
    REQUIRE(engine.Response(response, rseq_t(), 2000) == RemoteUpdateKeys::Result::IGNORED);
    REQUIRE(pair.Master().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
}

TEST_CASE("RemoteUpdateKeys - Outstation zero drops V12 but preserves active credentials", "[sa-zero-runtime]")
{
    RemotePair pair;
    UpdateKeyRequest request;
    request.name[0] = 'A'; request.nameSize = 1; request.verifyOnly = true;
    auto completed = pair.Start(request);
    pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    HexSequence completedProof(pair.masterWire.back());
    std::vector<uint8_t> lateConfirmation(static_cast<const uint8_t*>(completedProof.ToRSeq()),
        static_cast<const uint8_t*>(completedProof.ToRSeq()) + completedProof.ToRSeq().length());
    const uint8_t sequence = (lateConfirmation[0] + 1) & 15;
    lateConfirmation[0] = 0xC0 | sequence; // A new continuation, not a cached completed confirmation.
    auto& engine = *pair.Master().remote;
    REQUIRE(engine.Begin(request, 0));
    std::array<uint8_t, 2048> bytes{};
    APDURequest apdu(W(bytes));
    REQUIRE(engine.Build(apdu, sequence, 0));
    RemotePair zero(2, true, pair.authority, 0, 0);
    const auto credential = zero.outCredentials->users[1].updateKey;
    const auto before = zero.Out().statistics.Value(SecurityStatistic::REPLY_TIMEOUTS);
    zero.out.SendToOutstation(HexConversions::to_hex(apdu.ToRSeq()));
    REQUIRE(zero.out.lower->NumWrites() == 0);
    REQUIRE_FALSE(zero.Out().remote->Busy());
    zero.out.SendToOutstation(HexConversions::to_hex({lateConfirmation.data(), lateConfirmation.size()}));
    REQUIRE(zero.out.lower->NumWrites() == 0);
    REQUIRE_FALSE(zero.Out().Find(1)->Ready(0));
    REQUIRE_FALSE(zero.Out().Find(2)->Ready(0));
    REQUIRE(zero.outCredentials->users[1].updateKey == credential);
    REQUIRE(zero.Out().statistics.Value(SecurityStatistic::REPLY_TIMEOUTS) == before + 1);
    REQUIRE(zero.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    const auto writes = pair.outCredentials->writes;
    pair.out.SendToOutstation(HexConversions::to_hex(completedProof.ToRSeq()));
    REQUIRE(pair.out.lower->NumWrites() == 1); // The separate nonzero exchange retains its completed confirmation.
    HexSequence cached(pair.out.lower->PopWriteAsHex());
    REQUIRE(cached.ToRSeq()[5] == 15);
    REQUIRE(pair.outCredentials->writes == writes);
}

TEST_CASE("RemoteUpdateKeys - Outstation zero preserves certified status before continuation expiry", "[sa-zero-runtime]")
{
    RemotePair pair(2, true, std::make_shared<RemoteAuthority>(), 0, 0);
    const auto key = pair.outCredentials->users[1].updateKey;
    const auto common = pair.Out().Find(1)->Sequence();
    auto config = RemoteMasterSettings(RemoteSettings(pair.masterCredentials, pair.policy, pair.authority, 2)).authentication;
    AuthenticationSession master(SessionKeys::Role::MASTER, config);
    REQUIRE(master.Load(0));
    auto& engine = *master.remote;
    auto request = pair.authority->Status(3, 1, "A", 0);
    request.source = pair.authority;
    REQUIRE(engine.Begin(request, 0));
    std::array<uint8_t, 2048> bytes{};
    APDURequest statusRequest(W(bytes));
    REQUIRE(engine.Build(statusRequest, 0, 0));
    engine.Transmitted(statusRequest.ToRSeq());
    pair.out.SendToOutstation(HexConversions::to_hex(statusRequest.ToRSeq()));
    REQUIRE(pair.out.lower->NumWrites() == 1);
    HexSequence status(pair.out.lower->PopWriteAsHex());
    REQUIRE(status.ToRSeq().length() == 4);
    REQUIRE(status.ToRSeq()[1] == 0x81);
    pair.out.OnTxReady();
    const auto parsed = APDUHeaderParser::ParseResponse(status.ToRSeq());
    REQUIRE(parsed.success);
    REQUIRE(engine.Response(parsed.header, parsed.objects, 0) == RemoteUpdateKeys::Result::CONTINUE);
    APDURequest continuation(W(bytes));
    REQUIRE(engine.Build(continuation, 1, 0));
    engine.Transmitted(continuation.ToRSeq());
    pair.out.SendToOutstation(HexConversions::to_hex(continuation.ToRSeq()));
    REQUIRE(pair.out.lower->NumWrites() == 0); // Certified status survived, but V12 expired unsent.
    REQUIRE(engine.Busy());
    REQUIRE_FALSE(pair.Out().remote->Busy());
    REQUIRE(pair.outCredentials->users[1].pending);
    REQUIRE(pair.outCredentials->users[1].pendingRole == 0);
    REQUIRE(pair.outCredentials->users[1].updateKey == key);
    REQUIRE(pair.Out().Find(1)->Sequence() == common);
    REQUIRE_FALSE(pair.Out().Find(1)->Ready(0));
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
}

TEST_CASE("AuthenticationConfig - configured user capacity boundaries never fall back to usable defaults", "[auth-config][sa-v06-boundary]")
{
    const uint16_t capacity = GENERATE(uint16_t(1), uint16_t(2), uint16_t(16), uint16_t(17));
    const auto role = GENERATE(SessionKeys::Role::MASTER, SessionKeys::Role::OUTSTATION);
    auto credentials = std::make_shared<remote_update_test::RemoteCredentials>();
    auto policy = std::make_shared<remote_update_test::RemotePolicy>();
    auto authority = std::make_shared<remote_update_test::RemoteAuthority>();
    auto config = remote_update_test::RemoteSettings(credentials, policy, authority, capacity);
    if (role == SessionKeys::Role::MASTER) config.updateKeyTrust.reset();
    AuthenticationSession session(role, config);
    const bool valid = capacity == 2 || capacity == 16;
    REQUIRE(session.Load(0) == valid);
    REQUIRE(session.config.userCapacity == capacity);
    if (valid)
    {
        REQUIRE(session.Size() == capacity);
        REQUIRE(session.At(capacity) == nullptr);
        REQUIRE_FALSE(session.Find(1)->UpdateKey(0).is_empty());
        REQUIRE_FALSE(session.Find(2)->UpdateKey(0).is_empty());
    }
    for (size_t n = 0; n < session.Size(); ++n)
    {
        REQUIRE(session.At(n)->User() == n + 1);
        REQUIRE_FALSE(session.At(n)->Ready(0));
        if (!valid) REQUIRE(session.At(n)->UpdateKey(0).is_empty());
    }
    REQUIRE(credentials->writes == 0);
    REQUIRE(credentials->attempts == 0);
}

TEST_CASE("RemoteUpdateKeys - seventeenth active user cannot alter a full credential table", "[remote-update-keys][remote-update-runtime][sa-v06-boundary]")
{
    RemotePair pair(16);
    for (uint16_t user = 3; user <= 16; ++user)
    {
        CAPTURE(user);
        pair.authority->nextKey.fill(static_cast<uint8_t>(user + 3));
        auto completed = pair.Start(pair.authority->Status(1, 0, "user" + std::to_string(user)));
        pair.Pump();
        REQUIRE(completed->results.size() == 1);
        REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    }
    REQUIRE(pair.Master().Size() == 16);
    REQUIRE(pair.Out().Size() == 16);
    const auto masterUsers = pair.masterCredentials->users;
    const auto outUsers = pair.outCredentials->users;
    const auto masterStatus = pair.Master().GetStatus(0);
    const auto outStatus = pair.Out().GetStatus(0);
    std::array<uint32_t, 16> masterKSQ{}, outKSQ{};
    for (size_t n = 0; n < 16; ++n)
    {
        CAPTURE(n);
        REQUIRE(masterUsers[n].active);
        REQUIRE(outUsers[n].active);
        masterKSQ[n] = pair.Master().At(n)->Sequence();
        outKSQ[n] = pair.Out().At(n)->Sequence();
    }
    const auto masterWrites = pair.masterCredentials->writes, outWrites = pair.outCredentials->writes;
    const auto masterAttempts = pair.masterCredentials->attempts, outAttempts = pair.outCredentials->attempts;
    auto rejected = pair.Start(pair.authority->Status(1, 0, "overflow"));
    pair.Pump();
    REQUIRE(rejected->results.size() == 1);
    REQUIRE(rejected->results.front() != TaskCompletion::SUCCESS);
    REQUIRE_FALSE(pair.Master().remote->Busy());
    REQUIRE_FALSE(pair.Out().remote->Busy());
    HexSequence wire(pair.outWire.back());
    REQUIRE(wire.ToRSeq().length() >= 10);
    REQUIRE(wire.ToRSeq()[4] == 120);
    REQUIRE(wire.ToRSeq()[5] == 7);
    Group120Var7 error;
    REQUIRE(error.Read(wire.ToRSeq().skip(10)));
    REQUIRE(error.errorCode == 10); // Existing V10 no-slot rejection: Invalid Certification Data.
    // No WriteUser attempt means neither committed nor pending journal state changed.
    REQUIRE(pair.masterCredentials->writes == masterWrites);
    REQUIRE(pair.outCredentials->writes == outWrites);
    REQUIRE(pair.masterCredentials->attempts == masterAttempts);
    REQUIRE(pair.outCredentials->attempts == outAttempts);
    const auto afterMaster = pair.Master().GetStatus(0), afterOut = pair.Out().GetStatus(0);
    for (size_t n = 0; n < 16; ++n)
    {
        CAPTURE(n);
        REQUIRE(pair.masterCredentials->users[n].name == masterUsers[n].name);
        REQUIRE(pair.outCredentials->users[n].name == outUsers[n].name);
        REQUIRE(pair.masterCredentials->users[n].statusSequence == masterUsers[n].statusSequence);
        REQUIRE(pair.outCredentials->users[n].statusSequence == outUsers[n].statusSequence);
        REQUIRE(pair.masterCredentials->users[n].active);
        REQUIRE(pair.outCredentials->users[n].active);
        REQUIRE(crypto::ConstantTimeEqual(R(pair.masterCredentials->users[n].updateKey), R(masterUsers[n].updateKey)));
        REQUIRE(crypto::ConstantTimeEqual(R(pair.outCredentials->users[n].updateKey), R(outUsers[n].updateKey)));
        REQUIRE(pair.Master().At(n)->Sequence() == masterKSQ[n]);
        REQUIRE(pair.Out().At(n)->Sequence() == outKSQ[n]);
        REQUIRE(afterMaster.users[n].ready == masterStatus.users[n].ready);
        REQUIRE(afterOut.users[n].ready == outStatus.users[n].ready);
        REQUIRE(afterMaster.users[n].exchanging == masterStatus.users[n].exchanging);
        REQUIRE(afterOut.users[n].exchanging == outStatus.users[n].exchanging);
        REQUIRE(afterMaster.users[n].remainingMessages == masterStatus.users[n].remainingMessages);
        REQUIRE(afterOut.users[n].remainingMessages == outStatus.users[n].remainingMessages);
    }
    REQUIRE(pair.Master().GetStatus(0).statistics[static_cast<size_t>(SecurityStatistic::UPDATE_KEY_CHANGES)]
            == masterStatus.statistics[static_cast<size_t>(SecurityStatistic::UPDATE_KEY_CHANGES)]);
    REQUIRE(pair.Out().GetStatus(0).statistics[static_cast<size_t>(SecurityStatistic::UPDATE_KEY_CHANGES)]
            == outStatus.statistics[static_cast<size_t>(SecurityStatistic::UPDATE_KEY_CHANGES)]);
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
}
