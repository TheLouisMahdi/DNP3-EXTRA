// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "auth/UpdateKeyFunctions.h"
#include "crypto/CryptoProvider.h"
#include "auth/RemoteUpdateKeys.h"
#include "app/parsing/APDUHeaderParser.h"
#include "utils/MasterTestFixture.h"
#include "utils/OutstationTestObject.h"
#include "dnp3mocks/MockTaskCallback.h"
#include "dnp3mocks/RemoteUpdateKeyCredentials.h"
#include "utils/BufferHelpers.h"

#include <ser4cpp/util/HexConversions.h>
#include <catch.hpp>

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
MasterParams RemoteMasterSettings(AuthenticationConfig config)
{
    auto p = NoStartupTasks();
    config.updateKeyTrust.reset(); // The Master never receives BC.
    p.authentication = config;
    p.ignoreRestartIIN = true;
    return p;
}
OutstationConfig RemoteOutSettings(const AuthenticationConfig& config)
{
    OutstationConfig c;
    c.params.authentication = config;
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
    RemotePair(size_t capacity = 2, bool common = true)
        : masterCredentials(Credentials(common)), outCredentials(Credentials(common)),
          master(RemoteMasterSettings(RemoteSettings(masterCredentials, policy, authority, capacity)), Addresses()),
          out(RemoteOutSettings(RemoteSettings(outCredentials, policy, authority, capacity)))
    {
        out.application->currentTime = DNPTime(1700000000000ULL);
        out.LowerLayerUp();
        REQUIRE(master.context->OnLowerLayerUp());
        master.exe->run_many();
        Pump();
        REQUIRE(Master().Find(1)->Ready(0) == common);
        REQUIRE(Master().Find(2)->Ready(0));
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
    // A valid marker pointing to a missing/corrupt record fails closed; never
    // fall back to the other snapshot, even if it contains a well-formed key.
    REQUIRE(marker.size() == 49);
    const auto activeTarget = target + L"/remote" + std::to_wstring(marker[8]);
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

TEST_CASE("RemoteUpdateKeys - each lost response retries the owned native exchange exactly once", "[remote-update-keys][remote-update-runtime]")
{
    const auto response = GENERATE(uint8_t(0), uint8_t(12), uint8_t(15));
    RemotePair pair;
    pair.dropStatus = response == 0;
    pair.dropOutVariation = response;
    auto completed = pair.Start(pair.authority->Status(3, 1, "A"));
    pair.Pump();
    REQUIRE(completed->results.empty());
    pair.master.exe->advance_time(std::chrono::milliseconds(2000));
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

TEST_CASE("RemoteUpdateKeys - SCS wrap requires a newly trusted authority key and rejects historical certificates", "[remote-update-keys][remote-update-runtime]")
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
    REQUIRE(completed->results.front() == TaskCompletion::SUCCESS);
    REQUIRE(pair.outCredentials->users[1].statusSequence == 0);
    REQUIRE(pair.outCredentials->users[1].role == 0);
    completed = pair.Start(historical);
    pair.Pump();
    REQUIRE(completed->results.size() == 1);
    REQUIRE(completed->results.front() != TaskCompletion::SUCCESS);
    REQUIRE(pair.outCredentials->users[1].role == 0);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 2);
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

TEST_CASE("RemoteUpdateKeys - restart loads only verified active credentials and preserves pending recovery", "[remote-update-keys][remote-update-runtime]")
{
    RemotePair pair;
    pair.dropOutVariation = 15;
    auto completed = pair.Start(pair.authority->Status(3, 1, "A", 0));
    pair.Pump();
    REQUIRE(completed->results.empty());
    REQUIRE(pair.masterCredentials->users[1].havePendingKey);
    REQUIRE(pair.masterCredentials->users[1].role == 1);
    REQUIRE(pair.outCredentials->users[1].role == 0);
    REQUIRE(pair.master.context->OnLowerLayerDown());
    AuthenticationSession restarted(SessionKeys::Role::MASTER,
        RemoteMasterSettings(RemoteSettings(pair.masterCredentials, pair.policy, pair.authority, 2)).authentication);
    REQUIRE(restarted.Load(0));
    REQUIRE(restarted.Find(2)->UpdateKey(0).equals(R(pair.masterCredentials->users[1].updateKey)));
    REQUIRE_FALSE(restarted.Find(2)->UpdateKey(0).equals(R(pair.masterCredentials->users[1].pendingUpdateKey)));
    pair.out.LowerLayerDown();
    pair.out.LowerLayerUp();
    REQUIRE(pair.masterCredentials->users[1].havePendingKey);
    UpdateKeyRequest verify;
    verify.name[0] = 'A';
    verify.nameSize = 1;
    verify.verifyOnly = true;
    REQUIRE(restarted.remote->Begin(verify, 0));
    // Recreated Master engine and native Outstation, using only the durable
    // pending key. V15 proof, rather than a local restart, activates the key.
    for (uint8_t sequence = 9; sequence <= 10; ++sequence)
    {
        std::array<uint8_t, 1024> buffer{};
        APDURequest apdu(W(buffer));
        REQUIRE(restarted.remote->Build(apdu, sequence, 0));
        const rseq_t wire(buffer.data(), apdu.Size());
        restarted.remote->Transmitted(wire);
        pair.out.SendToOutstation(HexConversions::to_hex(wire));
        REQUIRE(pair.out.lower->NumWrites() == 1);
        HexSequence response(pair.out.lower->PopWriteAsHex());
        pair.out.OnTxReady();
        const auto parsed = APDUHeaderParser::ParseResponse(response.ToRSeq());
        REQUIRE(parsed.success);
        REQUIRE(restarted.remote->Response(parsed.header, parsed.objects, 0)
            == (sequence == 9 ? RemoteUpdateKeys::Result::CONTINUE : RemoteUpdateKeys::Result::COMPLETE));
    }
    REQUIRE_FALSE(pair.masterCredentials->users[1].havePendingKey);
    REQUIRE(pair.masterCredentials->users[1].updateKey == pair.outCredentials->users[1].updateKey);
    REQUIRE(restarted.Find(2)->UpdateKey(0).equals(R(pair.outCredentials->users[1].updateKey)));
    REQUIRE(restarted.statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.Out().statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 1);
    REQUIRE(pair.out.cmdHandler->NumInvocations() == 0);
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
