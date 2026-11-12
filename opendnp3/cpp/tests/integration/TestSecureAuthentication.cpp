// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "crypto/CryptoProvider.h"
#include "mocks/NullSOEHandler.h"
#include "mocks/QueuedChannelListener.h"
#include "dnp3mocks/RemoteUpdateKeyCredentials.h"
#include "dnp3mocks/AsymmetricUpdateKeyCredentials.h"
#include "dnp3mocks/UserIdentityCertificate.h"
#include "dnp3mocks/MockSOEHandler.h"
#include "../unit/utils/AcceptanceObservation.h"

#include <opendnp3/DNP3Manager.h>
#include <opendnp3/auth/SecurityStatistic.h>
#include <opendnp3/auth/AuthenticationStatus.h>
#include <opendnp3/master/DefaultMasterApplication.h>
#include <opendnp3/master/ICommandTaskResult.h>
#include <opendnp3/outstation/DefaultOutstationApplication.h>
#include <opendnp3/outstation/SimpleCommandHandler.h>

#include <catch.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <deque>
#include <chrono>
#include <condition_variable>
#include <thread>
#include <utility>
#include <future>
#include <mutex>
#include <sstream>

using namespace opendnp3;
namespace
{
class AuthenticationTrace final : public ILogHandler
{
public:
    void log(ModuleId, const char* id, LogLevel, char const*, char const* message) override
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (messages.size() == 128)
            messages.pop_front();
        messages.push_back(std::string(id) + " " + message);
    }
    std::string Snapshot()
    {
        std::lock_guard<std::mutex> lock(mutex);
        std::ostringstream out;
        for (const auto& line : messages)
            out << line << "\n";
        return out.str();
    }

private:
    std::mutex mutex;
    std::deque<std::string> messages;
};
class TcpCredentials final : public IAuthenticationCredentials
{
public:
    std::array<std::array<uint8_t, 32>, 2> keys{};
    size_t keyLength = 32;
    const uint64_t lifetimeMs;
    const uint16_t expectedAssociation;
    explicit TcpCredentials(uint64_t lifetimeMs_ = 3600000, uint16_t association = 7)
        : lifetimeMs(lifetimeMs_), expectedAssociation(association)
    {
        for (auto& key : keys)
            REQUIRE(crypto::GenerateRandom(ser4cpp::wseq_t(key.data(), key.size())) == crypto::Result::OK);
    }
    ~TcpCredentials()
    {
        for (auto& key : keys)
            crypto::Clear(ser4cpp::wseq_t(key.data(), key.size()));
    }
    bool ReadUpdateKey(
        uint16_t association, uint16_t user, uint8_t* output, size_t capacity, uint64_t& lifetime) override
    {
        if (association != expectedAssociation || user < 1 || user > 2 || !output || capacity != keyLength)
            return false;
        std::copy_n(keys[user - 1].begin(), capacity, output);
        lifetime = lifetimeMs;
        return true;
    }
};
class TcpPolicy final : public IAuthenticationAuthorization
{
    const uint16_t expectedAssociation;

public:
    explicit TcpPolicy(uint16_t association = 7) : expectedAssociation(association) {}

    bool IsAuthorized(
        uint16_t association, uint16_t user, uint8_t function, const uint8_t* apdu, size_t size) const override
    {
        return association == expectedAssociation && apdu && size >= 2 && apdu[1] == function
            && ((user == 1 && (function == 0 || function == 1 || function == 2)) || user == 2);
    }
};
class TcpCommands final : public SimpleCommandHandler
{
public:
    TcpCommands() : SimpleCommandHandler(CommandStatus::SUCCESS) {}
    std::atomic<size_t> selected{0}, operated{0};

private:
    void DoSelect(const ControlRelayOutputBlock&, uint16_t) override
    {
        ++selected;
    }
    void DoOperate(const ControlRelayOutputBlock&, uint16_t, OperateType) override
    {
        ++operated;
    }
};
class TcpRestartApplication final : public DefaultOutstationApplication
{
public:
    std::atomic<unsigned> coldRestarts{0};
    RestartMode ColdRestartSupport() const override { return RestartMode::SUPPORTED_DELAY_FINE; }
    uint16_t ColdRestart() override
    {
        ++coldRestarts;
        return 2;
    }
};

class ScanResult final : public ITaskCallback
{
public:
    std::promise<TaskCompletion> result;
    void OnStart() override {}
    void OnComplete(TaskCompletion status) override
    {
        result.set_value(status);
    }
    void OnDestroyed() override {}
};
} // namespace
TEST_CASE("SecureAuthenticationTCP - session keys authenticated READ CONTROL and reconnect", "[sa-tcp]")
{
    auto credentials = std::make_shared<TcpCredentials>();
    auto policy = std::make_shared<TcpPolicy>();
    auto commands = std::make_shared<TcpCommands>();
    auto listener = std::make_shared<QueuedChannelListener>();
    auto trace = std::make_shared<AuthenticationTrace>();
    DNP3Manager manager(1, trace);
    const auto levels = opendnp3::levels::NORMAL | flags::APP_HEADER_RX | flags::APP_HEADER_TX | flags::APP_OBJECT_RX
        | flags::APP_OBJECT_TX;
    auto server = manager.AddTCPServer("sa-server", levels, ServerAcceptMode::CloseExisting,
                                       IPEndpoint::Localhost(0), nullptr);
    const auto port = server->GetBoundPort();
    auto client = manager.AddTCPClient("sa-client", levels, ChannelRetry::Default(), {IPEndpoint::Localhost(port)},
                                       "127.0.0.1", listener);
    OutstationStackConfig oc(DatabaseConfig{});
    oc.link.LocalAddr = 10;
    oc.link.RemoteAddr = 1;
    oc.outstation.params.authentication.association = 7;
    oc.outstation.params.authentication.credentials = credentials;
    oc.outstation.params.authentication.authorization = policy;
    oc.outstation.params.authentication.renewalMessageCount = 12;
    const bool legacy = GENERATE(false, true);
    if (legacy)
    {
        credentials->keyLength = 16;
        oc.outstation.params.authentication.macAlgorithm = 2;
        oc.outstation.params.authentication.tagLength = 10;
        oc.outstation.params.authentication.keyWrapAlgorithm = 1;
    }
    const bool aggressive = GENERATE(false, true);
    oc.outstation.params.authentication.aggressiveTransmit = aggressive;
    oc.outstation.params.authentication.aggressiveReceive = aggressive;
    MasterStackConfig mc;
    mc.link.LocalAddr = 1;
    mc.link.RemoteAddr = 10;
    mc.master.disableUnsolOnStartup = false;
    mc.master.startupIntegrityClassMask = ClassField::None();
    mc.master.unsolClassMask = ClassField::None();
    mc.master.ignoreRestartIIN = true;
    mc.master.authentication = oc.outstation.params.authentication;
    auto restartApplication = std::make_shared<TcpRestartApplication>();
    auto outstation = server->AddOutstation("sa-outstation", commands, restartApplication, oc);
    auto master = client->AddMaster("sa-master", NullSOEHandler::Create(), DefaultMasterApplication::Create(), mc);
    REQUIRE(outstation);
    REQUIRE(master);
    REQUIRE(outstation->Enable());
    REQUIRE(master->Enable());
    REQUIRE(listener->WaitForState(ChannelState::OPEN, std::chrono::seconds(5)));
    auto read = [&]() {
        auto result = std::make_shared<ScanResult>();
        auto future = result->result.get_future();
        master->ScanClasses(ClassField::AllClasses(), NullSOEHandler::Create(), TaskConfig::With(result));
        REQUIRE(future.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
        const auto outcome = future.get();
        INFO(trace->Snapshot());
        REQUIRE(outcome == TaskCompletion::SUCCESS);
    };
    auto control = [&]() {
        auto result = std::make_shared<std::promise<TaskCompletion>>();
        auto future = result->get_future();
        auto config = TaskConfig::Default();
        config.authenticationUser = 2;
        master->SelectAndOperate(
            ControlRelayOutputBlock(OperationType::LATCH_ON), 0,
            [result](const ICommandTaskResult& status) { result->set_value(status.summary); }, config);
        REQUIRE(future.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
        const auto outcome = future.get();
        INFO(trace->Snapshot());
        REQUIRE(outcome == TaskCompletion::SUCCESS);
    };
    read();
    control();
    REQUIRE(commands->selected.load() == 1);
    REQUIRE(commands->operated.load() == 1);
    // Repeated real traffic reaches the configured renewal threshold. Every
    // request and response must still authenticate after new keys are negotiated.
    read();
    read();
    control();
    REQUIRE(commands->operated.load() == 2);
    REQUIRE(master->Disable());
    REQUIRE(listener->WaitForState(ChannelState::CLOSED, std::chrono::seconds(5)));
    REQUIRE(master->Enable());
    REQUIRE(listener->WaitForState(ChannelState::OPEN, std::chrono::seconds(5)));
    read();
    control();
    REQUIRE(commands->selected.load() == 3);
    REQUIRE(commands->operated.load() == 3);
    // The application supplies the delay and the test simulates its later reboot.
    const auto restarted = std::make_shared<std::promise<RestartOperationResult>>();
    auto restartFuture = restarted->get_future();
    auto restartTask = TaskConfig::Default();
    restartTask.authenticationUser = 2;
    master->Restart(RestartType::COLD,
        [restarted](const RestartOperationResult& result) { restarted->set_value(result); }, restartTask);
    REQUIRE(restartFuture.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    const auto restartResult = restartFuture.get();
    REQUIRE(restartResult.summary == TaskCompletion::SUCCESS);
    REQUIRE(restartResult.restartTime == TimeDuration::Milliseconds(2));
    REQUIRE(restartApplication->coldRestarts.load() == 1);
    // A new Outstation instance loses session material and resets its KSQ.
    server->Shutdown();
    REQUIRE(listener->WaitForState(ChannelState::CLOSED, std::chrono::seconds(5)));
    server = manager.AddTCPServer("sa-restarted-server", levels, ServerAcceptMode::CloseExisting,
                                  IPEndpoint::Localhost(port), nullptr);
    outstation = server->AddOutstation("sa-restarted-outstation", commands, DefaultOutstationApplication::Create(), oc);
    REQUIRE(outstation->Enable());
    REQUIRE(listener->WaitForState(ChannelState::OPEN, std::chrono::seconds(5)));
    read();
    control();
    REQUIRE(commands->operated.load() == 4);
    // FC6 local completion is distinct from the independently observed RTU count.
    // A following authenticated read acts as a wire/executor barrier for the receiver.
    auto submitted = std::make_shared<std::promise<CommandStatus>>();
    auto submittedFuture = submitted->get_future();
    auto config = TaskConfig::Default(); config.authenticationUser = 2;
    REQUIRE(master->DirectOperateNoAck(ControlRelayOutputBlock(OperationType::LATCH_OFF), 0,
        [submitted](const ICommandTaskResult& result) {
            struct Points final : IVisitor<CommandPointResult>
            {
                CommandStatus status = CommandStatus::SUCCESS;
                size_t count = 0;
                void OnValue(const CommandPointResult& value) override { status = value.status; ++count; }
            } points;
            result.Foreach(points);
            submitted->set_value(result.summary == TaskCompletion::SUCCESS && points.count == 1
                                    ? points.status : CommandStatus::FORMAT_ERROR);
        }, config));
    REQUIRE(submittedFuture.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    REQUIRE(submittedFuture.get() == CommandStatus::UNDEFINED);
    read();
    REQUIRE(commands->selected.load() == 4);
    REQUIRE(commands->operated.load() == 5);
    manager.Shutdown();
}

TEST_CASE("AT-PROFILE-065-TCP", "[sa-tcp][security-statistics-tcp]")
{
    constexpr auto statistic = static_cast<uint8_t>(SecurityStatistic::AUTHORIZATION_FAILURES);
    DNP3Manager manager(1, std::make_shared<AuthenticationTrace>());
    struct Pair
    {
        std::shared_ptr<IMaster> master;
        std::shared_ptr<IOutstation> outstation;
        std::shared_ptr<TcpCommands> commands;
    };
    const auto connect = [&](uint16_t association) {
        const auto suffix = std::to_string(association);
        auto listener = std::make_shared<QueuedChannelListener>();
        auto server = manager.AddTCPServer("stats-server-" + suffix, levels::NORMAL,
                                           ServerAcceptMode::CloseExisting, IPEndpoint::Localhost(0), nullptr);
        REQUIRE(server);
        auto client = manager.AddTCPClient("stats-client-" + suffix, levels::NORMAL, ChannelRetry::Default(),
            {IPEndpoint::Localhost(server->GetBoundPort())}, "127.0.0.1", listener);
        REQUIRE(client);
        OutstationStackConfig oc(DatabaseConfig{});
        oc.link.LocalAddr = 10;
        oc.link.RemoteAddr = 1;
        auto& auth = oc.outstation.params.authentication;
        auth.association = association;
        auth.credentials = std::make_shared<TcpCredentials>(3600000, association);
        auth.authorization = std::make_shared<TcpPolicy>(association);
        oc.outstation.eventBufferConfig.maxSecurityStatEvents = 8;
        oc.outstation.securityStatThresholds[statistic] = 1;
        oc.outstation.securityStatConfig[statistic].evariation = EventSecurityStatVariation::Group122Var1;
        MasterStackConfig mc;
        mc.link.LocalAddr = 1;
        mc.link.RemoteAddr = 10;
        mc.master.disableUnsolOnStartup = false;
        mc.master.startupIntegrityClassMask = ClassField::None();
        mc.master.unsolClassMask = ClassField::None();
        mc.master.ignoreRestartIIN = true;
        mc.master.authentication = auth;
        Pair pair;
        pair.commands = std::make_shared<TcpCommands>();
        pair.outstation = server->AddOutstation("stats-outstation-" + suffix, pair.commands,
                                               DefaultOutstationApplication::Create(), oc);
        pair.master = client->AddMaster("stats-master-" + suffix, NullSOEHandler::Create(),
                                        DefaultMasterApplication::Create(), mc);
        REQUIRE(pair.outstation);
        REQUIRE(pair.master);
        REQUIRE(pair.outstation->Enable());
        REQUIRE(pair.master->Enable());
        REQUIRE(listener->WaitForState(ChannelState::OPEN, std::chrono::seconds(5)));
        return pair;
    };
    const auto first = connect(7);
    const auto second = connect(8);
    const auto read = [&](const Pair& pair) {
        auto soe = std::make_shared<MockSOEHandler>();
        auto result = std::make_shared<ScanResult>();
        auto future = result->result.get_future();
        pair.master->ScanAllObjects(GroupVariationID(122, 1), soe, TaskConfig::With(result));
        REQUIRE(future.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
        REQUIRE(future.get() == TaskCompletion::SUCCESS);
        return soe;
    };

    const auto outcome = std::make_shared<std::promise<TaskCompletion>>();
    auto future = outcome->get_future();
    auto cfg = TaskConfig::Default();
    cfg.authenticationUser = 1;
    first.master->DirectOperate(ControlRelayOutputBlock(OperationType::LATCH_ON), 0,
        [outcome](const ICommandTaskResult& result) { outcome->set_value(result.summary); }, cfg);
    REQUIRE(future.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    REQUIRE(future.get() != TaskCompletion::SUCCESS);
    acceptance::Observe("denied_operations", first.commands->operated.load());
    REQUIRE(first.commands->operated.load() == 0);
    REQUIRE(first.outstation->GetAuthenticationStatus().statistics[statistic] == 1);
    REQUIRE(second.outstation->GetAuthenticationStatus().statistics[statistic] == 0);

    const auto authorizationEvent = [](const MockSOEHandler::Record<Indexed<SecurityStat>>& value) {
        return value.meas.index == static_cast<uint8_t>(SecurityStatistic::AUTHORIZATION_FAILURES);
    };
    const auto countAuthorization = [&](const MockSOEHandler& soe) {
        return std::count_if(soe.securityStatSOE.begin(), soe.securityStatSOE.end(), authorizationEvent);
    };
    const auto accepted = read(first);
    REQUIRE(countAuthorization(*accepted) == 1);
    const auto& record = *std::find_if(accepted->securityStatSOE.begin(), accepted->securityStatSOE.end(),
                                      authorizationEvent);
    REQUIRE(record.info.gv == GroupVariation::Group122Var1);
    REQUIRE(record.info.qualifier == QualifierCode::UINT16_CNT_UINT16_INDEX);
    REQUIRE(record.meas.index == statistic);
    REQUIRE(record.meas.value.associationId == 0);
    REQUIRE(record.meas.value.value == 1);
    REQUIRE_FALSE(record.meas.value.HasTime());
    acceptance::Observe("typed_authz_events", countAuthorization(*accepted));
    const auto isolated = read(second);
    acceptance::Observe("foreign_authz_events", countAuthorization(*isolated));
    REQUIRE(countAuthorization(*isolated) == 0);
    REQUIRE(countAuthorization(*read(first)) == 0);
    manager.Shutdown();
}


TEST_CASE("SecureAuthenticationTCP - remote update installs a key used by native commands and reconnect", "[sa-tcp][remote-update-tcp]")
{
    using namespace remote_update_test;
    auto mc = std::make_shared<RemoteCredentials>();
    auto oc = std::make_shared<RemoteCredentials>();
    auto policy = std::make_shared<RemotePolicy>();
    enum class AuthorityMode { SYMMETRIC, ASYMMETRIC, CERTIFICATE, RELATIVE_CERTIFICATE };
    const auto mode = GENERATE(AuthorityMode::SYMMETRIC, AuthorityMode::ASYMMETRIC,
                               AuthorityMode::CERTIFICATE, AuthorityMode::RELATIVE_CERTIFICATE);
    const bool relative = mode == AuthorityMode::RELATIVE_CERTIFICATE;
    const bool asymmetric = mode != AuthorityMode::SYMMETRIC;
    std::shared_ptr<RemoteAuthority> authority = asymmetric ? std::make_shared<AsymmetricAuthority>() : std::make_shared<RemoteAuthority>();
    std::unique_ptr<SignedIdentity> identity;
    std::unique_ptr<SignedAttribute> attribute;
    if (mode == AuthorityMode::CERTIFICATE || relative)
    {
        identity.reset(new SignedIdentity(*std::static_pointer_cast<AsymmetricAuthority>(authority)->material,
                                          1, 1, 3, false, false, 6000));
        attribute.reset(new SignedAttribute(*std::static_pointer_cast<AsymmetricAuthority>(authority)->material, *identity));
        if (relative)
        {
            oc->trustedTime = false;
            identity->policy->pkiTime = uint64_t(SignedIdentity::epoch) * 1000;
        }
    }
    std::shared_ptr<IUserCertificatePolicy> certificates = identity ? identity->policy : nullptr;
    auto listener = std::make_shared<QueuedChannelListener>();
    auto trace = std::make_shared<AuthenticationTrace>();
    auto commands = std::make_shared<TcpCommands>();
    DNP3Manager manager(1, trace);
    auto server = manager.AddTCPServer("remote-sa-server", levels::NORMAL, ServerAcceptMode::CloseExisting,
        IPEndpoint::Localhost(0), nullptr);
    const auto port = server->GetBoundPort();
    auto client = manager.AddTCPClient("remote-sa-client", levels::NORMAL, ChannelRetry::Default(),
        {IPEndpoint::Localhost(port)}, "127.0.0.1", listener);
    OutstationStackConfig outConfig(DatabaseConfig{});
    outConfig.link.LocalAddr = 10;
    outConfig.link.RemoteAddr = 1;
    outConfig.outstation.params.authentication = RemoteSettings(oc, policy, authority, 2, certificates);
    outConfig.outstation.params.allowUnsolicited = true;
    MasterStackConfig masterConfig;
    masterConfig.link.LocalAddr = 1;
    masterConfig.link.RemoteAddr = 10;
    masterConfig.master.disableUnsolOnStartup = false;
    masterConfig.master.startupIntegrityClassMask = ClassField::None();
    masterConfig.master.unsolClassMask = ClassField::None();
    masterConfig.master.ignoreRestartIIN = true;
    masterConfig.master.authentication = RemoteSettings(mc, policy, authority, 2, certificates);
    masterConfig.master.authentication.updateKeyTrust.reset();
    if (identity)
    {
        REQUIRE(identity->der.size() > 4096);
        REQUIRE(identity->der.size() <= MAX_USER_CERTIFICATE_SIZE);
        masterConfig.master.maxTxFragSize = MAX_USER_CERTIFICATE_SIZE + 10;
        outConfig.outstation.params.maxRxFragSize = MAX_USER_CERTIFICATE_SIZE + 10;
    }
    auto outstation = server->AddOutstation("remote-sa-outstation", commands, DefaultOutstationApplication::Create(), outConfig);
    auto master = client->AddMaster("remote-sa-master", NullSOEHandler::Create(), DefaultMasterApplication::Create(), masterConfig);
    REQUIRE(outstation);
    REQUIRE(master);
    REQUIRE(outstation->Enable());
    REQUIRE(master->Enable());
    REQUIRE(listener->WaitForState(ChannelState::OPEN, std::chrono::seconds(5)));
    auto request = identity ? identity->Request(authority) : authority->Status(3, 1, "A");
    request.source = authority;
    auto completion = std::make_shared<ScanResult>();
    auto future = completion->result.get_future();
    REQUIRE(master->ChangeUpdateKey(request, TaskConfig::With(completion)));
    REQUIRE(future.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    INFO(trace->Snapshot());
    REQUIRE(future.get() == TaskCompletion::SUCCESS);
    REQUIRE(mc->users[1].updateKey == authority->nextKey);
    REQUIRE(oc->users[1].updateKey == authority->nextKey);
    if (identity) REQUIRE(oc->users[1].certificateRevision == 1);
    if (relative) REQUIRE(oc->users[1].expiresUnixMs == 0);
    auto control = [&]() {
        auto completion = std::make_shared<std::promise<TaskCompletion>>();
        auto result = completion->get_future();
        auto config = TaskConfig::Default();
        config.authenticationUser = 2;
        master->SelectAndOperate(ControlRelayOutputBlock(OperationType::LATCH_ON), 0,
            [completion](const ICommandTaskResult& value) { completion->set_value(value.summary); }, config);
        REQUIRE(result.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
        INFO(trace->Snapshot());
        REQUIRE(result.get() == TaskCompletion::SUCCESS);
    };
    control();
    REQUIRE(commands->operated.load() == 1);
    REQUIRE(master->Disable());
    REQUIRE(listener->WaitForState(ChannelState::CLOSED, std::chrono::seconds(5)));
    REQUIRE(master->Enable());
    REQUIRE(listener->WaitForState(ChannelState::OPEN, std::chrono::seconds(5)));
    control();
    REQUIRE(commands->operated.load() == 2);
    // Recreate the Outstation: durable credentials, not cached Session Keys,
    // must establish the fresh sessions after restart.
    const auto restart = [&]() {
        server->Shutdown();
        REQUIRE(listener->WaitForState(ChannelState::CLOSED, std::chrono::seconds(5)));
        server = manager.AddTCPServer("remote-sa-restarted-server", levels::NORMAL, ServerAcceptMode::CloseExisting,
            IPEndpoint::Localhost(port), nullptr);
        outstation = server->AddOutstation("remote-sa-restarted-outstation", commands, DefaultOutstationApplication::Create(), outConfig);
        REQUIRE(outstation->Enable());
        REQUIRE(listener->WaitForState(ChannelState::OPEN, std::chrono::seconds(5)));
    };
    if (!relative)
    {
        restart();
        control();
        REQUIRE(commands->operated.load() == 3);
    }
    if (identity)
    {
        authority->nextKey.fill(0xA7);
        auto completed = std::make_shared<ScanResult>();
        auto result = completed->result.get_future();
        REQUIRE(master->ChangeUpdateKey(attribute->Request(authority), TaskConfig::With(completed)));
        REQUIRE(result.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
        REQUIRE(result.get() == TaskCompletion::SUCCESS);
        REQUIRE(oc->users[1].identity.serial.back() == 2);
        REQUIRE(oc->users[1].attribute.serial.back() == 2);
        REQUIRE(oc->users[1].certificateRevision == 2);
        REQUIRE(oc->users[1].roleMask == 5);
        REQUIRE(oc->users[1].updateKey == authority->nextKey);
        REQUIRE(mc->users[1].updateKey == authority->nextKey);
        if (relative) REQUIRE(oc->users[1].expiresUnixMs == 0);
        auto denied = std::make_shared<std::promise<TaskCompletion>>();
        auto resultDenied = denied->get_future();
        auto config = TaskConfig::Default();
        config.authenticationUser = 2;
        master->SelectAndOperate(ControlRelayOutputBlock(OperationType::LATCH_ON), 0,
            [denied](const ICommandTaskResult& value) { denied->set_value(value.summary); }, config);
        REQUIRE(resultDenied.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
        REQUIRE(resultDenied.get() != TaskCompletion::SUCCESS);
        REQUIRE(commands->operated.load() == (relative ? 2 : 3));
        if (relative)
        {
            restart();
            REQUIRE_FALSE(outstation->GetAuthenticationStatus().users[1].ready);
            REQUIRE(oc->users[1].updateKey == authority->nextKey);
        }
    }
    manager.Shutdown();
}

namespace
{
// Metadata only: never retain APDU bytes, nonces, wrapped keys or MACs.
class RenewalTrace final : public ILogHandler
{
public:
    using Clock = std::chrono::steady_clock;
    void log(ModuleId, const char* id, LogLevel level, const char*, const char* message) override
    {
        if (!(level == flags::APP_OBJECT_TX)) return;
        const std::string name(id), text(message);
        const bool master = name.find("renewal-master") != std::string::npos;
        const bool outstation = name.find("renewal-outstation") != std::string::npos;
        if (!master && !outstation) return;
        const bool v1 = text.find("120,001 ") == 0;
        const bool v2 = text.find("120,002 ") == 0;
        const bool v3 = text.find("120,003 ") == 0;
        const bool v4 = master && text.find("120,004 ") == 0;
        const bool v5 = outstation && text.find("120,005 ") == 0;
        const bool v6 = master && text.find("120,006 ") == 0;
        std::unique_lock<std::mutex> lock(mutex);
        // Count each authenticated ASDU once at its sender. V3/V9 is one ASDU.
        if (outstation && v1) ++traffic[0]; // Control Challenge
        if (master && v2) ++traffic[1];     // Control Reply
        if (master && v1) ++traffic[2];     // Monitoring Challenge
        if (outstation && v2) ++traffic[3]; // Monitoring Reply
        if (outstation && v3) ++traffic[4]; // Aggressive Monitoring response
        if (v4) { ++requests; lastRequest = Clock::now(); awaitingConfirmation = false; }
        if (v6) { ++changes; awaitingConfirmation = true; }
        if (v5 && awaitingConfirmation)
        {
            // The Outstation installed V6 before emitting this final V5. The
            // Master installs upon receiving it, before it can issue new traffic.
            confirmationTraffic = traffic;
            awaitingConfirmation = false;
        }
        if (v6 && armed)
        {
            armed = false;
            held = true;
            cv.notify_all();
            if (!cv.wait_for(lock, std::chrono::seconds(10), [this] { return released; })) gateExpired = true;
        }
    }
    void Arm()
    {
        std::lock_guard<std::mutex> lock(mutex);
        armed = true; held = released = gateExpired = false;
    }
    bool WaitHeld()
    {
        std::unique_lock<std::mutex> lock(mutex);
        return cv.wait_for(lock, std::chrono::seconds(10), [this] { return held; });
    }
    void Release()
    {
        std::lock_guard<std::mutex> lock(mutex);
        released = true;
        cv.notify_all();
    }
    bool Expired()
    {
        std::lock_guard<std::mutex> lock(mutex);
        return gateExpired;
    }
    std::pair<size_t, size_t> Counts()
    {
        std::lock_guard<std::mutex> lock(mutex);
        return {requests, changes};
    }
    std::array<size_t, 5> SinceConfirmation()
    {
        std::lock_guard<std::mutex> lock(mutex);
        std::array<size_t, 5> result{};
        for (size_t n = 0; n < result.size(); ++n) result[n] = traffic[n] - confirmationTraffic[n];
        return result;
    }
    Clock::time_point LastRequest()
    {
        std::lock_guard<std::mutex> lock(mutex);
        return lastRequest;
    }
private:
    std::mutex mutex;
    std::condition_variable cv;
    size_t requests = 0, changes = 0;
    bool armed = false, held = false, released = false, gateExpired = false;
    bool awaitingConfirmation = false;
    std::array<size_t, 5> traffic{}, confirmationTraffic{};
    Clock::time_point lastRequest{};
};

size_t CountedASDUs(const std::array<size_t, 5>& traffic, size_t user)
{
    // Only user 1 owns Monitoring authentication. User 2 owns the control
    // Challenge/Reply pair in this fixture's non-aggressive Master commands.
    const auto control = traffic[0] + traffic[1];
    return user == 0 ? control + traffic[2] + traffic[3] + traffic[4] : control;
}

uint32_t KeyChanges(const AuthenticationStatus& status)
{
    return status.statistics[static_cast<size_t>(SecurityStatistic::SESSION_KEY_CHANGES)];
}
bool ReadyUsers(const AuthenticationStatus& status)
{
    return status.available && status.size == 2 && status.users[0].number == 1 && status.users[1].number == 2
        && status.users[0].ready && status.users[1].ready
        && !status.users[0].exchanging && !status.users[1].exchanging;
}

struct RenewalTcpPair
{
    std::shared_ptr<RenewalTrace> trace = std::make_shared<RenewalTrace>();
    std::shared_ptr<TcpCredentials> credentials = std::make_shared<TcpCredentials>(14400000);
    std::shared_ptr<TcpPolicy> policy = std::make_shared<TcpPolicy>();
    std::shared_ptr<TcpCommands> commands = std::make_shared<TcpCommands>();
    std::shared_ptr<QueuedChannelListener> listener = std::make_shared<QueuedChannelListener>();
    // Separate workers allow peer shutdown while the Master's pre-TX log gate is held.
    DNP3Manager masterManager{1, trace}, outManager{1, trace};
    std::shared_ptr<IChannel> server, client;
    std::shared_ptr<IMaster> master;
    std::shared_ptr<IOutstation> outstation;
    OutstationStackConfig oc{DatabaseConfig{}};
    uint16_t port = 0;
    RenewalTrace::Clock::time_point enabled;
    explicit RenewalTcpPair(uint32_t count = 1000, uint32_t intervalMs = 900000)
    {
        oc.link.LocalAddr = 10; oc.link.RemoteAddr = 1;
        auto& auth = oc.outstation.params.authentication;
        auth.association = 7; auth.credentials = credentials; auth.authorization = policy;
        REQUIRE(auth.renewalMessageCount == 1000);
        if (count != 1000) auth.renewalMessageCount = count; // Exercise the actual default too.
        auth.renewalIntervalMs = intervalMs;
        auth.replyTimeoutMs = 1000;
        // Responses use the existing aggressive path after its real initial Challenge.
        // Thus Control user 2 can exhaust its own C/R budget while Common stays valid.
        auth.aggressiveTransmit = true;
        oc.outstation.params.allowUnsolicited = false;
        server = outManager.AddTCPServer("renewal-server", levels::NORMAL | flags::APP_HEADER_TX | flags::APP_OBJECT_TX, ServerAcceptMode::CloseExisting,
                                         IPEndpoint::Localhost(0), nullptr);
        port = server->GetBoundPort();
        client = masterManager.AddTCPClient("renewal-client", levels::NORMAL | flags::APP_HEADER_TX | flags::APP_OBJECT_TX,
            ChannelRetry::Default(), {IPEndpoint::Localhost(port)}, "127.0.0.1", listener);
        MasterStackConfig mc;
        mc.link.LocalAddr = 1; mc.link.RemoteAddr = 10;
        mc.master.authentication = auth;
        mc.master.authentication.aggressiveTransmit = false;
        mc.master.authentication.aggressiveReceive = true;
        mc.master.disableUnsolOnStartup = false;
        mc.master.startupIntegrityClassMask = ClassField::None();
        mc.master.unsolClassMask = ClassField::None();
        mc.master.ignoreRestartIIN = true;
        mc.master.taskStartTimeout = TimeDuration::Seconds(1);
        mc.master.responseTimeout = TimeDuration::Seconds(1);
        outstation = server->AddOutstation("renewal-outstation", commands, DefaultOutstationApplication::Create(), oc);
        master = client->AddMaster("renewal-master", NullSOEHandler::Create(), DefaultMasterApplication::Create(), mc);
        enabled = RenewalTrace::Clock::now();
        REQUIRE(outstation->Enable());
        REQUIRE(master->Enable());
        REQUIRE(listener->WaitForState(ChannelState::OPEN, std::chrono::seconds(5)));
        Until([&] { return ReadyUsers(master->GetAuthenticationStatus()) && ReadyUsers(outstation->GetAuthenticationStatus()); });
    }
    ~RenewalTcpPair()
    {
        trace->Release(); // Also releases the worker after a fatal test assertion.
        masterManager.Shutdown();
        outManager.Shutdown();
    }
    template<class Predicate> void Until(Predicate predicate)
    {
        const auto deadline = RenewalTrace::Clock::now() + std::chrono::seconds(10);
        while (!predicate())
        {
            if (RenewalTrace::Clock::now() >= deadline)
            {
                INFO(Diagnostics());
                FAIL("Timed out waiting for renewal state");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    std::string Diagnostics()
    {
        std::ostringstream result;
        for (const auto& stack : {std::static_pointer_cast<IStack>(master), std::static_pointer_cast<IStack>(outstation)})
        {
            const auto status = stack->GetAuthenticationStatus();
            result << " changes=" << KeyChanges(status);
            for (size_t n = 0; n < status.size; ++n)
                result << " user=" << status.users[n].number << " ready=" << status.users[n].ready
                    << " exchanging=" << status.users[n].exchanging << " remaining=" << status.users[n].remainingMessages;
        }
        const auto wire = trace->Counts();
        result << " Master V4=" << wire.first << " V6=" << wire.second;
        return result.str();
    }
    void Read()
    {
        auto callback = std::make_shared<ScanResult>();
        auto future = callback->result.get_future();
        master->ScanClasses(ClassField::AllClasses(), NullSOEHandler::Create(), TaskConfig::With(callback));
        REQUIRE(future.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
        REQUIRE(future.get() == TaskCompletion::SUCCESS);
    }
    std::future<TaskCompletion> BeginControl()
    {
        auto result = std::make_shared<std::promise<TaskCompletion>>();
        auto future = result->get_future();
        auto config = TaskConfig::Default(); config.authenticationUser = 2;
        master->SelectAndOperate(ControlRelayOutputBlock(OperationType::LATCH_ON), 0,
            [result](const ICommandTaskResult& value) { result->set_value(value.summary); }, config);
        return future;
    }
    void Control()
    {
        auto future = BeginControl();
        REQUIRE(future.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
        REQUIRE(future.get() == TaskCompletion::SUCCESS);
    }
};
} // namespace

TEST_CASE("SecureAuthenticationTCP - default and configured counts replace each user's keys", "[sa-tcp][sa-renewal-tcp]")
{
    const auto count = GENERATE(1000u, 2000u);
    RenewalTcpPair pair(count);
    REQUIRE(pair.master->GetAuthenticationStatus().users[0].remainingMessages == count);
    REQUIRE(pair.master->GetAuthenticationStatus().users[1].remainingMessages == count);
    for (size_t user = 0; user < 2; ++user)
    {
        const auto beforeMaster = pair.master->GetAuthenticationStatus();
        const auto beforeOut = pair.outstation->GetAuthenticationStatus();
        const auto wire = pair.trace->Counts();
        const auto deadline = RenewalTrace::Clock::now() + std::chrono::seconds(120);
        size_t operations = 0;
        while (KeyChanges(pair.master->GetAuthenticationStatus()) == KeyChanges(beforeMaster))
        {
            CAPTURE(count, user, operations);
            REQUIRE(RenewalTrace::Clock::now() < deadline);
            REQUIRE(++operations <= 2 * count);
            const auto current = pair.master->GetAuthenticationStatus();
            if (!current.users[user].ready) break; // Wait for the actual replacement, not another application operation.
            const auto otherOutBudget = pair.outstation->GetAuthenticationStatus().users[0].remainingMessages;
            if (user == 0) pair.Read(); else pair.Control();
            if (user == 0)
            {
                REQUIRE(pair.master->GetAuthenticationStatus().users[1].remainingMessages == beforeMaster.users[1].remainingMessages);
                REQUIRE(pair.outstation->GetAuthenticationStatus().users[1].remainingMessages == beforeOut.users[1].remainingMessages);
            }
            else
            {
                // Common legitimately accounts for response authentication, but must not be reset/cancelled.
                const auto m = pair.master->GetAuthenticationStatus();
                const auto o = pair.outstation->GetAuthenticationStatus();
                REQUIRE(m.users[0].ready);
                REQUIRE(o.users[0].ready);
                REQUIRE(m.users[0].remainingMessages <= current.users[0].remainingMessages);
                REQUIRE(o.users[0].remainingMessages <= otherOutBudget);
            }
        }
        pair.Until([&] {
            const auto m = pair.master->GetAuthenticationStatus(), o = pair.outstation->GetAuthenticationStatus();
            return KeyChanges(m) > KeyChanges(beforeMaster) && KeyChanges(o) > KeyChanges(beforeOut)
                && ReadyUsers(m) && ReadyUsers(o);
        });
        REQUIRE(KeyChanges(pair.master->GetAuthenticationStatus()) == KeyChanges(beforeMaster) + 1);
        REQUIRE(KeyChanges(pair.outstation->GetAuthenticationStatus()) == KeyChanges(beforeOut) + 1);
        const auto installedTraffic = pair.trace->SinceConfirmation();
        const auto consumed = CountedASDUs(installedTraffic, user);
        CAPTURE(user, count, installedTraffic[0], installedTraffic[1], installedTraffic[2], installedTraffic[3], installedTraffic[4]);
        REQUIRE(consumed < count);
        const auto freshMaster = pair.master->GetAuthenticationStatus();
        const auto freshOut = pair.outstation->GetAuthenticationStatus();
        REQUIRE(freshMaster.users[user].ready);
        REQUIRE(freshOut.users[user].ready);
        REQUIRE(freshMaster.users[user].remainingMessages == count - consumed);
        REQUIRE(freshOut.users[user].remainingMessages == count - consumed);
        // Metadata must represent successful authentication, not rejected traffic
        // or renewal retries being used to explain an unexpected budget decrement.
        for (auto statistic : {SecurityStatistic::AUTHENTICATION_FAILURES, SecurityStatistic::AUTHORIZATION_FAILURES,
                               SecurityStatistic::REPLY_TIMEOUTS})
        {
            const auto index = static_cast<size_t>(statistic);
            REQUIRE(freshMaster.statistics[index] == beforeMaster.statistics[index]);
            REQUIRE(freshOut.statistics[index] == beforeOut.statistics[index]);
        }
        REQUIRE(pair.trace->Counts().first == wire.first + 1);
        REQUIRE(pair.trace->Counts().second == wire.second + 1);
        const auto selected = pair.commands->selected.load(), operated = pair.commands->operated.load();
        if (user == 0) pair.Read(); else pair.Control(); // Real authenticated traffic on replacement keys.
        const auto afterTraffic = pair.trace->SinceConfirmation();
        std::array<size_t, 5> delta{};
        for (size_t n = 0; n < delta.size(); ++n)
        {
            REQUIRE(afterTraffic[n] >= installedTraffic[n]);
            delta[n] = afterTraffic[n] - installedTraffic[n];
        }
        const auto used = CountedASDUs(delta, user);
        REQUIRE(used > 0);
        REQUIRE(used < freshMaster.users[user].remainingMessages);
        REQUIRE(delta[0] == delta[1]); // Repeated/rejected Challenges cannot explain an extra Reply charge.
        REQUIRE(delta[2] == delta[3]);
        if (user == 0) REQUIRE(delta[0] == 1); // One normal READ request.
        else
        {
            REQUIRE(pair.commands->selected.load() == selected + 1);
            REQUIRE(pair.commands->operated.load() == operated + 1);
            REQUIRE(delta[0] == (pair.commands->selected.load() - selected) + (pair.commands->operated.load() - operated));
        }
        const auto afterMaster = pair.master->GetAuthenticationStatus(), afterOut = pair.outstation->GetAuthenticationStatus();
        REQUIRE(KeyChanges(afterMaster) == KeyChanges(freshMaster));
        REQUIRE(KeyChanges(afterOut) == KeyChanges(freshOut));
        REQUIRE(afterMaster.users[user].remainingMessages == freshMaster.users[user].remainingMessages - used);
        REQUIRE(afterOut.users[user].remainingMessages == freshOut.users[user].remainingMessages - used);
    }
    pair.Read(); pair.Control();
}

TEST_CASE("SecureAuthenticationTCP - elapsed interval installs replacement keys", "[sa-tcp][sa-renewal-tcp]")
{
    const uint32_t interval = 3000;
    RenewalTcpPair pair(1000, interval);
    const auto m = pair.master->GetAuthenticationStatus(), o = pair.outstation->GetAuthenticationStatus();
    const auto wire = pair.trace->Counts();
    pair.Until([&] {
        const auto nextM = pair.master->GetAuthenticationStatus(), nextO = pair.outstation->GetAuthenticationStatus();
        return KeyChanges(nextM) >= KeyChanges(m) + 2 && KeyChanges(nextO) >= KeyChanges(o) + 2
            && ReadyUsers(nextM) && ReadyUsers(nextO);
    });
    REQUIRE(pair.trace->Counts().first >= wire.first + 2);
    REQUIRE(pair.trace->Counts().second >= wire.second + 2);
    REQUIRE(pair.trace->LastRequest() >= pair.enabled + std::chrono::milliseconds(interval));
    REQUIRE(pair.commands->operated.load() == 0);
    pair.Read(); pair.Control();
}

TEST_CASE("SecureAuthenticationTCP - interrupted renewal cannot authorize and reconnect negotiates fresh keys", "[sa-tcp][sa-renewal-tcp]")
{
    RenewalTcpPair pair(1000, 3000);
    const auto beforeMaster = pair.master->GetAuthenticationStatus();
    const auto beforeOut = pair.outstation->GetAuthenticationStatus();
    pair.trace->Arm();
    REQUIRE(pair.trace->WaitHeld()); // Next timed renewal has reached V6 generation, before lower-layer TX.
    // Never synchronously query the gated Master worker. The peer has its own worker.
    const auto pendingOut = pair.outstation->GetAuthenticationStatus();
    REQUIRE_FALSE((pendingOut.users[0].ready && pendingOut.users[1].ready));
    REQUIRE(KeyChanges(pendingOut) == KeyChanges(beforeOut));
    auto denied = pair.BeginControl();
    pair.server->Shutdown();
    pair.trace->Release();
    REQUIRE(pair.listener->WaitForState(ChannelState::CLOSED, std::chrono::seconds(5)));
    REQUIRE(denied.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    REQUIRE(denied.get() != TaskCompletion::SUCCESS);
    REQUIRE(pair.commands->selected.load() == 0);
    REQUIRE(pair.commands->operated.load() == 0);
    REQUIRE_FALSE(pair.trace->Expired());
    REQUIRE_FALSE(pair.master->GetAuthenticationStatus().users[0].ready);
    REQUIRE(KeyChanges(pair.master->GetAuthenticationStatus()) == KeyChanges(beforeMaster));
    REQUIRE(KeyChanges(pair.outstation->GetAuthenticationStatus()) == KeyChanges(beforeOut));
    pair.server = pair.outManager.AddTCPServer("renewal-restarted-server", levels::NORMAL,
        ServerAcceptMode::CloseExisting, IPEndpoint::Localhost(pair.port), nullptr);
    pair.outstation = pair.server->AddOutstation("renewal-outstation", pair.commands, DefaultOutstationApplication::Create(), pair.oc);
    REQUIRE(pair.outstation->Enable());
    REQUIRE(pair.listener->WaitForState(ChannelState::OPEN, std::chrono::seconds(5)));
    pair.Until([&] {
        const auto m = pair.master->GetAuthenticationStatus(), o = pair.outstation->GetAuthenticationStatus();
        return ReadyUsers(m) && ReadyUsers(o) && KeyChanges(m) >= KeyChanges(beforeMaster) + 2 && KeyChanges(o) >= 2;
    });
    REQUIRE(KeyChanges(pair.outstation->GetAuthenticationStatus()) == 2); // No abandoned V6 installed on the new association.
    pair.Read(); pair.Control();
    REQUIRE(pair.commands->operated.load() == 1);
}
