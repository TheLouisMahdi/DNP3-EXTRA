// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "crypto/CryptoProvider.h"
#include "mocks/NullSOEHandler.h"
#include "mocks/QueuedChannelListener.h"
#include "dnp3mocks/RemoteUpdateKeyCredentials.h"
#include "dnp3mocks/AsymmetricUpdateKeyCredentials.h"

#include <opendnp3/DNP3Manager.h>
#include <opendnp3/master/DefaultMasterApplication.h>
#include <opendnp3/outstation/DefaultOutstationApplication.h>
#include <opendnp3/outstation/SimpleCommandHandler.h>

#include <catch.hpp>

#include <array>
#include <atomic>
#include <deque>
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
    TcpCredentials()
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
        if (association != 7 || user < 1 || user > 2 || !output || capacity != keyLength)
            return false;
        std::copy_n(keys[user - 1].begin(), capacity, output);
        lifetime = 3600000;
        return true;
    }
};
class TcpPolicy final : public IAuthenticationAuthorization
{
public:
    bool IsAuthorized(
        uint16_t association, uint16_t user, uint8_t function, const uint8_t* apdu, size_t size) const override
    {
        return association == 7 && apdu && size >= 2 && apdu[1] == function
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
    auto outstation = server->AddOutstation("sa-outstation", commands, DefaultOutstationApplication::Create(), oc);
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
    manager.Shutdown();
}

TEST_CASE("SecureAuthenticationTCP - remote update installs a key used by native commands and reconnect", "[sa-tcp][remote-update-tcp]")
{
    using namespace remote_update_test;
    auto mc = std::make_shared<RemoteCredentials>();
    auto oc = std::make_shared<RemoteCredentials>();
    auto policy = std::make_shared<RemotePolicy>();
    const bool asymmetric = GENERATE(false, true);
    std::shared_ptr<RemoteAuthority> authority = asymmetric ? std::make_shared<AsymmetricAuthority>() : std::make_shared<RemoteAuthority>();
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
    outConfig.outstation.params.authentication = RemoteSettings(oc, policy, authority, 2);
    outConfig.outstation.params.allowUnsolicited = false;
    MasterStackConfig masterConfig;
    masterConfig.link.LocalAddr = 1;
    masterConfig.link.RemoteAddr = 10;
    masterConfig.master.disableUnsolOnStartup = false;
    masterConfig.master.startupIntegrityClassMask = ClassField::None();
    masterConfig.master.unsolClassMask = ClassField::None();
    masterConfig.master.ignoreRestartIIN = true;
    masterConfig.master.authentication = RemoteSettings(mc, policy, authority, 2);
    masterConfig.master.authentication.updateKeyTrust.reset();
    auto outstation = server->AddOutstation("remote-sa-outstation", commands, DefaultOutstationApplication::Create(), outConfig);
    auto master = client->AddMaster("remote-sa-master", NullSOEHandler::Create(), DefaultMasterApplication::Create(), masterConfig);
    REQUIRE(outstation);
    REQUIRE(master);
    REQUIRE(outstation->Enable());
    REQUIRE(master->Enable());
    REQUIRE(listener->WaitForState(ChannelState::OPEN, std::chrono::seconds(5)));
    auto request = authority->Status(3, 1, "A");
    request.source = authority;
    auto completion = std::make_shared<ScanResult>();
    auto future = completion->result.get_future();
    REQUIRE(master->ChangeUpdateKey(request, TaskConfig::With(completion)));
    REQUIRE(future.wait_for(std::chrono::seconds(10)) == std::future_status::ready);
    INFO(trace->Snapshot());
    REQUIRE(future.get() == TaskCompletion::SUCCESS);
    REQUIRE(mc->users[1].updateKey == authority->nextKey);
    REQUIRE(oc->users[1].updateKey == authority->nextKey);
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
    server->Shutdown();
    REQUIRE(listener->WaitForState(ChannelState::CLOSED, std::chrono::seconds(5)));
    server = manager.AddTCPServer("remote-sa-restarted-server", levels::NORMAL, ServerAcceptMode::CloseExisting,
        IPEndpoint::Localhost(port), nullptr);
    outstation = server->AddOutstation("remote-sa-restarted-outstation", commands, DefaultOutstationApplication::Create(), outConfig);
    REQUIRE(outstation->Enable());
    REQUIRE(listener->WaitForState(ChannelState::OPEN, std::chrono::seconds(5)));
    control();
    REQUIRE(commands->operated.load() == 3);
    manager.Shutdown();
}
