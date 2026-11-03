#include <opendnp3/ConsoleLogger.h>
#include "Security.h"
#include <opendnp3/app/SecurityStat.h>
#include <opendnp3/app/DeviceAttribute.h>
#include <opendnp3/master/ITaskCallback.h>
#include <opendnp3/channel/TLSConfig.h>
#include <opendnp3/outstation/IUpdateHandler.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/channel/IChannelListener.h>
#include <opendnp3/gen/CommandPointState.h>
#include <opendnp3/gen/CommandStatus.h>
#include <opendnp3/gen/DoubleBit.h>
#include <opendnp3/gen/GroupVariation.h>
#include <opendnp3/gen/TaskCompletion.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/master/IMasterApplication.h>
#include <opendnp3/master/ISOEHandler.h>
#include <opendnp3/master/ICommandTaskResult.h>
#include <opendnp3/outstation/DefaultOutstationApplication.h>
#include <opendnp3/outstation/SimpleCommandHandler.h>
#include <opendnp3/outstation/UpdateBuilder.h>

#include <cstring>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <initializer_list>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
using namespace opendnp3;

std::atomic<bool> stopping{false};

class Console
{
public:
    static void Print(const std::string& label, const std::string& message)
    {
        std::lock_guard<std::mutex> lock(Mutex());
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - Start()).count();
        std::cout << '\n' << '[' << std::setw(7) << elapsed << "ms] [" << label << "] " << message << '\n';
        std::cout.flush();
    }

private:
    static std::mutex& Mutex()
    {
        static std::mutex mutex;
        return mutex;
    }

    static const std::chrono::steady_clock::time_point& Start()
    {
        static const auto start = std::chrono::steady_clock::now();
        return start;
    }
};

std::vector<std::string> Words(const std::string& line)
{
    std::istringstream stream(line);
    std::vector<std::string> result;
    std::string word;
    while (stream >> word)
    {
        result.push_back(word);
    }
    return result;
}

bool Unsigned(const std::string& text, uint32_t maximum, uint32_t& result)
{
    if (text.empty() || text[0] == '-') return false;
    try
    {
        std::size_t end = 0;
        const auto number = std::stoull(text, &end, 10);
        if (end != text.size() || number > maximum) return false;
        result = static_cast<uint32_t>(number);
        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
}

bool Floating(const std::string& text, double& result)
{
    try
    {
        std::size_t end = 0;
        const double number = std::stod(text, &end);
        if (end != text.size() || !std::isfinite(number)) return false;
        result = number;
        return true;
    }
    catch (const std::exception&)
    {
        return false;
    }
}

bool Is(const std::vector<std::string>& words, std::initializer_list<const char*> expected)
{
    if (words.size() != expected.size()) return false;
    auto next = words.begin();
    for (const auto* word : expected)
    {
        if (*next++ != word) return false;
    }
    return true;
}

std::string ValueText(bool value) { return value ? "ON" : "OFF"; }
std::string ValueText(DoubleBit value) { return DoubleBitSpec::to_string(value); }

template<class T> std::string ValueText(const T& value)
{
    std::ostringstream stream;
    stream << value;
    return stream.str();
}

std::string HeaderText(const HeaderInfo& info)
{
    std::ostringstream stream;
    stream << GroupVariationSpec::to_string(info.gv)
           << (info.isEventVariation ? " EVENT" : " STATIC");
    return stream.str();
}

class ChannelObserver final : public IChannelListener
{
public:
    void OnStateChange(ChannelState next) override
    {
        state.store(next);
        Console::Print("LINK", ChannelStateSpec::to_string(next));
    }

    ChannelState Current() const { return state.load(); }

private:
    std::atomic<ChannelState> state{ChannelState::CLOSED};
};

LogLevels LogFilter(const diagnostic::Options& options, bool trace)
{
    if (!trace) return levels::NORMAL;
    return options.auth == "compat" ? levels::NORMAL | levels::ALL_COMMS
                                    : levels::NORMAL | flags::APP_HEADER_TX | flags::APP_OBJECT_TX;
}

class DiagnosticLogger final : public ILogHandler
{
    const bool secure;
    const std::shared_ptr<ILogHandler> normal = ConsoleLogger::Create();
public:
    explicit DiagnosticLogger(bool sa) : secure(sa) {}
    void log(ModuleId module, const char* id, LogLevel level, const char* location, const char* message) override
    {
        if (!secure || levels::NORMAL.is_set(level)) { normal->log(module, id, level, location, message); return; }
        // Native parser metadata is "120,NNN - ...". Only print the numeric
        // object identity and direction, never the original diagnostic text.
        if ((level == flags::APP_OBJECT_RX || level == flags::APP_OBJECT_TX)
            && std::strlen(message) >= 8 && std::strncmp(message, "120,", 4) == 0 && message[7] == ' '
            && message[4] == '0' && message[5] >= '0' && message[5] <= '1'
            && message[6] >= '0' && message[6] <= '9')
            Console::Print("SA-OBJECT", std::string(level == flags::APP_OBJECT_RX ? "RX G120V" : "TX G120V")
                + std::to_string(10 * (message[5] - '0') + message[6] - '0'));
    }
};

class MasterObserver final : public IMasterApplication
{
public:
    UTCTimestamp Now() override
    {
        const auto time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return UTCTimestamp(static_cast<uint64_t>(time));
    }

    void OnReceiveIIN(const IINField& iin) override
    {
        if (!iin.Any()) return;
        std::ostringstream stream;
        stream << "IIN=" << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<unsigned>(iin.LSB) << ' '
               << std::setw(2) << static_cast<unsigned>(iin.MSB) << std::dec;
        if (iin.HasRequestError()) stream << " REQUEST_ERROR";
        if (iin.IsSet(IINBit::NEED_TIME)) stream << " NEED_TIME";
        Console::Print(iin.HasRequestError() ? "WARN" : "RX", stream.str());
    }

    void OnTaskComplete(const TaskInfo& info) override
    {
        if (info.type != MasterTaskType::USER_TASK && info.result == TaskCompletion::SUCCESS) return;
        Console::Print(info.result == TaskCompletion::SUCCESS ? "OK" : "WARN",
                       std::string("Task ") + MasterTaskTypeSpec::to_string(info.type)
                       + ": " + TaskCompletionSpec::to_string(info.result));
    }
};

class SoePrinter final : public ISOEHandler
{
public:
    void BeginFragment(const ResponseInfo& info) override
    {
        Console::Print("RX", info.unsolicited ? "Unsolicited response fragment" : "Response fragment");
    }

    void EndFragment(const ResponseInfo&) override {}

    void Process(const HeaderInfo& info, const ICollection<Indexed<SecurityStat>>& values) override
    {
        values.ForeachItem([&](const Indexed<SecurityStat>& item) {
            Console::Print("STAT", HeaderText(info) + " index=" + std::to_string(item.index)
                + " association=" + std::to_string(item.value.associationId)
                + " value=" + std::to_string(item.value.value)
                + " flags=" + std::to_string(item.value.flags.value)
                + (info.tsquality == TimestampQuality::INVALID ? " untimed" : " time=" + std::to_string(item.value.time.value)));
        });
    }
    void Process(const HeaderInfo& info, const ICollection<Indexed<DeviceAttribute>>& values) override
    {
        values.ForeachItem([&](const Indexed<DeviceAttribute>& item) {
            uint64_t value = 0;
            const bool numeric = item.value.GetUnsigned(value);
            Console::Print("ATTR", HeaderText(info) + " set=" + std::to_string(item.index)
                + " type=" + std::to_string(item.value.dataType)
                + (numeric ? " value=" + std::to_string(value) : " list-bytes=" + std::to_string(item.value.value.length())));
            if (!numeric && (item.value.dataType == 254 || item.value.dataType == 255))
            {
                const uint8_t* data = item.value.value;
                for (size_t n = 0; n + 1 < item.value.value.length(); n += 2)
                    Console::Print("ATTR", "variation=" + std::to_string(data[n]) + " properties=" + std::to_string(data[n + 1]));
            }
        });
    }

    template<class T>
    void Measurements(const HeaderInfo& info, const ICollection<Indexed<T>>& values, const char* type)
    {
        values.ForeachItem([&](const Indexed<T>& item) {
            std::ostringstream stream;
            stream << HeaderText(info) << ' ' << type << '[' << item.index << "]="
                   << ValueText(item.value.value);
            if (info.flagsValid)
            {
                stream << " flags=0x" << std::hex << std::setw(2) << std::setfill('0')
                       << static_cast<unsigned>(item.value.flags.value) << std::dec;
            }
            if (info.tsquality != TimestampQuality::INVALID)
            {
                stream << " time=" << item.value.time.value << "ms";
            }
            Console::Print("RX", stream.str());
        });
    }

    void Process(const HeaderInfo& h, const ICollection<Indexed<Binary>>& v) override { Measurements(h, v, "Binary"); }
    void Process(const HeaderInfo& h, const ICollection<Indexed<DoubleBitBinary>>& v) override { Measurements(h, v, "DoubleBit"); }
    void Process(const HeaderInfo& h, const ICollection<Indexed<Analog>>& v) override { Measurements(h, v, "Analog"); }
    void Process(const HeaderInfo& h, const ICollection<Indexed<Counter>>& v) override { Measurements(h, v, "Counter"); }
    void Process(const HeaderInfo& h, const ICollection<Indexed<FrozenCounter>>& v) override { Measurements(h, v, "FrozenCounter"); }
    void Process(const HeaderInfo& h, const ICollection<Indexed<BinaryOutputStatus>>& v) override { Measurements(h, v, "BinaryOutput"); }
    void Process(const HeaderInfo& h, const ICollection<Indexed<AnalogOutputStatus>>& v) override { Measurements(h, v, "AnalogOutput"); }

    void Process(const HeaderInfo& h, const ICollection<Indexed<OctetString>>& values) override
    {
        values.ForeachItem([&](const Indexed<OctetString>& item) {
            std::ostringstream stream;
            stream << HeaderText(h) << " OctetString[" << item.index << "]=";
            const auto data = item.value.ToBuffer();
            for (std::size_t i = 0; i < data.length; ++i)
                stream << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(data.data[i]);
            Console::Print("RX", stream.str());
        });
    }

    void Process(const HeaderInfo& h, const ICollection<Indexed<TimeAndInterval>>& values) override
    {
        values.ForeachItem([&](const Indexed<TimeAndInterval>& item) {
            std::ostringstream stream;
            stream << HeaderText(h) << " TimeAndInterval[" << item.index << "] time="
                   << item.value.time.value << "ms interval=" << item.value.interval
                   << " units=" << static_cast<unsigned>(item.value.units);
            Console::Print("RX", stream.str());
        });
    }

    void Process(const HeaderInfo& h, const ICollection<Indexed<BinaryCommandEvent>>& values) override
    {
        values.ForeachItem([&](const Indexed<BinaryCommandEvent>& item) {
            std::ostringstream stream;
            stream << HeaderText(h) << " BinaryCommandEvent[" << item.index << "]="
                   << ValueText(item.value.value) << " status=" << CommandStatusSpec::to_string(item.value.status);
            Console::Print("RX", stream.str());
        });
    }

    void Process(const HeaderInfo& h, const ICollection<Indexed<AnalogCommandEvent>>& values) override
    {
        values.ForeachItem([&](const Indexed<AnalogCommandEvent>& item) {
            std::ostringstream stream;
            stream << HeaderText(h) << " AnalogCommandEvent[" << item.index << "]="
                   << item.value.value << " status=" << CommandStatusSpec::to_string(item.value.status);
            Console::Print("RX", stream.str());
        });
    }

    void Process(const HeaderInfo&, const ICollection<DNPTime>& values) override
    {
        values.ForeachItem([](const DNPTime& value) {
            Console::Print("RX", "Absolute time=" + std::to_string(value.value) + "ms");
        });
    }
};

bool TraceOption(const std::vector<std::string>& words, bool& enabled)
{
    if (Is(words, {"trace", "on"})) { enabled = true; return true; }
    if (Is(words, {"trace", "off"})) { enabled = false; return true; }
    return false;
}

void CommandResult(const std::string& label, const ICommandTaskResult& result)
{
    result.ForeachItem([&](const CommandPointResult& point) {
        std::ostringstream stream;
        stream << label << '[' << point.index << "] state=" << CommandPointStateSpec::to_string(point.state);
        if (point.state == CommandPointState::SUCCESS || point.state == CommandPointState::SELECT_FAIL)
            stream << " status=" << CommandStatusSpec::to_string(point.status);
        stream << " (application handler may be simulated)";
        Console::Print("RX", stream.str());
    });
    Console::Print("RESULT", label + " task=" + TaskCompletionSpec::to_string(result.summary));
}

class SimulatedCommands final : public SimpleCommandHandler
{
public:
    std::atomic<uint32_t> executions{0};
    SimulatedCommands() : SimpleCommandHandler(CommandStatus::SUCCESS) {}
    template<class T> CommandStatus SelectValue(const T&, uint16_t index)
    { return index < 10 ? CommandStatus::SUCCESS : CommandStatus::OUT_OF_RANGE; }
    template<class T> CommandStatus OperateValue(const T& value, uint16_t index, IUpdateHandler& handler)
    {
        if (index >= 10) return CommandStatus::OUT_OF_RANGE;
        handler.Update(AnalogOutputStatus(value.value), index);
        Console::Print("EXECUTED", "AnalogOutput[" + std::to_string(index) + "]=" + ValueText(value.value)
            + " simulated count=" + std::to_string(++executions));
        return CommandStatus::SUCCESS;
    }
    CommandStatus OperateValue(const ControlRelayOutputBlock& value, uint16_t index, IUpdateHandler& handler)
    {
        if (index >= 10) return CommandStatus::OUT_OF_RANGE;
        handler.Update(BinaryOutputStatus(value.opType == OperationType::LATCH_ON), index);
        Console::Print("EXECUTED", "CROB[" + std::to_string(index) + "] simulated count=" + std::to_string(++executions));
        return CommandStatus::SUCCESS;
    }
#define CLI_COMMAND(T) \
    CommandStatus Select(const T& c, uint16_t i) override { return SelectValue(c, i); } \
    CommandStatus Operate(const T& c, uint16_t i, IUpdateHandler& h, OperateType) override { return OperateValue(c, i, h); }
    CLI_COMMAND(ControlRelayOutputBlock)
    CLI_COMMAND(AnalogOutputInt16)
    CLI_COMMAND(AnalogOutputInt32)
    CLI_COMMAND(AnalogOutputFloat32)
    CLI_COMMAND(AnalogOutputDouble64)
#undef CLI_COMMAND
};
class TaskPrinter final : public ITaskCallback
{
    const std::string label;
public:
    explicit TaskPrinter(std::string name) : label(std::move(name)) {}
    void OnStart() override { Console::Print("TASK", label + " START"); }
    void OnComplete(TaskCompletion result) override { Console::Print("TASK", label + " " + TaskCompletionSpec::to_string(result)); }
    void OnDestroyed() override {}
};
class Errors final : public IAuthenticationErrorObserver
{
public:
    void OnErrorReceived(uint16_t a, uint16_t u, uint32_t s, uint8_t c, bool discarded) override
    { Console::Print("SA-ERROR-RX", "association=" + std::to_string(a) + " user=" + std::to_string(u)
        + " sequence=" + std::to_string(s) + " code=" + std::to_string(c) + " discarded-owner=" + std::to_string(discarded)); }
    void OnAuthorizationFailure(uint16_t a, uint16_t u, uint32_t) override
    { Console::Print("DENIED", "association=" + std::to_string(a) + " user=" + std::to_string(u)); }
    void OnErrorSent(uint16_t a, uint16_t u, uint32_t, uint8_t c) override
    { Console::Print("SA-ERROR-TX", "association=" + std::to_string(a) + " user=" + std::to_string(u) + " code=" + std::to_string(c)); }
};
void AuthStatus(const std::shared_ptr<IStack>& stack, const diagnostic::Options& o)
{
    const auto status = stack->GetAuthenticationStatus();
    Console::Print("SA", "mode=" + o.auth + " selected-user=" + std::to_string(o.user)
        + " association=" + std::to_string(status.association) + " update-busy=" + std::to_string(status.updateKeyBusy)
        + " update-owner=" + std::to_string(status.updateKeyOwner));
    if (!status.available) { Console::Print("SA", "SA DISABLED (compatibility) or diagnostics unavailable"); return; }
    for (size_t n = 0; n < status.size; ++n)
        Console::Print("SESSION", "user=" + std::to_string(status.users[n].number)
            + " ready=" + std::to_string(status.users[n].ready)
            + " exchanging=" + std::to_string(status.users[n].exchanging)
            + " remaining=" + std::to_string(status.users[n].remainingMessages));
    for (size_t n = 0; n < status.statistics.size(); ++n)
        Console::Print("LOCAL-STAT", "index=" + std::to_string(n) + " value=" + std::to_string(status.statistics[n]));
}
std::shared_ptr<IChannel> MakeChannel(DNP3Manager& manager, const diagnostic::Options& o,
                                    const std::shared_ptr<ChannelObserver>& observer, bool master)
{
    // Protocol object/hex logs are deliberately excluded in secure mode. They
    // may contain MACs, ciphertext or protected application bytes.
    const auto logs = LogFilter(o, o.trace);
    if (o.tls)
    {
#ifdef CLI_TLS
        if (o.ca.empty() || o.cert.empty() || o.key.empty() || o.peerName.empty())
            throw std::runtime_error("TLS requires --ca --cert --key --peer-name");
        if (o.tlsVersion != "1.2" && o.tlsVersion != "1.3" && o.tlsVersion != "both") throw std::runtime_error("TLS version must be 1.2/1.3/both");
        TLSConfig config(o.ca, o.cert, o.key, false, false, o.tlsVersion != "1.3", o.tlsVersion != "1.2", o.ciphers);
        config.peerName = o.peerName; config.cipherSuites = o.suites;
        if (master) return manager.AddTLSClient("cli-master", logs, ChannelRetry::Default(), {IPEndpoint(o.host, o.port)}, "0.0.0.0", config, observer);
        return manager.AddTLSServer("cli-outstation", logs, ServerAcceptMode::CloseExisting, IPEndpoint(o.host, o.port), config, observer);
#else
        throw std::runtime_error("TLS unavailable: build with DNP3_TLS=ON");
#endif
    }
    if (master) return manager.AddTCPClient("cli-master", logs, ChannelRetry::Default(), {IPEndpoint(o.host, o.port)}, "0.0.0.0", observer);
    return manager.AddTCPServer("cli-outstation", logs, ServerAcceptMode::CloseExisting, IPEndpoint(o.host, o.port), observer);
}
void RuntimeInfo(const diagnostic::Options& o)
{
    Console::Print("INFO", "DNP3-EXTRA " + o.role + " | " + o.host + ":" + std::to_string(o.port)
        + " local=" + std::to_string(o.local) + " remote=" + std::to_string(o.remote) + " auth=" + o.auth + (o.tls ? " TLS" : " TCP"));
    if (o.auth == "compat") Console::Print("SA", "SA DISABLED: explicit compatibility diagnostic mode");
    if (o.testOnly) Console::Print("INFO", "TEST-ONLY localhost credentials/authority; not a production provisioning service");
}
void Help(bool master)
{
    if (master)
    {
        Console::Print("HELP", "read <g> <v> [start stop] | scan integrity|class0|class1|class2|class3 | attr 209|210|254|255");
        Console::Print("HELP", "crob <index> on|off [sbo|direct] | analog <v:1..4> <index> <value> [sbo|direct]");
        Console::Print("HELP", "user <number> | ruk add|change|delete <Common|operator|engineer|guest> <scs> <role> <expiry-days>");
        Console::Print("HELP", "ruk verify|change-key <name> | stats | events | assign <group> <class:0..3> <start> <stop>");
        Console::Print("HELP", "unsol on|off | restart cold|warm | time (G50V1 READ)");
    }
    else Console::Print("HELP", "set binary|double|analog|counter <index:0..9> <value> [force|suppress] | show | restart (restart IIN)");
    Console::Print("HELP", "status | auth | users | reconnect | trace on|off (metadata only in SA) | help | quit");
}
uint32_t RequiredNumber(const std::string& value, uint32_t maximum)
{
    uint32_t result = 0;
    if (!Unsigned(value, maximum, result)) throw std::runtime_error("Invalid unsigned number");
    return result;
}
int RunMaster(diagnostic::Options o)
{
    RuntimeInfo(o);
    auto auth = diagnostic::Authentication(o, true); auth.errorObserver = std::make_shared<Errors>();
    DNP3Manager manager(1, std::make_shared<DiagnosticLogger>(o.auth != "compat"));
    auto observer = std::make_shared<ChannelObserver>();
    auto channel = MakeChannel(manager, o, observer, true);
    MasterStackConfig config;
    config.master.authentication = auth;
    config.master.responseTimeout = TimeDuration::Milliseconds(o.responseMs);
    config.master.disableUnsolOnStartup = true;
    config.master.unsolClassMask = ClassField::None(); // Enable only on the explicit CLI command.
    config.master.startupIntegrityClassMask = ClassField::AllClasses();
    config.master.timeSyncMode = TimeSyncMode::NonLAN;
    config.link.LocalAddr = o.local; config.link.RemoteAddr = o.remote;
    auto soe = std::make_shared<SoePrinter>();
    auto master = channel->AddMaster("cli-master-stack", soe, std::make_shared<MasterObserver>(), config);
    if (!master || !master->Enable()) throw std::runtime_error("Master could not enable");
    Help(true);
    std::string line;
    while (!stopping.load() && std::getline(std::cin, line))
    {
        const auto w = Words(line);
        if (w.empty()) continue;
        if (Is(w, {"quit"}) || Is(w, {"exit"})) break;
        try
        {
            if (Is(w, {"help"})) { Help(true); continue; }
            if (Is(w, {"status"})) { Console::Print("INFO", "channel=" + std::string(ChannelStateSpec::to_string(observer->Current()))); AuthStatus(master, o); continue; }
            if (Is(w, {"auth"})) { AuthStatus(master, o); continue; }
            if (Is(w, {"users"})) { diagnostic::PrintUsers(o, true); continue; }
            if (Is(w, {"reconnect"})) { master->Disable(); master->Enable(); continue; }
            bool trace = false;
            if (TraceOption(w, trace)) { channel->SetLogFilters(LogFilter(o, trace)); master->SetLogFilters(LogFilter(o, trace)); continue; }
            if (w.size() == 2 && w[0] == "user")
            {
                const auto user = RequiredNumber(w[1], 65535);
                if (!user) throw std::runtime_error("User zero is reserved");
                o.user = static_cast<uint16_t>(user); continue;
            }
            auto task = TaskConfig::With(std::make_shared<TaskPrinter>(w[0])); task.authenticationUser = o.user;
            auto onResult = [name = w[0]](const ICommandTaskResult& result) { CommandResult(name, result); };
            if (w[0] == "read" && (w.size() == 3 || w.size() == 5))
            {
                const GroupVariationID gv(static_cast<uint8_t>(RequiredNumber(w[1], 255)), static_cast<uint8_t>(RequiredNumber(w[2], 255)));
                if (w.size() == 3) master->ScanAllObjects(gv, soe, task);
                else
                {
                    const auto start = RequiredNumber(w[3], 65535), stop = RequiredNumber(w[4], 65535);
                    if (start > stop) throw std::runtime_error("Range start exceeds stop");
                    if (gv.group == 0 && stop <= 255)
                        master->Scan({Header::Range8(gv.group, gv.variation, static_cast<uint8_t>(start), static_cast<uint8_t>(stop))}, soe, task);
                    else master->ScanRange(gv, static_cast<uint16_t>(start), static_cast<uint16_t>(stop), soe, task);
                }
            }
            else if (w.size() == 2 && w[0] == "attr")
                master->Scan({Header::Range8(0, static_cast<uint8_t>(RequiredNumber(w[1], 255)), 0, 0)}, soe, task);
            else if (w.size() == 2 && w[0] == "scan")
            {
                const auto field = w[1] == "integrity" ? ClassField::AllClasses() : w[1] == "class0" ? ClassField(ClassField::CLASS_0)
                    : w[1] == "class1" ? ClassField(ClassField::CLASS_1) : w[1] == "class2" ? ClassField(ClassField::CLASS_2)
                    : w[1] == "class3" ? ClassField(ClassField::CLASS_3) : ClassField::None();
                if (field.IsEmpty()) throw std::runtime_error("Unknown scan class");
                master->ScanClasses(field, soe, task);
            }
            else if (Is(w, {"stats"})) master->ScanRange(GroupVariationID(121, 1), 0, 17, soe, task);
            else if (Is(w, {"events"})) master->ScanAllObjects(GroupVariationID(122, 0), soe, task);
            else if (w[0] == "crob" && (w.size() == 3 || w.size() == 4))
            {
                if (w[2] != "on" && w[2] != "off") throw std::runtime_error("Expected on/off");
                const auto index = static_cast<uint16_t>(RequiredNumber(w[1], 65535));
                const ControlRelayOutputBlock command(w[2] == "on" ? OperationType::LATCH_ON : OperationType::LATCH_OFF);
                if (w.size() == 4 && w[3] == "direct") master->DirectOperate(command, index, onResult, task);
                else if (w.size() == 3 || w[3] == "sbo") master->SelectAndOperate(command, index, onResult, task);
                else throw std::runtime_error("Expected sbo/direct");
            }
            else if (w[0] == "analog" && (w.size() == 4 || w.size() == 5))
            {
                const auto variation = RequiredNumber(w[1], 4), index = RequiredNumber(w[2], 65535);
                double value = 0;
                if (!Floating(w[3], value) || variation == 0) throw std::runtime_error("Invalid analog command");
                const bool direct = w.size() == 5 && w[4] == "direct";
                if (w.size() == 5 && !direct && w[4] != "sbo") throw std::runtime_error("Expected sbo/direct");
                auto send = [&](const auto& command) {
                    if (direct) master->DirectOperate(command, static_cast<uint16_t>(index), onResult, task);
                    else master->SelectAndOperate(command, static_cast<uint16_t>(index), onResult, task);
                };
                if (variation <= 2 && (value != std::trunc(value) || value < (variation == 1 ? -2147483648.0 : -32768.0)
                    || value > (variation == 1 ? 2147483647.0 : 32767.0))) throw std::runtime_error("Integer command out of range");
                if (variation == 1) send(AnalogOutputInt32(static_cast<int32_t>(value)));
                if (variation == 2) send(AnalogOutputInt16(static_cast<int16_t>(value)));
                if (variation == 3) { if (std::abs(value) > std::numeric_limits<float>::max()) throw std::runtime_error("Float overflow"); send(AnalogOutputFloat32(static_cast<float>(value))); }
                if (variation == 4) send(AnalogOutputDouble64(value));
            }
            else if (w[0] == "ruk" && (w.size() == 3 || w.size() == 6))
            {
                auto request = diagnostic::AuthorizedRequest(o, w[1], w[2], w.size() == 6 ? RequiredNumber(w[3], 0xFFFFFFFFu) : 0,
                    w.size() == 6 ? static_cast<uint16_t>(RequiredNumber(w[4], 65535)) : 0,
                    w.size() == 6 ? static_cast<uint16_t>(RequiredNumber(w[5], 65535)) : 0);
                if (!master->ChangeUpdateKey(request, task)) throw std::runtime_error("Remote key task rejected locally");
            }
            else if (w[0] == "assign" && w.size() == 5)
            {
                const auto group = RequiredNumber(w[1], 255), clazz = RequiredNumber(w[2], 3);
                const auto start = RequiredNumber(w[3], 65535), stop = RequiredNumber(w[4], 65535);
                if (start > stop) throw std::runtime_error("Invalid class assignment range");
                master->PerformFunction("assign", FunctionCode::ASSIGN_CLASS, {Header::AllObjects(60, static_cast<uint8_t>(clazz + 1)),
                    Header::Range16(static_cast<uint8_t>(group), 0, static_cast<uint16_t>(start), static_cast<uint16_t>(stop))}, task);
            }
            else if (w[0] == "unsol" && w.size() == 2 && (w[1] == "on" || w[1] == "off"))
                master->PerformFunction("unsol", w[1] == "on" ? FunctionCode::ENABLE_UNSOLICITED : FunctionCode::DISABLE_UNSOLICITED,
                    {Header::AllObjects(60, 2), Header::AllObjects(60, 3), Header::AllObjects(60, 4)}, task);
            else if (w[0] == "restart" && w.size() == 2 && (w[1] == "cold" || w[1] == "warm"))
                master->Restart(w[1] == "cold" ? RestartType::COLD : RestartType::WARM, [](const RestartOperationResult& result) {
                    Console::Print("RESTART", TaskCompletionSpec::to_string(result.summary)); }, task);
            else if (Is(w, {"time"})) master->Scan({Header::Count8(50, 1, 1)}, soe, task);
            else { Console::Print("ERROR", "Unknown command. Type help."); continue; }
            Console::Print("SUBMITTED", line + " (completion pending)");
        }
        catch (const std::exception& e) { Console::Print("ERROR", e.what()); }
    }
    manager.Shutdown();
    Console::Print("SHUTDOWN", "Master stopped"); return 0;
}
struct LocalPoints
{
    bool binary = false;
    DoubleBit doubleBit = DoubleBit::DETERMINED_OFF;
    double analog = 0;
    uint32_t counter = 0;
};
class OutstationApplication final : public DefaultOutstationApplication
{
    mutable std::mutex mutex;
public:
    DNPTime Now() override { std::lock_guard<std::mutex> lock(mutex); return DefaultOutstationApplication::Now(); }
    bool WriteAbsoluteTime(const UTCTimestamp& time) override
    { std::lock_guard<std::mutex> lock(mutex); return DefaultOutstationApplication::WriteAbsoluteTime(time); }
    ApplicationIIN GetApplicationIIN() const override
    { std::lock_guard<std::mutex> lock(mutex); return DefaultOutstationApplication::GetApplicationIIN(); }
    void RecordClassAssignment(AssignClassType type, PointClass clazz, uint16_t start, uint16_t stop) override
    {
        Console::Print("CLASS", "assigned type=" + std::to_string(static_cast<unsigned>(type)) + " class-mask="
            + std::to_string(static_cast<unsigned>(clazz)) + " range=" + std::to_string(start) + ".." + std::to_string(stop));
    }
};
int RunOutstation(const diagnostic::Options& o)
{
    RuntimeInfo(o);
    auto auth = diagnostic::Authentication(o, false); auth.errorObserver = std::make_shared<Errors>();
    DNP3Manager manager(1, std::make_shared<DiagnosticLogger>(o.auth != "compat"));
    auto observer = std::make_shared<ChannelObserver>();
    auto channel = MakeChannel(manager, o, observer, false);
    DatabaseConfig database(10);
    for (auto& p : database.binary_input) { p.second.clazz = PointClass::Class1; p.second.evariation = EventBinaryVariation::Group2Var2; }
    for (auto& p : database.double_binary) { p.second.clazz = PointClass::Class1; p.second.evariation = EventDoubleBinaryVariation::Group4Var2; }
    for (auto& p : database.analog_input) { p.second.clazz = PointClass::Class2; p.second.svariation = StaticAnalogVariation::Group30Var5; p.second.evariation = EventAnalogVariation::Group32Var7; }
    for (auto& p : database.counter) p.second.clazz = PointClass::Class3;
    OutstationStackConfig config(database);
    config.outstation.params.authentication = auth;
    config.outstation.eventBufferConfig = EventBufferConfig::AllTypes(100);
    config.outstation.eventBufferConfig.maxSecurityStatEvents = 100;
    config.outstation.params.allowUnsolicited = o.unsolicited;
    config.link.LocalAddr = o.local; config.link.RemoteAddr = o.remote; config.link.KeepAliveTimeout = TimeDuration::Max();
    auto application = std::make_shared<OutstationApplication>();
    if (o.trustedTime) application->WriteAbsoluteTime(UTCTimestamp(static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count())));
    auto commands = std::make_shared<SimulatedCommands>();
    auto outstation = channel->AddOutstation("cli-outstation-stack", commands, application, config);
    if (!outstation || !outstation->Enable()) throw std::runtime_error("Outstation could not enable");
    std::array<LocalPoints, 10> points{};
    Help(false);
    std::string line;
    while (!stopping.load() && std::getline(std::cin, line))
    {
        const auto w = Words(line);
        if (w.empty()) continue;
        if (Is(w, {"quit"}) || Is(w, {"exit"})) break;
        try
        {
            if (Is(w, {"help"})) { Help(false); continue; }
            if (Is(w, {"auth"})) { AuthStatus(outstation, o); continue; }
            if (Is(w, {"users"})) { diagnostic::PrintUsers(o, false); continue; }
            if (Is(w, {"status"})) { Console::Print("INFO", "channel=" + std::string(ChannelStateSpec::to_string(observer->Current())) + " executed=" + std::to_string(commands->executions)); continue; }
            if (Is(w, {"restart"})) { outstation->SetRestartIIN(); Console::Print("INFO", "Restart IIN submitted; full restart/recovery requires process restart"); continue; }
            if (Is(w, {"reconnect"})) { outstation->Disable(); outstation->Enable(); continue; }
            if (Is(w, {"show"}))
            {
                outstation->GetStackStatistics(); // Executor barrier after submitted Apply operations.
                Console::Print("DATABASE", "Configured indices 0..9: binary/double Class1; analog G30V5/G32V7 Class2; counter Class3. Initial class assignments may be changed by Master ASSIGN_CLASS.");
                for (size_t n = 0; n < points.size(); ++n)
                    Console::Print("POINT", "index=" + std::to_string(n) + " binary=" + ValueText(points[n].binary)
                        + " double=" + ValueText(points[n].doubleBit) + " analog=" + ValueText(points[n].analog) + " counter=" + ValueText(points[n].counter));
                Console::Print("INFO", "Input values are this application's published values; use Master READ for native database/output readback."); continue;
            }
            bool trace = false;
            if (TraceOption(w, trace))
            {
                const auto logs = LogFilter(o, trace);
                channel->SetLogFilters(logs); outstation->SetLogFilters(logs); continue;
            }
            if (w[0] == "set" && (w.size() == 4 || w.size() == 5))
            {
                const auto index = static_cast<uint16_t>(RequiredNumber(w[2], 9));
                auto next = points[index];
                const auto mode = w.size() == 4 ? EventMode::Detect : w[4] == "force" ? EventMode::Force
                    : w[4] == "suppress" ? EventMode::Suppress : throw std::runtime_error("Expected force/suppress");
                UpdateBuilder builder;
                if (w[1] == "binary" && (w[3] == "on" || w[3] == "off"))
                { next.binary = w[3] == "on"; builder.Update(Binary(next.binary, Flags(1), application->Now()), index, mode); }
                else if (w[1] == "double" && (w[3] == "on" || w[3] == "off" || w[3] == "intermediate" || w[3] == "indeterminate"))
                { next.doubleBit = w[3] == "on" ? DoubleBit::DETERMINED_ON : w[3] == "off" ? DoubleBit::DETERMINED_OFF : w[3] == "intermediate" ? DoubleBit::INTERMEDIATE : DoubleBit::INDETERMINATE;
                    builder.Update(DoubleBitBinary(next.doubleBit, Flags(1), application->Now()), index, mode); }
                else if (w[1] == "analog" && Floating(w[3], next.analog)) builder.Update(Analog(next.analog, Flags(1), application->Now()), index, mode);
                else if (w[1] == "counter" && Unsigned(w[3], 0xFFFFFFFFu, next.counter)) builder.Update(Counter(next.counter, Flags(1), application->Now()), index, mode);
                else throw std::runtime_error("Invalid point type/value");
                outstation->Apply(builder.Build()); points[index] = next;
                Console::Print("UPDATE", "submitted " + line); continue;
            }
            Console::Print("ERROR", "Unknown command. Type help.");
        }
        catch (const std::exception& e) { Console::Print("ERROR", e.what()); }
    }
    manager.Shutdown(); Console::Print("SHUTDOWN", "Outstation stopped"); return 0;
}
#ifdef _WIN32
HANDLE mainThread = nullptr;
BOOL WINAPI StopConsole(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT)
    { stopping.store(true); if (mainThread) CancelSynchronousIo(mainThread); return TRUE; }
    return FALSE;
}
#endif
} // namespace
int main(int argc, char* argv[])
{
    try
    {
        const auto options = diagnostic::ParseOptions(argc, argv);
        if (options.role == "authority-worker") return diagnostic::AuthorityWorker(options);
        if (options.role == "test-provision" || options.role == "test-cleanup") return diagnostic::Provision(options);
        if (options.role == "test-tls") return diagnostic::ProvisionTLS(options);
#ifdef _WIN32
        mainThread = OpenThread(THREAD_TERMINATE, FALSE, GetCurrentThreadId());
        SetConsoleCtrlHandler(StopConsole, TRUE);
#endif
        const int result = options.role == "master" ? RunMaster(options) : options.role == "outstation" ? RunOutstation(options)
            : throw std::runtime_error("Unknown role");
#ifdef _WIN32
        SetConsoleCtrlHandler(StopConsole, FALSE);
        if (mainThread) CloseHandle(mainThread);
#endif
        return result;
    }
    catch (const std::exception& error)
    {
        // Native exceptions contain no credential bytes. Do not echo argv or binary IPC.
        std::cerr << "ERROR: " << error.what() << '\n'; return 1;
    }
}
