#include <opendnp3/ConsoleLogger.h>
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

#include <algorithm>
#include <cctype>
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

constexpr uint16_t kPort = 20000;
constexpr uint16_t kMasterAddress = 1;
constexpr uint16_t kOutstationAddress = 10;

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
        std::transform(word.begin(), word.end(), word.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
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

class CommandLogger final : public SimpleCommandHandler
{
public:
    CommandLogger() : SimpleCommandHandler(CommandStatus::SUCCESS) {}

protected:
    void DoSelect(const ControlRelayOutputBlock& command, uint16_t index) override
    {
        Console::Print("RX", "SELECT CROB[" + std::to_string(index) + "] "
                         + OperationTypeSpec::to_string(command.opType) + " -> SUCCESS (simulated)");
    }

    void DoOperate(const ControlRelayOutputBlock& command, uint16_t index, OperateType) override
    {
        Console::Print("RX", "OPERATE CROB[" + std::to_string(index) + "] "
                         + OperationTypeSpec::to_string(command.opType) + " -> SUCCESS (simulated)");
    }
};

void MasterHelp()
{
    Console::Print("HELP", "read <group> <variation> <start> <stop> | scan integrity | scan class1|class2|class3");
    Console::Print("HELP", "crob <index> on|off | status | trace on|off | help | quit");
}

void OutstationHelp()
{
    Console::Print("HELP", "set binary|double|analog|counter 0 <value> | show | status");
    Console::Print("HELP", "trace on|off | help | quit   (only point index 0 is writable)");
}

bool TraceOption(const std::vector<std::string>& words, bool& enabled)
{
    if (Is(words, {"trace", "on"})) { enabled = true; return true; }
    if (Is(words, {"trace", "off"})) { enabled = false; return true; }
    return false;
}

void CommandResult(const ICommandTaskResult& result)
{
    Console::Print("RESULT", std::string("CROB task=") + TaskCompletionSpec::to_string(result.summary));
    result.ForeachItem([](const CommandPointResult& point) {
        std::ostringstream stream;
        stream << "CROB[" << point.index << "] state=" << CommandPointStateSpec::to_string(point.state);
        if (point.state == CommandPointState::SUCCESS || point.state == CommandPointState::SELECT_FAIL)
            stream << " status=" << CommandStatusSpec::to_string(point.status);
        stream << " (application handler may be simulated)";
        Console::Print("RX", stream.str());
    });
}

int RunMaster()
{
    Console::Print("INFO", "DNP3-EXTRA MASTER | 127.0.0.1:20000 | local=1 remote=10");
    DNP3Manager manager(1, ConsoleLogger::Create());
    auto observer = std::make_shared<ChannelObserver>();
    auto channel = manager.AddTCPClient("cli-master", levels::NORMAL, ChannelRetry::Default(),
                                        {IPEndpoint("127.0.0.1", kPort)}, "0.0.0.0", observer);
    MasterStackConfig config;
    config.master.responseTimeout = TimeDuration::Seconds(2);
    config.master.disableUnsolOnStartup = true;
    config.master.timeSyncMode = TimeSyncMode::NonLAN;
    config.link.LocalAddr = kMasterAddress;
    config.link.RemoteAddr = kOutstationAddress;

    auto soe = std::make_shared<SoePrinter>();
    auto master = channel->AddMaster("cli-master-stack", soe,
                                      std::make_shared<MasterObserver>(), config);
    auto integrity = master->AddClassScan(ClassField::AllClasses(), TimeDuration::Minutes(1), soe);
    auto class1 = master->AddClassScan(ClassField(ClassField::CLASS_1), TimeDuration::Seconds(5), soe);
    (void)integrity;
    (void)class1;
    master->Enable();
    MasterHelp();

    std::string line;
    while (std::cout << "dnp(master)> " << std::flush, std::getline(std::cin, line))
    {
        const auto words = Words(line);
        if (words.empty()) continue;
        if (Is(words, {"quit"}) || Is(words, {"exit"})) break;
        if (Is(words, {"help"})) { MasterHelp(); continue; }
        if (Is(words, {"status"}))
        {
            Console::Print("INFO", std::string("channel=") + ChannelStateSpec::to_string(observer->Current())
                           + " | TCP 127.0.0.1:20000 | local=1 remote=10");
            continue;
        }
        bool trace = false;
        if (TraceOption(words, trace))
        {
            const auto filter = trace ? levels::NORMAL | levels::ALL_COMMS : levels::NORMAL;
            channel->SetLogFilters(filter);
            master->SetLogFilters(filter);
            Console::Print("INFO", trace ? "Trace ON" : "Trace OFF");
            continue;
        }
        if (Is(words, {"scan", "integrity"}))
        {
            Console::Print("TX", "READ Class 0/1/2/3");
            master->ScanClasses(ClassField::AllClasses(), soe);
            continue;
        }
        if (Is(words, {"scan", "class1"}) || Is(words, {"scan", "class2"}) || Is(words, {"scan", "class3"}))
        {
            const auto klass = words[1] == "class1" ? ClassField::CLASS_1
                             : words[1] == "class2" ? ClassField::CLASS_2 : ClassField::CLASS_3;
            Console::Print("TX", "READ " + words[1]);
            master->ScanClasses(ClassField(klass), soe);
            continue;
        }
        if (words.size() == 5 && words[0] == "read")
        {
            uint32_t group, variation, start, stop;
            if (!Unsigned(words[1], 255, group) || !Unsigned(words[2], 255, variation)
                || !Unsigned(words[3], 65535, start) || !Unsigned(words[4], 65535, stop) || start > stop)
            {
                Console::Print("ERROR", "Usage: read <group:0..255> <variation:0..255> <start:0..65535> <stop>=start");
                continue;
            }
            std::ostringstream request;
            request << "READ G" << group << "V" << variation << " [" << start << ".." << stop << ']';
            Console::Print("TX", request.str());
            master->ScanRange(GroupVariationID(static_cast<uint8_t>(group), static_cast<uint8_t>(variation)),
                              static_cast<uint16_t>(start), static_cast<uint16_t>(stop), soe);
            continue;
        }
        if (words.size() == 3 && words[0] == "crob")
        {
            uint32_t index;
            if (!Unsigned(words[1], 65535, index) || (words[2] != "on" && words[2] != "off"))
            {
                Console::Print("ERROR", "Usage: crob <index:0..65535> on|off");
                continue;
            }
            const auto op = words[2] == "on" ? OperationType::LATCH_ON : OperationType::LATCH_OFF;
            Console::Print("TX", "SELECT/OPERATE CROB[" + std::to_string(index) + "] " + words[2]);
            master->SelectAndOperate(ControlRelayOutputBlock(op), static_cast<uint16_t>(index), CommandResult);
            continue;
        }
        Console::Print("ERROR", "Unknown command. Type help.");
    }
    return 0;
}

struct LocalPoints
{
    bool binary = false;
    DoubleBit doubleBit = DoubleBit::DETERMINED_OFF;
    double analog = 0.0;
    uint32_t counter = 0;
};

int RunOutstation()
{
    Console::Print("INFO", "DNP3-EXTRA OUTSTATION | 127.0.0.1:20000 | local=10 remote=1");
    DNP3Manager manager(1, ConsoleLogger::Create());
    auto observer = std::make_shared<ChannelObserver>();
    auto channel = manager.AddTCPServer("cli-outstation", levels::NORMAL,
                                        ServerAcceptMode::CloseExisting, IPEndpoint("127.0.0.1", kPort), observer);
    DatabaseConfig database(10);
    database.analog_input[0].clazz = PointClass::Class2;
    database.analog_input[0].svariation = StaticAnalogVariation::Group30Var5;
    database.analog_input[0].evariation = EventAnalogVariation::Group32Var5;
    database.double_binary[0].evariation = EventDoubleBinaryVariation::Group4Var2;
    OutstationStackConfig config(database);
    config.outstation.eventBufferConfig = EventBufferConfig::AllTypes(100);
    config.outstation.params.allowUnsolicited = true;
    config.link.LocalAddr = kOutstationAddress;
    config.link.RemoteAddr = kMasterAddress;
    config.link.KeepAliveTimeout = TimeDuration::Max();

    auto application = DefaultOutstationApplication::Create();
    auto commands = std::make_shared<CommandLogger>();
    auto outstation = channel->AddOutstation("cli-outstation-stack", commands, application, config);
    outstation->Enable();
    LocalPoints points;
    OutstationHelp();

    std::string line;
    while (std::cout << "dnp(outstation)> " << std::flush, std::getline(std::cin, line))
    {
        const auto words = Words(line);
        if (words.empty()) continue;
        if (Is(words, {"quit"}) || Is(words, {"exit"})) break;
        if (Is(words, {"help"})) { OutstationHelp(); continue; }
        if (Is(words, {"status"}))
        {
            Console::Print("INFO", std::string("channel=") + ChannelStateSpec::to_string(observer->Current())
                           + " | TCP port=20000 | local=10 remote=1");
            continue;
        }
        if (Is(words, {"show"}))
        {
            std::ostringstream stream;
            stream << "Local sample points [0]: Binary=" << ValueText(points.binary)
                   << " DoubleBit=" << ValueText(points.doubleBit)
                   << " Analog=" << points.analog << " Counter=" << points.counter;
            Console::Print("INFO", stream.str());
            continue;
        }
        bool trace = false;
        if (TraceOption(words, trace))
        {
            const auto filter = trace ? levels::NORMAL | levels::ALL_COMMS : levels::NORMAL;
            channel->SetLogFilters(filter);
            outstation->SetLogFilters(filter);
            Console::Print("INFO", trace ? "Trace ON" : "Trace OFF");
            continue;
        }
        if (words.size() == 4 && words[0] == "set" && words[2] == "0")
        {
            UpdateBuilder builder;
            std::string display;
            if (words[1] == "binary" && (words[3] == "on" || words[3] == "off"))
            {
                points.binary = words[3] == "on";
                builder.Update(Binary(points.binary, Flags(0x01), application->Now()), 0);
                display = "Binary[0]=" + ValueText(points.binary);
            }
            else if (words[1] == "double" && (words[3] == "on" || words[3] == "off"))
            {
                points.doubleBit = words[3] == "on" ? DoubleBit::DETERMINED_ON : DoubleBit::DETERMINED_OFF;
                builder.Update(DoubleBitBinary(points.doubleBit, Flags(0x01), application->Now()), 0);
                display = "DoubleBit[0]=" + ValueText(points.doubleBit);
            }
            else if (words[1] == "analog" && Floating(words[3], points.analog))
            {
                builder.Update(Analog(points.analog, Flags(0x01), application->Now()), 0);
                display = "Analog[0]=" + ValueText(points.analog);
            }
            else if (words[1] == "counter" && Unsigned(words[3], std::numeric_limits<uint32_t>::max(), points.counter))
            {
                builder.Update(Counter(points.counter, Flags(0x01), application->Now()), 0);
                display = "Counter[0]=" + ValueText(points.counter);
            }
            else
            {
                Console::Print("ERROR", "Invalid value for selected point type");
                continue;
            }
            outstation->Apply(builder.Build());
            Console::Print("INFO", "Local update submitted: " + display);
            continue;
        }
        Console::Print("ERROR", "Unknown command. Try: set binary 0 on | set analog 0 12.5 | help");
    }
    return 0;
}
} // namespace

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: dnp3-cli.exe master|outstation\n";
        return 2;
    }
    try
    {
        const std::string role = argv[1];
        if (role == "master") return RunMaster();
        if (role == "outstation") return RunOutstation();
        std::cerr << "Unknown role: " << role << " (expected master|outstation)\n";
        return 2;
    }
    catch (const std::exception& error)
    {
        Console::Print("ERROR", error.what());
        return 1;
    }
}
