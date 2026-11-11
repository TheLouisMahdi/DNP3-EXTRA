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

#include <algorithm>
#include <cstring>
#include <atomic>
#include <array>
#include <bitset>
#include <chrono>
#include <cmath>
#include <condition_variable>
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
#include <thread>
#include <utility>
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
    using SteadyClock = std::chrono::steady_clock;
    enum class Drive { INACTIVE, CLOSE, TRIP };
    struct PulseState
    {
        Drive drive = Drive::INACTIVE;
        SteadyClock::time_point deadline{};
    };

    const bool rtuIoProfile;
    const std::bitset<10> rtuCrobLatches;
    const std::bitset<10> rtuCrobTwoOutputs;
    const std::array<uint32_t, 10> rtuCrobTwoOutputPulseMs;
    const bool testOnly;
    std::bitset<10> crobInterlockPermits;
    std::mutex crobInterlockMutex;
    std::condition_variable crobPulseChanged;
    std::array<PulseState, 10> crobPulseStates{};
    std::chrono::milliseconds crobTestClockOffset{0};
    std::thread crobPulseWorker;
    bool shuttingDown = false;
    size_t inFlightActuations = 0;

    SteadyClock::time_point PulseNowLocked() const
    {
        return (testOnly ? SteadyClock::time_point{} : SteadyClock::now()) +
            crobTestClockOffset;
    }

    void FinishActuation()
    {
        {
            std::lock_guard<std::mutex> lock(crobInterlockMutex);
            --inFlightActuations;
        }
        crobPulseChanged.notify_all();
    }

    struct ActuationLease
    {
        SimulatedCommands& owner;
        ~ActuationLease() { owner.FinishActuation(); }
    };

    void RunPulseTimer()
    {
        std::unique_lock<std::mutex> lock(crobInterlockMutex);
        while (!shuttingDown)
        {
            auto nextDeadline = SteadyClock::time_point::max();
            for (size_t index = 0; index < crobPulseStates.size(); ++index)
            {
                if (rtuCrobTwoOutputs.test(index) &&
                    crobPulseStates[index].drive != Drive::INACTIVE)
                    nextDeadline = std::min(nextDeadline, crobPulseStates[index].deadline);
            }

            if (nextDeadline == SteadyClock::time_point::max())
            {
                crobPulseChanged.wait(lock);
                continue;
            }

            if (testOnly)
            {
                crobPulseChanged.wait(lock);
                if (shuttingDown)
                    break;
            }
            else
            {
                const auto wakeAt = nextDeadline - crobTestClockOffset;
                if (crobPulseChanged.wait_until(lock, wakeAt) != std::cv_status::timeout)
                    continue;
            }

            const auto now = PulseNowLocked();
            if (nextDeadline > now)
                continue;
            std::vector<std::pair<uint16_t, Drive>> expired;
            for (size_t index = 0; index < crobPulseStates.size(); ++index)
            {
                auto& state = crobPulseStates[index];
                if (rtuCrobTwoOutputs.test(index) &&
                    state.drive != Drive::INACTIVE &&
                    state.deadline <= now)
                {
                    expired.emplace_back(static_cast<uint16_t>(index), state.drive);
                    state.drive = Drive::INACTIVE;
                }
            }

            lock.unlock();
            for (const auto& item : expired)
                Console::Print("CROB-PULSE",
                    "expired point=" + std::to_string(item.first) +
                    " drive=" + (item.second == Drive::CLOSE ? "close" : "trip"));
            lock.lock();
        }
    }

    CommandStatus ValidateCrob(const ControlRelayOutputBlock& value, uint16_t index) const
    {
        if (shuttingDown)
            return CommandStatus::AUTOMATION_INHIBIT;

        if (!rtuIoProfile)
            return index < 10 ? CommandStatus::SUCCESS : CommandStatus::OUT_OF_RANGE;

        if (index >= rtuCrobLatches.size())
            return CommandStatus::NOT_SUPPORTED;

        const bool latch = rtuCrobLatches.test(index);
        const bool twoOutput = rtuCrobTwoOutputs.test(index);
        if ((!latch && !twoOutput) || value.count != 1 ||
            (value.rawCode != 0x41 && value.rawCode != 0x81))
            return CommandStatus::NOT_SUPPORTED;

        if (twoOutput && crobPulseStates[index].drive != Drive::INACTIVE)
            return CommandStatus::ALREADY_ACTIVE;

        return crobInterlockPermits.test(index)
            ? CommandStatus::SUCCESS
            : CommandStatus::AUTOMATION_INHIBIT;
    }

public:
    std::atomic<uint32_t> executions{0};
    explicit SimulatedCommands(const diagnostic::Options& options)
        : SimpleCommandHandler(CommandStatus::SUCCESS),
          rtuIoProfile(options.rtuIoProfile),
          rtuCrobLatches(options.rtuCrobLatches),
          rtuCrobTwoOutputs(options.rtuCrobTwoOutputs),
          rtuCrobTwoOutputPulseMs(options.rtuCrobTwoOutputPulseMs),
          testOnly(options.testOnly)
    {
        if (rtuCrobTwoOutputs.any())
            crobPulseWorker = std::thread(&SimulatedCommands::RunPulseTimer, this);
    }

    ~SimulatedCommands() { Shutdown(); }

    bool SetCrobInterlock(uint16_t index, bool allowed)
    {
        if (!rtuIoProfile ||
            index >= rtuCrobLatches.size() ||
            (!rtuCrobLatches.test(index) && !rtuCrobTwoOutputs.test(index)))
            return false;

        std::lock_guard<std::mutex> lock(crobInterlockMutex);
        if (shuttingDown)
            return false;
        crobInterlockPermits.set(index, allowed);
        return true;
    }

    bool AdvancePulseClock(uint32_t milliseconds)
    {
        if (!testOnly || !rtuCrobTwoOutputs.any() || !milliseconds)
            return false;

        int64_t totalMilliseconds = 0;
        {
            std::lock_guard<std::mutex> lock(crobInterlockMutex);
            const auto maxClockMilliseconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    SteadyClock::time_point::max().time_since_epoch()).count() -
                120000;
            if (shuttingDown ||
                crobTestClockOffset.count() >
                    maxClockMilliseconds - static_cast<int64_t>(milliseconds))
                return false;
            crobTestClockOffset += std::chrono::milliseconds(milliseconds);
            totalMilliseconds = crobTestClockOffset.count();
        }
        crobPulseChanged.notify_all();
        Console::Print("CROB-CLOCK",
            "advanced-ms=" + std::to_string(milliseconds) +
            " total-ms=" + std::to_string(totalMilliseconds));
        return true;
    }

    void PrintConfiguration() const
    {
        for (size_t index = 0; index < rtuCrobLatches.size(); ++index)
        {
            if (rtuCrobLatches.test(index))
                Console::Print("CROB-CONFIG",
                    "point=" + std::to_string(index) +
                    " model=complementary-latch");
            if (rtuCrobTwoOutputs.test(index))
                Console::Print("CROB-CONFIG",
                    "point=" + std::to_string(index) +
                    " model=complementary-two-output pulse-ms=" +
                    std::to_string(rtuCrobTwoOutputPulseMs[index]) +
                    " close=inactive trip=inactive");
        }
    }

    void PrintDiagnostics()
    {
        struct DiagnosticState
        {
            uint16_t index;
            bool latch;
            bool twoOutput;
            bool permitted;
            Drive drive;
        };
        std::array<DiagnosticState, 10> states{};
        size_t count = 0;
        uint32_t executionCount = 0;
        {
            std::lock_guard<std::mutex> lock(crobInterlockMutex);
            executionCount = executions.load();
            for (size_t index = 0; index < rtuCrobLatches.size(); ++index)
            {
                if (rtuCrobLatches.test(index) || rtuCrobTwoOutputs.test(index))
                    states[count++] = {
                        static_cast<uint16_t>(index),
                        rtuCrobLatches.test(index),
                        rtuCrobTwoOutputs.test(index),
                        crobInterlockPermits.test(index),
                        crobPulseStates[index].drive
                    };
            }
        }

        for (size_t n = 0; n < count; ++n)
        {
            const auto& state = states[n];
            const auto prefix = "point=" + std::to_string(state.index) +
                " model=" + (state.twoOutput ? "complementary-two-output"
                                               : "complementary-latch") +
                " interlock=" + (state.permitted ? "allowed" : "blocked");
            if (state.twoOutput)
                Console::Print("CROB-STATE",
                    prefix + " close=" +
                    (state.drive == Drive::CLOSE ? "active" : "inactive") +
                    " trip=" +
                    (state.drive == Drive::TRIP ? "active" : "inactive") +
                    " executed=" + std::to_string(executionCount));
            else
                Console::Print("CROB-STATE",
                    prefix + " executed=" + std::to_string(executionCount));
        }
    }

    void Shutdown()
    {
        std::vector<std::pair<uint16_t, Drive>> stopped;
        {
            std::unique_lock<std::mutex> lock(crobInterlockMutex);
            shuttingDown = true;
            crobPulseChanged.notify_all();
            crobPulseChanged.wait(lock, [this] { return inFlightActuations == 0; });
            for (size_t index = 0; index < crobPulseStates.size(); ++index)
            {
                auto& state = crobPulseStates[index];
                if (state.drive != Drive::INACTIVE)
                {
                    stopped.emplace_back(static_cast<uint16_t>(index), state.drive);
                    state.drive = Drive::INACTIVE;
                }
            }
        }

        crobPulseChanged.notify_all();
        if (crobPulseWorker.joinable())
            crobPulseWorker.join();
        for (const auto& item : stopped)
            Console::Print("CROB-PULSE",
                "shutdown=inactive point=" + std::to_string(item.first) +
                " drive=" + (item.second == Drive::CLOSE ? "close" : "trip"));
    }
    template<class T> CommandStatus SelectValue(const T&, uint16_t index)
    { return index < 10 ? CommandStatus::SUCCESS : CommandStatus::OUT_OF_RANGE; }
    CommandStatus SelectValue(const AnalogOutputFloat32& value, uint16_t index)
    {
        if (index >= 10)
            return CommandStatus::OUT_OF_RANGE;

        if (rtuIoProfile && !std::isfinite(value.value))
            return CommandStatus::OUT_OF_RANGE;

        return CommandStatus::SUCCESS;
    }
    CommandStatus SelectValue(const AnalogOutputDouble64&, uint16_t index)
    {
        if (index >= 10) return CommandStatus::OUT_OF_RANGE;
        return rtuIoProfile ? CommandStatus::NOT_SUPPORTED : CommandStatus::SUCCESS;
    }
    CommandStatus SelectValue(const ControlRelayOutputBlock& value, uint16_t index)
    {
        std::lock_guard<std::mutex> lock(crobInterlockMutex);
        return ValidateCrob(value, index);
    }
    template<class T> CommandStatus OperateValue(const T& value, uint16_t index, IUpdateHandler& handler)
    {
        const auto result = SelectValue(value, index);
        if (result != CommandStatus::SUCCESS) return result;
        handler.Update(AnalogOutputStatus(value.value), index);
        Console::Print("EXECUTED", "AnalogOutput[" + std::to_string(index) + "]=" + ValueText(value.value)
            + " simulated count=" + std::to_string(++executions));
        return CommandStatus::SUCCESS;
    }
    CommandStatus OperateValue(const ControlRelayOutputBlock& value,
                               uint16_t index, IUpdateHandler& handler)
    {
        bool twoOutput = false;
        Drive drive = Drive::INACTIVE;
        uint32_t executionCount = 0;
        {
            std::lock_guard<std::mutex> lock(crobInterlockMutex);
            const auto result = ValidateCrob(value, index);
            if (result != CommandStatus::SUCCESS)
                return result;

            ++inFlightActuations;
            twoOutput = rtuCrobTwoOutputs.test(index);
            if (twoOutput)
            {
                drive = value.tcc == TripCloseCode::CLOSE
                    ? Drive::CLOSE : Drive::TRIP;
                auto& state = crobPulseStates[index];
                state.drive = drive;
                state.deadline = PulseNowLocked() +
                    std::chrono::milliseconds(rtuCrobTwoOutputPulseMs[index]);
                executionCount = ++executions;
            }
        }
        ActuationLease lease{*this};

        if (twoOutput)
        {
            crobPulseChanged.notify_all();
            Console::Print("CROB-PULSE",
                "started point=" + std::to_string(index) +
                " drive=" + (drive == Drive::CLOSE ? "close" : "trip") +
                " configured-ms=" +
                std::to_string(rtuCrobTwoOutputPulseMs[index]) +
                " request-on-ms=" + std::to_string(value.onTimeMS) +
                " request-off-ms=" + std::to_string(value.offTimeMS) +
                " executed=" + std::to_string(executionCount));
        }
        else
        {
            const bool closed = rtuIoProfile
                ? value.tcc == TripCloseCode::CLOSE
                : value.opType == OperationType::LATCH_ON;
            handler.Update(BinaryOutputStatus(closed), index);
            Console::Print("EXECUTED",
                "CROB[" + std::to_string(index) +
                "] simulated count=" + std::to_string(++executions));
        }

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
    const bool noAck;
public:
    explicit TaskPrinter(std::string name, bool noAck = false) : label(std::move(name)), noAck(noAck) {}
    void OnStart() override { Console::Print("TASK", label + " START"); }
    void OnComplete(TaskCompletion result) override
    {
        if (!noAck)
            Console::Print("TASK", label + " " + TaskCompletionSpec::to_string(result));
    }
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
        config.crlFilePath = o.crl;
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
void Help(bool master, bool rtuIoProfile)
{
    if (master)
    {
        Console::Print("HELP", "read <g> <v> [start stop] | scan integrity|class0|class1|class2|class3 | attr 209|210|254|255");
        Console::Print("HELP", "crob <index> on|off [sbo|direct|noack] | analog <v:1..4> <index> <value> [sbo|direct|noack]");
        Console::Print("HELP", "user <number> | ruk add|change|delete <Common|operator|engineer|guest> <scs> <role> <expiry-days>");
        Console::Print("HELP", "ruk verify|change-key <name> | stats | events | assign <group> <class:0..3> <start> <stop>");
        Console::Print("HELP", "unsol on|off | restart cold|warm | time (G50V1 READ)");
    }
    else Console::Print("HELP", std::string("set binary|double|analog")
        + (rtuIoProfile ? "" : "|counter") + " <index:0..9> <value> [force|suppress] | show | restart (restart IIN)");
    if (!master && rtuIoProfile)
        Console::Print("HELP", "crob-interlock <index:0..9> allow|block (configured TEST CROB point only)");
    if (!master && rtuIoProfile)
        Console::Print("HELP", "crob-pulse advance <ms> (TEST-only pulse clock)");
    Console::Print("HELP", "status | auth | users | reconnect | trace on|off (metadata only in SA) | help | quit");
}
uint32_t RequiredNumber(const std::string& value, uint32_t maximum)
{
    uint32_t result = 0;
    if (!Unsigned(value, maximum, result)) throw std::runtime_error("Invalid unsigned number");
    return result;
}
void ConfigureLink(LinkConfig& link, const diagnostic::Options& o)
{
    link.LocalAddr = o.local;
    link.RemoteAddr = o.remote;
    link.ConfirmMode = o.linkConfirmMode;
    link.NumRetries = o.linkRetries;
    if (o.linkTimeoutMs)
        link.Timeout = TimeDuration::Milliseconds(o.linkTimeoutMs);
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
    if (o.prefer8BitControlQualifiers)
        config.master.controlQualifierMode = IndexQualifierMode::allow_one_byte;
    config.master.maxRxFragSize = o.rxFragmentBytes;
    config.master.maxTxFragSize = o.txFragmentBytes;
    if (o.rxFragmentTimeoutMs)
        config.master.maxRxFragmentTime = TimeDuration::Milliseconds(o.rxFragmentTimeoutMs);
    if (o.completeResponseMs)
        config.master.maxResponseTime = TimeDuration::Milliseconds(o.completeResponseMs);
    config.master.disableUnsolOnStartup = true;
    config.master.unsolClassMask = ClassField::None(); // Enable only on the explicit CLI command.
    config.master.startupIntegrityClassMask = ClassField::AllClasses();
    config.master.timeSyncMode = TimeSyncMode::NonLAN;
    ConfigureLink(config.link, o);
    auto soe = std::make_shared<SoePrinter>();
    auto master = channel->AddMaster("cli-master-stack", soe, std::make_shared<MasterObserver>(), config);
    if (!master || !master->Enable()) throw std::runtime_error("Master could not enable");
    Help(true, o.rtuIoProfile);
    std::string line;
    while (!stopping.load() && std::getline(std::cin, line))
    {
        const auto w = Words(line);
        if (w.empty()) continue;
        if (Is(w, {"quit"}) || Is(w, {"exit"})) break;
        try
        {
            if (Is(w, {"help"})) { Help(true, o.rtuIoProfile); continue; }
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
            const bool fc6NoAck = (w[0] == "crob" && w.size() == 4 && w[3] == "noack")
                || (w[0] == "analog" && w.size() == 5 && w[4] == "noack");
            auto task = TaskConfig::With(std::make_shared<TaskPrinter>(w[0], fc6NoAck)); task.authenticationUser = o.user;
            auto onResult = [name = w[0]](const ICommandTaskResult& result) { CommandResult(name, result); };
            auto onNoAckResult = [](const ICommandTaskResult& result) {
                if (result.summary == TaskCompletion::SUCCESS)
                    Console::Print("FC6", "local transmission complete; remote execution unknown");
                else
                    Console::Print("FC6", "local transmission did not complete: "
                        + std::string(TaskCompletionSpec::to_string(result.summary)));
            };
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
                const bool on = w[2] == "on";
                const auto command = o.rtuIoProfile
                    ? ControlRelayOutputBlock(OperationType::PULSE_ON,
                                              on ? TripCloseCode::CLOSE : TripCloseCode::TRIP, false, 1, 100, 0)
                    : ControlRelayOutputBlock(on ? OperationType::LATCH_ON : OperationType::LATCH_OFF);
                const auto mode = w.size() == 3 ? std::string("sbo") : w[3];
                if (mode == "noack")
                {
                    if (!master->DirectOperateNoAck(command, index, onNoAckResult, task))
                    {
                        Console::Print("ERROR", "FC6 noack rejected locally");
                        continue;
                    }
                }
                else if (mode == "direct") master->DirectOperate(command, index, onResult, task);
                else if (mode == "sbo") master->SelectAndOperate(command, index, onResult, task);
                else throw std::runtime_error("Expected sbo/direct/noack");
            }
            else if (w[0] == "analog" && (w.size() == 4 || w.size() == 5))
            {
                const auto variation = RequiredNumber(w[1], 4), index = RequiredNumber(w[2], 65535);
                double value = 0;
                if (!Floating(w[3], value) || variation == 0) throw std::runtime_error("Invalid analog command");
                const auto mode = w.size() == 4 ? std::string("sbo") : w[4];
                if (mode != "sbo" && mode != "direct" && mode != "noack")
                    throw std::runtime_error("Expected sbo/direct/noack");
                auto send = [&](const auto& command) {
                    if (mode == "noack")
                        return master->DirectOperateNoAck(command, static_cast<uint16_t>(index), onNoAckResult, task);
                    if (mode == "direct")
                    {
                        master->DirectOperate(command, static_cast<uint16_t>(index), onResult, task);
                        return true;
                    }
                    master->SelectAndOperate(command, static_cast<uint16_t>(index), onResult, task);
                    return true;
                };
                if (variation <= 2 && (value != std::trunc(value) || value < (variation == 1 ? -2147483648.0 : -32768.0)
                    || value > (variation == 1 ? 2147483647.0 : 32767.0))) throw std::runtime_error("Integer command out of range");
                bool accepted = true;
                if (variation == 1) accepted = send(AnalogOutputInt32(static_cast<int32_t>(value)));
                if (variation == 2) accepted = send(AnalogOutputInt16(static_cast<int16_t>(value)));
                if (variation == 3) { if (std::abs(value) > std::numeric_limits<float>::max()) throw std::runtime_error("Float overflow"); accepted = send(AnalogOutputFloat32(static_cast<float>(value))); }
                if (variation == 4) accepted = send(AnalogOutputDouble64(value));
                if (!accepted)
                {
                    Console::Print("ERROR", "FC6 noack rejected locally");
                    continue;
                }
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
            Console::Print("SUBMITTED", line + (fc6NoAck
                ? " (FC6 locally accepted; remote execution unknown)" : " (completion pending)"));
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
    bool ClearNeedTime() override
    { std::lock_guard<std::mutex> lock(mutex); return DefaultOutstationApplication::ClearNeedTime(); }
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
    if (o.rtuIoProfile)
    {
        database.counter.clear();
        database.frozen_counter.clear();
    }
    for (auto& p : database.binary_input)
    {
        p.second.clazz = PointClass::Class1;
        p.second.evariation = o.relativeBinaryTime ? EventBinaryVariation::Group2Var3 : EventBinaryVariation::Group2Var2;
    }
    for (auto& p : database.double_binary) { p.second.clazz = PointClass::Class1; p.second.evariation = EventDoubleBinaryVariation::Group4Var2; }
    for (auto& p : database.analog_input)
    {
        p.second.clazz = PointClass::Class2;
        p.second.svariation = StaticAnalogVariation::Group30Var5;
        p.second.evariation = o.rtuIoProfile ? EventAnalogVariation::Group32Var5
                                             : EventAnalogVariation::Group32Var7;
    }
    for (auto& p : database.counter) p.second.clazz = PointClass::Class3;
    if (o.commandEvents)
    {
        for (uint16_t index = 0; index < 10; ++index)
        {
            database.binary_command_event[index].clazz = PointClass::Class1;
            database.analog_command_event[index].clazz = PointClass::Class2;
        }
    }
    OutstationStackConfig config(database);
    config.outstation.params.authentication = auth;
    config.outstation.params.maxRxFragSize = o.rxFragmentBytes;
    config.outstation.params.maxTxFragSize = o.txFragmentBytes;
    config.outstation.eventBufferConfig = EventBufferConfig::AllTypes(100);
    config.outstation.eventBufferConfig.maxSecurityStatEvents = 100;
    if (o.rtuIoProfile)
    {
        config.outstation.eventBufferConfig.maxCounterEvents = 0;
        config.outstation.eventBufferConfig.maxFrozenCounterEvents = 0;
    }
    if (o.commandEvents)
    {
        config.outstation.eventBufferConfig.maxBinaryCommandEvents = 100;
        config.outstation.eventBufferConfig.maxAnalogCommandEvents = 100;
    }
    config.outstation.params.allowUnsolicited = o.unsolicited;
    config.outstation.params.prefer8BitEventQualifiers = o.prefer8BitEventQualifiers;
    if (o.rxFragmentTimeoutMs)
        config.outstation.params.maxRxFragmentTime = TimeDuration::Milliseconds(o.rxFragmentTimeoutMs);
    if (o.solConfirmMs)
        config.outstation.params.solConfirmTimeout = TimeDuration::Milliseconds(o.solConfirmMs);
    if (o.unsolConfirmMs)
        config.outstation.params.unsolConfirmTimeout = TimeDuration::Milliseconds(o.unsolConfirmMs);
    if (o.unsolRetries)
        config.outstation.params.numUnsolRetries = NumRetries::Fixed(o.unsolRetries);
    ConfigureLink(config.link, o);
    config.link.KeepAliveTimeout = TimeDuration::Max();
    auto application = std::make_shared<OutstationApplication>();
    if (o.trustedTime) application->WriteAbsoluteTime(UTCTimestamp(static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count())));
    auto commands = std::make_shared<SimulatedCommands>(o);
    auto outstation = channel->AddOutstation("cli-outstation-stack", commands, application, config);
    if (!outstation || !outstation->Enable()) throw std::runtime_error("Outstation could not enable");
    commands->PrintConfiguration();
    std::array<LocalPoints, 10> points{};
    Help(false, o.rtuIoProfile);
    std::string line;
    while (!stopping.load() && std::getline(std::cin, line))
    {
        const auto w = Words(line);
        if (w.empty()) continue;
        if (Is(w, {"quit"}) || Is(w, {"exit"})) break;
        try
        {
            if (Is(w, {"help"})) { Help(false, o.rtuIoProfile); continue; }
            if (w[0] == "crob-interlock" && w.size() == 3)
            {
                if (w[2] != "allow" && w[2] != "block")
                    throw std::runtime_error("Expected allow or block");

                const auto index = static_cast<uint16_t>(RequiredNumber(w[1], 9));

                if (!commands->SetCrobInterlock(index, w[2] == "allow"))
                    throw std::runtime_error("CROB interlock requires a configured test CROB point");

                Console::Print("INTERLOCK",
                    "CROB[" + std::to_string(index) + "] " + w[2]);

                continue;
            }
            if (w[0] == "crob-pulse" && w.size() == 3 && w[1] == "advance")
            {
                const auto milliseconds = RequiredNumber(w[2], 120000);
                if (!milliseconds ||
                    !commands->AdvancePulseClock(milliseconds))
                    throw std::runtime_error("Pulse clock advance requires a configured TEST two-output point");
                continue;
            }
            if (Is(w, {"auth"})) { AuthStatus(outstation, o); continue; }
            if (Is(w, {"users"})) { diagnostic::PrintUsers(o, false); continue; }
            if (Is(w, {"status"}))
            {
                Console::Print("INFO", "channel=" + std::string(ChannelStateSpec::to_string(observer->Current())) + " executed=" + std::to_string(commands->executions));
                commands->PrintDiagnostics();
                continue;
            }
            if (Is(w, {"restart"})) { outstation->SetRestartIIN(); Console::Print("INFO", "Restart IIN submitted; full restart/recovery requires process restart"); continue; }
            if (Is(w, {"reconnect"})) { outstation->Disable(); outstation->Enable(); continue; }
            if (Is(w, {"show"}))
            {
                outstation->GetStackStatistics(); // Executor barrier after submitted Apply operations.
                Console::Print("DATABASE", std::string("Configured indices 0..9: binary/double Class1; analog G30V5/")
                    + (o.rtuIoProfile ? "G32V5" : "G32V7") + " Class2; "
                    + (o.rtuIoProfile ? "no counters. " : "counter Class3. ")
                    + "Initial class assignments may be changed by Master ASSIGN_CLASS.");
                for (size_t n = 0; n < points.size(); ++n)
                    Console::Print("POINT", "index=" + std::to_string(n) + " binary=" + ValueText(points[n].binary)
                        + " double=" + ValueText(points[n].doubleBit) + " analog=" + ValueText(points[n].analog)
                        + (o.rtuIoProfile ? "" : " counter=" + ValueText(points[n].counter)));
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
                else if (w[1] == "counter" && !o.rtuIoProfile && Unsigned(w[3], 0xFFFFFFFFu, next.counter))
                    builder.Update(Counter(next.counter, Flags(1), application->Now()), index, mode);
                else throw std::runtime_error("Invalid point type/value");
                outstation->Apply(builder.Build()); points[index] = next;
                Console::Print("UPDATE", "submitted " + line); continue;
            }
            Console::Print("ERROR", "Unknown command. Type help.");
        }
        catch (const std::exception& e) { Console::Print("ERROR", e.what()); }
    }
    commands->Shutdown();
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
