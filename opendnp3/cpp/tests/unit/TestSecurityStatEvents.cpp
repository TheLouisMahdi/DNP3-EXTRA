// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "app/APDUResponse.h"
#include "app/parsing/APDUParser.h"
#include "auth/AuthenticationStatistics.h"
#include "gen/objects/Group122.h"
#include "outstation/ReadHandler.h"
#include "outstation/SecurityStatEventPublisher.h"
#include "utils/OutstationTestObject.h"
#include "utils/BufferHelpers.h"

#include <ser4cpp/util/HexConversions.h>
#include <catch.hpp>

#include <array>
#include <limits>

using namespace opendnp3;
using namespace ser4cpp;

namespace opendnp3
{
class SecurityStatEventTestAccess
{
public:
    static uint32_t Count(OContext& context)
    {
        return context.eventBuffer.NumEvents(EventClass::EC1);
    }
    static void Attach(OContext& context, AuthenticationStatistics& statistics,
                       const SecurityStatisticThresholds& thresholds)
    {
        statistics.SetReporter(context.securityStatPublisher.get(), thresholds);
    }
};
}

namespace
{
struct EventStore final : IAuthenticationStatisticsStore
{
    SecurityStatisticValues saved{};
    bool available = true;
    bool Load(uint16_t, bool, SecurityStatisticValues& values) override { values = saved; return true; }
    bool Save(uint16_t, bool, const SecurityStatisticValues& values) override
    {
        if (!available) return false;
        saved = values;
        return true;
    }
};

struct EventsFixture
{
    static EventBufferConfig Capacity(uint16_t n)
    {
        EventBufferConfig config;
        config.maxSecurityStatEvents = n;
        return config;
    }
    AuthenticationStatistics statistics;
    EventBuffer events;
    MockOutstationApplication application;
    SecurityStatEventPublisher publisher;
    Database database;

    EventsFixture(uint16_t capacity = 10, std::shared_ptr<EventStore> store = nullptr)
        : statistics(7, false, DefaultSecurityStatisticThresholds(), store), events(Capacity(capacity)),
          publisher({}, application, events, [] {}), database({}, events, application, StaticTypeBitField())
    {
        application.currentTime = DNPTime(0x060504030201ULL);
        statistics.SetReporter(&publisher, DefaultSecurityStatisticThresholds());
    }
    void Increment(SecurityStatistic index, unsigned count = 1)
    {
        while (count--) statistics.Increment(index);
    }
    IINField Select(const std::string& request)
    {
        events.Unselect();
        ReadHandler handler(database, events);
        HexSequence bytes(request);
        REQUIRE(APDUParser::Parse(bytes.ToRSeq(), handler, nullptr, ParserSettings::NoContents()) == ParseResult::OK);
        return handler.Errors();
    }
    std::string Write(size_t capacity = 2048)
    {
        std::array<uint8_t, 2048> bytes{};
        APDUResponse apdu(wseq_t(bytes.data(), capacity));
        apdu.SetControl(AppControlField(true, true, true, false));
        apdu.SetFunction(FunctionCode::RESPONSE);
        apdu.SetIIN(IINField::Empty());
        auto writer = apdu.GetWriter();
        events.Load(writer);
        return HexConversions::to_hex(apdu.ToRSeq());
    }
};

struct NativeEvents
{
    AuthenticationStatistics statistics{7, false, DefaultSecurityStatisticThresholds()};
    OutstationTestObject outstation;
    explicit NativeEvents(OutstationConfig config = Config()) : outstation(config)
    {
        outstation.application->currentTime = DNPTime(0x060504030201ULL);
        SecurityStatEventTestAccess::Attach(outstation.context, statistics, config.securityStatThresholds);
        outstation.LowerLayerUp();
    }
    static OutstationConfig Config()
    {
        OutstationConfig config;
        config.eventBufferConfig.maxSecurityStatEvents = 32;
        return config;
    }
    void Generate()
    {
        for (int n = 0; n < 3; ++n) statistics.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    }
};
}

TEST_CASE("SecurityStatEvents - exact codecs and truncation", "[security-stat-events]")
{
    SecurityStat value(0x12345678, Flags(0xFF), 0xABCD, DNPTime(0x060504030201ULL));
    std::array<uint8_t, 13> bytes{};
    REQUIRE(Group122Var1::Size() == 7);
    REQUIRE(Group122Var2::Size() == 13);
    auto output = wseq_t(bytes.data(), 7);
    REQUIRE(Group122Var1::WriteTarget(value, output));
    REQUIRE(HexConversions::to_hex(rseq_t(bytes.data(), 7)) == "5F CD AB 78 56 34 12");
    output = wseq_t(bytes.data(), bytes.size());
    REQUIRE(Group122Var2::WriteTarget(value, output));
    REQUIRE(HexConversions::to_hex(rseq_t(bytes.data(), bytes.size()))
            == "5F CD AB 78 56 34 12 01 02 03 04 05 06");
    for (size_t n = 0; n <= 13; ++n)
    {
        auto input = rseq_t(bytes.data(), n);
        Group122Var2 decoded;
        REQUIRE(Group122Var2::Read(input, decoded) == (n == 13));
        if (n == 13)
        {
            REQUIRE(decoded.flags == 0x5F);
            REQUIRE(decoded.associationId == 0xABCD);
            REQUIRE(decoded.value == 0x12345678);
            REQUIRE(decoded.time.value == 0x060504030201ULL);
        }
        input = rseq_t(bytes.data(), n < 7 ? n : 7);
        Group122Var1 v1;
        REQUIRE(Group122Var1::Read(input, v1) == (n >= 7));
    }
}

TEST_CASE("SecurityStatEvents - generated serializers support both response prefixes", "[security-stat-events]")
{
    for (bool withTime : {false, true})
    {
        for (bool wide : {false, true})
        {
            std::array<uint8_t, 64> bytes{};
            APDUResponse apdu(wseq_t(bytes.data(), bytes.size()));
            apdu.SetControl(AppControlField(true, true, true, false));
            apdu.SetFunction(FunctionCode::RESPONSE);
            apdu.SetIIN(IINField::Empty());
            auto writer = apdu.GetWriter();
            const auto serializer = withTime ? Group122Var2::Inst() : Group122Var1::Inst();
            const SecurityStat value(0x12345678, Flags(0xFF), 0, DNPTime(0x060504030201ULL));
            if (wide)
            {
                auto iterator = writer.IterateOverCountWithPrefix<UInt16, SecurityStat>(QualifierCode::UINT16_CNT_UINT16_INDEX, serializer);
                REQUIRE(iterator.Write(value, 17));
            }
            else
            {
                auto iterator = writer.IterateOverCountWithPrefix<UInt8, SecurityStat>(QualifierCode::UINT8_CNT_UINT8_INDEX, serializer);
                REQUIRE(iterator.Write(value, 17));
            }
            const std::string expected = std::string("E0 81 00 00 7A ") + (withTime ? "02 " : "01 ")
                + (wide ? "28 01 00 11 00 " : "17 01 11 ") + "5F 00 00 78 56 34 12"
                + (withTime ? " 01 02 03 04 05 06" : "");
            REQUIRE(HexConversions::to_hex(apdu.ToRSeq()) == expected);
        }
    }
}

TEST_CASE("SecurityStatEvents - reporting equality and immutable occurrence", "[security-stat-events]")
{
    EventsFixture f;
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES, 2);
    REQUIRE(f.events.NumEvents(EventClass::EC1) == 0);
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    REQUIRE(f.events.NumEvents(EventClass::EC1) == 1);
    REQUIRE_FALSE(f.statistics.ReportPending(SecurityStatistic::UNEXPECTED_MESSAGES));
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    f.application.currentTime = DNPTime(99);
    REQUIRE(f.Select("7A 02 06") == IINField::Empty());
    REQUIRE(f.Write() == "E0 81 00 00 7A 02 28 01 00 00 00 41 00 00 03 00 00 00 01 02 03 04 05 06");
    f.events.Unselect();
    REQUIRE(f.Select("7A 01 06") == IINField::Empty());
    REQUIRE(f.Write() == "E0 81 00 00 7A 01 28 01 00 00 00 41 00 00 03 00 00 00");
}

TEST_CASE("SecurityStatEvents - failed save marks later G122 events discontinuous permanently",
          "[security-stat-events]")
{
    auto store = std::make_shared<EventStore>();
    EventsFixture f(10, store);
    auto thresholds = DefaultSecurityStatisticThresholds();
    thresholds[0] = 1;
    f.statistics.SetReporter(&f.publisher, thresholds);

    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    store->available = false;
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    REQUIRE_FALSE(f.statistics.Retained());
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);

    store->available = true;
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    REQUIRE(f.statistics.Retained());
    REQUIRE(f.Select("7A 01 06") == IINField::Empty());
    REQUIRE(f.Write()
            == "E0 81 00 00 7A 01 28 04 00 "
               "00 00 01 00 00 01 00 00 00 "
               "00 00 01 00 00 02 00 00 00 "
               "00 00 41 00 00 03 00 00 00 "
               "00 00 41 00 00 04 00 00 00");
}

TEST_CASE("SecurityStatEvents - reporting never resets authentication maxima", "[security-stat-events]")
{
    EventsFixture f;
    auto thresholds = DefaultSecurityStatisticThresholds();
    thresholds[2] = 2;
    f.statistics.SetReporter(&f.publisher, thresholds);
    f.Increment(SecurityStatistic::AUTHENTICATION_FAILURES, 6);
    REQUIRE(f.events.NumEvents(EventClass::EC1) == 3);
    REQUIRE(f.statistics.Maximum(SecurityStatistic::AUTHENTICATION_FAILURES) == 5);
    REQUIRE(f.statistics.Exceeded(SecurityStatistic::AUTHENTICATION_FAILURES));
}

TEST_CASE("SecurityStatEvents - forced authentication failures at real session key change", "[security-stat-events]")
{
    EventsFixture f;
    f.Increment(SecurityStatistic::AUTHENTICATION_FAILURES);
    REQUIRE(f.events.NumEvents(EventClass::EC1) == 0);
    f.statistics.SessionKeysChanged();
    REQUIRE(f.events.NumEvents(EventClass::EC1) == 1);
    REQUIRE(f.Select("7A 01 06") == IINField::Empty());
    REQUIRE(f.Write() == "E0 81 00 00 7A 01 28 01 00 02 00 41 00 00 01 00 00 00");
    REQUIRE(f.statistics.Value(SecurityStatistic::UPDATE_KEY_CHANGES) == 0);
    REQUIRE(f.statistics.Value(SecurityStatistic::FAILED_UPDATE_KEY_CHANGES) == 0);
    f.Increment(SecurityStatistic::RESTART_REKEYS, 5);
    REQUIRE(f.statistics.Value(SecurityStatistic::RESTART_REKEYS) == 0);
}

TEST_CASE("SecurityStatEvents - rollover is not discontinuity", "[security-stat-events]")
{
    auto store = std::make_shared<EventStore>();
    store->saved[0] = std::numeric_limits<uint32_t>::max() - 1;
    EventsFixture f(10, store);
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES, 3);
    REQUIRE(f.Select("7A 01 06") == IINField::Empty());
    REQUIRE(f.Write() == "E0 81 00 00 7A 01 28 01 00 00 00 01 00 00 01 00 00 00");
}

TEST_CASE("SecurityStatEvents - zero capacity preserves baseline and pending state", "[security-stat-events]")
{
    EventsFixture f(0);
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES, 3);
    REQUIRE(f.statistics.ReportPending(SecurityStatistic::UNEXPECTED_MESSAGES));
    f.statistics.RequireReport(SecurityStatistic::UNEXPECTED_MESSAGES);
    f.statistics.RequireReport(SecurityStatistic::UNEXPECTED_MESSAGES);
    REQUIRE(f.events.NumEvents(EventClass::EC1) == 0);
    REQUIRE_FALSE(f.events.IsOverflown());
    EventBuffer accepted(EventsFixture::Capacity(2));
    SecurityStatEventPublisher publisher({}, f.application, accepted, [] {});
    f.statistics.SetReporter(&publisher, DefaultSecurityStatisticThresholds());
    REQUIRE(accepted.NumEvents(EventClass::EC1) == 0); // Never poll/re-time history.
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    REQUIRE(accepted.NumEvents(EventClass::EC1) == 1);
    REQUIRE_FALSE(f.statistics.ReportPending(SecurityStatistic::UNEXPECTED_MESSAGES));
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES);
    REQUIRE(accepted.NumEvents(EventClass::EC1) == 1);
}

TEST_CASE("SecurityStatEvents - bounded overflow drops oldest same-type event", "[security-stat-events]")
{
    EventsFixture f(1);
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES, 6);
    REQUIRE(f.events.NumEvents(EventClass::EC1) == 1);
    REQUIRE(f.events.IsOverflown());
    REQUIRE_FALSE(f.statistics.ReportPending(SecurityStatistic::UNEXPECTED_MESSAGES));
    REQUIRE(f.Select("7A 01 06") == IINField::Empty());
    REQUIRE(f.Write() == "E0 81 00 00 7A 01 28 01 00 00 00 41 00 00 06 00 00 00");
    f.events.ClearWritten();
    REQUIRE_FALSE(f.events.IsOverflown());
}

TEST_CASE("SecurityStatEvents - V1 works without synchronization or absolute occurrence time", "[security-stat-events]")
{
    for (auto time : {DNPTime(), DNPTime(123, TimestampQuality::UNSYNCHRONIZED), DNPTime(0x1000000000000ULL)})
    {
        EventsFixture f;
        f.application.currentTime = time;
        f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES, 3);
        REQUIRE(f.events.NumEvents(EventClass::EC1) == 1);
        REQUIRE_FALSE(f.statistics.ReportPending(SecurityStatistic::UNEXPECTED_MESSAGES));
        REQUIRE(f.Select("7A 01 06") == IINField::Empty());
        REQUIRE(f.Write() == "E0 81 00 00 7A 01 28 01 00 00 00 41 00 00 03 00 00 00");
    }
}

TEST_CASE("SecurityStatEvents - permitted qualifiers and indexed selection", "[security-stat-events]")
{
    for (const auto& request : {"7A 00 00 00 00", "7A 00 01 00 00 00 00", "7A 00 06",
                               "7A 00 17 01 00", "7A 00 28 01 00 00 00",
                               "7A 01 06", "7A 01 07 01", "7A 01 08 01 00",
                               "7A 02 06", "7A 02 07 01", "7A 02 08 01 00"})
    {
        EventsFixture f;
        f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES, 3);
        REQUIRE(f.Select(request) == IINField::Empty());
        REQUIRE(f.events.HasAnySelection());
    }
    EventsFixture f;
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES, 3);
    f.Increment(SecurityStatistic::AUTHORIZATION_FAILURES, 5);
    REQUIRE(f.Select("7A 00 17 03 01 00 01") == IINField::Empty());
    REQUIRE(f.Write() == "E0 81 00 00 7A 01 28 02 00 00 00 41 00 00 03 00 00 00 01 00 41 00 00 05 00 00 00");
    REQUIRE(f.Select("7A 00 00 01 01") == IINField::Empty());
    REQUIRE(f.Write() == "E0 81 00 00 7A 01 28 01 00 01 00 41 00 00 05 00 00 00");
    REQUIRE(f.Select("7A 00 17 01 12").IsSet(IINBit::PARAM_ERROR));
}

TEST_CASE("SecurityStatEvents - rejects forbidden and malformed READ headers", "[security-stat-events]")
{
    EventsFixture f;
    for (const auto& request : {"7A 00 07 01", "7A 00 08 01 00", "7A 01 00 00 01",
                               "7A 02 01 00 00 01 00", "7A 01 17 01 00", "7A 02 28 01 00 00 00",
                               "7A 01 5B 01 00 00", "7A 00 17 01", "7A 00 01 00", "7A 02 08 01"})
    {
        HexSequence bytes(request);
        ReadHandler handler(f.database, f.events);
        REQUIRE(APDUParser::Parse(bytes.ToRSeq(), handler, nullptr, ParserSettings::NoContents()) != ParseResult::OK);
    }
}

TEST_CASE("SecurityStatEvents - class configuration and limited class polling", "[security-stat-events]")
{
    for (auto clazz : {PointClass::Class1, PointClass::Class2, PointClass::Class3})
    {
        auto config = NativeEvents::Config();
        config.securityStatConfig[0].clazz = clazz;
        config.securityStatConfig[0].evariation = EventSecurityStatVariation::Group122Var2;
        NativeEvents f(config);
        f.Generate();
        const auto poll = clazz == PointClass::Class1 ? "C0 01 3C 02 07 01"
                        : clazz == PointClass::Class2 ? "C0 01 3C 03 07 01" : "C0 01 3C 04 07 01";
        f.outstation.SendToOutstation(poll);
        REQUIRE(f.outstation.lower->PopWriteAsHex()
                == "E0 81 80 00 7A 02 28 01 00 00 00 41 00 00 03 00 00 00 01 02 03 04 05 06");
    }
    for (auto clazz : {PointClass::Class0, static_cast<PointClass>(0xFF)})
    {
        auto config = NativeEvents::Config();
        config.securityStatConfig[0].clazz = clazz;
        REQUIRE_THROWS_AS(OutstationTestObject(config), std::invalid_argument);
    }
}

TEST_CASE("SecurityStatEvents - matching and incorrect solicited confirmations", "[security-stat-events]")
{
    NativeEvents f;
    f.Generate();
    f.outstation.SendToOutstation("C0 01 7A 01 06");
    const auto event = f.outstation.lower->PopWriteAsHex();
    REQUIRE(event == "E0 81 80 00 7A 01 28 01 00 00 00 41 00 00 03 00 00 00");
    f.outstation.OnTxReady();
    f.outstation.SendToOutstation("C1 00"); // Wrong sequence.
    f.outstation.SendToOutstation("D0 00"); // Wrong UNS bit.
    f.outstation.SendToOutstation("C1 01 7A 01 06");
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "E1" + event.substr(2));
    f.outstation.OnTxReady();
    f.outstation.SendToOutstation("C1 00");
    f.outstation.SendToOutstation("C2 01 7A 01 06");
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "C2 81 80 00");
}

TEST_CASE("SecurityStatEvents - solicited timeout late confirm and reconnect retain events", "[security-stat-events]")
{
    NativeEvents f;
    f.Generate();
    f.outstation.SendToOutstation("C0 01 7A 02 06");
    const auto event = f.outstation.lower->PopWriteAsHex();
    f.outstation.OnTxReady();
    f.outstation.AdvanceTime(TimeDuration::Seconds(10));
    f.outstation.SendToOutstation("C0 00"); // Expired, must not remove.
    f.outstation.LowerLayerDown();
    f.outstation.LowerLayerUp();
    f.outstation.application->currentTime = DNPTime(999);
    f.outstation.SendToOutstation("C1 01 7A 02 06");
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "E1" + event.substr(2));
    f.outstation.OnTxReady();
    f.outstation.SendToOutstation("C1 00");
    f.outstation.SendToOutstation("C2 01 7A 02 06");
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "C2 81 80 00");
}

TEST_CASE("SecurityStatEvents - unsolicited retries preserve occurrence and remove on confirm", "[security-stat-events]")
{
    auto config = NativeEvents::Config();
    config.params.allowUnsolicited = true;
    config.params.unsolClassMask = ClassField::AllEventClasses();
    config.securityStatConfig[0].evariation = EventSecurityStatVariation::Group122Var2;
    NativeEvents f(config);
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "F0 82 80 00");
    f.outstation.OnTxReady();
    f.outstation.SendToOutstation("D0 00");
    f.Generate();
    REQUIRE(f.outstation.lower->HasNoData()); // Occurrence callback does not transmit recursively.
    f.outstation.AdvanceTime(TimeDuration::Milliseconds(1)); // Drain posted native scheduling work.
    const auto event = f.outstation.lower->PopWriteAsHex();
    REQUIRE(event == "F1 82 80 00 7A 02 28 01 00 00 00 41 00 00 03 00 00 00 01 02 03 04 05 06");
    f.outstation.OnTxReady();
    f.outstation.application->currentTime = DNPTime(999);
    f.outstation.SendToOutstation("D2 00");
    f.outstation.AdvanceTime(config.params.unsolConfirmTimeout);
    REQUIRE(f.outstation.lower->PopWriteAsHex() == event);
    f.outstation.OnTxReady();
    f.outstation.SendToOutstation("D1 00");
    f.outstation.SendToOutstation("C0 01 7A 02 06");
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "C0 81 80 00");
}

TEST_CASE("SecurityStatEvents - limited count leaves unselected events", "[security-stat-events]")
{
    NativeEvents f;
    f.Generate(); f.Generate();
    f.outstation.SendToOutstation("C0 01 7A 01 07 01");
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "E0 81 82 00 7A 01 28 01 00 00 00 41 00 00 03 00 00 00");
    f.outstation.OnTxReady(); f.outstation.SendToOutstation("C0 00");
    f.outstation.SendToOutstation("C1 01 7A 01 08 01 00");
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "E1 81 80 00 7A 01 28 01 00 00 00 41 00 00 06 00 00 00");
}

TEST_CASE("SecurityStatEvents - fragmented response uses native confirmation lifecycle", "[security-stat-events]")
{
    auto config = NativeEvents::Config();
    config.params.maxTxFragSize = 249;
    NativeEvents f(config);
    for (int n = 0; n < 20; ++n) f.Generate();
    f.outstation.SendToOutstation("C0 01 7A 02 06");
    auto first = f.outstation.lower->PopWriteAsHex();
    REQUIRE(first.substr(0, 14) == "A0 81 82 00 7A");
    REQUIRE(first.find("01 02 03 04 05 06") != std::string::npos);
    f.outstation.OnTxReady();
    f.outstation.SendToOutstation("C0 00");
    auto last = f.outstation.lower->PopWriteAsHex();
    REQUIRE(last.substr(0, 14) == "61 81 80 00 7A");
    REQUIRE(last.find("01 02 03 04 05 06") != std::string::npos);
    f.outstation.OnTxReady(); f.outstation.SendToOutstation("C1 00");
    f.outstation.SendToOutstation("C2 01 7A 02 06");
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "C2 81 80 00");
}

TEST_CASE("SecurityStatEvents - independent Outstation contexts", "[security-stat-events]")
{
    NativeEvents a, b;
    a.Generate();
    b.outstation.SendToOutstation("C0 01 7A 01 06");
    REQUIRE(b.outstation.lower->PopWriteAsHex() == "C0 81 80 00");
    a.outstation.SendToOutstation("C0 01 7A 01 06");
    REQUIRE(a.outstation.lower->PopWriteAsHex() == "E0 81 80 00 7A 01 28 01 00 00 00 41 00 00 03 00 00 00");
}

TEST_CASE("SecurityStatEvents - class poll restores configured variation after explicit READ", "[security-stat-events]")
{
    NativeEvents f;
    f.Generate();
    f.outstation.SendToOutstation("C0 01 7A 02 06");
    REQUIRE(f.outstation.lower->PopWriteAsHex().find("7A 02") != std::string::npos);
    f.outstation.OnTxReady();
    f.outstation.AdvanceTime(TimeDuration::Seconds(10));
    f.outstation.SendToOutstation("C1 01 3C 02 06");
    REQUIRE(f.outstation.lower->PopWriteAsHex()
            == "E1 81 80 00 7A 01 28 01 00 00 00 41 00 00 03 00 00 00");
}

TEST_CASE("SecurityStatEvents - storage validates every own-association index", "[security-stat-events]")
{
    EventBuffer events(EventsFixture::Capacity(18));
    const auto value = SecurityStat(0, Flags(0xFF), 0, DNPTime(123));
    for (uint16_t n = 0; n < 18; ++n)
        REQUIRE(events.Update(Event<SecurityStatSpec>(value, n, EventClass::EC1, EventSecurityStatVariation::Group122Var1)));
    REQUIRE(events.NumEvents(EventClass::EC1) == 18);
    REQUIRE_FALSE(events.Update(Event<SecurityStatSpec>(value, 18, EventClass::EC1, EventSecurityStatVariation::Group122Var1)));
    auto foreign = value;
    foreign.associationId = 7;
    REQUIRE_FALSE(events.Update(Event<SecurityStatSpec>(foreign, 0, EventClass::EC1, EventSecurityStatVariation::Group122Var1)));
    REQUIRE_FALSE(events.Update(Event<SecurityStatSpec>(value, 0, static_cast<EventClass>(3), EventSecurityStatVariation::Group122Var1)));
}

TEST_CASE("SecurityStatEvents - real secured context receive and transmit accounting publishes", "[security-stat-events]")
{
    struct Credentials final : IAuthenticationCredentials
    {
        bool ReadUpdateKey(uint16_t, uint16_t user, uint8_t* output, size_t capacity, uint64_t& lifetime) override
        {
            for (size_t n = 0; n < capacity; ++n) output[n] = static_cast<uint8_t>(n + user);
            lifetime = 600000;
            return true;
        }
    };
    struct Deny final : IAuthenticationAuthorization
    {
        bool IsAuthorized(uint16_t, uint16_t, uint8_t, const uint8_t*, size_t) const override { return false; }
    };
    auto config = NativeEvents::Config();
    config.params.authentication.credentials = std::make_shared<Credentials>();
    config.params.authentication.authorization = std::make_shared<Deny>();
    config.securityStatThresholds[5] = config.securityStatThresholds[6] = 1;
    OutstationTestObject t(config);
    t.application->currentTime = DNPTime(123);
    t.LowerLayerUp();
    REQUIRE(SecurityStatEventTestAccess::Count(t.context) == 0);
    t.SendToOutstation("C0 20 78 04 07 01 01 00"); // Real user's Key Status request, not a forged counter update.
    REQUIRE(t.lower->PopWriteAsHex().find("83") != std::string::npos);
    REQUIRE(SecurityStatEventTestAccess::Count(t.context) == 2); // Actual RX and lower-layer-accepted TX.
}

TEST_CASE("SecurityStatEvents - G121 static READ does not consume pending events", "[security-stat-events]")
{
    EventsFixture f;
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES, 3);
    f.database.SetSecurityStatistics(f.statistics.CaptureStaticSnapshot());
    REQUIRE(f.Select("79 01 06") == IINField::Empty());
    REQUIRE_FALSE(f.events.HasAnySelection());
    REQUIRE(f.events.NumEvents(EventClass::EC1) == 1);
    REQUIRE(f.Select("3C 01 06") == IINField::Empty());
    REQUIRE_FALSE(f.events.HasAnySelection());
    REQUIRE(f.events.NumEvents(EventClass::EC1) == 1);
}

TEST_CASE("SecurityStatEvents - unavailable time falls back for V0 and all event classes", "[security-stat-events]")
{
    for (const auto& request : {"C0 01 7A 00 06", "C0 01 3C 02 06", "C0 01 3C 03 06", "C0 01 3C 04 06"})
    {
        auto config = NativeEvents::Config();
        config.securityStatConfig[0].evariation = EventSecurityStatVariation::Group122Var2;
        if (std::string(request).find("3C 03") != std::string::npos) config.securityStatConfig[0].clazz = PointClass::Class2;
        if (std::string(request).find("3C 04") != std::string::npos) config.securityStatConfig[0].clazz = PointClass::Class3;
        NativeEvents f(config);
        f.outstation.application->currentTime = DNPTime();
        f.Generate();
        REQUIRE_FALSE(f.statistics.ReportPending(SecurityStatistic::UNEXPECTED_MESSAGES));
        f.outstation.application->currentTime = DNPTime(999); // Cannot retrofit this event's time.
        f.outstation.SendToOutstation(request);
        REQUIRE(f.outstation.lower->PopWriteAsHex() == "E0 81 80 00 7A 01 28 01 00 00 00 41 00 00 03 00 00 00");
        f.outstation.OnTxReady(); f.outstation.SendToOutstation("C0 00");
        f.outstation.SendToOutstation("C1 01 7A 01 06");
        REQUIRE(f.outstation.lower->PopWriteAsHex() == "C1 81 80 00");
    }
}

TEST_CASE("SecurityStatEvents - explicit V2 retains untimed events without substitution", "[security-stat-events]")
{
    NativeEvents f;
    f.outstation.application->currentTime = DNPTime();
    f.Generate();
    for (const auto& request : {"C0 01 7A 02 06", "C1 01 7A 02 07 01", "C2 01 7A 02 08 01 00"})
    {
        const auto sequence = std::string(request).substr(1, 1);
        f.outstation.SendToOutstation(request);
        REQUIRE(f.outstation.lower->PopWriteAsHex() == "C" + sequence + " 81 82 00");
        f.outstation.OnTxReady();
        f.outstation.SendToOutstation("C" + sequence + " 00"); // No event was written; CONFIRM cannot remove it.
        REQUIRE(SecurityStatEventTestAccess::Count(f.outstation.context) == 1);
        f.outstation.application->currentTime = DNPTime(999);
    }
    f.outstation.SendToOutstation("C3 01 7A 01 06");
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "E3 81 80 00 7A 01 28 01 00 00 00 41 00 00 03 00 00 00");
    f.outstation.OnTxReady(); f.outstation.SendToOutstation("C3 00");
    REQUIRE(SecurityStatEventTestAccess::Count(f.outstation.context) == 0);
}

TEST_CASE("SecurityStatEvents - V2 stops before untimed prefix and preserves occurrence order", "[security-stat-events]")
{
    NativeEvents f;
    f.Generate(); // Value 3, captured absolute time.
    f.outstation.application->currentTime = DNPTime();
    f.Generate(); // Value 6, no time.
    f.outstation.application->currentTime = DNPTime(999);
    f.Generate(); // Value 9, cannot pass value 6 in a V2 response.
    f.outstation.SendToOutstation("C0 01 7A 02 06");
    REQUIRE(f.outstation.lower->PopWriteAsHex()
            == "E0 81 82 00 7A 02 28 01 00 00 00 41 00 00 03 00 00 00 01 02 03 04 05 06");
    f.outstation.OnTxReady(); f.outstation.SendToOutstation("C0 00");
    f.outstation.SendToOutstation("C1 01 7A 02 06");
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "C1 81 82 00");
    f.outstation.OnTxReady();
    REQUIRE(SecurityStatEventTestAccess::Count(f.outstation.context) == 2);
    f.outstation.SendToOutstation("C2 01 3C 02 06");
    REQUIRE(f.outstation.lower->PopWriteAsHex()
            == "E2 81 80 00 7A 01 28 02 00 00 00 41 00 00 06 00 00 00 00 00 41 00 00 09 00 00 00");
    f.outstation.OnTxReady(); f.outstation.SendToOutstation("C2 00");
    REQUIRE(SecurityStatEventTestAccess::Count(f.outstation.context) == 0);
}

TEST_CASE("SecurityStatEvents - usable unsynchronized UTC and application NEED_TIME", "[security-stat-events]")
{
    for (bool needTime : {false, true})
    {
        for (auto clazz : {PointClass::Class1, PointClass::Class2, PointClass::Class3})
        {
            auto config = NativeEvents::Config();
            config.securityStatConfig[0].clazz = clazz;
            config.securityStatConfig[0].evariation = EventSecurityStatVariation::Group122Var2;
            NativeEvents f(config);
            f.outstation.application->currentTime = DNPTime(0x060504030201ULL, TimestampQuality::UNSYNCHRONIZED);
            f.outstation.application->appIIN.needTime = needTime;
            f.Generate();
            REQUIRE_FALSE(f.statistics.ReportPending(SecurityStatistic::UNEXPECTED_MESSAGES));
            f.outstation.application->currentTime = DNPTime(999); // Source now synchronized; old event stays immutable.
            const auto request = clazz == PointClass::Class1 ? "C0 01 3C 02 06"
                               : clazz == PointClass::Class2 ? "C0 01 3C 03 06" : "C0 01 3C 04 06";
            f.outstation.SendToOutstation(request);
            const std::string expected = std::string("E0 81 ") + (needTime ? "90" : "80")
                + " 00 7A 02 28 01 00 00 00 41 00 00 03 00 00 00 01 02 03 04 05 06";
            REQUIRE(f.outstation.lower->PopWriteAsHex() == expected);
            f.outstation.OnTxReady();
            f.outstation.AdvanceTime(TimeDuration::Seconds(10));
            f.outstation.SendToOutstation("C1 01 7A 02 07 01");
            REQUIRE(f.outstation.lower->PopWriteAsHex() == "E1" + expected.substr(2));
            f.outstation.OnTxReady(); f.outstation.SendToOutstation("C1 00");
            REQUIRE(SecurityStatEventTestAccess::Count(f.outstation.context) == 0);
        }
    }
}

TEST_CASE("SecurityStatEvents - untimed unsolicited retry remains V1 after synchronization", "[security-stat-events]")
{
    auto config = NativeEvents::Config();
    config.params.allowUnsolicited = true;
    config.params.unsolClassMask = ClassField::AllEventClasses();
    config.securityStatConfig[0].evariation = EventSecurityStatVariation::Group122Var2;
    NativeEvents f(config);
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "F0 82 80 00");
    f.outstation.OnTxReady(); f.outstation.SendToOutstation("D0 00");
    f.outstation.application->currentTime = DNPTime();
    f.outstation.application->appIIN.needTime = true;
    f.Generate();
    f.outstation.AdvanceTime(TimeDuration::Milliseconds(1));
    const auto event = f.outstation.lower->PopWriteAsHex();
    REQUIRE(event == "F1 82 90 00 7A 01 28 01 00 00 00 41 00 00 03 00 00 00");
    f.outstation.OnTxReady();
    f.outstation.application->currentTime = DNPTime(999);
    f.outstation.SendToOutstation("D2 00"); // Wrong confirm cannot remove.
    f.outstation.AdvanceTime(config.params.unsolConfirmTimeout);
    REQUIRE(f.outstation.lower->PopWriteAsHex() == event);
    f.outstation.OnTxReady(); f.outstation.SendToOutstation("D1 00");
    REQUIRE(SecurityStatEventTestAccess::Count(f.outstation.context) == 0);
}

TEST_CASE("SecurityStatEvents - clock exception cannot reject untimed events", "[security-stat-events]")
{
    struct FailedClock final : IDnpTimeSource
    {
        DNPTime Now() override { throw std::runtime_error("clock unavailable"); }
    } clock;
    EventsFixture f;
    SecurityStatEventPublisher publisher({}, clock, f.events, [] {});
    f.statistics.SetReporter(&publisher, DefaultSecurityStatisticThresholds());
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES, 3);
    REQUIRE_FALSE(f.statistics.ReportPending(SecurityStatistic::UNEXPECTED_MESSAGES));
    REQUIRE(f.Select("7A 00 06") == IINField::Empty());
    REQUIRE(f.Write() == "E0 81 00 00 7A 01 28 01 00 00 00 41 00 00 03 00 00 00");
    REQUIRE(f.Select("7A 02 06") == IINField::Empty());
    REQUIRE_FALSE(f.events.HasAnySelection());
}

TEST_CASE("SecurityStatEvents - no-time rejection is only native capacity rejection", "[security-stat-events]")
{
    EventsFixture f(0);
    f.application.currentTime = DNPTime();
    f.Increment(SecurityStatistic::UNEXPECTED_MESSAGES, 3);
    REQUIRE(f.statistics.ReportPending(SecurityStatistic::UNEXPECTED_MESSAGES));
    REQUIRE(f.events.NumEvents(EventClass::EC1) == 0);
    REQUIRE_FALSE(f.events.IsOverflown());
}

TEST_CASE("SecurityStatEvents - unsolicited usable unsynchronized time survives retry", "[security-stat-events]")
{
    auto config = NativeEvents::Config();
    config.params.allowUnsolicited = true;
    config.params.unsolClassMask = ClassField::AllEventClasses();
    config.securityStatConfig[0].evariation = EventSecurityStatVariation::Group122Var2;
    NativeEvents f(config);
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "F0 82 80 00");
    f.outstation.OnTxReady(); f.outstation.SendToOutstation("D0 00");
    f.outstation.application->currentTime = DNPTime(0x060504030201ULL, TimestampQuality::UNSYNCHRONIZED);
    f.outstation.application->appIIN.needTime = true;
    f.Generate();
    f.outstation.AdvanceTime(TimeDuration::Milliseconds(1));
    const auto event = f.outstation.lower->PopWriteAsHex();
    REQUIRE(event == "F1 82 90 00 7A 02 28 01 00 00 00 41 00 00 03 00 00 00 01 02 03 04 05 06");
    f.outstation.OnTxReady();
    f.outstation.application->currentTime = DNPTime(); // Losing the clock cannot alter a buffered event.
    f.outstation.AdvanceTime(config.params.unsolConfirmTimeout);
    REQUIRE(f.outstation.lower->PopWriteAsHex() == event);
    f.outstation.OnTxReady(); f.outstation.SendToOutstation("D1 00");
    f.outstation.SendToOutstation("C0 01 7A 02 06");
    REQUIRE(f.outstation.lower->PopWriteAsHex() == "C0 81 90 00");
}
