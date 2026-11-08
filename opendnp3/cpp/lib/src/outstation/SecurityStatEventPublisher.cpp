// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "outstation/SecurityStatEventPublisher.h"

#include <stdexcept>
#include <utility>

namespace opendnp3
{
SecurityStatEventPublisher::SecurityStatEventPublisher(const std::array<SecurityStatConfig, 18>& config_,
    IDnpTimeSource& clock_, IEventReceiver& receiver_, std::function<void()> accepted_)
    : config(config_), clock(clock_), receiver(receiver_), accepted(std::move(accepted_))
{
    for (const auto& point : config)
    {
        if ((point.clazz != PointClass::Class1 && point.clazz != PointClass::Class2
             && point.clazz != PointClass::Class3)
            || (point.evariation != EventSecurityStatVariation::Group122Var1
                && point.evariation != EventSecurityStatVariation::Group122Var2))
            throw std::invalid_argument("G122 requires Class 1/2/3 and variation 1/2");
    }
}

bool SecurityStatEventPublisher::Report(SecurityStatistic statistic, uint32_t value, uint8_t flags)
{
    return ReportAt(statistic, value, flags, CaptureOccurrenceTime());
}

DNPTime SecurityStatEventPublisher::CaptureOccurrenceTime()
{
    try { return clock.Now(); } catch (...) { return DNPTime(); }
}

bool SecurityStatEventPublisher::ReportAt(SecurityStatistic statistic, uint32_t value, uint8_t flags,
                                          const DNPTime& time)
{
    const auto index = static_cast<size_t>(statistic);
    if (index >= config.size()) return false;
    const auto& point = config[index];
    const auto clazz = point.clazz == PointClass::Class1 ? EventClass::EC1
                     : point.clazz == PointClass::Class2 ? EventClass::EC2 : EventClass::EC3;
    SecurityStat snapshot(value, Flags(flags & 0x5F), 0, time);
    // Table 11-19 permits untimed reporting. Preserve usable absolute occurrence
    // time even when its accuracy is uncertain; NEED_TIME belongs to the application.
    // Without time, ordinary Class/V0 reporting uses V1. Explicit V2 selection
    // must retain this snapshot rather than substitute V1 or reconstruct a time.
    if (!snapshot.HasTime()) snapshot.time = DNPTime();
    const auto variation = snapshot.HasTime() ? point.evariation : EventSecurityStatVariation::Group122Var1;
    if (!receiver.Update(Event<SecurityStatSpec>(snapshot, static_cast<uint16_t>(index), clazz, variation)))
        return false;
    // Acceptance is final; notification failure must not cause a duplicate.
    try { accepted(); } catch (...) {}
    return true;
}
} // namespace opendnp3
