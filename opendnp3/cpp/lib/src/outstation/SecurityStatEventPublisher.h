// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_SECURITYSTATEVENTPUBLISHER_H
#define OPENDNP3_SECURITYSTATEVENTPUBLISHER_H

#include "auth/AuthenticationStatistics.h"
#include "outstation/IEventReceiver.h"
#include "opendnp3/outstation/IDnpTimeSource.h"

#include <functional>

namespace opendnp3
{
// Owns configuration, not counters or event storage. Invoked at the reporting
// condition, before returning to authentication; scheduling is delegated to OContext.
class SecurityStatEventPublisher final : public IAuthenticationStatisticsReporter
{
public:
    SecurityStatEventPublisher(const std::array<SecurityStatConfig, 18>& config, IDnpTimeSource& clock,
                               IEventReceiver& receiver, std::function<void()> accepted);
    bool Report(SecurityStatistic statistic, uint32_t value, uint8_t flags) override;

private:
    const std::array<SecurityStatConfig, 18> config;
    IDnpTimeSource& clock;
    IEventReceiver& receiver;
    const std::function<void()> accepted;
};
} // namespace opendnp3
#endif
