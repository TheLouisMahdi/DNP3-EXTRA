// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_AUTHENTICATIONSESSION_H
#define OPENDNP3_AUTHENTICATIONSESSION_H
#include "auth/SessionKeys.h"
#include "auth/AuthenticationStatistics.h"

#include "opendnp3/auth/AuthenticationConfig.h"

#include <memory>
#include <vector>
namespace opendnp3
{
class RemoteUpdateKeys;
// One bounded credential/session table per association. The protocol state remains
// in SessionKeys and the existing challenge/responder engines.
class AuthenticationSession final
{
public:
    AuthenticationSession(SessionKeys::Role role, const AuthenticationConfig& config);
    ~AuthenticationSession();
    bool Load(uint64_t now);
    SessionKeys* Find(uint16_t user);
    SessionKeys* At(size_t index);
    size_t Size() const { return sessions.size(); }
    size_t Index(uint16_t user) const;
    bool Authorize(uint16_t user, uint8_t function, uint64_t now, ser4cpp::rseq_t request = ser4cpp::rseq_t()) const;
    void Disconnect();
    const AuthenticationConfig config;
    AuthenticationStatistics statistics;
    std::unique_ptr<RemoteUpdateKeys> remote;

private:
    std::vector<std::unique_ptr<SessionKeys>> sessions; // Allocated once, never on receive.
};
} // namespace opendnp3
#endif
