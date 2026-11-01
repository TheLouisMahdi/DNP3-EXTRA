// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_AUTHENTICATIONSESSION_H
#define OPENDNP3_AUTHENTICATIONSESSION_H
#include "auth/SessionKeys.h"

#include "opendnp3/auth/AuthenticationConfig.h"

#include <memory>
namespace opendnp3
{
// One bounded credential/session table per association. The protocol state remains
// in SessionKeys and the existing challenge/responder engines.
class AuthenticationSession final
{
public:
    AuthenticationSession(SessionKeys::Role role, const AuthenticationConfig& config);
    bool Load(uint64_t now);
    SessionKeys* Find(uint16_t user);
    SessionKeys* At(size_t index);
    bool Authorize(uint16_t user, uint8_t function, uint64_t now, ser4cpp::rseq_t request = ser4cpp::rseq_t()) const;
    void Disconnect();
    const AuthenticationConfig config;

private:
    std::array<std::unique_ptr<SessionKeys>, 2> sessions;
};
} // namespace opendnp3
#endif
