// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_AUTHENTICATIONSTATUS_H
#define OPENDNP3_AUTHENTICATIONSTATUS_H
#include <array>
#include <cstddef>
#include <cstdint>
namespace opendnp3
{
// Read-only diagnostics, with no keys, MACs or credential bytes. Readiness is
// time-bounded session state, never an authorization grant.
struct AuthenticationStatus
{
    struct User
    {
        uint16_t number = 0;
        bool ready = false;
        bool exchanging = false;
        uint32_t remainingMessages = 0;
    };
    bool available = false;
    uint16_t association = 0;
    bool updateKeyBusy = false;
    uint16_t updateKeyOwner = 0;
    size_t size = 0;
    std::array<User, 16> users{};
    std::array<uint32_t, 18> statistics{};
};
}
#endif
