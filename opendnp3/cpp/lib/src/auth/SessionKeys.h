// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_SESSIONKEYS_H
#define OPENDNP3_SESSIONKEYS_H

#include "opendnp3/app/IINField.h"

#include <ser4cpp/container/SequenceTypes.h>

#include <array>

namespace opendnp3
{
// Internal session-key lifecycle for one (association,user). The owner serializes
// calls, supplies monotonic milliseconds, schedules retries, and counts auth ASDUs.
// No transport, credential persistence, authorization or runtime activation.
class SessionKeys final
{
public:
    enum class Role
    {
        MASTER,
        OUTSTATION
    };
    enum class Result
    {
        OK,
        INSTALLED,
        WRONG_ASSOCIATION,
        INVALID,
        EXPIRED,
        BUSY,
        NO_CREDENTIAL,
        CRYPTO_ERROR
    };
    struct Config
    {
        uint32_t intervalMs = 900000;
        uint32_t messageLimit = 1000;
        uint32_t replyTimeoutMs = 2000;
        uint8_t tagLength = 16;
    };
    static constexpr size_t MAX_APDU = 2048;
    static constexpr size_t MAX_STATUS = 1024;

    SessionKeys(Role role, uint16_t association, uint16_t user, const Config& config);
    ~SessionKeys();
    SessionKeys(const SessionKeys&) = delete;
    SessionKeys& operator=(const SessionKeys&) = delete;

    // Copies an externally provisioned 32-byte Update Key. Replacement wipes all
    // session state. Expiry is an absolute monotonic deadline, never a default key.
    Result Configure(ser4cpp::rseq_t updateKey, uint64_t credentialExpiry, uint64_t now);
    bool NeedsExchange(uint64_t now);
    Result Begin(uint16_t association, uint8_t appSequence, uint64_t now, ser4cpp::wseq_t output, size_t& size);
    Result Process(uint16_t association,
                   ser4cpp::rseq_t apdu,
                   uint64_t now,
                   ser4cpp::wseq_t output,
                   size_t& size,
                   IINField iin = IINField::Empty());
    void Tick(uint64_t now);
    void CountAuthentication(uint64_t now);
    void Disconnect(); // invalidates authorization; keeps configured Update Key
    void Reset();      // wipes credentials and all owned secrets
    bool Ready(uint64_t now);
    ser4cpp::rseq_t ControlKey(uint64_t now);
    ser4cpp::rseq_t MonitoringKey(uint64_t now);
    uint64_t ValidUntil() const
    {
        return validUntil;
    }
    uint16_t User() const
    {
        return user;
    }
    uint32_t Sequence() const
    {
        return ksq;
    }

private:
    enum class Phase
    {
        IDLE,
        STATUS,
        CONFIRM
    };
    bool Observe(uint64_t now);
    bool ValidConfig() const;
    void ClearPending();
    void RetainRecovery();
    void Invalidate();
    Result Fail(Result result, uint64_t now);
    bool MakeStatus(
        uint8_t appSequence, uint8_t status, uint64_t now, ser4cpp::wseq_t output, size_t& size, IINField iin);
    bool CheckStatusMAC(const struct Group120Var5& value, ser4cpp::rseq_t key, ser4cpp::rseq_t transcript) const;
    const Role role;
    const uint16_t association;
    const uint16_t user;
    const Config config;
    std::array<uint8_t, 32> update{};
    std::array<uint8_t, 32> control{};
    std::array<uint8_t, 32> monitoring{};
    std::array<uint8_t, 64> candidate{};
    std::array<uint8_t, MAX_STATUS> statusBytes{}; // V5 fields, without MAC
    std::array<uint8_t, MAX_APDU> lastChange{};    // last accepted complete V6 APDU
    std::array<uint8_t, MAX_APDU> pendingChange{};
    std::array<uint8_t, 32> recoveryMonitoring{};
    std::array<uint8_t, MAX_APDU> recoveryChange{};
    size_t recoverySize = 0;
    size_t statusSize = 0;
    size_t lastChangeSize = 0;
    size_t pendingChangeSize = 0;
    size_t keySize = 0;
    bool configured = false;
    bool valid = false;
    bool haveMonitoring = false;
    bool awaitingChange = false;
    bool haveKSQ = false;
    uint32_t ksq = 0;
    uint32_t messages = 0;
    uint64_t credentialExpiry = 0;
    uint64_t validUntil = 0;
    uint64_t lastTime = 0;
    uint64_t deadline = 0;
    uint64_t nextAttempt = 0;
    uint8_t appSequence = 0;
    uint8_t attempts = 0;
    Phase phase = Phase::IDLE;
};
} // namespace opendnp3
#endif
