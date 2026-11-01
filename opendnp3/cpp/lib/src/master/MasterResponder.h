// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_MASTERRESPONDER_H
#define OPENDNP3_MASTERRESPONDER_H

#include "opendnp3/app/AppConstants.h"
#include "opendnp3/app/IINField.h"

#include <ser4cpp/container/SequenceTypes.h>

#include <array>

namespace opendnp3
{

// Internal, single-threaded, one association and one configured user per instance.
// No runtime dispatch, request execution, credential storage or key exchange.
// monitoringDirection reuses the engine as the Outstation Monitoring responder.
// Callers provide monotonic milliseconds and already-classified critical requests.
class MasterResponder final
{
public:
    enum class State
    {
        NO_SESSION_KEYS,
        IDLE,
        WAITING_FOR_CHALLENGE
    };
    enum class Result
    {
        OK,
        NO_SESSION_KEYS,
        WRONG_ASSOCIATION,
        INVALID_INPUT,
        BUSY,
        UNEXPECTED_CHALLENGE,
        INVALID_CHALLENGE,
        INVALID_USER,
        INVALID_SEQUENCE,
        UNSUPPORTED_ALGORITHM,
        EXPIRED,
        OUTPUT_TOO_SMALL,
        CRYPTO_ERROR
    };

    // Engineering memory bounds; not protocol limits. One pending request.
    static constexpr size_t MAX_REQUEST_SIZE = DEFAULT_MAX_APDU_SIZE;
    static constexpr size_t MAX_CHALLENGE_SIZE = DEFAULT_MAX_APDU_SIZE;

    // Expected tag length 8/16 -> MAL 3/4; no implicit algorithm downgrade.
    // Local pending lifetime in ms: 100..120000, steps of 100, default 2000.
    explicit MasterResponder(uint16_t associationId,
                             size_t tagLength = 16,
                             uint32_t pendingTimeoutMs = 2000,
                             bool monitoringDirection = false,
                             uint8_t macAlgorithm = 0);
    ~MasterResponder();
    MasterResponder(const MasterResponder&) = delete;
    MasterResponder& operator=(const MasterResponder&) = delete;

    // Trusted/test material: USR 1..65535 and 16/32-byte Control Direction key.
    // Installing material cancels the pending request, including on failure.
    // newSession clears CSQ history only after verified installation of fresh keys.
    Result SetSessionKey(
        uint16_t user, ser4cpp::rseq_t key, uint64_t validUntilMs, uint64_t nowMs, bool newSession = false);
    Result RetainRequest(uint16_t associationId, ser4cpp::rseq_t request, uint64_t nowMs);

    // Accepts a complete, standalone AUTH_RESPONSE fragment with exactly one
    // G120V1 object (0x5B, USR=0, reason=CRITICAL), using the existing parser.
    // Emits a complete AUTH_REQUEST/G120V2. OK means Reply produced, not that
    // the peer authenticated or authorized the operation. Input/output disjoint.
    // Every failure clears output and sets outputSize=0. Association mismatches
    // do not alter this instance; other failures wipe its owned request and key.
    Result Respond(uint16_t associationId,
                   ser4cpp::rseq_t challenge,
                   uint64_t nowMs,
                   ser4cpp::wseq_t output,
                   size_t& outputSize,
                   IINField iin = IINField::Empty());

    void Tick(uint64_t nowMs);
    void Reset(); // wipes sensitive state; preserves association CSQ replay history.
    State GetState() const;
    ser4cpp::rseq_t LastAcceptedChallenge() const
    {
        return ser4cpp::rseq_t(acceptedChallenge.data(), acceptedSize);
    }
    bool LastChallengeWasUnsolicited() const
    {
        return acceptedUnsolicited;
    }

private:
    bool ObserveTime(uint64_t nowMs);
    bool Expired(uint64_t nowMs) const;
    Result Fail(Result result);
    void ClearRequest();

    const bool monitoringDirection;
    const uint16_t associationId;
    const size_t tagLength;
    const uint8_t macAlgorithm;
    const uint32_t pendingTimeoutMs;
    std::array<uint8_t, 32> key{};
    size_t keySize = 0;
    uint16_t user = 0;
    uint64_t validUntil = 0;
    // Original request retained at offset MAX_CHALLENGE_SIZE, then moved next
    // to the received Challenge for Table A-3 MAC calculation (IEEE PDF p765).
    std::array<uint8_t, MAX_CHALLENGE_SIZE + MAX_REQUEST_SIZE> transcript{};
    std::array<uint8_t, MAX_CHALLENGE_SIZE> acceptedChallenge{};
    size_t acceptedSize = 0;
    bool acceptedUnsolicited = false;
    size_t requestSize = 0;
    uint64_t requestTime = 0;
    uint64_t lastTime = 0;
    bool haveSequence = false;
    uint32_t lastSequence = 0;
};

} // namespace opendnp3
#endif
