// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_OUTSTATIONCHALLENGER_H
#define OPENDNP3_OUTSTATIONCHALLENGER_H

#include "auth/AuthenticationMAC.h"

#include "gen/objects/Group120.h"

#include "opendnp3/app/AppConstants.h"
#include "opendnp3/app/IINField.h"

#include <array>

namespace opendnp3
{

// Internal, single-threaded, unconnected to request dispatch. One instance per
// association. Callers supply monotonic milliseconds; no host clock is used.
// IEEE 1815-2012 7.5.2.1/Table 7-5: at most one authentication is pending.
// A.45.1.2.2: an Outstation challenges USR=0; the Reply selects the user's key.
// User-specific key validity is separate from association-wide pending/CSQ state.
// monitoringDirection reuses the same core for Master-issued challenges (USR=1).
class OutstationChallenger final
{
public:
    enum class State
    {
        NO_SESSION_KEYS,
        IDLE,
        WAITING_FOR_REPLY
    };
    enum class Result
    {
        OK,
        AUTHENTICATED,
        NO_SESSION_KEYS,
        WRONG_ASSOCIATION,
        INVALID_INPUT,
        BUSY,
        UNEXPECTED_REPLY,
        INVALID_USER,
        INVALID_SEQUENCE,
        INVALID_MAC,
        EXPIRED,
        OUTPUT_TOO_SMALL,
        CRYPTO_ERROR
    };

    // Engineering bounds for this internal slice, not DNP3 limits.
    static constexpr size_t MAX_USERS = 2;
    static constexpr size_t MAX_REQUEST_SIZE = DEFAULT_MAX_APDU_SIZE;
    // IEEE Table 7-17 (PDF p288): 32-byte SHA256 challenge data.
    static constexpr size_t CHALLENGE_DATA_SIZE = 32;
    static constexpr size_t CHALLENGE_SIZE = 4 + 6 + 8 + CHALLENGE_DATA_SIZE;

    // Tag length 8/16 maps to MAL 3/4 (A.45.1.2.2). Reply timeout is in ms,
    // 100..120000 in steps of 100; default 2000 (7.6.1.4.1, PDF p284).
    explicit OutstationChallenger(uint16_t associationId,
                                  size_t tagLength = 16,
                                  uint32_t replyTimeoutMs = 2000,
                                  bool monitoringDirection = false,
                                  uint8_t macAlgorithm = 0);
    ~OutstationChallenger();
    OutstationChallenger(const OutstationChallenger&) = delete;
    OutstationChallenger& operator=(const OutstationChallenger&) = delete;

    // Trusted/test provisioning only: USR 1..65535, 16/32-byte Control Direction
    // key. No exchange, persistence or credential/role management is implemented.
    // A successful replacement cancels pending authentication; never reuse it
    // across a key change. validUntilMs is an injected session-validity deadline.
    Result SetSessionKey(uint16_t user, ser4cpp::rseq_t key, uint64_t validUntilMs, uint64_t nowMs);
    void Reset(); // wipes keys and pending state, but preserves CSQ (7.5.2.3.3).
    bool ConfigureMACs(const AuthenticationConfig& config)
    {
        if (requestSize) return false;
        const bool valid = macPolicy.Configure(config);
        macAlgorithm = valid ? ResolveAuthenticationMAC(config.macAlgorithm, config.tagLength) : 0;
        tagLength = AuthenticationTagLength(macAlgorithm);
        return valid;
    }
    void Tick(uint64_t nowMs);
    // Table 7-8 row 13: cancel only the exact outstanding Challenge, retaining keys/CSQ.
    bool MatchesError(const Group120Var7& error, uint8_t appSequence) const;
    bool CancelOnError(const Group120Var7& error, uint8_t appSequence, uint64_t nowMs);
    State GetState() const;
    uint8_t MACAlgorithm() const { return macAlgorithm; }
    ser4cpp::rseq_t LastAcceptedChallenge() const
    {
        return ser4cpp::rseq_t(acceptedChallenge.data(), acceptedSize);
    }
    bool LastChallengeWasUnsolicited() const
    {
        return acceptedUnsolicited;
    }
    void CancelPending()
    {
        ClearPending();
    }
    // Trusted caller invokes only after Aggressive Mode MAC verification.
    void ObserveAggressiveSequence(uint32_t value);

    // request is an already-classified critical Application Layer fragment,
    // INCLUDING its header, without transport/link bytes. No request is executed.
    // Emits a standalone G120V1 AUTH_RESPONSE, CON/UNS clear, echoing request SEQ.
    // The supplied IIN is frozen into the exact fragment used in the MAC.
    // Input and output views must be disjoint. Views are borrowed, not advanced.
    Result Challenge(uint16_t associationId,
                     ser4cpp::rseq_t request,
                     IINField iin,
                     uint64_t nowMs,
                     ser4cpp::wseq_t output,
                     size_t& outputSize);

    // Caller must already have validated AUTH_REQUEST framing, qualifier 0x5B,
    // and that G120V2 is its only object (A.45.2.1). No parser is duplicated here.
    // Only AUTHENTICATED publishes the exact pending request to output; that
    // result is one-shot and means authentication only, not role permission.
    // Every failure clears the caller's output and sets outputSize to zero.
    Result Reply(
        uint16_t associationId, const Group120Var2& reply, uint64_t nowMs, ser4cpp::wseq_t output, size_t& outputSize);

private:
    struct User
    {
        uint16_t number = 0;
        size_t keySize = 0;
        uint64_t validUntil = 0;
        std::array<uint8_t, 32> key{};
    };
    bool ObserveTime(uint64_t nowMs);
    void ClearPending();
    void ClearUser(User& user);
    bool HasKeys() const;
    User* FindUser(uint16_t user);

    const bool monitoringDirection;
    size_t challengeSize = 0;
    const uint16_t associationId;
    size_t tagLength;
    uint8_t macAlgorithm;
    AuthenticationMACPolicy macPolicy;
    const uint32_t replyTimeoutMs;
    std::array<User, MAX_USERS> users{};
    // Table A-3 (PDF p765): full Challenge fragment || full challenged fragment.
    // No addressing, Reply user field or application-added HMAC padding is added.
    std::array<uint8_t, CHALLENGE_SIZE + MAX_REQUEST_SIZE> transcript{};
    std::array<uint8_t, CHALLENGE_SIZE> acceptedChallenge{};
    size_t acceptedSize = 0;
    bool acceptedUnsolicited = false;
    bool pendingUnsolicited = false;
    size_t requestSize = 0;
    uint32_t pendingSequence = 0;
    uint32_t sequence = 0; // startup zero, independent of user; wraps modulo 2^32.
    uint64_t challengeTime = 0;
    uint64_t lastTime = 0;
};

} // namespace opendnp3
#endif
