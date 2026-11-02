// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_AGGRESSIVEMODE_H
#define OPENDNP3_AGGRESSIVEMODE_H
#include "auth/AuthenticationMAC.h"

#include <ser4cpp/container/SequenceTypes.h>

#include <array>
namespace opendnp3
{
struct Group120Var1;
// Authentication-mode helper, not a dispatcher. Seeds come from a completed
// Challenge/Reply exchange or an authenticated embedded Challenge. Runtime owns user eligibility,
// session validity, authorization and the explicit transmit/receive enable policy.
class AggressiveMode final
{
public:
    static constexpr size_t MAX_APDU = 2048;
    AggressiveMode(uint16_t association, size_t tagLength, bool monitoringDirection, uint8_t macAlgorithm = 0);
    ~AggressiveMode();
    AggressiveMode(const AggressiveMode&) = delete;
    AggressiveMode& operator=(const AggressiveMode&) = delete;
    bool ConfigureMACs(const AuthenticationConfig& config) { return macPolicy.Configure(config); }
    void Reset();
    bool RememberChallenge(ser4cpp::rseq_t challenge, bool unsolicited, bool embedded = false, uint8_t envelopeAlgorithm = 0);
    // Inspect a normal response, including the V3/.../V1/V9 arrangement. No trust
    // is granted here: the runtime must authenticate the entire response first.
    bool InspectEmbeddedChallenge(ser4cpp::rseq_t response, Group120Var1& challenge, size_t& nativeSize, uint8_t envelopeAlgorithm = 0) const;
    bool HasPendingConfirm() const;
    bool RequiresConfirm(uint8_t appSequence, bool unsolicited) const;
    void DiscardPendingConfirms();
    bool HasChallenge(bool unsolicited) const;
    // Metadata is untrusted: this is only for choosing a configured user's key.
    static bool InspectUser(ser4cpp::rseq_t apdu, bool monitoringDirection, uint16_t& user);
    bool Create(uint16_t association,
                uint16_t user,
                ser4cpp::rseq_t key,
                ser4cpp::rseq_t original,
                ser4cpp::wseq_t output,
                size_t& size);
    bool Verify(uint16_t association,
                uint16_t user,
                ser4cpp::rseq_t key,
                ser4cpp::rseq_t apdu,
                ser4cpp::wseq_t output,
                size_t& size);
    uint8_t Algorithm(bool unsolicited) const { return history[unsolicited ? 1 : 0].algorithm; }
    uint32_t Sequence() const
    {
        return sequence;
    }

private:
    struct History
    {
        std::array<uint8_t, MAX_APDU> apdu{};
        size_t size = 0;
        uint8_t algorithm = 0;
        uint32_t sequence = 0, challengeSequence = 0;
        bool haveChallenge = false, confirmPending = false;
    };
    const uint16_t association;
    const size_t tagLength;
    const uint8_t macAlgorithm;
    AuthenticationMACPolicy macPolicy;
    const bool monitoringDirection;
    std::array<History, 2> history{};
    std::array<uint8_t, 2 * MAX_APDU> scratch{};
    uint32_t sequence = 0;
    bool haveSequence = false;
};
} // namespace opendnp3
#endif
