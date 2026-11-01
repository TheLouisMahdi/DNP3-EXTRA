// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#ifndef OPENDNP3_AGGRESSIVEMODE_H
#define OPENDNP3_AGGRESSIVEMODE_H
#include <ser4cpp/container/SequenceTypes.h>

#include <array>
namespace opendnp3
{
// Authentication-mode helper, not a dispatcher. Seeds come ONLY from an existing
// successfully completed Challenge/Reply exchange. Runtime owns user eligibility,
// session validity, authorization and the explicit transmit/receive enable policy.
class AggressiveMode final
{
public:
    static constexpr size_t MAX_APDU = 2048;
    AggressiveMode(uint16_t association, size_t tagLength, bool monitoringDirection);
    ~AggressiveMode();
    AggressiveMode(const AggressiveMode&) = delete;
    AggressiveMode& operator=(const AggressiveMode&) = delete;
    void Reset();
    bool RememberChallenge(ser4cpp::rseq_t challenge, bool unsolicited);
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
    uint32_t Sequence() const
    {
        return sequence;
    }

private:
    struct History
    {
        std::array<uint8_t, MAX_APDU> apdu{};
        size_t size = 0;
        uint32_t sequence = 0, challengeSequence = 0;
    };
    const uint16_t association;
    const size_t tagLength;
    const bool monitoringDirection;
    std::array<History, 2> history{};
    std::array<uint8_t, 2 * MAX_APDU> scratch{};
    uint32_t sequence = 0;
    bool haveSequence = false;
};
} // namespace opendnp3
#endif
