// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "crypto/CryptoProvider.h"
#include "master/MasterResponder.h"
#include "outstation/OutstationChallenger.h"
#include "utils/BufferHelpers.h"

#include <catch.hpp>

#include <array>

using namespace opendnp3;
using namespace ser4cpp;
namespace
{
struct EphemeralKey
{
    std::array<uint8_t, 32> bytes{};
    EphemeralKey()
    {
        REQUIRE(crypto::GenerateRandom(wseq_t(bytes.data(), bytes.size())) == crypto::Result::OK);
    }
    ~EphemeralKey()
    {
        crypto::Clear(wseq_t(bytes.data(), bytes.size()));
    }
    rseq_t Read() const
    {
        return rseq_t(bytes.data(), bytes.size());
    }
};
} // namespace
TEST_CASE("AuthenticationDirections - Monitoring key authenticates complete solicited and unsolicited responses",
          "[auth-directions]")
{
    const auto algorithm = GENERATE(2, 3, 4, 5);
    const auto tag = algorithm == 2 ? 10 : (algorithm == 4 ? 16 : 8);
    const auto unsolicited = GENERATE(false, true);
    EphemeralKey monitoring;
    OutstationChallenger master(7, tag, 2000, true, algorithm);
    MasterResponder outstation(7, tag, 2000, true, algorithm);
    REQUIRE(master.SetSessionKey(1, monitoring.Read(), 10000, 1000) == OutstationChallenger::Result::OK);
    REQUIRE(outstation.SetSessionKey(1, monitoring.Read(), 10000, 1000) == MasterResponder::Result::OK);
    HexSequence original(unsolicited ? "D5 82 80 00" : "C5 81 80 00");
    REQUIRE(outstation.RetainRequest(7, original.ToRSeq(), 1000) == MasterResponder::Result::OK);
    std::array<uint8_t, 2048> challenge{}, reply{}, authorized{};
    size_t nc = 0, nr = 0, na = 0;
    REQUIRE(
        master.Challenge(7, original.ToRSeq(), IINField::Empty(), 1000, wseq_t(challenge.data(), challenge.size()), nc)
        == OutstationChallenger::Result::OK);
    REQUIRE(nc == 48);
    REQUIRE(challenge[0] == 0xC5);
    REQUIRE(challenge[1] == 0x20);
    Group120Var1 value;
    REQUIRE(value.Read(rseq_t(challenge.data() + 8, nc - 8)));
    REQUIRE(value.userNum == 1);
    REQUIRE(value.macAlgorithm == algorithm);
    REQUIRE(outstation.Respond(7, rseq_t(challenge.data(), nc), 1000, wseq_t(reply.data(), reply.size()), nr,
                               IINField(0x80, 0))
            == MasterResponder::Result::OK);
    REQUIRE(nr == static_cast<size_t>(16 + tag));
    REQUIRE(reply[0] == 0xC5);
    REQUIRE(reply[1] == 0x83);
    REQUIRE(reply[2] == 0x80);
    REQUIRE(reply[3] == 0);
    Group120Var2 response;
    REQUIRE(response.Read(rseq_t(reply.data() + 10, nr - 10)));
    REQUIRE(master.Reply(7, response, 1000, wseq_t(authorized.data(), authorized.size()), na)
            == OutstationChallenger::Result::AUTHENTICATED);
    REQUIRE(rseq_t(authorized.data(), na).equals(original.ToRSeq()));
    REQUIRE(master.Reply(7, response, 1000, wseq_t(authorized.data(), authorized.size()), na)
            == OutstationChallenger::Result::UNEXPECTED_REPLY);
}
TEST_CASE("AuthenticationDirections - IIN tampering user and direction confusion fail closed", "[auth-directions]")
{
    EphemeralKey monitoring, control;
    OutstationChallenger master(7, 16, 2000, true);
    MasterResponder outstation(7, 16, 2000, true);
    REQUIRE(master.SetSessionKey(1, monitoring.Read(), 10000, 1000) == OutstationChallenger::Result::OK);
    HexSequence original("C5 81 80 00"), modified("C5 81 00 00");
    const auto fault = GENERATE(0, 1, 2);
    REQUIRE(outstation.SetSessionKey(fault == 1 ? 2 : 1, fault == 2 ? control.Read() : monitoring.Read(), 10000, 1000)
            == MasterResponder::Result::OK);
    REQUIRE(outstation.RetainRequest(7, fault == 0 ? modified.ToRSeq() : original.ToRSeq(), 1000)
            == MasterResponder::Result::OK);
    std::array<uint8_t, 2048> challenge{}, reply{}, authorized{};
    size_t nc = 0, nr = 0, na = 0;
    REQUIRE(
        master.Challenge(7, original.ToRSeq(), IINField::Empty(), 1000, wseq_t(challenge.data(), challenge.size()), nc)
        == OutstationChallenger::Result::OK);
    const auto result
        = outstation.Respond(7, rseq_t(challenge.data(), nc), 1000, wseq_t(reply.data(), reply.size()), nr);
    if (fault == 1)
        REQUIRE(result == MasterResponder::Result::INVALID_USER);
    else
    {
        REQUIRE(result == MasterResponder::Result::OK);
        Group120Var2 response;
        REQUIRE(response.Read(rseq_t(reply.data() + 10, nr - 10)));
        REQUIRE(master.Reply(7, response, 1000, wseq_t(authorized.data(), authorized.size()), na)
                == OutstationChallenger::Result::INVALID_MAC);
        REQUIRE(na == 0);
    }
}

TEST_CASE("AuthenticationDirections - unsolicited confirm and fragmented response can be retained", "[auth-directions]")
{
    EphemeralKey key;
    MasterResponder master(7, 16), outstation(7, 16, 2000, true);
    REQUIRE(master.SetSessionKey(1, key.Read(), 10000, 1000) == MasterResponder::Result::OK);
    REQUIRE(outstation.SetSessionKey(1, key.Read(), 10000, 1000) == MasterResponder::Result::OK);
    HexSequence confirm("D5 00"), fragment("A5 81 80 00");
    REQUIRE(master.RetainRequest(7, confirm.ToRSeq(), 1000) == MasterResponder::Result::OK);
    REQUIRE(outstation.RetainRequest(7, fragment.ToRSeq(), 1000) == MasterResponder::Result::OK);
}
