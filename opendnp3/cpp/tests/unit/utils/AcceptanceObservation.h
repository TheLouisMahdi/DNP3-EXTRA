// Licensed under the Apache License, Version 2.0.
#ifndef OPENDNP3_TESTS_ACCEPTANCE_OBSERVATION_H
#define OPENDNP3_TESTS_ACCEPTANCE_OBSERVATION_H

#include <cstdlib>
#include <iostream>
#include <locale>
#include <sstream>
#include <string>

namespace acceptance
{
inline bool Selected(const char* vector)
{
    const char* selected = std::getenv("DNP3_ACCEPTANCE_VECTOR");
    return selected == nullptr || std::string(selected) == vector;
}

// Only synthetic, public APDU octets and allowlisted numeric observations are
// emitted by these cases. This fixture deliberately uses Compatibility mode.
template<class T> void Observe(const std::string& name, T value)
{
    if (std::getenv("DNP3_ACCEPTANCE_SCENARIO") != nullptr)
    {
        std::ostringstream line;
        line.imbue(std::locale::classic());
        line << "DNP3-ACCEPTANCE {\"check\":\"" << name << "\",\"value\":" << +value << '}';
        std::cout << line.str() << std::endl;
    }
}

} // namespace acceptance

#endif
