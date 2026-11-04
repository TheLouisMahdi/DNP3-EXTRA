//
//  _   _         ______    _ _ _   _             _ _ _
// | \ | |       |  ____|  | (_) | (_)           | | | |
// |  \| | ___   | |__   __| |_| |_ _ _ __   __ _| | | |
// | . ` |/ _ \  |  __| / _` | | __| | '_ \ / _` | | | |
// | |\  | (_) | | |___| (_| | | |_| | | | | (_| |_|_|_|
// |_| \_|\___/  |______\__,_|_|\__|_|_| |_|\__, (_|_|_)
//                                           __/ |
//                                          |___/
//
// This file is auto-generated. Do not edit manually
//
// Copyright 2013-2020 Automatak, LLC
//
// Licensed to Green Energy Corp (www.greenenergycorp.com) and Automatak
// LLC (www.automatak.com) under one or more contributor license agreements.
// See the NOTICE file distributed with this work for additional information
// regarding copyright ownership. Green Energy Corp and Automatak LLC license
// this file to you under the Apache License, Version 2.0 (the "License"); you
// may not use this file except in compliance with the License. You may obtain
// a copy of the License at:
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#ifndef OPENDNP3_GROUP34_H
#define OPENDNP3_GROUP34_H

#include "opendnp3/app/GroupVariationID.h"
#include <ser4cpp/container/SequenceTypes.h>
#include "opendnp3/app/DNPTime.h"
#include "app/DNP3Serializer.h"
#include "opendnp3/app/AnalogDeadband.h"

namespace opendnp3 {

// Analog Input Deadband - Any Variation
struct Group34Var0
{
  static GroupVariationID ID() { return GroupVariationID(34,0); }
};

// Analog Input Deadband - 16-bit
struct Group34Var1
{
  static GroupVariationID ID() { return GroupVariationID(34,1); }

  Group34Var1();

  static size_t Size() { return 2; }
  static bool Read(ser4cpp::rseq_t&, Group34Var1&);
  static bool Write(const Group34Var1&, ser4cpp::wseq_t&);

  typedef uint16_t ValueType;
  uint16_t value;

  typedef AnalogDeadband Target;
  static bool ReadTarget(ser4cpp::rseq_t&, AnalogDeadband&);
  static bool WriteTarget(const AnalogDeadband&, ser4cpp::wseq_t&);
  static DNP3Serializer<AnalogDeadband> Inst() { return DNP3Serializer<AnalogDeadband>(ID(), Size(), &ReadTarget, &WriteTarget); }
};

// Analog Input Deadband - 32-bit
struct Group34Var2
{
  static GroupVariationID ID() { return GroupVariationID(34,2); }

  Group34Var2();

  static size_t Size() { return 4; }
  static bool Read(ser4cpp::rseq_t&, Group34Var2&);
  static bool Write(const Group34Var2&, ser4cpp::wseq_t&);

  typedef uint32_t ValueType;
  uint32_t value;

  typedef AnalogDeadband Target;
  static bool ReadTarget(ser4cpp::rseq_t&, AnalogDeadband&);
  static bool WriteTarget(const AnalogDeadband&, ser4cpp::wseq_t&);
  static DNP3Serializer<AnalogDeadband> Inst() { return DNP3Serializer<AnalogDeadband>(ID(), Size(), &ReadTarget, &WriteTarget); }
};

// Analog Input Deadband - Single-precision floating point
struct Group34Var3
{
  static GroupVariationID ID() { return GroupVariationID(34,3); }

  Group34Var3();

  static size_t Size() { return 4; }
  static bool Read(ser4cpp::rseq_t&, Group34Var3&);
  static bool Write(const Group34Var3&, ser4cpp::wseq_t&);

  typedef float ValueType;
  float value;

  typedef AnalogDeadband Target;
  static bool ReadTarget(ser4cpp::rseq_t&, AnalogDeadband&);
  static bool WriteTarget(const AnalogDeadband&, ser4cpp::wseq_t&);
  static DNP3Serializer<AnalogDeadband> Inst() { return DNP3Serializer<AnalogDeadband>(ID(), Size(), &ReadTarget, &WriteTarget); }
};


}

#endif
