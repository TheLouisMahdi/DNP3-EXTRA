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

#include "Group34.h"

#include "app/parsing/DNPTimeParsing.h"
#include <ser4cpp/serialization/LittleEndian.h>
#include "app/MeasurementFactory.h"
#include "app/WriteConversions.h"

using namespace ser4cpp;

namespace opendnp3 {

// ------- Group34Var1 -------

Group34Var1::Group34Var1() : value(0)
{}

bool Group34Var1::Read(rseq_t& buffer, Group34Var1& output)
{
  return LittleEndian::read(buffer, output.value);
}

bool Group34Var1::Write(const Group34Var1& arg, ser4cpp::wseq_t& buffer)
{
  return LittleEndian::write(buffer, arg.value);
}

bool Group34Var1::ReadTarget(rseq_t& buff, AnalogDeadband& output)
{
  Group34Var1 value;
  if(Read(buff, value))
  {
    output = AnalogDeadbandFactory::From(value.value);
    return true;
  }
  else
  {
    return false;
  }
}

bool Group34Var1::WriteTarget(const AnalogDeadband& value, ser4cpp::wseq_t& buff)
{
  return Group34Var1::Write(ConvertGroup34Var1::Apply(value), buff);
}

// ------- Group34Var2 -------

Group34Var2::Group34Var2() : value(0)
{}

bool Group34Var2::Read(rseq_t& buffer, Group34Var2& output)
{
  return LittleEndian::read(buffer, output.value);
}

bool Group34Var2::Write(const Group34Var2& arg, ser4cpp::wseq_t& buffer)
{
  return LittleEndian::write(buffer, arg.value);
}

bool Group34Var2::ReadTarget(rseq_t& buff, AnalogDeadband& output)
{
  Group34Var2 value;
  if(Read(buff, value))
  {
    output = AnalogDeadbandFactory::From(value.value);
    return true;
  }
  else
  {
    return false;
  }
}

bool Group34Var2::WriteTarget(const AnalogDeadband& value, ser4cpp::wseq_t& buff)
{
  return Group34Var2::Write(ConvertGroup34Var2::Apply(value), buff);
}

// ------- Group34Var3 -------

Group34Var3::Group34Var3() : value(0.0)
{}

bool Group34Var3::Read(rseq_t& buffer, Group34Var3& output)
{
  return LittleEndian::read(buffer, output.value);
}

bool Group34Var3::Write(const Group34Var3& arg, ser4cpp::wseq_t& buffer)
{
  return LittleEndian::write(buffer, arg.value);
}

bool Group34Var3::ReadTarget(rseq_t& buff, AnalogDeadband& output)
{
  Group34Var3 value;
  if(Read(buff, value))
  {
    output = AnalogDeadbandFactory::From(value.value);
    return true;
  }
  else
  {
    return false;
  }
}

bool Group34Var3::WriteTarget(const AnalogDeadband& value, ser4cpp::wseq_t& buff)
{
  return Group34Var3::Write(ConvertGroup34Var3::Apply(value), buff);
}


}
