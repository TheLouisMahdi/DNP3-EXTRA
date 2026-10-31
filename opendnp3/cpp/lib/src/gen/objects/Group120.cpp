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

#include "Group120.h"

#include "app/parsing/DNPTimeParsing.h"
#include <ser4cpp/serialization/EndianHelpers.h>
#include "app/parsing/PrefixFields.h"
#include <ser4cpp/serialization/LittleEndian.h>

using namespace ser4cpp;

namespace opendnp3 {

// ------- Group120Var1 -------

Group120Var1::Group120Var1() : 
  seqNum(0), userNum(0), macAlgorithm(0), reason(0)
{}

Group120Var1::Group120Var1(
  uint32_t seqNum_,
  uint16_t userNum_,
  uint8_t macAlgorithm_,
  uint8_t reason_,
  const ser4cpp::rseq_t& challengeData_
) : 
  seqNum(seqNum_),
  userNum(userNum_),
  macAlgorithm(macAlgorithm_),
  reason(reason_),
  challengeData(challengeData_)
{}

size_t Group120Var1::Size() const
{
  return MIN_SIZE + challengeData.length();
}

bool Group120Var1::Read(const rseq_t& buffer)
{
  if(buffer.length() < Group120Var1::MIN_SIZE)
  {
    return false;
  }

  rseq_t copy(buffer); //mutable copy for parsing

  LittleEndian::read(copy, this->seqNum, this->userNum, this->macAlgorithm, this->reason);
  this->challengeData = copy; // whatever is left over
  return true;
}

bool Group120Var1::Write(ser4cpp::wseq_t& buffer) const
{
  if(this->Size() > buffer.length())
  {
    return false;
  }

  LittleEndian::write(buffer, this->seqNum, this->userNum, this->macAlgorithm, this->reason);
  buffer.copy_from(challengeData);
  return true;
}

// ------- Group120Var2 -------

Group120Var2::Group120Var2() : 
  seqNum(0), userNum(0)
{}

Group120Var2::Group120Var2(
  uint32_t seqNum_,
  uint16_t userNum_,
  const ser4cpp::rseq_t& hmacValue_
) : 
  seqNum(seqNum_),
  userNum(userNum_),
  hmacValue(hmacValue_)
{}

size_t Group120Var2::Size() const
{
  return MIN_SIZE + hmacValue.length();
}

bool Group120Var2::Read(const rseq_t& buffer)
{
  if(buffer.length() < Group120Var2::MIN_SIZE)
  {
    return false;
  }

  rseq_t copy(buffer); //mutable copy for parsing

  LittleEndian::read(copy, this->seqNum, this->userNum);
  this->hmacValue = copy; // whatever is left over
  return true;
}

bool Group120Var2::Write(ser4cpp::wseq_t& buffer) const
{
  if(this->Size() > buffer.length())
  {
    return false;
  }

  LittleEndian::write(buffer, this->seqNum, this->userNum);
  buffer.copy_from(hmacValue);
  return true;
}

// ------- Group120Var7 -------

Group120Var7::Group120Var7() : 
  seqNum(0), userNum(0), associationId(0), errorCode(0), time(0)
{}

Group120Var7::Group120Var7(
  uint32_t seqNum_,
  uint16_t userNum_,
  uint16_t associationId_,
  uint8_t errorCode_,
  DNPTime time_,
  const ser4cpp::rseq_t& errorText_
) : 
  seqNum(seqNum_),
  userNum(userNum_),
  associationId(associationId_),
  errorCode(errorCode_),
  time(time_),
  errorText(errorText_)
{}

size_t Group120Var7::Size() const
{
  return MIN_SIZE + errorText.length();
}

bool Group120Var7::Read(const rseq_t& buffer)
{
  if(buffer.length() < Group120Var7::MIN_SIZE)
  {
    return false;
  }

  rseq_t copy(buffer); //mutable copy for parsing

  LittleEndian::read(copy, this->seqNum, this->userNum, this->associationId, this->errorCode, this->time);
  this->errorText = copy; // whatever is left over
  return true;
}

bool Group120Var7::Write(ser4cpp::wseq_t& buffer) const
{
  if(this->Size() > buffer.length())
  {
    return false;
  }

  LittleEndian::write(buffer, this->seqNum, this->userNum, this->associationId, this->errorCode, this->time);
  buffer.copy_from(errorText);
  return true;
}


}
