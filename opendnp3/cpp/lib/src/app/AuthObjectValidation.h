/*
 * Copyright 2013-2020 Automatak, LLC
 *
 * Licensed to Green Energy Corp (www.greenenergycorp.com) and Automatak
 * LLC (www.automatak.com) under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership. Green Energy Corp and Automatak LLC license
 * this file to you under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License. You may obtain
 * a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef OPENDNP3_AUTHOBJECTVALIDATION_H
#define OPENDNP3_AUTHOBJECTVALIDATION_H
#include "gen/objects/Group120.h"
namespace opendnp3
{
// Wire validation only; this does not authenticate values or select algorithms.
bool IsValidAuthObject(const Group120Var1& value);
bool IsValidAuthObject(const Group120Var2& value);
bool IsValidAuthObject(const Group120Var7& value);
bool IsValidAuthObject(const Group120Var5& value);
bool IsValidAuthObject(const Group120Var6& value);
bool IsValidAuthObject(const Group120Var8& value);
bool IsValidAuthObject(const Group120Var9& value);
bool IsValidAuthObject(const Group120Var10& value);
bool IsValidAuthObject(const Group120Var11& value);
bool IsValidAuthObject(const Group120Var12& value);
bool IsValidAuthObject(const Group120Var13& value);
bool IsValidAuthObject(const Group120Var14& value);
bool IsValidAuthObject(const Group120Var15& value);

template<class T> bool IsValidFreeFormatObject(const T& value)
{
    return IsValidAuthObject(value);
}

}
#endif
