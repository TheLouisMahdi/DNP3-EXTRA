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
#include "RequestHistory.h"

namespace opendnp3
{

RequestHistory::RequestHistory(size_t capacity) : hasLast(false), lastObjects(capacity), lastObjectsLength(0) {}

void RequestHistory::Reset()
{
    hasLast = false;
}

void RequestHistory::RecordLastProcessedRequest(const APDUHeader& header, const ser4cpp::rseq_t& objects)
{
    hasLast = objects.length() <= lastObjects.length();
    if (!hasLast) return;
    if (objects.is_not_empty()) lastObjects.as_wslice().copy_from(objects);
    lastHeader = header;
    lastObjectsLength = objects.length();
}

bool RequestHistory::FullyEqualsLastRequest(const APDUHeader& header, const ser4cpp::rseq_t& objects) const
{
    return lastHeader.Equals(header) && EqualsLastObjects(objects);
}

APDUHeader RequestHistory::GetLastHeader() const
{
    return hasLast ? lastHeader : APDUHeader();
}

bool RequestHistory::EqualsLastObjects(const ser4cpp::rseq_t& objects) const
{
    return hasLast && objects.length() == lastObjectsLength
        && (lastObjectsLength == 0 || lastObjects.as_rslice().take(lastObjectsLength).equals(objects));
}

} // namespace opendnp3
