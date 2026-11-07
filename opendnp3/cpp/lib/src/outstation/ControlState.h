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
#ifndef OPENDNP3_CONTROLSTATE_H
#define OPENDNP3_CONTROLSTATE_H

#include "app/AppSeqNum.h"
#include "opendnp3/app/AppConstants.h"
#include "opendnp3/gen/FunctionCode.h"
#include <ser4cpp/container/Buffer.h>

#include "opendnp3/gen/CommandStatus.h"
#include "opendnp3/util/Timestamp.h"

namespace opendnp3
{

///
/// Represent all of the mutable state for SBO controls
///
class ControlState
{

public:
    explicit ControlState(size_t capacity = DEFAULT_MAX_APDU_SIZE) : selectedObjects(capacity) {}

    // Also prevents an authenticated retry from replacing the original SELECT owner.
    bool IsSelectSequence(const AppSeqNum& seq) const
    {
        return selected && expectedSeq.Equals(seq.Next());
    }

    // Table 4-9 applies only after native authentication/authorization admission.
    // A changed same-sequence SELECT is discarded without replacing the timer.
    bool OnRequest(FunctionCode function, const AppSeqNum& seq, const ser4cpp::rseq_t& objects)
    {
        if (!selected) return true;
        if (function == FunctionCode::SELECT)
        {
            if (IsSelectSequence(seq))
                return selectedObjects.as_rslice().take(length).equals(objects);
            Unselect();
        }
        else if (function != FunctionCode::OPERATE &&
                 function != FunctionCode::CONFIRM)
            Unselect();
        return true;
    }

    CommandStatus ValidateSelection(const AppSeqNum& seq,
                                    const Timestamp& now,
                                    const TimeDuration& timeout,
                                    const ser4cpp::rseq_t& objects) const
    {
        if (selected && expectedSeq.Equals(seq))
        {
            if (selectTime <= now)
            {
                auto elapsed = now - selectTime;
                if (elapsed < timeout)
                {
                    if (selectedObjects.as_rslice().take(length).equals(objects))
                    {
                        return CommandStatus::SUCCESS;
                    }
                    else
                    {
                        return CommandStatus::NO_SELECT;
                    }
                }
                else
                {
                    return CommandStatus::TIMEOUT;
                }
            }
            else
            {
                return CommandStatus::TIMEOUT;
            }
        }
        else
        {
            return CommandStatus::NO_SELECT;
        }
    }

    void Select(const AppSeqNum& currentSeqN, const Timestamp& now, const ser4cpp::rseq_t& objects)
    {
        selected = objects.is_not_empty() && objects.length() <= selectedObjects.length();
        if (!selected) return;
        selectedObjects.as_wslice().copy_from(objects);
        selectTime = now;
        expectedSeq = currentSeqN.Next();
        length = objects.length();
    }

    void Unselect()
    {
        selected = false;
    }

private:
    bool selected = false;
    AppSeqNum expectedSeq;
    Timestamp selectTime;
    ser4cpp::Buffer selectedObjects;
    size_t length = 0;
};

} // namespace opendnp3

#endif
