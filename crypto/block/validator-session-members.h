/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TOS Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include <vector>

#include "auto/tl/tos_api.h"
#include "tos/tos-types.h"

namespace block {

// The members a consensus session commits to.
//
// A post-quantum member carries both of its identities: the stable one saying which
// validator this is, and the one naming the consensus key it currently holds. That is
// what makes a key rotation start a different session while leaving the validator the
// same member of the set. A classical member keeps the identity derived from its key,
// so existing sessions are unchanged.
//
// The two forms are separate constructors of one boxed type, so their encodings carry
// distinct ids and a classical member can never be read as a post-quantum one.
std::vector<tos::tl_object_ptr<tos::tos_api::engine_validator_GroupMember>> validator_session_members(
    const std::vector<tos::ValidatorDescr>& nodes);

}  // namespace block
