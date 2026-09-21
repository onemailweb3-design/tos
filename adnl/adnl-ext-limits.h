/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <cstddef>

namespace tos::adnl {

inline constexpr std::size_t adnl_ext_max_packet_bytes = 1U << 24;
inline constexpr std::size_t adnl_ext_packet_framing_bytes = 64;

}  // namespace tos::adnl
