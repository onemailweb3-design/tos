/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "adnl/adnl-ext-limits.h"
#include "auto/tl/tos_api.h"
#include "overlay/overlays.h"
#include "tl-utils/tl-utils.hpp"

namespace {

[[noreturn]] void fail(const std::string& text) {
  std::fprintf(stderr, "%s\n", text.c_str());
  std::exit(1);
}

std::vector<std::string> fields(const std::string& line) {
  std::vector<std::string> out;
  std::istringstream input(line);
  std::string field;
  while (std::getline(input, field, '\t')) {
    out.push_back(std::move(field));
  }
  return out;
}

std::size_t number(const std::string& text, const std::string& context) {
  std::size_t end = 0;
  const auto value = std::stoull(text, &end);
  if (end != text.size()) {
    fail("ROUTE_INVENTORY_BAD_NUMBER: " + context + " value=" + text);
  }
  return value;
}

std::size_t answer_boxing_bytes() {
  td::BufferSlice aligned_payload(4);
  const auto serialized =
      tos::create_serialize_tl_object<tos::tos_api::adnl_message_answer>(td::Bits256{}, std::move(aligned_payload));
  return serialized.size() - 4;
}

std::size_t actual_constant(const std::string& name) {
  if (name == "overlay::Overlays::max_fec_broadcast_size") {
    return tos::overlay::Overlays::max_fec_broadcast_size();
  }
  if (name == "adnl::adnl_ext_max_packet_bytes") {
    return tos::adnl::adnl_ext_max_packet_bytes;
  }
  if (name == "adnl::adnl_ext_packet_framing_bytes") {
    return tos::adnl::adnl_ext_packet_framing_bytes;
  }
  if (name == "tos_api::adnl_message_answer.aligned_boxing_bytes") {
    return answer_boxing_bytes();
  }
  fail("ROUTE_INVENTORY_UNKNOWN_CONSTANT: " + name);
}

std::string source_needle(const std::string& name) {
  if (name == "overlay::Overlays::max_fec_broadcast_size") {
    return "max_fec_broadcast_size";
  }
  if (name == "adnl::adnl_ext_max_packet_bytes") {
    return "adnl_ext_max_packet_bytes";
  }
  if (name == "adnl::adnl_ext_packet_framing_bytes") {
    return "adnl_ext_packet_framing_bytes";
  }
  if (name == "tos_api::adnl_message_answer.aligned_boxing_bytes") {
    return "adnl.message.answer";
  }
  fail("ROUTE_INVENTORY_UNKNOWN_SOURCE_NEEDLE: " + name);
}

void check_source(const std::string& relative_path, const std::string& constant) {
  std::ifstream input(std::string(SOURCE_ROOT) + "/" + relative_path);
  if (!input) {
    fail("ROUTE_INVENTORY_SOURCE_MISSING: " + relative_path);
  }
  const std::string contents{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
  if (contents.find(source_needle(constant)) == std::string::npos) {
    fail("ROUTE_INVENTORY_SOURCE_DRIFT: " + relative_path + " no longer names " + constant);
  }
}

std::map<std::size_t, std::size_t> measured_object_sizes() {
  std::ifstream input(MEASUREMENTS_FILE);
  if (!input) {
    fail("ROUTE_INVENTORY_MISSING_MEASUREMENTS");
  }
  std::map<std::size_t, std::size_t> result;
  std::string line;
  while (std::getline(input, line)) {
    if (line.empty() || line[0] == '#' || line.rfind("signers\t", 0) == 0) {
      continue;
    }
    auto row = fields(line);
    if (row.size() == 11 && row[3] != "REFUSED") {
      result.emplace(number(row[0], "measurement signers"), number(row[3], "measurement BOC"));
    }
  }
  return result;
}

}  // namespace

int main() {
  std::ifstream input(ROUTES_FILE);
  if (!input) {
    fail("ROUTE_INVENTORY_MISSING");
  }

  std::map<std::string, std::size_t> capacities;
  std::map<std::string, std::size_t> expected_minima;
  struct Verdict {
    std::string route;
    std::size_t signers;
    std::size_t object_bytes;
    std::string result;
    std::size_t margin;
  };
  std::vector<Verdict> verdicts;
  std::size_t layers = 0;
  std::string line;
  while (std::getline(input, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    const auto row = fields(line);
    if (row[0] == "layer") {
      if (row.size() != 8 || (row[3] != "limit" && row[3] != "overhead")) {
        fail("ROUTE_INVENTORY_BAD_LAYER: " + line);
      }
      const auto recorded = number(row[6], row[5]);
      check_source(row[4], row[5]);
      const auto actual = actual_constant(row[5]);
      if (actual != recorded) {
        std::ostringstream error;
        error << "ROUTE_CONSTANT_MISMATCH: " << row[5] << " recorded=" << recorded << " actual=" << actual;
        fail(error.str());
      }
      auto [it, inserted] = capacities.emplace(row[1], std::numeric_limits<std::size_t>::max());
      if (row[3] == "limit") {
        it->second = std::min(it->second, recorded);
      } else {
        if (it->second == std::numeric_limits<std::size_t>::max() || recorded > it->second) {
          fail("ROUTE_INVENTORY_BAD_OVERHEAD_ORDER: " + row[1]);
        }
        it->second -= recorded;
      }
      ++layers;
    } else if (row[0] == "minimum") {
      if (row.size() != 3 || !expected_minima.emplace(row[1], number(row[2], row[1])).second) {
        fail("ROUTE_INVENTORY_BAD_MINIMUM: " + line);
      }
    } else if (row[0] == "verdict") {
      if (row.size() != 6) {
        fail("ROUTE_INVENTORY_BAD_VERDICT: " + line);
      }
      verdicts.push_back(Verdict{row[1], number(row[2], "verdict signers"), number(row[3], "verdict object"), row[4],
                                 number(row[5], "verdict margin")});
    } else {
      fail("ROUTE_INVENTORY_UNKNOWN_ROW: " + line);
    }
  }

  if (capacities.size() != 3 || expected_minima.size() != 3 || layers != 10) {
    fail("ROUTE_INVENTORY_INCOMPLETE");
  }
  for (const auto& [route, capacity] : capacities) {
    const auto expected = expected_minima.find(route);
    if (expected == expected_minima.end() || expected->second != capacity) {
      std::ostringstream error;
      error << "ROUTE_MINIMUM_MISMATCH: route=" << route
            << " recorded=" << (expected == expected_minima.end() ? 0 : expected->second) << " actual=" << capacity;
      fail(error.str());
    }
  }

  const auto measurements = measured_object_sizes();
  constexpr std::size_t signer_counts[]{1, 21, 100, 400};
  std::set<std::pair<std::string, std::size_t>> seen;
  for (const auto& verdict : verdicts) {
    const auto capacity = capacities.find(verdict.route);
    const auto measured = measurements.find(verdict.signers);
    if (capacity == capacities.end() || measured == measurements.end() || measured->second != verdict.object_bytes) {
      fail("ROUTE_VERDICT_INPUT_DRIFT: route=" + verdict.route + " signers=" + std::to_string(verdict.signers));
    }
    const bool fits = verdict.object_bytes <= capacity->second;
    const auto margin = fits ? capacity->second - verdict.object_bytes : verdict.object_bytes - capacity->second;
    if (verdict.result != (fits ? "fits" : "refused") || verdict.margin != margin) {
      fail("ROUTE_VERDICT_MISMATCH: route=" + verdict.route + " signers=" + std::to_string(verdict.signers));
    }
    if (!seen.emplace(verdict.route, verdict.signers).second) {
      fail("ROUTE_VERDICT_DUPLICATE");
    }
  }
  for (const auto& [route, unused] : capacities) {
    for (const auto signers : signer_counts) {
      if (!seen.contains({route, signers})) {
        fail("ROUTE_VERDICT_MISSING: route=" + route + " signers=" + std::to_string(signers));
      }
    }
  }
  if (seen.size() != 12) {
    fail("ROUTE_VERDICT_UNEXPECTED_COUNT");
  }

  std::printf("BLOCK_SIGNATURE_CARRIER_ROUTES_OK finality=%zu v2=%zu lite=%zu verdicts=%zu\n",
              capacities.at("finality-broadcast"), capacities.at("v2-broadcast"), capacities.at("lite-forward-proof"),
              verdicts.size());
  return 0;
}
