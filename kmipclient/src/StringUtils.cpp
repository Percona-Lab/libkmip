/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "StringUtils.hpp"

#include "kmipcore/kmip_errors.hpp"

#include <array>
#include <string_view>
#include <vector>
namespace kmipclient {

  unsigned char char2int(const char input) {
    if (input >= '0' && input <= '9') {
      return input - '0';
    }
    if (input >= 'A' && input <= 'F') {
      return input - 'A' + 10;
    }
    if (input >= 'a' && input <= 'f') {
      return input - 'a' + 10;
    }
    throw kmipcore::KmipException{"Invalid hex character."};
  }

  std::vector<unsigned char> StringUtils::fromHex(std::string_view hex) {
    if (hex.empty() || hex.size() % 2 != 0) {
      throw kmipcore::KmipException{"Invalid hex string length."};
    }
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
      const auto byte = static_cast<unsigned char>(
          char2int(hex[i]) * 16 + char2int(hex[i + 1])
      );
      bytes.push_back(byte);
    }
    return bytes;
  }

  std::vector<unsigned char> StringUtils::fromBase64(std::string_view base64) {
    static const std::array<int, 256> lookup = []() {
      std::array<int, 256> l{};
      l.fill(-1);
      for (int i = 0; i < 64; ++i) {
        l["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
              [i]] = i;
      }
      return l;
    }();

    std::vector<unsigned char> out;
    out.reserve((base64.size() / 4) * 3);

    int val = 0, val_b = -8;
    for (unsigned char c : base64) {
      if (lookup[c] == -1) {
        if (c == '=') {
          break;  // Padding reached
        }
        continue;  // Skip whitespace or invalid chars
      }
      val = (val << 6) + lookup[c];
      val_b += 6;
      if (val_b >= 0) {
        out.push_back(static_cast<unsigned char>((val >> val_b) & 0xFF));
        val_b -= 8;
      }
    }
    return out;
  }


}  // namespace kmipclient