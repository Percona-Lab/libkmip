/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef STRINGUTILS_HPP
#define STRINGUTILS_HPP

#include <string_view>
#include <vector>

namespace kmipclient {

  class StringUtils {
  public:
    static std::vector<unsigned char> fromHex(std::string_view hex);
    static std::vector<unsigned char> fromBase64(std::string_view base64);
  };

}  // namespace kmipclient

#endif  // STRINGUTILS_HPP
