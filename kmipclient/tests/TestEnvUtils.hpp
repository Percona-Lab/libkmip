/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCLIENT_TESTS_TEST_ENV_UTILS_HPP
#define KMIPCLIENT_TESTS_TEST_ENV_UTILS_HPP

#include <cstdlib>
#include <string_view>

namespace kmipclient::test {

  inline bool is_env_flag_enabled(const char *name) {
    const char *value = std::getenv(name);
    return value != nullptr && std::string_view(value) == "1";
  }

}  // namespace kmipclient::test

#endif  // KMIPCLIENT_TESTS_TEST_ENV_UTILS_HPP
