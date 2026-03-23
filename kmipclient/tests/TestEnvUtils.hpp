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
