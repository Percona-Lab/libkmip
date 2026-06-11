/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCORE_KMIP_ERRORS_HPP
#define KMIPCORE_KMIP_ERRORS_HPP

#include "kmipcore/kmip_enums.hpp"

#include <string>
#include <system_error>

namespace kmipcore {

  /**
   * @brief Returns the KMIP-specific std::error_category.
   */
  [[nodiscard]] const std::error_category &kmip_category() noexcept;

  /**
   * @brief Creates an error_code in the KMIP category from a native code.
   */
  [[nodiscard]] std::error_code
      make_kmip_error_code(int native_error_code) noexcept;

  /**
   * @brief Base exception for KMIP core protocol/encoding failures.
   */
  class KmipException : public std::system_error {
  public:
    /** @brief Creates an exception with message only. */
    explicit KmipException(const std::string &msg);
    /** @brief Creates an exception with numeric status code and message. */
    KmipException(int native_error_code, const std::string &msg);
  };

}  // namespace kmipcore

#endif /* KMIPCORE_KMIP_ERRORS_HPP */
