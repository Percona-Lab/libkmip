/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCORE_KMIP_FORMATTER_HPP
#define KMIPCORE_KMIP_FORMATTER_HPP

#include <cstdint>
#include <memory>
#include <span>
#include <string>

namespace kmipcore {

  // Element is defined as a struct; the forward declaration must use the
  // same class-key because MSVC encodes it in mangled names (C4099).
  struct Element;
  class RequestMessage;
  class ResponseMessage;

  /** @brief Formats an Element tree into a human-readable, redacted text dump.
   */
  [[nodiscard]] std::string
      format_element(const std::shared_ptr<Element> &element);
  /** @brief Formats a RequestMessage into a human-readable, redacted text dump.
   */
  [[nodiscard]] std::string format_request(const RequestMessage &request);
  /** @brief Formats a ResponseMessage into a human-readable, redacted text
   * dump. */
  [[nodiscard]] std::string format_response(const ResponseMessage &response);
  /** @brief Parses and formats raw TTLV bytes into human-readable, redacted
   * text. */
  [[nodiscard]] std::string format_ttlv(std::span<const uint8_t> ttlv);

  /**
   * @brief Converts a cryptographic usage mask to human-readable bit names.
   * @param mask The usage mask as a bitmask (e.g., 12 = ENCRYPT | DECRYPT).
   * @return A comma-separated string of flag names (e.g., "ENCRYPT, DECRYPT").
   *         Returns "UNSET" if no bits are set, or "UNKNOWN_BITS" if
   * unrecognized bits present.
   */
  [[nodiscard]] std::string usage_mask_to_string(std::uint32_t mask);

}  // namespace kmipcore

#endif /* KMIPCORE_KMIP_FORMATTER_HPP */
