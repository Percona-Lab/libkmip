/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPIOSEXCEPTION_HPP
#define KMIPIOSEXCEPTION_HPP

#include "kmipcore/kmip_errors.hpp"

#include <string>

namespace kmipclient {

  /**
   * Exception class for communication-level (IO/network) errors in the
   * kmipclient library. Thrown whenever a network send, receive, SSL
   * handshake, or connection operation fails.
   *
   * Inherits from kmipcore::KmipException so that existing catch handlers
   * for the base class continue to work without modification.
   */
  class KmipIOException : public kmipcore::KmipException {
  public:
    /**
     * @brief Creates an IO exception with a message.
     * @param msg Human-readable error description.
     */
    explicit KmipIOException(const std::string &msg)
      : kmipcore::KmipException(msg) {}

    /**
     * @brief Creates an IO exception with status code and message.
     * @param code Error code associated with the failure.
     * @param msg Human-readable error description.
     */
    KmipIOException(int code, const std::string &msg)
      : kmipcore::KmipException(code, msg) {}
  };

}  // namespace kmipclient

#endif  // KMIPIOSEXCEPTION_HPP
