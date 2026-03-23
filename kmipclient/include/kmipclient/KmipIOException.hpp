/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; version 2 of
   the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
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
