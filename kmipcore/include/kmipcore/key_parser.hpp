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

#ifndef KMIPCORE_KEY_PARSER_HPP
#define KMIPCORE_KEY_PARSER_HPP

#include "kmipcore/key.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_responses.hpp"
#include "kmipcore/secret.hpp"

#include <memory>

namespace kmipcore {

  /**
   * @brief Decodes KMIP Get payloads into Key or Secret model objects.
   */
  class KeyParser {
  public:
    /** @brief Default constructor. */
    KeyParser() = default;
    /**
     * @brief Parses typed Get response item into a key object.
     * @param item Typed Get response batch item.
     */
    static Key parseGetKeyResponse(const GetResponseBatchItem &item);
    /**
     * @brief Parses typed Get response item into a secret object.
     * @param item Typed Get response batch item.
     */
    static Secret parseGetSecretResponse(const GetResponseBatchItem &item);

  private:
    /** @brief Internal key parser used by typed public entry points. */
    static Key parseResponse(const std::shared_ptr<Element> &payload);
  };

}  // namespace kmipcore

#endif  // KMIPCORE_KEY_PARSER_HPP
