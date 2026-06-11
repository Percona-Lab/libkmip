/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
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
