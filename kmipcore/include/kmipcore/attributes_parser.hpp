/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCORE_ATTRIBUTES_PARSER_HPP
#define KMIPCORE_ATTRIBUTES_PARSER_HPP

#include "kmipcore/kmip_attributes.hpp"
#include "kmipcore/kmip_basics.hpp"

#include <memory>
#include <vector>

namespace kmipcore {

  /**
   * @brief Decodes raw KMIP Attribute structures into a typed @ref Attributes
   * bag.
   */
  class AttributesParser {
  public:
    AttributesParser() = default;
    /**
     * @brief Parses KMIP attribute elements into a typed @ref Attributes
     * object.
     *
     * Well-known attributes (Cryptographic Algorithm, Cryptographic Length,
     * Cryptographic Usage Mask, State) are stored in their dedicated typed
     * fields. All other attributes are stored in the generic string map.
     *
     * @param attributes Raw KMIP attribute elements.
     * @return Populated @ref Attributes bag.
     */
    static Attributes
        parse(const std::vector<std::shared_ptr<Element>> &attributes);
  };

}  // namespace kmipcore

#endif /* KMIPCORE_ATTRIBUTES_PARSER_HPP */
