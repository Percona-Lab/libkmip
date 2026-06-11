/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCLIENT_PEM_READER_HPP
#define KMIPCLIENT_PEM_READER_HPP

#include "kmipclient/KeyBase.hpp"

#include <memory>
#include <string>

namespace kmipclient {

  /**
   * Factory that parses PEM text and returns an object of the matching client
   * key type.
   */
  class PEMReader {
  public:
    [[nodiscard]] static std::unique_ptr<Key> from_PEM(const std::string &pem);
  };

}  // namespace kmipclient

#endif  // KMIPCLIENT_PEM_READER_HPP
