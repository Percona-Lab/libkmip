/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCLIENT_PRIVATE_KEY_HPP
#define KMIPCLIENT_PRIVATE_KEY_HPP

#include "kmipclient/KeyBase.hpp"

namespace kmipclient {

  class PrivateKey final : public Key {
  public:
    using Key::Key;

    [[nodiscard]] KeyType type() const noexcept override {
      return KeyType::PRIVATE_KEY;
    }
    [[nodiscard]] std::unique_ptr<Key> clone() const override;
  };

}  // namespace kmipclient

#endif  // KMIPCLIENT_PRIVATE_KEY_HPP
