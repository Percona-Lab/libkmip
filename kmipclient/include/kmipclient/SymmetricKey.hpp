/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCLIENT_SYMMETRIC_KEY_HPP
#define KMIPCLIENT_SYMMETRIC_KEY_HPP

#include "kmipclient/KeyBase.hpp"

namespace kmipclient {

  class SymmetricKey final : public Key {
  public:
    using Key::Key;

    [[nodiscard]] KeyType type() const noexcept override {
      return KeyType::SYMMETRIC_KEY;
    }
    [[nodiscard]] std::unique_ptr<Key> clone() const override;

    [[nodiscard]] static SymmetricKey aes_from_hex(const std::string &hex);
    [[nodiscard]] static SymmetricKey
        aes_from_base64(const std::string &base64);
    [[nodiscard]] static SymmetricKey
        aes_from_value(const std::vector<unsigned char> &val);
    [[nodiscard]] static SymmetricKey
        generate_aes(aes_key_size key_size = aes_key_size::AES_256);
  };

}  // namespace kmipclient

#endif  // KMIPCLIENT_SYMMETRIC_KEY_HPP
