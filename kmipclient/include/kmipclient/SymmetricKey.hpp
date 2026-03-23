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
