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

#ifndef KMIPCLIENT_PUBLIC_KEY_HPP
#define KMIPCLIENT_PUBLIC_KEY_HPP

#include "kmipclient/KeyBase.hpp"

namespace kmipclient {

  class PublicKey final : public Key {
  public:
    using Key::Key;

    [[nodiscard]] KeyType type() const noexcept override {
      return KeyType::PUBLIC_KEY;
    }
    [[nodiscard]] std::unique_ptr<Key> clone() const override;
  };

}  // namespace kmipclient

#endif  // KMIPCLIENT_PUBLIC_KEY_HPP
