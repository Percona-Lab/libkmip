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

#ifndef KMIPCORE_KEY_HPP
#define KMIPCORE_KEY_HPP

#include "kmipcore/kmip_enums.hpp"
#include "kmipcore/managed_object.hpp"

namespace kmipcore {

  /** @brief Key object families represented by @ref Key. */
  enum class KeyType {
    UNSET,
    SYMMETRIC_KEY,
    PUBLIC_KEY,
    PRIVATE_KEY,
    CERTIFICATE
  };

  /**
   * Minimal crypto key representation as KMIP spec sees it.
   * Contains raw key bytes, key type, and a type-safe @ref Attributes bag.
   *
   * All attribute access goes through @ref attributes().
   * Use @ref attributes().algorithm(), @ref attributes().usage_mask(), etc.
   * for the well-known typed attributes, and @ref attributes().get() /
   * @ref attributes().generic() for user-defined / generic ones.
   */
  class Key : public ManagedObject {
  public:
    /**
     * @brief Constructs a KMIP key object.
     * @param value Raw key bytes.
     * @param k_type Key family.
     * @param attrs  Type-safe attribute bag.
     */
    explicit Key(
        const std::vector<unsigned char> &value,
        KeyType k_type,
        Attributes attrs = {}
    )
      : ManagedObject(value, std::move(attrs)), key_type(k_type) {}

    /** @brief Constructs an empty key object. */
    Key() = default;

    Key(const Key &) = default;
    Key &operator=(const Key &) = default;
    Key(Key &&) noexcept = default;
    Key &operator=(Key &&) noexcept = default;

    /** @brief Returns key family discriminator. */
    [[nodiscard]] KeyType type() const noexcept { return key_type; }

    /** @brief Returns key length in bytes. */
    [[nodiscard]] size_t size() const noexcept { return value_.size(); }

  private:
    KeyType key_type = KeyType::UNSET;
  };

}  // namespace kmipcore

#endif  // KMIPCORE_KEY_HPP
