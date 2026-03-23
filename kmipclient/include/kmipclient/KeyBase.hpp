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

#ifndef KMIPCLIENT_KEY_BASE_HPP
#define KMIPCLIENT_KEY_BASE_HPP

#include "kmipclient/types.hpp"
#include "kmipcore/key.hpp"

#include <memory>
#include <string>
#include <vector>

namespace kmipclient {

  /**
   * Client-level key abstraction.
   *
   * All attributes — Cryptographic Algorithm, Length, Usage Mask, lifecycle
   * State, Name, Object Group, Unique Identifier, dates … — are held in a
   * single @ref kmipcore::Attributes bag.  Dedicated typed accessors are
   * provided for the most frequently accessed fields.
   */
  class Key {
  public:
    virtual ~Key() = default;

    Key(const Key &) = default;
    Key &operator=(const Key &) = default;
    Key(Key &&) noexcept = default;
    Key &operator=(Key &&) noexcept = default;

    // ---- Raw bytes ----

    [[nodiscard]] const std::vector<unsigned char> &value() const noexcept {
      return key_value_;
    }

    // ---- Attribute bag ----

    /** @brief Returns the type-safe attribute bag (read-only). */
    [[nodiscard]] const kmipcore::Attributes &attributes() const noexcept {
      return attributes_;
    }

    /** @brief Returns the type-safe attribute bag (mutable). */
    [[nodiscard]] kmipcore::Attributes &attributes() noexcept {
      return attributes_;
    }

    // ---- Typed convenience accessors ----

    [[nodiscard]] cryptographic_algorithm algorithm() const noexcept {
      return attributes_.algorithm();
    }
    [[nodiscard]] std::optional<int32_t> crypto_length() const noexcept {
      return attributes_.crypto_length();
    }
    [[nodiscard]] cryptographic_usage_mask usage_mask() const noexcept {
      return attributes_.usage_mask();
    }
    [[nodiscard]] kmipcore::state state() const noexcept {
      return attributes_.object_state();
    }

    // ---- Generic string attribute helpers (backward compatibility) ----

    /** @brief Returns a generic string attribute value, or empty string. */
    [[nodiscard]] const std::string &
        attribute_value(const std::string &name) const noexcept {
      return attributes_.get(name);
    }

    /** @brief Sets a string attribute by name (routes typed attrs to typed
     * setters). */
    void set_attribute(
        const std::string &name, const std::string &val
    ) noexcept {
      attributes_.set(name, val);
    }

    // ---- Key kind ----

    [[nodiscard]] virtual KeyType type() const noexcept = 0;
    [[nodiscard]] virtual std::unique_ptr<Key> clone() const = 0;

    // ---- Core-layer bridge ----

    /** @brief Build protocol-level representation from the client key object.
     */
    [[nodiscard]] kmipcore::Key to_core_key() const;
    /** @brief Build the corresponding client key subclass from protocol-level
     * data. */
    [[nodiscard]] static std::unique_ptr<Key>
        from_core_key(const kmipcore::Key &core_key);

    /**
     * @brief Constructor: raw bytes + full attribute bag.
     * @param value  Key material bytes.
     * @param attrs  Type-safe attribute bag (algorithm, length, mask, …).
     */
    Key(const std::vector<unsigned char> &value,
        kmipcore::Attributes attrs = {});

  private:
    std::vector<unsigned char> key_value_;
    kmipcore::Attributes attributes_;
  };

}  // namespace kmipclient

#endif  // KMIPCLIENT_KEY_BASE_HPP
