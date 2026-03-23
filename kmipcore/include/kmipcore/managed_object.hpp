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

#ifndef KMIPCORE_MANAGED_OBJECT_HPP
#define KMIPCORE_MANAGED_OBJECT_HPP

#include "kmipcore/kmip_attributes.hpp"

#include <vector>

namespace kmipcore {

  /**
   * @brief Base class for KMIP managed objects (Key, Secret, Certificate, etc.)
   *
   * Encapsulates the common pattern: raw payload bytes + type-safe @ref
   * Attributes bag. All KMIP objects in the KMS store metadata in a consistent
   * way through this base.
   */
  class ManagedObject {
  public:
    /** @brief Constructs an empty managed object. */
    ManagedObject() = default;

    /**
     * @brief Constructs a managed object from payload and attributes.
     * @param value Raw object bytes.
     * @param attrs Type-safe attribute bag.
     */
    explicit ManagedObject(
        const std::vector<unsigned char> &value, Attributes attrs = {}
    )
      : value_(value), attributes_(std::move(attrs)) {}

    /** @brief Virtual destructor for subclass-safe cleanup. */
    virtual ~ManagedObject() = default;

    ManagedObject(const ManagedObject &) = default;
    ManagedObject &operator=(const ManagedObject &) = default;
    ManagedObject(ManagedObject &&) noexcept = default;
    ManagedObject &operator=(ManagedObject &&) noexcept = default;

    // ---- Raw bytes ----

    /** @brief Returns raw object payload bytes. */
    [[nodiscard]] const std::vector<unsigned char> &value() const noexcept {
      return value_;
    }

    /** @brief Replaces raw object payload bytes. */
    void set_value(const std::vector<unsigned char> &val) noexcept {
      value_ = val;
    }

    // ---- Attribute bag ----

    /** @brief Returns the type-safe attribute bag (read-only). */
    [[nodiscard]] const Attributes &attributes() const noexcept {
      return attributes_;
    }

    /** @brief Returns the type-safe attribute bag (mutable). */
    [[nodiscard]] Attributes &attributes() noexcept { return attributes_; }

    // ---- Generic string attribute helpers ----

    /**
     * @brief Returns a generic string attribute value, or empty string.
     * @note Does not look up typed attributes (state, algorithm, …).
     *       Use attributes().object_state() etc. for those.
     */
    [[nodiscard]] const std::string &
        attribute_value(const std::string &name) const noexcept {
      return attributes_.get(name);
    }

    /** @brief Sets a string attribute by name (routes typed attrs to typed
     * setters). */
    void set_attribute(const std::string &name, std::string val) noexcept {
      attributes_.set(name, std::move(val));
    }

  protected:
    std::vector<unsigned char> value_;
    Attributes attributes_;
  };

}  // namespace kmipcore

#endif  // KMIPCORE_MANAGED_OBJECT_HPP
