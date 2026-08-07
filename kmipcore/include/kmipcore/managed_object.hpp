/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCORE_MANAGED_OBJECT_HPP
#define KMIPCORE_MANAGED_OBJECT_HPP

#include "kmipcore/kmip_attributes.hpp"
#include "kmipcore/secure_memory.hpp"

#include <span>
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
        std::span<const unsigned char> value, Attributes attrs = {}
    )
      : value_(value.begin(), value.end()), attributes_(std::move(attrs)) {}

    /** @brief Virtual destructor for subclass-safe cleanup. */
    virtual ~ManagedObject() = default;

    ManagedObject(const ManagedObject &) = default;
    ManagedObject &operator=(const ManagedObject &) = default;
    ManagedObject(ManagedObject &&) noexcept = default;
    ManagedObject &operator=(ManagedObject &&) noexcept = default;

    // ---- Raw bytes ----

    /** @brief Returns raw object payload bytes (stored in scrubbed memory). */
    [[nodiscard]] const secure_bytes &value() const noexcept { return value_; }

    /** @brief Replaces raw object payload bytes. */
    void set_value(std::span<const unsigned char> val) {
      value_.assign(val.begin(), val.end());
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
    secure_bytes value_;
    Attributes attributes_;
  };

}  // namespace kmipcore

#endif  // KMIPCORE_MANAGED_OBJECT_HPP
