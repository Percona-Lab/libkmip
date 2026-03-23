#ifndef KMIPCORE_SECRET_HPP
#define KMIPCORE_SECRET_HPP

#include "kmipcore/kmip_enums.hpp"
#include "kmipcore/managed_object.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace kmipcore {

  /**
   * @brief Minimal KMIP Secret Data model.
   *
   * Intrinsic properties (raw bytes, secret data type) are stored as dedicated
   * typed fields. All other attributes — including the object lifecycle state,
   * Name, Object Group, dates, etc. — live in the type-safe @ref Attributes
   * bag.
   */
  class Secret : public ManagedObject {
  public:
    /** @brief Constructs an empty secret. */
    Secret() = default;

    /**
     * @brief Constructs a secret from payload and metadata.
     * @param val Raw secret bytes.
     * @param type KMIP secret data type.
     * @param attrs Attribute bag (may include state, name, …).
     */
    Secret(
        const std::vector<unsigned char> &val,
        secret_data_type type,
        Attributes attrs = {}
    )
      : ManagedObject(val, std::move(attrs)), secret_type_(type) {}

    Secret(const Secret &) = default;
    Secret &operator=(const Secret &) = default;
    Secret(Secret &&) noexcept = default;
    Secret &operator=(Secret &&) noexcept = default;

    /** @brief Returns KMIP secret data type discriminator. */
    [[nodiscard]] secret_data_type get_secret_type() const noexcept {
      return secret_type_;
    }

    /** @brief Sets KMIP secret data type discriminator. */
    void set_secret_type(secret_data_type type) noexcept {
      secret_type_ = type;
    }

    // ---- Typed convenience accessors ----

    /** @brief Returns the object lifecycle state (KMIP_STATE_PRE_ACTIVE when
     * unset). */
    [[nodiscard]] kmipcore::state get_state() const noexcept {
      return attributes_.object_state();
    }

    /** @brief Sets the object lifecycle state. */
    void set_state(kmipcore::state st) noexcept { attributes_.set_state(st); }

    /**
     * @brief Creates a Secret from text bytes.
     * @param text Source text payload.
     * @param type KMIP secret data type.
     * @param st Initial lifecycle state.
     */
    [[nodiscard]] static Secret from_text(
        std::string_view text,
        secret_data_type type = secret_data_type::KMIP_SECDATA_PASSWORD,
        kmipcore::state st = state::KMIP_STATE_PRE_ACTIVE
    ) {
      Attributes attrs;
      attrs.set_state(st);
      return Secret{
          std::vector<unsigned char>(text.begin(), text.end()),
          type,
          std::move(attrs)
      };
    }

    /** @brief Returns payload interpreted as UTF-8/byte-preserving text. */
    [[nodiscard]] std::string as_text() const {
      return {value_.begin(), value_.end()};
    }

  private:
    secret_data_type secret_type_ = secret_data_type::KMIP_SECDATA_PASSWORD;
  };

}  // namespace kmipcore

#endif /* KMIPCORE_SECRET_HPP */
