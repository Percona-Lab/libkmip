#ifndef KMIPCLIENT_TYPES_HPP
#define KMIPCLIENT_TYPES_HPP

#include "kmipcore/key.hpp"
#include "kmipcore/kmip_attribute_names.hpp"
#include "kmipcore/kmip_attributes.hpp"
#include "kmipcore/secret.hpp"

#include <cstdint>

namespace kmipclient {
  /** @brief Alias for the type-safe KMIP attribute bag. */
  using kmipcore::Attributes;
  /** @brief Alias for supported key-kind discriminator enum. */
  using kmipcore::KeyType;
  /** @brief Alias for KMIP object type enum. */
  using kmipcore::object_type;
  /** @brief Alias for KMIP secret data type enum. */
  using kmipcore::secret_data_type;
  /** @brief Alias for KMIP revocation reason enum. */
  using kmipcore::revocation_reason_type;
  /** @brief Alias for KMIP cryptographic algorithm enum. */
  using kmipcore::cryptographic_algorithm;
  /** @brief Alias for KMIP cryptographic usage mask enum. */
  using kmipcore::cryptographic_usage_mask;
  /** @brief Alias for KMIP lifecycle state enum. */
  using kmipcore::state;
  /** @brief Alias for KMIP secret object representation. */
  using kmipcore::Secret;

  /** @brief Canonical KMIP attribute name for object name. */
  inline const std::string KMIP_ATTR_NAME_NAME =
      std::string(kmipcore::KMIP_ATTR_NAME_NAME);
  /** @brief Canonical KMIP attribute name for object group. */
  inline const std::string KMIP_ATTR_NAME_GROUP =
      std::string(kmipcore::KMIP_ATTR_NAME_GROUP);
  /** @brief Canonical KMIP attribute name for object state. */
  inline const std::string KMIP_ATTR_NAME_STATE =
      std::string(kmipcore::KMIP_ATTR_NAME_STATE);
  /** @brief Canonical KMIP attribute name for unique identifier. */
  inline const std::string KMIP_ATTR_NAME_UNIQUE_IDENTIFIER =
      std::string(kmipcore::KMIP_ATTR_NAME_UNIQUE_IDENTIFIER);
  /** @brief Canonical KMIP attribute name for operation policy name. */
  inline const std::string KMIP_ATTR_NAME_OPERATION_POLICY_NAME =
      std::string(kmipcore::KMIP_ATTR_NAME_OPERATION_POLICY_NAME);
  /** @brief Canonical KMIP attribute name for cryptographic algorithm
   *         (used when constructing GetAttributes requests). */
  inline const std::string KMIP_ATTR_NAME_CRYPTO_ALG =
      std::string(kmipcore::KMIP_ATTR_NAME_CRYPTO_ALG);
  /** @brief Canonical KMIP attribute name for cryptographic length
   *         (used when constructing GetAttributes requests). */
  inline const std::string KMIP_ATTR_NAME_CRYPTO_LEN =
      std::string(kmipcore::KMIP_ATTR_NAME_CRYPTO_LEN);
  /** @brief Canonical KMIP attribute name for cryptographic usage mask. */
  inline const std::string KMIP_ATTR_NAME_CRYPTO_USAGE_MASK =
      std::string(kmipcore::KMIP_ATTR_NAME_CRYPTO_USAGE_MASK);

  /** @brief Re-export stream formatter overloads from kmipcore. */
  using kmipcore::operator<<;

  /** @brief Strongly-typed AES key sizes for KMIP Create/Register APIs. */
  enum class aes_key_size : int32_t {
    AES_128 = 128,
    AES_192 = 192,
    AES_256 = 256,
  };

}  // namespace kmipclient

#endif /* KMIPCLIENT_TYPES_HPP */
