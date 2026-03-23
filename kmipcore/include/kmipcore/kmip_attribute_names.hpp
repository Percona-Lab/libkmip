#ifndef KMIPCORE_KMIP_ATTRIBUTE_NAMES_HPP
#define KMIPCORE_KMIP_ATTRIBUTE_NAMES_HPP

#include <string_view>

namespace kmipcore {

  // Known KMIP attribute names used across client/core layers.
  /** @brief KMIP Name attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_NAME = "Name";
  /** @brief KMIP Object Group attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_GROUP = "Object Group";
  /** @brief KMIP State attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_STATE = "State";
  /** @brief KMIP Unique Identifier attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_UNIQUE_IDENTIFIER =
      "Unique Identifier";
  /** @brief Backward-compatible alternative Unique Identifier attribute name.
   */
  inline constexpr std::string_view KMIP_ATTR_NAME_UNIQUE_IDENTIFIER_ALT =
      "UniqueID";  // backward compatibility
  /** @brief KMIP Initial Date attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_INITIAL_DATE =
      "Initial Date";
  /** @brief KMIP Activation Date attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_ACTIVATION_DATE =
      "Activation Date";
  /** @brief KMIP Process Start Date attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_PROCESS_START_DATE =
      "Process Start Date";
  /** @brief KMIP Protect Stop Date attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_PROTECT_STOP_DATE =
      "Protect Stop Date";
  /** @brief KMIP Deactivation Date attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_DEACTIVATION_DATE =
      "Deactivation Date";
  /** @brief KMIP Destroy Date attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_DESTROY_DATE =
      "Destroy Date";
  /** @brief KMIP Compromise Occurrence Date attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_COMPROMISE_OCCURRENCE_DATE =
      "Compromise Occurrence Date";
  /** @brief KMIP Compromise Date attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_COMPROMISE_DATE =
      "Compromise Date";
  /** @brief KMIP Archive Date attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_ARCHIVE_DATE =
      "Archive Date";
  /** @brief KMIP Last Change Date attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_LAST_CHANGE_DATE =
      "Last Change Date";
  /** @brief KMIP Cryptographic Algorithm attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_CRYPTO_ALG =
      "Cryptographic Algorithm";
  /** @brief KMIP Cryptographic Length attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_CRYPTO_LEN =
      "Cryptographic Length";
  /** @brief KMIP Cryptographic Usage Mask attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_CRYPTO_USAGE_MASK =
      "Cryptographic Usage Mask";
  /** @brief KMIP Contact Information attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_CONTACT_INFO =
      "Contact Information";
  /** @brief KMIP Operation Policy Name attribute. */
  inline constexpr std::string_view KMIP_ATTR_NAME_OPERATION_POLICY_NAME =
      "Operation Policy Name";

}  // namespace kmipcore

#endif /* KMIPCORE_KMIP_ATTRIBUTE_NAMES_HPP */
