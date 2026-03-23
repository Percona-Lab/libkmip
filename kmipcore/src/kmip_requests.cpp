#include "kmipcore/kmip_requests.hpp"

#include "kmipcore/kmip_attribute_names.hpp"
#include "kmipcore/kmip_errors.hpp"

#include <limits>
#include <string_view>
#include <unordered_set>

namespace kmipcore {

  namespace detail {
    [[nodiscard]] bool
        use_attributes_container(const ProtocolVersion &version) {
      return version.is_at_least(2, 0);
    }

    [[nodiscard]] std::optional<Tag>
        standard_attribute_name_to_tag(std::string_view name) {
      if (name == KMIP_ATTR_NAME_NAME) {
        return tag::KMIP_TAG_NAME;
      }
      if (name == KMIP_ATTR_NAME_GROUP) {
        return tag::KMIP_TAG_OBJECT_GROUP;
      }
      if (name == KMIP_ATTR_NAME_STATE) {
        return tag::KMIP_TAG_STATE;
      }
      if (name == KMIP_ATTR_NAME_UNIQUE_IDENTIFIER ||
          name == KMIP_ATTR_NAME_UNIQUE_IDENTIFIER_ALT) {
        return tag::KMIP_TAG_UNIQUE_IDENTIFIER;
      }
      if (name == KMIP_ATTR_NAME_ACTIVATION_DATE) {
        return tag::KMIP_TAG_ACTIVATION_DATE;
      }
      if (name == KMIP_ATTR_NAME_DEACTIVATION_DATE) {
        return tag::KMIP_TAG_DEACTIVATION_DATE;
      }
      if (name == KMIP_ATTR_NAME_PROCESS_START_DATE) {
        return tag::KMIP_TAG_PROCESS_START_DATE;
      }
      if (name == KMIP_ATTR_NAME_PROTECT_STOP_DATE) {
        return tag::KMIP_TAG_PROTECT_STOP_DATE;
      }
      if (name == KMIP_ATTR_NAME_CRYPTO_ALG) {
        return tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM;
      }
      if (name == KMIP_ATTR_NAME_CRYPTO_LEN) {
        return tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH;
      }
      if (name == KMIP_ATTR_NAME_CRYPTO_USAGE_MASK) {
        return tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK;
      }
      if (name == KMIP_ATTR_NAME_OPERATION_POLICY_NAME) {
        return tag::KMIP_TAG_OPERATION_POLICY_NAME;
      }
      return std::nullopt;
    }

    std::shared_ptr<Element>
        make_v2_attribute_reference(std::string_view attribute_name) {
      auto ref = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE_REFERENCE);
      if (const auto tag_value = standard_attribute_name_to_tag(attribute_name);
          tag_value.has_value()) {
        ref->asStructure()->add(
            Element::createEnumeration(
                tag::KMIP_TAG_ATTRIBUTE_REFERENCE,
                static_cast<int32_t>(*tag_value)
            )
        );
      } else {
        // Preserve interoperability with vendor-defined attributes by name.
        ref->asStructure()->add(
            Element::createTextString(
                tag::KMIP_TAG_ATTRIBUTE_NAME, std::string(attribute_name)
            )
        );
      }
      return ref;
    }

    std::shared_ptr<Element> make_text_attribute(
        const std::string &attribute_name, const std::string &value
    ) {
      auto attribute = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
      attribute->asStructure()->add(
          Element::createTextString(
              tag::KMIP_TAG_ATTRIBUTE_NAME, attribute_name
          )
      );
      auto attribute_value =
          Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_VALUE, value);
      attribute->asStructure()->add(attribute_value);
      return attribute;
    }
    std::shared_ptr<Element>
        make_enum_attribute(const std::string &attribute_name, int32_t value) {
      auto attribute = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
      attribute->asStructure()->add(
          Element::createTextString(
              tag::KMIP_TAG_ATTRIBUTE_NAME, attribute_name
          )
      );
      auto attribute_value =
          Element::createEnumeration(tag::KMIP_TAG_ATTRIBUTE_VALUE, value);
      attribute->asStructure()->add(attribute_value);
      return attribute;
    }
    std::shared_ptr<Element> make_integer_attribute(
        const std::string &attribute_name, int32_t value
    ) {
      auto attribute = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
      attribute->asStructure()->add(
          Element::createTextString(
              tag::KMIP_TAG_ATTRIBUTE_NAME, attribute_name
          )
      );
      auto attribute_value =
          Element::createInteger(tag::KMIP_TAG_ATTRIBUTE_VALUE, value);
      attribute->asStructure()->add(attribute_value);
      return attribute;
    }
    std::shared_ptr<Element> make_name_attribute(const std::string &value) {
      auto attribute_value =
          Element::createStructure(tag::KMIP_TAG_ATTRIBUTE_VALUE);
      attribute_value->asStructure()->add(
          Element::createTextString(tag::KMIP_TAG_NAME_VALUE, value)
      );
      attribute_value->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_NAME_TYPE, KMIP_NAME_UNINTERPRETED_TEXT_STRING
          )
      );
      auto attribute = Element::createStructure(tag::KMIP_TAG_ATTRIBUTE);
      attribute->asStructure()->add(
          Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, "Name")
      );
      attribute->asStructure()->add(attribute_value);
      return attribute;
    }
    std::shared_ptr<Element> make_template_attribute(
        const std::vector<std::shared_ptr<Element>> &attributes
    ) {
      auto template_attribute =
          Element::createStructure(tag::KMIP_TAG_TEMPLATE_ATTRIBUTE);
      for (const auto &attribute : attributes) {
        template_attribute->asStructure()->add(attribute);
      }
      return template_attribute;
    }
    std::shared_ptr<Element>
        make_key_value(const std::vector<unsigned char> &bytes) {
      auto key_value = Element::createStructure(tag::KMIP_TAG_KEY_VALUE);
      key_value->asStructure()->add(
          Element::createByteString(
              tag::KMIP_TAG_KEY_MATERIAL,
              std::vector<uint8_t>(bytes.begin(), bytes.end())
          )
      );
      return key_value;
    }
    std::shared_ptr<Element> make_key_block(
        int32_t key_format_type,
        const std::vector<unsigned char> &bytes,
        std::optional<int32_t> algorithm,
        std::optional<int32_t> cryptographic_length
    ) {
      auto key_block = Element::createStructure(tag::KMIP_TAG_KEY_BLOCK);
      key_block->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_KEY_FORMAT_TYPE, key_format_type
          )
      );
      key_block->asStructure()->add(make_key_value(bytes));
      if (algorithm) {
        key_block->asStructure()->add(
            Element::createEnumeration(
                tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, *algorithm
            )
        );
      }
      if (cryptographic_length) {
        key_block->asStructure()->add(
            Element::createInteger(
                tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, *cryptographic_length
            )
        );
      }
      return key_block;
    }
    std::shared_ptr<Element> make_key_object_from_key(const Key &key) {
      const auto alg = key.attributes().algorithm();
      const std::optional<int32_t> key_alg =
          (alg != cryptographic_algorithm::KMIP_CRYPTOALG_UNSET)
              ? std::optional<int32_t>(static_cast<int32_t>(alg))
              : std::nullopt;
      const int32_t key_len = key.attributes().crypto_length().value_or(
          static_cast<int32_t>(key.value().size() * 8)
      );
      switch (key.type()) {
        case KeyType::SYMMETRIC_KEY: {
          auto symmetric_key =
              Element::createStructure(tag::KMIP_TAG_SYMMETRIC_KEY);
          symmetric_key->asStructure()->add(
              make_key_block(KMIP_KEYFORMAT_RAW, key.value(), key_alg, key_len)
          );
          return symmetric_key;
        }
        case KeyType::PRIVATE_KEY: {
          auto private_key =
              Element::createStructure(tag::KMIP_TAG_PRIVATE_KEY);
          private_key->asStructure()->add(make_key_block(
              KMIP_KEYFORMAT_PKCS8, key.value(), key_alg, key_len
          ));
          return private_key;
        }
        case KeyType::PUBLIC_KEY: {
          auto public_key = Element::createStructure(tag::KMIP_TAG_PUBLIC_KEY);
          public_key->asStructure()->add(
              make_key_block(KMIP_KEYFORMAT_X509, key.value(), key_alg, key_len)
          );
          return public_key;
        }
        case KeyType::CERTIFICATE:
          throw KmipException(
              KMIP_NOT_IMPLEMENTED,
              "Certificate registration is not yet supported"
          );
        case KeyType::UNSET:
        default:
          throw KmipException(
              KMIP_INVALID_FIELD, "Unsupported key type for Register"
          );
      }
    }
    int32_t object_type_from_key_type(KeyType key_type) {
      switch (key_type) {
        case KeyType::SYMMETRIC_KEY:
          return KMIP_OBJTYPE_SYMMETRIC_KEY;
        case KeyType::PRIVATE_KEY:
          return KMIP_OBJTYPE_PRIVATE_KEY;
        case KeyType::PUBLIC_KEY:
          return KMIP_OBJTYPE_PUBLIC_KEY;
        case KeyType::CERTIFICATE:
          return KMIP_OBJTYPE_CERTIFICATE;
        case KeyType::UNSET:
        default:
          throw KmipException(
              KMIP_INVALID_FIELD, "Unsupported key type for Register"
          );
      }
    }
    std::shared_ptr<Element>
        make_symmetric_key(const std::vector<unsigned char> &key_value) {
      auto symmetric_key =
          Element::createStructure(tag::KMIP_TAG_SYMMETRIC_KEY);
      symmetric_key->asStructure()->add(make_key_block(
          KMIP_KEYFORMAT_RAW,
          key_value,
          KMIP_CRYPTOALG_AES,
          static_cast<int32_t>(key_value.size() * 8)
      ));
      return symmetric_key;
    }
    std::shared_ptr<Element> make_secret_data(
        const std::vector<unsigned char> &secret, secret_data_type secret_type
    ) {
      auto secret_data = Element::createStructure(tag::KMIP_TAG_SECRET_DATA);
      secret_data->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_SECRET_DATA_TYPE, static_cast<int32_t>(secret_type)
          )
      );
      secret_data->asStructure()->add(make_key_block(
          KMIP_KEYFORMAT_OPAQUE, secret, std::nullopt, std::nullopt
      ));
      return secret_data;
    }
    std::shared_ptr<Element> make_attributes_container(
        const ProtocolVersion &version,
        const std::vector<std::shared_ptr<Element>> &attributes
    ) {
      if (use_attributes_container(version)) {
        auto attrs = Element::createStructure(tag::KMIP_TAG_ATTRIBUTES);
        for (const auto &attribute : attributes) {
          attrs->asStructure()->add(attribute);
        }
        return attrs;
      }
      return make_template_attribute(attributes);
    }

    // -------------------------------------------------------------------------
    // KMIP 2.0: helpers that build properly-typed child elements for the
    // Attributes container (no Attribute name/value wrappers).
    // -------------------------------------------------------------------------

    std::shared_ptr<Element> make_v2_name_struct(const std::string &value) {
      auto name = Element::createStructure(tag::KMIP_TAG_NAME);
      name->asStructure()->add(
          Element::createTextString(tag::KMIP_TAG_NAME_VALUE, value)
      );
      name->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_NAME_TYPE, KMIP_NAME_UNINTERPRETED_TEXT_STRING
          )
      );
      return name;
    }

    /**
     * @brief Builds an Attributes container (KMIP 2.0) for a symmetric-key
     *        Create request using properly typed child elements.
     */
    std::shared_ptr<Element> make_v2_create_symmetric_attrs(
        const std::string &name,
        const std::string &group,
        int32_t key_bits,
        cryptographic_usage_mask usage_mask
    ) {
      auto attrs = Element::createStructure(tag::KMIP_TAG_ATTRIBUTES);
      attrs->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, KMIP_CRYPTOALG_AES
          )
      );
      attrs->asStructure()->add(
          Element::createInteger(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, key_bits)
      );
      attrs->asStructure()->add(
          Element::createInteger(
              tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK,
              static_cast<int32_t>(usage_mask)
          )
      );
      attrs->asStructure()->add(make_v2_name_struct(name));
      if (!group.empty()) {
        attrs->asStructure()->add(
            Element::createTextString(tag::KMIP_TAG_OBJECT_GROUP, group)
        );
      }
      return attrs;
    }

    /**
     * @brief Builds an Attributes container (KMIP 2.0) for a Register
     *        (symmetric key) request.
     */
    std::shared_ptr<Element> make_v2_register_symmetric_attrs(
        const std::string &name,
        const std::string &group,
        int32_t key_bits,
        int32_t usage_mask_bits
    ) {
      auto attrs = Element::createStructure(tag::KMIP_TAG_ATTRIBUTES);
      attrs->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, KMIP_CRYPTOALG_AES
          )
      );
      attrs->asStructure()->add(
          Element::createInteger(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, key_bits)
      );
      attrs->asStructure()->add(
          Element::createInteger(
              tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK, usage_mask_bits
          )
      );
      attrs->asStructure()->add(make_v2_name_struct(name));
      if (!group.empty()) {
        attrs->asStructure()->add(
            Element::createTextString(tag::KMIP_TAG_OBJECT_GROUP, group)
        );
      }
      return attrs;
    }

    /**
     * @brief Builds an Attributes container (KMIP 2.0) for a Register
     *        (secret data) request.
     */
    std::shared_ptr<Element> make_v2_register_secret_attrs(
        const std::string &name, const std::string &group
    ) {
      auto attrs = Element::createStructure(tag::KMIP_TAG_ATTRIBUTES);
      attrs->asStructure()->add(
          Element::createInteger(
              tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK,
              KMIP_CRYPTOMASK_DERIVE_KEY | KMIP_CRYPTOMASK_EXPORT
          )
      );
      attrs->asStructure()->add(make_v2_name_struct(name));
      if (!group.empty()) {
        attrs->asStructure()->add(
            Element::createTextString(tag::KMIP_TAG_OBJECT_GROUP, group)
        );
      }
      return attrs;
    }

    /**
     * @brief Builds an Attributes container (KMIP 2.0) for a generic Register
     *        (key) request from a Key object's typed and generic attributes.
     */
    std::shared_ptr<Element> make_v2_register_key_attrs(
        const std::string &name, const std::string &group, const Key &key
    ) {
      auto attrs = Element::createStructure(tag::KMIP_TAG_ATTRIBUTES);
      attrs->asStructure()->add(make_v2_name_struct(name));
      if (!group.empty()) {
        attrs->asStructure()->add(
            Element::createTextString(tag::KMIP_TAG_OBJECT_GROUP, group)
        );
      }
      if (const auto alg = key.attributes().algorithm();
          alg != cryptographic_algorithm::KMIP_CRYPTOALG_UNSET) {
        attrs->asStructure()->add(
            Element::createEnumeration(
                tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, static_cast<int32_t>(alg)
            )
        );
      }
      const int32_t key_len = key.attributes().crypto_length().value_or(
          static_cast<int32_t>(key.value().size() * 8)
      );
      if (key_len > 0) {
        attrs->asStructure()->add(
            Element::createInteger(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH, key_len)
        );
      }
      if (const auto mask = key.attributes().usage_mask();
          mask != cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET) {
        attrs->asStructure()->add(
            Element::createInteger(
                tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK,
                static_cast<int32_t>(mask)
            )
        );
      }
      // Generic attributes: not representable as typed KMIP 2.0 elements;
      // omit them to avoid protocol errors. Callers should use well-known
      // typed fields for all standard attributes.
      return attrs;
    }

  }  // namespace detail

  GetAttributesRequest::GetAttributesRequest(
      const std::string &unique_id,
      const std::vector<std::string> &attribute_names,
      ProtocolVersion version,
      bool legacy_attribute_names_for_v2
  ) {
    setOperation(KMIP_OP_GET_ATTRIBUTES);
    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    payload->asStructure()->add(
        Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, unique_id)
    );

    // Deduplicate selectors while preserving first-seen order.
    std::vector<std::string> unique_names;
    std::unordered_set<std::string> seen;
    unique_names.reserve(attribute_names.size());
    for (const auto &attr_name : attribute_names) {
      if (seen.insert(attr_name).second) {
        unique_names.push_back(attr_name);
      }
    }

    if (detail::use_attributes_container(version) &&
        !legacy_attribute_names_for_v2) {
      // KMIP 2.0: Get Attributes selectors are Attribute Reference structures.
      for (const auto &attr_name : unique_names) {
        payload->asStructure()->add(
            detail::make_v2_attribute_reference(attr_name)
        );
      }
    } else {
      // KMIP 1.x and compatibility fallback: selectors as Attribute Name text
      // strings.
      for (const auto &attr_name : unique_names) {
        payload->asStructure()->add(
            Element::createTextString(tag::KMIP_TAG_ATTRIBUTE_NAME, attr_name)
        );
      }
    }

    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // CreateSymmetricKeyRequest
  // ---------------------------------------------------------------------------
  CreateSymmetricKeyRequest::CreateSymmetricKeyRequest(
      const std::string &name,
      const std::string &group,
      int32_t key_bits,
      cryptographic_usage_mask usage_mask,
      ProtocolVersion version
  ) {
    setOperation(KMIP_OP_CREATE);

    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    payload->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_OBJECT_TYPE, KMIP_OBJTYPE_SYMMETRIC_KEY
        )
    );

    if (detail::use_attributes_container(version)) {
      // KMIP 2.0: properly typed elements in Attributes container.
      payload->asStructure()->add(
          detail::make_v2_create_symmetric_attrs(
              name, group, key_bits, usage_mask
          )
      );
    } else {
      // KMIP 1.x: Attribute name/value pairs wrapped in TemplateAttribute.
      std::vector<std::shared_ptr<Element>> attributes;
      attributes.push_back(
          detail::make_enum_attribute(
              "Cryptographic Algorithm", KMIP_CRYPTOALG_AES
          )
      );
      attributes.push_back(
          detail::make_integer_attribute("Cryptographic Length", key_bits)
      );
      attributes.push_back(
          detail::make_integer_attribute(
              "Cryptographic Usage Mask", static_cast<int32_t>(usage_mask)
          )
      );
      attributes.push_back(detail::make_name_attribute(name));
      if (!group.empty()) {
        attributes.push_back(
            detail::make_text_attribute("Object Group", group)
        );
      }
      payload->asStructure()->add(detail::make_template_attribute(attributes));
    }

    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // RegisterSymmetricKeyRequest
  // ---------------------------------------------------------------------------
  RegisterSymmetricKeyRequest::RegisterSymmetricKeyRequest(
      const std::string &name,
      const std::string &group,
      const std::vector<unsigned char> &key_value,
      ProtocolVersion version
  ) {
    setOperation(KMIP_OP_REGISTER);

    const int32_t key_bits = static_cast<int32_t>(key_value.size() * 8);

    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    payload->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_OBJECT_TYPE, KMIP_OBJTYPE_SYMMETRIC_KEY
        )
    );

    if (detail::use_attributes_container(version)) {
      payload->asStructure()->add(
          detail::make_v2_register_symmetric_attrs(
              name,
              group,
              key_bits,
              KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT
          )
      );
    } else {
      std::vector<std::shared_ptr<Element>> attributes;
      attributes.push_back(
          detail::make_enum_attribute(
              "Cryptographic Algorithm", KMIP_CRYPTOALG_AES
          )
      );
      attributes.push_back(
          detail::make_integer_attribute("Cryptographic Length", key_bits)
      );
      attributes.push_back(
          detail::make_integer_attribute(
              "Cryptographic Usage Mask",
              KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT
          )
      );
      attributes.push_back(detail::make_name_attribute(name));
      if (!group.empty()) {
        attributes.push_back(
            detail::make_text_attribute("Object Group", group)
        );
      }
      payload->asStructure()->add(detail::make_template_attribute(attributes));
    }

    payload->asStructure()->add(detail::make_symmetric_key(key_value));
    setRequestPayload(payload);
  }

  RegisterKeyRequest::RegisterKeyRequest(
      const std::string &name,
      const std::string &group,
      const Key &key,
      ProtocolVersion version
  ) {
    setOperation(KMIP_OP_REGISTER);

    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    payload->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_OBJECT_TYPE,
            detail::object_type_from_key_type(key.type())
        )
    );

    if (detail::use_attributes_container(version)) {
      // KMIP 2.0: properly typed elements in Attributes container.
      payload->asStructure()->add(
          detail::make_v2_register_key_attrs(name, group, key)
      );
    } else {
      // KMIP 1.x: Attribute name/value pairs in TemplateAttribute.
      std::vector<std::shared_ptr<Element>> attributes;
      attributes.push_back(detail::make_name_attribute(name));
      if (!group.empty()) {
        attributes.push_back(
            detail::make_text_attribute("Object Group", group)
        );
      }

      if (const auto alg = key.attributes().algorithm();
          alg != cryptographic_algorithm::KMIP_CRYPTOALG_UNSET) {
        attributes.push_back(
            detail::make_enum_attribute(
                "Cryptographic Algorithm", static_cast<int32_t>(alg)
            )
        );
      }
      if (const auto len = key.attributes().crypto_length(); len.has_value()) {
        attributes.push_back(
            detail::make_integer_attribute("Cryptographic Length", *len)
        );
      } else if (!key.value().empty()) {
        attributes.push_back(
            detail::make_integer_attribute(
                "Cryptographic Length",
                static_cast<int32_t>(key.value().size() * 8)
            )
        );
      }
      if (const auto mask = key.attributes().usage_mask();
          mask != cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET) {
        attributes.push_back(
            detail::make_integer_attribute(
                "Cryptographic Usage Mask", static_cast<int32_t>(mask)
            )
        );
      }

      for (const auto &[attr_name, attr_val] : key.attributes().generic()) {
        if (attr_name == "Name" || attr_name == "Object Group") {
          continue;
        }
        std::string str_val = std::visit(
            [](const auto &val) -> std::string {
              using T = std::decay_t<decltype(val)>;
              if constexpr (std::is_same_v<T, std::string>) {
                return val;
              } else if constexpr (std::is_same_v<T, bool>) {
                return val ? "true" : "false";
              } else {
                return std::to_string(val);
              }
            },
            attr_val
        );
        attributes.push_back(detail::make_text_attribute(attr_name, str_val));
      }
      payload->asStructure()->add(detail::make_template_attribute(attributes));
    }

    payload->asStructure()->add(detail::make_key_object_from_key(key));
    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // RegisterSecretRequest
  // ---------------------------------------------------------------------------
  RegisterSecretRequest::RegisterSecretRequest(
      const std::string &name,
      const std::string &group,
      const std::vector<unsigned char> &secret,
      secret_data_type secret_type,
      ProtocolVersion version
  ) {
    setOperation(KMIP_OP_REGISTER);

    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    payload->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_OBJECT_TYPE, KMIP_OBJTYPE_SECRET_DATA
        )
    );

    if (detail::use_attributes_container(version)) {
      payload->asStructure()->add(
          detail::make_v2_register_secret_attrs(name, group)
      );
    } else {
      std::vector<std::shared_ptr<Element>> attributes;
      attributes.push_back(
          detail::make_integer_attribute(
              "Cryptographic Usage Mask",
              KMIP_CRYPTOMASK_DERIVE_KEY | KMIP_CRYPTOMASK_EXPORT
          )
      );
      attributes.push_back(detail::make_name_attribute(name));
      if (!group.empty()) {
        attributes.push_back(
            detail::make_text_attribute("Object Group", group)
        );
      }
      payload->asStructure()->add(detail::make_template_attribute(attributes));
    }

    payload->asStructure()->add(detail::make_secret_data(secret, secret_type));
    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // LocateRequest
  // ---------------------------------------------------------------------------
  LocateRequest::LocateRequest(
      bool locate_by_group,
      const std::string &name,
      object_type obj_type,
      size_t max_items,
      size_t offset,
      ProtocolVersion version
  ) {
    setOperation(KMIP_OP_LOCATE);

    constexpr auto int32_max =
        static_cast<size_t>(std::numeric_limits<int32_t>::max());
    if (max_items > int32_max) {
      throw KmipException(
          "LocateRequest: max_items value " + std::to_string(max_items) +
          " exceeds int32_t maximum (" + std::to_string(int32_max) + ")"
      );
    }
    if (offset > int32_max) {
      throw KmipException(
          "LocateRequest: offset value " + std::to_string(offset) +
          " exceeds int32_t maximum (" + std::to_string(int32_max) + ")"
      );
    }

    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    if (max_items > 0) {
      payload->asStructure()->add(
          Element::createInteger(
              tag::KMIP_TAG_MAXIMUM_ITEMS, static_cast<int32_t>(max_items)
          )
      );
    }
    if (offset > 0) {
      payload->asStructure()->add(
          Element::createInteger(
              tag::KMIP_TAG_OFFSET_ITEMS, static_cast<int32_t>(offset)
          )
      );
    }

    if (detail::use_attributes_container(version)) {
      // KMIP 2.0: filter attributes go into an Attributes container with
      // properly typed child elements.
      auto attrs = Element::createStructure(tag::KMIP_TAG_ATTRIBUTES);
      attrs->asStructure()->add(
          Element::createEnumeration(
              tag::KMIP_TAG_OBJECT_TYPE, static_cast<int32_t>(obj_type)
          )
      );
      if (!name.empty()) {
        if (locate_by_group) {
          attrs->asStructure()->add(
              Element::createTextString(tag::KMIP_TAG_OBJECT_GROUP, name)
          );
        } else {
          attrs->asStructure()->add(detail::make_v2_name_struct(name));
        }
      }
      payload->asStructure()->add(attrs);
    } else {
      // KMIP 1.x: individual Attribute structures directly in payload.
      payload->asStructure()->add(
          detail::make_enum_attribute(
              "Object Type", static_cast<int32_t>(obj_type)
          )
      );
      if (!name.empty()) {
        if (locate_by_group) {
          payload->asStructure()->add(
              detail::make_text_attribute("Object Group", name)
          );
        } else {
          payload->asStructure()->add(detail::make_name_attribute(name));
        }
      }
    }
    setRequestPayload(payload);
  }

  // ---------------------------------------------------------------------------
  // RevokeRequest
  // ---------------------------------------------------------------------------
  RevokeRequest::RevokeRequest(
      const std::string &unique_id,
      revocation_reason_type reason,
      const std::string &message,
      time_t occurrence_time
  ) {
    setOperation(KMIP_OP_REVOKE);

    auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
    payload->asStructure()->add(
        Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, unique_id)
    );

    auto revocation_reason =
        Element::createStructure(tag::KMIP_TAG_REVOCATION_REASON);
    revocation_reason->asStructure()->add(
        Element::createEnumeration(
            tag::KMIP_TAG_REVOCATION_REASON_CODE, static_cast<int32_t>(reason)
        )
    );
    if (!message.empty()) {
      revocation_reason->asStructure()->add(
          Element::createTextString(tag::KMIP_TAG_REVOKATION_MESSAGE, message)
      );
    }
    payload->asStructure()->add(revocation_reason);

    if (occurrence_time > 0) {
      payload->asStructure()->add(
          Element::createDateTime(
              tag::KMIP_TAG_COMPROMISE_OCCURRANCE_DATE,
              static_cast<int64_t>(occurrence_time)
          )
      );
    }
    setRequestPayload(payload);
  }


}  // namespace kmipcore
