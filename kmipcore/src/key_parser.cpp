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

#include "kmipcore/key_parser.hpp"

#include "kmipcore/attributes_parser.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_errors.hpp"

namespace kmipcore {

  namespace {

    /** Extract a Key from an element that contains a KeyBlock (Symmetric Key,
     * Private Key, Public Key). */
    Key parse_key_from_key_block_holder(
        const std::shared_ptr<Element> &object_element,
        KeyType key_type,
        const char *type_name
    ) {
      auto key_block = object_element->getChild(tag::KMIP_TAG_KEY_BLOCK);
      if (!key_block) {
        throw KmipException(
            KMIP_INVALID_ENCODING,
            std::string("Missing Key Block in ") + type_name + " response."
        );
      }

      auto key_value = key_block->getChild(tag::KMIP_TAG_KEY_VALUE);
      if (!key_value) {
        throw KmipException(
            KMIP_INVALID_ENCODING,
            std::string("Missing Key Value in ") + type_name + " response."
        );
      }

      auto key_material = key_value->getChild(tag::KMIP_TAG_KEY_MATERIAL);
      if (!key_material) {
        throw KmipException(
            KMIP_INVALID_ENCODING,
            std::string("Missing Key Material in ") + type_name + " response."
        );
      }

      auto raw_bytes = key_material->toBytes();
      std::vector<unsigned char> kv(raw_bytes.begin(), raw_bytes.end());

      // Parse attributes from the key value's Attribute children.
      Attributes key_attrs = AttributesParser::parse(
          key_value->getChildren(tag::KMIP_TAG_ATTRIBUTE)
      );

      // Algorithm and Length may also appear directly in the Key Block.
      if (auto alg_elem =
              key_block->getChild(tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM)) {
        key_attrs.set_algorithm(
            static_cast<cryptographic_algorithm>(alg_elem->toEnum())
        );
      }
      if (auto len_elem =
              key_block->getChild(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH)) {
        key_attrs.set_crypto_length(len_elem->toInt());
      }

      return Key(kv, key_type, std::move(key_attrs));
    }

  }  // anonymous namespace

  Key KeyParser::parseGetKeyResponse(const GetResponseBatchItem &item) {
    return parseResponse(item.getResponsePayload());
  }

  Secret KeyParser::parseGetSecretResponse(const GetResponseBatchItem &item) {
    if (item.getObjectType() != KMIP_OBJTYPE_SECRET_DATA) {
      throw KmipException(
          KMIP_REASON_INVALID_DATA_TYPE, "Secret data expected in Get response."
      );
    }

    auto object = item.getObjectElement();
    if (!object) {
      throw KmipException(
          KMIP_INVALID_ENCODING, "Missing Secret Data object in response."
      );
    }

    auto secret_type = object->getChild(tag::KMIP_TAG_SECRET_DATA_TYPE);
    auto key_block = object->getChild(tag::KMIP_TAG_KEY_BLOCK);
    if (!secret_type || !key_block) {
      throw KmipException(
          KMIP_INVALID_ENCODING, "Secret data key block format mismatch"
      );
    }

    auto key_format = key_block->getChild(tag::KMIP_TAG_KEY_FORMAT_TYPE);
    if (!key_format || (key_format->toEnum() != KMIP_KEYFORMAT_OPAQUE &&
                        key_format->toEnum() != KMIP_KEYFORMAT_RAW)) {
      throw KmipException(
          KMIP_OBJECT_MISMATCH, "Secret data key block format mismatch"
      );
    }

    auto key_value = key_block->getChild(tag::KMIP_TAG_KEY_VALUE);
    if (!key_value) {
      throw KmipException(KMIP_INVALID_ENCODING, "Missing secret key value.");
    }

    auto key_material = key_value->getChild(tag::KMIP_TAG_KEY_MATERIAL);
    if (!key_material) {
      throw KmipException(
          KMIP_INVALID_ENCODING, "Missing secret key material."
      );
    }

    auto raw_bytes = key_material->toBytes();

    Secret secret;
    secret.set_value(
        std::vector<unsigned char>(raw_bytes.begin(), raw_bytes.end())
    );
    secret.set_secret_type(
        static_cast<secret_data_type>(secret_type->toEnum())
    );
    return secret;
  }

  Key KeyParser::parseResponse(const std::shared_ptr<Element> &payload) {
    if (payload == nullptr) {
      throw KmipException(KMIP_INVALID_ENCODING, "Missing response payload.");
    }

    auto object_type = payload->getChild(tag::KMIP_TAG_OBJECT_TYPE);
    if (!object_type) {
      throw KmipException(
          KMIP_INVALID_ENCODING, "Missing Object Type in Get response."
      );
    }

    // Map KMIP object type to wrapper tag, KeyType, and human-readable name.
    struct ObjectTypeMapping {
      int32_t obj_type;
      int32_t wrapper_tag;
      KeyType key_type;
      const char *name;
    };
    static constexpr ObjectTypeMapping mappings[] = {
        {KMIP_OBJTYPE_SYMMETRIC_KEY,
         KMIP_TAG_SYMMETRIC_KEY,
         KeyType::SYMMETRIC_KEY,
         "Symmetric Key"},
        {KMIP_OBJTYPE_PRIVATE_KEY,
         KMIP_TAG_PRIVATE_KEY,
         KeyType::PRIVATE_KEY,
         "Private Key"},
        {KMIP_OBJTYPE_PUBLIC_KEY,
         KMIP_TAG_PUBLIC_KEY,
         KeyType::PUBLIC_KEY,
         "Public Key"},
    };

    const auto obj_type_val = object_type->toEnum();

    for (const auto &m : mappings) {
      if (obj_type_val != m.obj_type) {
        continue;
      }

      auto object_element = payload->getChild(static_cast<Tag>(m.wrapper_tag));
      if (!object_element) {
        throw KmipException(
            KMIP_INVALID_ENCODING,
            std::string("Missing ") + m.name + " object in Get response."
        );
      }

      // Symmetric keys require RAW format
      if (m.obj_type == KMIP_OBJTYPE_SYMMETRIC_KEY) {
        auto key_block = object_element->getChild(tag::KMIP_TAG_KEY_BLOCK);
        if (key_block) {
          auto key_format = key_block->getChild(tag::KMIP_TAG_KEY_FORMAT_TYPE);
          if (!key_format || key_format->toEnum() != KMIP_KEYFORMAT_RAW) {
            throw KmipException(
                KMIP_INVALID_ENCODING, "Invalid response object format."
            );
          }
        }
      }

      return parse_key_from_key_block_holder(
          object_element, m.key_type, m.name
      );
    }

    if (obj_type_val == KMIP_OBJTYPE_CERTIFICATE) {
      throw KmipException(
          KMIP_NOT_IMPLEMENTED,
          "Certificate object type parsing is not yet supported."
      );
    }

    throw KmipException(
        KMIP_NOT_IMPLEMENTED,
        std::string("Unsupported object type: ") + std::to_string(obj_type_val)
    );
  }

}  // namespace kmipcore
