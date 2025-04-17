//
// Created by al on 01.04.25.
//

#include "KeyFactory.hpp"
#include "AttributesFactory.hpp"

namespace kmipclient
{

ve::expected<Key, Error>
kmipclient::KeyFactory::parse_response (GetResponsePayload *pld)
{
  switch (pld->object_type)
    {
    case KMIP_OBJTYPE_SYMMETRIC_KEY:
      {
        auto     *symmetric_key = static_cast<SymmetricKey *> (pld->object);
        KeyBlock *block         = symmetric_key->key_block;
        if ((block->key_format_type != KMIP_KEYFORMAT_RAW) || (block->key_wrapping_data != nullptr))
          {
            return Error (-1, "Invalid response object format.");
          }
        auto block_value = static_cast<KeyValue *> (block->key_value);
        auto material    = static_cast<ByteString *> (block_value->key_material);

        key_t kv (material->value, material->value + material->size);

        auto key_attributes = AttributesFactory::parse (block_value->attributes, block_value->attribute_count);
        Key  key (kv, KeyType::KEY_TYPE_SYMMETRIC_KEY, KeyAlgorithm::KEY_ALGORITHM_AES, key_attributes);

        return key;
      }
    case KMIP_OBJTYPE_PRIVATE_KEY:
      {
        return Error (KMIP_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
      }
    case KMIP_OBJTYPE_PUBLIC_KEY:
      {
        return Error (KMIP_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
      }
    case KMIP_OBJTYPE_CERTIFICATE:
      {
        return Error (KMIP_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
      }
    default:
      {
        return Error (KMIP_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
      }
    }
}
}