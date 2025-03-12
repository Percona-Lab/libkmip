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

#include "KeyFactory.hpp"
#include "../include/kmip_exceptions.hpp"
#include "AttributesFactory.hpp"

namespace kmipclient
{

Key
kmipclient::KeyFactory::parse_response (const GetResponsePayload *pld)
{
  switch (pld->object_type)
    {
    case KMIP_OBJTYPE_SYMMETRIC_KEY:
      {
        auto     *symmetric_key = static_cast<SymmetricKey *> (pld->object);
        KeyBlock *block         = symmetric_key->key_block;
        if ((block->key_format_type != KMIP_KEYFORMAT_RAW) || (block->key_wrapping_data != nullptr))
          {
            throw ErrorException (KMIP_INVALID_ENCODING, "Invalid response object format.");
          }
        auto block_value = static_cast<KeyValue *> (block->key_value);
        auto material    = static_cast<ByteString *> (block_value->key_material);

        key_t kv (material->value, material->value + material->size);
        // Do we have some other attributes here with any KMIP server? block_value->attribute_count is 0
        auto  key_attributes = AttributesFactory::parse (block_value->attributes, block_value->attribute_count);
        Key   key (kv, KeyType::SYMMETRIC_KEY, block->cryptographic_algorithm,
                   cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET, key_attributes);

        return key;
      }
    case KMIP_OBJTYPE_PRIVATE_KEY:
      {
        throw ErrorException (KMIP_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
      }
    case KMIP_OBJTYPE_PUBLIC_KEY:
      {
        throw ErrorException (KMIP_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
      }
    case KMIP_OBJTYPE_CERTIFICATE:
      {
        throw ErrorException (KMIP_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
      }
    default:
      {
        throw ErrorException (KMIP_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
      }
    }
}
}