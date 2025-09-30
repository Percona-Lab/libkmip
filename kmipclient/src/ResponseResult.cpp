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

#include "ResponseResult.hpp"
#include "KeyFactory.hpp"

#include "AttributesFactory.hpp"
#include "StringUtils.hpp"

#include "kmip.h"
#include "kmip_exceptions.hpp"
#include "kmip_locate.h"

namespace kmipclient
{

std::string
from_kmip_text (const TextString *s)
{
  return std::string{ s->value, s->size };
}

id_t
ResponseResult::get_id (const ResponseBatchItem *rbi)
{
  id_t id;
  switch (rbi->operation)
    {
    case KMIP_OP_CREATE:
      {
        auto *pld = static_cast<CreateResponsePayload *> (rbi->response_payload);
        id        = std::string{ pld->unique_identifier->value, pld->unique_identifier->size };
      }
      break;
    case KMIP_OP_GET:
      {
        auto *pld = static_cast<GetResponsePayload *> (rbi->response_payload);
        id        = std::string{ pld->unique_identifier->value, pld->unique_identifier->size };
      }
      break;
    case KMIP_OP_REGISTER:
      {
        auto *pld = static_cast<RegisterResponsePayload *> (rbi->response_payload);
        id        = std::string{ pld->unique_identifier->value, pld->unique_identifier->size };
      }
      break;
    case KMIP_OP_ACTIVATE:
      {
        auto *pld = static_cast<ActivateResponsePayload *> (rbi->response_payload);
        id        = std::string{ pld->unique_identifier->value, pld->unique_identifier->size };
      }
      break;
    case KMIP_OP_REVOKE:
      {
        const auto *pld = static_cast<RevokeResponsePayload *> (rbi->response_payload);
        id              = std::string{ pld->unique_identifier->value, pld->unique_identifier->size };
      }
      break;
    case KMIP_OP_DESTROY:
      {
        const auto *pld = static_cast<DestroyResponsePayload *> (rbi->response_payload);
        id              = std::string{ pld->unique_identifier->value, pld->unique_identifier->size };
      }
      break;
    // TODO: other operations
    default:
      throw ErrorException (KMIP_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
    }
  return id;
}

Key
ResponseResult::get_key (const ResponseBatchItem *rbi)
{
  auto *pld = static_cast<GetResponsePayload *> (rbi->response_payload);
  switch (pld->object_type)
    {
      // name known to KeyFactory key types
    case KMIP_OBJTYPE_SYMMETRIC_KEY:
    case KMIP_OBJTYPE_PUBLIC_KEY:
    case KMIP_OBJTYPE_PRIVATE_KEY:
    case KMIP_OBJTYPE_CERTIFICATE:
      {
        return KeyFactory::parse_response (pld);
      };
    default:
      throw ErrorException ("Invalid or unknown response object type.");
    }
}

Secret
ResponseResult::get_secret (const ResponseBatchItem *rbi)
{
  if (auto *pld = static_cast<GetResponsePayload *> (rbi->response_payload);
      pld->object_type != KMIP_OBJTYPE_SECRET_DATA)
    {
      throw ErrorException (KMIP_REASON_INVALID_DATA_TYPE, "Secret data expected");
    }
  else
    {
      auto     *secret = static_cast<SecretData *> (pld->object);
      KeyBlock *block  = secret->key_block;
      if (!(block->key_format_type != KMIP_KEYFORMAT_OPAQUE || block->key_format_type != KMIP_KEYFORMAT_RAW)
          || (block->key_wrapping_data != nullptr))
        {
          throw ErrorException (KMIP_OBJECT_MISMATCH, "Secret data key block format mismatch");
        }

      auto   block_value = static_cast<KeyValue *> (block->key_value);
      auto  *material    = static_cast<ByteString *> (block_value->key_material);
      size_t secret_size = material->size;
      char   result_key[secret_size];
      for (int i = 0; i < secret_size; i++)
        {
          result_key[i] = static_cast<char> (material->value[i]);
        }
      // TODO: State attribute should be in the key response but it is empty. How to read a state from kmip? RBI?
      return Secret{ result_key, KMIP_STATE_PRE_ACTIVE, secret->secret_data_type };
    }
}

attributes_t
ResponseResult::get_attributes (const ResponseBatchItem *rbi)
{
  auto *pld = static_cast<GetAttributeResponsePayload *> (rbi->response_payload);

  Attribute *attribute = pld->attribute;
  // TODO: how to read multiple attributes? How to get attribute count?
  //  Solution: re-implement parsing in C++ or change to linked list in kmip.c
  return AttributesFactory::parse (attribute, 1);
}

names_t
ResponseResult::get_attribute_list (const ResponseBatchItem *rbi)
{
  names_t res;
  auto   *pld = static_cast<GetAttributeListResponsePayload *> (rbi->response_payload);
  // TODO: process multiple
  res.push_back (StringUtils::fromKmipText (pld->attribute_name));
  return res;
}

void
copy_unique_ids (char ids[][MAX_LOCATE_LEN], size_t *id_size, const UniqueIdentifiers *value, const unsigned max_ids)
{
  size_t idx = 0;
  if (value != nullptr)
    {
      LinkedListItem *curr = value->unique_identifier_list->head;
      while (curr != nullptr && idx < max_ids)
        {
          kmip_copy_textstring (ids[idx], static_cast<TextString *> (curr->data), MAX_LOCATE_LEN - 1);
          curr = curr->next;
          idx++;
        }
    }
  *id_size = idx;
}

ids_t
ResponseResult::get_ids (const ResponseBatchItem *rbi)
{
  auto           pld = static_cast<LocateResponsePayload *> (rbi->response_payload);
  LocateResponse locate_result;
  copy_unique_ids (locate_result.ids, &locate_result.ids_size, pld->unique_ids, MAX_LOCATE_IDS);
  ids_t res;
  for (int i = 0; i < locate_result.ids_size; ++i)
    {
      res.emplace_back (locate_result.ids[i]);
    }

  return res;
}

}