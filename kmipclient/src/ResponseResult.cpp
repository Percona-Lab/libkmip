//
// Created by al on 24.03.25.
//
#include <sstream>

#include "KeyFactory.hpp"
#include "ResponseResult.hpp"

#include "StringUtils.hpp"

#include "kmip.h"
#include "kmip_locate.h"

namespace kmipclient
{

std::string
from_kmip_text (TextString *s)
{
  return std::string{ s->value, s->size };
}

ve::expected<id_t, Error>
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
      return Error (KMIP_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
    }
  return id;
}

ve::expected<Key, Error>
ResponseResult::get_key (ResponseBatchItem *rbi)
{
  auto *pld = static_cast<GetResponsePayload *> (rbi->response_payload);
  switch (pld->object_type)
    {
      // name known to KeyFactory key types
    case KMIP_OBJTYPE_SYMMETRIC_KEY:
    KMIP_OBJTYPE_PUBLIC_KEY:
    KMIP_OBJTYPE_PRIVATE_KEY:
    KMIP_OBJTYPE_CERTIFICATE:
      {
        return KeyFactory::parse_response (pld);
      };
    default:
      return Error (-1, "Invalid response object type.");
    }
}

ve::expected<Secret, Error>
ResponseResult::get_secret (ResponseBatchItem *rbi)
{
  if (auto *pld = static_cast<GetResponsePayload *> (rbi->response_payload);
      pld->object_type != KMIP_OBJTYPE_SECRET_DATA)
    {
      return Error (KMIP_REASON_INVALID_DATA_TYPE, "Secret data expected");
    }
  else
    {
      auto     *secret = static_cast<SecretData *> (pld->object);
      KeyBlock *block  = secret->key_block;
      if ((block->key_format_type != KMIP_KEYFORMAT_OPAQUE) || (block->key_wrapping_data != NULL))
        {
          return Error (KMIP_OBJECT_MISMATCH, "Secret data key block format mismatch");
        }

      auto   block_value = static_cast<KeyValue *> (block->key_value);
      auto  *material    = static_cast<ByteString *> (block_value->key_material);
      size_t secret_size = material->size;
      char   result_key[secret_size];
      for (int i = 0; i < secret_size; i++)
        {
          result_key[i] = material->value[i];
        }
      return Secret{ result_key, 0, static_cast<int> (secret->secret_data_type) };
    }
}

ve::expected<name_t, Error>
ResponseResult::get_attributes (ResponseBatchItem *rbi)
{
  auto      *pld = static_cast<GetAttributeResponsePayload *> (rbi->response_payload);
  name_t     res;
  Attribute *attribute = pld->attribute;
  switch (attribute->type)
    {
    case KMIP_ATTR_UNIQUE_IDENTIFIER:
    case KMIP_ATTR_NAME:
      {
        const auto *ns = static_cast<Name *> (pld->attribute->value);
        const auto *ts = static_cast<TextString *> (ns->value);
        res            = StringUtils::fromKmipText (ts);
      }
      break;
    case KMIP_ATTR_STATE:
      {
        const auto       *a = static_cast<enum kmip_entity_state *> (pld->attribute->value);
        std::stringstream ss;
        ss << *a;
        res = ss.str ();
      }
      break;
    default:
      {
        res = "Unknown attribute type, not converted";
      }
    }
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

ve::expected<ids_t, Error>
ResponseResult::get_ids (ResponseBatchItem *rbi)
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