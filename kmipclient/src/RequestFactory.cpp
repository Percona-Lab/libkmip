//
// Created by al on 21.03.25.
//

#include "RequestFactory.hpp"

#include "KmipCtx.hpp"
#include "KmipRequest.hpp"
#include "kmip.h"

#include <kmip_locate.h>

namespace kmipclient
{

void
RequestFactory::create_get_rq (const id_t &id)
{

  TextString uuid = {};
  uuid.size       = id.size ();
  uuid.value      = const_cast<char *> (id.c_str ());

  GetRequestPayload grp{};
  grp.unique_identifier = &uuid;

  RequestBatchItem rbi{};
  kmip_init_request_batch_item (&rbi);
  rbi.operation       = KMIP_OP_GET;
  rbi.request_payload = &grp;

  rq.add_batch_item (&rbi);
  rq.encode ();
}

void
RequestFactory::create_activate_rq (const id_t &id)
{
  TextString uuid = {};
  uuid.size       = id.size ();
  uuid.value      = const_cast<char *> (id.c_str ());

  ActivateRequestPayload arp{};
  arp.unique_identifier = &uuid;

  RequestBatchItem rbi{};
  kmip_init_request_batch_item (&rbi);
  rbi.operation       = KMIP_OP_ACTIVATE;
  rbi.request_payload = &arp;

  rq.add_batch_item (&rbi);
  rq.encode ();
}

void
RequestFactory::create_create_aes_rq (const name_t &name, const name_t &group)
{

  Attribute a[5];
  for (auto &i : a)
    {
      kmip_init_attribute (&i);
    }

  enum cryptographic_algorithm algorithm = KMIP_CRYPTOALG_AES;
  a[0].type                              = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
  a[0].value                             = &algorithm;

  int32 length = 256;
  a[1].type    = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
  a[1].value   = &length;

  int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
  a[2].type  = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
  a[2].value = &mask;

  Name       ts;
  TextString ts2 = { nullptr, 0 };
  ts2.value      = const_cast<char *> (name.c_str ());
  ts2.size       = kmip_strnlen_s (ts2.value, 250);
  ts.value       = &ts2;
  ts.type        = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
  a[3].type      = KMIP_ATTR_NAME;
  a[3].value     = &ts;

  TextString gs2 = { 0, 0 };
  gs2.value      = const_cast<char *> (group.c_str ());
  gs2.size       = kmip_strnlen_s (gs2.value, 250);
  a[4].type      = KMIP_ATTR_OBJECT_GROUP;
  a[4].value     = &gs2;

  TemplateAttribute ta = {};
  ta.attributes        = a;
  ta.attribute_count   = std::size (a);

  int   id_max_len = 64;
  char *idp        = nullptr;

  CreateRequestPayload crp = {};
  crp.object_type          = KMIP_OBJTYPE_SYMMETRIC_KEY;
  crp.template_attribute   = &ta;

  RequestBatchItem rbi = {};
  kmip_init_request_batch_item (&rbi);
  rbi.operation       = KMIP_OP_CREATE;
  rbi.request_payload = &crp;

  rq.add_batch_item (&rbi);
  rq.encode ();
}

void
RequestFactory::create_register_key_rq (const name_t &name, const name_t &group, Key &k)
{

  int attr_count;

  group.empty () ? attr_count = 4 : attr_count = 5;

  Attribute a[attr_count];
  for (int i = 0; i < attr_count; i++)
    {
      kmip_init_attribute (&a[i]);
    }

  enum cryptographic_algorithm algorithm = KMIP_CRYPTOALG_AES;
  a[0].type                              = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
  a[0].value                             = &algorithm;
  key_t key                              = k.value ();
  int32 length                           = key.size () * 8;
  a[1].type                              = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
  a[1].value                             = &length;

  int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
  a[2].type  = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
  a[2].value = &mask;

  Name       ts;
  TextString ts2 = { nullptr, 0 };
  ts2.value      = const_cast<char *> (name.c_str ());
  ts2.size       = kmip_strnlen_s (ts2.value, 250);
  ts.value       = &ts2;
  ts.type        = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
  a[3].type      = KMIP_ATTR_NAME;
  a[3].value     = &ts;

  if (attr_count == 5)
    {
      TextString gs2 = { 0, 0 };
      gs2.value      = const_cast<char *> (group.c_str ());
      gs2.size       = kmip_strnlen_s (gs2.value, 250);
      a[4].type      = KMIP_ATTR_OBJECT_GROUP;
      a[4].value     = &gs2;
    }

  TemplateAttribute ta       = {};
  ta.attributes              = a;
  ta.attribute_count         = attr_count;
  RegisterRequestPayload crp = {};
  crp.object_type            = KMIP_OBJTYPE_SYMMETRIC_KEY;
  crp.template_attribute     = &ta;

  KeyBlock kb;
  crp.object.symmetric_key.key_block = &kb;
  kmip_init_key_block (crp.object.symmetric_key.key_block);
  crp.object.symmetric_key.key_block->key_format_type = KMIP_KEYFORMAT_RAW;
  // key compression should be not set for HasiCorp Vault
  // crp.object.symmetric_key.key_block->key_compression_type = KMIP_KEYCOMP_EC_PUB_UNCOMPRESSED;

  ByteString bs;
  bs.value = key.data ();
  bs.size  = key.size ();

  KeyValue kv;
  kv.key_material    = &bs;
  kv.attribute_count = 0;
  kv.attributes      = nullptr;

  crp.object.symmetric_key.key_block->key_value               = &kv;
  crp.object.symmetric_key.key_block->key_value_type          = KMIP_TYPE_BYTE_STRING;
  crp.object.symmetric_key.key_block->cryptographic_algorithm = KMIP_CRYPTOALG_AES;
  crp.object.symmetric_key.key_block->cryptographic_length    = key.size () * 8;

  RequestBatchItem rbi = {};
  kmip_init_request_batch_item (&rbi);
  rbi.operation       = KMIP_OP_REGISTER;
  rbi.request_payload = &crp;

  rq.add_batch_item (&rbi);
  rq.encode ();
}

void
RequestFactory::create_register_secret_rq (const name_t &name, const name_t &group, std::string &secret,
                                           int secret_type)
{
  int attr_count;
  group.empty () ? attr_count = 2 : attr_count = 3;

  Attribute a[attr_count];
  for (int i = 0; i < attr_count; i++)
    {
      kmip_init_attribute (&a[i]);
    }

  int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT | KMIP_CRYPTOMASK_EXPORT;
  a[0].type  = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
  a[0].value = &mask;

  Name       ts;
  TextString ts2 = {};
  ts2.value      = const_cast<char *> (name.c_str ());
  ts2.size       = kmip_strnlen_s (ts2.value, 250);
  ts.value       = &ts2;
  ts.type        = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
  a[1].type      = KMIP_ATTR_NAME;
  a[1].value     = &ts;

  if (attr_count == 3)
    {
      TextString gs2 = {};
      gs2.value      = const_cast<char *> (group.c_str ());
      gs2.size       = kmip_strnlen_s (gs2.value, 250);
      a[2].type      = KMIP_ATTR_OBJECT_GROUP;
      a[2].value     = &gs2;
    }

  TemplateAttribute ta = {};
  ta.attributes        = a;
  ta.attribute_count   = attr_count;

  int   id_max_len = 64;
  char *idp        = nullptr;

  RegisterRequestPayload crp = {};
  crp.object_type            = KMIP_OBJTYPE_SECRET_DATA;
  crp.template_attribute     = &ta;

  crp.object.secret_data.secret_data_type = static_cast<secret_data_type> (secret_type);

  KeyBlock kb;
  crp.object.secret_data.key_block = &kb;
  kmip_init_key_block (crp.object.secret_data.key_block);
  crp.object.secret_data.key_block->key_format_type = KMIP_KEYFORMAT_OPAQUE;

  ByteString bs;
  bs.value = reinterpret_cast<uint8_t *> (secret.data ());
  bs.size  = secret.size ();

  KeyValue kv;
  kv.key_material    = &bs;
  kv.attribute_count = 0;
  kv.attributes      = nullptr;

  crp.object.secret_data.key_block->key_value      = &kv;
  crp.object.secret_data.key_block->key_value_type = KMIP_TYPE_BYTE_STRING;

  RequestBatchItem rbi = {};
  kmip_init_request_batch_item (&rbi);
  rbi.operation       = KMIP_OP_REGISTER;
  rbi.request_payload = &crp;

  rq.add_batch_item (&rbi);
  rq.encode ();
}

void
RequestFactory::create_revoke_rq (const id_t &id, int reason, const name_t &message, time_t occurrence_time)
{
  RevokeRequestPayload rrp = {};

  rrp.compromise_occurence_date = occurrence_time;

  RevocationReason revocation_reason = {};
  revocation_reason.reason           = static_cast<revocation_reason_type> (reason);

  TextString msg            = {};
  msg.value                 = const_cast<char *> (message.c_str ());
  msg.size                  = message.size ();
  revocation_reason.message = &msg;

  rrp.revocation_reason = &revocation_reason;

  TextString uuid       = {};
  uuid.value            = const_cast<char *> (id.c_str ());
  uuid.size             = id.size ();
  rrp.unique_identifier = &uuid;

  RequestBatchItem rbi{};
  kmip_init_request_batch_item (&rbi);
  rbi.operation       = KMIP_OP_REVOKE;
  rbi.request_payload = &rrp;

  rq.add_batch_item (&rbi);
  rq.encode ();
}

void
RequestFactory::create_destroy_rq (const id_t &id)
{
  TextString idt = {};
  idt.value      = const_cast<char *> (id.c_str ());
  idt.size       = id.size ();

  DestroyRequestPayload drp = {};
  drp.unique_identifier     = &idt;

  RequestBatchItem rbi = {};
  kmip_init_request_batch_item (&rbi);
  rbi.operation       = KMIP_OP_DESTROY;
  rbi.request_payload = &drp;

  rq.add_batch_item (&rbi);
  rq.encode ();
}

void
RequestFactory::create_get_attribute_rq (const id_t &id, const std::string &attr_name)
{
  TextString uuid = {};
  uuid.value      = const_cast<char *> (id.c_str ());
  uuid.size       = id.size ();

  TextString an = {};
  an.value      = const_cast<char *> (attr_name.c_str ());
  ;
  an.size = attr_name.size ();

  GetAttributeRequestPayload grp = {};
  grp.unique_identifier          = &uuid;
  grp.attribute_name             = &an;

  RequestBatchItem rbi = {};
  kmip_init_request_batch_item (&rbi);
  rbi.operation       = KMIP_OP_GET_ATTRIBUTES;
  rbi.request_payload = &grp;

  rq.add_batch_item (&rbi);
  rq.encode ();
}

void
RequestFactory::create_locate_by_name_rq (const name_t &name, const kmip_entity_type type, const int max_items,
                                          const int offset)
{
  create_locate_rq (false, name, type, max_items, offset);
}

void
RequestFactory::create_locate_by_group_rq (const name_t &group_name, kmip_entity_type type, int max_items,
                                           size_t offset)
{
  create_locate_rq (true, group_name, type, max_items, offset);
}
void
RequestFactory::create_locate_all_rq (kmip_entity_type type, int max_items, int offset)
{
  create_locate_rq (true, "", type, max_items, offset);
}

void
RequestFactory::create_locate_rq (bool is_group, const name_t &name, kmip_entity_type type, int max_items,
                                  size_t offset)
{
  size_t    attrib_count = name.empty () ? 1 : 2;
  Attribute a[attrib_count];
  for (int i = 0; i < attrib_count; i++)
    {
      kmip_init_attribute (&a[i]);
    }

  object_type loctype = from_entity_type (type);
  a[0].type           = KMIP_ATTR_OBJECT_TYPE;
  a[0].value          = &loctype;

  if (attrib_count == 2)
    {
      Name       ts;
      TextString ts2 = {};
      ts2.value      = const_cast<char *> (name.c_str ());
      ts2.size       = kmip_strnlen_s (ts2.value, 250);
      ts.value       = &ts2;
      ts.type        = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
      if (is_group)
        {
          a[1].type = KMIP_ATTR_OBJECT_GROUP;
        }
      else
        {
          a[1].type = KMIP_ATTR_NAME;
        }
      a[1].value = &ts;
    }

  // TODO: this is a piece of bad code! Handle it somehow. Why they need lists at all?
  // copy input array to list
  auto attribute_list = rq.get_ctx ().allocate<LinkedList> ();
  if (attribute_list == nullptr)
    {
      throw std::bad_alloc ();
    }
  for (size_t i = 0; i < attrib_count; i++)
    {
      auto item = rq.get_ctx ().allocate<LinkedListItem> ();
      if (item == nullptr)
        {
          throw std::bad_alloc ();
        }
      item->data = kmip_deep_copy_attribute (rq.get_ctx ().get (), &a[i]);
      if (item->data == nullptr)
        {
          throw std::bad_alloc ();
        }
      kmip_linked_list_enqueue (attribute_list, item);
    }

  LocateRequestPayload lrp = {};
  lrp.maximum_items        = max_items;
  lrp.offset_items         = offset;
  lrp.storage_status_mask  = 0;
  lrp.group_member_option  = group_member_option::group_member_default;
  lrp.attribute_list       = attribute_list;

  RequestBatchItem rbi = {};
  kmip_init_request_batch_item (&rbi);
  rbi.operation       = KMIP_OP_LOCATE;
  rbi.request_payload = &lrp;

  rq.add_batch_item (&rbi);
  rq.encode ();

  // TODO: this is dealoc of bad code from above
  LinkedListItem *item = nullptr;
  while ((item = kmip_linked_list_pop (attribute_list)) != nullptr)
    {
      kmip_free_attribute (rq.get_ctx ().get (), static_cast<Attribute *> (item->data));
      free (item->data);
      kmip_free_buffer (rq.get_ctx ().get (), item, sizeof (LinkedListItem));
    }
  rq.get_ctx ().free (attribute_list);
}

enum object_type
RequestFactory::from_entity_type (enum kmip_entity_type t)
{
  int val = static_cast<int> (t);
  return static_cast<object_type> (val);
}

} // namespace
