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

#include "RequestFactory.hpp"

#include "KmipCtx.hpp"
#include "KmipRequest.hpp"
#include "kmip.h"

#include <kmip_locate.h>

namespace kmipclient
{

void
RequestFactory::create_get_rq (KmipCtx &ctx, const id_t &id)
{
  KmipRequest rq (ctx);

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
RequestFactory::create_activate_rq (KmipCtx &ctx, const id_t &id)
{
  KmipRequest rq (ctx);

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
RequestFactory::create_create_aes_rq (KmipCtx &ctx, const name_t &name, const name_t &group)
{
  KmipRequest rq (ctx);
  Attribute   a[5];
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

  TextString gs2 = { nullptr, 0 };
  gs2.value      = const_cast<char *> (group.c_str ());
  gs2.size       = kmip_strnlen_s (gs2.value, 250);
  a[4].type      = KMIP_ATTR_OBJECT_GROUP;
  a[4].value     = &gs2;

  TemplateAttribute ta = {};
  ta.attributes        = a;
  ta.attribute_count   = std::size (a);

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
RequestFactory::create_register_key_rq (KmipCtx &ctx, const name_t &name, const name_t &group, const Key &key)
{
  KmipRequest rq (ctx);
  int         attr_count;

  group.empty () ? attr_count = 4 : attr_count = 5;

  Attribute a[attr_count];
  for (int i = 0; i < attr_count; i++)
    {
      kmip_init_attribute (&a[i]);
    }

  cryptographic_algorithm algorithm = KMIP_CRYPTOALG_AES;
  a[0].type                         = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
  a[0].value                        = &algorithm;
  int32 length                      = key.size () * 8;
  a[1].type                         = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
  a[1].value                        = &length;

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
      TextString gs2 = { nullptr, 0 };
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

  ByteString bs;
  bs.value = const_cast<uint8 *> (key.value ().data ());
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
RequestFactory::create_register_secret_rq (KmipCtx &ctx, const name_t &name, const name_t &group,
                                           const std::string_view &secret, int secret_type)
{
  KmipRequest rq (ctx);

  int attr_count;
  group.empty () ? attr_count = 2 : attr_count = 3;

  Attribute a[attr_count];
  for (int i = 0; i < attr_count; i++)
    {
      kmip_init_attribute (&a[i]);
    }

  int32 mask = KMIP_CRYPTOMASK_DERIVE_KEY | KMIP_CRYPTOMASK_EXPORT;
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

  RegisterRequestPayload crp = {};
  crp.object_type            = KMIP_OBJTYPE_SECRET_DATA;
  crp.template_attribute     = &ta;

  crp.object.secret_data.secret_data_type = static_cast<secret_data_type> (secret_type);

  KeyBlock kb;
  crp.object.secret_data.key_block = &kb;
  kmip_init_key_block (crp.object.secret_data.key_block);
  crp.object.secret_data.key_block->key_format_type = KMIP_KEYFORMAT_OPAQUE;

  ByteString bs;
  bs.value = reinterpret_cast<uint8_t *> (const_cast<char *> (secret.data ()));
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
RequestFactory::create_revoke_rq (KmipCtx &ctx, const id_t &id, int reason, const name_t &message,
                                  time_t occurrence_time)
{
  KmipRequest rq (ctx);

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
RequestFactory::create_destroy_rq (KmipCtx &ctx, const id_t &id)
{
  KmipRequest rq (ctx);

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
RequestFactory::create_get_attributes_rq (KmipCtx &ctx, const id_t &id, const std::vector<std::string> &attr_names)
{
  KmipRequest rq (ctx);

  TextString uuid = {};
  uuid.value      = const_cast<char *> (id.c_str ());
  uuid.size       = id.size ();

  GetAttributeRequestPayload grp = {};
  grp.unique_identifier          = &uuid;

  // create an array of attributes
  std::vector<TextString> a_names;
  if (!attr_names.empty ())
    {
      for (const auto &attr_name : attr_names)
        {
          TextString an = {};
          an.value      = const_cast<char *> (attr_name.c_str ());
          an.size       = attr_name.size ();
          a_names.push_back (an);
        }
      grp.attribute_name = &a_names[0];
    }
  else
    {
      grp.attribute_name = nullptr;
    }

  RequestBatchItem rbi = {};
  kmip_init_request_batch_item (&rbi);
  rbi.operation       = KMIP_OP_GET_ATTRIBUTES;
  rbi.request_payload = &grp;

  rq.add_batch_item (&rbi);
  rq.encode ();
}

void
RequestFactory::create_get_attribute_list_rq (KmipCtx &ctx, const id_t &id)
{
  KmipRequest rq (ctx);

  TextString uuid = {};
  uuid.value      = const_cast<char *> (id.c_str ());
  uuid.size       = id.size ();

  GetAttributeListRequestPayload grp = {};

  RequestBatchItem rbi = {};
  kmip_init_request_batch_item (&rbi);
  rbi.operation       = KMIP_OP_GET_ATTRIBUTE_LIST;
  rbi.request_payload = &grp;

  rq.add_batch_item (&rbi);
  rq.encode ();
}

void
RequestFactory::create_locate_by_name_rq (KmipCtx &ctx, const name_t &name, object_type o_type, const size_t max_items,
                                          const size_t offset)
{
  create_locate_rq (ctx, false, name, o_type, max_items, offset);
}

void
RequestFactory::create_locate_by_group_rq (KmipCtx &ctx, const name_t &group_name, object_type o_type, size_t max_items,
                                           size_t offset)
{
  create_locate_rq (ctx, true, group_name, o_type, max_items, offset);
}
void
RequestFactory::create_locate_all_rq (KmipCtx &ctx, object_type o_type, size_t max_items, size_t offset)
{
  create_locate_rq (ctx, true, "", o_type, max_items, offset);
}

void
RequestFactory::create_locate_rq (KmipCtx &ctx, bool is_group, const name_t &name, object_type o_type, size_t max_items,
                                  size_t offset)
{
  KmipRequest rq (ctx);

  size_t    attrib_count = name.empty () ? 1 : 2;
  Attribute a[attrib_count];
  for (int i = 0; i < attrib_count; i++)
    {
      kmip_init_attribute (&a[i]);
    }

  object_type loctype = o_type;
  a[0].type           = KMIP_ATTR_OBJECT_TYPE;
  a[0].value          = &loctype;

  if (attrib_count == 2)
    {
      Name       a_name;
      TextString ts = {};
      ts.value      = const_cast<char *> (name.c_str ());
      ts.size       = kmip_strnlen_s (ts.value, 250);
      a_name.value  = &ts;
      a_name.type   = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
      if (is_group)
        {
          a[1].type  = KMIP_ATTR_OBJECT_GROUP;
          a[1].value = &ts;
        }
      else
        {
          a[1].type  = KMIP_ATTR_NAME;
          a[1].value = &a_name;
        }
    }

  // TODO: this is a piece of bad code! Handle it later.
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

  // TODO: this is dealock of bad code from above
  LinkedListItem *item = nullptr;
  while ((item = kmip_linked_list_pop (attribute_list)) != nullptr)
    {
      kmip_free_attribute (rq.get_ctx ().get (), static_cast<Attribute *> (item->data));
      free (item->data);
      kmip_free_buffer (rq.get_ctx ().get (), item, sizeof (LinkedListItem));
    }
  rq.get_ctx ().free (attribute_list);
}

} // namespace
