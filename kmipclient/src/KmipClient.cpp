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

#include "KmipClient.hpp"

#include "IOUtils.hpp"
#include "KmipCtx.hpp"
#include "RequestFactory.hpp"
#include "ResponseFactory.hpp"

namespace kmipclient
{

KmipClient::KmipClient (NetClient &net_client)
    : net_client (net_client), io (std::make_unique<IOUtils> (net_client)) {};

KmipClient::KmipClient (NetClient &net_client, const std::shared_ptr<Logger> &log)
    : net_client (net_client), logger (log), io (std::make_unique<IOUtils> (net_client))
{
}

KmipClient::~KmipClient () { net_client.close (); };

id_t
KmipClient::op_register_key (const name_t &name, const name_t &group, const Key &k) const
{
  KmipCtx         ctx;
  ResponseFactory rf (ctx);
  RequestFactory::create_register_key_rq (ctx, name, group, k);
  io->do_exchange (ctx);
  return rf.get_id (0);
}

id_t
KmipClient::op_register_secret (const name_t &name, const name_t &group, const std::string_view secret,
                                enum secret_data_type secret_type) const
{
  KmipCtx         ctx;
  ResponseFactory rf (ctx);
  RequestFactory::create_register_secret_rq (ctx, name, group, secret, secret_type);
  io->do_exchange (ctx);
  return rf.get_id (0);
}

id_t
KmipClient::op_create_aes_key (const name_t &name, const name_t &group) const
{
  KmipCtx         ctx;
  ResponseFactory rf (ctx);
  RequestFactory::create_create_aes_rq (ctx, name, group);
  io->do_exchange (ctx);
  return rf.get_id (0);
}

Key
KmipClient::op_get_key (const id_t &id) const
{
  KmipCtx         ctx;
  ResponseFactory rf (ctx);
  RequestFactory::create_get_rq (ctx, id);
  io->do_exchange (ctx);

  auto         key   = rf.get_key (0);
  // TODO: this is temporary solution, we'll use multiple batch items in the future
  attributes_t attrs = op_get_attributes (id, { KMIP_ATTR_NAME_STATE });
  key.set_attribute (KMIP_ATTR_NAME_STATE, attrs[KMIP_ATTR_NAME_STATE]);
  return key;
}

Secret
KmipClient::op_get_secret (const id_t &id) const
{
  KmipCtx         ctx;
  ResponseFactory rf (ctx);
  RequestFactory::create_get_rq (ctx, id);
  io->do_exchange (ctx);
  return rf.get_secret (0);
}

id_t
KmipClient::op_activate (const id_t &id) const
{
  KmipCtx         ctx;
  ResponseFactory rf (ctx);
  RequestFactory::create_activate_rq (ctx, id);
  io->do_exchange (ctx);
  return rf.get_id (0);
}
names_t
KmipClient::op_get_attribute_list (const id_t &id) const
{
  KmipCtx         ctx;
  ResponseFactory rf (ctx);
  RequestFactory::create_get_attribute_list_rq (ctx, id);
  io->do_exchange (ctx);
  return rf.get_attribute_names (0);
}

attributes_t
KmipClient::op_get_attributes (const id_t &id, const std::vector<name_t> &attr_names) const
{
  KmipCtx         ctx;
  ResponseFactory rf (ctx);
  RequestFactory::create_get_attributes_rq (ctx, id, attr_names);
  io->do_exchange (ctx);
  return rf.get_attributes (0);
}

ids_t
KmipClient::op_locate_by_name (const name_t &name, enum object_type o_type) const
{
  KmipCtx         ctx;
  ResponseFactory rf (ctx);
  // actually, with Vault server there should be only one item with the name
  RequestFactory::create_locate_by_name_rq (ctx, name, o_type, MAX_ITEMS_IN_BATCH, 0);
  io->do_exchange (ctx);
  return rf.get_ids (0);
}

ids_t
KmipClient::op_locate_by_group (const name_t &group, enum object_type o_type, size_t max_ids) const
{

  KmipCtx         ctx;
  ResponseFactory rf (ctx);
  ids_t           result;
  size_t          received = 0;
  size_t          offset   = 0;
  do
    {
      RequestFactory::create_locate_by_group_rq (ctx, group, o_type, MAX_ITEMS_IN_BATCH, offset);
      io->do_exchange (ctx);
      auto exp = rf.get_ids (0);

      if (ids_t got = exp; !got.empty ())
        {
          received = got.size ();
          offset += got.size ();
          result.insert (result.end (), got.begin (), got.end ());
        }
      else
        {
          break;
        }
    }
  while (received == MAX_ITEMS_IN_BATCH && result.size () < max_ids);
  return result;
}

ids_t
KmipClient::op_all (enum object_type o_type, size_t max_ids) const
{

  KmipCtx         ctx;
  ResponseFactory rf (ctx);
  ids_t           result;
  size_t          received = 0;
  size_t          offset   = 0;
  do
    {
      RequestFactory::create_locate_all_rq (ctx, o_type, MAX_ITEMS_IN_BATCH, offset);
      io->do_exchange (ctx);
      auto exp = rf.get_ids (0);
      if (ids_t got = exp; !got.empty ())
        {
          received = got.size ();
          offset += got.size ();
          result.insert (result.end (), got.begin (), got.end ());
        }
      else
        {
          break;
        }
    }
  while (received == MAX_ITEMS_IN_BATCH && result.size () < max_ids);
  return result;
}

id_t
KmipClient::op_revoke (const id_t &id, enum revocation_reason_type reason, const name_t &message,
                       time_t occurrence_time) const
{
  KmipCtx         ctx;
  ResponseFactory rf (ctx);

  RequestFactory::create_revoke_rq (ctx, id, reason, message, occurrence_time);
  io->do_exchange (ctx);
  return rf.get_id (0);
}

id_t
KmipClient::op_destroy (const id_t &id) const
{
  KmipCtx         ctx;
  ResponseFactory rf (ctx);
  RequestFactory::create_destroy_rq (ctx, id);
  io->do_exchange (ctx);
  return rf.get_id (0);
}

}
