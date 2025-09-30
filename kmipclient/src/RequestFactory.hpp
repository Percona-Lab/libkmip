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

#ifndef REQUESTFACTORY_HPP
#define REQUESTFACTORY_HPP

#include "KmipCtx.hpp"
#include "include/Key.hpp"
#include "include/kmip_data_types.hpp"

namespace kmipclient
{

/**
 * Creates requests and encodes them into KmipCtx
 */

class RequestFactory
{
public:
  static void create_get_rq (KmipCtx &ctx, const id_t &id);
  static void create_activate_rq (KmipCtx &ctx, const id_t &id);
  static void create_create_aes_rq (KmipCtx &ctx, const name_t &name, const name_t &group);
  static void create_register_key_rq (KmipCtx &ctx, const name_t &name, const name_t &group, const Key &k);
  static void create_register_secret_rq (KmipCtx &ctx, const name_t &name, const name_t &group, std::string &secret,
                                         int secret_data_type);
  static void create_revoke_rq (KmipCtx &ctx, const id_t &id, int reason, const name_t &message,
                                time_t occurrence_time);
  static void create_destroy_rq (KmipCtx &ctx, const id_t &id);
  static void create_get_attributes_rq (KmipCtx &ctx, const id_t &id, const std::vector<std::string> &attr_names);
  static void create_get_attribute_list_rq (KmipCtx &ctx, const id_t &id);
  static void create_locate_by_name_rq (KmipCtx &ctx, const name_t &name, enum object_type o_type, int max_items,
                                        int offset);
  static void create_locate_by_group_rq (KmipCtx &ctx, const name_t &group_name, enum object_type o_type, int max_items,
                                         size_t offset);
  static void create_locate_all_rq (KmipCtx &ctxm, enum object_type o_type, int max_items, int offset);

private:
  static void create_locate_rq (KmipCtx &ctx, bool is_group, const name_t &name, enum object_type o_type, int max_items,
                                size_t offset);
};

} // namespace

#endif // REQUESTFACTORY_HPP
