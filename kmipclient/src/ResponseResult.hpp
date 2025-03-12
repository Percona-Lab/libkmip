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

#ifndef RESPONSERESULT_HPP
#define RESPONSERESULT_HPP

#include "KmipCtx.hpp"
#include "Key.hpp"
#include "kmip_data_types.hpp"

#include "kmip.h"

namespace kmipclient
{
class ResponseResult
{
public:
  static id_t         get_id (const ResponseBatchItem *rbi);
  static Key          get_key (const ResponseBatchItem *rbi);
  static Secret       get_secret (const ResponseBatchItem *rbi);
  static attributes_t get_attributes (const ResponseBatchItem *rbi);
  static names_t      get_attribute_list (const ResponseBatchItem *rbi);
  static ids_t        get_ids (const ResponseBatchItem *rbi);
};

}

#endif // RESPONSERESULT_HPP
