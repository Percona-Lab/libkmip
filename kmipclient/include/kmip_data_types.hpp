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

#ifndef DATA_TYPES_HPP
#define DATA_TYPES_HPP

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "kmip_enums.h"

namespace kmipclient
{
// we use protocol/specification version 1.4 as default
#define KMIP_PROTOCOL_VERSION_DEFAULT KMIP_1_4

// known attributes so far
static const std::string KMIP_ATTR_NAME_NAME              = "Name";
static const std::string KMIP_ATTR_NAME_GROUP             = "Object Group";
static const std::string KMIP_ATTR_NAME_STATE             = "State";
static const std::string KMIP_ATTR_NAME_UNIQUE_IDENTIFIER = "UniqueID";

using key_t        = std::vector<unsigned char>;
using bin_data_t   = std::vector<unsigned char>;
using id_t         = std::string;
using ids_t        = std::vector<std::string>;
using name_t       = std::string;
using names_t      = std::vector<std::string>;
using secret_t     = std::string;
using attributes_t = std::unordered_map<std::string, std::string>;

inline std::ostream &
operator<< (std::ostream &out, const state value)
{
  const char *str;
  switch (value)
    {
#define PROCESS_VAL(p)                                                                                                 \
  case (p):                                                                                                            \
    str = #p;                                                                                                          \
    break;
      PROCESS_VAL (KMIP_STATE_PRE_ACTIVE);
      PROCESS_VAL (KMIP_STATE_ACTIVE);
      PROCESS_VAL (KMIP_STATE_DEACTIVATED);
      PROCESS_VAL (KMIP_STATE_COMPROMISED);
      PROCESS_VAL (KMIP_STATE_DESTROYED);
      PROCESS_VAL (KMIP_STATE_DESTROYED_COMPROMISED);
#undef PROCESS_VAL
    default:
      str = "UNKNOWN_KMIP_STATE";
      break; // Handle unknown values
    }
  return out << str;
}

class Secret
{
public:
  secret_t              value;
  enum state            state       = KMIP_STATE_PRE_ACTIVE;
  enum secret_data_type secret_type = PASSWORD;
};

}
#endif // DATA_TYPES_HPP
