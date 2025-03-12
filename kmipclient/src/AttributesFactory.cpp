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
#include <sstream>

#include "../include/kmip_exceptions.hpp"
#include "AttributesFactory.hpp"
#include "StringUtils.hpp"

namespace kmipclient
{

attributes_t
kmipclient::AttributesFactory::parse (Attribute *attributes, size_t attribute_count)
{
  attributes_t res;
  for (Attribute *attribute = attributes; attribute_count-- > 0; attribute++)
    {
      switch (attribute->type)
        {
        case KMIP_ATTR_UNIQUE_IDENTIFIER:
          res[KMIP_ATTR_NAME_NAME] = "Not yet parsed";
          break;
        case KMIP_ATTR_NAME:
          {
            const auto *ns           = static_cast<Name *> (attribute->value);
            const auto *ts           = static_cast<TextString *> (ns->value);
            auto        val          = StringUtils::fromKmipText (ts);
            res[KMIP_ATTR_NAME_NAME] = val;
          }
          break;
        case KMIP_ATTR_STATE:
          {
            const auto       *a = static_cast<enum state *> (attribute->value);
            std::stringstream ss;
            ss << *a;
            res[KMIP_ATTR_NAME_STATE] = ss.str ();
          }
          break;
        case KMIP_ATTR_OBJECT_GROUP:
          {
            const auto *ts            = static_cast<TextString *> (attribute->value);
            auto        val           = StringUtils::fromKmipText (ts);
            res[KMIP_ATTR_NAME_GROUP] = val;
          }
          break;
        default:
          {
            throw ErrorException ("Unknown attribute type, not converted");
          }
        }
    }
  return res;
}
}