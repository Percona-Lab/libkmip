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

#ifndef STRINGUTILS_HPP
#define STRINGUTILS_HPP
#include "include/kmip_data_types.hpp"

#include <kmip.h>

namespace kmipclient
{

class StringUtils
{
public:
  static key_t                      fromHex (const std::string &hex);
  static std::string                fromKmipText (const TextString *ts);
  static std::vector<unsigned char> fromBase64 (const std::string &base64);
};

}

#endif // STRINGUTILS_HPP
