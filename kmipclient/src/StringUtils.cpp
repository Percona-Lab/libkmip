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

#include <array>
#include <string>
#include <vector>

#include "StringUtils.hpp"

#include "../include/kmip_exceptions.hpp"
namespace kmipclient
{

unsigned char
char2int (const char input)
{
  if (input >= '0' && input <= '9')
    return input - '0';
  if (input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if (input >= 'a' && input <= 'f')
    return input - 'a' + 10;
  throw std::invalid_argument ("Invalid input string");
}

key_t
StringUtils::fromHex (const std::string &hex)
{
  if (hex.empty () || hex.size () % 2 != 0)
    {
      throw ErrorException{ "Invalid hex string length." };
    }
  key_t bytes;
  try
    {
      for (unsigned int i = 0; i < hex.length (); i += 2)
        {
          std::string byteString = hex.substr (i, 2);
          auto        byte       = char2int (byteString.c_str ()[0]) * 16 + char2int (byteString.c_str ()[1]);
          bytes.push_back (byte);
        }
    }
  catch ([[maybe_unused]] const std::invalid_argument &e)
    {
      throw ErrorException{ "Invalid hex string length." };
    }
  return bytes;
}

std::vector<unsigned char>
StringUtils::fromBase64 (const std::string &base64)
{
  static const std::array<int, 256> lookup = [] () {
    std::array<int, 256> l{};
    l.fill (-1);
    for (int i = 0; i < 64; ++i)
      l["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
    return l;
  }();

  std::vector<unsigned char> out;
  out.reserve ((base64.size () / 4) * 3);

  int val = 0, val_b = -8;
  for (unsigned char c : base64)
    {
      if (lookup[c] == -1)
        {
          if (c == '=')
            break;  // Padding reached
          continue; // Skip whitespace or invalid chars
        }
      val = (val << 6) + lookup[c];
      val_b += 6;
      if (val_b >= 0)
        {
          out.push_back (static_cast<unsigned char> ((val >> val_b) & 0xFF));
          val_b -= 8;
        }
    }
  return out;
}

std::string
StringUtils::fromKmipText (const TextString *ts)
{
  if (ts == nullptr || ts->size == 0)
    {
      return "";
    }
  return std::string{ ts->value, ts->size };
}

}