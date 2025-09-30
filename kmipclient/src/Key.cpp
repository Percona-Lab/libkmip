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

#include "Key.hpp"
#include "StringUtils.hpp"
#include "kmip.h"
#include "kmip_data_types.hpp"
#include "kmip_exceptions.hpp"

#include <format>

namespace kmipclient
{

Key
Key::aes_from_hex (const std::string &hex)
{
  auto hex_parsed = StringUtils::fromHex (hex);
  if (size_t size = hex_parsed.size (); size == 128 || size == 256 || size == 192 || size == 512)
    {
      throw ErrorException{ -1, std::format ("Invalid RSA key length: {}. Should be 128, 192 256 or 512 (non-standard)",
                                             size) };
    }
  return Key (hex_parsed, KeyType::SYMMETRIC_KEY, cryptographic_algorithm::KMIP_CRYPTOALG_AES,
              cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET, {});
}

Key
Key::aes_from_base64 (const std::string &base64)
{
  auto parsed = StringUtils::fromBase64 (base64);
  if (size_t size = parsed.size (); size == 128 || size == 256 || size == 192 || size == 512)
    {
      throw ErrorException{ -1, std::format ("Invalid RSA key length: {}. Should be 128, 192 256 or 512 (non-standard)",
                                             size) };
    }
  return Key (parsed, KeyType::SYMMETRIC_KEY, cryptographic_algorithm::KMIP_CRYPTOALG_AES,
              cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET, {});
}

Key
Key::aes_from_value (const std::vector<unsigned char> &val)
{
  if (size_t size = val.size (); size == 128 || size == 256 || size == 192 || size == 512)
    {
      throw ErrorException{ -1, std::format ("Invalid RSA key length: {}. Should be 128, 192 256 or 512 (non-standard)",
                                             size) };
    }
  return Key (val, KeyType::SYMMETRIC_KEY, cryptographic_algorithm::KMIP_CRYPTOALG_AES,
              cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET, {});
}

Key
Key::from_PEM (std::string pem)
{
  throw ErrorException (KMIP_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
}
}