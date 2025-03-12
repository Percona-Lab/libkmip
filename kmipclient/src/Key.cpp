//
// Created by al on 01.04.25.
//

#include "../include/Key.hpp"
#include "../include/kmip_data_types.hpp"
#include "StringUtils.hpp"
#include "kmip.h"

#include <format>

namespace kmipclient
{

ve::expected<Key, Error>
Key::aes_from_hex (std::string hex)
{
  auto hex_parsed = StringUtils::fromHex (hex);
  if (hex_parsed.has_error ())
    return hex_parsed.error ();
  if (size_t size = hex_parsed.value ().size (); size == 128 || size == 256 || size == 192)
    {
      return Error{ -1, std::format ("Invalid RSA key length: {}. Should be 128, 192 or 256.", size) };
    }
  return Key (hex_parsed.value (), KeyType::KEY_TYPE_SYMMETRIC_KEY, KeyAlgorithm::KEY_ALGORITHM_AES, {});
}

ve::expected<Key, Error>
Key::aes_from_base64 (std::string hex)
{
  return Error (KMIP_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
}

ve::expected<Key, Error>
Key::from_PEM (std::string pem)
{
  return Error (KMIP_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
}
}