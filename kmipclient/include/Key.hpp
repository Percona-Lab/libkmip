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

#ifndef KEY_HPP
#define KEY_HPP
#include <utility>

#include "kmip_data_types.hpp"

namespace kmipclient
{
/** Key types corresponding to KMIP Object Types */
enum KeyType
{
  UNSET,
  SYMMETRIC_KEY,
  PUBLIC_KEY,
  PRIVATE_KEY,
  CERTIFICATE
};

class KeyFactory;

/**
 * Genric crypto key representation, as KMIP spec sees it.
 */
class Key
{
  friend class KeyFactory;

public:
  explicit Key (key_t value, KeyType k_type, cryptographic_algorithm algo, cryptographic_usage_mask usage_mask,
                attributes_t attributes)
      : key_value (std::move (value)), key_type (k_type), key_attributes (std::move (attributes)),
        crypto_algorithm (algo), crypto_usage_mask (usage_mask) {};

  Key () = default;

  [[nodiscard]] const key_t &
  value () const noexcept
  {
    return key_value;
  };

  [[nodiscard]] const attributes_t &
  attributes () const noexcept
  {
    return key_attributes;
  };

  [[nodiscard]] const std::string &
  attribute_value (const std::string &name) const noexcept
  {
    return key_attributes.at (name);
  };

  void
  set_attribute (const std::string &name, const std::string &value) noexcept
  {
    key_attributes[name] = value;
  };

  [[nodiscard]] cryptographic_usage_mask
  usage_mask () const noexcept
  {
    return crypto_usage_mask;
  }

  [[nodiscard]] cryptographic_algorithm
  algorithm () const noexcept
  {
    return crypto_algorithm;
  };

  [[nodiscard]] size_t
  size () const noexcept
  {
    return key_value.size ();
  }

  /**
   * Creates an instance from a hexadecimal string
   * @param hex Hexadecimal string of key value
   * @return AES key initialized
   */
  static Key aes_from_hex (const std::string &hex);
  /**
   * Creates an instance from a base64 encoded string
   * @param base64 Base64 encoded binary
   * @return AES key initialized
   */
  static Key aes_from_base64 (const std::string &base64);

  /**
   * Creates an instance from a bytes vector
   * @param val binary key value
   * @return AES key initialized
   */
  static Key aes_from_value (const std::vector<unsigned char> &val);
  /**
   * Generate an AES key of given size (in bits). Valid sizes: 128, 192, 256.
   * Uses OpenSSL RAND to generate cryptographically secure random bytes.
   */
  static Key generate_aes (size_t size_bits);
  /**
   *  Reads a PEM-formatted string, decides what type of key it has
   *  (X.509 certificate, public key, private key) and creates the
   *  Key instance from it.
   * @param pem PEM-formatted string
   * @return Key of a corresponding type
   */
  static Key from_PEM (const std::string &pem);

private:
  key_t                    key_value;
  KeyType                  key_type = UNSET;
  attributes_t             key_attributes;
  cryptographic_algorithm  crypto_algorithm  = cryptographic_algorithm::KMIP_CRYPTOALG_UNSET;
  cryptographic_usage_mask crypto_usage_mask = cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET;
};
}

#endif // KEY_HPP
