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
#include "../include/kmip_exceptions.hpp"
#include "StringUtils.hpp"
#include "kmip.h"
#include "kmip_data_types.hpp"

#include <format>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <optional>
#include <sstream>

namespace kmipclient
{

namespace
{
// Try to parse BIO as X509 certificate and return Key if successful
std::optional<Key>
try_parse_certificate (BIO *bio)
{
  X509 *cert = PEM_read_bio_X509 (bio, nullptr, nullptr, nullptr);
  if (!cert)
    return std::nullopt;

  EVP_PKEY *pkey = X509_get_pubkey (cert);
  if (!pkey)
    {
      X509_free (cert);
      return std::nullopt;
    }

  unsigned char *der = nullptr;
  int der_len = i2d_PUBKEY (pkey, &der);
  EVP_PKEY_free (pkey);
  X509_free (cert);

  if (der_len <= 0)
    {
      if (der)
        OPENSSL_free (der);
      return std::nullopt;
    }

  std::vector<unsigned char> key_bytes (der, der + der_len);
  OPENSSL_free (der);

  attributes_t attrs;
  attrs[KMIP_ATTR_NAME_NAME] = "certificate_public_key";
  return Key (key_bytes, KeyType::PUBLIC_KEY, cryptographic_algorithm::KMIP_CRYPTOALG_UNSET,
              cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET, attrs);
}

// Try to parse BIO as private key
std::optional<Key>
try_parse_private_key (BIO *bio)
{
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey (bio, nullptr, nullptr, nullptr);
  if (!pkey)
    return std::nullopt;

  unsigned char *der = nullptr;
  int der_len = i2d_PrivateKey (pkey, &der);
  EVP_PKEY_free (pkey);

  if (der_len <= 0)
    {
      if (der)
        OPENSSL_free (der);
      return std::nullopt;
    }

  std::vector<unsigned char> key_bytes (der, der + der_len);
  OPENSSL_free (der);

  attributes_t attrs;
  attrs[KMIP_ATTR_NAME_NAME] = "private_key";
  return Key (key_bytes, KeyType::PRIVATE_KEY, cryptographic_algorithm::KMIP_CRYPTOALG_UNSET,
              cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET, attrs);
}

// Try to parse BIO as public key
std::optional<Key>
try_parse_public_key (BIO *bio)
{
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY (bio, nullptr, nullptr, nullptr);
  if (!pkey)
    return std::nullopt;

  unsigned char *der = nullptr;
  int der_len = i2d_PUBKEY (pkey, &der);
  EVP_PKEY_free (pkey);

  if (der_len <= 0)
    {
      if (der)
        OPENSSL_free (der);
      return std::nullopt;
    }

  std::vector<unsigned char> key_bytes (der, der + der_len);
  OPENSSL_free (der);

  attributes_t attrs;
  attrs[KMIP_ATTR_NAME_NAME] = "public_key";
  return Key (key_bytes, KeyType::PUBLIC_KEY, cryptographic_algorithm::KMIP_CRYPTOALG_UNSET,
              cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET, attrs);
}

// Try to detect an AES/raw key encoded in PEM-like text by extracting base64 between headers
std::optional<Key>
try_parse_aes_from_pem_text (const std::string &pem)
{
  // Find the first PEM header and footer lines, extract base64 content between them
  std::istringstream iss (pem);
  std::string line;
  bool in_pem = false;
  std::string b64;
  while (std::getline (iss, line))
    {
      if (!in_pem)
        {
          if (line.rfind ("-----BEGIN", 0) == 0)
            {
              in_pem = true;
            }
        }
      else
        {
          if (line.rfind ("-----END", 0) == 0)
            break;
          // skip header/footer and empty lines
          if (line.empty ())
            continue;
          b64 += line;
        }
    }

  if (b64.empty ())
    return std::nullopt;

  try
    {
      auto decoded = StringUtils::fromBase64 (b64);
      size_t size = decoded.size ();
      if (size == 16 || size == 24 || size == 32)
        {
          return Key (decoded, KeyType::SYMMETRIC_KEY, cryptographic_algorithm::KMIP_CRYPTOALG_AES,
                      cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET, {});
        }
    }
  catch (...) // any parsing errors
    {
      return std::nullopt;
    }

  return std::nullopt;
}
} // anonymous namespace


Key
Key::aes_from_hex (const std::string &hex)
{
  auto hex_parsed = StringUtils::fromHex (hex);
  size_t size = hex_parsed.size ();
  // Expect AES key sizes in bytes: 16 (128 bits), 24 (192 bits), 32 (256 bits)
  if (size != 16 && size != 24 && size != 32)
    {
      throw ErrorException{ -1, std::string ("Invalid AES key length: ") + std::to_string (size * 8) +
                           " bits. Should be 128, 192 or 256 bits" };
    }
  return Key (hex_parsed, KeyType::SYMMETRIC_KEY, cryptographic_algorithm::KMIP_CRYPTOALG_AES,
              cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET, {});
}

Key
Key::aes_from_base64 (const std::string &base64)
{
  auto parsed = StringUtils::fromBase64 (base64);
  size_t size = parsed.size ();
  if (size != 16 && size != 24 && size != 32)
    {
      throw ErrorException{ -1, std::string ("Invalid AES key length: ") + std::to_string (size * 8) +
                           " bits. Should be 128, 192 or 256 bits" };
    }
  return Key (parsed, KeyType::SYMMETRIC_KEY, cryptographic_algorithm::KMIP_CRYPTOALG_AES,
              cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET, {});
}

Key
Key::aes_from_value (const std::vector<unsigned char> &val)
{
  size_t size = val.size ();
  if (size != 16 && size != 24 && size != 32)
    {
      throw ErrorException{ -1, std::string ("Invalid AES key length: ") + std::to_string (size * 8) +
                           " bits. Should be 128, 192 or 256 bits" };
    }
  return Key (val, KeyType::SYMMETRIC_KEY, cryptographic_algorithm::KMIP_CRYPTOALG_AES,
              cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET, {});
}

Key
Key::from_PEM (const std::string &pem)
{
  // 1) Try as certificate
  BIO *bio = BIO_new_mem_buf (pem.data (), static_cast<int> (pem.size ()));
  if (!bio)
    throw ErrorException ("Failed to create BIO for PEM data");

  if (auto cert_key = try_parse_certificate (bio); cert_key.has_value ())
    {
      BIO_free (bio);
      return cert_key.value ();
    }

  (void)BIO_reset (bio);
  if (auto priv_key = try_parse_private_key (bio); priv_key.has_value ())
    {
      BIO_free (bio);
      return priv_key.value ();
    }

  (void)BIO_reset (bio);
  if (auto pub_key = try_parse_public_key (bio); pub_key.has_value ())
    {
      BIO_free (bio);
      return pub_key.value ();
    }

  BIO_free (bio);

  // 2) Try to detect an AES/raw key encoded in PEM text (base64 between headers)
  if (auto aes_key = try_parse_aes_from_pem_text (pem); aes_key.has_value ())
    return aes_key.value ();

  throw ErrorException (KMIP_NOT_IMPLEMENTED, "Unsupported PEM format or not implemented");
}

Key
Key::generate_aes (size_t size_bits)
{
  if (size_bits != 128 && size_bits != 192 && size_bits != 256)
    {
      throw ErrorException ("Unsupported AES key size. Use 128, 192 or 256 bits");
    }

  size_t size_bytes = size_bits / 8;
  std::vector<unsigned char> buf (size_bytes);
  if (1 != RAND_bytes (buf.data (), static_cast<int> (size_bytes)))
    {
      unsigned long err = ERR_get_error ();
      char err_buf[256];
      ERR_error_string_n (err, err_buf, sizeof (err_buf));
      throw ErrorException (std::string ("OpenSSL RAND_bytes failed: ") + err_buf);
    }

  return Key (buf, KeyType::SYMMETRIC_KEY, cryptographic_algorithm::KMIP_CRYPTOALG_AES,
              cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET, {});
}
}