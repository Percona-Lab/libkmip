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

#include "kmipclient/SymmetricKey.hpp"

#include "StringUtils.hpp"
#include "kmipcore/kmip_errors.hpp"

#include <openssl/err.h>
#include <openssl/rand.h>

namespace kmipclient {

  namespace {

    SymmetricKey make_aes_key(const std::vector<unsigned char> &bytes) {
      const size_t size = bytes.size();
      if (size != 16 && size != 24 && size != 32) {
        throw kmipcore::KmipException{
            -1,
            std::string("Invalid AES key length: ") + std::to_string(size * 8) +
                " bits. Should be 128, 192 or 256 bits"
        };
      }

      kmipcore::Attributes attrs;
      attrs.set_algorithm(cryptographic_algorithm::KMIP_CRYPTOALG_AES)
          .set_crypto_length(static_cast<int32_t>(size * 8))
          // CryptographicUsageMask is required by strict servers (e.g. Vault).
          // ENCRYPT|DECRYPT is the correct default for a symmetric AES key.
          .set_usage_mask(
              static_cast<cryptographic_usage_mask>(
                  kmipcore::KMIP_CRYPTOMASK_ENCRYPT |
                  kmipcore::KMIP_CRYPTOMASK_DECRYPT
              )
          );

      return SymmetricKey(bytes, std::move(attrs));
    }

  }  // anonymous namespace


  std::unique_ptr<Key> SymmetricKey::clone() const {
    return std::make_unique<SymmetricKey>(*this);
  }

  SymmetricKey SymmetricKey::aes_from_hex(const std::string &hex) {
    return make_aes_key(StringUtils::fromHex(hex));
  }

  SymmetricKey SymmetricKey::aes_from_base64(const std::string &base64) {
    return make_aes_key(StringUtils::fromBase64(base64));
  }

  SymmetricKey
      SymmetricKey::aes_from_value(const std::vector<unsigned char> &val) {
    return make_aes_key(val);
  }

  SymmetricKey SymmetricKey::generate_aes(aes_key_size key_size) {
    const size_t size_bits = static_cast<size_t>(key_size);

    const size_t size_bytes = size_bits / 8;
    std::vector<unsigned char> buf(size_bytes);
    if (1 != RAND_bytes(buf.data(), static_cast<int>(size_bytes))) {
      const unsigned long err = ERR_get_error();
      char err_buf[256];
      ERR_error_string_n(err, err_buf, sizeof(err_buf));
      throw kmipcore::KmipException(
          std::string("OpenSSL RAND_bytes failed: ") + err_buf
      );
    }

    return make_aes_key(buf);
  }

}  // namespace kmipclient
