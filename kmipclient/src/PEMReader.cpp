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

#include "kmipclient/PEMReader.hpp"

#include "kmipclient/PrivateKey.hpp"
#include "kmipclient/PublicKey.hpp"
#include "kmipclient/SymmetricKey.hpp"
#include "kmipclient/X509Certificate.hpp"
#include "kmipclient/types.hpp"
#include "kmipcore/kmip_errors.hpp"

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <optional>
#include <sstream>

namespace kmipclient {

  namespace {

    std::optional<X509Certificate> try_parse_x509_certificate(BIO *bio) {
      X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
      if (!cert) {
        return std::nullopt;
      }

      unsigned char *der = nullptr;
      const int der_len = i2d_X509(cert, &der);
      X509_free(cert);
      if (der_len <= 0) {
        if (der) {
          OPENSSL_free(der);
        }
        return std::nullopt;
      }

      std::vector<unsigned char> cert_bytes(der, der + der_len);
      OPENSSL_free(der);

      kmipcore::Attributes attrs;
      attrs.set(KMIP_ATTR_NAME_NAME, "certificate");
      return X509Certificate(cert_bytes, std::move(attrs));
    }

    std::optional<PrivateKey> try_parse_private_key(BIO *bio) {
      EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
      if (!pkey) {
        return std::nullopt;
      }

      unsigned char *der = nullptr;
      const int der_len = i2d_PrivateKey(pkey, &der);
      EVP_PKEY_free(pkey);

      if (der_len <= 0) {
        if (der) {
          OPENSSL_free(der);
        }
        return std::nullopt;
      }

      std::vector<unsigned char> key_bytes(der, der + der_len);
      OPENSSL_free(der);

      kmipcore::Attributes attrs;
      attrs.set(KMIP_ATTR_NAME_NAME, "private_key");
      return PrivateKey(key_bytes, std::move(attrs));
    }

    std::optional<PublicKey> try_parse_public_key(BIO *bio) {
      EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
      if (!pkey) {
        return std::nullopt;
      }

      unsigned char *der = nullptr;
      const int der_len = i2d_PUBKEY(pkey, &der);
      EVP_PKEY_free(pkey);

      if (der_len <= 0) {
        if (der) {
          OPENSSL_free(der);
        }
        return std::nullopt;
      }

      std::vector<unsigned char> key_bytes(der, der + der_len);
      OPENSSL_free(der);

      kmipcore::Attributes attrs;
      attrs.set(KMIP_ATTR_NAME_NAME, "public_key");
      return PublicKey(key_bytes, std::move(attrs));
    }

    std::optional<SymmetricKey>
        try_parse_aes_from_pem_text(const std::string &pem) {
      std::istringstream iss(pem);
      std::string line;
      bool in_pem = false;
      std::string b64;
      while (std::getline(iss, line)) {
        if (!in_pem) {
          if (line.rfind("-----BEGIN", 0) == 0) {
            in_pem = true;
          }
          continue;
        }
        if (line.rfind("-----END", 0) == 0) {
          break;
        }
        if (!line.empty()) {
          b64 += line;
        }
      }

      if (b64.empty()) {
        return std::nullopt;
      }

      try {
        return SymmetricKey::aes_from_base64(b64);
      } catch (...) {
        return std::nullopt;
      }
    }

  }  // namespace

  std::unique_ptr<Key> PEMReader::from_PEM(const std::string &pem) {
    BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
      throw kmipcore::KmipException("Failed to create BIO for PEM data");
    }

    if (auto x509_cert = try_parse_x509_certificate(bio);
        x509_cert.has_value()) {
      BIO_free(bio);
      return std::make_unique<X509Certificate>(*x509_cert);
    }

    (void) BIO_reset(bio);
    if (auto priv_key = try_parse_private_key(bio); priv_key.has_value()) {
      BIO_free(bio);
      return std::make_unique<PrivateKey>(*priv_key);
    }

    (void) BIO_reset(bio);
    if (auto pub_key = try_parse_public_key(bio); pub_key.has_value()) {
      BIO_free(bio);
      return std::make_unique<PublicKey>(*pub_key);
    }

    BIO_free(bio);

    if (auto aes_key = try_parse_aes_from_pem_text(pem); aes_key.has_value()) {
      return std::make_unique<SymmetricKey>(*aes_key);
    }

    throw kmipcore::KmipException(
        kmipcore::KMIP_NOT_IMPLEMENTED,
        "Unsupported PEM format or not implemented"
    );
  }

}  // namespace kmipclient
