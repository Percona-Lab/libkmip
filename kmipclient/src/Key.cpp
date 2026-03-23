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

#include "kmipclient/Key.hpp"

#include "kmipcore/kmip_errors.hpp"

namespace kmipclient {

  Key::Key(const std::vector<unsigned char> &value, kmipcore::Attributes attrs)
    : key_value_(value), attributes_(std::move(attrs)) {}

  kmipcore::Key Key::to_core_key() const {
    return kmipcore::Key(key_value_, type(), attributes_);
  }

  std::unique_ptr<Key> Key::from_core_key(const kmipcore::Key &core_key) {
    switch (core_key.type()) {
      case KeyType::SYMMETRIC_KEY:
        return std::make_unique<SymmetricKey>(
            core_key.value(), core_key.attributes()
        );
      case KeyType::PUBLIC_KEY:
        return std::make_unique<PublicKey>(
            core_key.value(), core_key.attributes()
        );
      case KeyType::PRIVATE_KEY:
        return std::make_unique<PrivateKey>(
            core_key.value(), core_key.attributes()
        );
      case KeyType::CERTIFICATE:
        return std::make_unique<X509Certificate>(
            core_key.value(), core_key.attributes()
        );
      case KeyType::UNSET:
      default:
        throw kmipcore::KmipException(
            "Unsupported key type in core->client conversion"
        );
    }
  }

}  // namespace kmipclient
