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
#include "kmipclient/KmipClient.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"
#include "kmipclient/kmipclient_version.hpp"
#include "kmipcore/kmip_errors.hpp"

#include <iomanip>
#include <iostream>

using namespace kmipclient;

namespace {

  void print_hex(const std::vector<unsigned char> &bytes) {
    for (const auto b : bytes) {
      std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;
  }

}  // namespace

int main(int argc, char **argv) {
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << std::endl;
  std::cout << "KMIP library version: " << KMIPCORE_VERSION_STR << std::endl;

  if (argc < 7) {
    std::cerr << "Usage:example_register_key <host> <port> <client_cert> "
                 "<client_key> <server_cert> <key_name>"
              << std::endl;
    return -1;
  }
  NetClientOpenSSL net_client(argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  KmipClient client(net_client);

  try {
    auto generated_key = SymmetricKey::generate_aes(aes_key_size::AES_256);
    generated_key.attributes().set_usage_mask(
        static_cast<kmipcore::cryptographic_usage_mask>(
            kmipcore::KMIP_CRYPTOMASK_ENCRYPT |
            kmipcore::KMIP_CRYPTOMASK_DECRYPT |
            kmipcore::KMIP_CRYPTOMASK_MAC_GENERATE
        )
    );
    std::cout << "Generated AES-256 key (hex): ";
    print_hex(generated_key.value());

    const auto key_id =
        client.op_register_key(argv[6], "TestGroup", generated_key);
    std::cout << "Key registered. ID: " << key_id << std::endl;

    auto fetched_key = client.op_get_key(key_id);

    std::cout << "Fetched key from server (hex): ";
    print_hex(fetched_key->value());
    std::cout << "Attributes:" << std::endl;
    for (const auto &[attr_name, attr_value] :
         fetched_key->attributes().as_string_map()) {
      std::cout << "  " << attr_name << ": " << attr_value << std::endl;
    }
    (void) client.op_revoke(
        key_id,
        revocation_reason_type::KMIP_REVOKE_KEY_COMPROMISE,
        "example cleanup",
        0
    );
    (void) client.op_destroy(key_id);
    std::cout << "Key revoked and destroyed: " << key_id << std::endl;
  } catch (std::exception &e) {
    std::cerr << "Can not register key:" << argv[6] << " Cause: " << e.what()
              << std::endl;
    return -1;
  };

  return 0;
}
