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

#include "kmipclient/Kmip.hpp"
#include "kmipclient/KmipClient.hpp"
#include "kmipclient/kmipclient_version.hpp"

#include <iomanip>
#include <iostream>
#include <string>

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
    std::cerr << "Usage: example_register_secret <host> <port> <client_cert> "
                 "<client_key> <server_cert> "
                 "<secret_name>"
              << std::endl;
    return -1;
  }

  Kmip kmip(argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  try {
    const std::string generated_secret_text = "example_secret_2026";
    auto secret = Secret::from_text(
        generated_secret_text, secret_data_type::KMIP_SECDATA_PASSWORD
    );
    std::cout << "Generated secret (text): " << secret.as_text() << std::endl;
    std::cout << "Generated secret (hex): ";
    print_hex(secret.value());

    auto id = kmip.client().op_register_secret(argv[6], "TestGroup", secret);
    std::cout << "Secret ID: " << id << std::endl;

    auto fetched_secret = kmip.client().op_get_secret(id);
    std::cout << "Fetched secret (text): " << fetched_secret.as_text()
              << std::endl;
    std::cout << "Fetched secret (hex): ";
    print_hex(fetched_secret.value());

    (void) kmip.client().op_revoke(
        id,
        revocation_reason_type::KMIP_REVOKE_KEY_COMPROMISE,
        "example cleanup",
        0
    );
    (void) kmip.client().op_destroy(id);
    std::cout << "Secret revoked and destroyed: " << id << std::endl;
  } catch (std::exception &e) {
    std::cerr << "Can not register secret with name:" << argv[6]
              << " Cause: " << e.what() << std::endl;
    return -1;
  }
  return 0;
}
