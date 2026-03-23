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

#include <iostream>

using namespace kmipclient;

int main(int argc, char **argv) {
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << std::endl;
  std::cout << "KMIP library version: " << KMIPCORE_VERSION_STR << std::endl;

  if (argc < 7) {
    std::cerr << "Usage: example_locate <host> <port> <client_cert> "
                 "<client_key> <server_cert> <name>"
              << std::endl;
    return -1;
  }

  NetClientOpenSSL net_client(argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  KmipClient client(net_client);

  std::cout << "Searching for name: " << argv[6] << std::endl;
  try {
    const auto opt_ids = client.op_locate_by_name(
        argv[6], object_type::KMIP_OBJTYPE_SYMMETRIC_KEY
    );

    std::cout << "Found IDs of symmetric keys:" << std::endl;
    for (const auto &id : opt_ids) {
      std::cout << id << std::endl;
    }
  } catch (const std::exception &e) {
    std::cerr << "Can not get keys with name:" << argv[6]
              << " Cause: " << e.what() << std::endl;
    return 1;
  };

  try {
    const auto opt_ids_s = client.op_locate_by_name(
        argv[6], object_type::KMIP_OBJTYPE_SECRET_DATA
    );
    std::cout << "Found IDs of secret data:" << std::endl;
    for (const auto &id : opt_ids_s) {
      std::cout << id << std::endl;
    }
  } catch (const std::exception &e) {
    std::cerr << "Can not get secrets with name:" << argv[6]
              << " Cause: " << e.what() << std::endl;
    return 1;
  };

  return 0;
}
