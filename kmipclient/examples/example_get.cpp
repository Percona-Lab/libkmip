
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

void print_hex(const std::vector<unsigned char> &key) {
  for (auto const &c : key) {
    std::cout << std::hex << static_cast<int>(c);
  }
  std::cout << std::endl;
}

int main(int argc, char **argv) {
  std::cout << "KMIP CLIENT  version: " << KMIPCLIENT_VERSION_STR << std::endl;
  std::cout << "KMIP library version: " << KMIPCORE_VERSION_STR << std::endl;
  if (argc < 7) {
    std::cerr << "Usage: example_get <host> <port> <client_cert> <client_key> "
                 "<server_cert> <key_id>"
              << std::endl;
    return -1;
  }

  NetClientOpenSSL net_client(argv[1], argv[2], argv[3], argv[4], argv[5]);
  KmipClient client(net_client);

  try {
    std::string id = argv[6];
    auto key = client.op_get_key(id);
    std::cout << "Key: 0x";
    print_hex(key->value());
    std::cout << "Attributes:" << std::endl;
    for (const auto &[attr_name, attr_value] :
         key->attributes().as_string_map()) {
      std::cout << "  " << attr_name << ": " << attr_value << std::endl;
    }
  } catch (const std::exception &e) {
    std::cerr << "Can not get key with id:" << argv[6] << " Cause: " << e.what()
              << std::endl;
    return 1;
  };

  return 0;
}
