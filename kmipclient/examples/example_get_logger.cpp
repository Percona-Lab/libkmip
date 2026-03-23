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
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_logger.hpp"

#include <iostream>
#include <memory>

using namespace kmipclient;

namespace {

  class StdoutLogger final : public kmipcore::Logger {
  public:
    [[nodiscard]] bool shouldLog(kmipcore::LogLevel) const override {
      return true;
    }

    void log(const kmipcore::LogRecord &record) override {
      std::cout << '[' << kmipcore::to_string(record.level) << "] "
                << record.component << " " << record.event << '\n'
                << record.message << std::endl;
    }
  };

  void print_hex(const std::vector<unsigned char> &key) {
    for (auto const &c : key) {
      std::cout << std::hex << static_cast<int>(c);
    }
    std::cout << std::dec << std::endl;
  }

}  // namespace

int main(int argc, char **argv) {
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << std::endl;
  std::cout << "KMIP library version: " << KMIPCORE_VERSION_STR << std::endl;
  if (argc < 7) {
    std::cerr
        << "Usage: example_get_logger <host> <port> <client_cert> <client_key> "
           "<server_cert> <key_id>"
        << std::endl;
    return -1;
  }

  auto logger = std::make_shared<StdoutLogger>();
  NetClientOpenSSL net_client(argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  KmipClient client(net_client, logger);

  try {
    std::string id = argv[6];
    auto key = client.op_get_key(id);
    std::cout << "Key: 0x";
    print_hex(key->value());
    std::cout << "State: " << key->attribute_value(KMIP_ATTR_NAME_STATE)
              << std::endl;
    std::cout << "Name: " << key->attribute_value(KMIP_ATTR_NAME_NAME)
              << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "Can not get key with id:" << argv[6] << " Cause: " << e.what()
              << std::endl;
    return 1;
  }

  return 0;
}
