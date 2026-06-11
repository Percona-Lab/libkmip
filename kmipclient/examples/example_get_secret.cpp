/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipclient/KmipClient.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"
#include "kmipclient/kmipclient_version.hpp"

#include <iomanip>
#include <iostream>

using namespace kmipclient;

int main(int argc, char **argv) {
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << std::endl;
  std::cout << "KMIP library version: " << KMIPCORE_VERSION_STR << std::endl;

  if (argc < 7) {
    std::cerr << "Usage: example_get_secret <host> <port> <client_cert> "
                 "<client_key> <server_cert> "
                 "<secret_id>"
              << std::endl;
    return -1;
  }

  NetClientOpenSSL net_client(argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  KmipClient client(net_client);
  try {
    auto secret = client.op_get_secret(argv[6], true);
    std::cout << "Secret (text): " << secret.as_text() << std::endl;
    std::cout << "Secret (hex): ";
    for (const auto b : secret.value()) {
      std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;

    const auto &attrs = secret.attributes();
    std::cout << "Attributes:" << std::endl;
    for (const auto &[key, value] : attrs.as_string_map()) {
      std::cout << "  " << key << ": " << value << std::endl;
    }
  } catch (std::exception &e) {
    std::cerr << "Can not get secret with id:" << argv[6]
              << " Cause: " << e.what() << std::endl;
    return -1;
  };

  return 0;
}
