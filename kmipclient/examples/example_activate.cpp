/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
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
    std::cerr << "Usage: example_activate <host> <port> <client_cert> "
                 "<client_key> <server_cert> <key_id>"
              << std::endl;
    return -1;
  }

  NetClientOpenSSL net_client(argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  KmipClient client(net_client);
  try {
    const auto opt_key = client.op_activate(argv[6]);
    std::cout << "Key wih ID: " << argv[6] << " is activated." << std::endl;
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "Can not activate key with id:" << argv[6]
              << " Cause: " << e.what() << std::endl;
  };

  return -1;
}
