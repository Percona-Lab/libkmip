
/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipclient/KmipClient.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"
#include "kmipclient/kmipclient_version.hpp"
#include "kmipcore/kmip_basics.hpp"

#include <iostream>

using namespace kmipclient;

void print_hex(const std::vector<unsigned char> &key) {
  for (auto const &c : key) {
    std::cout << std::hex << static_cast<int>(c);
  }
  std::cout << std::endl;
}

void print_attributes(const kmipcore::Attributes &attrs) {
  for (const auto &[name, value] : attrs.as_string_map()) {
    std::cout << name << ": " << value << std::endl;
  }
}

/* This example is incomplete because of the low-level kmip.c is quite
 * incomplete, and there's no sense to complete exiting ugly C code. The next
 * version of the "KMIPClient" library will remove dependency on old C code and
 * will be replaced with C++ code of the protocol serialization/deserialization
 */

int main(int argc, char **argv) {
  std::cout << "KMIP CLIENT  version: " << KMIPCLIENT_VERSION_STR << std::endl;
  std::cout << "KMIP library version: " << KMIPCORE_VERSION_STR << std::endl;
  if (argc < 7) {
    std::cerr << "Usage: example_get <host> <port> <client_cert> <client_key> "
                 "<server_cert> <key_id>"
              << std::endl;
    return -1;
  }

  NetClientOpenSSL net_client(argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  KmipClient client(net_client);

  try {
    std::string id = argv[6];
    auto key = client.op_get_key(id);
    std::cout << "Key: 0x";
    print_hex(key->value());
    auto attr_names = client.op_get_attribute_list(id);

    auto attr = client.op_get_attributes(id, attr_names);

    std::cout << "======= key attributes: =======" << std::endl;
    print_attributes(key->attributes());
    std::cout << "======= all attributes: =======" << std::endl;
    print_attributes(attr);
  } catch (const std::exception &e) {
    std::cerr << "Can not get key with id:" << argv[6] << " Cause: " << e.what()
              << std::endl;
    return -1;
  };

  return 0;
}
