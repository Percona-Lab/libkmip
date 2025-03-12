//
// Created by al on 02.04.25.
//
#include "../include/KmipClient.hpp"
#include "../include/NetClientOpenSSL.hpp"
#include "../include/kmip_data_types.hpp"
#include "../include/kmipclient_version.hpp"

#include <iostream>

using namespace kmipclient;

int
main (int argc, char **argv)
{
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << std::endl;
  if (argc < 8)
    {
      std::cerr << "Usage:example_register_key <host> <port> <client_cert> "
                   "<client_key> <server_cert> <key_name> <key>"
                << std::endl;
      return -1;
    }
  NetClientOpenSSL net_client (argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  KmipClient       client (net_client);

  auto k = Key::aes_from_hex (argv[7]);
  if (k.has_error ())
    {
      std::cerr << "Can not create AES key from input. Cause: " << k.error ().message << std::endl;
    }
  const auto opt_id = client.op_register_key (argv[6], "TestGroup", k.value ());
  if (opt_id.has_value ())
    {
      std::cout << "Key registered. ID: " << opt_id.value () << std::endl;
      ;
    }
  else
    {
      std::cerr << "Can not register key:" << argv[6] << " Cause: " << opt_id.error ().message << std::endl;
    };

  return 0;
}