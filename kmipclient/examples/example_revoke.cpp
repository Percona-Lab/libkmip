//
// Created by al on 02.04.25.
//

#include "../include/KmipClient.hpp"
#include "../include/NetClientOpenSSL.hpp"
#include "../include/kmipclient_version.hpp"

#include <iostream>

using namespace kmipclient;

int
main (int argc, char **argv)
{
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << std::endl;
  if (argc < 7)
    {
      std::cerr << "Usage: example_revoke <host> <port> <client_cert> <client_key> <server_cert> <key_id>"
                << std::endl;
      return -1;
    }

  NetClientOpenSSL net_client (argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  KmipClient       client (net_client);

  const auto opt_key = client.op_revoke (argv[6], KMIP_REVIKE_UNSPECIFIED, "Deactivate", 0L);
  if (opt_key.has_value ())
    {
      std::cout << "Key ID: " << argv[6] << " is deactivated." << std::endl;
    }
  else
    {
      std::cerr << "Can not get key with id:" << argv[6] << " Cause: " << opt_key.error ().message << std::endl;
    };

  return 0;
}
