

#include "../include/KmipClient.hpp"
#include "../include/NetClientOpenSSL.hpp"
#include "../include/kmipclient_version.hpp"

#include <iostream>

using namespace kmipclient;

int
main (int argc, char **argv)
{
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << std::endl;
  if (argc < 6)
    {
      std::cerr << "Usage: example_get_all_ids <host> <port> <client_cert> <client_key> <server_cert>" << std::endl;
      return -1;
    }

  NetClientOpenSSL net_client (argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  KmipClient       client (net_client);

  const auto opt_ids = client.op_all (KMIP_ENTITY_SYMMETRIC_KEY);
  if (opt_ids.has_value ())
    {
      std::cout << "Found IDs of symmetric keys:" << std::endl;
      for (const auto &id : opt_ids.value ())
        {
          std::cout << id << std::endl;
        }
    }
  else
    {
      std::cerr << "Can not get keys." << " Cause: " << opt_ids.error ().message << std::endl;
    };

  const auto opt_ids_s = client.op_all (KMIP_ENTITY_SECRET_DATA);
  if (opt_ids.has_value ())
    {
      std::cout << "Found IDs of secret data:" << std::endl;
      for (const auto &id : opt_ids_s.value ())
        {
          std::cout << id << std::endl;
        }
    }
  else
    {
      std::cerr << "Can not get secrets." << " Cause: " << opt_ids.error ().message << std::endl;
    };

  return 0;
}
