

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
      std::cerr << "Usage: example_get_name <host> <port> <client_cert> <client_key> <server_cert> <key_id>"
                << std::endl;
      return -1;
    }

  NetClientOpenSSL net_client (argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  KmipClient       client (net_client);

  // get name
  const auto opt_attr = client.op_get_attribute (argv[6], KMIP_ATTR_NAME_NAME);
  if (opt_attr.has_value ())
    {
      std::cout << "ID: " << argv[6] << " Name: " << opt_attr.value () << std::endl;
    }
  else
    {
      std::cerr << "Can not get name for id:" << argv[6] << " Cause: " << opt_attr.error ().message << std::endl;
    };

  // get state
  const auto opt_attr2 = client.op_get_attribute (argv[6], KMIP_ATTR_NAME_STATE);
  if (opt_attr.has_value ())
    {
      std::cout << "ID: " << argv[6] << " State: " << opt_attr2.value () << std::endl;
    }
  else
    {
      std::cerr << "Can not get state for id:" << argv[6] << " Cause: " << opt_attr2.error ().message << std::endl;
    };

  return 0;
}
