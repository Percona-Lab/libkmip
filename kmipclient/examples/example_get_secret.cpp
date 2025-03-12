

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
      std::cerr << "Usage: example_get_secret <host> <port> <client_cert> <client_key> <server_cert> <secret_id>"
                << std::endl;
      return -1;
    }

  NetClientOpenSSL net_client (argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  KmipClient       client (net_client);

  auto opt_secret = client.op_get_secret (argv[6]);
  if (opt_secret.has_value ())
    {
      std::cout << "Secret: " << opt_secret.value ().value << std::endl;
    }
  else
    {
      std::cerr << "Can not get key with id:" << argv[6] << " Cause: " << opt_secret.error ().message << std::endl;
    };

  return 0;
}
