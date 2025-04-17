

#include "../include/KmipClient.hpp"
#include "../include/NetClientOpenSSL.hpp"
#include "../include/kmipclient_version.hpp"

#include <iostream>

using namespace kmipclient;

void
print_hex (const kmipclient::key_t &key)
{
  for (auto const &c : key)
    {
      std::cout << std::hex << static_cast<int> (c);
    }
  std::cout << std::endl;
}

int
main (int argc, char **argv)
{
  std::cout << "KMIP CLIENT  version: " << KMIPCLIENT_VERSION_STR << std::endl;
  std::cout << "KMIP library version: " << KMIP_LIB_VERSION_STR << std::endl;
  if (argc < 7)
    {
      std::cerr << "Usage: example_get <host> <port> <client_cert> <client_key> <server_cert> <key_id>" << std::endl;
      return -1;
    }

  NetClientOpenSSL net_client (argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  KmipClient       client (net_client);

  const auto opt_key = client.op_get_key (argv[6]);
  if (opt_key.has_value ())
    {
      std::cout << "Key: 0x";
      auto k = opt_key.value ();
      print_hex (k.value ());
    }
  else
    {
      std::cerr << "Can not get key with id:" << argv[6] << " Cause: " << opt_key.error ().message << std::endl;
    };

  return 0;
}
