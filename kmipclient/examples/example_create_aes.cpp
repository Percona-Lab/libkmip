

#include "../include/Kmip.hpp"
#include "../include/KmipClient.hpp"
#include "../include/NetClientOpenSSL.hpp"
#include <iostream>

using namespace kmipclient;

int
main (int argc, char **argv)
{
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << std::endl;
  if (argc < 7)
    {
      std::cerr << "Usage: example_create_aes <host> <port> <client_cert> <client_key> <server_cert> <key_id>"
                << std::endl;
      return -1;
    }

  Kmip kmip (argv[1], argv[2], argv[3], argv[4], argv[5], 200);

  auto key_opt = kmip.client ().op_create_aes_key (argv[6], "TestGroup");
  if (key_opt.has_value ())
    {
      const name_t &key_id = key_opt.value ();
      std::cout << "Key ID: " << key_id << std::endl;
    }
  else
    {
      std::cerr << "Can not create key with name:" << argv[6] << " Cause: " << key_opt.error ().message << std::endl;
    }
  return 0;
}
