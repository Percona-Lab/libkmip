

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
      std::cerr << "Usage: example_register_secret <host> <port> <client_cert> <client_key> <server_cert> "
                   "<secret_name> <secret>"
                << std::endl;
      return -1;
    }

  Kmip kmip (argv[1], argv[2], argv[3], argv[4], argv[5], 200);

  auto id_opt = kmip.client ().op_register_secret (argv[6], "TestGroup", argv[7], KMIP_SECRET_TYPE_PASSWORD);
  if (id_opt.has_value ())
    {
      const name_t &id = id_opt.value ();
      std::cout << "Secret ID: " << id << std::endl;
    }
  else
    {
      std::cerr << "Can not register secret with name:" << argv[6] << " Cause: " << id_opt.error ().message
                << std::endl;
    }
  return 0;
}
