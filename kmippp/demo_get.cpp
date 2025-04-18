

#include "kmippp.h"
#include <iostream>

int
main (int argc, char **argv)
{

  if (argc < 7)
    {
      std::cerr << "Usage: demo_create <host> <port> <client_cert> "
                   "<client_key> <server_cert> <key_id>"
                << std::endl;
      return -1;
    }

  kmippp::context ctx (argv[1], argv[2], argv[3], argv[4], argv[5]);

  auto key = ctx.op_get (argv[6]);
  if(key.empty ())
    {
      std::cout << "Can not get Key: " << argv[6] << std::endl;
      std::cout << ctx.get_last_result () << std::endl;
      return 1;
    }
  std::cout << "Key: 0x";
  for (auto const &c : key)
    {
      std::cout << std::hex << ((int)c);
    }
  std::cout << std::endl;
  return 0;
}
