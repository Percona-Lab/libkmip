/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; version 2 of
   the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <iostream>

#include "KmipClient.hpp"
#include "NetClientOpenSSL.hpp"
#include "kmipclient_version.hpp"

using namespace kmipclient;

int
main (int argc, char **argv)
{
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << std::endl;
  std::cout << "KMIP library version: " << KMIP_LIB_VERSION_STR << std::endl;

  if (argc < 8)
    {
      std::cerr << "Usage:example_register_key <host> <port> <client_cert> "
                   "<client_key> <server_cert> <key_name> <key>"
                << std::endl;
      return -1;
    }
  NetClientOpenSSL net_client (argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  KmipClient       client (net_client);

  try
    {
      auto       k      = Key::aes_from_hex (argv[7]);
      const auto opt_id = client.op_register_key (argv[6], "TestGroup", k);
      std::cout << "Key registered. ID: " << opt_id << std::endl;
    }
  catch (std::exception &e)
    {
      std::cerr << "Can not register key:" << argv[6] << " Cause: " << e.what () << std::endl;
      return -1;
    };

  return 0;
}
