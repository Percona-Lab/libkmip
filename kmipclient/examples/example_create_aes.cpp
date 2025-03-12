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

#include "Kmip.hpp"
#include "KmipClient.hpp"
#include "kmipclient_version.hpp"

using namespace kmipclient;

int
main (int argc, char **argv)
{
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << std::endl;
  std::cout << "KMIP library version: " << KMIP_LIB_VERSION_STR << std::endl;

  if (argc < 7)
    {
      std::cerr << "Usage: example_create_aes <host> <port> <client_cert> <client_key> <server_cert> <key_name>"
                << std::endl;
      return -1;
    }

  Kmip kmip (argv[1], argv[2], argv[3], argv[4], argv[5], 200);
  try
    {
      auto key_id = kmip.client ().op_create_aes_key (argv[6], "TestGroup");
      std::cout << "Key ID: " << key_id << std::endl;
      return 0;
    }
  catch (std::exception &e)
    {
      std::cerr << "Can not create key with name:" << argv[6] << " Cause: " << e.what () << std::endl;
    }
  return -1;
}
