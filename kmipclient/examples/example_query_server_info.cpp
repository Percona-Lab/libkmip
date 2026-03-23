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

/**
 * @file example_query_server_info.cpp
 * @brief Queries KMIP server for capabilities and vendor information
 *
 * This example demonstrates how to:
 * 1. Connect to a KMIP server
 * 2. Call op_query() to get server capabilities and metadata
 * 3. Display supported operations, object types, and vendor information
 *
 * Usage:
 *   ./example_query_server_info <host> <port> <client_cert> <client_key>
 * <server_cert>
 */

#include "kmipclient/Kmip.hpp"
#include "kmipclient/kmipclient_version.hpp"
#include "kmipcore/kmip_enums.hpp"
#include "kmipcore/kmip_errors.hpp"

#include <iomanip>
#include <iostream>
#include <string>

using namespace kmipclient;
using namespace kmipcore;

int main(int argc, char **argv) {
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << std::endl;
  std::cout << "KMIP library version: " << KMIPCORE_VERSION_STR << std::endl;

  if (argc < 6) {
    std::cerr << "Usage: example_query_server_info <host> <port> <client_cert> "
                 "<client_key> <server_cert>"
              << std::endl;
    return -1;
  }

  try {
    std::cout << "\nQuerying KMIP server capabilities and information...\n"
              << "Server: " << argv[1] << ":" << argv[2] << "\n\n";

    // Create KMIP client with TLS configuration
    Kmip kmip(argv[1], argv[2], argv[3], argv[4], argv[5], 200);

    // Call Query operation
    std::cout << "Sending Query request...\n";
    auto server_info = kmip.client().op_query();

    // Display results
    std::cout << "\n" << std::string(70, '=') << "\n";
    std::cout << "SERVER INFORMATION\n";
    std::cout << std::string(70, '=') << "\n\n";

    // Display vendor information
    if (!server_info.vendor_name.empty()) {
      std::cout << "Vendor Name:          " << server_info.vendor_name << "\n";
    }
    if (!server_info.server_name.empty()) {
      std::cout << "Server Name:          " << server_info.server_name << "\n";
    }
    if (!server_info.product_name.empty()) {
      std::cout << "Product Name:         " << server_info.product_name << "\n";
    }
    if (!server_info.server_version.empty()) {
      std::cout << "Server Version:       " << server_info.server_version
                << "\n";
    }
    if (!server_info.build_level.empty()) {
      std::cout << "Build Level:          " << server_info.build_level << "\n";
    }
    if (!server_info.build_date.empty()) {
      std::cout << "Build Date:           " << server_info.build_date << "\n";
    }
    if (!server_info.server_serial_number.empty()) {
      std::cout << "Serial Number:        " << server_info.server_serial_number
                << "\n";
    }
    if (!server_info.server_load.empty()) {
      std::cout << "Server Load:          " << server_info.server_load << "\n";
    }
    if (!server_info.cluster_info.empty()) {
      std::cout << "Cluster Info:         " << server_info.cluster_info << "\n";
    }

    // Display supported operations
    std::cout << "\n" << std::string(70, '-') << "\n";
    std::cout << "SUPPORTED OPERATIONS ("
              << server_info.supported_operations.size() << " total)\n";
    std::cout << std::string(70, '-') << "\n\n";

    int col_width = 35;
    int col_count = 0;
    for (const auto &op : server_info.supported_operations) {
      if (col_count > 0) {
        std::cout << std::setw(col_width) << " ";
      }
      const auto *name =
          kmipcore::operation_to_string(static_cast<int32_t>(op));
      std::cout << std::left << std::setw(col_width) << name;
      col_count++;
      if (col_count >= 2) {
        std::cout << "\n";
        col_count = 0;
      }
    }
    if (col_count > 0) {
      std::cout << "\n";
    }

    // Display supported object types
    std::cout << "\n" << std::string(70, '-') << "\n";
    std::cout << "SUPPORTED OBJECT TYPES ("
              << server_info.supported_object_types.size() << " total)\n";
    std::cout << std::string(70, '-') << "\n\n";

    col_count = 0;
    for (const auto &type : server_info.supported_object_types) {
      if (col_count > 0) {
        std::cout << std::setw(col_width) << " ";
      }
      const auto *name =
          kmipcore::object_type_to_string(static_cast<int32_t>(type));
      std::cout << std::left << std::setw(col_width) << name;
      col_count++;
      if (col_count >= 2) {
        std::cout << "\n";
        col_count = 0;
      }
    }
    if (col_count > 0) {
      std::cout << "\n";
    }

    std::cout << "\n" << std::string(70, '=') << "\n";

    return 0;

  } catch (const kmipcore::KmipException &e) {
    std::cerr << "KMIP Error: " << e.what() << "\n";
    return 1;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }
}
