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
 * @file example_supported_versions.cpp
 * @brief Discovers KMIP protocol versions supported by a server
 *
 * This example demonstrates how to:
 * 1. Connect to a KMIP server
 * 2. Call op_discover_versions() to query supported protocol versions
 * 3. Display the versions in a readable format
 *
 * Usage:
 *   ./example_supported_versions <host> <port> <client_cert> <client_key>
 * <server_cert>
 */

#include "kmipclient/Kmip.hpp"
#include "kmipclient/kmipclient_version.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_errors.hpp"

#include <iomanip>
#include <iostream>
#include <string>

using namespace kmipclient;

// Helper function to format protocol version for display
static std::string formatVersion(const kmipcore::ProtocolVersion &version) {
  return std::to_string(version.getMajor()) + "." +
         std::to_string(version.getMinor());
}

int main(int argc, char **argv) {
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << std::endl;
  std::cout << "KMIP library version: " << KMIPCORE_VERSION_STR << std::endl;

  if (argc < 6) {
    std::cerr
        << "Usage: example_supported_versions <host> <port> <client_cert> "
           "<client_key> <server_cert>"
        << std::endl;
    return -1;
  }

  try {
    std::cout << "\nDiscovering KMIP versions from server...\n"
              << "Server: " << argv[1] << ":" << argv[2] << "\n\n";

    // Create KMIP client with TLS configuration
    // Use default timeout of 200ms and KMIP 1.4 protocol version
    Kmip kmip(argv[1], argv[2], argv[3], argv[4], argv[5], 200);

    // Call Discover Versions operation
    std::cout << "Sending Discover Versions request...\n";
    auto supported_versions = kmip.client().op_discover_versions();

    // Display results
    if (supported_versions.empty()) {
      std::cout << "\nServer advertises: (empty list)\n";
      std::cout << "This typically means the server supports KMIP 1.0\n";
      return 0;
    }

    std::cout << "\nServer supports the following KMIP protocol versions:\n"
              << std::string(50, '=') << "\n\n";

    for (size_t i = 0; i < supported_versions.size(); ++i) {
      const auto &version = supported_versions[i];
      std::cout << std::setw(2) << (i + 1) << ". KMIP "
                << formatVersion(version);

      if (i == 0) {
        std::cout << " (preferred/recommended by server)";
      }
      std::cout << "\n";
    }

    std::cout << "\n" << std::string(50, '=') << "\n";
    std::cout << "Total supported versions: " << supported_versions.size()
              << "\n";

    // Show which versions are considered "modern" (2.0 or later)
    size_t modern_count = 0;
    for (const auto &version : supported_versions) {
      if (version.getMajor() >= 2) {
        modern_count++;
      }
    }

    if (modern_count > 0) {
      std::cout << "Modern versions (2.0+): " << modern_count << "\n";
    }

    std::cout << "\nNote: The first version in the list is the server's "
              << "preferred version.\n";
    std::cout << "      Clients should typically use the first supported "
              << "version for best\n";
    std::cout << "      compatibility and performance.\n";

    return 0;

  } catch (const kmipcore::KmipException &e) {
    std::cerr << "KMIP Error: " << e.what() << "\n";
    return 1;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }
}
