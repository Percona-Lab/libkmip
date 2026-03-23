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
 * example_pool.cpp
 *
 * Demonstrates KmipClientPool used from multiple threads simultaneously.
 *
 * Usage:
 *   example_pool <host> <port> <client_cert> <client_key> <server_ca_cert>
 *                <key_name_prefix> [num_threads] [max_pool_size]
 *
 * Each thread borrows a KmipClient from the pool, creates one AES-256 key,
 * and returns the connection automatically.
 */

#include "kmipclient/KmipClientPool.hpp"
#include "kmipclient/kmipclient_version.hpp"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace kmipclient;
using namespace std::chrono_literals;

int main(int argc, char **argv) {
  std::cout << "KMIP CLIENT version: " << KMIPCLIENT_VERSION_STR << "\n";

  if (argc < 7) {
    std::cerr
        << "Usage: example_pool <host> <port> <client_cert> <client_key> "
           "<server_ca_cert> <key_name_prefix> [num_threads] [max_pool_size]\n";
    return 1;
  }

  const std::string host = argv[1];
  const std::string port = argv[2];
  const std::string client_cert = argv[3];
  const std::string client_key = argv[4];
  const std::string server_ca_cert = argv[5];
  const std::string key_name_prefix = argv[6];
  const int num_threads = argc > 7 ? std::stoi(argv[7]) : 4;
  const int max_pool_size = argc > 8 ? std::stoi(argv[8]) : 2;

  std::cout << "Launching " << num_threads
            << " threads against a pool of max " << max_pool_size
            << " connections\n";

  // ------------------------------------------------------------------
  // Build the pool.  No connections are created here yet.
  // ------------------------------------------------------------------
  KmipClientPool pool(
      KmipClientPool::Config{
          .host = host,
          .port = port,
          .client_cert = client_cert,
          .client_key = client_key,
          .server_ca_cert = server_ca_cert,
          .timeout_ms = 5000,
          .max_connections = static_cast<size_t>(max_pool_size),
      }
  );

  // ------------------------------------------------------------------
  // Spawn threads – each borrows a connection, uses it, returns it.
  // ------------------------------------------------------------------
  std::vector<std::thread> threads;
  threads.reserve(num_threads);

  for (int i = 0; i < num_threads; ++i) {
    threads.emplace_back([&pool, &key_name_prefix, i]() {
      const std::string key_name = key_name_prefix + "_" + std::to_string(i);
      try {
        // borrow() blocks until a connection is available (or creates a
        // new one if the pool is below its limit).
        auto conn = pool.borrow(10s);  // wait at most 10 s
        auto key_id = conn->op_create_aes_key(key_name, "PoolTestGroup");

        std::ostringstream oss;
        oss << "[thread " << std::setw(2) << i << "] created key '" << key_name
            << "' -> id=" << key_id << "\n";
        std::cout << oss.str();

        // conn goes out of scope here → connection returned to pool.
      } catch (const std::exception &e) {
        std::ostringstream oss;
        oss << "[thread " << std::setw(2) << i << "] ERROR: " << e.what()
            << "\n";
        std::cerr << oss.str();
      }
    });
  }

  for (auto &t : threads) {
    t.join();
  }

  std::cout << "Pool stats: total=" << pool.total_count()
            << " available=" << pool.available_count()
            << " max=" << pool.max_connections() << "\n";

  return 0;
}
