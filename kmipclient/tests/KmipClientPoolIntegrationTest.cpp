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
 * KmipClientPoolIntegrationTest.cpp
 *
 * Integration tests for KmipClientPool, verifying thread-safe concurrent
 * operations and proper connection pooling behavior.
 */

#include "kmipclient/Kmip.hpp"
#include "kmipclient/KmipClient.hpp"
#include "kmipclient/KmipClientPool.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_errors.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <gtest/gtest.h>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#define TEST_GROUP "pool_tests"

using namespace kmipclient;
using namespace std::chrono_literals;

static std::string POOL_TEST_NAME_PREFIX = "pool_test_";

// Helper class to manage environment variables
class KmipPoolTestConfig {
public:
  static KmipPoolTestConfig &getInstance() {
    static KmipPoolTestConfig instance;
    return instance;
  }

  [[nodiscard]] bool isConfigured() const {
    return !kmip_addr.empty() && !kmip_port.empty() &&
           !kmip_client_ca.empty() && !kmip_client_key.empty() &&
           !kmip_server_ca.empty();
  }

  std::string kmip_addr;
  std::string kmip_port;
  std::string kmip_client_ca;
  std::string kmip_client_key;
  std::string kmip_server_ca;
  int timeout_ms;

private:
  KmipPoolTestConfig() {
    const char *addr = std::getenv("KMIP_ADDR");
    const char *port = std::getenv("KMIP_PORT");
    const char *client_ca = std::getenv("KMIP_CLIENT_CA");
    const char *client_key = std::getenv("KMIP_CLIENT_KEY");
    const char *server_ca = std::getenv("KMIP_SERVER_CA");
    const char *timeout = std::getenv("KMIP_TIMEOUT_MS");

    if (addr) {
      kmip_addr = addr;
    }
    if (port) {
      kmip_port = port;
    }
    if (client_ca) {
      kmip_client_ca = client_ca;
    }
    if (client_key) {
      kmip_client_key = client_key;
    }
    if (server_ca) {
      kmip_server_ca = server_ca;
    }

    timeout_ms = 5000;
    if (timeout) {
      errno = 0;
      char *end = nullptr;
      const long parsed = std::strtol(timeout, &end, 10);
      if (errno == 0 && end != timeout && *end == '\0' && parsed >= 0 &&
          parsed <= INT_MAX) {
        timeout_ms = static_cast<int>(parsed);
      }
    }

    if (!isConfigured()) {
      std::cerr << "WARNING: KMIP environment variables not set. Pool tests "
                   "will be skipped.\n"
                << "Required variables:\n"
                << "  KMIP_ADDR\n"
                << "  KMIP_PORT\n"
                << "  KMIP_CLIENT_CA\n"
                << "  KMIP_CLIENT_KEY\n"
                << "  KMIP_SERVER_CA\n";
    }
  }
};

// Base test fixture for KMIP connection pool integration tests
class KmipClientPoolIntegrationTest : public ::testing::Test {
protected:
  std::vector<std::string> created_key_ids;
  std::mutex cleanup_mutex;

  void SetUp() override {
    auto &config = KmipPoolTestConfig::getInstance();

    if (!config.isConfigured()) {
      GTEST_SKIP() << "KMIP environment variables not configured";
    }
  }

  void TearDown() override {
    const auto *test_info =
        ::testing::UnitTest::GetInstance()->current_test_info();
    if (HasFailure()) {
      std::cout << test_info->name() << ": FAIL" << std::endl;
    } else {
      std::cout << test_info->name() << ": OK" << std::endl;
    }

    // Cleanup created keys
    auto &config = KmipPoolTestConfig::getInstance();
    if (config.isConfigured() && !created_key_ids.empty()) {
      try {
        Kmip kmip(
            config.kmip_addr.c_str(),
            config.kmip_port.c_str(),
            config.kmip_client_ca.c_str(),
            config.kmip_client_key.c_str(),
            config.kmip_server_ca.c_str(),
            config.timeout_ms,
            kmipcore::KMIP_VERSION_1_4,
            nullptr,
            NetClient::TlsVerificationOptions{
                .peer_verification = true,
                .hostname_verification = false,
            }
        );

        for (const auto &key_id : created_key_ids) {
          try {
            [[maybe_unused]] auto revoke_result = kmip.client().op_revoke(
                key_id,
                revocation_reason_type::KMIP_REVOKE_KEY_COMPROMISE,
                "Pool test cleanup",
                0
            );
            [[maybe_unused]] auto destroy_result =
                kmip.client().op_destroy(key_id);
          } catch (kmipcore::KmipException &e) {
            std::cerr << "Failed to destroy key: " << e.what() << std::endl;
          }
        }
      } catch (...) {
        // Ignore cleanup errors
      }
    }
  }

  static KmipClientPool::Config createPoolConfig(size_t max_connections = 4) {
    auto &config = KmipPoolTestConfig::getInstance();
    return KmipClientPool::Config{
        .host = config.kmip_addr,
        .port = config.kmip_port,
        .client_cert = config.kmip_client_ca,
        .client_key = config.kmip_client_key,
        .server_ca_cert = config.kmip_server_ca,
        .timeout_ms = config.timeout_ms,
        .max_connections = max_connections,
        .tls_verification = {
            .peer_verification = true,
            .hostname_verification = false,
        },
    };
  }

  void trackKeyForCleanup(const std::string &key_id) {
    std::lock_guard<std::mutex> lk(cleanup_mutex);
    created_key_ids.push_back(key_id);
  }
};

// ============================================================================
// Basic Pool Functionality Tests
// ============================================================================

TEST_F(KmipClientPoolIntegrationTest, PoolConstruction) {
  auto pool = KmipClientPool(createPoolConfig(4));

  EXPECT_EQ(pool.available_count(), 0)
      << "Pool should have no available connections at construction";
  EXPECT_EQ(pool.total_count(), 0)
      << "Pool should have no total connections at construction";
  EXPECT_EQ(pool.max_connections(), 4);
}

TEST_F(KmipClientPoolIntegrationTest, BorrowAndReturn) {
  auto pool = KmipClientPool(createPoolConfig(2));

  // Borrow a connection
  {
    auto conn = pool.borrow();
    EXPECT_EQ(pool.available_count(), 0)
        << "Borrowed connection should not be available";
    EXPECT_EQ(pool.total_count(), 1);
  }

  // Connection returned to pool
  EXPECT_EQ(pool.available_count(), 1)
      << "Returned connection should be available";
  EXPECT_EQ(pool.total_count(), 1);
}

TEST_F(KmipClientPoolIntegrationTest, MultipleConnections) {
  auto pool = KmipClientPool(createPoolConfig(3));

  std::vector<KmipClientPool::BorrowedClient> connections;

  // Borrow multiple connections
  for (int i = 0; i < 3; ++i) {
    connections.push_back(pool.borrow());
    EXPECT_EQ(pool.available_count(), 0)
        << "No connections should be available when all borrowed";
    EXPECT_EQ(pool.total_count(), i + 1);
  }

  // All connections back to pool
  connections.clear();
  EXPECT_EQ(pool.available_count(), 3);
  EXPECT_EQ(pool.total_count(), 3);
}

// ============================================================================
// Single-Threaded KMIP Operations via Pool
// ============================================================================

TEST_F(KmipClientPoolIntegrationTest, PoolCreateAesKey) {
  auto pool = KmipClientPool(createPoolConfig(2));

  try {
    auto conn = pool.borrow();
    auto key_id = conn->op_create_aes_key(
        POOL_TEST_NAME_PREFIX + "CreateAesKey", TEST_GROUP
    );
    EXPECT_FALSE(key_id.empty());
    trackKeyForCleanup(key_id);
    std::cout << "Created key via pool: " << key_id << std::endl;
  } catch (const kmipcore::KmipException &e) {
    FAIL() << "Failed to create key via pool: " << e.what();
  }
}

TEST_F(KmipClientPoolIntegrationTest, PoolCreateAndGet) {
  auto pool = KmipClientPool(createPoolConfig(2));

  try {
    std::string key_id;

    // Create via pool
    {
      auto conn = pool.borrow();
      key_id = conn->op_create_aes_key(
          POOL_TEST_NAME_PREFIX + "CreateAndGet", TEST_GROUP
      );
      trackKeyForCleanup(key_id);
    }

    // Get via pool (reusing connection)
    {
      auto conn = pool.borrow();
      auto key = conn->op_get_key(key_id);
      EXPECT_EQ(key->value().size(), 32);  // 256-bit AES
      std::cout << "Retrieved key via pool: " << key_id << std::endl;
    }
  } catch (kmipcore::KmipException &e) {
    FAIL() << "Failed pool create-and-get: " << e.what();
  }
}


// ============================================================================
// Concurrent Operations Tests
// ============================================================================

TEST_F(KmipClientPoolIntegrationTest, ConcurrentKeyCreation) {
  auto pool = KmipClientPool(createPoolConfig(4));

  const int num_threads = 8;
  std::vector<std::thread> threads;

  for (int i = 0; i < num_threads; ++i) {
    threads.emplace_back([this, &pool, i]() {
      try {
        auto conn = pool.borrow();
        auto key_id = conn->op_create_aes_key(
            POOL_TEST_NAME_PREFIX + "concurrent_" + std::to_string(i),
            TEST_GROUP
        );
        trackKeyForCleanup(key_id);
        std::cout << "Thread " << i << " created key: " << key_id << std::endl;
      } catch (const std::exception &e) {
        FAIL() << "Thread " << i << " failed: " << e.what();
      }
    });
  }

  for (auto &t : threads) {
    t.join();
  }

  EXPECT_EQ(created_key_ids.size(), num_threads)
      << "All threads should have created a key";
  std::cout << "Successfully created " << created_key_ids.size()
            << " keys concurrently" << std::endl;
}

TEST_F(KmipClientPoolIntegrationTest, PoolExhaustion) {
  auto pool = KmipClientPool(createPoolConfig(2));

  std::vector<KmipClientPool::BorrowedClient> borrowed;

  // Borrow all available connections
  for (int i = 0; i < 2; ++i) {
    borrowed.push_back(pool.borrow());
  }

  EXPECT_EQ(pool.available_count(), 0);
  EXPECT_EQ(pool.total_count(), 2);

  // Third borrow will block until timeout
  auto start = std::chrono::high_resolution_clock::now();
  try {
    [[maybe_unused]] auto conn = pool.borrow(500ms);
    FAIL() << "Should have thrown exception on timeout";
  } catch (const kmipcore::KmipException &) {
    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    EXPECT_GE(elapsed, 500ms)
        << "Timeout should have waited approximately 500ms";
    std::cout << "Pool exhaustion test: timeout waited "
              << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed)
                     .count()
              << "ms" << std::endl;
  }

  borrowed.clear();
}

TEST_F(KmipClientPoolIntegrationTest, TryBorrowNonBlocking) {
  auto pool = KmipClientPool(createPoolConfig(1));

  // Borrow the only connection
  {
    auto conn1 = pool.borrow();
    EXPECT_EQ(pool.available_count(), 0);

    // try_borrow should return nullopt immediately
    auto result = pool.try_borrow();
    EXPECT_FALSE(result.has_value())
        << "try_borrow should return nullopt when pool exhausted";
  }

  // Connection returned, now try_borrow should succeed
  auto result = pool.try_borrow();
  EXPECT_TRUE(result.has_value())
      << "try_borrow should succeed when connection available";
}

TEST_F(KmipClientPoolIntegrationTest, ConnectionReuse) {
  auto pool = KmipClientPool(createPoolConfig(1));

  std::string conn_id_1, conn_id_2;

  // Borrow, note its identity, return
  {
    auto conn = pool.borrow();
    // The NetClientOpenSSL address acts as a "connection ID"
    std::ostringstream oss;
    oss << static_cast<void *>(conn.operator->());
    conn_id_1 = oss.str();
  }

  // Borrow again - should get the same connection
  {
    auto conn = pool.borrow();
    std::ostringstream oss;
    oss << static_cast<void *>(conn.operator->());
    conn_id_2 = oss.str();
  }

  EXPECT_EQ(conn_id_1, conn_id_2)
      << "Same KmipClient should be reused from the pool";
  std::cout << "Connection reuse verified: " << conn_id_1 << std::endl;
}

TEST_F(KmipClientPoolIntegrationTest, UnhealthyConnectionDiscard) {
  auto pool = KmipClientPool(createPoolConfig(1));

  {
    auto conn = pool.borrow();
    // Simulate a network error by marking unhealthy
    conn.markUnhealthy();
    EXPECT_FALSE(conn.isHealthy());
  }

  // Connection should be discarded, pool should be able to create a new one
  EXPECT_EQ(pool.available_count(), 0)
      << "Unhealthy connection should not be returned to pool";
  EXPECT_EQ(pool.total_count(), 0)
      << "Unhealthy connection should decrement total count";

  // New borrow should create a fresh connection
  {
    auto conn = pool.borrow();
    EXPECT_EQ(pool.total_count(), 1);
  }
}

// ============================================================================
// Stress and Realistic Load Tests
// ============================================================================

TEST_F(KmipClientPoolIntegrationTest, ConcurrentOperationsWithReuse) {
  auto pool = KmipClientPool(createPoolConfig(4));

  const int num_threads = 8;
  const int ops_per_thread = 5;

  std::vector<std::thread> threads;

  for (int t = 0; t < num_threads; ++t) {
    threads.emplace_back([this, &pool, t]() {
      try {
        for (int op = 0; op < ops_per_thread; ++op) {
          auto conn = pool.borrow();

          // Create a key
          auto key_id = conn->op_create_aes_key(
              POOL_TEST_NAME_PREFIX + "stress_t" + std::to_string(t) +
                  "_op" + std::to_string(op),
              TEST_GROUP
          );
          trackKeyForCleanup(key_id);

          // Get the key back
          auto key = conn->op_get_key(key_id);
          EXPECT_FALSE(key->value().empty());

          // Get attributes
          auto attrs = conn->op_get_attributes(key_id, {KMIP_ATTR_NAME_NAME});
          EXPECT_TRUE(
              attrs.has_attribute(KMIP_ATTR_NAME_NAME) ||
              !attrs.generic().empty()
          );

          // Connection is returned here when out of scope
        }
      } catch (const std::exception &e) {
        FAIL() << "Thread " << t << " failed: " << e.what();
      }
    });
  }

  for (auto &t : threads) {
    t.join();
  }

  EXPECT_EQ(created_key_ids.size(), num_threads * ops_per_thread);
  std::cout << "Successfully completed " << (num_threads * ops_per_thread)
            << " concurrent operations with " << num_threads << " threads"
            << std::endl;
}

TEST_F(KmipClientPoolIntegrationTest, PoolStatistics) {
  auto pool = KmipClientPool(createPoolConfig(3));

  std::cout << "\nPool statistics:" << std::endl;
  std::cout << "  Max connections: " << pool.max_connections() << std::endl;
  std::cout << "  Available: " << pool.available_count() << std::endl;
  std::cout << "  Total: " << pool.total_count() << std::endl;

  // Borrow one
  {
    auto conn = pool.borrow();
    std::cout << "\nAfter borrowing one:" << std::endl;
    std::cout << "  Available: " << pool.available_count() << std::endl;
    std::cout << "  Total: " << pool.total_count() << std::endl;
    EXPECT_EQ(pool.available_count(), 0);
    EXPECT_EQ(pool.total_count(), 1);
  }

  // After return
  std::cout << "\nAfter returning:" << std::endl;
  std::cout << "  Available: " << pool.available_count() << std::endl;
  std::cout << "  Total: " << pool.total_count() << std::endl;
  EXPECT_EQ(pool.available_count(), 1);
  EXPECT_EQ(pool.total_count(), 1);
}
