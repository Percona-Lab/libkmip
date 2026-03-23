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

#include "kmipclient/KmipClientPool.hpp"

#include "kmipcore/kmip_errors.hpp"

#include <sstream>
#include <stdexcept>

namespace kmipclient {

  // ============================================================================
  // BorrowedClient
  // ============================================================================

  KmipClientPool::BorrowedClient::BorrowedClient(
      KmipClientPool &pool, std::unique_ptr<Slot> slot
  ) noexcept
    : pool_(&pool), slot_(std::move(slot)) {}

  KmipClientPool::BorrowedClient::BorrowedClient(
      BorrowedClient &&other
  ) noexcept
    : pool_(other.pool_),
      slot_(std::move(other.slot_)),
      healthy_(other.healthy_) {
    other.pool_ = nullptr;  // disown so other's dtor is a no-op
  }

  KmipClientPool::BorrowedClient &KmipClientPool::BorrowedClient::operator=(
      BorrowedClient &&other
  ) noexcept {
    if (this != &other) {
      // Return our current slot before taking ownership of the incoming one.
      if (pool_ != nullptr && slot_ != nullptr) {
        pool_->return_slot(std::move(slot_), healthy_);
      }
      pool_ = other.pool_;
      slot_ = std::move(other.slot_);
      healthy_ = other.healthy_;
      other.pool_ = nullptr;
    }
    return *this;
  }

  KmipClientPool::BorrowedClient::~BorrowedClient() {
    if (pool_ != nullptr && slot_ != nullptr) {
      pool_->return_slot(std::move(slot_), healthy_);
    }
  }

  KmipClient &KmipClientPool::BorrowedClient::operator*() {
    return *slot_->kmip_client;
  }

  KmipClient *KmipClientPool::BorrowedClient::operator->() {
    return slot_->kmip_client.get();
  }

  // ============================================================================
  // KmipClientPool
  // ============================================================================

  KmipClientPool::KmipClientPool(const Config &config) : config_(config) {
    if (config_.max_connections == 0) {
      throw kmipcore::KmipException(
          -1, "KmipClientPool: max_connections must be greater than zero"
      );
    }
    available_.reserve(config_.max_connections);
  }

  // ----------------------------------------------------------------------------
  // Private helpers
  // ----------------------------------------------------------------------------

  std::unique_ptr<KmipClientPool::Slot> KmipClientPool::create_slot() {
    auto slot = std::make_unique<Slot>();

    slot->net_client = std::make_unique<NetClientOpenSSL>(
        config_.host,
        config_.port,
        config_.client_cert,
        config_.client_key,
        config_.server_ca_cert,
        config_.timeout_ms
    );
    slot->net_client->set_tls_verification(config_.tls_verification);
    slot->net_client->connect();  // throws KmipException on failure

    slot->kmip_client = std::make_unique<KmipClient>(
        *slot->net_client, config_.logger, config_.version
    );

    return slot;
  }

  void KmipClientPool::return_slot(
      std::unique_ptr<Slot> slot, bool healthy
  ) noexcept {
    // Decide under the lock what to do with the slot.
    bool discard = !healthy || !slot->net_client->is_connected();

    {
      std::lock_guard<std::mutex> lk(mutex_);
      if (!discard) {
        available_.push_back(std::move(slot));
      } else {
        --total_count_;  // one fewer live connection
      }
      cv_.notify_one();
    }
    // If slot was not moved into available_, its destructor runs here –
    // outside the lock – which calls KmipClient::~KmipClient() →
    // net_client.close().
  }

  KmipClientPool::BorrowedClient
      KmipClientPool::acquire_locked(std::unique_lock<std::mutex> lk) {
    if (!available_.empty()) {
      // Re-use an idle connection.
      auto slot = std::move(available_.back());
      available_.pop_back();
      lk.unlock();
      return BorrowedClient(*this, std::move(slot));
    }

    // total_count_ < max_connections is guaranteed by the caller.
    // Reserve the slot under the lock, then release before the slow TLS
    // connect.
    ++total_count_;
    lk.unlock();

    try {
      return BorrowedClient(*this, create_slot());
    } catch (...) {
      // Connection failed: give the reserved slot back.
      std::lock_guard<std::mutex> guard(mutex_);
      --total_count_;
      cv_.notify_one();
      throw;
    }
  }

  // ----------------------------------------------------------------------------
  // Public borrow methods
  // ----------------------------------------------------------------------------

  KmipClientPool::BorrowedClient KmipClientPool::borrow() {
    std::unique_lock<std::mutex> lk(mutex_);
    cv_.wait(lk, [this] {
      return !available_.empty() || total_count_ < config_.max_connections;
    });
    return acquire_locked(std::move(lk));
  }

  KmipClientPool::BorrowedClient
      KmipClientPool::borrow(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lk(mutex_);

    const bool slot_available = cv_.wait_for(lk, timeout, [this] {
      return !available_.empty() || total_count_ < config_.max_connections;
    });

    if (!slot_available) {
      std::ostringstream oss;
      oss << "KmipClientPool: no connection available after " << timeout.count()
          << "ms (pool size: " << config_.max_connections
          << ", all " << total_count_ << " connections in use)";
      throw kmipcore::KmipException(
          -1,
          oss.str()
      );
    }
    return acquire_locked(std::move(lk));
  }

  std::optional<KmipClientPool::BorrowedClient> KmipClientPool::try_borrow() {
    std::unique_lock<std::mutex> lk(mutex_);

    if (available_.empty() && total_count_ >= config_.max_connections) {
      return std::nullopt;
    }
    return acquire_locked(std::move(lk));
  }

  // ----------------------------------------------------------------------------
  // Diagnostic accessors
  // ----------------------------------------------------------------------------

  size_t KmipClientPool::available_count() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return available_.size();
  }

  size_t KmipClientPool::total_count() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return total_count_;
  }

}  // namespace kmipclient
