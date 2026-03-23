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

#ifndef IOUTILS_HPP
#define IOUTILS_HPP

#include "kmipclient/NetClient.hpp"
#include "kmipclient/types.hpp"
#include "kmipcore/kmip_logger.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace kmipclient {

  class IOUtils {
  public:
    explicit IOUtils(
        NetClient &nc, const std::shared_ptr<kmipcore::Logger> &logger = {}
    )
      : net_client(nc), logger_(logger) {};

    void do_exchange(
        const std::vector<uint8_t> &request_bytes,
        std::vector<uint8_t> &response_bytes,
        size_t max_message_size
    );

  private:
    void log_debug(const char *event, std::span<const uint8_t> ttlv) const;
    void send(const std::vector<uint8_t> &request_bytes) const;
    std::vector<uint8_t> receive_message(size_t max_message_size);

    /**
     * Reads exactly n bytes from the network into the buffer.
     * Throws KmipException on error or prematureEOF.
     */
    void read_exact(std::span<uint8_t> buf);

    NetClient &net_client;
    std::shared_ptr<kmipcore::Logger> logger_;
  };

}  // namespace kmipclient

#endif  // IOUTILS_HPP
