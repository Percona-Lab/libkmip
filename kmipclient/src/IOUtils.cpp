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

#include "IOUtils.hpp"

#include "kmipclient/KmipIOException.hpp"
#include "kmipcore/kmip_formatter.hpp"
#include "kmipcore/kmip_logger.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <sstream>

namespace kmipclient {
#define KMIP_MSG_LENGTH_BYTES 8

  namespace {

    [[nodiscard]] int32_t read_int32_be(std::span<const uint8_t> bytes) {
      return (static_cast<int32_t>(bytes[0]) << 24) |
             (static_cast<int32_t>(bytes[1]) << 16) |
             (static_cast<int32_t>(bytes[2]) << 8) |
             static_cast<int32_t>(bytes[3]);
    }

  }  // namespace

  void IOUtils::log_debug(
      const char *event, std::span<const uint8_t> ttlv
  ) const {
    try {
      if (!logger_ || !logger_->shouldLog(kmipcore::LogLevel::Debug)) {
        return;
      }

      logger_->log(
          kmipcore::LogRecord{
              .level = kmipcore::LogLevel::Debug,
              .component = "kmip.protocol",
              .event = event,
              .message = kmipcore::format_ttlv(ttlv)
          }
      );
    } catch (...) {
      // Logging is strictly best-effort: protocol operations must not fail
      // because a custom logger threw.
    }
  }

  void IOUtils::send(const std::vector<uint8_t> &request_bytes) const {
    const int dlen = static_cast<int>(request_bytes.size());
    if (dlen <= 0) {
      throw KmipIOException(
          kmipcore::KMIP_IO_FAILURE, "Can not send empty KMIP request."
      );
    }

    int total_sent = 0;
    while (total_sent < dlen) {
      const int sent = net_client.send(
          std::span<const uint8_t>(request_bytes)
              .subspan(static_cast<size_t>(total_sent))
      );
      if (sent <= 0) {
        std::ostringstream oss;
        oss << "Can not send request. Bytes total: " << dlen
            << ", bytes sent: " << total_sent;
        throw KmipIOException(
            kmipcore::KMIP_IO_FAILURE,
            oss.str()
        );
      }
      total_sent += sent;
    }
  }

  void IOUtils::read_exact(std::span<uint8_t> buf) {
    int total_read = 0;
    const int n = static_cast<int>(buf.size());
    while (total_read < n) {
      const int received =
          net_client.recv(buf.subspan(static_cast<size_t>(total_read)));
      if (received <= 0) {
        std::ostringstream oss;
        oss << "Connection closed or error while reading. Expected " << n
            << ", got " << total_read;
        throw KmipIOException(
            kmipcore::KMIP_IO_FAILURE,
            oss.str()
        );
      }
      total_read += received;
    }
  }

  std::vector<uint8_t> IOUtils::receive_message(size_t max_message_size) {
    std::array<uint8_t, KMIP_MSG_LENGTH_BYTES> msg_len_buf{};

    read_exact(msg_len_buf);

    const int32_t length = read_int32_be(std::span(msg_len_buf).subspan(4, 4));
    const std::size_t effective_limit =
        std::min(max_message_size, kmipcore::KMIP_MAX_MESSAGE_HARD_LIMIT);
    if (length < 0 || static_cast<size_t>(length) > effective_limit) {
      std::ostringstream oss;
      oss << "Message too long. Length: " << length
          << ", allowed: " << effective_limit;
      throw KmipIOException(
          kmipcore::KMIP_EXCEED_MAX_MESSAGE_SIZE,
          oss.str()
      );
    }

    std::vector<uint8_t> response(
        KMIP_MSG_LENGTH_BYTES + static_cast<size_t>(length)
    );
    memcpy(response.data(), msg_len_buf.data(), KMIP_MSG_LENGTH_BYTES);

    read_exact(
        std::span(response).subspan(
            KMIP_MSG_LENGTH_BYTES, static_cast<size_t>(length)
        )
    );


    return response;
  }

  void IOUtils::do_exchange(
      const std::vector<uint8_t> &request_bytes,
      std::vector<uint8_t> &response_bytes,
      size_t max_message_size
  ) {
    try {
      log_debug("request", request_bytes);
      send(request_bytes);
      response_bytes = receive_message(max_message_size);
      log_debug("response", response_bytes);
    } catch (const KmipIOException &) {
      // Mark the underlying connection as dead so the pool (via
      // return_slot → is_connected() check) discards this slot
      // automatically — no need for the caller to call markUnhealthy().
      net_client.close();
      throw;
    }
  }

}  // namespace kmipclient
