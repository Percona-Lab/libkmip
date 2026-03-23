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

#include "../src/IOUtils.hpp"

#include "kmipclient/Kmip.hpp"
#include "kmipclient/KmipIOException.hpp"
#include "kmipclient/NetClientOpenSSL.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_logger.hpp"
#include "kmipcore/serialization_buffer.hpp"

#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace {

  class CollectingLogger final : public kmipcore::Logger {
  public:
    [[nodiscard]] bool shouldLog(kmipcore::LogLevel level) const override {
      return level == kmipcore::LogLevel::Debug;
    }

    void log(const kmipcore::LogRecord &record) override {
      records.push_back(record);
    }

    std::vector<kmipcore::LogRecord> records;
  };

  class FakeNetClient final : public kmipclient::NetClient {
  public:
    FakeNetClient()
      : NetClient("host", "5696", "client.pem", "client.key", "ca.pem", 1000) {}

    bool connect() override {
      m_isConnected = true;
      return true;
    }

    void close() override { m_isConnected = false; }

    int send(std::span<const std::uint8_t> data) override {
      ++send_calls;

      const int desired = send_plan_index < static_cast<int>(send_plan.size())
                            ? send_plan[send_plan_index++]
                            : static_cast<int>(data.size());
      if (desired <= 0) {
        return desired;
      }

      const int sent = std::min(desired, static_cast<int>(data.size()));
      sent_bytes.insert(sent_bytes.end(), data.begin(), data.begin() + sent);
      return sent;
    }

    int recv(std::span<std::uint8_t> data) override {
      if (recv_offset >= response_bytes.size()) {
        return 0;
      }

      const size_t count =
          std::min(data.size(), response_bytes.size() - recv_offset);
      std::copy_n(response_bytes.data() + recv_offset, count, data.data());
      recv_offset += count;
      return static_cast<int>(count);
    }

    std::vector<int> send_plan;
    std::vector<uint8_t> response_bytes;
    std::vector<uint8_t> sent_bytes;
    int send_calls = 0;

  private:
    int send_plan_index = 0;
    size_t recv_offset = 0;
  };

  std::vector<uint8_t>
      build_response_with_payload(const std::vector<uint8_t> &payload) {
    const auto len = static_cast<int32_t>(payload.size());
    std::vector<uint8_t> out{
        0,
        0,
        0,
        0,
        static_cast<uint8_t>((len >> 24) & 0xFF),
        static_cast<uint8_t>((len >> 16) & 0xFF),
        static_cast<uint8_t>((len >> 8) & 0xFF),
        static_cast<uint8_t>(len & 0xFF)
    };
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
  }

  std::vector<uint8_t>
      serialize_element(const std::shared_ptr<kmipcore::Element> &element) {
    kmipcore::SerializationBuffer buf;
    element->serialize(buf);
    return buf.release();
  }

}  // namespace

static_assert(
    std::is_move_constructible_v<kmipclient::Kmip>,
    "Kmip must be move-constructible"
);
static_assert(
    std::is_move_assignable_v<kmipclient::Kmip>,
    "Kmip must be move-assignable"
);
static_assert(
    !std::is_copy_constructible_v<kmipclient::Kmip>,
    "Kmip must remain non-copyable"
);
static_assert(
    !std::is_copy_assignable_v<kmipclient::Kmip>,
    "Kmip must remain non-copy-assignable"
);

TEST(IOUtilsTest, SendRetriesOnShortWritesUntilComplete) {
  FakeNetClient nc;
  nc.send_plan = {3, 2, 128};
  nc.response_bytes = build_response_with_payload({0x42});

  kmipclient::IOUtils io(nc);
  const std::vector<uint8_t> request{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  std::vector<uint8_t> response;

  ASSERT_NO_THROW(io.do_exchange(request, response, 1024));
  EXPECT_EQ(nc.sent_bytes, request);
  EXPECT_EQ(nc.send_calls, 3);
  EXPECT_EQ(response, nc.response_bytes);
}

TEST(IOUtilsTest, SendFailsIfTransportStopsProgress) {
  FakeNetClient nc;
  nc.send_plan = {2, 0};
  nc.response_bytes = build_response_with_payload({0x42});

  kmipclient::IOUtils io(nc);
  const std::vector<uint8_t> request{0, 1, 2, 3};
  std::vector<uint8_t> response;

  EXPECT_THROW(
      io.do_exchange(request, response, 1024), kmipclient::KmipIOException
  );
}

TEST(IOUtilsTest, DebugLoggingRedactsSensitiveTtlvFields) {
  FakeNetClient nc;

  auto request = kmipcore::Element::createStructure(
      kmipcore::tag::KMIP_TAG_REQUEST_MESSAGE
  );
  request->asStructure()->add(
      kmipcore::Element::createTextString(
          kmipcore::tag::KMIP_TAG_USERNAME, "alice"
      )
  );
  request->asStructure()->add(
      kmipcore::Element::createTextString(
          kmipcore::tag::KMIP_TAG_PASSWORD, "s3cr3t"
      )
  );
  request->asStructure()->add(
      kmipcore::Element::createByteString(
          kmipcore::tag::KMIP_TAG_KEY_MATERIAL, {0xDE, 0xAD, 0xBE, 0xEF}
      )
  );
  const auto request_bytes = serialize_element(request);

  auto response = kmipcore::Element::createStructure(
      kmipcore::tag::KMIP_TAG_RESPONSE_MESSAGE
  );
  auto secret_data =
      kmipcore::Element::createStructure(kmipcore::tag::KMIP_TAG_SECRET_DATA);
  secret_data->asStructure()->add(
      kmipcore::Element::createEnumeration(
          kmipcore::tag::KMIP_TAG_SECRET_DATA_TYPE,
          static_cast<int32_t>(
              kmipcore::secret_data_type::KMIP_SECDATA_PASSWORD
          )
      )
  );
  response->asStructure()->add(secret_data);
  nc.response_bytes = serialize_element(response);

  auto logger = std::make_shared<CollectingLogger>();
  kmipclient::IOUtils io(nc, logger);
  std::vector<uint8_t> response_bytes;

  ASSERT_NO_THROW(io.do_exchange(request_bytes, response_bytes, 1024));
  ASSERT_EQ(logger->records.size(), 2u);

  const std::string combined =
      logger->records[0].message + "\n" + logger->records[1].message;
  EXPECT_NE(combined.find("Username"), std::string::npos);
  EXPECT_NE(combined.find("Password"), std::string::npos);
  EXPECT_NE(combined.find("KeyMaterial"), std::string::npos);
  EXPECT_NE(combined.find("SecretData"), std::string::npos);
  EXPECT_NE(combined.find("<redacted sensitive"), std::string::npos);
  EXPECT_EQ(combined.find("alice"), std::string::npos);
  EXPECT_EQ(combined.find("s3cr3t"), std::string::npos);
  EXPECT_EQ(combined.find("DE AD BE EF"), std::string::npos);
}

TEST(NetClientTest, TlsVerificationDefaultsToPeerAndHostnameEnabled) {
  FakeNetClient nc;

  const auto options = nc.tls_verification();
  EXPECT_TRUE(options.peer_verification);
  EXPECT_TRUE(options.hostname_verification);
}

TEST(NetClientTest, TlsVerificationCanBeUpdatedBeforeConnect) {
  FakeNetClient nc;

  nc.set_tls_verification({
      .peer_verification = true,
      .hostname_verification = false,
  });

  auto options = nc.tls_verification();
  EXPECT_TRUE(options.peer_verification);
  EXPECT_FALSE(options.hostname_verification);

  nc.set_tls_verification({
      .peer_verification = false,
      .hostname_verification = false,
  });

  options = nc.tls_verification();
  EXPECT_FALSE(options.peer_verification);
  EXPECT_FALSE(options.hostname_verification);
}

TEST(NetClientOpenSSLTest, TlsVerificationSettingsAreStoredOnTransport) {
  kmipclient::NetClientOpenSSL nc(
      "kmip.example.test", "5696", "client.pem", "client.key", "ca.pem", 1000
  );

  nc.set_tls_verification({
      .peer_verification = true,
      .hostname_verification = false,
  });

  const auto options = nc.tls_verification();
  EXPECT_TRUE(options.peer_verification);
  EXPECT_FALSE(options.hostname_verification);
}
