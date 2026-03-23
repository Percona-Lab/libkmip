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

#include "kmipclient/KmipClient.hpp"

#include "IOUtils.hpp"
#include "kmipcore/attributes_parser.hpp"
#include "kmipcore/key_parser.hpp"
#include "kmipcore/kmip_errors.hpp"
#include "kmipcore/kmip_requests.hpp"
#include "kmipcore/response_parser.hpp"

#include <algorithm>
#include <optional>
#include <stdexcept>

namespace kmipclient {

  static std::vector<std::string> default_get_key_attrs(bool all_attributes) {
    if (all_attributes) {
      return {};
    }
    return {
        KMIP_ATTR_NAME_STATE,
        KMIP_ATTR_NAME_NAME,
        KMIP_ATTR_NAME_OPERATION_POLICY_NAME,
        KMIP_ATTR_NAME_CRYPTO_ALG,
        KMIP_ATTR_NAME_CRYPTO_LEN,
        KMIP_ATTR_NAME_CRYPTO_USAGE_MASK
    };
  }

  static std::vector<std::string>
      default_get_secret_attrs(bool all_attributes) {
    if (all_attributes) {
      return {};
    }
    return {
        KMIP_ATTR_NAME_STATE,
        KMIP_ATTR_NAME_NAME,
        KMIP_ATTR_NAME_OPERATION_POLICY_NAME
    };
  }

  static bool should_retry_get_attributes_with_legacy_v2_encoding(
      const kmipcore::KmipException &e
  ) {
    switch (e.code().value()) {
      case kmipcore::KMIP_REASON_INVALID_MESSAGE:
      case kmipcore::KMIP_REASON_INVALID_FIELD:
      case kmipcore::KMIP_REASON_FEATURE_NOT_SUPPORTED:
        return true;
      default:
        return false;
    }
  }

  KmipClient::KmipClient(
      NetClient &net_client,
      const std::shared_ptr<kmipcore::Logger> &logger,
      kmipcore::ProtocolVersion version,
      bool close_on_destroy
  )
    : net_client(&net_client),
      io(std::make_unique<IOUtils>(net_client, logger)),
      version_(version),
      close_on_destroy_(close_on_destroy) {};

  KmipClient::KmipClient(
      std::shared_ptr<NetClient> net_client,
      const std::shared_ptr<kmipcore::Logger> &logger,
      kmipcore::ProtocolVersion version,
      bool close_on_destroy
  )
    : net_client(net_client.get()),
      net_client_owner_(std::move(net_client)),
      io(),
      version_(version),
      close_on_destroy_(close_on_destroy) {
    if (this->net_client == nullptr) {
      throw std::invalid_argument("KmipClient: net_client must not be null");
    }
    io = std::make_unique<IOUtils>(*this->net_client, logger);
  };

  KmipClient::KmipClient(KmipClient &&other) noexcept
    : net_client(other.net_client),
      net_client_owner_(std::move(other.net_client_owner_)),
      io(std::move(other.io)),
      version_(other.version_),
      close_on_destroy_(other.close_on_destroy_) {
    other.net_client = nullptr;
    other.close_on_destroy_ = false;
  }

  KmipClient &KmipClient::operator=(KmipClient &&other) noexcept {
    if (this != &other) {
      net_client = other.net_client;
      net_client_owner_ = std::move(other.net_client_owner_);
      io = std::move(other.io);
      version_ = other.version_;
      close_on_destroy_ = other.close_on_destroy_;

      other.net_client = nullptr;
      other.close_on_destroy_ = false;
    }
    return *this;
  }

  std::shared_ptr<KmipClient> KmipClient::create_shared(
      NetClient &net_client,
      const std::shared_ptr<kmipcore::Logger> &logger,
      kmipcore::ProtocolVersion version,
      bool close_on_destroy
  ) {
    return std::make_shared<KmipClient>(net_client, logger, version, close_on_destroy);
  }

  std::shared_ptr<KmipClient> KmipClient::create_shared(
      std::shared_ptr<NetClient> net_client,
      const std::shared_ptr<kmipcore::Logger> &logger,
      kmipcore::ProtocolVersion version,
      bool close_on_destroy
  ) {
    return std::make_shared<KmipClient>(std::move(net_client), logger, version, close_on_destroy);
  }

  KmipClient::~KmipClient() {
    // Reference-based construction is non-owning by default; close only when
    // explicitly requested (or when using an owning/shared setup).
    if (close_on_destroy_ && net_client != nullptr) {
      net_client->close();
    }
  };

  std::string KmipClient::op_register_key(
      const std::string &name, const std::string &group, const Key &k
  ) const {
    auto request = make_request_message();
    const auto batch_item_id = request.add_batch_item(
        kmipcore::RegisterKeyRequest(
            name,
            group,
            k.to_core_key(),
            request.getHeader().getProtocolVersion()
        )
    );

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    return rf
        .getResponseByBatchItemId<kmipcore::RegisterResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  std::string KmipClient::op_register_secret(
      const std::string &name, const std::string &group, const Secret &secret
  ) const {
    auto request = make_request_message();
    const auto batch_item_id = request.add_batch_item(
        kmipcore::RegisterSecretRequest(
            name,
            group,
            secret.value(),
            secret.get_secret_type(),
            request.getHeader().getProtocolVersion()
        )
    );

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    return rf
        .getResponseByBatchItemId<kmipcore::RegisterResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }


  std::string KmipClient::op_create_aes_key(
      const std::string &name,
      const std::string &group,
      aes_key_size key_size,
      cryptographic_usage_mask usage_mask
  ) const {
    auto request = make_request_message();
    const auto batch_item_id = request.add_batch_item(
        kmipcore::CreateSymmetricKeyRequest(
            name,
            group,
            static_cast<int32_t>(key_size),
            usage_mask,
            request.getHeader().getProtocolVersion()
        )
    );

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    return rf
        .getResponseByBatchItemId<kmipcore::CreateResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  std::unique_ptr<Key>
      KmipClient::op_get_key(const std::string &id, bool all_attributes) const {
    const auto requested_attrs = default_get_key_attrs(all_attributes);
    const auto execute = [&](bool legacy_attribute_names_for_v2) {
      auto request = make_request_message();
      const auto get_item_id = request.add_batch_item(kmipcore::GetRequest(id));

      const auto attributes_item_id = request.add_batch_item(
          kmipcore::GetAttributesRequest(
              id,
              requested_attrs,
              request.getHeader().getProtocolVersion(),
              legacy_attribute_names_for_v2
          )
      );

      std::vector<uint8_t> response_bytes;
      io->do_exchange(
          request.serialize(), response_bytes, request.getMaxResponseSize()
      );

      kmipcore::ResponseParser rf(response_bytes, request);
      auto get_response =
          rf.getResponseByBatchItemId<kmipcore::GetResponseBatchItem>(
              get_item_id
          );
      auto core_key = kmipcore::KeyParser::parseGetKeyResponse(get_response);
      auto key = Key::from_core_key(core_key);

      auto attrs_response =
          rf.getResponseByBatchItemId<kmipcore::GetAttributesResponseBatchItem>(
              attributes_item_id
          );
      kmipcore::Attributes server_attrs =
          kmipcore::AttributesParser::parse(attrs_response.getAttributes());

      // Verify required attributes are present in the server response.
      if (!server_attrs.has_attribute(KMIP_ATTR_NAME_STATE)) {
        throw kmipcore::KmipException(
            "Required attribute 'State' missing from server response"
        );
      }
      // Merge server-provided metadata (state, name, dates, …) into the key.
      key->attributes().merge(server_attrs);
      return key;
    };

    try {
      return execute(false);
    } catch (const kmipcore::KmipException &first_error) {
      if (!version_.is_at_least(2, 0) ||
          !should_retry_get_attributes_with_legacy_v2_encoding(first_error)) {
        throw;
      }
    }
    try {
      return execute(true);
    } catch (const kmipcore::KmipException &second_error) {
      if (requested_attrs.empty() ||
          !should_retry_get_attributes_with_legacy_v2_encoding(second_error)) {
        throw;
      }
    }

    // Compatibility fallback for servers that reject explicit selectors in
    // Get Attributes requests: request all attributes and filter client-side.
    auto request = make_request_message();
    const auto get_item_id = request.add_batch_item(kmipcore::GetRequest(id));
    const auto attributes_item_id = request.add_batch_item(
        kmipcore::GetAttributesRequest(
            id, {}, request.getHeader().getProtocolVersion(), true
        )
    );
    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );
    kmipcore::ResponseParser rf(response_bytes, request);
    auto get_response =
        rf.getResponseByBatchItemId<kmipcore::GetResponseBatchItem>(
            get_item_id
        );
    auto core_key = kmipcore::KeyParser::parseGetKeyResponse(get_response);
    auto key = Key::from_core_key(core_key);
    auto attrs_response =
        rf.getResponseByBatchItemId<kmipcore::GetAttributesResponseBatchItem>(
            attributes_item_id
        );
    kmipcore::Attributes server_attrs =
        kmipcore::AttributesParser::parse(attrs_response.getAttributes());
    if (!server_attrs.has_attribute(KMIP_ATTR_NAME_STATE)) {
      throw kmipcore::KmipException(
          "Required attribute 'State' missing from server response"
      );
    }
    key->attributes().merge(server_attrs);
    return key;
  }

  Secret KmipClient::op_get_secret(
      const std::string &id, bool all_attributes
  ) const {
    const auto requested_attrs = default_get_secret_attrs(all_attributes);
    const auto execute = [&](bool legacy_attribute_names_for_v2) {
      auto request = make_request_message();
      const auto get_item_id = request.add_batch_item(kmipcore::GetRequest(id));

      const auto attributes_item_id = request.add_batch_item(
          kmipcore::GetAttributesRequest(
              id,
              requested_attrs,
              request.getHeader().getProtocolVersion(),
              legacy_attribute_names_for_v2
          )
      );

      std::vector<uint8_t> response_bytes;
      io->do_exchange(
          request.serialize(), response_bytes, request.getMaxResponseSize()
      );

      kmipcore::ResponseParser rf(response_bytes, request);
      auto get_response =
          rf.getResponseByBatchItemId<kmipcore::GetResponseBatchItem>(
              get_item_id
          );
      Secret secret = kmipcore::KeyParser::parseGetSecretResponse(get_response);

      auto attrs_response =
          rf.getResponseByBatchItemId<kmipcore::GetAttributesResponseBatchItem>(
              attributes_item_id
          );
      kmipcore::Attributes server_attrs =
          kmipcore::AttributesParser::parse(attrs_response.getAttributes());

      if (all_attributes) {
        // Merge all server-provided attributes into the secret.
        secret.attributes().merge(server_attrs);
      } else {
        if (!server_attrs.has_attribute(KMIP_ATTR_NAME_STATE)) {
          throw kmipcore::KmipException(
              "Required attribute 'State' missing from server response"
          );
        }
        // Copy only the minimal set: state (typed) + optional name (generic).
        secret.set_state(server_attrs.object_state());
        if (server_attrs.has_attribute(KMIP_ATTR_NAME_NAME)) {
          secret.set_attribute(
              KMIP_ATTR_NAME_NAME,
              std::string(server_attrs.get(KMIP_ATTR_NAME_NAME))
          );
        }
      }

      return secret;
    };

    try {
      return execute(false);
    } catch (const kmipcore::KmipException &first_error) {
      if (!version_.is_at_least(2, 0) ||
          !should_retry_get_attributes_with_legacy_v2_encoding(first_error)) {
        throw;
      }
    }
    try {
      return execute(true);
    } catch (const kmipcore::KmipException &second_error) {
      if (requested_attrs.empty() ||
          !should_retry_get_attributes_with_legacy_v2_encoding(second_error)) {
        throw;
      }
    }

    auto request = make_request_message();
    const auto get_item_id = request.add_batch_item(kmipcore::GetRequest(id));
    const auto attributes_item_id = request.add_batch_item(
        kmipcore::GetAttributesRequest(
            id, {}, request.getHeader().getProtocolVersion(), true
        )
    );
    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );
    kmipcore::ResponseParser rf(response_bytes, request);
    auto get_response =
        rf.getResponseByBatchItemId<kmipcore::GetResponseBatchItem>(
            get_item_id
        );
    Secret secret = kmipcore::KeyParser::parseGetSecretResponse(get_response);
    auto attrs_response =
        rf.getResponseByBatchItemId<kmipcore::GetAttributesResponseBatchItem>(
            attributes_item_id
        );
    kmipcore::Attributes server_attrs =
        kmipcore::AttributesParser::parse(attrs_response.getAttributes());
    if (all_attributes) {
      secret.attributes().merge(server_attrs);
    } else {
      if (!server_attrs.has_attribute(KMIP_ATTR_NAME_STATE)) {
        throw kmipcore::KmipException(
            "Required attribute 'State' missing from server response"
        );
      }
      secret.set_state(server_attrs.object_state());
      if (server_attrs.has_attribute(KMIP_ATTR_NAME_NAME)) {
        secret.set_attribute(
            KMIP_ATTR_NAME_NAME,
            std::string(server_attrs.get(KMIP_ATTR_NAME_NAME))
        );
      }
    }
    return secret;
  }

  std::string KmipClient::op_activate(const std::string &id) const {
    auto request = make_request_message();
    const auto batch_item_id =
        request.add_batch_item(kmipcore::ActivateRequest(id));

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    return rf
        .getResponseByBatchItemId<kmipcore::ActivateResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  std::vector<std::string>
      KmipClient::op_get_attribute_list(const std::string &id) const {
    auto request = make_request_message();
    const auto batch_item_id =
        request.add_batch_item(kmipcore::GetAttributeListRequest(id));

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    auto response = rf.getResponseByBatchItemId<
        kmipcore::GetAttributeListResponseBatchItem>(batch_item_id);
    return std::vector<std::string>{
        response.getAttributeNames().begin(), response.getAttributeNames().end()
    };
  }

  kmipcore::Attributes KmipClient::op_get_attributes(
      const std::string &id, const std::vector<std::string> &attr_names
  ) const {
    const auto execute = [&](const std::vector<std::string> &selectors,
                             bool legacy_attribute_names_for_v2) {
      auto request = make_request_message();
      const auto batch_item_id = request.add_batch_item(
          kmipcore::GetAttributesRequest(
              id,
              selectors,
              request.getHeader().getProtocolVersion(),
              legacy_attribute_names_for_v2
          )
      );

      std::vector<uint8_t> response_bytes;
      io->do_exchange(
          request.serialize(), response_bytes, request.getMaxResponseSize()
      );

      kmipcore::ResponseParser rf(response_bytes, request);
      auto response =
          rf.getResponseByBatchItemId<kmipcore::GetAttributesResponseBatchItem>(
              batch_item_id
          );
      return kmipcore::AttributesParser::parse(response.getAttributes());
    };

    try {
      return execute(attr_names, false);
    } catch (const kmipcore::KmipException &first_error) {
      if (!version_.is_at_least(2, 0) ||
          !should_retry_get_attributes_with_legacy_v2_encoding(first_error)) {
        throw;
      }
    }
    try {
      return execute(attr_names, true);
    } catch (const kmipcore::KmipException &second_error) {
      if (attr_names.empty() ||
          !should_retry_get_attributes_with_legacy_v2_encoding(second_error)) {
        throw;
      }
    }
    return execute({}, true);
  }

  std::vector<std::string> KmipClient::op_locate_by_name(
      const std::string &name, object_type o_type
  ) const {
    std::vector<std::string> result;
    std::size_t offset = 0;

    for (std::size_t batch = 0; batch < MAX_BATCHES_IN_SEARCH; ++batch) {
      auto request = make_request_message();
      const auto batch_item_id = request.add_batch_item(
          kmipcore::LocateRequest(
              false,
              name,
              o_type,
              MAX_ITEMS_IN_BATCH,
              offset,
              request.getHeader().getProtocolVersion()
          )
      );

      std::vector<uint8_t> response_bytes;
      io->do_exchange(
          request.serialize(), response_bytes, request.getMaxResponseSize()
      );

      kmipcore::ResponseParser rf(response_bytes, request);
      auto response =
          rf.getResponseByBatchItemId<kmipcore::LocateResponseBatchItem>(
              batch_item_id
          );
      auto got = std::vector<std::string>(
          response.getUniqueIdentifiers().begin(),
          response.getUniqueIdentifiers().end()
      );

      if (got.empty()) {
        break;
      }

      offset += got.size();
      result.insert(result.end(), got.begin(), got.end());

      if (const auto located_items =
              response.getLocatePayload().getLocatedItems();
          located_items.has_value() && *located_items >= 0 &&
          offset >= static_cast<std::size_t>(*located_items)) {
        break;
      }

      if (got.size() < MAX_ITEMS_IN_BATCH) {
        break;
      }
    }

    return result;
  }

  std::vector<std::string> KmipClient::op_locate_by_group(
      const std::string &group, object_type o_type, std::size_t max_ids
  ) const {
    if (max_ids == 0) {
      return {};
    }

    std::vector<std::string> result;
    std::size_t offset = 0;

    for (std::size_t batch = 0;
         batch < MAX_BATCHES_IN_SEARCH && result.size() < max_ids;
         ++batch) {
      const std::size_t remaining = max_ids - result.size();
      const std::size_t page_size = std::min(remaining, MAX_ITEMS_IN_BATCH);

      auto request = make_request_message();
      const auto batch_item_id = request.add_batch_item(
          kmipcore::LocateRequest(
              true,
              group,
              o_type,
              page_size,
              offset,
              request.getHeader().getProtocolVersion()
          )
      );

      std::vector<uint8_t> response_bytes;
      io->do_exchange(
          request.serialize(), response_bytes, request.getMaxResponseSize()
      );

      kmipcore::ResponseParser rf(response_bytes, request);
      auto response =
          rf.getResponseByBatchItemId<kmipcore::LocateResponseBatchItem>(
              batch_item_id
          );
      auto got = std::vector<std::string>(
          response.getUniqueIdentifiers().begin(),
          response.getUniqueIdentifiers().end()
      );

      if (got.empty()) {
        break;
      }

      offset += got.size();
      const std::size_t to_take = std::min(remaining, got.size());
      std::copy_n(got.begin(), to_take, std::back_inserter(result));

      if (const auto located_items =
              response.getLocatePayload().getLocatedItems();
          located_items.has_value() && *located_items >= 0 &&
          offset >= static_cast<std::size_t>(*located_items)) {
        break;
      }

      if (got.size() < page_size) {
        break;
      }
    }

    return result;
  }

  std::vector<std::string>
      KmipClient::op_all(object_type o_type, std::size_t max_ids) const {
    return op_locate_by_group("", o_type, max_ids);
  }

  std::vector<kmipcore::ProtocolVersion>
      KmipClient::op_discover_versions() const {
    auto request = make_request_message();

    kmipcore::RequestBatchItem item;
    item.setOperation(kmipcore::KMIP_OP_DISCOVER_VERSIONS);
    item.setRequestPayload(
        kmipcore::Element::createStructure(
            kmipcore::tag::KMIP_TAG_REQUEST_PAYLOAD
        )
    );
    const auto batch_item_id = request.add_batch_item(std::move(item));

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    auto response = rf.getResponseByBatchItemId<
        kmipcore::DiscoverVersionsResponseBatchItem>(batch_item_id);
    return std::vector<kmipcore::ProtocolVersion>{
        response.getProtocolVersions().begin(),
        response.getProtocolVersions().end()
    };
  }

  KmipClient::QueryServerInfo KmipClient::op_query() const {
    auto request = make_request_message();

    kmipcore::RequestBatchItem item;
    item.setOperation(kmipcore::KMIP_OP_QUERY);

    // Create request payload with query functions
    // Request: Query Operations, Query Objects, and Query Server Information
    auto payload = kmipcore::Element::createStructure(
        kmipcore::tag::KMIP_TAG_REQUEST_PAYLOAD
    );

    // Add Query Function items for: Operations, Objects, and Server Information
    auto query_ops_elem = kmipcore::Element::createEnumeration(
        kmipcore::tag::KMIP_TAG_QUERY_FUNCTION,
        static_cast<int32_t>(kmipcore::KMIP_QUERY_OPERATIONS)
    );
    payload->asStructure()->add(query_ops_elem);

    auto query_objs_elem = kmipcore::Element::createEnumeration(
        kmipcore::tag::KMIP_TAG_QUERY_FUNCTION,
        static_cast<int32_t>(kmipcore::KMIP_QUERY_OBJECTS)
    );
    payload->asStructure()->add(query_objs_elem);

    auto query_info_elem = kmipcore::Element::createEnumeration(
        kmipcore::tag::KMIP_TAG_QUERY_FUNCTION,
        static_cast<int32_t>(kmipcore::KMIP_QUERY_SERVER_INFORMATION)
    );
    payload->asStructure()->add(query_info_elem);

    item.setRequestPayload(payload);
    const auto batch_item_id = request.add_batch_item(std::move(item));

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    const auto response =
        rf.getResponseByBatchItemId<kmipcore::QueryResponseBatchItem>(
            batch_item_id
        );

    QueryServerInfo result;
    result.supported_operations.reserve(response.getOperations().size());
    for (const auto op : response.getOperations()) {
      result.supported_operations.push_back(
          static_cast<kmipcore::operation>(op)
      );
    }
    result.supported_object_types.reserve(response.getObjectTypes().size());
    for (const auto type : response.getObjectTypes()) {
      result.supported_object_types.push_back(
          static_cast<kmipcore::object_type>(type)
      );
    }
    result.vendor_name = response.getVendorIdentification();
    result.server_name = response.getServerName();
    result.product_name = response.getProductName();
    result.server_version = response.getServerVersion();
    result.build_level = response.getBuildLevel();
    result.build_date = response.getBuildDate();
    result.server_serial_number = response.getServerSerialNumber();
    result.server_load = response.getServerLoad();
    result.cluster_info = response.getClusterInfo();
    return result;
  }

  std::string KmipClient::op_revoke(
      const std::string &id,
      revocation_reason_type reason,
      const std::string &message,
      time_t occurrence_time
  ) const {
    auto request = make_request_message();
    const auto batch_item_id = request.add_batch_item(
        kmipcore::RevokeRequest(id, reason, message, occurrence_time)
    );

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    return rf
        .getResponseByBatchItemId<kmipcore::RevokeResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

  std::string KmipClient::op_destroy(const std::string &id) const {
    auto request = make_request_message();
    const auto batch_item_id =
        request.add_batch_item(kmipcore::DestroyRequest(id));

    std::vector<uint8_t> response_bytes;
    io->do_exchange(
        request.serialize(), response_bytes, request.getMaxResponseSize()
    );

    kmipcore::ResponseParser rf(response_bytes, request);
    return rf
        .getResponseByBatchItemId<kmipcore::DestroyResponseBatchItem>(
            batch_item_id
        )
        .getUniqueIdentifier();
  }

}  // namespace kmipclient
