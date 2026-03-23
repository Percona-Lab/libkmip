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
#ifndef KMIP_CLIENT_HPP
#define KMIP_CLIENT_HPP

#include "kmipclient/Key.hpp"
#include "kmipclient/NetClient.hpp"
#include "kmipclient/types.hpp"
#include "kmipcore/kmip_attributes.hpp"
#include "kmipcore/kmip_logger.hpp"
#include "kmipcore/kmip_protocol.hpp"

#include <ctime>
#include <memory>
#include <string>
#include <vector>

namespace kmipclient {

  /** Maximum number of KMIP locate response batches processed by search
   * helpers. */
  constexpr size_t MAX_BATCHES_IN_SEARCH = 64;
  /** Maximum number of response items expected per single KMIP batch. */
  constexpr size_t MAX_ITEMS_IN_BATCH = 1024;

  class IOUtils;
  /**
   * @brief High-level KMIP client API for key and secret lifecycle operations.
   *
   * The instance uses an already configured and connected @ref NetClient
   * transport and provides typed wrappers around common KMIP operations.
   */
  class KmipClient {
  public:
    /**
     * @brief Creates a client bound to an existing transport.
     * @param net_client Pre-initialized network transport implementation.
     * @param logger Optional KMIP protocol logger. When set, serialized TTLV
     * request and response payloads are logged at DEBUG level.
     * @param version KMIP protocol version to use for requests.
     * @param close_on_destroy When true, closes the transport on client
     *        destruction. Defaults to false for this non-owning overload.
     */
    explicit KmipClient(
        NetClient &net_client,
        const std::shared_ptr<kmipcore::Logger> &logger = {},
        kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4,
        bool close_on_destroy = false
    );

    /**
     * @brief Creates a client that shares ownership of the transport.
     *
     * This overload helps migration from pointer-centric wrappers: callers can
     * keep and pass `std::shared_ptr<KmipClient>`/`std::shared_ptr<NetClient>`
     * handles instead of owning client objects by value.
     *
     * @param net_client Shared transport; must not be null.
     * @param logger Optional KMIP protocol logger.
     * @param version KMIP protocol version to use for requests.
     * @param close_on_destroy When true (default), closes the transport on
     *        client destruction. Set to false to keep transport alive after
     *        client destruction.
     * @throws std::invalid_argument when @p net_client is null.
     */
    explicit KmipClient(
        std::shared_ptr<NetClient> net_client,
        const std::shared_ptr<kmipcore::Logger> &logger = {},
        kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4,
        bool close_on_destroy = true
    );

    /**
     * @brief Convenience factory for reference-based integrations.
     *
     * Defaults to non-owning close behavior (`close_on_destroy=false`) to
     * mirror the `NetClient&` constructor.
     */
    [[nodiscard]] static std::shared_ptr<KmipClient> create_shared(
        NetClient &net_client,
        const std::shared_ptr<kmipcore::Logger> &logger = {},
        kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4,
        bool close_on_destroy = false
    );

    /**
     * @brief Convenience factory that keeps transport ownership shared.
     */
    [[nodiscard]] static std::shared_ptr<KmipClient> create_shared(
        std::shared_ptr<NetClient> net_client,
        const std::shared_ptr<kmipcore::Logger> &logger = {},
        kmipcore::ProtocolVersion version = kmipcore::KMIP_VERSION_1_4,
        bool close_on_destroy = true
    );

    /** @brief Destroys the client and internal helpers. */
    ~KmipClient();
    // non-copyable, move-only
    KmipClient(const KmipClient &) = delete;
    KmipClient &operator=(const KmipClient &) = delete;
    KmipClient(KmipClient &&other) noexcept;
    KmipClient &operator=(KmipClient &&other) noexcept;

    /**
     * @brief Executes KMIP Register for a key object.
     * @param name Value of the KMIP "Name" attribute.
     * @param group Value of the KMIP "Object Group" attribute.
     * @param k Key material and metadata to register.
     * @return Unique identifier assigned by the KMIP server.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::string op_register_key(
        const std::string &name, const std::string &group, const Key &k
    ) const;

    /**
     * @brief Executes KMIP Register for Secret Data.
     * @param name Value of the KMIP "Name" attribute.
     * @param group Value of the KMIP "Object Group" attribute.
     * @param secret Secret payload and type descriptor.
     * @return Unique identifier assigned by the KMIP server.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::string op_register_secret(
        const std::string &name, const std::string &group, const Secret &secret
    ) const;


    /**
     * @brief Executes KMIP Create to generate a server-side AES key.
     * @param name Value of the KMIP "Name" attribute.
     * @param group Value of the KMIP "Object Group" attribute.
     * @param key_size AES key size (typed constants: AES_128/AES_192/AES_256).
     * @param usage_mask Cryptographic Usage Mask bits to assign to the key.
     * @return Unique identifier of the created key.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::string op_create_aes_key(
        const std::string &name,
        const std::string &group,
        aes_key_size key_size = aes_key_size::AES_256,
        cryptographic_usage_mask usage_mask =
            static_cast<cryptographic_usage_mask>(
                kmipcore::KMIP_CRYPTOMASK_ENCRYPT |
                kmipcore::KMIP_CRYPTOMASK_DECRYPT
            )
    ) const;

    /**
     * @brief Executes KMIP Get and decodes a key object.
     * @param id Unique identifier of the key object.
     * @param all_attributes When true, fetches all available attributes.
     * @return Decoded key object.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::unique_ptr<Key>
        op_get_key(const std::string &id, bool all_attributes = false) const;

    /**
     * @brief Executes KMIP Get and decodes a secret object.
     * @param id Unique identifier of the secret object.
     * @param all_attributes When true, fetches all available attributes.
     * @return Decoded secret object.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] Secret
        op_get_secret(const std::string &id, bool all_attributes = false) const;

    /**
     * @brief Executes KMIP Activate for a managed object.
     * @param id Unique identifier of the object to activate.
     * @return Identifier returned by the server (normally equals @p id).
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::string op_activate(const std::string &id) const;

    /**
     * @brief Executes KMIP Get Attribute List.
     * @param id Unique identifier of the target object.
     * @return List of attribute names available for the object.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::vector<std::string>
        op_get_attribute_list(const std::string &id) const;

    /**
     * @brief Executes KMIP Get Attributes for selected attribute names.
     * @param id Unique identifier of the target object.
     * @param attr_names Attribute names to fetch (for example "Name", "State").
     * @return Type-safe @ref Attributes bag with the requested attributes.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] kmipcore::Attributes op_get_attributes(
        const std::string &id, const std::vector<std::string> &attr_names
    ) const;

    /**
     * @brief Executes KMIP Locate using an exact object name filter.
     * @param name Object name to match.
     * @param o_type KMIP object type to search.
     * @return Matching object identifiers; may contain multiple IDs.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::vector<std::string>
        op_locate_by_name(const std::string &name, object_type o_type) const;


    /**
     * @brief Executes KMIP Locate using the object group filter.
     * @param group Group name to match.
     * @param o_type KMIP object type to search.
     * @param max_ids Upper bound on collected IDs across locate batches.
     * @return Matching object identifiers, up to @p max_ids entries.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::vector<std::string> op_locate_by_group(
        const std::string &group,
        object_type o_type,
        std::size_t max_ids = MAX_BATCHES_IN_SEARCH * MAX_ITEMS_IN_BATCH
    ) const;


    /**
     * @brief Executes KMIP Revoke for a managed object.
     * @param id Unique identifier of the object to revoke.
     * @param reason KMIP revocation reason code.
     * @param message Optional human-readable revocation message.
     * @param occurrence_time Incident time for reasons that require it; use 0
     * for regular deactivation flows.
     * @return Identifier returned by the server (normally equals @p id).
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::string op_revoke(
        const std::string &id,
        revocation_reason_type reason,
        const std::string &message,
        time_t occurrence_time
    ) const;
    /**
     * @brief Executes KMIP Destroy for a managed object.
     * @param id Unique identifier of the object to destroy.
     * @return Identifier returned by the server (normally equals @p id).
     * @throws kmipcore::KmipException on protocol or server-side failure.
     * @note Most KMIP servers require the object to be revoked first.
     */
    [[nodiscard]] std::string op_destroy(const std::string &id) const;

    /**
     * @brief Executes KMIP Locate without name/group filters.
     * @param o_type KMIP object type to fetch.
     * @param max_ids Upper bound on collected IDs across locate batches.
     * @return Identifiers of matching objects, up to @p max_ids entries.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::vector<std::string> op_all(
        object_type o_type,
        std::size_t max_ids = MAX_BATCHES_IN_SEARCH * MAX_ITEMS_IN_BATCH
    ) const;


    /**
     * @brief Executes KMIP Discover Versions to query supported protocol
     * versions.
     *
     * @return Ordered list of KMIP protocol versions supported by the server.
     *         An empty list means the server returned no version information.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    [[nodiscard]] std::vector<kmipcore::ProtocolVersion>
        op_discover_versions() const;

    /**
     * @brief Executes KMIP Query to get server information and capabilities.
     *
     * Queries the server for its capabilities and vendor-specific information.
     * Returns supported operations, object types, and server metadata.
     *
     * @return Structure containing server information and capabilities.
     * @throws kmipcore::KmipException on protocol or server-side failure.
     */
    struct QueryServerInfo {
      std::vector<kmipcore::operation>
          supported_operations;  ///< Operations supported by server
      std::vector<kmipcore::object_type>
          supported_object_types;        ///< Object types supported by server
      std::string server_name;           ///< Human-readable server name
      std::string vendor_name;           ///< Vendor identification string
      std::string product_name;          ///< Product name
      std::string server_version;        ///< Server version string
      std::string build_level;           ///< Build level
      std::string build_date;            ///< Build date
      std::string server_serial_number;  ///< Server serial number
      std::string server_load;           ///< Current server load
      std::string cluster_info;          ///< Cluster information
    };

    [[nodiscard]] QueryServerInfo op_query() const;

    /** @brief Returns the configured KMIP protocol version. */
    [[nodiscard]] const kmipcore::ProtocolVersion &
        protocol_version() const noexcept {
      return version_;
    }

    /** @brief Replaces the configured KMIP protocol version for subsequent
     * requests. */
    void set_protocol_version(kmipcore::ProtocolVersion version) noexcept {
      version_ = version;
    }

    /**
     * @brief Queries the close_on_destroy setting.
     * @return true if the transport will be closed on destruction, false otherwise.
     */
    [[nodiscard]] bool close_on_destroy() const noexcept {
      return close_on_destroy_;
    }


  private:
    NetClient *net_client = nullptr;
    std::shared_ptr<NetClient> net_client_owner_;
    std::unique_ptr<IOUtils> io;
    kmipcore::ProtocolVersion version_;
    bool close_on_destroy_ = true;

    [[nodiscard]] kmipcore::RequestMessage make_request_message() const {
      return kmipcore::RequestMessage(version_);
    }
  };

}  // namespace kmipclient
#endif  // KMIP_CLIENT_HPP
