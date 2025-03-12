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

#include <memory>

#include "Key.hpp"
#include "Logger.hpp"
#include "NetClient.hpp"
#include "kmip_data_types.hpp"

namespace kmipclient
{

constexpr size_t MAX_BATCHES_IN_SEARCH = 16;
constexpr size_t MAX_ITEMS_IN_BATCH  = 1024;

class IOUtils;
/**
 * A client that communicates with a KMIP-compliant server to perform cryptographic operations
 * such as key management, secret management, and cryptographic operations.
 */
class KmipClient
{
public:
  /**
   * Creates instance of KmipClient without logger
   * @param net_client pre-initialized instance of NetClient interface
   */
  explicit KmipClient (NetClient &net_client);
  /**
   * Creates instance of KmipClient with logger
   * @param net_client pre-initialized instance of NetClient interface
   * @param log initialized instance of Logger interface
   */
  explicit KmipClient (NetClient &net_client, const std::shared_ptr<Logger> &log);
  ~KmipClient ();
  // no copy, no move
  KmipClient (const KmipClient &)            = delete;
  KmipClient &operator= (const KmipClient &) = delete;
  KmipClient (KmipClient &&)                 = delete;
  KmipClient &operator= (KmipClient &&)      = delete;

  /**
   * KMIP register operation, stores a proposed key on the server
   * @param name The "Name" attribute of the key
   * @param group The group name for the key
   * @param k The key to register
   * @return ID of the key if success or throws ErrorException
   */
  [[nodiscard]] id_t op_register_key (const name_t &name, const name_t &group, const Key &k) const;

  /**
   *
   * @param name The "Name" attribute of the secret
   * @param group The group name for the secret
   * @param secret The secret to register
   * @param secret_type Type of the secret, @see
   * @return ID of the key if success or throws ErrorException
   */
  [[nodiscard]] id_t op_register_secret (const name_t &name, const name_t &group, std::string_view secret,
                                         enum secret_data_type secret_type) const;

  /** KMIP::create operation, generates a new AES-256 symmetric key on the server
   * @param name name attribute of the key
   * @param group group attribute of the key
   * @return ID of the created key or throws ErrorException
   */
  [[nodiscard]] id_t op_create_aes_key (const name_t &name, const name_t &group) const;

  /**
   * Gets key by ID
   * @param id id of the Key
   * @return The Key or throws ErrorException
   */
  [[nodiscard]] Key op_get_key (const id_t &id) const;

  /**
   * Gets secret by the ID
   * @param id ID of the secret
   * @return The secret or throws ErrorException
   */
  [[nodiscard]] Secret op_get_secret (const id_t &id) const;

  /**
   * Changes key/secret state from pre-active to active.
   * @param id ID of the entity
   * @return ID of the entity or throws ErrorException
   */
  [[nodiscard]] id_t op_activate (const id_t &id) const;

  /** KMIP::get_attributes operation, retrieve the names of a symmetric key by id
   * @paran id ID of the entity
   * @return value of the attribute or throws ErrorException
   */
  [[nodiscard]] names_t op_get_attribute_list (const id_t &id) const;

  /** KMIP::get_attribute operation, retrieve the attribute of an entity with id by attribute names name
   * @param id ID of the entity
   * @param attr_names names of the attribute in a vector, e.g. "Name", "State", "Object Group"
   * @return value of the attribute or throws ErrorException
   */
  [[nodiscard]] attributes_t op_get_attributes (const id_t &id, const std::vector<name_t> &attr_names) const;

  /** KMIP::locate operation, retrieve symmetric keys by name
   * Note: HasiCorp Vault does not allow name duplication
   * @param name name of the entity
   * @param o_type type of the entity to retrieve
   * @return In general case, one ID. Some KMIP servers allow multiple IDs with the same name, so there will be multiple
   * IDs. If there are no entities with such a name, an empty vector is returned.
   */
  [[nodiscard]] ids_t op_locate_by_name (const name_t &name, enum object_type o_type) const;

  /**
   * Gets IDs of entities by the group name
   * @param group group name
   * @param o_type type of the entity to retrieve
   * @param max_ids maximum number of IDs to retrieve, default is MAX_BATCHES_IN_SEARCH * MAX_ITEMS_IN_BATCH
   * @return vector of key IDs
   */
  [[nodiscard]] ids_t op_locate_by_group (const name_t &group, enum object_type o_type, size_t max_ids = MAX_BATCHES_IN_SEARCH * MAX_ITEMS_IN_BATCH) const;

  /**
   * Revokes/deactivates a key or another entity
   * @param id ID of the entity
   * @param reason the reason to revoke
   * @param message Message of revocation to be saved in the server side
   * @param occurrence_time time of the incident, 0 for the key deactivation
   * @return ID of the empty string on error
   */
  [[nodiscard]] id_t op_revoke (const id_t &id, enum revocation_reason_type reason, const name_t &message,
                                time_t occurrence_time) const;
  /**
   * Destroys an entity by ID
   * NOTE: Entity should be revoked/deactivated
   * @param id ID of the entity
   * @return ID of the entity or empty string on error
   */
  [[nodiscard]] id_t op_destroy (const id_t &id) const;

  /**
   * KMIP::locate operation, retrieve all symmetric keys
   * note: name can be empty, and will retrieve all keys
   * @param o_type type of the entity to fetch
   * @param max_ids maximum number of IDs to retrieve, default is MAX_BATCHES_IN_SEARCH * MAX_ITEMS_IN_BATCH
   * @return vector of IDs of entities
   */
  [[nodiscard]] ids_t op_all (enum object_type o_type, size_t max_ids = MAX_BATCHES_IN_SEARCH * MAX_ITEMS_IN_BATCH ) const;

private:
  NetClient               &net_client;
  std::shared_ptr<Logger>  logger = nullptr;
  std::unique_ptr<IOUtils> io;
};

}
#endif // KMIP_CLIENT_HPP
