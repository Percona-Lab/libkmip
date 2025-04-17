//
// Created by al on 10.03.25.
//

#ifndef KMIP_CLIENT_HPP
#define KMIP_CLIENT_HPP

#include "../src/RequestFactory.hpp"
#include "Key.hpp"
#include "Logger.hpp"
#include "NetClient.hpp"
#include "kmip_data_types.hpp"
#include "v_expected.hpp"

#include <memory>

namespace kmipclient
{

using namespace ve; // std::expected in C++ 23 or ve::expected in earlier versions

class IOUtils;

class KmipClient
{
public:
  explicit KmipClient (NetClient &net_client);
  explicit KmipClient (NetClient &net_client, const std::shared_ptr<Logger> &log);
  ~KmipClient ();
  // no copy, no move
  KmipClient (const KmipClient &)            = delete;
  KmipClient &operator= (const KmipClient &) = delete;
  KmipClient (KmipClient &&)                 = delete;
  KmipClient &operator= (KmipClient &&)      = delete;

  /**
   * KMIP register operation, stores an proposed key on the server
   * @param name The "Name" attribute of the key
   * @param group The group name for the key
   * @param k The key to register
   * @return ID of the key if success or error
   */
  [[nodiscard]] expected<id_t, Error> op_register_key (const name_t &name, const name_t &group, Key &k) const;

  /**
   *
   * @param name The "Name" attribute of the secret
   * @param group The group name for the secret
   * @param secret The secret to register
   * @param secret_type Type of the secret, @see
   * @return ID of the key if success or error
   */
  [[nodiscard]] expected<id_t, Error> op_register_secret (const name_t &name, const name_t &group, std::string secret,
                                                          enum kmip_secret_type secret_type) const;

  /** KMIP::create operation, generates a new AES-256 symmetric key on the server
   * @param name name attribute of the key
   * @param group group attribute of the key
   * @return ID of the created ley
   */
  [[nodiscard]] expected<id_t, Error> op_create_aes_key (const name_t &name, const name_t &group) const;

  /**
   * Gets key by ID
   * @param id ?Id of the Key
   * @return The Key or Error
   */
  [[nodiscard]] expected<Key, Error>  op_get_key (const id_t &id) const;

  /**
   * Gets secret by the ID
   * @param id ID of the secret
   * @return The secret or Error
   */
  [[nodiscard]] expected<Secret, Error> op_get_secret (const id_t &id) const;

  /**
   * Changes key/secret state from pre-active to active.
   * @param id ID of the entity
   * @return ID of the entity or Error
   */
  [[nodiscard]] expected<id_t, Error>   op_activate (const id_t &id) const;

  /** KMIP::get_attribute operation, retrieve the name of a symmetric key by id
   * @paran id ID of the entity
   * @param attr_name name of the attribute, e.g. "Name", "State"
   * @return value of the attribute or error
   */
  [[nodiscard]] expected<name_t, Error> op_get_attribute (const id_t &id, const name_t &attr_name) const;

  /** KMIP::locate operation, retrieve symmetric keys by name
   * Note: HasiCorp Vault does not allow name duplication
   * @param name name of the entity
   * @param type type of the entity to retrieve
   */
  [[nodiscard]] expected<ids_t, Error> op_locate_by_name (const name_t &name, kmip_entity_type type) const;

  /**
   * Gets IDs of entities by the group name
   * @param group group name
   * @return vector of key IDs or Error
   */
  [[nodiscard]] expected<ids_t, Error> op_locate_by_group (const name_t &group, kmip_entity_type type) const;

  /**
   * Revokes/deactivates key or other entity
   * @param id ID of the entity
   * @param reason the reason to revoke
   * @param message Message of revocation to be saved in the server side
   * @param occurrence_time time of the incident, 0 for the key deactivation
   * @return ID of the entity or error
   */
  [[nodiscard]] expected<id_t, Error> op_revoke (const id_t &id, enum kmip_revocation_reason reason, const name_t &message,
                                                 time_t occurrence_time) const;
  /**
   * Destroys an entity by ID
   * NOTE: Entity should be revoked/deactivated
   * @param id ID of the entity
   * @return ID of the entity or error
   */
  [[nodiscard]] expected<id_t, Error> op_destroy (const id_t &id) const;

  /**
   * KMIP::locate operation, retrieve all symmetric keys
   * note: name can be empty, and will retrieve all keys
   * @param type type of the entity to fetch
   * @return vector of IDs of entities
   */
  [[nodiscard]] expected<ids_t, Error> op_all (kmip_entity_type type) const;

private:
  NetClient               &net_client;
  std::shared_ptr<Logger>  logger;
  std::unique_ptr<IOUtils> io;
};

}
#endif // KMIP_CLIENT_HPP
