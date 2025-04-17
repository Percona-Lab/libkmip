//
// Created by al on 21.03.25.
//

#ifndef REQUESTFACTORY_HPP
#define REQUESTFACTORY_HPP

#include "KmipCtx.hpp"
#include "KmipRequest.hpp"
#include "include/Key.hpp"
#include "include/kmip_data_types.hpp"

namespace kmipclient
{

class RequestFactory
{
public:
  explicit RequestFactory (KmipCtx &ctx) : rq (ctx) {};
  /**
   * Created and encodes into ctx a GET request
   * @param ctx KMIP context
   * @param id Id of entity to get
   */
  void create_get_rq (const id_t &id);
  void create_activate_rq (const id_t &id);
  void create_create_aes_rq (const name_t &name, const name_t &group);
  void create_register_key_rq (const name_t &name, const name_t &group, Key &k);
  void create_register_secret_rq (const name_t &name, const name_t &group, std::string &secret, int secret_data_type);
  void create_revoke_rq (const id_t &id, int reason, const name_t &message, time_t occurrence_time);
  void create_destroy_rq (const id_t &id);
  void create_get_attribute_rq (const id_t &id, const std::string &attr_name);
  void create_locate_by_name_rq (const name_t &name, kmip_entity_type type, int max_items, int offset);
  void create_locate_by_group_rq (const name_t &group_name, kmip_entity_type type, int max_items, size_t offset);
  void create_locate_all_rq (kmip_entity_type type, int max_items, int offset);

private:
  void create_locate_rq (bool is_group, const name_t &name, kmip_entity_type type, int max_items, size_t offset);
  static enum object_type from_entity_type (enum kmip_entity_type t);
  KmipRequest             rq;
};

} // namespace

#endif // REQUESTFACTORY_HPP
