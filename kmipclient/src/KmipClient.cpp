//
// Created by al on 10.03.25.
//
#include "include/KmipClient.hpp"

#include "IOUtils.hpp"
#include "KmipCtx.hpp"
#include "RequestFactory.hpp"
#include "ResponseFactory.hpp"
#include "kmip_exceptions.hpp"

namespace kmipclient
{

#define MAX_ITEMS_IN_SEARCH 16

KmipClient::KmipClient (NetClient &net_client) : net_client (net_client)
{
  io = std::make_unique<IOUtils> (net_client);
};

KmipClient::KmipClient (NetClient &net_client, const std::shared_ptr<Logger> &log) : net_client (net_client)
{
  io     = std::make_unique<IOUtils> (net_client);
  logger = log;
}

KmipClient::~KmipClient () { net_client.close (); };

ve::expected<id_t, Error>
KmipClient::op_register_key (const name_t &name, const name_t &group, Key &k) const
{
  KmipCtx         ctx;
  RequestFactory  request_factory (ctx);
  ResponseFactory rf (ctx);
  try
    {
      request_factory.create_register_key_rq (name, group, k);
      io->do_exchange (ctx);
      return rf.get_id (0);
    }
  catch (ErrorException &e)
    {
      return Error (e.code (), e.what ());
    }
}

ve::expected<id_t, Error>
KmipClient::op_register_secret (const name_t &name, const name_t &group, std::string secret,
                                enum kmip_secret_type secret_type) const
{
  KmipCtx         ctx;
  RequestFactory  request_factory (ctx);
  ResponseFactory rf (ctx);
  try
    {
      request_factory.create_register_secret_rq (name, group, secret, secret_type);
      io->do_exchange (ctx);
      return rf.get_id (0);
    }
  catch (ErrorException &e)
    {
      return Error (e.code (), e.what ());
    }
}

ve::expected<id_t, Error>
KmipClient::op_create_aes_key (const name_t &name, const name_t &group) const
{
  KmipCtx         ctx;
  RequestFactory  request_factory (ctx);
  ResponseFactory rf (ctx);
  try
    {
      request_factory.create_create_aes_rq (name, group);
      io->do_exchange (ctx);
      return rf.get_id (0);
    }
  catch (ErrorException &e)
    {
      return Error (e.code (), e.what ());
    }
}

ve::expected<Key, Error>
KmipClient::op_get_key (const id_t &id) const
{
  KmipCtx         ctx;
  RequestFactory  request_factory (ctx);
  ResponseFactory rf (ctx);
  try
    {
      request_factory.create_get_rq (id);
      io->do_exchange (ctx);
      return rf.get_key (0);
    }
  catch (ErrorException &e)
    {
      return Error (e.code (), e.what ());
    }
}

ve::expected<Secret, Error>
KmipClient::op_get_secret (const id_t &id) const
{
  KmipCtx         ctx;
  RequestFactory  request_factory (ctx);
  ResponseFactory rf (ctx);
  try
    {
      request_factory.create_get_rq (id);
      io->do_exchange (ctx);
      return rf.get_secret (0);
    }
  catch (ErrorException &e)
    {
      return Error (e.code (), e.what ());
    }
}

ve::expected<id_t, Error>
KmipClient::op_activate (const id_t &id) const
{
  KmipCtx         ctx;
  RequestFactory  request_factory (ctx);
  ResponseFactory rf (ctx);
  try
    {
      request_factory.create_activate_rq (id);
      io->do_exchange (ctx);
      return rf.get_id (0);
    }
  catch (ErrorException &e)
    {
      return Error (e.code (), e.what ());
    }
}

expected<name_t, Error>
KmipClient::op_get_attribute (const id_t &id, const name_t &attr_name) const
{
  KmipCtx         ctx;
  RequestFactory  request_factory (ctx);
  ResponseFactory rf (ctx);
  try
    {
      request_factory.create_get_attribute_rq (id, attr_name);
      io->do_exchange (ctx);
      return rf.get_attributes (0);
    }
  catch (ErrorException &e)
    {
      return Error (e.code (), e.what ());
    }
}

ve::expected<ids_t, Error>
KmipClient::op_locate_by_name (const name_t &name, kmip_entity_type type) const
{
  KmipCtx         ctx;
  RequestFactory  request_factory (ctx);
  ResponseFactory rf (ctx);
  try
    {
      // actually, with Vault server there should be only one item with the name
      request_factory.create_locate_by_name_rq (name, type, MAX_ITEMS_IN_SEARCH, 0);
      io->do_exchange (ctx);
      return rf.get_ids (0);
    }
  catch (ErrorException &e)
    {
      return Error (e.code (), e.what ());
    }
}

expected<ids_t, Error>
KmipClient::op_locate_by_group (const name_t &group, kmip_entity_type type) const
{

  KmipCtx         ctx;
  RequestFactory  request_factory (ctx);
  ResponseFactory rf (ctx);
  ids_t           result;
  try
    {
      size_t received = 0;
      size_t offset   = 0;
      do
        {
          request_factory.create_locate_by_group_rq (group, type, MAX_ITEMS_IN_SEARCH, offset);
          io->do_exchange (ctx);
          auto exp = rf.get_ids (0);
          if (exp.has_error ())
            {
              return exp.error ();
            }

          if (ids_t got = exp.value (); !got.empty ())
            {
              received = got.size ();
              offset += got.size ();
              result.insert (result.end (), got.begin (), got.end ());
            }
          else
            {
              break;
            }
        }
      while (received == MAX_ITEMS_IN_SEARCH);
    }
  catch (ErrorException &e)
    {
      return Error (e.code (), e.what ());
    }
  return result;
}

ve::expected<ids_t, Error>
KmipClient::op_all (kmip_entity_type type) const
{

  KmipCtx         ctx;
  RequestFactory  request_factory (ctx);
  ResponseFactory rf (ctx);
  ids_t           result;
  try
    {
      size_t received = 0;
      size_t offset   = 0;
      do
        {
          request_factory.create_locate_all_rq (type, MAX_ITEMS_IN_SEARCH, 0);
          io->do_exchange (ctx);
          auto exp = rf.get_ids (0);
          if (exp.has_error ())
            {
              return exp.error ();
            }
          if (ids_t got = exp.value (); !got.empty ())
            {
              received = got.size ();
              offset += got.size ();
              result.insert (result.end (), got.begin (), got.end ());
            }
          else
            {
              break;
            }
        }
      while (received == MAX_ITEMS_IN_SEARCH);
    }
  catch (ErrorException &e)
    {
      return Error (e.code (), e.what ());
    }
  return result;
}

ve::expected<id_t, Error>
KmipClient::op_revoke (const id_t &id, enum kmip_revocation_reason reason, const name_t &message, time_t occurrence_time) const
{
  KmipCtx         ctx;
  RequestFactory  request_factory (ctx);
  ResponseFactory rf (ctx);
  try
    {
      request_factory.create_revoke_rq (id, reason, message, occurrence_time);
      io->do_exchange (ctx);
      return rf.get_id (0);
    }
  catch (ErrorException &e)
    {
      return Error (e.code (), e.what ());
    }
}

ve::expected<id_t, Error>
KmipClient::op_destroy (const id_t &id) const
{
  KmipCtx         ctx;
  RequestFactory  request_factory (ctx);
  ResponseFactory rf (ctx);
  try
    {
      request_factory.create_get_rq (id);
      io->do_exchange (ctx);
      return rf.get_id (0);
    }
  catch (ErrorException &e)
    {
      return Error (e.code (), e.what ());
    }
}

}
