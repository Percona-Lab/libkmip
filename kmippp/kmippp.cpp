
#include "kmippp.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include <stdexcept>

#include "core_error.hpp"
#include "kmip.h"
#include "kmip_bio.h"
#include "kmip_locate.h"

namespace kmippp
{

context::context (std::string server_address, std::string server_port, std::string client_cert_fn,
                  std::string client_key_fn, std::string ca_cert_fn)
{
  ctx_ = SSL_CTX_new (SSLv23_method ());

  if (SSL_CTX_use_certificate_file (ctx_, client_cert_fn.c_str (), SSL_FILETYPE_PEM) != 1)
    {
      SSL_CTX_free (ctx_);
      core_error::raise_with_error_string ("Loading the client certificate failed");
    }
  if (SSL_CTX_use_PrivateKey_file (ctx_, client_key_fn.c_str (), SSL_FILETYPE_PEM) != 1)
    {
      SSL_CTX_free (ctx_);
      core_error::raise_with_error_string ("Loading the client key failed");
    }
  if (SSL_CTX_load_verify_locations (ctx_, ca_cert_fn.c_str (), nullptr) != 1)
    {
      SSL_CTX_free (ctx_);
      core_error::raise_with_error_string ("Loading the CA certificate failed");
    }

  bio_ = BIO_new_ssl_connect (ctx_);
  if (bio_ == nullptr)
    {
      SSL_CTX_free (ctx_);
      core_error::raise_with_error_string ("BIO_new_ssl_connect failed");
    }

  SSL *ssl = nullptr;
  BIO_get_ssl (bio_, &ssl);
  SSL_set_mode (ssl, SSL_MODE_AUTO_RETRY);
  BIO_set_conn_hostname (bio_, server_address.c_str ());
  BIO_set_conn_port (bio_, server_port.c_str ());
  if (BIO_do_connect (bio_) != 1)
    {
      BIO_free_all (bio_);
      SSL_CTX_free (ctx_);
      core_error::raise_with_error_string ("BIO_do_connect failed");
    }
}

context::~context ()
{
  BIO_free_all (bio_);
  SSL_CTX_free (ctx_);
}

context::id_t
context::op_create (context::name_t name, context::name_t group)
{
  Attribute a[5];
  for (int i = 0; i < 5; i++)
    {
      kmip_init_attribute (&a[i]);
    }

  enum cryptographic_algorithm algorithm = KMIP_CRYPTOALG_AES;
  a[0].type                              = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
  a[0].value                             = &algorithm;

  int32 length = 256;
  a[1].type    = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
  a[1].value   = &length;

  int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
  a[2].type  = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
  a[2].value = &mask;

  Name       ts;
  TextString ts2 = { 0, 0 };
  ts2.value      = const_cast<char *> (name.c_str ());
  ts2.size       = kmip_strnlen_s (ts2.value, 250);
  ts.value       = &ts2;
  ts.type        = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
  a[3].type      = KMIP_ATTR_NAME;
  a[3].value     = &ts;

  TextString gs2 = { 0, 0 };
  gs2.value      = const_cast<char *> (group.c_str ());
  gs2.size       = kmip_strnlen_s (gs2.value, 250);
  a[4].type      = KMIP_ATTR_OBJECT_GROUP;
  a[4].value     = &gs2;

  TemplateAttribute ta = { 0 };
  ta.attributes        = a;
  ta.attribute_count   = ARRAY_LENGTH (a);

  int   id_max_len = 64;
  char *idp        = nullptr;
  int   result     = kmip_bio_create_symmetric_key (bio_, &ta, &idp, &id_max_len);

  std::string ret;
  if (idp != nullptr)
    {
      ret = std::string (idp, id_max_len);
      free (idp);
    }

  if (result != 0)
    {
      return "";
    }

  return ret;
}

context::id_t
context::op_register (context::name_t name, name_t group, key_t key)
{
  int attr_count;

  group.empty()? attr_count = 4 : attr_count = 5;

  Attribute a[attr_count];
  for (int i = 0; i < attr_count; i++)
    {
      kmip_init_attribute (&a[i]);
    }

  enum cryptographic_algorithm algorithm = KMIP_CRYPTOALG_AES;
  a[0].type                              = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
  a[0].value                             = &algorithm;

  int32 length = key.size() * 8;
  a[1].type    = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
  a[1].value   = &length;

  int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
  a[2].type  = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
  a[2].value = &mask;

  Name       ts;
  TextString ts2 = { 0, 0 };
  ts2.value      = const_cast<char *> (name.c_str ());
  ts2.size       = kmip_strnlen_s (ts2.value, 250);
  ts.value       = &ts2;
  ts.type        = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
  a[3].type      = KMIP_ATTR_NAME;
  a[3].value     = &ts;

  if (attr_count == 5)
   {
     TextString gs2 = { 0, 0 };
     gs2.value      = const_cast<char *> (group.c_str ());
     gs2.size       = kmip_strnlen_s (gs2.value, 250);
     a[4].type      = KMIP_ATTR_OBJECT_GROUP;
     a[4].value     = &gs2;
   }

  TemplateAttribute ta = { 0 };
  ta.attributes        = a;
  ta.attribute_count   = attr_count;

  int   id_max_len = 64;
  char *idp        = nullptr;
  int   result = kmip_bio_register_symmetric_key (bio_, &ta, reinterpret_cast<char *> (key.data ()), key.size (), &idp,
                                                  &id_max_len);

  std::string ret;
  if (idp != nullptr)
    {
      ret = std::string (idp, id_max_len);
      free (idp);
    }

  if (result != 0)
    {
      return "";
    }

  return ret;
}

context::key_t
context::op_get (context::id_t id)
{

  int   key_len = 0;
  char *keyp    = nullptr;
  int   result  = kmip_bio_get_symmetric_key (bio_, const_cast<char *> (id.c_str ()), id.length (), &keyp, &key_len);

  key_t key (key_len);
  if (keyp != nullptr)
    {
      memcpy (key.data (), keyp, key_len);
      free (keyp);
    }

  if (result != 0)
    {
      return {};
    }

  return key;
}

bool
context::op_activate (context::id_t id)
{
  int result = kmip_bio_activate_symmetric_key (bio_, const_cast<char *> (id.c_str ()), id.length ());
  if (result != KMIP_OK)
    {
      return false;
    }
  return true;
}

bool
context::op_destroy (context::id_t id)
{

  int   key_len = 0;
  char *keyp    = nullptr;
  int   result  = kmip_bio_destroy_symmetric_key (bio_, const_cast<char *> (id.c_str ()), id.length ());

  return result == KMIP_OK;
}

context::name_t
context::op_get_name_attr (context::id_t id)
{

  int   key_len = 0;
  char *keyp    = nullptr;
  int   result  = kmip_bio_get_name_attribute (bio_, const_cast<char *> (id.c_str ()), id.length (), &keyp, &key_len);

  name_t key;
  if (keyp != nullptr)
    {
      key = keyp;
      free (keyp);
    }

  if (result != 0)
    {
      return {};
    }

  return key;
}

context::ids_t
context::op_locate (context::name_t name)
{
  Attribute a[3];
  for (int i = 0; i < 3; i++)
    {
      kmip_init_attribute (&a[i]);
    }
  object_type loctype = KMIP_OBJTYPE_SYMMETRIC_KEY;
  a[0].type           = KMIP_ATTR_OBJECT_TYPE;
  a[0].value          = &loctype;

  Name       ts;
  TextString ts2 = { 0, 0 };
  ts2.value      = const_cast<char *> (name.c_str ());
  ts2.size       = kmip_strnlen_s (ts2.value, 250);
  ts.value       = &ts2;
  ts.type        = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
  a[1].type      = KMIP_ATTR_NAME;
  a[1].value     = &ts;

  int   upto = 0;
  int   all  = 1; // TMP
  ids_t ret;

  LocateResponse locate_result;

  while (upto < all)
    {
      // 16 is hard coded: seems like the most vault supports?
      int result = kmip_bio_locate (bio_, a, 2, &locate_result, 16, upto);

      if (result != 0)
        {
          return {};
        }

      for (int i = 0; i < locate_result.ids_size; ++i)
        {
          ret.push_back (locate_result.ids[i]);
        }
      if (locate_result.located_items != 0)
        {
          all = locate_result.located_items; // shouldn't change after its != 1
        }
      else
        {
          // Dummy server sometimes returns 0 for located_items
          all += locate_result.ids_size;
          if (locate_result.ids_size == 0)
            {
              --all;
            }
        }
      upto += locate_result.ids_size;
    }

  return ret;
}

context::ids_t
context::op_locate_by_group (context::name_t group)
{
  Attribute a[2];
  for (int i = 0; i < 2; i++)
    {
      kmip_init_attribute (&a[i]);
    }

  object_type loctype = KMIP_OBJTYPE_SYMMETRIC_KEY;
  a[0].type           = KMIP_ATTR_OBJECT_TYPE;
  a[0].value          = &loctype;

  TextString ts2 = { 0, 0 };
  ts2.value      = const_cast<char *> (group.c_str ());
  ts2.size       = kmip_strnlen_s (ts2.value, 250);
  a[1].type      = KMIP_ATTR_OBJECT_GROUP;
  a[1].value     = &ts2;

  TemplateAttribute ta = { 0 };
  ta.attributes        = a;
  ta.attribute_count   = ARRAY_LENGTH (a);

  int   upto = 0;
  int   all  = 1; // TMP
  ids_t ret;

  LocateResponse locate_result;

  while (upto < all)
    {
      int result = kmip_bio_locate (bio_, a, 2, &locate_result, 16, upto);

      if (result != 0)
        {
          return {};
        }

      for (int i = 0; i < locate_result.ids_size; ++i)
        {
          ret.push_back (locate_result.ids[i]);
        }
      if (locate_result.located_items != 0)
        {
          all = locate_result.located_items; // shouldn't change after its != 1
        }
      else
        {
          // Dummy server sometimes returns 0 for located_items
          all += locate_result.ids_size;
          if (locate_result.ids_size == 0)
            {
              --all;
            }
        }
      upto += locate_result.ids_size;
    }

  return ret;
}

context::ids_t
context::op_locate_secrets_by_group (context::name_t group)
{
  Attribute a[2];
  for (int i = 0; i < 2; i++)
    {
      kmip_init_attribute (&a[i]);
    }

  object_type loctype = KMIP_OBJTYPE_SECRET_DATA;
  a[0].type           = KMIP_ATTR_OBJECT_TYPE;
  a[0].value          = &loctype;

  TextString ts2 = { 0, 0 };
  ts2.value      = const_cast<char *> (group.c_str ());
  ts2.size       = kmip_strnlen_s (ts2.value, 250);
  a[1].type      = KMIP_ATTR_OBJECT_GROUP;
  a[1].value     = &ts2;

  TemplateAttribute ta = { 0 };
  ta.attributes        = a;
  ta.attribute_count   = ARRAY_LENGTH (a);

  int   upto = 0;
  int   all  = 1; // TMP
  ids_t ret;

  LocateResponse locate_result;

  while (upto < all)
    {
      int result = kmip_bio_locate (bio_, a, 2, &locate_result, 16, upto);

      if (result != 0)
        {
          return {};
        }

      for (int i = 0; i < locate_result.ids_size; ++i)
        {
          ret.push_back (locate_result.ids[i]);
        }
      if (locate_result.located_items != 0)
        {
          all = locate_result.located_items; // shouldn't change after its != 1
        }
      else
        {
          // Dummy server sometimes returns 0 for located_items
          all += locate_result.ids_size;
          if (locate_result.ids_size == 0)
            {
              --all;
            }
        }
      upto += locate_result.ids_size;
    }

  return ret;
}

context::ids_t
context::op_all ()
{
  Attribute a[1];
  for (int i = 0; i < 1; i++)
    {
      kmip_init_attribute (&a[i]);
    }

  object_type loctype = KMIP_OBJTYPE_SYMMETRIC_KEY;
  a[0].type           = KMIP_ATTR_OBJECT_TYPE;
  a[0].value          = &loctype;

  LocateResponse locate_result;

  int   upto = 0;
  int   all  = 1; // TMP
  ids_t ret;

  while (upto < all)
    {
      int result = kmip_bio_locate (bio_, a, 1, &locate_result, 16, upto);

      if (result != 0)
        {
          return {};
        }

      for (int i = 0; i < locate_result.ids_size; ++i)
        {
          ret.push_back (locate_result.ids[i]);
        }
      if (locate_result.located_items != 0)
        {
          all = locate_result.located_items; // shouldn't change after its != 1
        }
      else
        {
          // Dummy server sometimes returns 0 for located_items
          all += locate_result.ids_size;
          if (locate_result.ids_size == 0)
            {
              --all;
            }
        }
      upto += locate_result.ids_size;
    }

  return ret;
}

context::ids_t
context::op_all_secrets ()
{
  Attribute a[1];
  for (int i = 0; i < 1; i++)
    {
      kmip_init_attribute (&a[i]);
    }

  object_type loctype = KMIP_OBJTYPE_SECRET_DATA;
  a[0].type           = KMIP_ATTR_OBJECT_TYPE;
  a[0].value          = &loctype;

  LocateResponse locate_result;

  int   upto = 0;
  int   all  = 1; // TMP
  ids_t ret;

  while (upto < all)
    {
      int result = kmip_bio_locate (bio_, a, 1, &locate_result, 16, upto);

      if (result != 0)
        {
          return {};
        }

      for (int i = 0; i < locate_result.ids_size; ++i)
        {
          ret.push_back (locate_result.ids[i]);
        }
      if (locate_result.located_items != 0)
        {
          all = locate_result.located_items; // shouldn't change after its != 1
        }
      else
        {
          // Dummy server sometimes returns 0 for located_items
          all += locate_result.ids_size;
          if (locate_result.ids_size == 0)
            {
              --all;
            }
        }
      upto += locate_result.ids_size;
    }

  return ret;
}

bool
context::op_revoke (id_t id, int reason, name_t message, time_t occurrence_time)
{
  if (reason < 0)
    return false;
  const enum revocation_reason_type reason_enum = static_cast<revocation_reason_type> (reason);
  int                               result      = kmip_bio_revoke (bio_, const_cast<char *> (id.c_str ()), id.length (),
                                                                   const_cast<char *> (message.c_str ()), message.length (), reason_enum, occurrence_time);
  return (result == KMIP_OK) ;
}

context::id_t
context::op_register_secret (name_t name, name_t group, name_t secret, int secret_type)
{
  int attr_count;
  group.empty () ? attr_count = 2 : attr_count = 3;

  Attribute a[attr_count];
  for (int i = 0; i < attr_count; i++)
  {
    kmip_init_attribute (&a[i]);
  }

  int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT | KMIP_CRYPTOMASK_EXPORT;
  a[0].type  = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
  a[0].value = &mask;

  Name       ts;
  TextString ts2 = { 0, 0 };
  ts2.value      = const_cast<char *> (name.c_str ());
  ts2.size       = kmip_strnlen_s (ts2.value, 250);
  ts.value       = &ts2;
  ts.type        = KMIP_NAME_UNINTERPRETED_TEXT_STRING;
  a[1].type      = KMIP_ATTR_NAME;
  a[1].value     = &ts;

if (attr_count == 3 )
  {
    TextString gs2 = { 0, 0 };
    gs2.value      = const_cast<char *> (group.c_str ());
    gs2.size       = kmip_strnlen_s (gs2.value, 250);
    a[2].type      = KMIP_ATTR_OBJECT_GROUP;
    a[2].value     = &gs2;
  }

  TemplateAttribute ta = { 0 };
  ta.attributes        = a;
  ta.attribute_count   = attr_count;

  int   id_max_len = 64;
  char *idp        = nullptr;

  secret_data_type sdt = static_cast<secret_data_type> (secret_type);

  int result = kmip_bio_register_secret (bio_, &ta, reinterpret_cast<char *> (secret.data ()), secret.size (), &idp,
                                         &id_max_len, sdt);

  id_t ret;
  if (idp != nullptr)
  {
    ret = id_t (idp, id_max_len);
    free (idp);
  }

  return result == 0 ? ret : id_t("");
}

context::name_t
context::op_get_secret (id_t id)
{
  int   secret_len = 0;
  char *secret_p   = nullptr;
  int   result     = kmip_bio_get_secret (bio_, const_cast<char *> (id.c_str ()), id.length (), &secret_p, &secret_len);

  name_t secret;
  if (secret_p != nullptr)
  {
    secret = name_t (secret_p, secret_len);
    free (secret_p);
  }

  return result == 0 ? secret : name_t();
}

std::string
context::get_last_result ()
{
  char *bp;
  size_t size;

  const LastResult *lr = kmip_get_last_result();
  FILE             *mem_stream = open_memstream (&bp, &size);
  fprintf(mem_stream, "Message: %s\nOperation: ",lr->result_message);
  fflush (mem_stream);
  kmip_print_operation_enum (mem_stream, lr->operation);
  fflush (mem_stream);
  fprintf(mem_stream, "; Result status: ");
  fflush (mem_stream);
  kmip_print_result_status_enum (mem_stream, lr->result_status);
  fflush (mem_stream);
  fprintf(mem_stream, "; Result reason: ");
  fflush (mem_stream);
  kmip_print_result_reason_enum (mem_stream, lr->result_reason);
  fclose (mem_stream);
  std::string res {bp, size};
  free (bp);
  kmip_clear_last_result ();
  return res;
}
}
