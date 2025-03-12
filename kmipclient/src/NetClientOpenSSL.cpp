//
// Created by al on 17.03.25.
//

#include "../include/NetClientOpenSSL.hpp"

#include "include/kmip_data_types.hpp"
#include "kmip_exceptions.hpp"
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace kmipclient
{

int
check_connected (NetClientOpenSSL *nc)
{
  if (nc->is_connected ())
    {
      return 0;
    }
  else
    {
      return nc->connect ();
    }
}

NetClientOpenSSL::NetClientOpenSSL (const char *host, const char *port, const char *clientCertificateFn,
                                    const char *clientKeyFn,
                                    const char *serverCaCertFn, // should it be sever's CA certificate?
                                    int         timeout_ms)
    : NetClient (host, port, clientCertificateFn, clientKeyFn, serverCaCertFn, timeout_ms)
{
}

NetClientOpenSSL::~NetClientOpenSSL () { close (); }

int
NetClientOpenSSL::connect ()
{
  ctx_ = SSL_CTX_new (SSLv23_method ());

  if (SSL_CTX_use_certificate_file (ctx_, m_clientCertificateFn.c_str (), SSL_FILETYPE_PEM) != 1)
    {
      SSL_CTX_free (ctx_);
      throw ErrorException (-1, "Loading the client certificate failed");
      return -1;
    }
  if (SSL_CTX_use_PrivateKey_file (ctx_, m_clientKeyFn.c_str (), SSL_FILETYPE_PEM) != 1)
    {
      SSL_CTX_free (ctx_);
      throw ErrorException (-1, "Loading the client key failed");
      return -1;
    }
  if (SSL_CTX_load_verify_locations (ctx_, m_serverCaCertificateFn.c_str (), nullptr) != 1)
    {
      SSL_CTX_free (ctx_);
      throw ErrorException (-1, "Loading the CA certificate failed");
      return -1;
    }

  bio_ = BIO_new_ssl_connect (ctx_);
  if (bio_ == nullptr)
    {
      SSL_CTX_free (ctx_);
      throw ErrorException (-1, "BIO_new_ssl_connect failed");
      return -1;
    }

  SSL *ssl = nullptr;
  BIO_get_ssl (bio_, &ssl);
  SSL_set_mode (ssl, SSL_MODE_AUTO_RETRY);
  BIO_set_conn_hostname (bio_, m_host.c_str ());
  BIO_set_conn_port (bio_, m_port.c_str ());
  BIO_set_ssl_renegotiate_timeout (bio_, m_timeout_ms);
  if (BIO_do_connect (bio_) != 1)
    {
      BIO_free_all (bio_);
      SSL_CTX_free (ctx_);
      bio_ = nullptr;
      ctx_ = nullptr;
      throw ErrorException (-1, "BIO_do_connect failed");
      return -1;
    }
  m_isConnected = true;
  return 0;
}

void
NetClientOpenSSL::close ()
{
  if (bio_ != nullptr)
    {
      BIO_free_all (bio_);
      bio_ = nullptr;
    }
  if (ctx_ != nullptr)
    {
      SSL_CTX_free (ctx_);
      ctx_ = nullptr;
    }
  m_isConnected = false;
}

int
NetClientOpenSSL::send (const void *data, int dlen)
{
  if (check_connected (this) < 0)
    return -1;
  return BIO_write (bio_, data, dlen);
}

int
NetClientOpenSSL::recv (void *data, int dlen)
{
  if (check_connected (this) < 0)
    return -1;
  return BIO_read (bio_, data, dlen);
}

} // namespace