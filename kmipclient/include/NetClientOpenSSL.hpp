//
// Created by al on 17.03.25.
//

#ifndef KMIPNETCLILENTOPENSSL_HPP
#define KMIPNETCLILENTOPENSSL_HPP

#include "NetClient.hpp"

extern "C"
{ // we do not want to expose SSL stuff ti class users
  typedef struct ssl_ctx_st SSL_CTX;
  typedef struct bio_st     BIO;
}

namespace kmipclient
{

class NetClientOpenSSL : public NetClient
{
public:
  NetClientOpenSSL (const char *host, const char *port, const char *clientCertificateFn, const char *clientKeyFn,
                    const char *serverCaCertFn, int timeout_ms);
  ~NetClientOpenSSL () override;
  // no copy, no move
  NetClientOpenSSL (const NetClient &)                     = delete;
  NetClientOpenSSL &operator= (const NetClient &) override = delete;
  NetClientOpenSSL (NetClient &&)                          = delete;
  NetClientOpenSSL &operator= (NetClient &&) override      = delete;

  int  connect () override;
  void close () override;
  int  send (const void *data, int dlen) override;
  int  recv (void *data, int dlen) override;

private:
  SSL_CTX *ctx_ = nullptr;
  BIO     *bio_ = nullptr;
};
}

#endif // KMIPNETCLILENTOPENSSL_HPP
