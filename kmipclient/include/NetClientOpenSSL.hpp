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

#ifndef KMIPNETCLILENTOPENSSL_HPP
#define KMIPNETCLILENTOPENSSL_HPP

#include "NetClient.hpp"

extern "C"
{ // we do not want to expose SSL stuff to this class users
  typedef struct ssl_ctx_st SSL_CTX;
  typedef struct bio_st     BIO;
}

namespace kmipclient
{
/**
 * OpenSSL's BIO-based implementation of the NetClient interface
 */
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
  int      check_connected ();
};
}

#endif // KMIPNETCLILENTOPENSSL_HPP
