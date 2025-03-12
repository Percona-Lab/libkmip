//
// Created by al on 24.03.25.
//

#ifndef KMIP_HPP
#define KMIP_HPP
#include "KmipClient.hpp"
#include "NetClientOpenSSL.hpp"
#include "kmipclient_version.hpp"

namespace kmipclient
{
/**
 * Simplified interface with network client initialization
 */
class Kmip
{
public:
  Kmip (const char *host, const char *port, const char *clientCertificateFn, const char *clientKeyFn,
        const char *serverCaCertFn, int timeout_ms)
      : m_net_client (host, port, clientCertificateFn, clientKeyFn, serverCaCertFn, timeout_ms),
        m_client (m_net_client) {

        };
  KmipClient &
  client ()
  {
    return m_client;
  };

private:
  /**
   * Instance of the NetClient using OpenSSL BIO
   */
  NetClientOpenSSL m_net_client;
  /**
   * KMIP protocol client, initialized with m_net_client in the constructor
   */
  KmipClient       m_client;
};
}
#endif // KMIP_HPP
