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

#ifndef KMIP_HPP
#define KMIP_HPP
#include "KmipClient.hpp"
#include "NetClientOpenSSL.hpp"

namespace kmipclient
{
/**
 * Simplified interface to the KmipClient, with network client initialization
 */
class Kmip
{
public:
  /** Constructor creates instances of the OpenSSL-based network client and a KMIP protocol handling client.
   *  After successful initialization, use the client() method to access KMIP operations.
   *  Constructor possibly throws ErrorException from the NetClient!
   */
  Kmip (const char *host, const char *port, const char *clientCertificateFn, const char *clientKeyFn,
        const char *serverCaCertFn, int timeout_ms)
      : m_net_client (host, port, clientCertificateFn, clientKeyFn, serverCaCertFn, timeout_ms), m_client (m_net_client)
  {
    m_net_client.connect ();
  };

  /**
   * Gets reference to the inited instance of KmipClient, which has all KMIP operations.
   * @return the reference to the instance of KmipClient
   */
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
