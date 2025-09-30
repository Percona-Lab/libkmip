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

#ifndef KMIP_NET_CLIENT_HPP
#define KMIP_NET_CLIENT_HPP

#include <string>

namespace kmipclient
{
/**
 * Interface for the SSL network communication level
 */
class NetClient
{
public:
  /**
   * Constructor for the KMIP SSL network level
   * @param host KMIP server host
   * @param port KMIP server port
   * @param clientCertificateFn File path for a client X.509 certificate in PEM format
   * @param clientKeyFn File path for a corresponding client private key in PEM format
   * @param serverCaCertFn File path for the server cert. Also, may work with the CA certificate that signed server cert
   * @param timeout_ms connection timeout in milliseconds
   */
  NetClient (const char *host, const char *port, const char *clientCertificateFn, const char *clientKeyFn,
             const char *serverCaCertFn, int timeout_ms) noexcept : m_host (host),
                                                                    m_port (port),
                                                                    m_clientCertificateFn (clientCertificateFn),
                                                                    m_clientKeyFn (clientKeyFn),
                                                                    m_serverCaCertificateFn (serverCaCertFn),
                                                                    m_timeout_ms (timeout_ms) {};

  virtual ~NetClient ()                            = default;
  // no copy, no move
  NetClient (const NetClient &)                    = delete;
  virtual NetClient &operator= (const NetClient &) = delete;
  NetClient (NetClient &&)                         = delete;
  virtual NetClient &operator= (NetClient &&)      = delete;
  /**
   * Performs SSL connection to the server
   * @return 0 in case of success, negative value in case of error
   */

  virtual int  connect () = 0;
  /**
   * Closes SSL connection to the server
   */
  virtual void close ()   = 0;

  /**
   * Checks if the network client is already connected to the server
   * @return true if the connection is established, false otherwise
   */
  [[nodiscard]] bool
  is_connected () const
  {
    return m_isConnected;
  }
  /**
   * Sends dlen bytes from the buffer in *data
   * @param data data buffer
   * @param dlen number of bytes to send
   * @return In success, these calls return the number of bytes sent.  On error, -1 is returned
   */
  virtual int send (const void *data, int dlen) = 0;

  /**
   * Receives dlen bytes into the pre-allocated buffer *data
   * @param data buffer for received data
   * @param dlen number of bytes to receive
   * @return the number of bytes received, or -1 if an error occurred
   */
  virtual int recv (void *data, int dlen) = 0;

protected:
  std::string m_host;
  std::string m_port;
  std::string m_clientCertificateFn;
  std::string m_clientKeyFn;
  std::string m_serverCertFn;
  std::string m_serverCaCertificateFn;
  int         m_timeout_ms;
  bool        m_isConnected = false;
};
}
#endif // KMIP_NET_CLIENT_HPP
