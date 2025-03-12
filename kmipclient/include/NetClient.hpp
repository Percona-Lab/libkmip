//
// Created by al on 11.03.25.
//

#ifndef KMIP_NET_CLIENT_HPP
#define KMIP_NET_CLIENT_HPP

#include <string>

namespace kmipclient
{
class NetClient
{
public:
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

  virtual int  connect () = 0;
  virtual void close ()   = 0;
  [[nodiscard]] bool
  is_connected () const
  {
    return m_isConnected;
  }

  virtual int send (const void *data, int dlen) = 0;
  virtual int recv (void *data, int dlen)       = 0;

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
