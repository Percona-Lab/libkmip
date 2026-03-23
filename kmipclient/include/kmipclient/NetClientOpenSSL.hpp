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

#include "kmipclient/NetClient.hpp"

#include <memory>

extern "C" {  // we do not want to expose SSL stuff to this class users
typedef struct ssl_ctx_st SSL_CTX;
typedef struct bio_st BIO;
void SSL_CTX_free(SSL_CTX *);
void BIO_free_all(BIO *);
}

namespace kmipclient {
  /**
   * @brief OpenSSL BIO-based implementation of @ref NetClient.
   */
  class NetClientOpenSSL : public NetClient {
  public:
    /** Default transport timeout (connect/handshake/read/write), in ms. */
    static constexpr int DEFAULT_TIMEOUT_MS = 500;

    /**
     * @brief Constructs an OpenSSL-backed transport.
     * @param host KMIP server host.
     * @param port KMIP server port.
     * @param clientCertificateFn Path to client certificate in PEM.
     * @param clientKeyFn Path to client private key in PEM.
     * @param serverCaCertFn Path to trusted server CA/certificate in PEM.
     * @param timeout_ms Timeout in milliseconds applied to TCP connect, TLS
     *        handshake, and each read/write operation.
     */
    NetClientOpenSSL(
        const std::string &host,
        const std::string &port,
        const std::string &clientCertificateFn,
        const std::string &clientKeyFn,
        const std::string &serverCaCertFn,
        int timeout_ms = DEFAULT_TIMEOUT_MS
    );
    /** @brief Releases OpenSSL resources and closes any open connection. */
    ~NetClientOpenSSL() override;
    // no copy, no move
    NetClientOpenSSL(const NetClientOpenSSL &) = delete;
    NetClientOpenSSL &operator=(const NetClientOpenSSL &) = delete;
    NetClientOpenSSL(NetClientOpenSSL &&) = delete;
    NetClientOpenSSL &operator=(NetClientOpenSSL &&) = delete;

    /**
     * @brief Establishes a TLS connection to the configured KMIP endpoint.
     *        Honors timeout_ms for both TCP connect and TLS handshake.
     *        The handshake also honors the TLS verification settings configured
     *        via @ref set_tls_verification().
     * @return true on success, false on failure.
     */
    bool connect() override;
    /** @brief Closes the underlying OpenSSL BIO connection. */
    void close() override;
    /**
     * @brief Sends raw bytes through the TLS channel.
     * @param data Source buffer.
     * @return Number of bytes sent, or -1 on failure.
     */
    int send(std::span<const std::uint8_t> data) override;
    /**
     * @brief Receives raw bytes through the TLS channel.
     * @param data Destination buffer.
     * @return Number of bytes read, or -1 on failure.
     */
    int recv(std::span<std::uint8_t> data) override;

  private:
    struct SslCtxDeleter {
      void operator()(SSL_CTX *ptr) const { SSL_CTX_free(ptr); }
    };
    struct BioDeleter {
      void operator()(BIO *ptr) const { BIO_free_all(ptr); }
    };

    std::unique_ptr<SSL_CTX, SslCtxDeleter> ctx_;
    std::unique_ptr<BIO, BioDeleter> bio_;

    bool checkConnected();
  };
}  // namespace kmipclient

#endif  // KMIPNETCLILENTOPENSSL_HPP
