//
// Created by al on 22.03.25.
//

#ifndef IOUTILS_HPP
#define IOUTILS_HPP
#include "KmipCtx.hpp"
#include "include/Logger.hpp"
#include "include/NetClient.hpp"
#include "include/kmip_data_types.hpp"
#include "include/v_expected.hpp"

#include <memory>
#include <optional>

namespace kmipclient
{

class IOUtils
{

public:
  explicit IOUtils (NetClient &nc) : net_client (nc) {};
  explicit IOUtils (NetClient &nc, std::shared_ptr<Logger> log) : net_client (nc) { logger = log; };

  void        do_exchange (KmipCtx &kmip_ctx);
  // log for debug purposes, not implemented yet
  std::string print_request ();
  std::string print_response ();

private:
  void                    send (KmipCtx &kmip_ctx);
  void                    receive_message_in_ctx (KmipCtx &kmip_ctx);
  NetClient              &net_client;
  std::shared_ptr<Logger> logger;
};

} // namespace

#endif // IOUTILS_HPP
