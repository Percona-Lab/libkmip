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

#ifndef IOUTILS_HPP
#define IOUTILS_HPP

#include <memory>

#include "KmipCtx.hpp"
#include "Logger.hpp"
#include "NetClient.hpp"

namespace kmipclient
{

class IOUtils
{

public:
  explicit IOUtils (NetClient &nc) : net_client (nc) {};
  explicit IOUtils (NetClient &nc, const std::shared_ptr<Logger> &log) : net_client (nc) { logger = log; };

  void        do_exchange (KmipCtx &kmip_ctx);
  // log for debug purposes, not implemented yet
  std::string print_request ();
  std::string print_response ();

private:
  void                    send (KmipCtx &kmip_ctx) const;
  void                    receive_message_in_ctx (KmipCtx &kmip_ctx);
  NetClient              &net_client;
  std::shared_ptr<Logger> logger;
};

} // namespace

#endif // IOUTILS_HPP
