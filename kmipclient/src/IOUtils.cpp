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

#include "IOUtils.hpp"
#include "../include/kmip_exceptions.hpp"
#include "ResponseFactory.hpp"

#include <cstring>
#include <format>

namespace kmipclient
{
#define KMIP_MSG_LENGTH_BYTES 8

void
IOUtils::send (KmipCtx &kmip_ctx) const
{
  const KMIP *ctx  = kmip_ctx.get ();
  int         dlen = static_cast<int> (ctx->index - ctx->buffer);
  if (int sent = net_client.send (ctx->buffer, dlen); sent < dlen)
    {
      kmip_ctx.free_buffer ();
      throw ErrorException (-1, std::format ("Can not send request. Bytes total: {}, bytes sent: {}", dlen, sent));
    }
  kmip_ctx.free_buffer ();
}

void
IOUtils::receive_message_in_ctx (KmipCtx &kmip_ctx)
{
  uint8_t msg_len_buf[KMIP_MSG_LENGTH_BYTES];

  int received = net_client.recv (&msg_len_buf, KMIP_MSG_LENGTH_BYTES);
  if (received < KMIP_MSG_LENGTH_BYTES)
    {
      kmip_ctx.free_buffer ();
      throw ErrorException (-1, std::format ("Can not receive response length. Bytes total: {}, bytes received: {}",
                                             KMIP_MSG_LENGTH_BYTES, received));
    }

  // this is ugly method to get message length!!!
  kmip_ctx.set_buffer (msg_len_buf, KMIP_MSG_LENGTH_BYTES);
  KMIP *ctx = kmip_ctx.get ();
  ctx->index += 4;
  int length = 0;
  kmip_decode_int32_be (ctx, &length);
  //
  if (length > ctx->max_message_size)
    {
      throw ErrorException (-1, std::format ("Message too long. Length: {}", length));
    }
  // TODO: deallocate buffer
  kmip_ctx.alloc_buffer (KMIP_MSG_LENGTH_BYTES + length);
  memcpy (ctx->buffer, msg_len_buf, KMIP_MSG_LENGTH_BYTES);
  received = net_client.recv (ctx->buffer + KMIP_MSG_LENGTH_BYTES, length);
  if (received < length)
    {
      kmip_ctx.free_buffer ();
      throw ErrorException (
          -1, std::format ("Can not receive response. Bytes total: {}, bytes received: {}", length, received));
    }
  if (logger != nullptr)
    {
      logger->log (ERROR, print_response ());
    }
}

void
IOUtils::do_exchange (KmipCtx &kmip_ctx)
{
  send (kmip_ctx);
  receive_message_in_ctx (kmip_ctx);
}

std::string
IOUtils::print_request ()
{
  // TODO: implement request text representation
  return "NOT_IMPLEMENTED";
}

std::string
IOUtils::print_response ()
{
  // TODO: implement response text representation
  return "NOT_IMPLEMENTED";
}

} // namespace
