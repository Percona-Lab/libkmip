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

#ifndef KMIPREQUEST_HPP
#define KMIPREQUEST_HPP

#include "../include/kmip_exceptions.hpp"
#include "KmipCtx.hpp"
#include <kmip.h>

namespace kmipclient
{
class KmipRequest
{
public:
  explicit KmipRequest (KmipCtx &ctx);

  RequestMessage &
  get ()
  {
    return request;
  };
  void add_batch_item (RequestBatchItem *bi);
  void encode () const;
  [[nodiscard]] KmipCtx &
  get_ctx () const
  {
    return ctx_;
  };

private:
  RequestMessage  request{};
  RequestHeader   rh{};
  ProtocolVersion pv{};
  KmipCtx        &ctx_;
};

inline KmipRequest::KmipRequest (KmipCtx &ctx) : ctx_ (ctx)
{
  kmip_init_protocol_version (&pv, ctx_.get ()->version);
  kmip_init_request_header (&rh);
  rh.protocol_version      = &pv;
  rh.maximum_response_size = ctx_.get ()->max_message_size;
  rh.time_stamp            = time (nullptr);
  rh.batch_count           = 0;
  request.request_header   = &rh;
};

inline void
KmipRequest::add_batch_item (RequestBatchItem *rbi)
{
  // Sorry, C++ guys, we have to use address arithmetic here because of the lower level
  *(&request.batch_items + request.batch_count) = rbi;
  request.batch_count += 1;
  request.request_header->batch_count += 1;
}

inline void
KmipRequest::encode () const
{
  /* Encode the request message. Dynamically resize the encoding buffer */
  /* if it's not big enough. Once encoding succeeds, send the request   */
  /* message.                                                           */

  int encode_result = kmip_encode_request_message (ctx_.get (), &request);
  while (encode_result == KMIP_ERROR_BUFFER_FULL)
    {
      ctx_.increase_buffer ();
      encode_result = kmip_encode_request_message (ctx_.get (), &request);
    }
  if (encode_result != KMIP_OK)
    {
      // very low probability, usually we have plenty of memory
      throw ErrorException (encode_result, "Error in the KMIP request encoding");
    }
}

}
#endif // KMIPREQUEST_HPP
