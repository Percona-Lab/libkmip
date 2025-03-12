//
// Created by al on 21.03.25.
//

#ifndef KMIPREQUEST_HPP
#define KMIPREQUEST_HPP
#include "KmipCtx.hpp"
#include "include/kmip_data_types.hpp"
#include "kmip_exceptions.hpp"
#include <kmip.h>

#include <optional>

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

inline KmipRequest::KmipRequest (KmipCtx &ctx) : request (), rh (), ctx_ (ctx)
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
  // TODO: multiple batch items
  request.batch_items = rbi; //[request.batch_count] = rbi;
  request.batch_count += 1;
}

inline void
KmipRequest::encode () const
{
  /* Encode the request message. Dynamically resize the encoding buffer */
  /* if it's not big enough. Once encoding succeeds, send the request   */
  /* message.                                                           */
  auto ctx      = ctx_.get ();
  auto encoding = ctx_.get ()->buffer;

  int encode_result = kmip_encode_request_message (ctx, &request);
  while (encode_result == KMIP_ERROR_BUFFER_FULL)
    {
      ctx_.increase_buffer ();
      encode_result = kmip_encode_request_message (ctx, &request);
    }
  if (encode_result != KMIP_OK)
    {
      // very low probability, we have plenty of memory usually
      throw ErrorException (encode_result, "Error in the KMIP request encoding");
    }
}

}
#endif // KMIPREQUEST_HPP
