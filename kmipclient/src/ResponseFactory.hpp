//
// Created by al on 23.03.25.
//

#ifndef RESPONSEFACTORY_HPP
#define RESPONSEFACTORY_HPP

#include "KmipCtx.hpp"
#include "ResponseResult.hpp"
#include "include/v_expected.hpp"
#include "kmip.h"
#include "kmip_exceptions.hpp"

namespace kmipclient
{
#define LAST_RESULT_MAX_MESSAGE_SIZE 512 // could be big with HasiCorp Vault

struct OperationResult
{
  enum operation     operation;
  enum result_status result_status;
  enum result_reason result_reason;
  char               result_message[LAST_RESULT_MAX_MESSAGE_SIZE];
};

class ResponseFactory
{
public:
  explicit ResponseFactory (KmipCtx &ctx) : ctx_ (ctx) {};
  ~ResponseFactory () { kmip_free_response_message (ctx_.get (), &m_resp); }
  // disable copy and move
  ResponseFactory (const ResponseFactory &)            = delete;
  ResponseFactory (ResponseFactory &&)                 = delete;
  ResponseFactory &operator= (const ResponseFactory &) = delete;
  ResponseFactory &operator= (ResponseFactory &&)      = delete;

  ve::expected<id_t, Error>
  get_id (int item_idx)
  {
    return ResponseResult::get_id (get_response_items ()[item_idx]);
  }

  ve::expected<Key, Error>
  get_key (int item_idx)
  {
    return ResponseResult::get_key (get_response_items ()[item_idx]);
  }

  ve::expected<Secret, Error>
  get_secret (int item_idx)
  {
    return ResponseResult::get_secret (get_response_items ()[item_idx]);
  }

  ve::expected<name_t, Error>
  get_attributes (int item_idx)
  {
    return ResponseResult::get_attributes (get_response_items ()[item_idx]);
  }

  ve::expected<ids_t, Error>
  get_ids (int item_idx)
  {
    return ResponseResult::get_ids (get_response_items ()[item_idx]);
  }

private:
  void                             parse_response ();
  std::vector<ResponseBatchItem *> get_response_items ();
  static std::string               get_operation_result (const ResponseBatchItem &value);
  KmipCtx                         &ctx_;
  ResponseMessage                  m_resp{};
  bool                             is_parsed = false;
};

inline void
ResponseFactory::parse_response ()
{
  // decode response;
  int decode_result = kmip_decode_response_message (ctx_.get (), &m_resp);
  if (decode_result != KMIP_OK)
    {
      throw ErrorException{ decode_result, ctx_.get_errors () };
    }
  is_parsed = true;
}

inline std::vector<ResponseBatchItem *>
ResponseFactory::get_response_items ()
{
  if (!is_parsed)
    {
      parse_response ();
    }

  std::vector<ResponseBatchItem *> items;
  if (m_resp.batch_count < 1)
    { // something went wrong
      throw ErrorException{ -1, "No response batch items from the server." };
    }

  for (int idx = 0; idx < m_resp.batch_count; idx++)
    {
      if (m_resp.batch_items[idx].result_status != KMIP_STATUS_SUCCESS) // error from the server
        {
          throw ErrorException (-1, get_operation_result (m_resp.batch_items[idx]));
        }
      items.push_back (&m_resp.batch_items[idx]);
    }
  return items;
}

inline std::string
ResponseFactory::get_operation_result (const ResponseBatchItem &value)
{
  char           *bp;
  size_t          size;
  OperationResult last_result{};

  last_result.operation     = value.operation;
  last_result.result_status = value.result_status;
  last_result.result_reason = value.result_reason;
  if (value.result_message)
    kmip_copy_textstring (last_result.result_message, value.result_message, sizeof (last_result.result_message));
  else
    last_result.result_message[0] = 0;

  FILE *mem_stream = open_memstream (&bp, &size);
  fprintf (mem_stream, "Message: %s\nOperation: ", last_result.result_message);
  fflush (mem_stream);
  kmip_print_operation_enum (mem_stream, last_result.operation);
  fflush (mem_stream);
  fprintf (mem_stream, "; Result status: ");
  fflush (mem_stream);
  kmip_print_result_status_enum (mem_stream, last_result.result_status);
  fflush (mem_stream);
  fprintf (mem_stream, "; Result reason: ");
  fflush (mem_stream);
  kmip_print_result_reason_enum (mem_stream, last_result.result_reason);
  fclose (mem_stream);
  std::string res{ bp, size };
  free (bp);
  return res;
}

}

#endif // RESPONSEFACTORY_HPP
