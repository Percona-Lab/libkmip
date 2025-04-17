//
// Created by al on 24.03.25.
//

#ifndef RESPONSERESULT_HPP
#define RESPONSERESULT_HPP

#include "KmipCtx.hpp"
#include "include/Key.hpp"
#include "include/kmip_data_types.hpp"
#include "include/v_expected.hpp"

#include "kmip.h"

namespace kmipclient
{
class ResponseResult
{
public:
  static ve::expected<id_t, Error>   get_id (const ResponseBatchItem *rbi);
  static ve::expected<Key, Error>    get_key (ResponseBatchItem *rbi);
  static ve::expected<Secret, Error> get_secret (ResponseBatchItem *rbi);
  static ve::expected<name_t, Error> get_attributes (ResponseBatchItem *rbi);
  static ve::expected<ids_t, Error>  get_ids (ResponseBatchItem *rbi);
};

}

#endif // RESPONSERESULT_HPP
