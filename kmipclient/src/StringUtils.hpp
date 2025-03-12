//
// Created by al on 02.04.25.
//

#ifndef STRINGUTILS_HPP
#define STRINGUTILS_HPP
#include "include/kmip_data_types.hpp"
#include "include/v_expected.hpp"

#include <kmip.h>

namespace kmipclient
{

class StringUtils
{
public:
  static ve::expected<key_t, Error> fromHex (const std::string &hex);
  static std::string
  fromKmipText (const TextString *ts)
  {
    return std::string{ ts->value, ts->size };
  };
};

}

#endif // STRINGUTILS_HPP
