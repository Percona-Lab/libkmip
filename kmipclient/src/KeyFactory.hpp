//
// Created by al on 01.04.25.
//

#ifndef KEYFACTORY_HPP
#define KEYFACTORY_HPP
#include "../include/Key.hpp"
#include "../include/kmip_data_types.hpp"
#include "../include/v_expected.hpp"
#include "kmip.h"
#include <string>

namespace kmipclient
{
class KeyFactory
{
public:
  KeyFactory () = default;
  static ve::expected<Key, Error> parse_response (GetResponsePayload *pld);
};

}

#endif // KEYFACTORY_HPP
