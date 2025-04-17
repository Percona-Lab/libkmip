//
// Created by al on 01.04.25.
//

#ifndef ATTRIBUTESFACTORY_HPP
#define ATTRIBUTESFACTORY_HPP
#include "include/kmip_data_types.hpp"
#include "kmip.h"

namespace kmipclient
{
class AttributesFactory
{
public:
  AttributesFactory () = default;
  static attributes_t parse (Attribute *attribute, size_t attribute_count);
};
}

#endif // ATTRIBUTESFACTORY_HPP
