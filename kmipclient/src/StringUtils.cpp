//
// Created by al on 02.04.25.
//

#include "StringUtils.hpp"
namespace kmipclient
{

unsigned char
char2int (const char input)
{
  if (input >= '0' && input <= '9')
    return input - '0';
  if (input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if (input >= 'a' && input <= 'f')
    return input - 'a' + 10;
  throw std::invalid_argument ("Invalid input string");
}

ve::expected<key_t, Error>
StringUtils::fromHex (const std::string &hex)
{
  if (hex.empty () || hex.size () % 2 != 0)
    {
      return Error{ -1, "Invalid hex string length." };
      // return ve::unexpected<key_t, Error>(Error {-1, "Invalid hex string length."});
    }
  key_t bytes;
  try
    {
      for (unsigned int i = 0; i < hex.length (); i += 2)
        {
          std::string byteString = hex.substr (i, 2);
          auto        byte       = char2int (byteString.c_str ()[0]) * 16 + char2int (byteString.c_str ()[1]);
          bytes.push_back (byte);
        }
    }
  catch (const std::invalid_argument &e)
    {
      return Error{ -1, "Invalid hex string length." };
    }
  return bytes;
}

}