//
// Created by al on 18.03.25.
//

#ifndef DATA_TYPES_HPP
#define DATA_TYPES_HPP

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace kmipclient
{

// known attributes so far
#define KMIP_ATTR_NAME_NAME  "Name"
#define KMIP_ATTR_NAME_STATE "State"

using key_t        = std::vector<unsigned char>;
using bin_data_t   = std::vector<unsigned char>;
using id_t         = std::string;
using ids_t        = std::vector<std::string>;
using name_t       = std::string;
using secret_t     = std::string;
using attributes_t = std::unordered_map<std::string, std::string>;

// should be the same as   enum object_type in kmip.h
enum kmip_entity_type
{
  /* KMIP 1.0 */
  KMIP_ENTITY_CERTIFICATE         = 0x01,
  KMIP_ENTITY_SYMMETRIC_KEY       = 0x02,
  KMIP_ENTITY_PUBLIC_KEY          = 0x03,
  KMIP_ENTITY_PRIVATE_KEY         = 0x04,
  KMIP_ENTITY_SPLIT_KEY           = 0x05,
  KMIP_ENTITY_TEMPLATE            = 0x06, /* Deprecated as of KMIP 1.3 */
  KMIP_ENTITY_SECRET_DATA         = 0x07,
  KMIP_ENTITY_OPAQUE_OBJECT       = 0x08,
  /* KMIP 1.2 */
  KMIP_ENTITY_PGP_KEY             = 0x09,
  /* KMIP 2.0 */
  KMIP_ENTITY_CERTIFICATE_REQUEST = 0x0A
};

enum kmip_entity_state // should be the same as "enum" state in kmip.h
{
  /* KMIP 1.0 */
  KMIP_STATE_PRE_ACTIVE            = 0x01,
  KMIP_STATE_ACTIVE                = 0x02,
  KMIP_STATE_DEACTIVATED           = 0x03,
  KMIP_STATE_COMPROMISED           = 0x04,
  KMIP_STATE_DESTROYED             = 0x05,
  KMIP_STATE_DESTROYED_COMPROMISED = 0x06
};

inline std::ostream &
operator<< (std::ostream &out, const kmip_entity_state value)
{
  const char *str;
  switch (value)
    {
#define PROCESS_VAL(p)                                                                                                 \
  case (p):                                                                                                            \
    str = #p;                                                                                                          \
    break;
      PROCESS_VAL (KMIP_STATE_PRE_ACTIVE);
      PROCESS_VAL (KMIP_STATE_ACTIVE);
      PROCESS_VAL (KMIP_STATE_DEACTIVATED);
      PROCESS_VAL (KMIP_STATE_COMPROMISED);
      PROCESS_VAL (KMIP_STATE_DESTROYED);
      PROCESS_VAL (KMIP_STATE_DESTROYED_COMPROMISED);
#undef PROCESS_VAL
    default:
      str = "UNKNOWN_KMIP_STATE";
      break; // Handle unknown values
    }
  return out << str;
}

enum kmip_secret_type
{
  KMIP_SECRET_TYPE_NONE                   = 0,
  KMIP_SECRET_TYPE_PASSWORD               = 0x01,
  KMIP_SECRET_TYPE_SEED                   = 0x02,
  KMIP_SECRET_TYPE_SECRET_DATA_EXTENSIONS = 0x80000000
};

enum kmip_revocation_reason
{
  /* KMIP 1.0 */
  KMIP_REVIKE_UNSPECIFIED            = 0x01,
  KMIP_REVIKE_KEY_COMPROMISE         = 0x02,
  KMIP_REVIKE_CA_COMPROMISE          = 0x03,
  KMIP_REVIKE_AFFILIATION_CHANGED    = 0x04,
  KMIP_REVIKE_SUSPENDED              = 0x05,
  KMIP_REVIKE_CESSATION_OF_OPERATION = 0x06,
  KMIP_REVIKE_PRIVILEDGE_WITHDRAWN   = 0x07,
  KMIP_REVIKE_REVOCATION_EXTENSIONS  = 0x80000000
};

class Secret
{
public:
  secret_t value;
  int      state       = 0;
  int      secret_type = 0;
};

class Error
{
public:
  int         code;
  std::string message;
};

}
#endif // DATA_TYPES_HPP
