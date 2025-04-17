#ifndef KMIPCLIENT_VERSION_H
#define KMIPCLIENT_VERSION_H

#include "libkmip_version.h"

#define KMIPCLIENT_VERSION_MAJOR 0
#define KMIPCLIENT_VERSION_MINOR 1
#define KMIPCLIENT_VERSION_PATCH 0

#define KMIPCLIENT_STRINGIFY_I(x) #x
#define KMIPCLIENT_TOSTRING_I(x)  KMIPCLIENT_STRINGIFY_I (x)

#define KMIPCLIENT_VERSION_STR                                                                                         \
  KMIPCLIENT_TOSTRING_I (KMIPCLIENT_VERSION_MAJOR)                                                                     \
  "." KMIPCLIENT_TOSTRING_I (KMIPCLIENT_VERSION_MINOR) "." KMIPCLIENT_TOSTRING_I (KMIPCLIENT_VERSION_PATCH)

#endif // KMIPCLIENT_VERSION_H
