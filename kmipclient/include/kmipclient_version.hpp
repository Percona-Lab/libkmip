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

#ifndef KMIPCLIENT_VERSION_H
#define KMIPCLIENT_VERSION_H

#include "libkmip_version.h"

#define KMIPCLIENT_VERSION_MAJOR 0
#define KMIPCLIENT_VERSION_MINOR 1
#define KMIPCLIENT_VERSION_PATCH 1

#define KMIPCLIENT_STRINGIFY_I(x) #x
#define KMIPCLIENT_TOSTRING_I(x)  KMIPCLIENT_STRINGIFY_I (x)

#define KMIPCLIENT_VERSION_STR                                                                                         \
  KMIPCLIENT_TOSTRING_I (KMIPCLIENT_VERSION_MAJOR)                                                                     \
  "." KMIPCLIENT_TOSTRING_I (KMIPCLIENT_VERSION_MINOR) "." KMIPCLIENT_TOSTRING_I (KMIPCLIENT_VERSION_PATCH)

#endif // KMIPCLIENT_VERSION_H
