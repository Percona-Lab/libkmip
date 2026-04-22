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

#ifndef KMIPCORE_VERSION_HPP
#define KMIPCORE_VERSION_HPP

/** @brief kmipcore semantic version major component. */
#define KMIPCORE_VERSION_MAJOR 0
/** @brief kmipcore semantic version minor component. */
#define KMIPCORE_VERSION_MINOR 1
/** @brief kmipcore semantic version patch component. */
#define KMIPCORE_VERSION_PATCH 1

/** @brief Internal helper for macro stringification. */
#define KMIPCORE_STRINGIFY_I(x) #x
/** @brief Internal helper for macro stringification. */
#define KMIPCORE_TOSTRING_I(x) KMIPCORE_STRINGIFY_I(x)

/** @brief Full kmipcore version string in "major.minor.patch" form. */
#define KMIPCORE_VERSION_STR                                                   \
  KMIPCORE_TOSTRING_I(KMIPCORE_VERSION_MAJOR)                                  \
  "." KMIPCORE_TOSTRING_I(KMIPCORE_VERSION_MINOR) "." KMIPCORE_TOSTRING_I(     \
      KMIPCORE_VERSION_PATCH                                                   \
  )

#endif  // KMIPCORE_VERSION_HPP
