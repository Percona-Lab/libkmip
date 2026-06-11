/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCORE_VERSION_HPP
#define KMIPCORE_VERSION_HPP

/** @brief kmipcore semantic version major component. */
#define KMIPCORE_VERSION_MAJOR 0
/** @brief kmipcore semantic version minor component. */
#define KMIPCORE_VERSION_MINOR 1
/** @brief kmipcore semantic version patch component. */
#define KMIPCORE_VERSION_PATCH 2

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
