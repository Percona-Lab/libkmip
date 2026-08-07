/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipcore/secure_memory.hpp"

#include <cstring>

#if defined(_WIN32)
  #include <windows.h>
#endif

namespace kmipcore {

  void secure_clear(void *p, std::size_t n) noexcept {
    if (p == nullptr || n == 0) {
      return;
    }

#if defined(_WIN32)
    ::SecureZeroMemory(p, n);
#elif defined(__STDC_LIB_EXT1__)
    // C11 Annex K bounds-checked memset that is not subject to dead-store
    // elimination.
    ::memset_s(p, n, 0, n);
#elif defined(__GLIBC__) &&                                                    \
    (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
    // glibc >= 2.25 and the BSDs provide explicit_bzero.
    ::explicit_bzero(p, n);
#else
    // Portable fallback: a volatile write loop the optimizer must not drop.
    volatile unsigned char *vp = static_cast<volatile unsigned char *>(p);
    while (n-- != 0) {
      *vp++ = 0;
    }
    // Compiler barrier so the writes are not reordered/coalesced away.
    __asm__ __volatile__("" : : "r"(p) : "memory");
#endif
  }

}  // namespace kmipcore
