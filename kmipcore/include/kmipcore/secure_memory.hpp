/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIPCORE_SECURE_MEMORY_HPP
#define KMIPCORE_SECURE_MEMORY_HPP

#include <algorithm>
#include <cstddef>
#include <new>
#include <string>
#include <vector>

namespace kmipcore {

  /**
   * @brief Overwrite @p n bytes at @p p with zeros in a way the compiler is
   *        not permitted to optimize away.
   *
   * Plain std::memset on a buffer that is about to be freed is a textbook
   * dead-store elimination target: the optimizer sees the memory is never read
   * again and removes the write, leaving secrets in place. secure_clear routes
   * through a platform "explicit" zeroing primitive when available and falls
   * back to a volatile write loop otherwise, so the store always happens.
   *
   * kmipcore intentionally does not depend on OpenSSL, so this does not use
   * OPENSSL_cleanse.
   */
  void secure_clear(void *p, std::size_t n) noexcept;

  /**
   * @brief Allocator that scrubs memory before handing it back to the runtime.
   *
   * Drop-in for the default std::allocator except that deallocate() runs
   * @ref secure_clear over the whole block first. Compose it with the standard
   * containers to get storage whose contents never survive the container:
   * reallocation on growth, moves, and destruction all pass through
   * deallocate() and therefore zero the freed bytes.
   */
  template<typename T> struct secure_allocator {
    using value_type = T;

    secure_allocator() noexcept = default;

    template<typename U>
    secure_allocator(const secure_allocator<U> & /*other*/) noexcept {}

    template<typename U> struct rebind {
      using other = secure_allocator<U>;
    };

    [[nodiscard]] T *allocate(std::size_t n) {
      if (n > (static_cast<std::size_t>(-1) / sizeof(T))) {
        throw std::bad_alloc();
      }
      return static_cast<T *>(::operator new(n * sizeof(T)));
    }

    void deallocate(T *p, std::size_t n) noexcept {
      if (p != nullptr) {
        secure_clear(p, n * sizeof(T));
        ::operator delete(p);
      }
    }
  };

  template<typename T, typename U>
  bool operator==(
      const secure_allocator<T> & /*a*/, const secure_allocator<U> & /*b*/
  ) noexcept {
    return true;
  }

  template<typename T, typename U>
  bool operator!=(
      const secure_allocator<T> & /*a*/, const secure_allocator<U> & /*b*/
  ) noexcept {
    return false;
  }

  /** @brief Byte buffer whose storage is zeroed when freed. */
  using secure_bytes =
      std::vector<unsigned char, secure_allocator<unsigned char>>;

  /** @brief String whose storage is zeroed when freed. */
  using secure_string =
      std::basic_string<char, std::char_traits<char>, secure_allocator<char>>;

  // ---- Heterogeneous comparisons ----
  //
  // secure_bytes / secure_string differ from the default-allocator containers
  // only in their allocator type, but the standard comparison operators are not
  // heterogeneous across allocators. These let callers and tests compare secure
  // and plain containers element-wise without copying secrets into a plain one.

  inline bool
      operator==(const secure_bytes &a, const std::vector<unsigned char> &b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
  }
  inline bool
      operator==(const std::vector<unsigned char> &a, const secure_bytes &b) {
    return b == a;
  }
  inline bool
      operator!=(const secure_bytes &a, const std::vector<unsigned char> &b) {
    return !(a == b);
  }
  inline bool
      operator!=(const std::vector<unsigned char> &a, const secure_bytes &b) {
    return !(b == a);
  }

  inline bool operator==(const secure_string &a, const std::string &b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
  }
  inline bool operator==(const std::string &a, const secure_string &b) {
    return b == a;
  }
  inline bool operator!=(const secure_string &a, const std::string &b) {
    return !(a == b);
  }
  inline bool operator!=(const std::string &a, const secure_string &b) {
    return !(b == a);
  }

}  // namespace kmipcore

#endif  // KMIPCORE_SECURE_MEMORY_HPP
