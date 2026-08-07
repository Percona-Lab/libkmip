/* Copyright (c) 2026 Percona LLC and/or its affiliates. All rights reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmipcore/secure_memory.hpp"
#include "kmipcore/serialization_buffer.hpp"

#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

using namespace kmipcore;

#define EXPECT(cond)                                                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      throw std::runtime_error(                                                \
          std::string(__FILE__) + ":" + std::to_string(__LINE__) +             \
          ": expectation failed: " #cond                                       \
      );                                                                       \
    }                                                                          \
  } while (false)

void testSecureClearZeroes() {
  unsigned char buf[16];
  for (unsigned char &b : buf) {
    b = 0xAB;
  }
  secure_clear(buf, sizeof(buf));
  for (unsigned char b : buf) {
    EXPECT(b == 0);
  }

  // No-ops must not crash.
  secure_clear(nullptr, 16);
  secure_clear(buf, 0);

  std::cout << "testSecureClearZeroes passed" << std::endl;
}

void testHeterogeneousByteCompare() {
  const std::vector<unsigned char> plain{0x01, 0x02, 0x03};
  secure_bytes secure{0x01, 0x02, 0x03};

  EXPECT(secure == plain);
  EXPECT(plain == secure);
  EXPECT(!(secure != plain));

  secure.push_back(0x04);
  EXPECT(secure != plain);
  EXPECT(plain != secure);

  std::cout << "testHeterogeneousByteCompare passed" << std::endl;
}

void testHeterogeneousStringCompare() {
  const std::string plain = "s3cr3t";
  secure_string secure = "s3cr3t";

  EXPECT(secure == plain);
  EXPECT(plain == secure);
  EXPECT(secure == "s3cr3t");  // basic_string vs const char*
  EXPECT(secure != std::string("other"));

  std::cout << "testHeterogeneousStringCompare passed" << std::endl;
}

// F12: release() must scrub the bytes left behind in the retained capacity.
void testReleaseScrubsRetainedCapacity() {
  SerializationBuffer buf(64);

  const std::vector<uint8_t> secret{0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22};
  buf.writeBytes(std::as_bytes(std::span{secret}));
  EXPECT(buf.size() == secret.size());

  // Capture the storage pointer before release(); clear() keeps capacity, so
  // the pointer stays valid and no reallocation happens.
  const uint8_t *storage = buf.data();
  const size_t written = buf.size();

  const secure_bytes released = buf.release();

  // The returned copy still holds the serialized secret ...
  EXPECT(released.size() == written);
  EXPECT(released[0] == 0xDE);

  // ... but the buffer's retained capacity has been zeroed.
  EXPECT(buf.size() == 0);
  bool all_zero = true;
  for (size_t i = 0; i < written; ++i) {
    if (storage[i] != 0) {
      all_zero = false;
      break;
    }
  }
  EXPECT(all_zero);

  std::cout << "testReleaseScrubsRetainedCapacity passed" << std::endl;
}

void testShrinkReleasesCapacity() {
  SerializationBuffer buf(64);
  const std::vector<uint8_t> secret{0x01, 0x02, 0x03, 0x04};
  buf.writeBytes(std::as_bytes(std::span{secret}));
  EXPECT(buf.capacity() > 0);

  buf.shrink();
  EXPECT(buf.size() == 0);
  EXPECT(buf.capacity() == 0);

  std::cout << "testShrinkReleasesCapacity passed" << std::endl;
}

int main() {
  std::cout << "Running secure_memory tests..." << std::endl;

  try {
    testSecureClearZeroes();
    testHeterogeneousByteCompare();
    testHeterogeneousStringCompare();
    testReleaseScrubsRetainedCapacity();
    testShrinkReleasesCapacity();

    std::cout << "All secure_memory tests passed" << std::endl;
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "Test failed: " << e.what() << std::endl;
    return 1;
  }
}
