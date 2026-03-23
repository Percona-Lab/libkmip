#include "kmipcore/serialization_buffer.hpp"

#include <cstring>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

using namespace kmipcore;

// Throws std::runtime_error with file/line context on failure.
// Unlike assert(), this propagates through the try/catch in main() so every
// test failure is reported cleanly instead of calling abort().
#define EXPECT(cond)                                                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      throw std::runtime_error(                                                \
          std::string(__FILE__) + ":" + std::to_string(__LINE__) +             \
          ": expectation failed: " #cond                                       \
      );                                                                       \
    }                                                                          \
  } while (false)

void testWriteByte() {
  SerializationBuffer buf(100);

  buf.writeByte(0xAB);
  buf.writeByte(0xCD);
  buf.writeByte(0xEF);

  EXPECT(buf.size() == 3);
  EXPECT(buf.data()[0] == 0xAB);
  EXPECT(buf.data()[1] == 0xCD);
  EXPECT(buf.data()[2] == 0xEF);

  std::cout << "✓ testWriteByte passed" << std::endl;
}

void testWriteBytes() {
  SerializationBuffer buf(100);

  uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
  buf.writeBytes(std::as_bytes(std::span{data}));

  EXPECT(buf.size() == 5);
  EXPECT(std::memcmp(buf.data(), data, 5) == 0);

  std::cout << "✓ testWriteBytes passed" << std::endl;
}

void testWritePadded() {
  SerializationBuffer buf(100);

  // Write 3 bytes (should add 5 bytes of padding to reach 8)
  uint8_t data[] = {0x01, 0x02, 0x03};
  buf.writePadded(std::as_bytes(std::span{data}));

  EXPECT(buf.size() == 8);
  EXPECT(buf.data()[0] == 0x01);
  EXPECT(buf.data()[1] == 0x02);
  EXPECT(buf.data()[2] == 0x03);
  EXPECT(buf.data()[3] == 0x00);  // Padding
  EXPECT(buf.data()[4] == 0x00);  // Padding
  EXPECT(buf.data()[5] == 0x00);  // Padding
  EXPECT(buf.data()[6] == 0x00);  // Padding
  EXPECT(buf.data()[7] == 0x00);  // Padding

  std::cout << "✓ testWritePadded passed" << std::endl;
}

void testMultiplePaddedWrites() {
  SerializationBuffer buf(100);

  // 3 bytes -> 8 bytes padded
  uint8_t data1[] = {0x01, 0x02, 0x03};
  buf.writePadded(std::as_bytes(std::span{data1}));

  // 2 bytes -> 8 bytes padded
  uint8_t data2[] = {0x04, 0x05};
  buf.writePadded(std::as_bytes(std::span{data2}));

  EXPECT(buf.size() == 16);  // 8 + 8

  // First block (8 bytes)
  EXPECT(buf.data()[0] == 0x01);
  EXPECT(buf.data()[1] == 0x02);
  EXPECT(buf.data()[2] == 0x03);
  EXPECT(buf.data()[7] == 0x00);

  // Second block (8 bytes)
  EXPECT(buf.data()[8] == 0x04);
  EXPECT(buf.data()[9] == 0x05);
  EXPECT(buf.data()[15] == 0x00);

  std::cout << "✓ testMultiplePaddedWrites passed" << std::endl;
}

void testAutoExpansion() {
  SerializationBuffer buf(10);  // Small initial size

  EXPECT(buf.capacity() >= 10);

  // Write more than initial capacity
  for (int i = 0; i < 50; ++i) {
    buf.writeByte(static_cast<uint8_t>(i & 0xFF));
  }

  EXPECT(buf.size() == 50);
  EXPECT(buf.capacity() >= 50);

  // Verify data is correct
  for (int i = 0; i < 50; ++i) {
    EXPECT(buf.data()[i] == (i & 0xFF));
  }

  std::cout << "✓ testAutoExpansion passed" << std::endl;
}

void testReset() {
  SerializationBuffer buf(100);

  buf.writeByte(0xFF);
  buf.writeByte(0xFF);
  buf.writeByte(0xFF);

  EXPECT(buf.size() == 3);

  buf.reset();

  EXPECT(buf.size() == 0);
  EXPECT(buf.capacity() >= 100);  // Capacity preserved

  // Can reuse the buffer
  buf.writeByte(0xAA);
  EXPECT(buf.size() == 1);
  EXPECT(buf.data()[0] == 0xAA);

  std::cout << "✓ testReset passed" << std::endl;
}

void testRelease() {
  SerializationBuffer buf(100);

  uint8_t data[] = {0x11, 0x22, 0x33, 0x44, 0x55};
  buf.writeBytes(std::as_bytes(std::span{data}));

  EXPECT(buf.size() == 5);

  std::vector<uint8_t> result = buf.release();

  EXPECT(result.size() == 5);
  EXPECT(result[0] == 0x11);
  EXPECT(result[1] == 0x22);
  EXPECT(result[2] == 0x33);
  EXPECT(result[3] == 0x44);
  EXPECT(result[4] == 0x55);

  // Buffer is reset but capacity is kept for reuse
  EXPECT(buf.size() == 0);
  EXPECT(buf.capacity() >= 100);

  std::cout << "✓ testRelease passed" << std::endl;
}

void testRemaining() {
  SerializationBuffer buf(100);

  EXPECT(buf.remaining() == 100);

  buf.writeByte(0xFF);
  EXPECT(buf.remaining() == 99);

  for (int i = 0; i < 99; ++i) {
    buf.writeByte(0xFF);
  }

  EXPECT(buf.size() == 100);
  EXPECT(buf.remaining() == 0);

  // Should auto-expand
  buf.writeByte(0xFF);
  EXPECT(buf.size() == 101);
  EXPECT(buf.remaining() > 0);

  std::cout << "✓ testRemaining passed" << std::endl;
}

void testLargeMessage() {
  SerializationBuffer buf(8192);  // Default KMIP buffer size

  // Simulate writing a large message
  for (int i = 0; i < 1000; ++i) {
    uint8_t data[] = {
        static_cast<uint8_t>((i >> 24) & 0xFF),
        static_cast<uint8_t>((i >> 16) & 0xFF),
        static_cast<uint8_t>((i >> 8) & 0xFF),
        static_cast<uint8_t>(i & 0xFF),
    };
    buf.writePadded(std::as_bytes(std::span{data}));
  }

  // Each write is 4 bytes + 4 bytes padding = 8 bytes
  // 1000 writes = 8000 bytes
  EXPECT(buf.size() == 8000);

  std::cout << "✓ testLargeMessage passed" << std::endl;
}

void testConsecutiveAllocation() {
  // Test 10 sequential buffers
  for (int iteration = 0; iteration < 10; ++iteration) {
    SerializationBuffer buf(512);

    for (int i = 0; i < 64; ++i) {
      auto val = static_cast<uint8_t>((iteration * 64 + i) & 0xFF);
      buf.writeByte(val);
    }

    EXPECT(buf.size() == 64);

    auto result = buf.release();
    EXPECT(result.size() == 64);
  }

  std::cout << "✓ testConsecutiveAllocation passed" << std::endl;
}

int main() {
  std::cout << "Running SerializationBuffer tests...\n" << std::endl;

  try {
    testWriteByte();
    testWriteBytes();
    testWritePadded();
    testMultiplePaddedWrites();
    testAutoExpansion();
    testReset();
    testRelease();
    testRemaining();
    testLargeMessage();
    testConsecutiveAllocation();

    std::cout << "\n✅ All SerializationBuffer tests passed!" << std::endl;
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "❌ Test failed: " << e.what() << std::endl;
    return 1;
  }
}
