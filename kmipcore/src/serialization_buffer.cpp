#include "kmipcore/serialization_buffer.hpp"

#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_errors.hpp"

#include <cstring>

namespace kmipcore {

  SerializationBuffer::SerializationBuffer(size_t initial_capacity)
    : current_offset_(0) {
    // Pre-allocate to requested capacity
    // This single allocation covers most common messages
    buffer_.reserve(initial_capacity);
  }

  void SerializationBuffer::writeByte(uint8_t value) {
    ensureSpace(1);

    // Ensure buffer is large enough (resize if needed)
    if (current_offset_ >= buffer_.size()) {
      buffer_.resize(current_offset_ + 1);
    }

    buffer_[current_offset_++] = value;
  }

  void SerializationBuffer::writeBytes(std::span<const std::byte> data) {
    if (data.empty()) {
      return;
    }

    const size_t length = data.size();

    ensureSpace(length);

    // Ensure buffer is large enough (resize to accommodate)
    if (current_offset_ + length > buffer_.size()) {
      buffer_.resize(current_offset_ + length);
    }

    std::memcpy(&buffer_[current_offset_], data.data(), length);
    current_offset_ += length;
  }

  void SerializationBuffer::writePadded(std::span<const std::byte> data) {
    const size_t length = data.size();

    // Write data first
    writeBytes(data);

    // Calculate KMIP padding (align to TTLV_ALIGNMENT bytes)
    // Formula: (A - (size % A)) % A gives 0 for multiples of A,
    // otherwise 1..A-1
    size_t padding =
        (TTLV_ALIGNMENT - (length % TTLV_ALIGNMENT)) % TTLV_ALIGNMENT;

    // Write zero-fill padding
    if (padding > 0) {
      ensureSpace(padding);

      // Ensure buffer is large enough
      if (current_offset_ + padding > buffer_.size()) {
        buffer_.resize(current_offset_ + padding);
      }

      // Zero-fill padding
      std::memset(&buffer_[current_offset_], 0, padding);
      current_offset_ += padding;
    }
  }

  void SerializationBuffer::ensureSpace(size_t required_bytes) {
    // Check if we have enough capacity
    if (current_offset_ + required_bytes <= buffer_.capacity()) {
      return;  // No reallocation needed
    }

    // Need to expand
    expandCapacity(current_offset_ + required_bytes);
  }

  void SerializationBuffer::expandCapacity(size_t required) {
    // Start with current capacity
    size_t new_capacity = buffer_.capacity();

    if (new_capacity == 0) {
      new_capacity = MIN_CAPACITY;
    }

    // Double capacity until we have enough
    while (new_capacity < required) {
      new_capacity *= 2;
    }

    // Cap maximum to prevent pathological allocations
    if (new_capacity > MAX_CAPACITY) {
      throw KmipException(
          "SerializationBuffer exceeded maximum size of 100 MB"
      );
    }

    buffer_.reserve(new_capacity);
  }

  std::vector<uint8_t> SerializationBuffer::release() {
    // Copy only the serialized bytes into the result.
    // Use iterators instead of buffer_.data() + offset to avoid pointer
    // arithmetic on a potentially-null data() when size()==0 (UB even for +0).
    std::vector<uint8_t> result(
        buffer_.begin(),
        buffer_.begin() + static_cast<std::ptrdiff_t>(current_offset_)
    );

    // Reset write position and logical size but KEEP the reserved capacity so
    // the buffer can be reused immediately without a new heap allocation.
    // Callers that need to reclaim memory explicitly can call shrink().
    buffer_.clear();  // size -> 0, capacity unchanged
    current_offset_ = 0;

    return result;  // NRVO / move
  }

  void SerializationBuffer::shrink() {
    // Aggressively release all heap memory (capacity included).
    // Use the swap-with-empty idiom because shrink_to_fit() is advisory.
    std::vector<uint8_t>().swap(buffer_);
    current_offset_ = 0;
  }

}  // namespace kmipcore
