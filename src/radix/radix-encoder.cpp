#include "radix/radix-encoder.h"
#include "utils.h"
#include <cstring>
#include <cmath>
#include <limits>

namespace apex {

void RadixEncoder::DecodeFromSegments(
    const std::vector<std::vector<int64_t>>& segments,
    void* values,
    size_t count) const
{
  if (count > segments[0].size()) {
    OPENFHE_THROW("DecodeFromSegments: count exceeds segment size");
  }

  int64_t* int_values = static_cast<int64_t*>(values);

  for (size_t i = 0; i < count; ++i) {
    int_values[i] = 0;
    for (size_t j = 0; j < segmentCount; ++j) {
      int_values[i] += segments[j][i] * (1ULL << (j * radix));
    }
  }
}

void SignedIntEncoder::EncodeToSegments(
    const void* values,
    size_t count,
    std::vector<std::vector<int64_t>>& segments) const
{
  const int64_t* int_values = static_cast<const int64_t*>(values);
  const uint32_t integerBits = segmentCount * radix;
  const int64_t maxValue = (1ULL << (integerBits - 1)) - 1;
  const int64_t minValue = -(1ULL << (integerBits - 1));

  segments.resize(segmentCount);
  for (auto& segment : segments) {
    segment.resize(count, 0);
  }

  for (size_t i = 0; i < count; ++i) {
    int64_t value = int_values[i];
    if (value < minValue || value > maxValue) {
      OPENFHE_THROW("Value out of range for SignedIntEncoder: " + std::to_string(value));
    }

    for (size_t j = 0; j < segmentCount; ++j) {
      uint64_t mask = ((1ULL << radix) - 1) << (j * radix);
      segments[j][i] = static_cast<int64_t>((value & mask) >> (j * radix));
    }

    // Sign extension for negative values in the most significant integer segment
    if (value < 0) {
      segments[segmentCount - 1][i] |= ((-1ULL >> radix) << radix);
    }
  }
}


std::vector<SegRange> SignedIntEncoder::GetSegmentRanges() const {
  std::vector<SegRange> ranges(segmentCount, SegRange(0, (1ULL << radix) - 1));
  // Most significant integer segment can be negative (if we have integer segments)
  ranges[segmentCount - 1] = SegRange(-(1ULL << (radix-1)), (1ULL << (radix-1)) - 1);
  return ranges;
}

void UnsignedIntEncoder::EncodeToSegments(
    const void* values, 
    size_t count,
    std::vector<std::vector<int64_t>>& segments) const 
{
  const uint64_t* uint_values = static_cast<const uint64_t*>(values);
  const uint32_t precision = segmentCount * radix;
  const uint64_t maxValue = (segmentCount * radix >= 64) ? UINT64_MAX : ((1ULL << precision) - 1);

  segments.resize(segmentCount);
  for (auto& segment : segments) {
    segment.resize(count, 0);
  }

  for (size_t i = 0; i < count; ++i) {
    uint64_t value = uint_values[i];
    if (value > maxValue) {
      OPENFHE_THROW("Value out of range for UnsignedIntEncoder: " + std::to_string(value));
    }

    for (size_t j = 0; j < segmentCount; ++j) {
      uint64_t mask = ((1ULL << radix) - 1) << (j * radix);
      segments[j][i] = static_cast<int64_t>((value & mask) >> (j * radix));
    }
  }
}


std::vector<SegRange> UnsignedIntEncoder::GetSegmentRanges() const {
  return std::vector<SegRange>(segmentCount, SegRange(0, (1ULL << radix) - 1));
}

} // namespace apex
