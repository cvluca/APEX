#pragma once

#include "utils.h"
#include "base/psr-encoder.h"
#include <vector>
#include <cstdint>
#include <memory>

namespace apex {

class RadixEncoder : public PSREncoder {
public:
  RadixEncoder(uint32_t radix, uint32_t intSegCount, uint32_t fracSegCount)
    : PSREncoder(intSegCount + fracSegCount),
    radix(radix), intSegCount(intSegCount), fracSegCount(fracSegCount) {}

  virtual ~RadixEncoder() = default;

  virtual void EncodeToSegments(
    const void* values,
    size_t count,
    std::vector<std::vector<int64_t>>& segments) const = 0;

  virtual void DecodeFromSegments(
    const std::vector<std::vector<int64_t>>& segments,
    void* values,
    size_t count
  ) const;

  virtual std::vector<SegRange> GetSegmentRanges() const = 0;

  uint32_t GetFracSegCount() const { return fracSegCount; }
  uint32_t GetIntSegCount() const { return intSegCount; }
  uint32_t GetFractionalBits() const { return fracSegCount * radix; }

  uint32_t GetRadix() const { return radix; }

protected:
  uint32_t radix;
  uint32_t intSegCount;
  uint32_t fracSegCount;
};

class SignedIntEncoder : public RadixEncoder {
public:
  SignedIntEncoder(uint32_t radix, uint32_t intSegCount, uint32_t fracSegCount = 0)
    : RadixEncoder(radix, intSegCount, fracSegCount) {}

  void EncodeToSegments(
    const void* values,
    size_t count,
    std::vector<std::vector<int64_t>>& segments) const override;

  std::vector<SegRange> GetSegmentRanges() const override;
};

class UnsignedIntEncoder : public RadixEncoder {
public:
  UnsignedIntEncoder(uint32_t radix, uint32_t intSegCount, uint32_t fracSegCount = 0)
    : RadixEncoder(radix, intSegCount, fracSegCount) {}

  void EncodeToSegments(
    const void* values,
    size_t count,
    std::vector<std::vector<int64_t>>& segments) const override;

  std::vector<SegRange> GetSegmentRanges() const override;
};

} // namespace apex
