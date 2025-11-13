#pragma once

#include "utils.h"
#include "seg-range.h"
#include <vector>
#include <cstdint>
#include <memory>

namespace apex {

class PSREncoder {
public:
  PSREncoder(uint32_t segmentCount) : segmentCount(segmentCount) {}
  virtual ~PSREncoder() = default;

  virtual void EncodeToSegments(
    const void* values,
    size_t count,
    std::vector<std::vector<int64_t>>& segments) const = 0;

  virtual void DecodeFromSegments(
    const std::vector<std::vector<int64_t>>& segments,
    void* values,
    size_t count) const = 0;

  virtual std::vector<SegRange> GetSegmentRanges() const {
    return {};
  }

  uint32_t GetSegmentCount() const { return segmentCount; }

protected:
  uint32_t segmentCount;
};

using PSREncoderPtr = std::shared_ptr<PSREncoder>;

} // namespace apex
