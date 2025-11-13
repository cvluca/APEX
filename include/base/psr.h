#pragma once

#include "utils.h"
#include <vector>
#include <memory>

namespace apex {

// PSR (Positional Segmented Representation) base class for plaintexts
template<typename SegmentType>
class PSR {
public:
  PSR() = default;

  PSR(std::vector<SegmentType> segments)
    : segments(std::move(segments)) {}

  virtual ~PSR() = default;

  const std::vector<SegmentType>& GetSegments() const {
    return segments;
  }

  std::vector<SegmentType>& GetSegments() {
    return segments;
  }

  size_t GetSegmentCount() const {
    return segments.size();
  }

  bool HasSegments() const {
    return !segments.empty();
  }


protected:
  void SetSegments(std::vector<SegmentType> newSegments) {
    segments = std::move(newSegments);
  }

  std::vector<SegmentType> segments;
};

} // namespace apex
