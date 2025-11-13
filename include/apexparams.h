#pragma once

#include "utils.h"

namespace apex {

class ApexParams {
public:
  ApexParams() : radix(2), segmentCount(4), fracSegmentCount(0) {
    // Calculate charSegmentCount for 7-bit ASCII
    charSegmentCount = (7 + radix - 1) / radix;
  }

  void SetRadix(uint32_t r)
  {
    // redix need to be power of 2
    // if (r < 1 || (r & (r - 1)) != 0) {
    //   OPENFHE_THROW("ApexParams: Radix must be a positive power of 2");
    // }

    radix = r;
    // Automatically recalculate charSegmentCount for 7-bit ASCII
    charSegmentCount = (7 + radix - 1) / radix;
  }

  uint32_t GetRadix() const
  {
    return radix;
  }

  void SetSegmentCount(uint32_t n)
  {
    if (n < 1) {
      OPENFHE_THROW("ApexParams: Segment count must be a positive integer");
    }

    if (n <= fracSegmentCount) {
      // OPENFHE_THROW("ApexParams: Segment count must be greater than fractional segments");
      fracSegmentCount = 0;
    }

    segmentCount = n;
  }

  uint32_t GetSegmentCount() const
  {
    return segmentCount;
  }

  void SetFracSegmentCount(uint32_t segments)
  {
    if (segments >= segmentCount) {
      OPENFHE_THROW("ApexParams: Fractional segments must be less than total segment count");
    }
    fracSegmentCount = segments;
  }

  uint32_t GetFracSegmentCount() const
  {
    return fracSegmentCount;
  }

  // Helper methods to get precision information
  uint32_t GetFractionalBits() const
  {
    return fracSegmentCount * radix;
  }

  uint32_t GetIntegerSegments() const
  {
    return segmentCount - fracSegmentCount;
  }

  uint32_t GetCharSegmentCount() const
  {
    return charSegmentCount;
  }

private:
  uint32_t radix;
  uint32_t segmentCount;
  uint32_t fracSegmentCount;  // Number of fractional segments
  uint32_t charSegmentCount;  // Number of segments per character (for string encoding)
};

} // namespace apex
