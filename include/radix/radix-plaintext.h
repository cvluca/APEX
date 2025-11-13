#pragma once

#include "utils.h"
#include "radix-fwd.h"
#include "base/psr-plaintext.h"
#include "base/seg-range.h"

namespace apex {

class RadixPlaintextImpl : public PSRPlaintextBase {
public:
  RadixPlaintextImpl() : fracSegCount(0) {}
  RadixPlaintextImpl(
    std::vector<int64_t> values,
    std::vector<lbcrypto::Plaintext> segments,
    std::vector<SegRange> segmentRanges,
    uint32_t radix,
    bool carryEvaluated,
    uint32_t fracSegCount = 0
  ) : PSRPlaintextBase(std::move(segments)),
    values(std::move(values)),
    segmentRanges(std::move(segmentRanges)),
    radix(radix),
    carryEvaluated(carryEvaluated),
    fracSegCount(fracSegCount)
  { }


  std::vector<SegRange> GetSegmentRanges() const
  {
    return this->segmentRanges;
  }

  uint32_t GetRadix() const
  {
    return this->radix;
  }

  bool GetCarryEvaluated() const
  {
    return this->carryEvaluated;
  }

  uint32_t GetFracSegCount() const
  {
    return this->fracSegCount;
  }

  uint32_t GetFractionalBits() const
  {
    return this->fracSegCount * this->radix;
  }

  const std::vector<int64_t>& GetPackedValue() const
  {
    return this->values;
  }

  void SetSegments(const std::vector<lbcrypto::Plaintext>& segments,
                   std::vector<SegRange> segmentRanges,
                   uint32_t radix,
                   uint32_t fracSegCount = 0);


  friend std::ostream& operator<<(std::ostream& os, const RadixPlaintextImpl& pt) {
    std::vector<std::vector<int64_t>> segments;
    for (const auto& segment : pt.segments) {
      segments.push_back(segment->GetPackedValue());
    }

    os << "[";
    for (size_t i = 0; i < pt.values.size(); ++i) {
      os << pt.values[i] << " (";
      for (int j = segments.size()-1; j >= 0; --j) {
        os << segments[j][i];
        if (j > 0) {
          os << ", ";
        }
      }
      os << ")";
      if (i < pt.values.size() - 1) {
        os << ", ";
      }
    }
    os << "]\n";
    return os;
  }

private:
  std::vector<int64_t> values;
  std::vector<SegRange> segmentRanges;
  uint32_t radix;
  bool carryEvaluated;
  uint32_t fracSegCount;
}; // class RadixPlaintext

inline RadixPlaintext MakeRadixPlaintext(
  std::vector<int64_t> values,
  std::vector<lbcrypto::Plaintext> segments,
  std::vector<SegRange> segmentRanges,
  uint32_t radix,
  bool carryEvaluated,
  uint32_t fracSegCount = 0)
{
  if (segments.empty()) {
    OPENFHE_THROW("RadixPlaintext: segments must not be empty.");
  }

  if (values.size() != segments[0]->GetLength()) {
    OPENFHE_THROW("RadixPlaintext: values and segments must have the same size.");
  }

  return std::make_shared<RadixPlaintextImpl>(std::move(values), std::move(segments),
                                              std::move(segmentRanges), radix, carryEvaluated, fracSegCount);
}

} // namespace apex
