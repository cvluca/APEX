#pragma once

#include "utils.h"
#include "radix-fwd.h"
#include "apex-fwd.h"
#include "base/psr-ciphertext.h"
#include "base/seg-range.h"

namespace apex {

class RadixCiphertextImpl : public PSRCiphertextBase {
public:
  RadixCiphertextImpl(
    ConstApexContext& ctx,
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> segments,
    std::vector<SegRange> segmentRanges,
    uint32_t radix,
    bool carryEvaluated,
    uint32_t fracSegCount = 0)
    : PSRCiphertextBase(std::move(segments)),
      ctx(ctx),
      segmentRanges(std::move(segmentRanges)),
      radix(radix),
      carryEvaluated(carryEvaluated),
      fracSegCount(fracSegCount) {}


  uint32_t GetRadix() const
  {
    return this->radix;
  }

  std::vector<SegRange>& GetSegmentRanges()
  {
    return this->segmentRanges;
  }

  void SetCarryEvaluated(bool carryEvaluated)
  {
    this->carryEvaluated = carryEvaluated;
  }

  uint32_t GetFracSegCount() const {
    return this->fracSegCount;
  }

  void SetFracSegCount(uint32_t fracSegCount) {
    this->fracSegCount = fracSegCount;
  }

  RadixCiphertext Clone() const;

  bool GetCarryEvaluated() const
  {
    return this->carryEvaluated;
  }

  void SubSegmentRange(const SegRange& range, size_t segmentIndex)
  {
    if (segmentIndex >= segments.size()) {
      throw std::out_of_range("Segment index out of range");
    }
    segmentRanges[segmentIndex].Sub(range);
  }

  void AddSegmentRange(const SegRange& range, size_t segmentIndex)
  {
    if (segmentIndex >= segments.size()) {
      throw std::out_of_range("Segment index out of range");
    }
    segmentRanges[segmentIndex].Add(range);
  }

private:
  ConstApexContext ctx;
  std::vector<SegRange> segmentRanges;
  uint32_t radix;
  bool carryEvaluated;
  uint32_t fracSegCount;
}; // class RadixCiphertext

inline RadixCiphertext MakeRadixCiphertext(
  ConstApexContext ctx,
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> segments,
  std::vector<SegRange> segmentRanges,
  uint32_t radix,
  bool carryEvaluated,
  uint32_t fracSegCount = 0)
{
  return std::make_shared<RadixCiphertextImpl>(ctx, std::move(segments), std::move(segmentRanges), radix, carryEvaluated, fracSegCount);
}

} // namespace apex
