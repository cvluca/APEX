#include "radix/radix-plaintext.h"
#include "radix/radix-encoder.h"

namespace apex {

void RadixPlaintextImpl::SetSegments(
  const std::vector<lbcrypto::Plaintext>& newSegments,
  std::vector<SegRange> segmentRanges,
  uint32_t radix,
  uint32_t fracSegCount)
{
  this->segments = newSegments;
  this->radix = radix;
  this->segmentRanges = std::move(segmentRanges);
  this->fracSegCount = fracSegCount;

  const uint32_t length = this->segments[0]->GetLength();
  this->values = std::vector<int64_t>(length, 0);

  // Convert segments to int64 vectors for encoder
  std::vector<std::vector<int64_t>> segmentValues;
  segmentValues.resize(this->segments.size());
  for (size_t i = 0; i < this->segments.size(); ++i) {
    const auto& packedValue = this->segments[i]->GetPackedValue();
    segmentValues[i] = std::vector<int64_t>(packedValue.begin(), packedValue.end());

    // Validate ranges
    for (size_t j = 0; j < length; ++j) {
      if (segmentValues[i][j] < this->segmentRanges[i].GetMin() ||
          segmentValues[i][j] > this->segmentRanges[i].GetMax())
      {
        OPENFHE_THROW("RadixPlaintextImpl::SetSegments: Value out of range for segment " +
          std::to_string(i) + ": " + std::to_string(segmentValues[i][j]) +
          " not in [" + std::to_string(this->segmentRanges[i].GetMin()) + ", " +
          std::to_string(this->segmentRanges[i].GetMax()) + "]");
      }
    }
  }

  uint32_t intSegCount = this->segments.size() - fracSegCount;
  SignedIntEncoder encoder(radix, intSegCount, fracSegCount);
  encoder.DecodeFromSegments(segmentValues, this->values.data(), length);
}

} // namespace apex
