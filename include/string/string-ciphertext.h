#pragma once

#include "string-fwd.h"
#include "apex-fwd.h"
#include "base/psr-ciphertext.h"

namespace apex {

class StringCiphertextImpl : public PSRCiphertextBase {
public:
  StringCiphertextImpl(
    ConstApexContext& ctx,
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> segments,
    std::vector<int64_t> segment_max_values,
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> mask,
    uint32_t radix,
    size_t max_length
  ) : PSRCiphertextBase(std::move(segments)),
      ctx(ctx),
      mask(std::move(mask)),
      radix(radix),
      maxLength(max_length),
      segmentMaxValues(std::move(segment_max_values))
  {
    // Calculate charSegmentCount: ceil(7 / radix) for 7-bit ASCII
    charSegmentCount = (7 + radix - 1) / radix;

    // Validate segments size
    if (this->segments.size() != maxLength * charSegmentCount) {
      OPENFHE_THROW("StringCiphertextImpl: segments size must equal maxLength * charSegmentCount");
    }

    // Mask size should equal maxLength (one per character position)
    if (this->mask.size() != maxLength) {
      OPENFHE_THROW("StringCiphertextImpl: mask size must equal maxLength");
    }

    // Validate segmentMaxValues size
    if (this->segmentMaxValues.size() != this->segments.size()) {
      OPENFHE_THROW("StringCiphertextImpl: segmentMaxValues size must equal segments size");
    }
  }

  const std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& GetMask() const
  {
    return this->mask;
  }

  size_t GetLength() const
  {
    return maxLength;
  }

  uint32_t GetRadix() const
  {
    return this->radix;
  }

  uint32_t GetCharSegmentCount() const
  {
    return this->charSegmentCount;
  }

  size_t GetMaxLength() const
  {
    return this->maxLength;
  }

  const std::vector<int64_t>& GetSegmentMaxValues() const
  {
    return this->segmentMaxValues;
  }

private:
  ConstApexContext ctx;
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> mask;
  uint32_t radix = 0;
  uint32_t charSegmentCount = 0;
  size_t maxLength = 0;
  std::vector<int64_t> segmentMaxValues;  // Max value for each segment [0, max]
};

inline StringCiphertext MakeStringCiphertext(
    ConstApexContext ctx,
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> segments,
    std::vector<int64_t> segment_max_values,
    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> mask,
    uint32_t radix,
    size_t max_length
) {
  return std::make_shared<StringCiphertextImpl>(ctx, std::move(segments), std::move(segment_max_values), std::move(mask), radix, max_length);
}

} // namespace apex
