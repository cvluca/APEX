#pragma once

#include "utils.h"
#include "string-fwd.h"
#include "base/psr-plaintext.h"

namespace apex {

class StringPlaintextImpl : public PSRPlaintextBase {
public:
  StringPlaintextImpl() {}
  StringPlaintextImpl(
    std::vector<std::string> values,
    std::vector<lbcrypto::Plaintext> segments,
    std::vector<int64_t> segment_max_values,
    std::vector<lbcrypto::Plaintext> mask,
    uint32_t radix,
    size_t max_length
  ) : PSRPlaintextBase(segments),
      values(std::move(values)),
      mask(std::move(mask)),
      radix(radix),
      maxLength(max_length),
      segmentMaxValues(std::move(segment_max_values))
  {
    // Calculate charSegmentCount: ceil(7 / radix) for 7-bit ASCII
    charSegmentCount = (7 + radix - 1) / radix;

    // Validate segments size
    if (this->segments.size() != maxLength * charSegmentCount) {
      OPENFHE_THROW("StringPlaintextImpl: segments size must equal maxLength * charSegmentCount");
    }

    // Mask size should equal maxLength (one per character position)
    if (this->mask.size() != maxLength) {
      OPENFHE_THROW("StringPlaintextImpl: mask size must equal maxLength");
    }

    // Validate segmentMaxValues size
    if (this->segmentMaxValues.size() != this->segments.size()) {
      OPENFHE_THROW("StringPlaintextImpl: segmentMaxValues size must equal segments size");
    }
  }

  const std::vector<lbcrypto::Plaintext>& GetMask() const
  {
    return this->mask;
  }

  void SetSegments(
    const std::vector<lbcrypto::Plaintext>& segments,
    const std::vector<lbcrypto::Plaintext>& mask,
    uint32_t radix,
    size_t max_length,
    std::vector<int64_t> segment_max_values);

  const std::vector<std::string>& GetPackedValue() const
  {
    return this->values;
  }

  size_t GetLength() const
  {
    return this->maxLength;
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
  std::vector<std::string> values;
  std::vector<lbcrypto::Plaintext> mask;
  uint32_t radix = 0;
  uint32_t charSegmentCount = 0;
  size_t maxLength = 0;
  std::vector<int64_t> segmentMaxValues;  // Max value for each segment [0, max]
};

inline StringPlaintext MakeStringPlaintext(
  std::vector<std::string> values,
  std::vector<lbcrypto::Plaintext> segments,
  std::vector<int64_t> segment_max_values,
  std::vector<lbcrypto::Plaintext> mask,
  uint32_t radix,
  size_t max_length)
{
  return std::make_shared<StringPlaintextImpl>(
    std::move(values), std::move(segments), std::move(segment_max_values), std::move(mask), radix, max_length);
}

} // namespace apex
