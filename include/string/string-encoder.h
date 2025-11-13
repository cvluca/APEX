#pragma once

#include "utils.h"
#include "base/psr-encoder.h"
#include "apexparams.h"
#include <vector>
#include <string>
#include <cstdint>

namespace apex {

/**
 * StringEncoder - PSR encoder for string representations
 * Each character is decomposed into multiple bit-slice segments (radix-based)
 * Uses 7-bit ASCII encoding directly (0-127)
 */
class StringEncoder : public PSREncoder {
public:
  StringEncoder(size_t maxLength, const ApexParams& params)
    : PSREncoder(maxLength * params.GetCharSegmentCount()),  // Total segments = maxLength * charSegmentCount
      maxLength(maxLength),
      radix(params.GetRadix()),
      charSegmentCount(params.GetCharSegmentCount())
  {}

  virtual ~StringEncoder() = default;

  /**
   * Encode vector of strings into segments
   * @param values Pointer to vector<string>
   * @param count Number of strings to encode
   * @param segments Output segments[i][j] = character i of string j
   */
  void EncodeToSegments(
    const void* values,
    size_t count,
    std::vector<std::vector<int64_t>>& segments) const override;

  /**
   * Decode segments back to vector of strings
   * @param segments Input segments
   * @param values Pointer to output vector<string>
   * @param count Number of strings to decode
   */
  void DecodeFromSegments(
    const std::vector<std::vector<int64_t>>& segments,
    void* values,
    size_t count) const override;

  /**
   * Get segment ranges for string encoding
   * Each segment can contain values based on the character set
   */
  std::vector<SegRange> GetSegmentRanges() const override;

  /**
   * Get additional encoding information for string mask
   * @param values Input strings
   * @param count Number of strings
   * @param mask Output mask[i][j] = 1 if character i is present in string j
   */
  void EncodeToMask(
    const void* values,
    size_t count,
    std::vector<std::vector<int64_t>>& mask) const;

  size_t GetMaxLength() const { return maxLength; }
  uint32_t GetRadix() const { return radix; }
  uint32_t GetCharSegmentCount() const { return charSegmentCount; }

private:
  size_t maxLength;
  uint32_t radix;
  uint32_t charSegmentCount;
};

using StringEncoderPtr = std::shared_ptr<StringEncoder>;

} // namespace apex
