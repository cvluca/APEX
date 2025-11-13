#include "string/string-encoder.h"
#include <algorithm>

namespace apex {

void StringEncoder::EncodeToSegments(
    const void* values,
    size_t count,
    std::vector<std::vector<int64_t>>& segments) const {

  const auto* stringVector = static_cast<const std::vector<std::string>*>(values);

  if (stringVector->size() != count) {
    OPENFHE_THROW("StringEncoder::EncodeToSegments: values size doesn't match count");
  }

  // Validate string lengths
  for (const auto& value : *stringVector) {
    if (value.size() > maxLength) {
      OPENFHE_THROW("StringEncoder::EncodeToSegments: string length exceeds max_length " +
                   std::to_string(maxLength) + ": " + value);
    }
  }

  // Total segments = maxLength * charSegmentCount
  size_t totalSegments = maxLength * charSegmentCount;
  segments.resize(totalSegments);
  for (size_t i = 0; i < totalSegments; ++i) {
    segments[i].resize(count, 0);
  }

  // Encode each string
  for (size_t stringIdx = 0; stringIdx < count; ++stringIdx) {
    const auto& value = (*stringVector)[stringIdx];

    // Encode each character in the string
    for (size_t charPos = 0; charPos < value.size(); ++charPos) {
      char c = value[charPos];

      // Use ASCII value directly (7-bit: 0-127)
      int64_t asciiValue = static_cast<unsigned char>(c) & 0x7F;  // Ensure 7-bit

      // Decompose ASCII value into bit-slice segments
      for (uint32_t segIdx = 0; segIdx < charSegmentCount; ++segIdx) {
        uint32_t shift = segIdx * radix;
        uint32_t mask = (1 << radix) - 1;
        int64_t segValue = (asciiValue >> shift) & mask;

        size_t segmentIndex = charPos * charSegmentCount + segIdx;
        segments[segmentIndex][stringIdx] = segValue;
      }
    }

    // Remaining character positions stay 0 (null character)
  }
}

void StringEncoder::DecodeFromSegments(
    const std::vector<std::vector<int64_t>>& segments,
    void* values,
    size_t count) const {

  auto* stringVector = static_cast<std::vector<std::string>*>(values);

  size_t totalSegments = maxLength * charSegmentCount;
  if (segments.size() != totalSegments) {
    OPENFHE_THROW("StringEncoder::DecodeFromSegments: segments size doesn't match maxLength * charSegmentCount");
  }

  if (segments.empty()) {
    stringVector->resize(count);
    return;
  }

  if (segments[0].size() != count) {
    OPENFHE_THROW("StringEncoder::DecodeFromSegments: segment size doesn't match count");
  }

  stringVector->resize(count);

  // Decode each string
  for (size_t stringIdx = 0; stringIdx < count; ++stringIdx) {
    std::string& result = (*stringVector)[stringIdx];
    result.clear();
    result.reserve(maxLength);

    // Decode each character position
    for (size_t charPos = 0; charPos < maxLength; ++charPos) {
      // Reconstruct ASCII value from bit-slice segments
      int64_t asciiValue = 0;
      for (uint32_t segIdx = 0; segIdx < charSegmentCount; ++segIdx) {
        size_t segmentIndex = charPos * charSegmentCount + segIdx;
        int64_t segValue = segments[segmentIndex][stringIdx];
        asciiValue |= (segValue << (segIdx * radix));
      }

      // Stop at first null character (ASCII 0)
      if (asciiValue == 0) {
        break;
      }

      char decodedChar = static_cast<char>(asciiValue & 0x7F);
      result.push_back(decodedChar);
    }
  }
}

std::vector<SegRange> StringEncoder::GetSegmentRanges() const {
  // Calculate segment ranges for bit-slice representation
  // 7-bit ASCII: 0-127, decomposed into radix-bit segments

  size_t totalSegments = maxLength * charSegmentCount;
  std::vector<SegRange> ranges;
  ranges.reserve(totalSegments);

  // For each character position
  for (size_t charPos = 0; charPos < maxLength; ++charPos) {
    // For each bit-segment of this character
    for (uint32_t segIdx = 0; segIdx < charSegmentCount; ++segIdx) {
      uint32_t bitsInSegment = radix;

      // Last segment of a character may have fewer bits
      uint32_t bitsUsed = segIdx * radix;
      if (bitsUsed + radix > 7) {
        bitsInSegment = 7 - bitsUsed;  // Remaining bits for 7-bit ASCII
      }

      int64_t maxVal = (1 << bitsInSegment) - 1;  // 2^bits - 1
      ranges.push_back(SegRange(0, maxVal));
    }
  }

  return ranges;
}

void StringEncoder::EncodeToMask(
    const void* values,
    size_t count,
    std::vector<std::vector<int64_t>>& mask) const {

  const auto* stringVector = static_cast<const std::vector<std::string>*>(values);

  if (stringVector->size() != count) {
    OPENFHE_THROW("StringEncoder::EncodeToMask: values size doesn't match count");
  }

  // Initialize mask: mask[i] = character position i presence across all strings
  mask.resize(maxLength);
  for (size_t i = 0; i < maxLength; ++i) {
    mask[i].resize(count, 0);
  }

  // Create mask for each string
  for (size_t stringIdx = 0; stringIdx < count; ++stringIdx) {
    const auto& value = (*stringVector)[stringIdx];

    // Mark character positions as present
    for (size_t charPos = 0; charPos < value.size() && charPos < maxLength; ++charPos) {
      mask[charPos][stringIdx] = 1;
    }

    // Remaining positions stay 0 (no character present)
  }
}

} // namespace apex
