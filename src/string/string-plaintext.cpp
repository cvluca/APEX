#include "string/string-plaintext.h"
#include "string/string-encoder.h"
#include "utils.h"

namespace apex {

// Helper functions to check character types
namespace {
  inline bool is_punctuation(char c) {
    return c == '!' || c == '"' || c == '\'' || c == '(' || c == ')' ||
           c == ',' || c == '-' || c == '.' || c == '/' || c == ':' ||
           c == ';' || c == '?';
  }

  inline bool is_symbol(char c) {
    return c == '#' || c == '$' || c == '%' || c == '&' || c == '*' ||
           c == '+' || c == '<' || c == '=' || c == '>' || c == '@';
  }

  inline bool is_bracket(char c) {
    return c == '[' || c == ']' || c == '{' || c == '}' ||
           c == '(' || c == ')';
  }

  inline bool is_special(char c) {
    return c == '^' || c == '_' || c == '`' || c == '|' ||
           c == '~' || c == '\\';
  }

  inline bool is_control(char c) {
    // Control characters: ASCII 1-31 and 127 (DEL), excluding '\0'
    return (c >= 1 && c <= 31) || c == 127;
  }
}

void StringPlaintextImpl::SetSegments(
  const std::vector<lbcrypto::Plaintext>& newSegments,
  const std::vector<lbcrypto::Plaintext>& newMask,
  uint32_t radix,
  size_t max_length,
  std::vector<int64_t> segment_max_values)
{
  this->segments = newSegments;
  this->mask = newMask;
  this->radix = radix;
  this->maxLength = max_length;
  this->segmentMaxValues = std::move(segment_max_values);
  this->charSegmentCount = (7 + radix - 1) / radix;

  if (this->segments.empty()) {
    this->values.clear();
    return;
  }

  const uint32_t numStrings = this->segments[0]->GetLength();
  this->values = std::vector<std::string>(numStrings);

  // Decode bit-slice segments back to strings
  for (size_t stringIdx = 0; stringIdx < numStrings; ++stringIdx) {
    std::string& result = this->values[stringIdx];
    result.clear();
    result.reserve(maxLength);

    // Decode each character position
    for (size_t charPos = 0; charPos < maxLength; ++charPos) {
      // Reconstruct ASCII value from bit-slice segments
      int64_t asciiValue = 0;
      for (uint32_t segIdx = 0; segIdx < charSegmentCount; ++segIdx) {
        size_t segmentIndex = charPos * charSegmentCount + segIdx;
        const auto& segment = this->segments[segmentIndex];
        const auto& packedValues = segment->GetPackedValue();
        int64_t segValue = packedValues[stringIdx];
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

} // namespace apex
