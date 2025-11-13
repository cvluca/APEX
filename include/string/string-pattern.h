#pragma once

#include "utils.h"
#include "string-fwd.h"
#include "string/string-token.h"

namespace apex {

class StringPatternImpl
{
public:
  StringPatternImpl() = delete;
  StringPatternImpl(std::vector<StringToken> tokens)
      : tokens(std::move(tokens))
  {
    for (const auto& token : this->tokens)
    {
      switch (token->GetType())
      {
        case TokenType::LITERAL:
        case TokenType::ENC_LITERAL:
        case TokenType::ANY1:
          min_length++;
          break;
        case TokenType::ANYSTAR:
          has_star = true;
          break;
        default:
          OPENFHE_THROW("Unknown token type in StringPatternImpl constructor");
          break;
      }
    }
  }

  StringPatternImpl operator+(const StringPatternImpl& other) const
  {
    std::vector<StringToken> combined_tokens = this->tokens;
    combined_tokens.insert(combined_tokens.end(), other.tokens.begin(), other.tokens.end());
    return StringPatternImpl(std::move(combined_tokens));
  }

  std::vector<StringToken> GetTokens() const
  {
    return tokens;
  }

  size_t GetMinLength() const
  {
    return min_length;
  }

  bool HasStar() const
  {
    return has_star;
  }

private:
  std::vector<StringToken> tokens;
  size_t min_length = 0;
  bool has_star = false; // true if pattern contains anystar (%)
};

inline StringPattern MakeStringPattern(
    std::vector<StringToken> tokens)
{
  return std::make_shared<StringPatternImpl>(std::move(tokens));
}

struct StringPatternSegment
{
  size_t firstToken;
  size_t lastToken;
  size_t length;
  size_t firstIndex;
};

struct StringPatternSplit
{
  bool leadingStar = false; // % at the beginning
  bool trailingStar = false; // % at the end
  std::vector<StringPatternSegment> segments; // segments of the pattern
  std::vector<size_t> minLenRemain; // minimum length required for each segment
};

inline StringPatternSplit SplitOnStar(const StringPattern pattern)
{
  StringPatternSplit p;

  const auto& tokens = pattern->GetTokens();
  size_t n = tokens.size();

  size_t i = 0;
  if (n > 0 && tokens[0]->GetType() == TokenType::ANYSTAR) {
    p.leadingStar = true;
    i++;
  }

  size_t validLength = 0;
  size_t segStart = i;
  for (; i<n; ++i) {
    if (tokens[i]->GetType() == TokenType::ANYSTAR) {
      if (segStart < i) {
        p.segments.push_back({segStart, i - 1, i - segStart, validLength});
        validLength += i - segStart;
      }
      segStart = i + 1;
    }
  }

  if (segStart < n && tokens[n-1]->GetType() != ANYSTAR) {
    p.segments.push_back({segStart, n - 1, n - segStart, validLength});
    validLength += i - segStart;
  }

  if (n && tokens[n-1]->GetType() == TokenType::ANYSTAR)
    p.trailingStar = true;

  for (const auto& seg : p.segments) {
    p.minLenRemain.push_back(validLength - seg.length);
    validLength -= seg.length;
  }

  return p;
}

} // namespace apex
