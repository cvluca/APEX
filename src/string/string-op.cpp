#include "apexcontext.h"
#include "utils.h"
#include "string/string-plaintext.h"
#include "string/string-ciphertext.h"
#include "string/string-token.h"
#include "string/string-pattern.h"
#include "string/string-encoder.h"
#include "coeffs/coeffs.h"
#include "poly-evaluation.h"

namespace apex {

StringPlaintext ApexContextImpl::MakePackedStringPlaintext(
  const std::vector<std::string>& values,
  size_t max_length) const
{
  if (max_length == 0) {
    OPENFHE_THROW("ApexContextImpl::MakePackedStringPlaintext: max_length must be greater than 0");
  }
  if (max_length > 64) {
    OPENFHE_THROW("ApexContextImpl::MakePackedStringPlaintext: max_length must be less than or equal to 64");
  }

  const size_t n = values.size();

  // Create StringEncoder using params for radix/charSegmentCount
  StringEncoder encoder(max_length, *params);

  // Use encoder to create segments and mask
  std::vector<std::vector<int64_t>> segments;
  std::vector<std::vector<int64_t>> mask;

  encoder.EncodeToSegments(&values, n, segments);
  encoder.EncodeToMask(&values, n, mask);

  // Get segment ranges from encoder
  auto segmentRanges = encoder.GetSegmentRanges();

  // Calculate segment max values from ranges
  std::vector<int64_t> segmentMaxValues;
  segmentMaxValues.reserve(segmentRanges.size());
  for (const auto& range : segmentRanges) {
    segmentMaxValues.push_back(range.GetMax());
  }

  // Convert to OpenFHE plaintexts (total segments = maxLength * charSegmentCount)
  size_t totalSegments = max_length * params->GetCharSegmentCount();
  std::vector<lbcrypto::Plaintext> plaintextSegments(totalSegments);
  std::vector<lbcrypto::Plaintext> plaintextMask(max_length);

  for (size_t i = 0; i < totalSegments; ++i) {
    plaintextSegments[i] = cc->MakePackedPlaintext(segments[i]);
  }

  for (size_t i = 0; i < max_length; ++i) {
    plaintextMask[i] = cc->MakePackedPlaintext(mask[i]);
  }

  return MakeStringPlaintext(values, std::move(plaintextSegments), std::move(segmentMaxValues),
                             std::move(plaintextMask), params->GetRadix(), max_length);
}

StringCiphertext ApexContextImpl::Encrypt(
  const StringPlaintext& plaintext) const
{
  const auto& segmentsVec = plaintext->GetSegments();
  const auto& maskVec = plaintext->GetMask();
  const size_t totalSegments = segmentsVec.size();
  const size_t maxLength = plaintext->GetMaxLength();

  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> segments(totalSegments);
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> mask(maxLength);

  // Encrypt all bit-slice segments
  for (size_t i = 0; i < totalSegments; ++i) {
    segments[i] = cc->Encrypt(publicKey, segmentsVec[i]);
  }

  // Encrypt character position masks
  for (size_t i = 0; i < maxLength; ++i) {
    mask[i] = cc->Encrypt(publicKey, maskVec[i]);
  }

  return MakeStringCiphertext(
    shared_from_this(), std::move(segments), plaintext->GetSegmentMaxValues(),
    std::move(mask), plaintext->GetRadix(), plaintext->GetMaxLength());
}

void ApexContextImpl::Decrypt(
  const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& privateKey,
  const StringCiphertext& ciphertext,
  StringPlaintext* plaintext) const
{
  const auto& segmentsVec = ciphertext->GetSegments();
  const auto& maskVec = ciphertext->GetMask();
  const size_t totalSegments = segmentsVec.size();
  const size_t maxLength = ciphertext->GetMaxLength();

  std::vector<lbcrypto::Plaintext> segments(totalSegments);
  std::vector<lbcrypto::Plaintext> mask(maxLength);

  // Decrypt all bit-slice segments
  for (size_t i = 0; i < totalSegments; ++i) {
    cc->Decrypt(privateKey, segmentsVec[i], &segments[i]);
  }

  // Decrypt character position masks
  for (size_t i = 0; i < maxLength; ++i) {
    cc->Decrypt(privateKey, maskVec[i], &mask[i]);
  }

  *plaintext = std::make_shared<StringPlaintextImpl>();

  (*plaintext)->SetSegments(std::move(segments), std::move(mask),
                            ciphertext->GetRadix(), ciphertext->GetMaxLength(),
                            ciphertext->GetSegmentMaxValues());
}

StringPattern ApexContextImpl::EncodePattern(std::string pattern) const
{
  std::vector<StringToken> tokens;

  for (size_t i = 0; i < pattern.size(); ++i)
    tokens.push_back(MakeStringToken(pattern[i]));

  return MakeStringPattern(std::move(tokens));
}

StringPattern ApexContextImpl::EncryptPattern(
  const StringPattern& pattern
) const
{
  // Check if pattern is already encrypted by checking for ENC_LITERAL tokens
  auto tokens = pattern->GetTokens();
  for (const auto& token : tokens) {
    if (token->GetType() == TokenType::ENC_LITERAL) {
      OPENFHE_THROW("ApexContextImpl::EncryptPattern: pattern is already encrypted");
    }
  }

  // Get radix and charSegmentCount from params
  const uint32_t radix = params->GetRadix();
  const uint32_t charSegmentCount = params->GetCharSegmentCount();

  for (size_t i = 0; i < tokens.size(); ++i) {
    switch (tokens[i]->GetType()) {
      case TokenType::LITERAL: {
        // Decompose character into bit-slice segments
        char c = tokens[i]->Get();
        int64_t ascii_value = static_cast<unsigned char>(c) & 0x7F;

        std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> enc_segments(charSegmentCount);

        for (uint32_t segIdx = 0; segIdx < charSegmentCount; ++segIdx) {
          uint32_t shift = segIdx * radix;
          uint32_t mask = (1 << radix) - 1;
          int64_t segValue = (ascii_value >> shift) & mask;

          auto pt = cc->MakePackedPlaintext(
            std::vector<int64_t>(cc->GetRingDimension(), segValue));
          enc_segments[segIdx] = cc->Encrypt(publicKey, pt);
        }

        // Encrypt wildcard_mask = 0 (not a wildcard)
        auto wildcard_mask_pt = cc->MakePackedPlaintext(
          std::vector<int64_t>(cc->GetRingDimension(), 0));
        auto wildcard_mask = cc->Encrypt(publicKey, wildcard_mask_pt);

        tokens[i] = MakeStringToken(std::move(enc_segments), wildcard_mask);
        break;
      }
      case TokenType::ANY1: {
        // Encrypt ANY1 (_) as all zeros with wildcard_mask = 1
        std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> enc_segments(charSegmentCount);

        for (uint32_t segIdx = 0; segIdx < charSegmentCount; ++segIdx) {
          auto pt = cc->MakePackedPlaintext(
            std::vector<int64_t>(cc->GetRingDimension(), 0));
          enc_segments[segIdx] = cc->Encrypt(publicKey, pt);
        }

        // Encrypt wildcard_mask = 1 (is a wildcard)
        auto wildcard_mask_pt = cc->MakePackedPlaintext(
          std::vector<int64_t>(cc->GetRingDimension(), 1));
        auto wildcard_mask = cc->Encrypt(publicKey, wildcard_mask_pt);

        tokens[i] = MakeStringToken(std::move(enc_segments), wildcard_mask);
        break;
      }
      case TokenType::ANYSTAR:
        // Keep ANYSTAR (%) as-is for structure metadata
        // We need to know where % is for the DP algorithm in EvalLike
        break;
      default:
        break;
    }
  }

  return MakeStringPattern(std::move(tokens));
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ApexContextImpl::EvalLike(
  const StringCiphertext& ciphertext,
  const StringPattern& pattern)
{
  // Fast path checks
  // NOTE: We only check if ciphertext is too short. We cannot check if it's too long
  // because ciphertext might be padded to max_length, and actual length is determined by mask.
  if (ciphertext->GetLength() < pattern->GetMinLength()) {
    return GetConstCiphertext(0)->Clone();
  }

  if (pattern->GetMinLength() == 0) {
    return GetConstCiphertext(1)->Clone();
  }

  StringPatternSplit split = SplitOnStar(pattern);
  size_t n = ciphertext->GetLength();
  const auto& ctBitSlices = ciphertext->GetSegments();
  const auto& ctMasks = ciphertext->GetMask();
  const uint32_t charSegmentCount = ciphertext->GetCharSegmentCount();
  const auto& segmentMaxValues = ciphertext->GetSegmentMaxValues();

  // Step 1: Compute segment matches at each position (same as original)
  std::vector<std::unordered_map<size_t, lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>> reachPrev(split.segments.size());

  for (size_t seg_idx = 0; seg_idx < split.segments.size(); ++seg_idx) {
    const auto& seg = split.segments[seg_idx];

    for (size_t ct_idx = seg.firstIndex; ct_idx <= n - split.minLenRemain[seg_idx] - seg.length; ++ct_idx) {
      if (seg_idx == 0 && ct_idx > 0 && !split.leadingStar) break;

      std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> match;
      for (size_t tok_idx = seg.firstToken; tok_idx <= seg.lastToken; ++tok_idx) {
        auto token = pattern->GetTokens()[tok_idx];

        if (token->GetType() == TokenType::ENC_LITERAL) {
          // Encrypted literal: compare bit-slice segments
          // Support ANY1 wildcard via wildcard_mask
          size_t charPos = ct_idx + tok_idx - seg.firstToken;
          const auto& pattern_segments = token->GetEncSegments();
          auto wildcard_mask = token->GetWildcardMask();

          // Compare each bit-slice segment
          std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> segment_eq_checks;
          for (uint32_t bitIdx = 0; bitIdx < charSegmentCount; ++bitIdx) {
            size_t text_seg_index = charPos * charSegmentCount + bitIdx;
            auto text_segment = ctBitSlices[text_seg_index];
            auto pattern_segment = pattern_segments[bitIdx];

            // Check if segments are equal: diff = text - pattern
            auto diff = cc->EvalSub(text_segment, pattern_segment);

            // Use polynomial interpolation to check if diff == 0
            // Get the range for this segment
            int64_t maxVal = segmentMaxValues[text_seg_index];
            SegRange segRange(-maxVal, maxVal);

            auto coeffs = CoeffsFactory::GetZeroEvalCoeffs(segRange, GetPlaintextModulus());
            auto is_equal = EvalPoly(diff, coeffs);

            segment_eq_checks.push_back(is_equal);
          }

          // AND all segment equality checks
          auto all_segments_equal = cc->EvalMultMany(segment_eq_checks);

          // Add wildcard_mask: if ANY1 (wildcard_mask=1), result >= 1
          auto eq_check = cc->EvalAdd(all_segments_equal, wildcard_mask);

          // Multiply by ctMask to handle padding
          eq_check = cc->EvalMult(eq_check, ctMasks[charPos]);

          match.push_back(eq_check);
        } else {
          OPENFHE_THROW("ApexContextImpl::EvalLike: unsupported token type in pattern");
        }
      }

      if (seg_idx == split.segments.size() - 1 && ct_idx + seg.length < n && !split.trailingStar)
        match.push_back(cc->EvalSub(GetConstCiphertext(1), ctMasks[ct_idx + seg.length]));

      reachPrev[seg_idx][ct_idx] = match.empty() ? GetConstCiphertext(1) : cc->EvalMultMany(match);
    }
  }

  // Step 2: DP-based combination (OPTIMIZED - avoids combinatorial explosion)

  if (split.segments.empty()) {
    return GetConstCiphertext(1)->Clone();
  }

  // dp[end_pos] = ciphertext indicating whether we can match segments [0..seg_idx] ending at position end_pos
  std::map<size_t, lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> dp;

  // Initialize with first segment
  const auto& first_seg = split.segments[0];
  for (const auto& [start_pos, match_ct] : reachPrev[0]) {
    size_t end_pos = start_pos + first_seg.length;
    dp[end_pos] = match_ct;
  }

  // Process remaining segments
  for (size_t seg_idx = 1; seg_idx < split.segments.size(); ++seg_idx) {
    const auto& seg = split.segments[seg_idx];
    std::map<size_t, lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> new_dp;

    // Build prefix OR map: prefix_or[pos] = OR of all dp[p] where p <= pos
    // This optimizes the inner loop by avoiding repeated ORs
    std::unordered_map<size_t, lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> prefix_or;

    // Build prefix OR (using boolean OR to avoid accumulation)
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> running_or = nullptr;
    for (auto &[pos, dp_prev] : dp) {
      if (running_or == nullptr) {
        running_or = dp_prev;
      } else {
        // OR(a,b) = a + b - a*b
        auto tmp = cc->EvalMult(running_or, dp_prev);
        running_or = cc->EvalAdd(running_or, dp_prev);
        cc->EvalSubInPlace(running_or, tmp);
      }
      prefix_or[pos] = running_or;
    }

    // For each possible starting position of current segment
    for (const auto& [start_pos, match_ct] : reachPrev[seg_idx]) {
      size_t end_pos = start_pos + seg.length;

      // Find the largest position <= start_pos in prefix_or
      lbcrypto::Ciphertext<lbcrypto::DCRTPoly> prev_matches = nullptr;

      for (auto it = dp.rbegin(); it != dp.rend(); ++it) {
        if (it->first <= start_pos) {
          prev_matches = prefix_or[it->first];
          break;
        }
      }

      auto transition = cc->EvalMult(prev_matches, match_ct);

      new_dp[end_pos] = transition;
    }

    dp = std::move(new_dp);
  }

  // Step 3: Collect final result
  // OR all valid ending positions
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> final_matches;

  for (const auto& [end_pos, match_ct] : dp) {
    // All ending positions are valid because:
    // 1. If trailingStar=true, pattern can match anywhere
    // 2. If trailingStar=false, we already added constraints in Step 1
    //    to check that characters after the segment are padding (mask=0)
    final_matches.push_back(match_ct);
  }

  if (final_matches.empty()) {
    return GetConstCiphertext(0)->Clone();
  }

  // OR all final matches using De Morgan's law: OR(a,b,c) = 1 - AND(1-a, 1-b, 1-c)
  // This ensures the result is in {0, 1} rather than accumulated sum
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> negated_matches;
  for (const auto& match : final_matches) {
    negated_matches.push_back(cc->EvalSub(GetConstCiphertext(1), match));
  }

  auto all_fail = cc->EvalMultMany(negated_matches);
  auto result = cc->EvalSub(GetConstCiphertext(1), all_fail);

  return result;
}

} // namespace apex
