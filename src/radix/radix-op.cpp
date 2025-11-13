#include "apexcontext.h"
#include "radix/radix-plaintext.h"
#include "radix/radix-ciphertext.h"
#include "radix/radix-encoder.h"
#include "coeffs/coeffsfactory.h"
#include "poly-evaluation.h"
#include "poly-interpolate.h"
#include "base/seg-range.h"

namespace apex {

template<typename T>
RadixPlaintext ApexContextImpl::MakePackedRadixPlaintextInternal(
  const std::vector<T>& values,
  const RadixEncoder& encoder,
  const ApexParams& params
) const
{
  const size_t segmentCount = params.GetSegmentCount();
  const size_t n = values.size();

  std::vector<std::vector<int64_t>> segments;
  encoder.EncodeToSegments(values.data(), n, segments);

  std::vector<lbcrypto::Plaintext> plaintextSegments;
  for (const auto& segment : segments) {
    lbcrypto::Plaintext pt = cc->MakePackedPlaintext(segment);
    plaintextSegments.push_back(pt);
  }

  auto segmentRanges = encoder.GetSegmentRanges();

  // Convert values to int64_t for storage (we'll need to track the original type)
  std::vector<int64_t> int64_values(n);
  if constexpr (std::is_same_v<T, int64_t>) {
    int64_values = values;
  } else if constexpr (std::is_same_v<T, uint64_t>) {
    for (size_t i = 0; i < n; ++i) {
      int64_values[i] = static_cast<int64_t>(values[i]);
    }
  }

  uint32_t fracSegCount = encoder.GetFracSegCount();
  if (dynamic_cast<const UnsignedIntEncoder*>(&encoder)) {
    // Validate no negative values for unsigned encoding
    for (size_t i = 0; i < n; ++i) {
      if (int64_values[i] < 0) {
        OPENFHE_THROW("Negative values not allowed with unsigned encoding: " + std::to_string(int64_values[i]));
      }
    }
  }

  return MakeRadixPlaintext(
    std::move(int64_values),
    std::move(plaintextSegments),
    std::move(segmentRanges),
    encoder.GetRadix(),
    true,
    fracSegCount);
}

RadixCiphertext ApexContextImpl::Encrypt(
  const RadixPlaintext& plaintext) const
{
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> segments;

  for (const auto& segment : plaintext->GetSegments()) {
    auto ct = cc->Encrypt(publicKey, segment);
    segments.push_back(ct);
  }

  return MakeRadixCiphertext(
    shared_from_this(), std::move(segments), plaintext->GetSegmentRanges(),
    plaintext->GetRadix(), plaintext->GetCarryEvaluated(), 
    plaintext->GetFracSegCount());
}

void ApexContextImpl::Decrypt(
  const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& privateKey,
  const RadixCiphertext& ciphertext,
  RadixPlaintext* plaintext) const
{
  std::vector<lbcrypto::Plaintext> segments;

  for (const auto& segment : ciphertext->GetSegments()) {
    lbcrypto::Plaintext pt;
    cc->Decrypt(privateKey, segment, &pt);
    segments.push_back(pt);
  }

  *plaintext = std::make_shared<RadixPlaintextImpl>();

  (*plaintext)->SetSegments(std::move(segments), ciphertext->GetSegmentRanges(),
                            ciphertext->GetRadix(),
                            ciphertext->GetFracSegCount());
}

RadixCiphertext ApexContextImpl::EvalSub(
  const RadixCiphertext& ciphertext1,
  const RadixCiphertext& ciphertext2) const
{
  RadixCiphertext result = ciphertext1->Clone();
  EvalSubInPlace(result, ciphertext2);
  return result;
}

void ApexContextImpl::EvalSubInPlace(
  RadixCiphertext& ciphertext1,
  const RadixCiphertext& ciphertext2) const
{

  if (ciphertext1->GetSegmentCount() != ciphertext2->GetSegmentCount()) {
    OPENFHE_THROW("Ciphertexts must have the same number of segments for EvalSub, got " +
                std::to_string(ciphertext1->GetSegmentCount()) + " and " +
                std::to_string(ciphertext2->GetSegmentCount()) + ".");
  }

  if (ciphertext1->GetFracSegCount() != ciphertext2->GetFracSegCount()) {
    OPENFHE_THROW("Ciphertexts must have the same fractional segment count for EvalSub, got " +
                std::to_string(ciphertext1->GetFracSegCount()) + " and " +
                std::to_string(ciphertext2->GetFracSegCount()) + ".");
  }

  auto& segments1 = ciphertext1->GetSegments();
  const auto& segments2 = ciphertext2->GetSegments();

  const auto& segmentRanges2 = ciphertext2->GetSegmentRanges();

  uint32_t n = ciphertext1->GetSegmentCount();

  for (size_t i = 0; i < n; ++i) {
    cc->EvalSubInPlace(segments1[i], segments2[i]);
    ciphertext1->SubSegmentRange(segmentRanges2[i], i);
  }

  ciphertext1->SetCarryEvaluated(false);
}

RadixCiphertext ApexContextImpl::EvalAdd(
  const RadixCiphertext& ciphertext1,
  const RadixCiphertext& ciphertext2) const
{
  RadixCiphertext result = ciphertext1->Clone();
  EvalAddInPlace(result, ciphertext2);
  return result;
}

void ApexContextImpl::EvalAddInPlace(
  RadixCiphertext& ciphertext1,
  const RadixCiphertext& ciphertext2) const
{

  if (ciphertext1->GetSegmentCount() != ciphertext2->GetSegmentCount()) {
    OPENFHE_THROW("Ciphertexts must have the same number of segments for EvalAdd, got " +
                std::to_string(ciphertext1->GetSegmentCount()) + " and " +
                std::to_string(ciphertext2->GetSegmentCount()) + ".");
  }

  if (ciphertext1->GetFracSegCount() != ciphertext2->GetFracSegCount()) {
    OPENFHE_THROW("Ciphertexts must have the same fractional segment count for EvalAdd, got " +
                std::to_string(ciphertext1->GetFracSegCount()) + " and " +
                std::to_string(ciphertext2->GetFracSegCount()) + ".");
  }

  auto& segments1 = ciphertext1->GetSegments();
  const auto& segments2 = ciphertext2->GetSegments();

  const auto& segmentRanges2 = ciphertext2->GetSegmentRanges();

  uint32_t n = ciphertext1->GetSegmentCount();

  for (size_t i = 0; i < n; ++i) {
    cc->EvalAddInPlace(segments1[i], segments2[i]);
    ciphertext1->AddSegmentRange(segmentRanges2[i], i);
  }

  ciphertext1->SetCarryEvaluated(false);
}

RadixCiphertext ApexContextImpl::EvalCarry(const RadixCiphertext & ciphertext, bool ignore_overflow) const
{
  RadixCiphertext result = ciphertext->Clone();
  EvalCarryInPlace(result, ignore_overflow);
  return result;
}

void ApexContextImpl::EvalCarryInPlace(RadixCiphertext& ciphertext, bool ignore_overflow) const
{
  auto& segments = ciphertext->GetSegments();
  auto& segmentRanges = ciphertext->GetSegmentRanges();

  uint32_t n = ciphertext->GetSegmentCount();
  uint32_t r = ciphertext->GetRadix();
  int64_t base = 1LL << r;
  bool evaluated = true;

  while (evaluated) {
    evaluated = false;

    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> carrySegments(n, nullptr);
    std::vector<SegRange> carryRanges(n);
    for (size_t i = 0; i < n-1; ++i)
    {
      // Check if no carry needed for this segment (considering carry from previous segment)
      SegRange effectiveRange = segmentRanges[i];
      if (i > 0 && carrySegments[i-1] != nullptr) {
        effectiveRange.Add(carryRanges[i-1]);
      }
      if (effectiveRange.GetMin() > -base && effectiveRange.GetMax() < base) continue;
      evaluated = true;

      int64_t range = std::max(
        std::abs(segmentRanges[i].GetMin()), std::abs(segmentRanges[i].GetMax()));

      carryRanges[i] = segmentRanges[i].ComputeCarry(base);

      auto coeffs = CoeffsFactory::GetCarryEvalCoeffs(
        static_cast<uint64_t>(range), r, GetPlaintextModulus());

      carrySegments[i] = EvalPoly(segments[i], coeffs);
      cc->EvalSubInPlace(segments[i],
        cc->EvalMult(carrySegments[i], cc->MakePackedPlaintext(std::vector<int64_t>(cc->GetRingDimension(), base))));
      segmentRanges[i] = SegRange(-base/2, base/2);
    }

    if (!evaluated) break;
    for (size_t i = 1; i < n; ++i)
    {
      if (carrySegments[i-1] != nullptr) {
        segments[i] = cc->EvalAdd(segments[i], carrySegments[i-1]);
        ciphertext->AddSegmentRange(carryRanges[i-1], i);
      }
    }
  }

  // If ignore_overflow is true, clamp the highest segment range to (-base, base)
  if (ignore_overflow && n > 0) {
    auto& highestRange = segmentRanges[n - 1];
    if (highestRange.GetMin() <= -base || highestRange.GetMax() >= base) {
      // Clamp the range to (-base, base)
      int64_t clampedMin = std::max(highestRange.GetMin(), -base + 1);
      int64_t clampedMax = std::min(highestRange.GetMax(), base - 1);
      segmentRanges[n - 1] = SegRange(clampedMin, clampedMax);
    }
  }

  ciphertext->SetCarryEvaluated(true);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ApexContextImpl::EvalSign(
  const RadixCiphertext& ciphertext)
{
  auto& segments = ciphertext->GetSegments();
  auto& segmentRanges = ciphertext->GetSegmentRanges();

  uint32_t n = ciphertext->GetSegmentCount();
  uint32_t r = ciphertext->GetRadix();
  int64_t base = 1LL << r;

  // Check if carry needs to be evaluated
  for (size_t i = 0; i < n - 1; ++i) {
    if (segmentRanges[i].NeedsCarry(base)) {
      OPENFHE_THROW("EvalSign requires carry evaluation for segment " + std::to_string(i) +
                " with range [" + std::to_string(segmentRanges[i].GetMin()) + ", " +
                std::to_string(segmentRanges[i].GetMax()) + "]");
    }
  }

  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> gt(n);
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> eq(n);
  lbcrypto::Ciphertext<lbcrypto::DCRTPoly> res;
  bool symmetric = true;

  auto ptOne = GetConstPlaintext(1);
  auto ptInv = symmetric ?
    GetConstPlaintext((GetPlaintextModulus()+1)/2) : GetConstPlaintext((GetPlaintextModulus()-1)/2);

  for (size_t i = 0; i < n; ++i) {
    auto coeffs = CoeffsFactory::GetCompEvalCoeffs(
      segmentRanges[i], GetPlaintextModulus(), symmetric);

    gt[i] = EvalPoly(segments[i], coeffs);
    if (symmetric) {
      eq[i] = cc->EvalAdd(gt[i], ptOne);
      gt[i] = cc->EvalMult(gt[i], eq[i]);
      cc->EvalSubInPlace(eq[i], gt[i]);
      gt[i] = cc->EvalMult(gt[i], ptInv);
    }
    else {
      eq[i] = cc->EvalNegate(gt[i]);
      cc->EvalAddInPlace(eq[i], ptOne);
      eq[i] = cc->EvalMult(eq[i], gt[i]);
      eq[i] = cc->EvalMult(eq[i], ptInv);
      cc->EvalAddInPlace(gt[i], eq[i]);
    }
  }

  if (n <= 4) {
    for (size_t i = 0; i < n; ++i) {
      if (i == 0) res = gt[i];
      else {
        cc->EvalSubInPlace(res, gt[i]);
        res = cc->EvalMult(res, eq[i]);
        cc->EvalAddInPlace(res, gt[i]);
      }
    }
  } else {
    // Recursive merge function: merges pairs (gt, eq) in a binary tree fashion
    // At the final level, only merges gt (no need to compute eq)
    std::function<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>(
      std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>&,
      std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>&,
      size_t, size_t, bool)> recursiveMerge;

    recursiveMerge = [&](
      std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& gtVec,
      std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& eqVec,
      size_t start, size_t end, bool computeEq) -> lbcrypto::Ciphertext<lbcrypto::DCRTPoly> {

      if (end - start == 1) {
        return gtVec[start];
      }

      size_t mid = (start + end) / 2;

      // Recursively merge left (higher bits) and right (lower bits)
      auto gtLeft = recursiveMerge(gtVec, eqVec, start, mid, computeEq);
      auto gtRight = recursiveMerge(gtVec, eqVec, mid, end, true);

      // Merge: gt_new = (gt_left - gt_right) * eq_right + gt_right
      cc->EvalSubInPlace(gtLeft, gtRight);
      gtLeft = cc->EvalMult(gtLeft, eqVec[mid]);
      cc->EvalAddInPlace(gtLeft, gtRight);
      if (computeEq) {
        eqVec[start] = cc->EvalMult(eqVec[start], eqVec[mid]);
      }
      return gtLeft;
    };

    res = recursiveMerge(gt, eq, 0, n, false);
  }

  return std::move(res);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ApexContextImpl::EvalZero(
  const RadixCiphertext& ciphertext)
{
  auto& segments = ciphertext->GetSegments();
  auto& segmentRanges = ciphertext->GetSegmentRanges();

  uint32_t n = ciphertext->GetSegmentCount();
  uint32_t r = ciphertext->GetRadix();
  int64_t base = 1LL << r;

  // Check if carry needs to be evaluated
  for (size_t i = 0; i < n - 1; ++i) {
    if (segmentRanges[i].NeedsCarry(base)) {
      OPENFHE_THROW("EvalZero requires carry evaluation for segment " + std::to_string(i) +
                " with range [" + std::to_string(segmentRanges[i].GetMin()) + ", " +
                std::to_string(segmentRanges[i].GetMax()) + "]");
    }
  }

  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> eq(n);
  lbcrypto::Ciphertext<lbcrypto::DCRTPoly> res;

  for (size_t i = 0; i < n; ++i) {
    auto coeffs = CoeffsFactory::GetZeroEvalCoeffs(
      segmentRanges[i], GetPlaintextModulus());

    eq[i] = EvalPoly(segments[i], coeffs);
  }

  res = cc->EvalMultMany(eq);

  return std::move(res);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ApexContextImpl::EvalComp(
  const RadixCiphertext& ciphertext1,
  const RadixCiphertext& ciphertext2,
  CompType type) 
{
  switch(type) {
    case CompType::GT:
      return EvalSign(EvalSub(ciphertext1, ciphertext2));
    case CompType::LT:
      return EvalSign(EvalSub(ciphertext2, ciphertext1));
    case CompType::EQ:
      return EvalZero(EvalSub(ciphertext1, ciphertext2));
    default:
      OPENFHE_THROW("Unsupported comparison type.");
  }
  return nullptr;
}

RadixCiphertext ApexContextImpl::EvalBalance(const RadixCiphertext & ciphertext) const
{
  RadixCiphertext result = ciphertext->Clone();
  EvalBalanceInPlace(result);
  return result;
}

void ApexContextImpl::EvalBalanceInPlace(RadixCiphertext& ciphertext) const
{
  auto& segments = ciphertext->GetSegments();
  auto& segmentRanges = ciphertext->GetSegmentRanges();
  uint32_t n = ciphertext->GetSegmentCount();
  uint32_t r = ciphertext->GetRadix();
  int64_t base = 1LL << r;

  for (size_t i = 0; i < n-1; ++i) {
    int64_t carry = 0;
    if (segmentRanges[i].GetMin() >= 0 && segmentRanges[i].GetMax() >= 0) {
      carry -= static_cast<int64_t>(std::ceil(segmentRanges[i].GetMin() / (double)base));
    } else if (segmentRanges[i].GetMin() <= 0 && segmentRanges[i].GetMax() <= 0) {
      carry -= static_cast<int64_t>(std::floor((segmentRanges[i].GetMax()) / (double)base));
    }

    SegRange testRange = segmentRanges[i];
    SegRange carryRange(carry * base, carry * base);
    testRange.Add(carryRange);

    double diff = (std::abs(testRange.GetMin()) + testRange.GetMax())/2.0 - testRange.GetMax();
    if (std::abs(diff) > base/2.0)
      carry += static_cast<int64_t>(std::ceil((diff-(base/2.0))/base));

    if (carry == 0) continue;
    carryRange = SegRange(carry * base, carry * base);
    SegRange range = segmentRanges[i];
    range.Add(carryRange);

    // std::cout << "Balancing segment " << i << ": carry = " << carry << ", range = ["
    //   << segmentRanges[i].GetMin() << ", " << segmentRanges[i].GetMax() << "], after = ["
    //   << range.GetMin() << ", " << range.GetMax() << "]\n";

    segments[i] = cc->EvalAdd(
      segments[i], cc->MakePackedPlaintext(std::vector<int64_t>(cc->GetRingDimension(), carry*base)));
    segmentRanges[i] = range;

    segments[i+1] = cc->EvalSub(
      segments[i+1], cc->MakePackedPlaintext(std::vector<int64_t>(cc->GetRingDimension(), carry)));
    SegRange nextCarryRange(-carry, -carry);
    segmentRanges[i+1].Add(nextCarryRange);
  }
}

RadixCiphertext ApexContextImpl::EvalMult(
  const RadixCiphertext& ciphertext1,
  const RadixCiphertext& ciphertext2) const
{
  uint32_t n1 = ciphertext1->GetSegmentCount();
  uint32_t n2 = ciphertext2->GetSegmentCount();

  uint32_t n = n1 + n2 - 1;

  std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>> segments(n);

  std::vector<SegRange> segmentRanges(n, SegRange(0, 0));

  const auto& segments1 = ciphertext1->GetSegments();
  const auto& segments2 = ciphertext2->GetSegments();
  const auto& ranges1 = ciphertext1->GetSegmentRanges();
  const auto& ranges2 = ciphertext2->GetSegmentRanges();

  for (size_t i = 0; i < n1; ++i) {
    for (size_t j = 0; j < n2; ++j) {
      auto prod = cc->EvalMult(segments1[i], segments2[j]);
      segments[i+j].push_back(prod);

      SegRange multRange = ranges1[i];
      multRange.Mult(ranges2[j]);
      segmentRanges[i+j].Add(multRange);
    }
  }

  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> finalSegments(n);

  for (size_t i = 0; i < n; ++i) {
    finalSegments[i] = cc->EvalAddMany(segments[i]);
  }

  return MakeRadixCiphertext(
    shared_from_this(), std::move(finalSegments), std::move(segmentRanges),
    ciphertext1->GetRadix(), false, ciphertext1->GetFracSegCount() + ciphertext2->GetFracSegCount());
}

RadixCiphertext ApexContextImpl::ReduceSegment(const RadixCiphertext& ciphertext, const ApexParams& customParams)
{
  RadixCiphertext result = ciphertext->Clone();
  ReduceSegmentInPlace(result, customParams);
  return result;
}

void ApexContextImpl::ReduceSegmentInPlace(RadixCiphertext& ciphertext, const ApexParams& customParams)
{
  uint32_t currentSegCount = ciphertext->GetSegmentCount();
  uint32_t currentFracSegCount = ciphertext->GetFracSegCount();
  uint32_t currentIntSegCount = currentSegCount - currentFracSegCount;

  uint32_t targetSegCount = customParams.GetSegmentCount();

  // Determine target fractional segment count based on current type
  uint32_t targetFracSegCount;
  if (currentFracSegCount > 0) {
    // Current ciphertext is floating-point, use fractional segments from params
    // But cannot exceed current fractional segments (fractional segments can only be discarded)
    targetFracSegCount = std::min(customParams.GetFracSegmentCount(), currentFracSegCount);
  } else {
    // Current ciphertext is integer
    targetFracSegCount = 0;
  }

  uint32_t targetIntSegCount = targetSegCount - targetFracSegCount;

  if (targetSegCount >= currentSegCount) {
    OPENFHE_THROW("Target segment count (" + std::to_string(targetSegCount) +
                  ") must be less than current segment count (" + std::to_string(currentSegCount) + ")");
  }

  if (targetIntSegCount > currentIntSegCount) {
    OPENFHE_THROW("Target integer segments (" + std::to_string(targetIntSegCount) +
                  ") cannot exceed current integer segments (" + std::to_string(currentIntSegCount) + ")");
  }

  if (targetIntSegCount >= currentIntSegCount && targetFracSegCount >= currentFracSegCount) {
    OPENFHE_THROW("No reduction needed: target integer segments (" + std::to_string(targetIntSegCount) +
                  ") >= current (" + std::to_string(currentIntSegCount) + ") and target frac segments (" +
                  std::to_string(targetFracSegCount) + ") >= current (" + std::to_string(currentFracSegCount) + ")");
  }

  auto& segments = ciphertext->GetSegments();
  auto& segmentRanges = ciphertext->GetSegmentRanges();

  uint32_t r = ciphertext->GetRadix();
  int64_t base = 1LL << r;

  // Process integer part reduction if needed
  if (targetIntSegCount < currentIntSegCount) {
    // Integer segments are at indices [currentFracSegCount, currentSegCount-1]
    // We need to reduce them to targetIntSegCount segments

    // The highest kept integer segment index (in original array)
    uint32_t highestKeptIntIdx = currentFracSegCount + targetIntSegCount - 1;

    // Accumulate higher integer segments into the highest kept integer segment
    int64_t multiplier = base;
    for (size_t i = highestKeptIntIdx + 1; i < currentSegCount; ++i) {
      auto scaled = cc->EvalMult(segments[i], GetConstCiphertext(multiplier));
      segments[highestKeptIntIdx] = cc->EvalAdd(segments[highestKeptIntIdx], scaled);

      // Update the range for the target segment
      SegRange highOrderRange = segmentRanges[i];
      highOrderRange.Mult(SegRange(multiplier, multiplier));
      segmentRanges[highestKeptIntIdx].Add(highOrderRange);

      multiplier *= base;
    }
  }

  // Reorganize segments: discard unwanted fractional and integer segments
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> newSegments;
  std::vector<SegRange> newRanges;

  // Keep fractional segments [0, targetFracSegCount-1]
  for (size_t i = 0; i < targetFracSegCount; ++i) {
    newSegments.push_back(segments[i]);
    newRanges.push_back(segmentRanges[i]);
  }

  // Keep integer segments [currentFracSegCount, currentFracSegCount + targetIntSegCount - 1]
  for (size_t i = 0; i < targetIntSegCount; ++i) {
    newSegments.push_back(segments[currentFracSegCount + i]);
    newRanges.push_back(segmentRanges[currentFracSegCount + i]);
  }

  segments = std::move(newSegments);
  segmentRanges = std::move(newRanges);

  // Update fractional segment count
  ciphertext->SetFracSegCount(targetFracSegCount);
}

RadixPlaintext ApexContextImpl::MakePackedRadixPlaintext(const std::vector<int64_t>& values) const {
  return MakePackedRadixPlaintext(values, *params);
}
RadixPlaintext ApexContextImpl::MakePackedRadixPlaintext(const std::vector<uint64_t>& values) const {
  return MakePackedRadixPlaintext(values, *params);
}

RadixPlaintext ApexContextImpl::MakePackedRadixPlaintext(const std::vector<double>& values) const {
  return MakePackedRadixPlaintext(values, *params);
}

RadixPlaintext ApexContextImpl::MakePackedRadixPlaintext(const std::vector<float>& values) const {
  return MakePackedRadixPlaintext(values, *params);
}

// Overloaded factory methods using encoders
RadixPlaintext ApexContextImpl::MakePackedRadixPlaintext(
  const std::vector<int64_t>& values,
  const ApexParams& params
) const {
  // Check if any values are negative to determine encoder type
  bool hasNegative = std::any_of(values.begin(), values.end(), [](int64_t v) { return v < 0; });

  if (hasNegative) {
    SignedIntEncoder encoder(params.GetRadix(), params.GetSegmentCount(), 0);
    return MakePackedRadixPlaintextInternal(values, encoder, params);
  } else {
    // All values are non-negative, can use unsigned encoding for efficiency
    std::vector<uint64_t> unsignedValues(values.begin(), values.end());
    UnsignedIntEncoder encoder(params.GetRadix(), params.GetSegmentCount());
    return MakePackedRadixPlaintextInternal(unsignedValues, encoder, params);
  }
}

RadixPlaintext ApexContextImpl::MakePackedRadixPlaintext(
  const std::vector<uint64_t>& values,
  const ApexParams& params
) const {
  // uint64_t input type automatically uses unsigned encoding
  UnsignedIntEncoder encoder(params.GetRadix(), params.GetSegmentCount());
  return MakePackedRadixPlaintextInternal(values, encoder, params);
}

RadixPlaintext ApexContextImpl::MakePackedRadixPlaintext(
  const std::vector<double>& values,
  const ApexParams& params
) const {
  // Use configured fractional segments for double precision
  const uint32_t fracSegCount = params.GetFracSegmentCount();
  const uint32_t intSegCount = params.GetIntegerSegments();

  // Validation: ensure fracSegCount doesn't exceed total segments
  if (fracSegCount >= params.GetSegmentCount()) {
    OPENFHE_THROW("Fractional segments (" + std::to_string(fracSegCount) +
                 ") must be less than total segment count (" + std::to_string(params.GetSegmentCount()) + ")");
  }
  const uint32_t fractionalBits = params.GetFractionalBits();
  const int64_t scale = 1LL << fractionalBits;

  // Convert doubles to fixed-point integers by scaling
  std::vector<int64_t> fixedValues;
  fixedValues.reserve(values.size());

  for (double value : values) {
    if (std::isnan(value) || std::isinf(value)) {
      OPENFHE_THROW("Cannot encode NaN or infinity values");
    }

    // Scale and round to nearest integer
    double scaledValue = value * scale;
    int64_t fixedValue = static_cast<int64_t>(std::round(scaledValue));
    fixedValues.push_back(fixedValue);
  }

  SignedIntEncoder encoder(params.GetRadix(), intSegCount, fracSegCount);
  return MakePackedRadixPlaintextInternal(fixedValues, encoder, params);
}

RadixPlaintext ApexContextImpl::MakePackedRadixPlaintext(
  const std::vector<float>& values,
  const ApexParams& params
) const {
  // Use configured fractional segments for float precision
  const uint32_t fracSegCount = params.GetFracSegmentCount();
  const uint32_t intSegCount = params.GetIntegerSegments();

  // Validation: ensure fracSegCount doesn't exceed total segments
  if (fracSegCount >= params.GetSegmentCount()) {
    OPENFHE_THROW("Fractional segments (" + std::to_string(fracSegCount) +
                 ") must be less than total segment count (" + std::to_string(params.GetSegmentCount()) + ")");
  }
  const uint32_t fractionalBits = params.GetFractionalBits();
  const int64_t scale = 1LL << fractionalBits;

  // Convert floats to fixed-point integers by scaling
  std::vector<int64_t> fixedValues;
  fixedValues.reserve(values.size());

  for (float value : values) {
    if (std::isnan(value) || std::isinf(value)) {
      OPENFHE_THROW("Cannot encode NaN or infinity values");
    }

    // Scale and round to nearest integer
    double scaledValue = static_cast<double>(value) * scale;
    int64_t fixedValue = static_cast<int64_t>(std::round(scaledValue));
    fixedValues.push_back(fixedValue);
  }

  SignedIntEncoder encoder(params.GetRadix(), intSegCount, fracSegCount);
  return MakePackedRadixPlaintextInternal(fixedValues, encoder, params);
}

} // namespace apex
