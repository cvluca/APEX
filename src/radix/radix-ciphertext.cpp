#include "radix/radix-ciphertext.h"

namespace apex {

RadixCiphertext RadixCiphertextImpl::Clone() const
{
  uint32_t n = GetSegmentCount();
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> clonedSegments(n);

  for (uint32_t i = 0; i < n; ++i) {
    clonedSegments[i] = segments[i]->Clone();
  }

  return MakeRadixCiphertext(ctx, clonedSegments, segmentRanges, radix, carryEvaluated, fracSegCount);
}

} // namespace apex
