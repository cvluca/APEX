#pragma once

#include "coeffsbase.h"
#include "coeffs-fwd.h"
#include "base/seg-range.h"

namespace apex {

inline ZeroEvalCoeffs MakeZeroEvalCoeffs(
  std::vector<std::vector<uint64_t>> coeffs,
  const SegRange& evalRange,
  PlaintextModulus p
) {
  return std::make_shared<ZeroEvalCoeffsImpl>(
    std::move(coeffs), evalRange, p);
}

class ZeroEvalCoeffsImpl : public CoeffsImpl {
public:
  ZeroEvalCoeffsImpl(
    std::vector<std::vector<uint64_t>> coeffs,
    const SegRange& evalRange,
    PlaintextModulus p
  ) : CoeffsImpl(std::move(coeffs), p),
    eval_range(evalRange) {}

private:
  SegRange eval_range;
};

} // namespace apex
