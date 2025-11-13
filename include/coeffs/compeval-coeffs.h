#pragma once

#include "coeffsbase.h"
#include "coeffs-fwd.h"
#include "base/seg-range.h"

namespace apex {

inline CompEvalCoeffs MakeCompEvalCoeffs(
  std::vector<std::vector<uint64_t>> coeffs,
  const SegRange& evalRange,
  PlaintextModulus p,
  bool symmetric
) {
  return std::make_shared<CompEvalCoeffsImpl>(
    std::move(coeffs), evalRange, p, symmetric);
}

class CompEvalCoeffsImpl : public CoeffsImpl {
public:
  CompEvalCoeffsImpl(
    std::vector<std::vector<uint64_t>> coeffs,
    const SegRange& evalRange,
    PlaintextModulus p,
    bool symmetric
  ) : CoeffsImpl(std::move(coeffs), p),
    eval_range(evalRange), symmetric(symmetric) {}

private:
  SegRange eval_range;
  bool symmetric;
};

} // namespace apex
