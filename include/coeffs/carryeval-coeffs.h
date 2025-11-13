#pragma once

#include "coeffsbase.h"
#include "coeffs-fwd.h"

namespace apex {

inline CarryEvalCoeffs MakeCarryEvalCoeffs(
  std::vector<std::vector<uint64_t>> coeffs,
  int64_t range,
  uint32_t radix,
  PlaintextModulus p)
{
  return std::make_shared<CarryEvalCoeffsImpl>(
    std::move(coeffs), range, radix, p);
}

class CarryEvalCoeffsImpl : public CoeffsImpl {
public:
  CarryEvalCoeffsImpl(
    std::vector<std::vector<uint64_t>> coeffs,
    int64_t range,
    uint32_t radix,
    PlaintextModulus p
  ) : CoeffsImpl(std::move(coeffs), p),
      range(range), radix(radix) {}

private:
  int64_t range;
  uint32_t radix;
};

} // namespace apex
