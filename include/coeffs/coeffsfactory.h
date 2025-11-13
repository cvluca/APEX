#pragma once

#include <vector>
#include <unordered_map>
#include <string>
#include "utils.h"
#include "coeffs/coeffs-fwd.h"
#include "coeffs/compeval-coeffs.h"
#include "coeffs/zeroeval-coeffs.h"
#include "coeffs/carryeval-coeffs.h"
#include "base/seg-range.h"

namespace apex {

class CoeffsFactory {
public:
  static CarryEvalCoeffs GetCarryEvalCoeffs(
    uint64_t range,
    uint32_t radix,
    PlaintextModulus p
  );

  static CompEvalCoeffs GetCompEvalCoeffs(
    const SegRange& eval_range,
    PlaintextModulus p,
    bool symmetric
  );

  static ZeroEvalCoeffs GetZeroEvalCoeffs(
    const SegRange& eval_range,
    PlaintextModulus p
  );

private:
  static std::unordered_map<std::string, Coeffs> allCoeffs;
};

} // namespace apex
