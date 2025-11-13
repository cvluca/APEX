#pragma once

#include <vector>
#include <openfhe.h>

namespace apex {

std::vector<uint64_t> GenInterpolateCoeffs(
  const std::vector<uint64_t>& x_vals,
  const std::vector<uint64_t>& y_vals,
  PlaintextModulus p
);

} // namespace apex
