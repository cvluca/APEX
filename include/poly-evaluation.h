#pragma once

#include <vector>
#include <openfhe.h>
#include "coeffs/coeffs.h"

namespace apex {

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> EvalPoly(
  lbcrypto::ConstCiphertext<lbcrypto::DCRTPoly>& cipher,
  Coeffs coeffs
);

std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> EvalPolyMany(
  lbcrypto::ConstCiphertext<lbcrypto::DCRTPoly>& cipher,
  Coeffs coeffs
);

} // namespace apex
