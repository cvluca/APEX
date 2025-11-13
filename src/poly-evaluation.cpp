#include "poly-evaluation.h"

namespace apex {

std::unordered_map<usint, lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> PrecomputePowers(
  lbcrypto::ConstCiphertext<lbcrypto::DCRTPoly>& cipher,
  Coeffs coeffs
) {
  std::unordered_map<usint, lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> powers;

  const uint32_t k = coeffs->Degree();
  const usint bs = coeffs->GetBS();

  std::vector<bool> indices(bs, false);
  for (size_t i = 1; i <= bs; i++) {
    if (!(i & (i - 1))) {
      // if i is a power of 2
      indices[i] = true;
    } else {
      bool all_zero_coeffs = true;
      for (size_t n = 0; n < coeffs->Size(); n++) {
        const auto& coeffs_n = coeffs->Get(n);
        for (size_t j = i; j <= k; j += bs) {
          if (coeffs_n[j] != 0) {
            all_zero_coeffs = false;
            break;
          }
        }
        if (!all_zero_coeffs) break;
      }
      if (!all_zero_coeffs) indices[i] = true;
    }
  }

  // verify indices
  for (size_t i = bs; i > 1; i--) {
    if (indices[i] && (i & (i - 1))) {
      usint a = i/2;
      bool can_compute = false;
      while(a > 0) {
        if (indices[a] && indices[i-a]) {
          can_compute = true;
          break;
        }
        a--;
      }
      if (!can_compute) {
        a = i/2;
        indices[a] = true;
        indices[i-a] = true;
      }
    }
  }

  powers[1] = cipher->Clone();
  auto cc = cipher->GetCryptoContext();

  // computes all power of 2 powers up to k for cipher
  for (size_t i = 2; i < k; i *= 2) {
    powers[i] = cc->EvalSquare(powers[i / 2]);
    /*cc->ModReduceInPlace(powers[i]);*/
  }

  std::set<usint> computed = {1};
  for (size_t i = 2; i <= bs; i++) {
    if (!indices[i]) continue;

    if (powers.find(i) != powers.end()) {
      computed.insert(i);
      continue;
    }

    auto it = computed.upper_bound(i/2);
    if (it != computed.begin()) --it;

    for (auto rit = std::make_reverse_iterator(std::next(it)); rit != computed.rend(); ++rit) {
      usint a = *rit;
      usint b = i - a;
      if (computed.count(b)) {
        if (a == b) {
          powers[i] = cc->EvalSquare(powers[a]);
          /*cc->ModReduceInPlace(powers[i]);*/
        } else {
          powers[i] = cc->EvalMult(powers[a], powers[b]);
          /*cc->ModReduceInPlace(powers[i]);*/
        }
        computed.insert(i);
        break;
      }
    }
  }

  return powers;
}

std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> EvalPolyBSGS(
  lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc,
  Coeffs coeffs,
  std::unordered_map<usint, lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& powers,
  const usint coeffsStart,
  const usint coeffsEnd
) {
  const uint32_t k = coeffs->Degree();
  const int32_t bs = static_cast<int32_t>(coeffs->GetBS());

  if (coeffsStart > coeffsEnd || coeffsStart > k || coeffsStart == 0) {
    OPENFHE_THROW("Invalid coefficient range (" + std::to_string(coeffsStart) + " to " +
                  std::to_string(coeffsEnd) + ") for polynomial evaluation.");
  }

  int32_t n = static_cast<int32_t>(coeffsEnd - coeffsStart + 1);

  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> ctResult(coeffs->Size(), nullptr);

  while (n > bs) {
    int32_t gs = 1 << static_cast<int32_t>(std::ceil(std::log2(n)) - 1);

    std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> ctGroup = EvalPolyBSGS(
      cc, coeffs, powers, coeffsStart + gs, coeffsStart + n - 1);
    for (size_t i = 0; i < coeffs->Size(); i++) {
      if (ctGroup[i] != nullptr) {
        ctGroup[i] = cc->EvalMult(ctGroup[i], powers[gs]);
        if (ctResult[i] == nullptr) {
          ctResult[i] = ctGroup[i];
        } else {
          cc->EvalAddInPlace(ctResult[i], ctGroup[i]);
        }
      }
    }
    n = gs;
  }

  for (int32_t i = n-1; i >= 0; i--) {
    for (size_t j = 0; j < coeffs->Size(); j++) {
      const auto& coeff = coeffs->Get(j)[i + coeffsStart];
      if (coeff == 0) continue;
      lbcrypto::ConstPlaintext ptCoeff = cc->MakePackedPlaintext(std::vector<int64_t>(cc->GetRingDimension(), coeff));
      lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ctCoeff = cc->EvalMult(powers[i+1], ptCoeff);
      if (ctResult[j] == nullptr) {
        ctResult[j] = ctCoeff;
      } else {
        cc->EvalAddInPlace(ctResult[j], ctCoeff);
      }
    }
  }

  return std::move(ctResult);
}

std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> EvalPolyManyCore(
  lbcrypto::ConstCiphertext<lbcrypto::DCRTPoly>& cipher,
  Coeffs coeffs
) {
  std::unordered_map<usint, lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> powers = PrecomputePowers(cipher, coeffs);

  auto cc = cipher->GetCryptoContext();
  std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> result = EvalPolyBSGS(cc, coeffs, powers, 1, coeffs->Degree());

  for (size_t i = 0; i < coeffs->Size(); i++) {
    if (coeffs->Get(i)[0] != 0) {
      lbcrypto::ConstPlaintext ptCoeff = cc->MakePackedPlaintext(std::vector<int64_t>(cc->GetRingDimension(), coeffs->Get(i)[0]));
      cc->EvalAddInPlace(result[i], ptCoeff);
    }
  }

  return std::move(result);
}

std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> EvalPolyMany(
  lbcrypto::ConstCiphertext<lbcrypto::DCRTPoly>& cipher,
  Coeffs coeffs
) {
  if (coeffs->OddOnly()) {
    auto cc = cipher->GetCryptoContext();
    auto tmp = cc->EvalSquare(cipher);
    auto result = EvalPolyManyCore(tmp, std::make_shared<const CoeffsImpl>(coeffs->GetOdd()));

    for (size_t i = 0; i < coeffs->Size(); i++) {
      result[i] = cc->EvalMult(result[i], cipher);
    }
    return result;
  } else if (coeffs->EvenOnly()) {
    auto cc = cipher->GetCryptoContext();
    auto tmp = cc->EvalSquare(cipher);
    auto result = EvalPolyManyCore(tmp, std::make_shared<const CoeffsImpl>(coeffs->GetEven()));
    return result;
  }

  return EvalPolyManyCore(cipher, coeffs);
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> EvalPoly(
  lbcrypto::ConstCiphertext<lbcrypto::DCRTPoly>& cipher,
  Coeffs coeffs
) {
  if (coeffs->Size() != 1) {
    OPENFHE_THROW("EvalPoly expects a single coefficient set, got " + std::to_string(coeffs->Size()) + ".");
  }

  return std::move(EvalPolyMany(cipher, coeffs)[0]);
}

} // namespace apex
