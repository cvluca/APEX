#include "apexcontext.h"

namespace apex {

ApexContextImpl::ApexContextImpl(
  const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
  const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& publicKey,
  const ApexParams& params)
  : cc(cc), publicKey(publicKey), params(std::make_shared<ApexParams>(params))
{
  VerifyApexParams();
}

void ApexContextImpl::GenSumKey(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> secretKey)
{
  std::vector<int> rotstep;
  for (int i = 1; i < cc->GetRingDimension(); i *= 2)
  {
      rotstep.push_back(i);
      rotstep.push_back(-i);
  }

  cc->EvalRotateKeyGen(secretKey, rotstep);
  sumKeyGen = true;
}

lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ApexContextImpl::EvalSum(
  lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext) const
{
  auto result = ciphertext->Clone();
  EvalSumInPlace(result);
  return result;
}

void ApexContextImpl::EvalSumInPlace(
  lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext) const
{
  if (!sumKeyGen)
  {
    OPENFHE_THROW("Sum key not generated. Call GenSumKey() first.");
  }

  int64_t row = std::log2(cc->GetRingDimension());
  for (size_t i = 0; i < row; ++i)
  {
    int step = 1 << (row - i - 1);
    auto temp = ciphertext;
    auto rot_temp = cc->EvalRotate(temp, step);
    cc->EvalAddInPlace(ciphertext, rot_temp);
  }
}

} // namespace apex
