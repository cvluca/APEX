#pragma once

#include "radix/radix.h"
#include "string/string-fwd.h"
#include "apex-fwd.h"
#include "apexparams.h"
#include "utils.h"

namespace apex {

enum CompType {
  EQ = 0,
  NE,
  GT,
  LT,
  GE,
  LE
};

class ApexContextImpl : public std::enable_shared_from_this<ApexContextImpl> {
public:
  ApexContextImpl() = default;

  ApexContextImpl(
    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
    const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& publicKey,
    const ApexParams& params);

  std::shared_ptr<ApexParams> GetApexParams() const
  {
    return this->params;
  }

  PlaintextModulus GetPlaintextModulus() const
  {
    return cc->GetCryptoParameters()->GetPlaintextModulus();
  }

  uint32_t GetPrecision() const
  {
    return params->GetSegmentCount() * params->GetRadix();
  }


  // Radix factory methods for different data types
  RadixPlaintext MakePackedRadixPlaintext(const std::vector<int64_t>& values) const;
  RadixPlaintext MakePackedRadixPlaintext(const std::vector<uint64_t>& values) const;
  RadixPlaintext MakePackedRadixPlaintext(const std::vector<double>& values) const;
  RadixPlaintext MakePackedRadixPlaintext(const std::vector<float>& values) const;

  // Radix overloads with custom ApexParams
  RadixPlaintext MakePackedRadixPlaintext(const std::vector<int64_t>& values,
                                          const ApexParams& customParams) const;
  RadixPlaintext MakePackedRadixPlaintext(const std::vector<uint64_t>& values,
                                          const ApexParams& customParams) const;
  RadixPlaintext MakePackedRadixPlaintext(const std::vector<double>& values,
                                          const ApexParams& customParams) const;
  RadixPlaintext MakePackedRadixPlaintext(const std::vector<float>& values,
                                          const ApexParams& customParams) const;

  StringPlaintext MakePackedStringPlaintext(
    const std::vector<std::string>& values,
    size_t max_length) const;

private:
  // Helper method for type-specific encoding
  template<typename T>
  RadixPlaintext MakePackedRadixPlaintextInternal(
    const std::vector<T>& values,
    const RadixEncoder& encoder,
    const ApexParams& customParams) const;

public:

  RadixCiphertext Encrypt(const RadixPlaintext& plaintext) const;

  StringCiphertext Encrypt(const StringPlaintext& plaintext) const;

  void Decrypt(const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& PrivateKey,
              const RadixCiphertext& ciphertext,
              RadixPlaintext* plaintext) const;

  void Decrypt(const lbcrypto::PrivateKey<lbcrypto::DCRTPoly>& PrivateKey,
              const StringCiphertext& ciphertext,
              StringPlaintext* plaintext) const;

  RadixCiphertext EvalSub(const RadixCiphertext& ciphertext1,
                          const RadixCiphertext& ciphertext2) const;

  void EvalSubInPlace(RadixCiphertext& ciphertext1,
                      const RadixCiphertext& ciphertext2) const;

  RadixCiphertext EvalAdd(const RadixCiphertext& ciphertext1,
                          const RadixCiphertext& ciphertext2) const;

  void EvalAddInPlace(RadixCiphertext& ciphertext1,
                      const RadixCiphertext& ciphertext2) const;

  RadixCiphertext EvalMult(const RadixCiphertext& ciphertext1,
                          const RadixCiphertext& ciphertext2) const;

  RadixCiphertext EvalCarry(const RadixCiphertext& ciphertext, bool ignore_overflow = false) const;

  void EvalCarryInPlace(RadixCiphertext& ciphertext, bool ignore_overflow = false) const;

  RadixCiphertext EvalBalance(const RadixCiphertext& ciphertext) const;

  void EvalBalanceInPlace(RadixCiphertext& ciphertext) const;

  RadixCiphertext ReduceSegment(const RadixCiphertext& ciphertext, const ApexParams& customParams);

  void ReduceSegmentInPlace(RadixCiphertext& ciphertext, const ApexParams& customParams);

  StringPattern EncodePattern(std::string pattern) const;

  StringPattern EncryptPattern(const StringPattern& pattern) const;

  lbcrypto::Ciphertext<lbcrypto::DCRTPoly> EvalLike(
    const StringCiphertext& ciphertext,
    const StringPattern& pattern);

  lbcrypto::Ciphertext<lbcrypto::DCRTPoly> EvalSign(const RadixCiphertext& ciphertext);

  lbcrypto::Ciphertext<lbcrypto::DCRTPoly> EvalZero(const RadixCiphertext& ciphertext);

  lbcrypto::Ciphertext<lbcrypto::DCRTPoly> EvalComp(
    const RadixCiphertext& ciphertext1,
    const RadixCiphertext& ciphertext2,
    CompType type);

  void GenSumKey(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> keyPair);

  lbcrypto::Ciphertext<lbcrypto::DCRTPoly> EvalSum(
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext) const;

  void EvalSumInPlace(lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& ciphertext) const;

  const lbcrypto::Plaintext GetConstPlaintext(int64_t val)
  {
    if (cached_const_pt.find(val) == cached_const_pt.end()) {
      cached_const_pt.emplace(val, cc->MakePackedPlaintext(std::vector<int64_t>(cc->GetRingDimension(), val)));
    }
    return cached_const_pt.at(val);
  }

  const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> GetConstCiphertext(int64_t val)
  {
    if (cached_const_ct.find(val) == cached_const_ct.end()) {
      auto pt = GetConstPlaintext(val);
      cached_const_ct.emplace(val, cc->Encrypt(publicKey, pt));
    }
    return cached_const_ct.at(val);
  }

  inline void VerifyApexParams() const {
    PlaintextModulus p = GetPlaintextModulus();
    uint32_t r = params->GetRadix();


    if (r <= 0 || r >= static_cast<uint32_t>(std::floor(std::log2(p)))) {
      OPENFHE_THROW("Radix must be in the range (0, log2(p)) where p is the plaintext modulus.");
    }
  }

private:
  lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc;
  std::shared_ptr<ApexParams> params;
  bool sumKeyGen = false;
  lbcrypto::PublicKey<lbcrypto::DCRTPoly> publicKey;
  std::unordered_map<int64_t, lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> cached_const_ct;
  std::unordered_map<int64_t, lbcrypto::Plaintext> cached_const_pt;
}; // class ApexContext

inline ApexContext MakeApexContext(
  const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc,
  const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& publicKey,
  const ApexParams& params)
{
  return std::make_shared<ApexContextImpl>(cc, publicKey, params);
}

} // namespace apex
