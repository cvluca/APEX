#include <libapex.h>

using namespace lbcrypto;
using namespace apex;

void test_radix_comp(
  uint64_t RingDim, uint32_t radix, uint32_t segmentCount, bool test_eq=false)
{
  uint64_t p = RingParams::GetPlaintextModulus(RingDim);

  //---------------------------------------------
  // 1. Setuo BGV CryptoContext
  //---------------------------------------------
  // config BGV parameters
  const uint32_t depth = 20; // ensure enough depth for larger precisions
  CCParams<CryptoContextBGVRNS> parameters;
  parameters.SetPlaintextModulus(p);
  parameters.SetMultiplicativeDepth(depth);
  parameters.SetRingDim(RingDim);
  parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);

  KeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  const uint32_t precision = radix * segmentCount;

  ApexParams fparams;
  fparams.SetRadix(radix);
  fparams.SetSegmentCount(segmentCount);

  ApexContext ctx = MakeApexContext(cc, keyPair.publicKey, fparams);

  //---------------------------------------------
  // 2. Generate random inputs
  //---------------------------------------------
  const usint SLOT_COUNT = RingDim;

  std::default_random_engine engine(0);
  int64_t max_value = std::pow(2, precision/2) - 1;
  std::uniform_int_distribution<int> message(-max_value, max_value);

  std::cout << "Generating random inputs for " << SLOT_COUNT << " slots with max value " << max_value << std::endl;

  std::vector<int64_t> vecX(SLOT_COUNT), vecY(SLOT_COUNT), expected(SLOT_COUNT);

  for (uint i = 0; i < SLOT_COUNT; i++) {
    vecX[i] = int(message(engine));
    vecY[i] = int(message(engine));
    expected[i] = (test_eq ? (vecX[i] == vecY[i]) : (vecX[i] > vecY[i])) ? 1 : 0; // expected result
  }

  // check data validity
  for (size_t i = 0; i < SLOT_COUNT; i++) {
    if (vecX[i] < -max_value || vecX[i] > max_value ||
      vecY[i] < -max_value || vecY[i] > max_value) {
      std::cerr << "output values must be in [" << -max_value << ", " << max_value << ") range\n";
      return;
    }
  }

  RadixPlaintext radixX = ctx->MakePackedRadixPlaintext(vecX);
  RadixPlaintext radixY = ctx->MakePackedRadixPlaintext(vecY);
  auto ctX = ctx->Encrypt(radixX);
  auto ctY = ctx->Encrypt(radixY);

  std::chrono::system_clock::time_point start, end;
  start = std::chrono::system_clock::now();

  auto ctDiff = ctx->EvalSub(ctX, ctY);
  auto ctSign = test_eq ? ctx->EvalZero(ctDiff) : ctx->EvalSign(ctDiff);
  end = std::chrono::system_clock::now();

  for (auto& segmentRange : ctX->GetSegmentRanges()) {
    std::cout << "Segment range before sub: " << segmentRange << "\n";
  }
  for (auto& segmentRange : ctDiff->GetSegmentRanges()) {
    std::cout << "Segment range after sub: " << segmentRange << "\n";
  }

  std::cout << "number of levels remaining after comp: " << depth - ctSign->GetLevel() << "\n";

  RadixPlaintext radixResult;
  ctx->Decrypt(keyPair.secretKey, ctDiff, &radixResult);
  const auto& resultVec = radixResult->GetPackedValue();
  Plaintext ptSign;
  cc->Decrypt(keyPair.secretKey, ctSign, &ptSign);
  const auto& signVec = ptSign->GetPackedValue();

  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
  std::cout << "total time = " << duration << " ms\n";
  std::cout << "average time per slot = " << (duration / static_cast<double>(SLOT_COUNT)) << " ms\n";

  for (size_t i = 0; i < SLOT_COUNT; i++) {
    int64_t expectedValue = vecX[i] - vecY[i];
    if (resultVec[i] != expectedValue) {
      std::cerr << "Decryption failed for ctDiff at slot " << i << ": expected " << expectedValue << ", got " << resultVec[i] << "\n";
      return;
    }

    if (signVec[i] != expected[i]) {
      std::cerr << "Decryption failed for ctSign at slot " << i << ": expected " << expected[i] << ", got " << signVec[i] << "\n";
      return;
    }
  }
}

int main() {
  test_radix_comp(1 << 7, 2, 8);

  return 0;
}
