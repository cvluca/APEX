#include <libapex.h>

using namespace lbcrypto;
using namespace apex;

void test_carry_eval(uint64_t RingDim, uint32_t radix, uint32_t segmentCount)
{
  uint64_t p = RingParams::GetPlaintextModulus(RingDim);

  //---------------------------------------------
  // 1. Setuo BGV CryptoContext
  //---------------------------------------------
  // config BGV parameters
  CCParams<CryptoContextBGVRNS> parameters;
  parameters.SetPlaintextModulus(p);
  parameters.SetMultiplicativeDepth(30);
  parameters.SetRingDim(RingDim);
  parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);

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
    expected[i] = (vecX[i] - vecY[i] - vecY[i] - vecY[i] - vecY[i]) > 0 ? 1 : 0;  // expected result
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

  auto ctDiff = ctx->EvalSub(ctX, ctY);
  ctDiff = ctx->EvalSub(ctDiff, ctY);
  ctDiff = ctx->EvalSub(ctDiff, ctY);
  ctDiff = ctx->EvalSub(ctDiff, ctY);

  for (auto& segmentRange : ctX->GetSegmentRanges()) {
    std::cout << "Segment range before sub: " << segmentRange << "\n";
  }

  for (auto& segmentRange : ctDiff->GetSegmentRanges()) {
    std::cout << "Segment range after sub: " << segmentRange << "\n";
  }

  std::chrono::system_clock::time_point start, end;
  start = std::chrono::system_clock::now();

  ctx->EvalBalanceInPlace(ctDiff);
  ctx->EvalCarryInPlace(ctDiff);
  auto ctSign = ctx->EvalSign(ctDiff);
  end = std::chrono::system_clock::now();

  for (auto& segmentRange : ctDiff->GetSegmentRanges()) {
    std::cout << "Segment range after carry-prop: " << segmentRange << "\n";
  }

  for (auto& level : ctDiff->GetLevels()) {
    std::cout << "number of levels remaining after comp: " << 30 - level << "\n";
  }

  std::cout << "number of levels remaining after comp: " << 30 - ctSign->GetLevel() << "\n";

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
    int64_t expectedValue = vecX[i] - vecY[i] - vecY[i] - vecY[i] - vecY[i];
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
  test_carry_eval(1 << 17, 2, 4);

  return 0;
}
