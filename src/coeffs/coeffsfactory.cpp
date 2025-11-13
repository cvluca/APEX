#include "coeffs/coeffsfactory.h"
#include "poly-interpolate.h"
#include "string/string-encoder.h"

namespace apex {

std::unordered_map<std::string, Coeffs> CoeffsFactory::allCoeffs;

CarryEvalCoeffs CoeffsFactory::GetCarryEvalCoeffs(
  uint64_t range,
  uint32_t radix,
  PlaintextModulus p)
{

  std::string key = "carry_eval_" +
                    std::to_string(range) + "_" +
                    std::to_string(radix) + "_" +
                    std::to_string(p);

  if (allCoeffs.find(key) != allCoeffs.end()) {
    return std::dynamic_pointer_cast<const CarryEvalCoeffsImpl>(allCoeffs[key]);
  }


  int64_t end = static_cast<int64_t>(range);
  int64_t start = -end;
  int64_t pos_p = static_cast<int64_t>(p);
  int64_t base = 1LL << radix;

  std::vector<uint64_t> x_vals, y_vals;

  for (int64_t v = start; v <= end; ++v) {
    int64_t x = mod(v, pos_p);
    x_vals.push_back(static_cast<uint64_t>(x));

    int64_t y = std::round((double)v/base);
    y_vals.push_back(static_cast<uint64_t>(mod(y, pos_p)));
  }

  std::vector<std::vector<uint64_t>> coeffs;
  coeffs.push_back(GenInterpolateCoeffs(x_vals, y_vals, p));

  allCoeffs[key] =
    MakeCarryEvalCoeffs(coeffs, range, radix, p);

  return std::dynamic_pointer_cast<const CarryEvalCoeffsImpl>(allCoeffs[key]);
}

CompEvalCoeffs CoeffsFactory::GetCompEvalCoeffs(
  const SegRange& eval_range,
  PlaintextModulus p, bool symmetric)
{
  std::string key = "comp_eval_" +
                    std::to_string(eval_range.GetMin()) + "_" +
                    std::to_string(eval_range.GetMax()) + "_" +
                    std::to_string(symmetric) + "_" +
                    std::to_string(p);

  if (allCoeffs.find(key) != allCoeffs.end()) {
    return std::dynamic_pointer_cast<const CompEvalCoeffsImpl>(allCoeffs[key]);
  }


  std::vector<uint64_t> x_vals, y_vals;
  int64_t pos_p = static_cast<int64_t>(p);
  for (int64_t v = eval_range.GetMin(); v <= eval_range.GetMax(); ++v) {
    int64_t x = mod(v, pos_p);
    x_vals.push_back(static_cast<uint64_t>(x));

    if (symmetric) {
      y_vals.push_back((x == 0) ? 0 : ((x <= p/2) ? 1 : p-1));
    } else {
      y_vals.push_back((x == 0) ? p-1 : ((x <= p/2) ? 1 : 0));
    }
  }

  std::vector<std::vector<uint64_t>> coeffs;
  coeffs.push_back(std::move(GenInterpolateCoeffs(x_vals, y_vals, p)));

  allCoeffs[key] = MakeCompEvalCoeffs(coeffs, eval_range, p, symmetric);

  return std::dynamic_pointer_cast<const CompEvalCoeffsImpl>(allCoeffs[key]);
}

ZeroEvalCoeffs CoeffsFactory::GetZeroEvalCoeffs(
  const SegRange& eval_range,
  PlaintextModulus p)
{
  std::string key = "comp_zero_" +
                    std::to_string(eval_range.GetMin()) + "_" +
                    std::to_string(eval_range.GetMax()) + "_" +
                    std::to_string(p);

  if (allCoeffs.find(key) != allCoeffs.end()) {
    return std::dynamic_pointer_cast<const ZeroEvalCoeffsImpl>(allCoeffs[key]);
  }


  std::vector<uint64_t> x_vals, y_vals;
  int64_t pos_p = static_cast<int64_t>(p);
  for (int64_t v = eval_range.GetMin(); v <= eval_range.GetMax(); ++v) {
    int64_t x = mod(v, pos_p);
    x_vals.push_back(static_cast<uint64_t>(x));
    y_vals.push_back((x == 0) ? 1U : 0U);
  }

  std::vector<std::vector<uint64_t>> coeffs;
  coeffs.push_back(std::move(GenInterpolateCoeffs(x_vals, y_vals, p)));

  allCoeffs[key] = MakeZeroEvalCoeffs(coeffs, eval_range, p);

  return std::dynamic_pointer_cast<const ZeroEvalCoeffsImpl>(allCoeffs[key]);
}

} // namespace apex
