#pragma once

#include <vector>
#include <openfhe.h>

namespace apex {

class CoeffsImpl {

public:
  CoeffsImpl() = delete;

  virtual const std::vector<uint64_t>& Get(size_t i) const
  {
    return coeffs[i];
  }

  virtual const std::vector<uint64_t>& Get() const
  {
    return coeffs[0];
  }

  const std::vector<std::vector<uint64_t>>& GetAll() const
  {
    return coeffs;
  }

  size_t Degree() const
  {
    return coeffs[0].size() - 1;
  }

  size_t Size() const
  {
    return coeffs.size();
  }

  bool OddOnly() const
  {
    return oddOnly;
  }

  bool EvenOnly() const
  {
    return evenOnly;
  }

  uint32_t GetBS() const
  {
    size_t degree = Degree();
    if (degree <= 4) {
      return degree;
    }

    double r = std::sqrt(static_cast<double>(degree));

    uint32_t k = static_cast<uint32_t>(std::floor(std::log2(r)));

    uint32_t lower = 1 << k;
    uint32_t upper = 1 << (k + 1);

    uint32_t bs = (r - static_cast<double>(lower) < static_cast<double>(upper) - r) ? lower : upper;
    return std::max(bs, static_cast<uint32_t>(4));
  }

  CoeffsImpl GetOdd() const
  {
    if (!oddOnly) {
      OPENFHE_THROW("Cannot get odd coefficients from non-odd-only coefficients.");
    }

    std::vector<std::vector<uint64_t>> oddCoeffs;
    for (const auto& coeff : coeffs) {
      std::vector<uint64_t> oddCoeff;
      for (size_t i = 1; i < coeff.size(); i += 2) {
      oddCoeff.push_back(coeff[i]);
      }
      oddCoeffs.push_back(std::move(oddCoeff));
    }
    return CoeffsImpl(std::move(oddCoeffs), p);
  }

  CoeffsImpl GetEven() const
  {
    if (!evenOnly) {
      OPENFHE_THROW("Cannot get even coefficients from non-even-only coefficients.");
    }

    std::vector<std::vector<uint64_t>> evenCoeffs;
    for (const auto& coeff : coeffs) {
      std::vector<uint64_t> evenCoeff;
      for (size_t i = 0; i < coeff.size(); i += 2) {
        evenCoeff.push_back(coeff[i]);
      }
      evenCoeffs.push_back(std::move(evenCoeff));
    }
    return CoeffsImpl(std::move(evenCoeffs), p);
  }

protected:
  CoeffsImpl(
    std::vector<std::vector<uint64_t>> coeffs,
    PlaintextModulus p
  ) : p(p)
  {
    this->coeffs = std::move(coeffs);
    if (this->coeffs.empty()) {
      OPENFHE_THROW("Coefficients cannot be empty.");
    }

    size_t degree = Degree();
    if (degree < 1) {
      OPENFHE_THROW("Coefficients degree must have at least 1.");
    }

    // all coefficients must be of the same degree
    oddOnly = degree > 1 ? true : false;
    evenOnly = degree > 2 ? true : false;
    for (size_t i = 0; i < Size(); i++) {
      if (this->coeffs[i].size() - 1 != degree) {
        OPENFHE_THROW("All coefficients must have the same degree.");
      }

      if (this->coeffs[i][degree] == 0) {
        OPENFHE_THROW("The highest-order coefficient cannot be set to 0.");
      }

      if (oddOnly) {
        for (size_t j = 0; j <= degree; j+=2) {
          if (this->coeffs[i][j] != 0) {
            oddOnly = false;
            break;
          }
        }
      }

      if (evenOnly) {
        for (size_t j = 1; j <= degree; j+=2) {
          if (this->coeffs[i][j] != 0) {
            evenOnly = false;
            break;
          }
        }
      }
    }
  }

  std::vector<std::vector<uint64_t>> coeffs;
  PlaintextModulus p;
  bool oddOnly;
  bool evenOnly;
};

} // namespace apex
