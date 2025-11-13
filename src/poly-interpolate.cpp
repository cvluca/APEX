#include "poly-interpolate.h"

namespace apex {

// x^e mod m
uint64_t mod_pow(uint64_t x, uint64_t e, uint64_t m)
{
  uint64_t r = 1;
  uint64_t b = x % m;
  while (e > 0)
  {
    if (e & 1) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1;
  }
  return r;
}

std::vector<uint64_t> poly_add(
  const std::vector<uint64_t>& a,
  const std::vector<uint64_t>& b,
  PlaintextModulus p)
{
  size_t n = std::max(a.size(), b.size());

  std::vector<uint64_t> result(n, 0);
  for (size_t i = 0; i < n; i++)
  {
    uint64_t ai = (i < a.size()) ? a[i] : 0;
    uint64_t bi = (i < b.size()) ? b[i] : 0;
    result[i] = (ai + bi) % p;
  }
  return std::move(result);
}

std::vector<uint64_t> poly_mul(
  const std::vector<uint64_t>& a,
  const std::vector<uint64_t>& b,
  PlaintextModulus p)
{
  size_t n = a.size(), m = b.size();

  std::vector<uint64_t> result(n + m - 1, 0);
  for (size_t i = 0; i < n; i++)
    for (size_t j = 0; j < m; j++)
      result[i+j] = (result[i+j] + ((a[i] * b[j]) % p)) % p;
  return std::move(result);
}

std::vector<uint64_t> synthetic_divide(
  const std::vector<uint64_t>& poly,
  uint64_t root,
  PlaintextModulus p
)
{
  size_t m = poly.size() - 1;
  if (m == 0) {
    OPENFHE_THROW("synthetic_divide: Polynomial must have at least one coefficient.");
  }

  std::vector<uint64_t> result(m, 0);
  result[m - 1] = poly[m];
  for (int i = int(m) - 2; i >= 0; i--)
    result[i] = (poly[i + 1] + ((root * result[i + 1]) % p)) % p;
  return result;
}

std::vector<uint64_t> derivative(
  const std::vector<uint64_t>& poly,
  PlaintextModulus p)
{
  if (poly.size() <= 1) return {};

  std::vector<uint64_t> result(poly.size() - 1);
  for (size_t i = 1; i < poly.size(); i++)
    result[i - 1] = (poly[i] * i) % p;

  return std::move(result);
}

std::vector<uint64_t> GenInterpolateCoeffs(
  const std::vector<uint64_t>& x_vals,
  const std::vector<uint64_t>& y_vals,
  PlaintextModulus p)
{
  size_t n = x_vals.size();
  if (n != y_vals.size() || n < 2) {
    OPENFHE_THROW("GenInterpolateCoeffs: x_vals and y_vals must have the same size and at least 2 elements.");
  }

  // S(t) = prod((t - xi)) for i = 0 to n-1
  std::vector<uint64_t> S = {1};
  for (size_t i = 0; i < n; i++) {
    uint64_t neg_xi = (p - (x_vals[i] % p)) % p;
    S = poly_mul(S, {neg_xi, 1}, p);
  }

  std::vector<uint64_t> Sp = derivative(S, p);
  std::vector<uint64_t> P(n, 0);

  for (size_t i = 0; i < n; i++)
  {
    uint64_t denom = 0;
    for (auto it = Sp.rbegin(); it != Sp.rend(); ++it) {
      denom = (denom * (x_vals[i] % p) + *it) % p;
    }

    uint64_t inv_denom = mod_pow(denom, p - 2, p);

    std::vector<uint64_t> Qi = synthetic_divide(S, x_vals[i] % p, p);

    uint64_t factor = (((y_vals[i] + p) % p) * inv_denom) % p;
    for (size_t j = 0; j < n; j++)
      P[j] = (P[j] + ((factor * Qi[j]) % p)) % p;
  }

  while (!P.empty() && P.back() == 0) {
    P.pop_back(); // remove trailing zeros
  }

  return P;
}

} // namespace apex
