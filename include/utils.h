#pragma once

#include <openfhe.h>
#include <bitset>

namespace apex {

inline int64_t mod(int64_t a, int64_t m)
{
  int64_t r = a % m;
  return (r < 0) ? r + m : r;
}

} // namespace apex
