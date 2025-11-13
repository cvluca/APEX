#pragma once

#include "utils.h"
#include <vector>
#include <cstdint>
#include <utility>
#include <iostream>

namespace apex {

class SegRange {
public:
  SegRange() : min(0), max(0) {}
  SegRange(int64_t min, int64_t max) : min(min), max(max) {}
  SegRange(const std::pair<int64_t, int64_t>& pair) : min(pair.first), max(pair.second) {}

  int64_t GetMin() const { return min; }
  int64_t GetMax() const { return max; }

  std::pair<int64_t, int64_t> ToPair() const { return {min, max}; }

  void Add(const SegRange& other) {
    min += other.min;
    max += other.max;
  }

  void Sub(const SegRange& other) {
    int64_t new_min = min - other.max;
    int64_t new_max = max - other.min;
    min = new_min;
    max = new_max;
  }

  void Mult(const SegRange& other) {
    int64_t p1 = min * other.min;
    int64_t p2 = min * other.max;
    int64_t p3 = max * other.min;
    int64_t p4 = max * other.max;

    min = std::min({p1, p2, p3, p4});
    max = std::max({p1, p2, p3, p4});
  }

  void Negate() {
    int64_t temp = -max;
    max = -min;
    min = temp;
  }

  bool NeedsCarry(int64_t base) const {
    return min <= -base || max >= base;
  }

  SegRange ComputeCarry(int64_t base) const {
    int64_t carry_min = min < 0 ? (min - 1) / base : (min + 1) / base;
    int64_t carry_max = max < 0 ? (max - 1) / base : (max + 1) / base;
    return SegRange(carry_min, carry_max);
  }

  void ApplyCarry(const SegRange& carryRange, int64_t base) {
    min -= carryRange.max * base;
    max -= carryRange.min * base;
  }

  void AddCarry(const SegRange& carryRange) {
    min += carryRange.min;
    max += carryRange.max;
  }

  friend std::ostream& operator<<(std::ostream& os, const SegRange& range) {
    os << "[" << range.min << ", " << range.max << "]";
    return os;
  }

private:
  int64_t min;
  int64_t max;
};

} // namespace apex
