#pragma once

#include <cstdint>
#include <unordered_map>
#include <stdexcept>
#include <string>
#include <vector>

namespace apex {

class RingParams {
public:
  static uint64_t GetPlaintextModulus(uint64_t ringDim) {
    static const std::unordered_map<uint64_t, uint64_t> paramTable = {
      // RingDim        PlaintextModulus
      // -------        ----------------
      {128,            65537},        // 2^7  - minimal security, testing only
      {256,            65537},        // 2^8  - minimal security, testing only
      {512,            65537},        // 2^9  - minimal security, testing only
      {1024,           65537},        // 2^10 - low security
      {2048,           65537},        // 2^11 - low security
      {4096,           65537},        // 2^12 - moderate security
      {8192,           65537},        // 2^13 - good security
      {16384,          65537},        // 2^14 - good security
      {32768,          65537},        // 2^15 - good security
      {65536,          786433},       // 2^16 - high security (TPC-H default)
      {131072,         786433},       // 2^17 - very high security
    };

    auto it = paramTable.find(ringDim);
    if (it == paramTable.end()) {
      throw std::invalid_argument(
        "No PlaintextModulus configured for RingDim=" + std::to_string(ringDim) +
        ". Supported values: 128, 2048, 4096, 32768, 65536, 131072");
    }

    return it->second;
  }
};

} // namespace apex
