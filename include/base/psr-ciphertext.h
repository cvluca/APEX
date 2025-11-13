#pragma once

#include "psr.h"

namespace apex {

// PSR (Positional Segmented Representation) base class for ciphertexts
class PSRCiphertextBase : public PSR<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> {
public:
  PSRCiphertextBase() = default;

  PSRCiphertextBase(std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> segments)
    : PSR(std::move(segments)) {}

  virtual ~PSRCiphertextBase() = default;

  std::vector<size_t> GetLevels() const {
    std::vector<size_t> levels;
    levels.reserve(segments.size());
    for (const auto& segment : segments) {
      levels.push_back(segment->GetLevel());
    }
    return levels;
  }

  virtual size_t GetPackedSize() const {
    if (segments.empty()) return 0;
    return segments[0]->GetSlots();
  }
};

} // namespace apex
