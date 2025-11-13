#pragma once

#include "psr.h"

namespace apex {

class PSRPlaintextBase : public PSR<lbcrypto::Plaintext> {
public:
  PSRPlaintextBase() = default;

  PSRPlaintextBase(std::vector<lbcrypto::Plaintext> segments)
    : PSR(std::move(segments)) {}

  virtual ~PSRPlaintextBase() = default;

  virtual size_t GetPackedSize() const {
    if (segments.empty()) return 0;
    return segments[0]->GetLength();
  }

protected:
  void SetSegments(const std::vector<lbcrypto::Plaintext>& newSegments) {
    segments = newSegments;
  }
};


} // namespace apex
