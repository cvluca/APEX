#pragma once

#include <memory>

namespace apex {

class RadixCiphertextImpl;
class RadixPlaintextImpl;

using RadixCiphertext = std::shared_ptr<RadixCiphertextImpl>;
using RadixPlaintext = std::shared_ptr<RadixPlaintextImpl>;

} // namespace apex
