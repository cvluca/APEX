#pragma once

#include <memory>

namespace apex {

class StringCiphertextImpl;
class StringPlaintextImpl;
class StringTokenImpl;
class StringPatternImpl;

using StringCiphertext = std::shared_ptr<StringCiphertextImpl>;
using StringPlaintext = std::shared_ptr<StringPlaintextImpl>;
using StringToken = std::shared_ptr<StringTokenImpl>;
using StringPattern = std::shared_ptr<StringPatternImpl>;

} // namespace apex
