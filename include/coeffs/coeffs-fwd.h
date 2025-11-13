#pragma once

#include <memory>

namespace apex {

class CoeffsImpl;
class CarryEvalCoeffsImpl;
class CompEvalCoeffsImpl;
class ZeroEvalCoeffsImpl;

using Coeffs = std::shared_ptr<const CoeffsImpl>;
using CarryEvalCoeffs = std::shared_ptr<const CarryEvalCoeffsImpl>;
using CompEvalCoeffs = std::shared_ptr<const CompEvalCoeffsImpl>;
using ZeroEvalCoeffs = std::shared_ptr<const ZeroEvalCoeffsImpl>;

} // namespace apex
