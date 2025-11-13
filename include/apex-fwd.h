#pragma once

#include <memory>

namespace apex {

class ApexContextImpl;

using ApexContext = std::shared_ptr<ApexContextImpl>;
using ConstApexContext = std::shared_ptr<const ApexContextImpl>;

} // namespace apex
