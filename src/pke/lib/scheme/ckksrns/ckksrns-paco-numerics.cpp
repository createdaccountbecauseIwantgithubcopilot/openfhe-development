//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#include "scheme/ckksrns/ckksrns-paco-numerics.h"

#include "utils/exception.h"

#include <boost/multiprecision/cpp_dec_float.hpp>

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>

namespace lbcrypto::paco::detail {
namespace {

constexpr long double kPi = 3.141592653589793238462643383279502884L;

using boost::multiprecision::cpp_dec_float_100;

long double ToFiniteLongDouble(const BigInteger& value, const char* label) {
    const long double converted = value.ConvertToLongDouble();
    if (!std::isfinite(converted)) {
        std::ostringstream message;
        message << "PaCo " << label << " exceeds the supported long-double exponent range";
        OPENFHE_THROW(message.str());
    }
    return converted;
}

cpp_dec_float_100 ToHighPrecision(const BigInteger& value) {
    std::ostringstream encoded;
    encoded << value;
    return cpp_dec_float_100(encoded.str());
}

}  // namespace

DCRTPoly::PolyLargeType InterpolateActiveQ(DCRTPoly polynomial) {
    if (polynomial.GetNumOfElements() == 0)
        OPENFHE_THROW("PaCo cannot interpolate an empty active-Q basis");
    if (!polynomial.GetParams())
        OPENFHE_THROW("PaCo cannot interpolate a polynomial without CRT parameters");
    if (polynomial.GetFormat() != Format::COEFFICIENT)
        polynomial.SetFormat(Format::COEFFICIENT);
    return polynomial.CRTInterpolate();
}

BigInteger AddModulo(const BigInteger& lhs, const BigInteger& rhs, const BigInteger& modulus) {
    if (modulus == BigInteger(0))
        OPENFHE_THROW("PaCo modular addition requires a positive modulus");
    return (lhs.Mod(modulus) + rhs.Mod(modulus)).Mod(modulus);
}

BigInteger NegateModulo(const BigInteger& value, const BigInteger& modulus) {
    if (modulus == BigInteger(0))
        OPENFHE_THROW("PaCo modular negation requires a positive modulus");
    const BigInteger reduced = value.Mod(modulus);
    return reduced == BigInteger(0) ? BigInteger(0) : modulus - reduced;
}

std::complex<double> CirclePhase(const BigInteger& residue, const BigInteger& modulus) {
    if (modulus <= BigInteger(1))
        OPENFHE_THROW("PaCo phase conversion requires modulus greater than one");
    const BigInteger reduced   = residue.Mod(modulus);
    const BigInteger half      = modulus >> 1;
    const bool negative        = reduced > half;
    const BigInteger magnitude = negative ? modulus - reduced : reduced;

    // Do not convert the integers separately to binary64/long double.  For a
    // multi-tower active modulus that can discard low residue bits before the
    // division.  One hundred decimal digits are far beyond the precision of
    // the final complex<double> representation and make this conversion
    // independent of the host long-double format.
    cpp_dec_float_100 ratio = ToHighPrecision(magnitude) / ToHighPrecision(modulus);
    if (ratio < 0 || ratio > cpp_dec_float_100("0.5000000000000000000000000000000000000001"))
        OPENFHE_THROW("PaCo centered phase ratio is outside [0,1/2]");
    ratio                         = min(ratio, cpp_dec_float_100("0.5"));
    const cpp_dec_float_100 pi    = acos(cpp_dec_float_100(-1));
    const cpp_dec_float_100 angle = (negative ? -1 : 1) * 2 * pi * ratio;
    const double real             = cos(angle).convert_to<double>();
    const double imag             = sin(angle).convert_to<double>();
    if (!std::isfinite(real) || !std::isfinite(imag))
        OPENFHE_THROW("PaCo high-precision phase conversion produced a non-finite binary64 value");
    return {real, imag};
}

double CheckedBigRatio(const BigInteger& numerator, long double denominator, const char* label) {
    if (denominator <= 0.0L || !std::isfinite(denominator))
        OPENFHE_THROW("PaCo big-ratio denominator must be finite and positive");
    const long double ratio = ToFiniteLongDouble(numerator, label ? label : "big-ratio numerator") / denominator;
    if (!std::isfinite(ratio) || ratio < 0.0L || ratio > static_cast<long double>(std::numeric_limits<double>::max())) {
        std::ostringstream message;
        message << "PaCo " << (label ? label : "big ratio") << " cannot be represented as a finite double";
        OPENFHE_THROW(message.str());
    }
    return static_cast<double>(ratio);
}

PaCoNumericalBudget AnalyzeNumericalBudget(const BigInteger& modulus, long double maximumAbsCoefficient,
                                           long double maximumNonSmallAngleAbsoluteError) {
    if (modulus <= BigInteger(1))
        OPENFHE_THROW("PaCo numerical analysis requires modulus greater than one");
    if (!std::isfinite(maximumAbsCoefficient) || maximumAbsCoefficient <= 0.0L)
        OPENFHE_THROW("PaCo numerical analysis requires a finite positive coefficient bound");
    if (!std::isfinite(maximumNonSmallAngleAbsoluteError) || maximumNonSmallAngleAbsoluteError < 0.0L)
        OPENFHE_THROW("PaCo numerical analysis requires a finite nonnegative non-small-angle error bound");

    PaCoNumericalBudget budget;
    budget.modulusBits                       = modulus.GetMSB();
    budget.maximumAbsCoefficient             = maximumAbsCoefficient;
    budget.maximumNonSmallAngleAbsoluteError = maximumNonSmallAngleAbsoluteError;
    const long double q                      = ToFiniteLongDouble(modulus, "numerical-analysis modulus");
    const long double occupiedMagnitude      = maximumAbsCoefficient + maximumNonSmallAngleAbsoluteError;
    budget.avoidsModularWrap                 = occupiedMagnitude < q / 2.0L;
    budget.phaseArgumentBound                = 2.0L * kPi * occupiedMagnitude / q;
    budget.smallAngleErrorBound =
        (4.0L * kPi * kPi / 6.0L) * occupiedMagnitude * occupiedMagnitude * occupiedMagnitude / (q * q);
    // The non-small-angle term is deliberately supplied as one end-to-end
    // bound.  An operation count alone cannot bound cancellation, transform
    // norms, CKKS encoding/rescaling error, or key-switch noise.
    budget.totalAbsoluteErrorBound = budget.smallAngleErrorBound + maximumNonSmallAngleAbsoluteError;
    if (budget.totalAbsoluteErrorBound == 0.0L)
        budget.conditionalPrecisionBits = std::numeric_limits<long double>::infinity();
    else
        budget.conditionalPrecisionBits = std::log2(maximumAbsCoefficient / budget.totalAbsoluteErrorBound);
    return budget;
}

void RequireNumericalBudget(const PaCoNumericalBudget& budget, uint32_t requestedPrecisionBits) {
    if (requestedPrecisionBits == 0)
        OPENFHE_THROW("PaCo certified precision target must be positive");
    if (!budget.avoidsModularWrap)
        OPENFHE_THROW("PaCo numerical budget does not avoid modular wrap");
    if (!std::isfinite(budget.conditionalPrecisionBits) && budget.totalAbsoluteErrorBound != 0.0L)
        OPENFHE_THROW("PaCo numerical budget produced a non-finite precision bound");
    if (budget.conditionalPrecisionBits < static_cast<long double>(requestedPrecisionBits)) {
        std::ostringstream message;
        message << "PaCo conditional numerical budget provides only "
                << static_cast<double>(budget.conditionalPrecisionBits) << " bits, below the requested "
                << requestedPrecisionBits;
        OPENFHE_THROW(message.str());
    }
}

std::string FormatNumericalBudget(const PaCoNumericalBudget& budget) {
    std::ostringstream output;
    output << std::setprecision(18) << "modulus_bits=" << budget.modulusBits
           << " max_abs_coefficient=" << static_cast<double>(budget.maximumAbsCoefficient)
           << " max_non_small_angle_error=" << static_cast<double>(budget.maximumNonSmallAngleAbsoluteError)
           << " phase_argument_bound=" << static_cast<double>(budget.phaseArgumentBound)
           << " small_angle_error_bound=" << static_cast<double>(budget.smallAngleErrorBound)
           << " total_error_bound=" << static_cast<double>(budget.totalAbsoluteErrorBound)
           << " conditional_precision_bits=" << static_cast<double>(budget.conditionalPrecisionBits)
           << " avoids_modular_wrap=" << (budget.avoidsModularWrap ? "true" : "false");
    return output.str();
}

}  // namespace lbcrypto::paco::detail
