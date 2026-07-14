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
#include "scheme/ckksrns/ckksrns-paco.h"

#include "gtest/gtest.h"

#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <cmath>
#include <complex>
#include <limits>
#include <set>
#include <string>
#include <vector>

namespace lbcrypto {
namespace {

using boost::multiprecision::cpp_dec_float_100;
using boost::multiprecision::cpp_int;

constexpr long double kPi = 3.141592653589793238462643383279502884L;

struct HighPrecisionComplex {
    cpp_dec_float_100 real = 0;
    cpp_dec_float_100 imag = 0;
};

HighPrecisionComplex operator+(const HighPrecisionComplex& left, const HighPrecisionComplex& right) {
    return {left.real + right.real, left.imag + right.imag};
}

HighPrecisionComplex operator-(const HighPrecisionComplex& left, const HighPrecisionComplex& right) {
    return {left.real - right.real, left.imag - right.imag};
}

HighPrecisionComplex operator*(const HighPrecisionComplex& left, const HighPrecisionComplex& right) {
    return {left.real * right.real - left.imag * right.imag, left.real * right.imag + left.imag * right.real};
}

HighPrecisionComplex operator*(const cpp_dec_float_100& scalar, const HighPrecisionComplex& value) {
    return {scalar * value.real, scalar * value.imag};
}

uint32_t OracleBitReverse(uint32_t value, uint32_t bits) {
    uint32_t reversed = 0;
    for (uint32_t bit = 0; bit < bits; ++bit) {
        reversed = (reversed << 1) | (value & 1U);
        value >>= 1;
    }
    return reversed;
}

uint64_t OraclePowMod(uint64_t base, uint64_t exponent, uint64_t modulus) {
    uint64_t result = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0)
            result = (result * base) % modulus;
        base = (base * base) % modulus;
        exponent >>= 1;
    }
    return result;
}

HighPrecisionComplex OracleRoot4N(uint32_t dimension, uint64_t exponent) {
    const uint64_t order = 4ULL * dimension;
    const cpp_dec_float_100 angle =
        2 * acos(cpp_dec_float_100(-1)) * cpp_dec_float_100(exponent % order) / cpp_dec_float_100(order);
    return {cos(angle), sin(angle)};
}

uint32_t OracleExactLog2(uint32_t value) {
    uint32_t result = 0;
    while (value > 1) {
        value >>= 1;
        ++result;
    }
    return result;
}

HighPrecisionComplex OracleInverseDStageRow(const std::vector<HighPrecisionComplex>& input, uint32_t row,
                                            uint32_t logStride) {
    const uint32_t dimension  = static_cast<uint32_t>(input.size());
    const uint32_t halfStride = 1U << logStride;
    const uint32_t stride     = 2 * halfStride;
    const uint32_t block      = row / stride;
    const bool upper          = (row % stride) >= halfStride;
    const uint32_t reversed   = OracleBitReverse(block, OracleExactLog2(dimension) - 1 - logStride);
    const uint64_t rootOrder  = 4ULL * dimension;
    const uint64_t rootExponent =
        (static_cast<uint64_t>(halfStride) * OraclePowMod(5, reversed, rootOrder)) % rootOrder;
    if (!upper)
        return cpp_dec_float_100("0.5") * (input[row] + input[(row + halfStride) % dimension]);

    const auto inverseRoot = cpp_dec_float_100("0.5") * OracleRoot4N(dimension, (rootOrder - rootExponent) % rootOrder);
    return inverseRoot * (input[(row + dimension - halfStride) % dimension] - input[row]);
}

HighPrecisionComplex OracleInverseEStageRow(const std::vector<HighPrecisionComplex>& input, uint32_t row,
                                            uint32_t logStride, uint32_t reversalBlock) {
    const uint32_t dimension  = static_cast<uint32_t>(input.size());
    const uint64_t divisor    = 2ULL * (1ULL << logStride);
    const uint32_t halfStride = static_cast<uint32_t>(reversalBlock / divisor);
    if (halfStride < 1)
        return OracleInverseDStageRow(input, row, logStride);

    const uint32_t stride                = 2 * halfStride;
    const uint32_t rowDiv                = row / stride;
    const uint32_t rowMod                = row % stride;
    const bool upper                     = rowMod >= halfStride;
    const uint32_t local                 = upper ? rowMod - halfStride : rowMod;
    const uint32_t dimensionOverBlock    = dimension / reversalBlock;
    const uint32_t logDimensionOverBlock = OracleExactLog2(dimensionOverBlock);
    const uint64_t rootOrder             = 4ULL * dimension;
    const uint64_t exponent              = static_cast<uint64_t>(local) * dimensionOverBlock +
                              OracleBitReverse(rowDiv >> logStride, logDimensionOverBlock);
    const uint64_t rootExponent = ((1ULL << logStride) * OraclePowMod(5, exponent, rootOrder)) % rootOrder;
    if (!upper)
        return cpp_dec_float_100("0.5") * (input[row] + input[(row + halfStride) % dimension]);

    const auto inverseRoot = cpp_dec_float_100("0.5") * OracleRoot4N(dimension, (rootOrder - rootExponent) % rootOrder);
    return inverseRoot * (input[(row + dimension - halfStride) % dimension] - input[row]);
}

TEST(UTCKKSRNS_PACO_NUMERICS, ArbitraryPrecisionCirclePhaseMatchesIndependentOracle) {
    const cpp_int qReference = (cpp_int(1) << 180) - 137;
    const cpp_int rReference = (cpp_int(1) << 177) + 123456789;
    const BigInteger q(qReference.convert_to<std::string>());
    const BigInteger r(rReference.convert_to<std::string>());

    const auto actual             = paco::detail::CirclePhase(r, q);
    const cpp_dec_float_100 angle = cpp_dec_float_100(2) * acos(cpp_dec_float_100(-1)) * cpp_dec_float_100(rReference) /
                                    cpp_dec_float_100(qReference);
    const std::complex<double> expected(sin(angle + acos(cpp_dec_float_100(-1)) / 2).convert_to<double>(),
                                        sin(angle).convert_to<double>());
    EXPECT_NEAR(actual.real(), expected.real(), 2e-15);
    EXPECT_NEAR(actual.imag(), expected.imag(), 2e-15);

    const auto negative = paco::detail::CirclePhase(q - r, q);
    EXPECT_NEAR(negative.real(), actual.real(), 2e-15);
    EXPECT_NEAR(negative.imag(), -actual.imag(), 2e-15);
}

TEST(UTCKKSRNS_PACO_NUMERICS, PhaseConversionDoesNotDependOnHostLongDoubleExponentRange) {
    BigInteger q(1);
    q <<= 20000;
    q -= BigInteger(159);
    BigInteger r = q >> 2;
    r += BigInteger(123);

    const auto actual = paco::detail::CirclePhase(r, q);
    EXPECT_NEAR(actual.real(), 0.0, 2e-15);
    EXPECT_NEAR(actual.imag(), 1.0, 2e-15);
}

TEST(UTCKKSRNS_PACO_NUMERICS, ProductionScaleInverseDEStagesMatchIndependentHighPrecisionOracle) {
    constexpr uint32_t dimension     = 32768;
    constexpr uint32_t reversalBlock = 64;
    constexpr double tolerance       = 1e-13;

    std::vector<std::complex<double>> input(dimension);
    std::vector<HighPrecisionComplex> highPrecisionInput(dimension);
    for (uint32_t index = 0; index < dimension; ++index) {
        const int32_t realNumerator = static_cast<int32_t>(index % 257) - 128;
        const int32_t imagNumerator = static_cast<int32_t>((index * 73U) % 251) - 125;
        input[index]                = {std::ldexp(static_cast<double>(realNumerator), -8),
                        std::ldexp(static_cast<double>(imagNumerator), -9)};
        highPrecisionInput[index]   = {cpp_dec_float_100(realNumerator) / 256, cpp_dec_float_100(imagNumerator) / 512};
    }

    const std::set<uint32_t> fixedRows{0, 1, 31, 32, 63, 64, 127, 1023, 16383, 16384, 32703, 32704, 32767};
    for (uint32_t logStride = 0; logStride <= 7; ++logStride) {
        SCOPED_TRACE("logStride=" + std::to_string(logStride));
        const auto actual = paco::detail::MakeEStage(dimension, logStride, reversalBlock, true).Apply(input);

        const uint32_t eHalfStride      = static_cast<uint32_t>(reversalBlock / (2ULL * (1ULL << logStride)));
        const uint32_t activeHalfStride = eHalfStride == 0 ? 1U << logStride : eHalfStride;
        std::set<uint32_t> sampledRows  = fixedRows;
        for (const uint32_t boundary : {activeHalfStride, 2 * activeHalfStride, dimension / 2}) {
            if (boundary > 0)
                sampledRows.insert(boundary - 1);
            if (boundary < dimension)
                sampledRows.insert(boundary);
        }

        std::vector<std::complex<double>> directD;
        if (eHalfStride == 0)
            directD = paco::detail::MakeDStage(dimension, logStride, true).Apply(input);

        for (const uint32_t row : sampledRows) {
            SCOPED_TRACE("row=" + std::to_string(row));
            const auto expected = OracleInverseEStageRow(highPrecisionInput, row, logStride, reversalBlock);
            EXPECT_NEAR(actual[row].real(), expected.real.convert_to<double>(), tolerance);
            EXPECT_NEAR(actual[row].imag(), expected.imag.convert_to<double>(), tolerance);
            if (!directD.empty()) {
                EXPECT_NEAR(directD[row].real(), expected.real.convert_to<double>(), tolerance);
                EXPECT_NEAR(directD[row].imag(), expected.imag.convert_to<double>(), tolerance);
            }
        }
    }
}

TEST(UTCKKSRNS_PACO_NUMERICS, SmallAngleBudgetIsConservativeAgainstHighPrecisionOracle) {
    const BigInteger q(uint64_t{1} << 44);
    constexpr long double bound = static_cast<long double>(uint64_t{1} << 32);
    const auto budget           = paco::detail::AnalyzeNumericalBudget(q, bound, 0.0L);
    ASSERT_TRUE(budget.avoidsModularWrap);

    const cpp_dec_float_100 qHigh     = cpp_dec_float_100(cpp_int(1) << 44);
    const cpp_dec_float_100 xHigh     = cpp_dec_float_100(cpp_int(1) << 32);
    const cpp_dec_float_100 pi        = acos(cpp_dec_float_100(-1));
    const cpp_dec_float_100 recovered = qHigh / (2 * pi) * sin(2 * pi * xHigh / qHigh);
    const long double observed        = (xHigh - recovered).convert_to<long double>();
    EXPECT_GT(budget.smallAngleErrorBound, observed);
    EXPECT_GT(budget.conditionalPrecisionBits, 20.0L);
    EXPECT_NO_THROW(paco::detail::RequireNumericalBudget(budget, 20));
    EXPECT_THROW(paco::detail::RequireNumericalBudget(budget, 23), OpenFHEException);
}

TEST(UTCKKSRNS_PACO_NUMERICS, ProductionCandidateBudgetCoversAdmissionBoundary) {
    const BigInteger q(UINT64_C(576460752300015617));
    constexpr long double coefficientBound   = 1125899908022273.0L;
    constexpr long double nonSmallAngleError = static_cast<long double>(uint64_t{1} << 34);
    const auto budget = paco::detail::AnalyzeNumericalBudget(q, coefficientBound, nonSmallAngleError);
    ASSERT_TRUE(budget.avoidsModularWrap);

    const cpp_dec_float_100 qHigh("576460752300015617");
    const cpp_dec_float_100 occupied     = cpp_dec_float_100("1125899908022273") + cpp_dec_float_100(uint64_t{1} << 34);
    const cpp_dec_float_100 pi           = acos(cpp_dec_float_100(-1));
    const cpp_dec_float_100 recovered    = qHigh / (2 * pi) * sin(2 * pi * occupied / qHigh);
    const long double observedSmallAngle = abs(occupied - recovered).convert_to<long double>();
    EXPECT_GE(budget.smallAngleErrorBound, observedSmallAngle);
    EXPECT_GE(budget.totalAbsoluteErrorBound, observedSmallAngle + nonSmallAngleError);
    EXPECT_GE(budget.conditionalPrecisionBits, 14.0L);
    EXPECT_NO_THROW(paco::detail::RequireNumericalBudget(budget, 14));
}

TEST(UTCKKSRNS_PACO_NUMERICS, BudgetRejectsWrapAndNonFiniteScaleRatio) {
    const BigInteger q(uint64_t{1} << 44);
    const auto wrapped = paco::detail::AnalyzeNumericalBudget(q, static_cast<long double>(uint64_t{1} << 43), 1.0L);
    EXPECT_FALSE(wrapped.avoidsModularWrap);
    EXPECT_THROW(paco::detail::RequireNumericalBudget(wrapped, 1), OpenFHEException);

    BigInteger huge(1);
    huge <<= 1200;
    EXPECT_THROW(paco::detail::CheckedBigRatio(huge, 1.0L, "test scalar"), OpenFHEException);
    const std::string report = paco::detail::FormatNumericalBudget(wrapped);
    EXPECT_NE(report.find("avoids_modular_wrap=false"), std::string::npos);
}

TEST(UTCKKSRNS_PACO_NUMERICS, ConditionalErrorBoundControlsSelectedEvaluationModulus) {
    BigInteger q(uint64_t{1} << 59);
    q *= BigInteger((uint64_t{1} << 45) - 55);
    constexpr long double coefficientBound = static_cast<long double>(uint64_t{1} << 45);
    const auto budget                      = paco::detail::AnalyzeNumericalBudget(
        q, coefficientBound, /*maximumNonSmallAngleAbsoluteError=*/static_cast<long double>(uint64_t{1} << 46));
    EXPECT_TRUE(budget.avoidsModularWrap);
    EXPECT_LT(budget.conditionalPrecisionBits, 0.0L);
    EXPECT_THROW(paco::detail::RequireNumericalBudget(budget, 1), OpenFHEException);

    const BigInteger productionBaseQ(UINT64_C(576460752300015617));
    const auto baseBudget = paco::detail::AnalyzeNumericalBudget(productionBaseQ, coefficientBound,
                                                                 /*maximumNonSmallAngleAbsoluteError=*/1024.0L);
    EXPECT_TRUE(baseBudget.avoidsModularWrap);
    EXPECT_GT(baseBudget.conditionalPrecisionBits, 20.0L);
    EXPECT_NO_THROW(paco::detail::RequireNumericalBudget(baseBudget, 20));
}

}  // namespace
}  // namespace lbcrypto
