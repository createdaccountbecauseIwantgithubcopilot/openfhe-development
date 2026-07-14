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

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_PACO_NUMERICS_H
#define LBCRYPTO_CRYPTO_CKKSRNS_PACO_NUMERICS_H

#include "lattice/hal/lat-backend.h"
#include "math/math-hal.h"

#include <complex>
#include <cstdint>
#include <string>

namespace lbcrypto::paco::detail {

/** Exact coefficient interpolation for every active Q tower. */
DCRTPoly::PolyLargeType InterpolateActiveQ(DCRTPoly polynomial);

/** Canonical modular helpers over an arbitrary-size active-Q product. */
BigInteger AddModulo(const BigInteger& lhs, const BigInteger& rhs, const BigInteger& modulus);
BigInteger NegateModulo(const BigInteger& value, const BigInteger& modulus);

/**
 * Evaluate exp(2*pi*i*residue/modulus) after exact modular reduction.
 *
 * Only the final centered ratio is converted to long double. This avoids the
 * lossy uint64 truncation that would otherwise invalidate multi-tower inputs.
 */
std::complex<double> CirclePhase(const BigInteger& residue, const BigInteger& modulus);

/** Convert numerator/denominator to a finite binary64 scalar or fail closed. */
double CheckedBigRatio(const BigInteger& numerator, long double denominator, const char* label);

/** A deterministic, conditional PaCo small-angle admission report. */
struct PaCoNumericalBudget {
    uint32_t modulusBits                          = 0;
    long double maximumAbsCoefficient             = 0.0L;
    long double maximumNonSmallAngleAbsoluteError = 0.0L;
    long double phaseArgumentBound                = 0.0L;
    long double smallAngleErrorBound              = 0.0L;
    long double totalAbsoluteErrorBound           = 0.0L;
    long double conditionalPrecisionBits          = 0.0L;
    bool avoidsModularWrap                        = false;
};

/**
 * Prove the remaining deterministic error budget for
 * q/(2*pi)*sin(2*pi*x/q), |x| <= maximumAbsCoefficient.
 *
 * maximumNonSmallAngleAbsoluteError is an application-established bound on
 * every other error source, including incoming CKKS error, binary64 phase and
 * transform error, encoding, rescaling, key switching, and evaluation noise.
 * The result is a mathematical implication of that external bound; this
 * routine does not claim to infer or prove it from a ciphertext.
 */
PaCoNumericalBudget AnalyzeNumericalBudget(const BigInteger& modulus, long double maximumAbsCoefficient,
                                           long double maximumNonSmallAngleAbsoluteError);

/** Throw when the report cannot guarantee requestedPrecisionBits. */
void RequireNumericalBudget(const PaCoNumericalBudget& budget, uint32_t requestedPrecisionBits);

/** Stable human-readable report used by security/benchmark artifacts. */
std::string FormatNumericalBudget(const PaCoNumericalBudget& budget);

}  // namespace lbcrypto::paco::detail

#endif  // LBCRYPTO_CRYPTO_CKKSRNS_PACO_NUMERICS_H
