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

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_PACO_BSGS_H
#define LBCRYPTO_CRYPTO_CKKSRNS_PACO_BSGS_H

#include <cstdint>
#include <map>
#include <utility>
#include <vector>

namespace lbcrypto::paco::detail {

/**
 * Validated baby-step/giant-step schedule for a cyclic-diagonal matrix.
 *
 * Each canonical diagonal c has exactly one decomposition c = b + g (mod n).
 * Rotations lists contain only steps that are actually used by a decomposition.
 * directFallback is true only when the diagonal support does not have either of
 * the two regular forms used by the PaCo reference implementation, or BSGS would
 * require more rotation operations than direct diagonal evaluation.
 */
struct SparseDiagonalBSGSPlan {
    uint32_t dimension  = 0;
    bool directFallback = true;
    std::vector<int32_t> babySteps;
    std::vector<int32_t> giantSteps;
    std::map<uint32_t, std::pair<int32_t, int32_t>> decomposition;

    uint32_t RotationOperationCount() const noexcept;
    std::vector<int32_t> RotationKeyIndices() const;
};

/** Construct and validate a resource-minimized PaCo BSGS schedule. */
SparseDiagonalBSGSPlan MakeSparseDiagonalBSGSPlan(uint32_t dimension, const std::vector<uint32_t>& canonicalDiagonals);

}  // namespace lbcrypto::paco::detail

#endif  // LBCRYPTO_CRYPTO_CKKSRNS_PACO_BSGS_H
