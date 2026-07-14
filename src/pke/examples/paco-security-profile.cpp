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

// Emit the exact, machine-readable OpenFHE parameter manifest for the PaCo
// 128-bit-classical production candidate.  This is estimator input and a
// regression guard; it is not a security proof or an audit.

#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-paco.h"
#include "version.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

using namespace lbcrypto;

namespace {

constexpr uint32_t kRingDimension  = 65536;
constexpr uint32_t kH              = 128;
constexpr uint32_t kC              = 128;
constexpr uint32_t kG0             = 3;
constexpr uint32_t kG1             = 3;
constexpr uint32_t kPaCoDepth      = 15;
constexpr uint32_t kContextDepth   = kPaCoDepth + 2;
constexpr uint32_t kFirstModSize   = 59;
constexpr uint32_t kScalingModSize = 50;
constexpr uint32_t kNumLargeDigits = 3;
constexpr uint32_t kExpectedAlpha  = 6;
constexpr uint32_t kExpectedQBits  = 910;
constexpr uint32_t kExpectedPBits  = 360;
constexpr uint32_t kExpectedQPBits = 1270;
constexpr float kGaussianSigma     = 3.19F;

constexpr std::array<uint64_t, 18> kExpectedQ = {
    576460752300015617ULL, 1125899935547393ULL, 1125899927027713ULL, 1125899935285249ULL, 1125899930959873ULL,
    1125899941445633ULL,   1125899887312897ULL, 1125899926110209ULL, 1125899911168001ULL, 1125899924275201ULL,
    1125899915231233ULL,   1125899922702337ULL, 1125899915886593ULL, 1125899921391617ULL, 1125899902124033ULL,
    1125899913527297ULL,   1125899903827969ULL, 1125899908022273ULL,
};

constexpr std::array<uint64_t, 6> kExpectedP = {
    1152921504606584833ULL, 1152921504598720513ULL, 1152921504597016577ULL,
    1152921504595968001ULL, 1152921504592822273ULL, 1152921504592429057ULL,
};

template <size_t Size>
void RequirePrimeVector(const char* name, const std::shared_ptr<ILDCRTParams<BigInteger>>& params,
                        const std::array<uint64_t, Size>& expected) {
    if (!params || params->GetParams().size() != expected.size())
        throw std::runtime_error(std::string(name) + " tower count differs from the frozen PaCo profile");
    for (size_t i = 0; i < expected.size(); ++i) {
        if (params->GetParams()[i]->GetModulus().ConvertToInt() != expected[i])
            throw std::runtime_error(std::string(name) + " prime vector differs from the frozen PaCo profile");
    }
}

template <size_t Size>
void PrintPrimeVector(const std::array<uint64_t, Size>& primes) {
    std::cout << '[';
    for (size_t i = 0; i < primes.size(); ++i) {
        if (i != 0)
            std::cout << ',';
        std::cout << primes[i];
    }
    std::cout << ']';
}

}  // namespace

int main() {
    try {
#if NATIVEINT != 64
        throw std::runtime_error("the frozen PaCo security candidate requires NATIVEINT=64");
#else
        const PaCoParameters paco{/*h=*/kH, /*C=*/kC, /*g0=*/kG0, /*g1=*/kG1};
        paco.Validate(kRingDimension);
        if (paco.MultiplicativeDepth() != kPaCoDepth || paco.CoefficientBudget(kRingDimension) != kC ||
            paco.ResidueBlockCount(kRingDimension) != 1 || paco.PartialRingSlots() != kRingDimension / 2)
            throw std::runtime_error("the frozen PaCo algebraic profile is internally inconsistent");

        CCParams<CryptoContextCKKSRNS> parameters;
        // HEStd_128_classic is a necessary ordinary-ternary envelope check.  It
        // does not model PaCo's block-structured secret or KDM/circular material.
        parameters.SetSecurityLevel(HEStd_128_classic);
        parameters.SetRingDim(kRingDimension);
        parameters.SetBatchSize(kRingDimension / 2);
        parameters.SetSecretKeyDist(UNIFORM_TERNARY);
        parameters.SetStandardDeviation(kGaussianSigma);
        parameters.SetCKKSDataType(COMPLEX);
        parameters.SetScalingTechnique(FLEXIBLEAUTO);
        parameters.SetScalingModSize(kScalingModSize);
        parameters.SetFirstModSize(kFirstModSize);
        parameters.SetKeySwitchTechnique(HYBRID);
        parameters.SetNumLargeDigits(kNumLargeDigits);
        parameters.SetMultiplicativeDepth(kContextDepth);

        const auto context      = GenCryptoContext(parameters);
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(context->GetCryptoParameters());
        if (!cryptoParams)
            throw std::runtime_error("failed to obtain CKKS-RNS parameters");

        const auto paramsQ  = cryptoParams->GetElementParams();
        const auto paramsP  = cryptoParams->GetParamsP();
        const auto paramsQP = cryptoParams->GetParamsQP();
        RequirePrimeVector("Q", paramsQ, kExpectedQ);
        RequirePrimeVector("P", paramsP, kExpectedP);
        if (paramsQ->GetModulus().GetMSB() != kExpectedQBits || paramsP->GetModulus().GetMSB() != kExpectedPBits ||
            paramsQP->GetModulus().GetMSB() != kExpectedQPBits)
            throw std::runtime_error("Q/P bit counts differ from the frozen PaCo profile");
        if (cryptoParams->GetNumPartQ() != kNumLargeDigits || cryptoParams->GetNumPerPartQ() != kExpectedAlpha)
            throw std::runtime_error("HYBRID decomposition differs from the frozen PaCo profile");
        if (cryptoParams->GetDistributionParameter() != kGaussianSigma)
            throw std::runtime_error("error distribution differs from the frozen PaCo profile");

        std::cout << "{\n"
                  << "  \"schema\": \"openfhe-paco-security-profile-v1\",\n"
                  << "  \"evidence_only\": true,\n"
                  << "  \"openfhe_version\": \"" << GetOPENFHEVersion() << "\",\n"
                  << "  \"security_envelope\": \"HEStd_128_classic/HEStd_ternary\",\n"
                  << "  \"N\": " << kRingDimension << ",\n"
                  << "  \"h\": " << kH << ",\n"
                  << "  \"C\": " << kC << ",\n"
                  << "  \"g0\": " << kG0 << ",\n"
                  << "  \"g1\": " << kG1 << ",\n"
                  << "  \"paco_depth\": " << kPaCoDepth << ",\n"
                  << "  \"context_multiplicative_depth\": " << kContextDepth << ",\n"
                  << "  \"first_mod_size\": " << kFirstModSize << ",\n"
                  << "  \"scaling_mod_size\": " << kScalingModSize << ",\n"
                  << "  \"error_distribution\": {\"name\": \"discrete_gaussian\", \"sigma\": "
                  << cryptoParams->GetDistributionParameter() << "},\n"
                  << "  \"hybrid\": {\"num_part_q\": " << cryptoParams->GetNumPartQ()
                  << ", \"alpha_q_towers_per_part\": " << cryptoParams->GetNumPerPartQ() << "},\n"
                  << "  \"Q_product_bits\": " << paramsQ->GetModulus().GetMSB() << ",\n"
                  << "  \"P_product_bits\": " << paramsP->GetModulus().GetMSB() << ",\n"
                  << "  \"QP_product_bits\": " << paramsQP->GetModulus().GetMSB() << ",\n"
                  << "  \"Q_product\": \"" << paramsQ->GetModulus() << "\",\n"
                  << "  \"P_product\": \"" << paramsP->GetModulus() << "\",\n"
                  << "  \"QP_product\": \"" << paramsQP->GetModulus() << "\",\n"
                  << "  \"Q_primes\": ";
        PrintPrimeVector(kExpectedQ);
        std::cout << ",\n  \"P_primes\": ";
        PrintPrimeVector(kExpectedP);
        std::cout << "\n}\n";
        return 0;
#endif
    }
    catch (const std::exception& error) {
        std::cerr << "PaCo security-profile generation failed closed: " << error.what() << '\n';
        return 1;
    }
}
