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

// Fast N=64, HEStd_NotSet smoke demonstration of PaCo CKKS bootstrapping.
// This executable is intentionally a toy; it is not the separately frozen and
// measured PACO-P128-65536-v1 production-candidate profile.
//
// Paper source: the workspace's GL_scheme/PACO.md transcription
//   J.-S. Coron and T. Seure, "PaCo: Bootstrapping for CKKS via Partial
//   CoeffToSlot," ASIACRYPT 2025.
// Reference behavior: https://github.com/se-tim/PaCo-Implementation
//
// IMPORTANT: the pinned top-level reference repository currently has no LICENSE
// file.  Its nested CKKS submodule's license does not license the top-level PaCo
// Python files.  This independently written BSD example does not grant rights to
// that upstream code.  See PACO_BOOTSTRAPPING.md before redistribution.

#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-paco.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace lbcrypto;

namespace {

constexpr uint32_t kRingDimension = 64;
constexpr uint32_t kH             = 2;
constexpr uint32_t kC             = 4;
constexpr uint32_t kG0            = 2;
constexpr uint32_t kG1            = 1;
constexpr uint32_t kParallelD     = 8;
constexpr uint32_t kParallelJobs  = 2;
constexpr double kMaximumToyError = 5e-3;

std::vector<std::complex<double>> RepeatToAmbient(const std::vector<std::complex<double>>& logicalValues,
                                                  uint32_t ambientSlots) {
    if (logicalValues.empty() || ambientSlots % logicalValues.size() != 0)
        throw std::invalid_argument("logical PaCo slots must nontrivially divide the ambient slot count");

    std::vector<std::complex<double>> ambient(ambientSlots);
    for (uint32_t i = 0; i < ambientSlots; ++i)
        ambient[i] = logicalValues[i % logicalValues.size()];
    return ambient;
}

uint32_t ActiveTowers(ConstCiphertext<DCRTPoly> ciphertext) {
    if (!ciphertext || ciphertext->GetElements().empty())
        throw std::invalid_argument("cannot inspect a null or empty ciphertext");
    const uint32_t towers = ciphertext->GetElements().front().GetNumOfElements();
    for (const auto& element : ciphertext->GetElements()) {
        if (element.GetNumOfElements() != towers)
            throw std::runtime_error("ciphertext components have inconsistent RNS tower counts");
    }
    return towers;
}

Ciphertext<DCRTPoly> EncryptOneTower(const CryptoContext<DCRTPoly>& context, const PublicKey<DCRTPoly>& publicKey,
                                     const std::vector<std::complex<double>>& logicalValues, uint32_t ambientSlots) {
    // Periodic repetition realizes the paper's natural subring embedding;
    // zero-padding a short vector would encode a different message.  Compress
    // performs a valid CKKS reduction to the one-tower Algorithm 3 boundary.
    auto ambientValues = RepeatToAmbient(logicalValues, ambientSlots);
    auto plaintext     = context->MakeCKKSPackedPlaintext(ambientValues, 1, 0, nullptr, ambientSlots);
    auto ciphertext    = context->Encrypt(publicKey, plaintext);
    ciphertext         = context->Compress(ciphertext, 1);

    if (ActiveTowers(ciphertext) != 1)
        throw std::runtime_error("PaCo input construction failed to produce exactly one active RNS tower");
    return ciphertext;
}

std::vector<std::complex<double>> DecryptLogical(const CryptoContext<DCRTPoly>& context,
                                                 const PrivateKey<DCRTPoly>& secretKey,
                                                 ConstCiphertext<DCRTPoly> ciphertext, uint32_t logicalSlots) {
    Plaintext plaintext;
    const auto result = context->Decrypt(secretKey, ciphertext, &plaintext);
    if (!result.isValid || !plaintext)
        throw std::runtime_error("CKKS decryption failed");

    plaintext->SetLength(logicalSlots);
    auto values = plaintext->GetCKKSPackedValue();
    if (values.size() < logicalSlots)
        throw std::runtime_error("decryption returned fewer slots than requested");
    values.resize(logicalSlots);
    return values;
}

double MaximumError(const std::vector<std::complex<double>>& expected,
                    const std::vector<std::complex<double>>& actual) {
    if (expected.size() != actual.size())
        throw std::invalid_argument("cannot compare PaCo vectors of different sizes");

    double maximum = 0.0;
    for (size_t i = 0; i < expected.size(); ++i)
        maximum = std::max(maximum, std::abs(expected[i] - actual[i]));
    return maximum;
}

void PrintVector(const std::string& label, const std::vector<std::complex<double>>& values) {
    std::cout << label << " [";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0)
            std::cout << ", ";
        std::cout << values[i];
    }
    std::cout << "]\n";
}

CryptoContext<DCRTPoly> MakeToySmokeContext(const PaCoParameters& pacoParameters) {
#if NATIVEINT != 64
    throw std::runtime_error("this example requires the 64-bit FLEXIBLEAUTO CKKS build");
#else
    CCParams<CryptoContextCKKSRNS> parameters;

    // This deliberately small ring and HEStd_NotSet make the example quick.
    // They provide no standards-based or production security claim.
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(kRingDimension);
    parameters.SetBatchSize(kRingDimension / 2);

    // PaCo currently requires complex CKKS slot semantics and the native port's
    // explicit one-level FLEXIBLEAUTO rescale schedule.
    parameters.SetCKKSDataType(COMPLEX);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    parameters.SetScalingModSize(35);
    parameters.SetFirstModSize(45);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetNumLargeDigits(2);

    // PaCo consumes
    //   ceil(log2(2C)/g0) + ceil(log2(C/2)/g1) + log2(h) + 3
    // levels.  For h=2, C=4, g0=2, g1=1, L=2+1+1+3=7.  Two
    // additional levels make the refreshed output visibly useful.
    parameters.SetMultiplicativeDepth(pacoParameters.MultiplicativeDepth() + 2);

    auto context = GenCryptoContext(parameters);
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);
    context->Enable(ADVANCEDSHE);
    context->Enable(FHE);
    return context;
#endif
}

}  // namespace

int main() {
    try {
        std::cout << "PaCo CKKS bootstrapping -- toy N=64 HEStd_NotSet smoke demonstration\n"
                  << "This executable makes no security or production claim.\n"
                  << "For PACO-P128-65536-v1, use paco-security-profile and paco-production-audit.\n\n";

        const PaCoParameters parameters{/*h=*/kH, /*C=*/kC, /*g0=*/kG0, /*g1=*/kG1};
        parameters.Validate(kRingDimension);

        const uint32_t depth = parameters.MultiplicativeDepth();
        auto context         = MakeToySmokeContext(parameters);
        const uint32_t slots = context->GetRingDimension() / 2;

        std::cout << "N=" << context->GetRingDimension() << ", h=" << parameters.h << ", C=" << parameters.C
                  << ", B=" << parameters.CoefficientBudget(context->GetRingDimension())
                  << ", k=" << parameters.ResidueBlockCount(context->GetRingDimension())
                  << ", n=" << parameters.PartialRingSlots() << ", PaCo depth=" << depth << "\n";

        // KeyGen is owner-side: it creates Algorithm 1's structured binary
        // secret.  It is not interchangeable with context->KeyGen().
        auto ownerMaterial = PaCoCKKSRNS::KeyGen(context, parameters.h, UINT64_C(0x5041434F));
        if (!ownerMaterial.keyPair.good())
            throw std::runtime_error("PaCo structured key generation failed");

        PaCoCKKSRNS paco(context, parameters);
        paco.GenerateBootstrapKeys(ownerMaterial);
        const auto bootstrapKeys = paco.GetBootstrapKeys();
        std::cout << "PaCo evaluator setup: " << bootstrapKeys.rotationIndices.size() << " signed rotations, "
                  << bootstrapKeys.automorphismIndices.size()
                  << " total automorphisms, and four encrypted selector vectors.\n\n";

        // C=4 real polynomial coefficients are C/2=2 logical complex slots.
        const std::vector<std::complex<double>> sequentialInput = {
            {0.020, 0.010},
            {-0.015, 0.005},
        };
        auto sequentialCiphertext = EncryptOneTower(context, ownerMaterial.keyPair.publicKey, sequentialInput, slots);
        std::cout << "Sequential input towers: " << ActiveTowers(sequentialCiphertext) << "\n";

        auto sequentialOutput = paco.EvalSequential(sequentialCiphertext);
        auto sequentialDecoded =
            DecryptLogical(context, ownerMaterial.keyPair.secretKey, sequentialOutput, parameters.C / 2);

        PrintVector("Sequential input :", sequentialInput);
        PrintVector("Sequential output:", sequentialDecoded);
        const double sequentialError = MaximumError(sequentialInput, sequentialDecoded);
        std::cout << "Sequential maximum slot error: " << std::scientific << std::setprecision(6) << sequentialError
                  << "\n\n";
        if (sequentialError > kMaximumToyError)
            throw std::runtime_error("sequential PaCo error exceeded the toy smoke-test threshold");

        // D=8 and kappa=2 split four logical complex slots into two independent
        // C=4 PaCo jobs.  Passing true requests actual std::async execution.
        const std::vector<std::complex<double>> parallelInput = {
            {0.010, 0.004},
            {-0.012, 0.006},
            {0.008, -0.003},
            {-0.006, -0.002},
        };
        auto parallelCiphertext = EncryptOneTower(context, ownerMaterial.keyPair.publicKey, parallelInput, slots);
        std::cout << "Parallel input towers: " << ActiveTowers(parallelCiphertext) << "\n";

        auto parallelOutput  = paco.EvalParallel(parallelCiphertext, kParallelD, kParallelJobs,
                                                /*runConcurrently=*/true, /*maxConcurrency=*/kParallelJobs);
        auto parallelDecoded = DecryptLogical(context, ownerMaterial.keyPair.secretKey, parallelOutput, kParallelD / 2);

        PrintVector("Parallel input   :", parallelInput);
        PrintVector("Parallel output  :", parallelDecoded);
        const double parallelError = MaximumError(parallelInput, parallelDecoded);
        std::cout << "Parallel maximum slot error: " << std::scientific << std::setprecision(6) << parallelError
                  << "\n\n";
        if (parallelError > kMaximumToyError)
            throw std::runtime_error("parallel PaCo error exceeded the toy smoke-test threshold");

        std::cout << "Completed sequential and two-way concurrent PaCo demonstrations.\n"
                  << "These toy results are correctness evidence only, not security or performance evidence.\n";
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "PaCo example failed: " << error.what() << '\n';
        return 1;
    }
}
