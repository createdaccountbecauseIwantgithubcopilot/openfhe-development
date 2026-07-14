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

#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-paco.h"

#include "gtest/gtest.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <limits>
#include <set>
#include <vector>

namespace lbcrypto {
namespace {

using Complex = std::complex<double>;

constexpr uint32_t kTestRingDimension = 32;
constexpr uint32_t kTestH             = 2;
constexpr uint32_t kTestC             = 2;
constexpr double kMatrixTolerance     = 2e-12;

PaCoParameters SmallPaCoParameters() {
    return PaCoParameters{kTestH, kTestC, 1, 1};
}

CryptoContext<DCRTPoly> MakeComplexContext(uint32_t ringDimension, uint32_t multiplicativeDepth,
                                           ScalingTechnique scalingTechnique     = FLEXIBLEAUTO,
                                           CKKSDataType dataType                 = COMPLEX,
                                           KeySwitchTechnique keySwitchTechnique = HYBRID) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(ringDimension);
    parameters.SetBatchSize(ringDimension / 2);
    parameters.SetMultiplicativeDepth(multiplicativeDepth);
    parameters.SetFirstModSize(45);
    parameters.SetScalingModSize(35);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetKeySwitchTechnique(keySwitchTechnique);
    parameters.SetNumLargeDigits(2);
    parameters.SetScalingTechnique(scalingTechnique);
    parameters.SetCKKSDataType(dataType);

    auto context = GenCryptoContext(parameters);
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);
    context->Enable(ADVANCEDSHE);
    context->Enable(FHE);
    return context;
}

CryptoContext<DCRTPoly> MakeSmallComplexContext(uint32_t multiplicativeDepth) {
    return MakeComplexContext(kTestRingDimension, multiplicativeDepth);
}

std::vector<Complex> RepeatToAmbient(const std::vector<Complex>& values, uint32_t ambientSlots) {
    if (values.empty() || ambientSlots % values.size() != 0)
        throw std::invalid_argument("test vector must divide the ambient slot count");
    std::vector<Complex> result(ambientSlots);
    for (uint32_t i = 0; i < ambientSlots; ++i)
        result[i] = values[i % values.size()];
    return result;
}

uint32_t ActiveTowers(ConstCiphertext<DCRTPoly> ciphertext) {
    return ciphertext->GetElements().at(0).GetNumOfElements();
}

void ExpectVectorsNear(const std::vector<Complex>& actual, const std::vector<Complex>& expected, double tolerance,
                       const char* label) {
    ASSERT_EQ(actual.size(), expected.size()) << label;
    for (size_t i = 0; i < expected.size(); ++i)
        EXPECT_LE(std::abs(actual[i] - expected[i]), tolerance) << label << " at index " << i;
}

std::vector<Complex> ApplyInOrder(const std::vector<paco::detail::SparseDiagonalMatrix>& matrices,
                                  std::vector<Complex> value) {
    for (const auto& matrix : matrices)
        value = matrix.Apply(value);
    return value;
}

std::vector<Complex> ApplyInReverseOrder(const std::vector<paco::detail::SparseDiagonalMatrix>& matrices,
                                         std::vector<Complex> value) {
    for (auto matrix = matrices.rbegin(); matrix != matrices.rend(); ++matrix)
        value = matrix->Apply(value);
    return value;
}

Ciphertext<DCRTPoly> EncryptAtBaseModulus(const CryptoContext<DCRTPoly>& context, const PublicKey<DCRTPoly>& publicKey,
                                          const std::vector<Complex>& slots) {
    auto plaintext  = context->MakeCKKSPackedPlaintext(slots, 1, 0, nullptr, slots.size());
    auto ciphertext = context->Encrypt(publicKey, plaintext);
    ciphertext      = context->Compress(ciphertext, 1);
    EXPECT_EQ(ciphertext->GetElements().at(0).GetNumOfElements(), 1U);
    EXPECT_EQ(ciphertext->GetElements().at(1).GetNumOfElements(), 1U);
    return ciphertext;
}

std::vector<Complex> DecryptSlots(const CryptoContext<DCRTPoly>& context, const PrivateKey<DCRTPoly>& secretKey,
                                  ConstCiphertext<DCRTPoly> ciphertext, uint32_t slots) {
    Plaintext plaintext;
    const auto result = context->Decrypt(secretKey, ciphertext, &plaintext);
    EXPECT_TRUE(result.isValid);
    if (!result.isValid || !plaintext)
        return {};
    plaintext->SetLength(slots);
    return plaintext->GetCKKSPackedValue();
}

std::vector<Complex> ApplyForwardD(std::vector<Complex> values, uint32_t C) {
    uint32_t logC = 0;
    for (uint32_t value = C; value > 1; value >>= 1)
        ++logC;
    for (int32_t logStride = static_cast<int32_t>(logC); logStride >= 0; --logStride)
        values = paco::detail::MakeDStage(static_cast<uint32_t>(values.size()), static_cast<uint32_t>(logStride))
                     .Apply(values);
    return values;
}

std::vector<Complex> ExpectedSelectorVector(const PaCoParameters& parameters, uint32_t ringDimension,
                                            const PaCoKeyMaterial& owner, uint32_t selectorGroup) {
    const uint32_t slots = ringDimension / 2;
    const uint32_t k     = parameters.ResidueBlockCount(ringDimension);
    const uint32_t n     = parameters.PartialRingSlots();
    std::vector<Complex> sigma(slots);
    for (uint32_t r = 0; r < k; ++r) {
        std::vector<Complex> block(n);
        for (uint32_t v = 0; v < parameters.h; ++v) {
            const uint32_t candidate = selectorGroup * parameters.h + v;
            const uint32_t shifted   = owner.shiftIndices[candidate] + r;
            if (shifted % k == 0)
                block[v * 2 * parameters.C + shifted / k] = static_cast<double>(owner.selectors[candidate]);
        }
        block = ApplyForwardD(std::move(block), parameters.C);
        std::copy(block.begin(), block.end(), sigma.begin() + r * n);
    }
    return paco::detail::ExtendedBitReverseVector(sigma, parameters.C / 2);
}

class UTCKKSRNS_PACO : public ::testing::Test {
protected:
    void TearDown() override {
        CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
        CryptoContextImpl<DCRTPoly>::ClearEvalSumKeys();
        CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }
};

TEST_F(UTCKKSRNS_PACO, ParameterGeometryAndDepthValidation) {
    const PaCoParameters parameters{/*h=*/2, /*C=*/4, /*g0=*/2, /*g1=*/1};

    EXPECT_NO_THROW(parameters.Validate(64));
    EXPECT_EQ(parameters.CoefficientBudget(64), 8U);
    EXPECT_EQ(parameters.ResidueBlockCount(64), 2U);
    EXPECT_EQ(parameters.PartialRingSlots(), 16U);
    // ceil(log2(8)/2) + ceil(log2(2)/1) + log2(2) + 3 = 7.
    EXPECT_EQ(parameters.MultiplicativeDepth(), 7U);

    auto invalid = parameters;
    invalid.h    = 0;
    EXPECT_THROW(invalid.Validate(64), OpenFHEException);

    invalid   = parameters;
    invalid.h = 3;
    EXPECT_THROW(invalid.Validate(64), OpenFHEException);

    invalid   = parameters;
    invalid.C = 1;
    EXPECT_THROW(invalid.Validate(64), OpenFHEException);

    invalid   = parameters;
    invalid.C = 3;
    EXPECT_THROW(invalid.Validate(64), OpenFHEException);

    invalid    = parameters;
    invalid.g0 = 0;
    EXPECT_THROW(invalid.Validate(64), OpenFHEException);

    invalid    = parameters;
    invalid.g1 = 0;
    EXPECT_THROW(invalid.Validate(64), OpenFHEException);

    EXPECT_THROW(parameters.Validate(16), OpenFHEException);
    EXPECT_THROW(parameters.Validate(48), OpenFHEException);

    const auto setI = PaCoPaperSetI();
    EXPECT_EQ(setI.name, "PaCo I");
    EXPECT_EQ(setI.logRingDimension, 15U);
    EXPECT_EQ(setI.multiplicativeDepth, 14U);
    EXPECT_EQ(setI.logEvaluationKeyModulus, 934U);
    EXPECT_EQ(setI.reportedPrecisionBits, 12U);

    const auto setII = PaCoPaperSetII();
    EXPECT_EQ(setII.name, "PaCo II");
    EXPECT_EQ(setII.logRingDimension, 16U);
    EXPECT_EQ(setII.multiplicativeDepth, 15U);
    EXPECT_EQ(setII.logEvaluationKeyModulus, 1496U);
    EXPECT_EQ(setII.reportedPrecisionBits, 22U);
}

TEST_F(UTCKKSRNS_PACO, ExtendedBitReversalMatchesReferencePermutation) {
    const std::vector<uint32_t> expected{0, 2, 1, 3, 4, 6, 5, 7};
    for (uint32_t i = 0; i < expected.size(); ++i)
        EXPECT_EQ(paco::detail::ExtendedBitReverse(i, 4), expected[i]);

    const std::vector<Complex> input{{0.0, 0.0}, {1.0, -1.0}, {2.0, -2.0}, {3.0, -3.0},
                                     {4.0, 0.5}, {5.0, 1.5},  {6.0, 2.5},  {7.0, 3.5}};
    const std::vector<Complex> expectedVector{input[0], input[2], input[1], input[3],
                                              input[4], input[6], input[5], input[7]};
    EXPECT_EQ(paco::detail::ExtendedBitReverseVector(input, 4), expectedVector);
    EXPECT_EQ(paco::detail::ExtendedBitReverseVector(expectedVector, 4), input);
}

TEST_F(UTCKKSRNS_PACO, DAndEStagesInvertAndGroupingPreservesComposition) {
    constexpr uint32_t dimension = 16;
    std::vector<Complex> input(dimension);
    for (uint32_t i = 0; i < dimension; ++i)
        input[i] = Complex{0.125 * static_cast<double>(i + 1), -0.0625 * static_cast<double>(i % 5)};

    for (uint32_t logStride = 0; logStride < 4; ++logStride) {
        const auto forwardD = paco::detail::MakeDStage(dimension, logStride, false);
        const auto inverseD = paco::detail::MakeDStage(dimension, logStride, true);
        ExpectVectorsNear(inverseD.Apply(forwardD.Apply(input)), input, kMatrixTolerance, "D inverse");

        const auto forwardE = paco::detail::MakeEStage(dimension, logStride, 4, false);
        const auto inverseE = paco::detail::MakeEStage(dimension, logStride, 4, true);
        ExpectVectorsNear(inverseE.Apply(forwardE.Apply(input)), input, kMatrixTolerance, "E inverse");
    }

    std::vector<paco::detail::SparseDiagonalMatrix> stages;
    for (uint32_t logStride = 0; logStride < 4; ++logStride)
        stages.push_back(paco::detail::MakeEStage(dimension, logStride, 4, false));

    const auto leftGrouped = paco::detail::GroupStages(stages, 2, false);
    ASSERT_EQ(leftGrouped.size(), 2U);
    ExpectVectorsNear(ApplyInOrder(leftGrouped, input), ApplyInReverseOrder(stages, input), kMatrixTolerance,
                      "left-grouped E composition");

    const auto rightGrouped = paco::detail::GroupStages(stages, 3, true);
    ASSERT_EQ(rightGrouped.size(), 2U);
    ExpectVectorsNear(ApplyInOrder(rightGrouped, input), ApplyInOrder(stages, input), kMatrixTolerance,
                      "right-grouped E composition");
}

TEST_F(UTCKKSRNS_PACO, DAndEMatricesMatchPinnedSageReferenceFixtures) {
    // Numerical fixture generated with get_matrix_D/get_matrix_E at reference
    // revision e8467fad32cf17243f8ee83d09c307c546fb6d87.  These values are
    // independent regression data, not a translation of the upstream source.
    constexpr uint32_t dimension = 16;
    std::vector<Complex> input(dimension);
    for (uint32_t i = 0; i < dimension; ++i)
        input[i] = Complex{static_cast<double>(i + 1) / 8.0, -static_cast<double>(i % 5) / 16.0};

    const std::vector<Complex> expectedD2 = {
        {0.7980955659108266, 0.008207262100359436},   {0.942909649383465, 0.22451257427381732},
        {1.207312305470194, 0.15210553253749814},     {1.471714961556923, 0.07969849080117897},
        {-0.5480955659108266, -0.008207262100359436}, {-0.442909649383465, -0.3495125742738173},
        {-0.45731230547019397, -0.40210553253749814}, {-0.47171496155692294, -0.45469849080117897},
        {0.61862436397064, 1.3616396693764772},       {0.7535314057069592, 1.4385423254632062},
        {0.8884384474432785, 1.8279449815499351},     {0.7346331352698205, 1.7852590650225735},
        {1.63137563602936, -1.7366396693764772},      {1.7464685942930407, -1.9385423254632062},
        {1.8615615525567215, -1.8279449815499351},    {2.2653668647301792, -1.9102590650225735},
    };
    const std::vector<Complex> expectedE1 = {
        {0.3823894652268156, -0.01252649952116984}, {-0.1323894652268156, 0.01252649952116984},
        {0.9019720755796392, -0.21135207906754158}, {-0.1519720755796392, -0.03864792093245842},
        {0.7713177415120962, -0.9855889603024228},  {0.47868225848790386, 0.4855889603024228},
        {0.9474921619657244, -1.0676715706552464},  {0.8025078380342756, 0.9426715706552464},
        {2.027330194350139, 0.712944457123281},     {0.22266980564986083, -1.087944457123281},
        {2.2603222002983125, 1.2124812788900927},   {0.48967779970168746, -1.2124812788900927},
        {2.975902402838279, -1.253148460091031},    {0.274097597161721, 1.003148460091031},
        {3.5379392246050907, -1.3611404660392044},  {0.2120607753949093, 0.8611404660392044},
    };

    ExpectVectorsNear(paco::detail::MakeDStage(dimension, 2).Apply(input), expectedD2, kMatrixTolerance,
                      "pinned D(16,4) fixture");
    ExpectVectorsNear(paco::detail::MakeEStage(dimension, 1, 4).Apply(input), expectedE1, kMatrixTolerance,
                      "pinned E(16,2,4) fixture");
}

TEST_F(UTCKKSRNS_PACO, PositiveAutomorphismIndexMatchesPaperRotationConvention) {
    auto context         = MakeSmallComplexContext(/*multiplicativeDepth=*/2);
    auto owner           = PaCoCKKSRNS::KeyGen(context, kTestH, UINT64_C(0x524f5441));
    const uint32_t slots = kTestRingDimension / 2;
    std::vector<Complex> oneHot(slots);
    oneHot[1]       = {1.0, 0.0};
    auto plaintext  = context->MakeCKKSPackedPlaintext(oneHot, 1, 0, nullptr, slots);
    auto ciphertext = context->Encrypt(owner.keyPair.publicKey, plaintext);

    const uint32_t automorphism = FindAutomorphismIndex2nComplex(1, 2 * kTestRingDimension);
    auto keys                   = context->GetScheme()->EvalAutomorphismKeyGen(owner.keyPair.secretKey, {automorphism});
    auto rotated                = context->EvalAutomorphism(ciphertext, automorphism, *keys);
    auto observed               = DecryptSlots(context, owner.keyPair.secretKey, rotated, slots);

    std::vector<Complex> expected(slots);
    expected[0] = {1.0, 0.0};
    ExpectVectorsNear(observed, expected, 2e-5, "positive paper rotation");
}

TEST_F(UTCKKSRNS_PACO, StructuredKeyHasAlgorithmOneShape) {
    auto context = MakeSmallComplexContext(/*multiplicativeDepth=*/2);
    EXPECT_THROW((void)PaCoCKKSRNS::KeyGen(context, /*h=*/8, UINT64_C(0xBAD)), OpenFHEException);
    const auto owner = PaCoCKKSRNS::KeyGen(context, kTestH, /*deterministicSeed=*/UINT64_C(0x5041434f));

    ASSERT_TRUE(owner.keyPair.good());
    ASSERT_TRUE(owner.keyPair.publicKey);
    ASSERT_TRUE(owner.keyPair.secretKey);
    EXPECT_EQ(owner.h, kTestH);
    ASSERT_EQ(owner.shiftIndices.size(), 4U * kTestH);
    ASSERT_EQ(owner.selectors.size(), 4U * kTestH);
    EXPECT_EQ(owner.shiftIndices[0], 0U);
    EXPECT_EQ(owner.selectors[0], 1U);
    EXPECT_EQ(owner.keyPair.publicKey->GetKeyTag(), owner.keyPair.secretKey->GetKeyTag());

    const uint32_t blockCount = kTestRingDimension / (4U * kTestH);
    std::set<uint32_t> expectedSupport;
    for (uint32_t v = 0; v < kTestH; ++v) {
        uint32_t selected = 0;
        for (uint32_t t = 0; t < 4; ++t) {
            const uint32_t record = t * kTestH + v;
            EXPECT_LT(owner.shiftIndices[record], blockCount);
            ASSERT_TRUE(owner.selectors[record] == 0U || owner.selectors[record] == 1U);
            if (owner.selectors[record] != 0U) {
                ++selected;
                expectedSupport.insert(record + owner.shiftIndices[record] * 4U * kTestH);
            }
        }
        EXPECT_EQ(selected, 1U) << "selector column " << v;
    }
    ASSERT_EQ(expectedSupport.size(), kTestH);

    auto secret = owner.keyPair.secretKey->GetPrivateElement();
    secret.SetFormat(Format::COEFFICIENT);
    const auto& tower       = secret.GetElementAtIndex(0);
    uint32_t observedWeight = 0;
    for (uint32_t coefficient = 0; coefficient < kTestRingDimension; ++coefficient) {
        const uint64_t value = tower[coefficient].ConvertToInt();
        const bool expected  = expectedSupport.count(coefficient) != 0U;
        EXPECT_EQ(value, expected ? 1U : 0U) << "secret coefficient " << coefficient;
        observedWeight += value != 0U;
    }
    EXPECT_EQ(observedWeight, kTestH);
}

TEST_F(UTCKKSRNS_PACO, MaterialImportRejectsUnboundIncompleteAndMismatchedBundles) {
    const auto parameters = SmallPaCoParameters();
    auto context          = MakeSmallComplexContext(parameters.MultiplicativeDepth() + 2);
    auto owner            = PaCoCKKSRNS::KeyGen(context, parameters.h, UINT64_C(0x4d41544c));

    // Regression: an overlapping key already present in OpenFHE's ambient map
    // must be merged into PaCo's explicit private bundle.
    context->EvalRotateKeyGen(owner.keyPair.secretKey, {1});
    PaCoCKKSRNS ownerSide(context, parameters);
    EXPECT_NO_THROW(ownerSide.GenerateBootstrapKeys(owner));
    ASSERT_TRUE(ownerSide.IsSetup());
    const auto bundle = ownerSide.GetBootstrapKeys();
    EXPECT_EQ(bundle.automorphismIndices.size(), bundle.automorphismKeys->size());
    EXPECT_FALSE(bundle.rotationIndices.empty());

    PaCoCKKSRNS evaluator(context, parameters);
    EXPECT_NO_THROW(evaluator.LoadBootstrapKeys(bundle));
    EXPECT_TRUE(evaluator.IsSetup());
    EXPECT_NE(evaluator.GetBootstrapKeys().selectorCiphertexts[0].get(), bundle.selectorCiphertexts[0].get());
    EXPECT_NE(evaluator.GetBootstrapKeys().automorphismKeys.get(), bundle.automorphismKeys.get());

    auto incomplete = bundle;
    incomplete.automorphismIndices.pop_back();
    EXPECT_THROW(evaluator.LoadBootstrapKeys(std::move(incomplete)), OpenFHEException);

    auto missingSelector                   = bundle;
    missingSelector.selectorCiphertexts[0] = nullptr;
    EXPECT_THROW(evaluator.LoadBootstrapKeys(std::move(missingSelector)), OpenFHEException);

    auto wrongSelectorScale                   = bundle;
    wrongSelectorScale.selectorCiphertexts[0] = bundle.selectorCiphertexts[0]->Clone();
    wrongSelectorScale.selectorCiphertexts[0]->SetScalingFactor(2.0 *
                                                                bundle.selectorCiphertexts[0]->GetScalingFactor());
    EXPECT_THROW(evaluator.LoadBootstrapKeys(std::move(wrongSelectorScale)), OpenFHEException);

    auto wrongParameters = bundle;
    wrongParameters.parameters.C *= 2;
    EXPECT_THROW(evaluator.LoadBootstrapKeys(std::move(wrongParameters)), OpenFHEException);

    auto otherContext = MakeComplexContext(64, parameters.MultiplicativeDepth() + 2);
    PaCoCKKSRNS otherEvaluator(otherContext, parameters);
    EXPECT_THROW(otherEvaluator.LoadBootstrapKeys(bundle), OpenFHEException);

    auto tamperedDescriptor = owner;
    uint32_t selectedBlock  = 0;
    for (uint32_t t = 0; t < 4; ++t) {
        if (tamperedDescriptor.selectors[t * parameters.h + 1] != 0) {
            selectedBlock                                      = t;
            tamperedDescriptor.selectors[t * parameters.h + 1] = 0;
            break;
        }
    }
    tamperedDescriptor.selectors[((selectedBlock + 1) % 4) * parameters.h + 1] = 1;
    EXPECT_THROW(ownerSide.GenerateBootstrapKeys(tamperedDescriptor), OpenFHEException);

    auto unstructured    = owner;
    unstructured.keyPair = context->KeyGen();
    EXPECT_THROW(ownerSide.GenerateBootstrapKeys(unstructured), OpenFHEException);
    EXPECT_TRUE(ownerSide.IsSetup());
}

TEST_F(UTCKKSRNS_PACO, ContextAndInputPreconditionsFailBeforeEvaluation) {
    const auto parameters = SmallPaCoParameters();
    const uint32_t depth  = parameters.MultiplicativeDepth();

    auto insufficient = MakeSmallComplexContext(depth);
    EXPECT_THROW((void)PaCoCKKSRNS(insufficient, parameters), OpenFHEException);

    auto fixedManual = MakeComplexContext(kTestRingDimension, depth + 2, FIXEDMANUAL);
    EXPECT_THROW((void)PaCoCKKSRNS(fixedManual, parameters), OpenFHEException);

    auto realPacking = MakeComplexContext(kTestRingDimension, depth + 2, FLEXIBLEAUTO, REAL);
    EXPECT_THROW((void)PaCoCKKSRNS(realPacking, parameters), OpenFHEException);

    auto bvKeys = MakeComplexContext(kTestRingDimension, depth + 2, FLEXIBLEAUTO, COMPLEX, BV);
    EXPECT_THROW((void)PaCoCKKSRNS(bvKeys, parameters), OpenFHEException);

    auto context = MakeSmallComplexContext(depth + 2);
    auto owner   = PaCoCKKSRNS::KeyGen(context, parameters.h, UINT64_C(0x50524543));
    PaCoCKKSRNS paco(context, parameters);
    paco.GenerateBootstrapKeys(owner);

    const std::vector<Complex> values(kTestRingDimension / 2, {0.01, -0.005});
    auto plaintext = context->MakeCKKSPackedPlaintext(values, 1, 0, nullptr, values.size());
    auto fullChain = context->Encrypt(owner.keyPair.publicKey, plaintext);
    EXPECT_THROW((void)paco.EvalSequential(fullChain), OpenFHEException);

    auto depleted = context->Compress(fullChain, 1);
    EXPECT_NO_THROW((void)paco.GetCoefficientEncodings(depleted));

    auto wrongLevel = depleted->Clone();
    wrongLevel->SetLevel(wrongLevel->GetLevel() - 1);
    EXPECT_THROW((void)paco.EvalSequential(wrongLevel), OpenFHEException);

    auto wrongNoiseScale = depleted->Clone();
    wrongNoiseScale->SetNoiseScaleDeg(2);
    EXPECT_THROW((void)paco.EvalSequential(wrongNoiseScale), OpenFHEException);

    auto wrongScale = depleted->Clone();
    wrongScale->SetScalingFactor(std::numeric_limits<double>::infinity());
    EXPECT_THROW((void)paco.EvalSequential(wrongScale), OpenFHEException);

    auto finiteWrongScale = depleted->Clone();
    finiteWrongScale->SetScalingFactor(1.5 * depleted->GetScalingFactor());
    EXPECT_THROW((void)paco.EvalSequential(finiteWrongScale), OpenFHEException);

    auto wrongTag = depleted->Clone();
    wrongTag->SetKeyTag("not-the-paco-key");
    EXPECT_THROW((void)paco.EvalSequential(wrongTag), OpenFHEException);
}

TEST_F(UTCKKSRNS_PACO, CoefficientEncodingsMatchIndependentPublicBoundaryOracle) {
    constexpr uint32_t ringDimension = 64;
    const PaCoParameters parameters{/*h=*/2, /*C=*/4, /*g0=*/2, /*g1=*/1};
    auto context = MakeComplexContext(ringDimension, parameters.MultiplicativeDepth() + 2);
    auto owner   = PaCoCKKSRNS::KeyGen(context, parameters.h, UINT64_C(0x434f4546));
    PaCoCKKSRNS paco(context, parameters);
    paco.GenerateBootstrapKeys(owner);

    const uint32_t slots = ringDimension / 2;
    const auto input     = RepeatToAmbient({{0.013, -0.004}, {-0.009, 0.006}}, slots);
    auto depleted        = EncryptAtBaseModulus(context, owner.keyPair.publicKey, input);
    const auto actual    = paco.GetCoefficientEncodings(depleted);
    ASSERT_EQ(actual.size(), 4U);

    DCRTPoly c0 = depleted->GetElements()[0];
    DCRTPoly c1 = depleted->GetElements()[1];
    c0.SetFormat(Format::COEFFICIENT);
    c1.SetFormat(Format::COEFFICIENT);
    const auto c0Tower       = c0.GetElementAtIndex(0);
    const auto c1Tower       = c1.GetElementAtIndex(0);
    const uint64_t q         = c0Tower.GetModulus().ConvertToInt();
    constexpr long double pi = 3.141592653589793238462643383279502884L;
    auto phase               = [&](uint64_t residue) {
        residue %= q;
        const long double centered = residue > q / 2 ? static_cast<long double>(residue) - q : residue;
        const long double angle    = 2.0L * pi * centered / q;
        return Complex{static_cast<double>(std::cos(angle)), static_cast<double>(std::sin(angle))};
    };

    const uint32_t k = parameters.ResidueBlockCount(ringDimension);
    const uint32_t n = parameters.PartialRingSlots();
    std::vector<std::vector<Complex>> publicPhases(4 * parameters.h * k, std::vector<Complex>(2 * parameters.C));
    auto at = [&](uint32_t v, uint32_t r) -> std::vector<Complex>& {
        return publicPhases[v * k + r];
    };
    for (uint32_t v = 0; v < 4 * parameters.h; ++v) {
        for (uint32_t r = 0; r < k; ++r) {
            for (uint32_t i = 0; i < parameters.C; ++i) {
                const uint32_t base = 4 * parameters.h * (i * k + r);
                uint64_t residue;
                if (v == 0)
                    residue = (c0Tower[base].ConvertToInt() + c1Tower[base].ConvertToInt()) % q;
                else if (i == 0 && r == 0) {
                    const uint64_t value = c1Tower[ringDimension - v].ConvertToInt() % q;
                    residue              = value == 0 ? 0 : q - value;
                }
                else
                    residue = c1Tower[base - v].ConvertToInt();
                at(v, r)[i] = phase(residue);
            }
        }
    }

    for (uint32_t t = 0; t < 4; ++t) {
        std::vector<Complex> expected(slots);
        for (uint32_t r = 0; r < k; ++r) {
            std::vector<Complex> block(n);
            for (uint32_t v = 0; v < parameters.h; ++v)
                std::copy(at(t * parameters.h + v, r).begin(), at(t * parameters.h + v, r).end(),
                          block.begin() + v * 2 * parameters.C);
            for (int32_t logStride = 2; logStride >= 0; --logStride)
                block = paco::detail::MakeDStage(n, static_cast<uint32_t>(logStride)).Apply(block);
            std::copy(block.begin(), block.end(), expected.begin() + r * n);
        }
        expected = paco::detail::ExtendedBitReverseVector(expected, parameters.C / 2);
        actual[t]->SetLength(slots);
        auto observed = actual[t]->GetCKKSPackedValue();
        observed.resize(slots);
        ExpectVectorsNear(observed, expected, 2e-10, "public coefficient encoding");
    }
}

TEST_F(UTCKKSRNS_PACO, BootstrapSelectorsAndPackingRelationMatchIndependentOracle) {
    constexpr uint32_t ringDimension = 64;
    const PaCoParameters parameters{/*h=*/2, /*C=*/4, /*g0=*/2, /*g1=*/1};
    auto context = MakeComplexContext(ringDimension, parameters.MultiplicativeDepth() + 2);
    auto owner   = PaCoCKKSRNS::KeyGen(context, parameters.h, UINT64_C(0x5041434b));
    PaCoCKKSRNS paco(context, parameters);
    paco.GenerateBootstrapKeys(owner);

    const uint32_t slots            = ringDimension / 2;
    const uint32_t k                = parameters.ResidueBlockCount(ringDimension);
    const uint32_t n                = parameters.PartialRingSlots();
    const auto input                = RepeatToAmbient({{0.011, -0.007}, {-0.005, 0.009}}, slots);
    auto depleted                   = EncryptAtBaseModulus(context, owner.keyPair.publicKey, input);
    const auto coefficientEncodings = paco.GetCoefficientEncodings(depleted);

    std::array<std::vector<Complex>, 4> beta;
    std::array<std::vector<Complex>, 4> sigma;
    for (uint32_t t = 0; t < 4; ++t) {
        coefficientEncodings[t]->SetLength(slots);
        beta[t] = coefficientEncodings[t]->GetCKKSPackedValue();
        beta[t].resize(slots);

        sigma[t] =
            DecryptSlots(context, owner.keyPair.secretKey, paco.GetBootstrapKeys().selectorCiphertexts[t], slots);
        sigma[t].resize(slots);
        const auto expectedSigma = ExpectedSelectorVector(parameters, ringDimension, owner, t);
        ExpectVectorsNear(sigma[t], expectedSigma, 2e-5, "Algorithm 2 encrypted selector");
    }

    // Left side of the paper's packing relation (Eq. (2) in the port
    // contract): Hadamard-sum the four bit-reversed vectors, trace the k
    // residue blocks, then apply inverse E_(n,1)..inverse E_(n,C).
    std::vector<Complex> packed(slots);
    for (uint32_t i = 0; i < slots; ++i) {
        for (uint32_t t = 0; t < 4; ++t)
            packed[i] += beta[t][i] * sigma[t][i];
    }
    std::vector<Complex> observed(n);
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t r = 0; r < k; ++r)
            observed[i] += packed[r * n + i];
    }
    for (uint32_t logStride = 0; logStride <= 2; ++logStride)
        observed = paco::detail::MakeEStage(n, logStride, parameters.C / 2, true).Apply(observed);

    // Independently build b'_lambda = Z^ceil(u_lambda/k) * b~_lambda^(-u_lambda mod k)
    // from the public base-q ciphertext coefficients, including Algorithm 3's
    // negacyclic boundary case at i=r=0.
    DCRTPoly c0 = depleted->GetElements()[0];
    DCRTPoly c1 = depleted->GetElements()[1];
    c0.SetFormat(Format::COEFFICIENT);
    c1.SetFormat(Format::COEFFICIENT);
    const auto c0Tower       = c0.GetElementAtIndex(0);
    const auto c1Tower       = c1.GetElementAtIndex(0);
    const uint64_t q         = c0Tower.GetModulus().ConvertToInt();
    constexpr long double pi = 3.141592653589793238462643383279502884L;
    auto phase               = [&](uint64_t residue) {
        residue %= q;
        const long double centered = residue > q / 2 ? static_cast<long double>(residue) - q : residue;
        const long double angle    = 2.0L * pi * centered / q;
        return Complex{static_cast<double>(std::cos(angle)), static_cast<double>(std::sin(angle))};
    };

    std::vector<std::vector<Complex>> phases(4 * parameters.h * k, std::vector<Complex>(2 * parameters.C));
    auto phaseAt = [&](uint32_t v, uint32_t r) -> std::vector<Complex>& {
        return phases[v * k + r];
    };
    for (uint32_t v = 0; v < 4 * parameters.h; ++v) {
        for (uint32_t r = 0; r < k; ++r) {
            for (uint32_t i = 0; i < parameters.C; ++i) {
                const uint32_t base = 4 * parameters.h * (i * k + r);
                uint64_t residue;
                if (v == 0)
                    residue = (c0Tower[base].ConvertToInt() + c1Tower[base].ConvertToInt()) % q;
                else if (i == 0 && r == 0) {
                    const uint64_t value = c1Tower[ringDimension - v].ConvertToInt() % q;
                    residue              = value == 0 ? 0 : q - value;
                }
                else
                    residue = c1Tower[base - v].ConvertToInt();
                phaseAt(v, r)[i] = phase(residue);
            }
        }
    }

    std::vector<Complex> expected(n);
    for (uint32_t v = 0; v < parameters.h; ++v) {
        uint32_t lambda = 0;
        for (uint32_t t = 0; t < 4; ++t) {
            const uint32_t candidate = t * parameters.h + v;
            if (owner.selectors[candidate] != 0) {
                lambda = candidate;
                break;
            }
        }
        const uint32_t u            = owner.shiftIndices[lambda];
        const uint32_t residueBlock = (k - (u % k)) % k;
        const uint32_t monomial     = (u + k - 1) / k;
        std::vector<Complex> shifted(2 * parameters.C);
        for (uint32_t i = 0; i < parameters.C; ++i)
            shifted[i + monomial] = phaseAt(lambda, residueBlock)[i];
        shifted = paco::detail::ExtendedBitReverseVector(shifted, parameters.C / 2);
        std::copy(shifted.begin(), shifted.end(), expected.begin() + v * 2 * parameters.C);
    }
    ExpectVectorsNear(observed, expected, 5e-5, "PaCo packing relation");
}

TEST_F(UTCKKSRNS_PACO, SequentialRefreshesConstantComplexMessageFromOneTower) {
    const auto parameters = SmallPaCoParameters();
    auto context          = MakeSmallComplexContext(parameters.MultiplicativeDepth() + 2);
    auto owner            = PaCoCKKSRNS::KeyGen(context, parameters.h, /*deterministicSeed=*/UINT64_C(0x534551));

    PaCoCKKSRNS paco(context, parameters);
    EXPECT_FALSE(paco.IsSetup());
    EXPECT_THROW((void)paco.GetBootstrapKeys(), OpenFHEException);
    paco.GenerateBootstrapKeys(owner);
    ASSERT_TRUE(paco.IsSetup());
    ASSERT_EQ(paco.GetBootstrapKeys().selectorCiphertexts.size(), 4U);

    const uint32_t slots = kTestRingDimension / 2;
    const Complex message{0.03125, -0.015625};
    const std::vector<Complex> expected(slots, message);
    auto depleted           = EncryptAtBaseModulus(context, owner.keyPair.publicKey, expected);
    const double inputScale = depleted->GetScalingFactor();
    auto refreshed          = paco.EvalSequential(depleted);

    ASSERT_TRUE(refreshed);
    const auto cryptoParams    = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(context->GetCryptoParameters());
    const uint32_t totalTowers = cryptoParams->GetElementParams()->GetParams().size();
    EXPECT_EQ(refreshed->GetLevel(), parameters.MultiplicativeDepth());
    EXPECT_EQ(ActiveTowers(refreshed), totalTowers - parameters.MultiplicativeDepth());
    EXPECT_EQ(refreshed->GetNoiseScaleDeg(), 1U);
    EXPECT_DOUBLE_EQ(refreshed->GetScalingFactor(), inputScale);
    const auto actual = DecryptSlots(context, owner.keyPair.secretKey, refreshed, slots);
    ExpectVectorsNear(actual, expected, 2e-4, "sequential PaCo output");

    const std::vector<Complex> half(slots, {0.5, 0.0});
    auto halfPlaintext = context->MakeCKKSPackedPlaintext(half, 1, refreshed->GetLevel(), nullptr, slots);
    auto continued     = context->EvalMult(refreshed, halfPlaintext);
    ASSERT_EQ(continued->GetNoiseScaleDeg(), 2U);
    context->GetScheme()->ModReduceInternalInPlace(continued, 1);
    EXPECT_EQ(continued->GetLevel(), refreshed->GetLevel() + 1);
    EXPECT_EQ(ActiveTowers(continued) + 1, ActiveTowers(refreshed));
    EXPECT_EQ(continued->GetNoiseScaleDeg(), 1U);
    const auto continuedSlots = DecryptSlots(context, owner.keyPair.secretKey, continued, slots);
    const std::vector<Complex> expectedHalf(slots, 0.5 * message);
    ExpectVectorsNear(continuedSlots, expectedHalf, 4e-4, "post-PaCo multiplication");
}

TEST_F(UTCKKSRNS_PACO, ParallelConcurrentEvaluationMatchesSequentialSchedule) {
    const auto parameters = SmallPaCoParameters();
    auto context          = MakeSmallComplexContext(parameters.MultiplicativeDepth() + 2);
    auto owner            = PaCoCKKSRNS::KeyGen(context, parameters.h, /*deterministicSeed=*/UINT64_C(0x504152));
    PaCoCKKSRNS paco(context, parameters);
    paco.GenerateBootstrapKeys(owner);

    const uint32_t slots = kTestRingDimension / 2;
    std::vector<Complex> input(slots);
    for (uint32_t i = 0; i < slots; ++i) {
        const double real = 0.0025 * static_cast<double>(static_cast<int32_t>(i % 5) - 2);
        const double imag = 0.0015 * static_cast<double>(static_cast<int32_t>(i % 3) - 1);
        input[i]          = {real, imag};
    }
    auto depleted = EncryptAtBaseModulus(context, owner.keyPair.publicKey, input);

    auto scheduled  = paco.EvalParallel(depleted, /*D=*/4, /*kappa=*/2, /*runConcurrently=*/false);
    auto concurrent = paco.EvalParallel(depleted, /*D=*/4, /*kappa=*/2, /*runConcurrently=*/true);
    ASSERT_TRUE(scheduled);
    ASSERT_TRUE(concurrent);
    EXPECT_EQ(scheduled->GetLevel(), concurrent->GetLevel());
    EXPECT_EQ(scheduled->GetNoiseScaleDeg(), concurrent->GetNoiseScaleDeg());
    EXPECT_EQ(scheduled->GetElements().at(0).GetNumOfElements(), concurrent->GetElements().at(0).GetNumOfElements());

    const auto scheduledSlots  = DecryptSlots(context, owner.keyPair.secretKey, scheduled, slots);
    const auto concurrentSlots = DecryptSlots(context, owner.keyPair.secretKey, concurrent, slots);
    ExpectVectorsNear(concurrentSlots, scheduledSlots, 2e-6, "parallel schedule parity");
}

TEST_F(UTCKKSRNS_PACO, NonconstantSequentialAndParallelMessagesMatchExpectedSlots) {
    constexpr uint32_t ringDimension = 64;
    const PaCoParameters parameters{/*h=*/2, /*C=*/4, /*g0=*/2, /*g1=*/1};
    auto context = MakeComplexContext(ringDimension, parameters.MultiplicativeDepth() + 2);
    auto owner   = PaCoCKKSRNS::KeyGen(context, parameters.h, UINT64_C(0x4e4f4e43));
    PaCoCKKSRNS paco(context, parameters);
    paco.GenerateBootstrapKeys(owner);
    const uint32_t slots = ringDimension / 2;

    const std::vector<Complex> sequentialLogical{{0.020, 0.010}, {-0.015, 0.005}};
    const auto sequentialExpected = RepeatToAmbient(sequentialLogical, slots);
    auto sequentialInput          = EncryptAtBaseModulus(context, owner.keyPair.publicKey, sequentialExpected);
    auto sequentialOutput         = paco.EvalSequential(sequentialInput);
    const auto sequentialActual   = DecryptSlots(context, owner.keyPair.secretKey, sequentialOutput, slots);
    ExpectVectorsNear(sequentialActual, sequentialExpected, 3e-4, "nonconstant sequential message");

    const std::vector<Complex> parallelLogical{{0.010, 0.004}, {-0.012, 0.006}, {0.008, -0.003}, {-0.006, -0.002}};
    const auto parallelExpected = RepeatToAmbient(parallelLogical, slots);
    auto parallelInput          = EncryptAtBaseModulus(context, owner.keyPair.publicKey, parallelExpected);
    auto parallelOutput         = paco.EvalParallel(parallelInput, /*D=*/8, /*kappa=*/2,
                                            /*runConcurrently=*/true, /*maxConcurrency=*/2);
    const auto parallelActual   = DecryptSlots(context, owner.keyPair.secretKey, parallelOutput, slots);
    ExpectVectorsNear(parallelActual, parallelExpected, 4e-4, "nonconstant parallel message");
}

TEST_F(UTCKKSRNS_PACO, MaximumCAndFourResidueBlocksRefresh) {
    {
        // k=N/(4*h*C)=1 and C=B: maximum sequential coefficient budget.
        constexpr uint32_t ringDimension = 32;
        const PaCoParameters parameters{/*h=*/2, /*C=*/4, /*g0=*/2, /*g1=*/1};
        auto context = MakeComplexContext(ringDimension, parameters.MultiplicativeDepth() + 2);
        auto owner   = PaCoCKKSRNS::KeyGen(context, parameters.h, UINT64_C(0x4b4f4e45));
        PaCoCKKSRNS paco(context, parameters);
        paco.GenerateBootstrapKeys(owner);
        const auto expected = RepeatToAmbient({{0.011, -0.004}, {-0.007, 0.003}}, ringDimension / 2);
        auto input          = EncryptAtBaseModulus(context, owner.keyPair.publicKey, expected);
        auto output         = paco.EvalSequential(input);
        ExpectVectorsNear(DecryptSlots(context, owner.keyPair.secretKey, output, expected.size()), expected, 4e-4,
                          "k=1 maximum-C message");
    }

    {
        // k=4 exercises four concatenated public/secret residue blocks.
        constexpr uint32_t ringDimension = 64;
        const PaCoParameters parameters{/*h=*/2, /*C=*/2, /*g0=*/1, /*g1=*/1};
        auto context = MakeComplexContext(ringDimension, parameters.MultiplicativeDepth() + 2);
        auto owner   = PaCoCKKSRNS::KeyGen(context, parameters.h, UINT64_C(0x4b464f55));
        PaCoCKKSRNS paco(context, parameters);
        paco.GenerateBootstrapKeys(owner);
        const std::vector<Complex> expected(ringDimension / 2, {0.012, -0.006});
        auto input  = EncryptAtBaseModulus(context, owner.keyPair.publicKey, expected);
        auto output = paco.EvalSequential(input);
        ExpectVectorsNear(DecryptSlots(context, owner.keyPair.secretKey, output, expected.size()), expected, 4e-4,
                          "k=4 message");
    }
}

}  // namespace
}  // namespace lbcrypto
