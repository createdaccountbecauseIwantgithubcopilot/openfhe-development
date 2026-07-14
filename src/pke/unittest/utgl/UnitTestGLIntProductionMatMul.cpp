//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "gtest/gtest.h"

#include "scheme/gl/gl-int-production-matmul.h"

namespace lbcrypto {
namespace {

TEST(GLIntProductionMatMul, GadgetTErrCrossLaneAndHadamard) {
    const GLIntProductionRLWECore rlwe;
    const GLIntProductionMatMulCore evaluator;
    const GLIntProductionCore codec;
    const auto primary = rlwe.KeyGen(1, 0x4d41544d554c4b45ULL);

    const auto capabilities = evaluator.GetCapabilities();
    EXPECT_TRUE(capabilities.exactCompositeRnsSlotDomain);
    EXPECT_TRUE(capabilities.symmetricTErrEncryption);
    EXPECT_TRUE(capabilities.gadgetDigitTErrEvaluationKeys);
    EXPECT_TRUE(capabilities.switchIntSmall);
    EXPECT_TRUE(capabilities.switchIntBig);
    EXPECT_TRUE(capabilities.encryptedCrossLaneMatrixMultiply);
    EXPECT_TRUE(capabilities.encryptedHadamard);
    EXPECT_FALSE(capabilities.ordinaryProductNormalization);
    EXPECT_TRUE(capabilities.paperTraceNormalization);
    EXPECT_FALSE(capabilities.auxiliaryModulusKeySwitch);
    EXPECT_FALSE(capabilities.noiseScalingModSwitch);
    EXPECT_FALSE(capabilities.coefficientDomainBridge);
    EXPECT_TRUE(capabilities.columnRotation);
    EXPECT_FALSE(capabilities.rowRotation);
    EXPECT_FALSE(capabilities.interMatrixRotation);
    EXPECT_FALSE(capabilities.transpose);
    EXPECT_FALSE(capabilities.conjugationFamilySwap);
    EXPECT_FALSE(capabilities.auxiliaryAutomorphismSwitch);
    EXPECT_FALSE(capabilities.securityAuthorized);

    const GLIntProductionSparsePlaintext left(
        evaluator.GetParameters(),
        {{GLIntBranch::Plus, 9, 1, 4, 6},
         {GLIntBranch::Minus, 9, 2, 5, 7}});
    const GLIntProductionSparsePlaintext right(
        evaluator.GetParameters(),
        {{GLIntBranch::Minus, 9, 3, 4, 10},
         {GLIntBranch::Plus, 9, 6, 5, 11}});
    const auto encryptedLeft =
        evaluator.Encrypt(primary, left, 0x4c454654454e43ULL);
    const auto encryptedRight =
        evaluator.Encrypt(primary, right, 0x5249474854454e43ULL);
    const auto sum = evaluator.Decrypt(
        primary, evaluator.Add(encryptedLeft, encryptedRight));
    EXPECT_EQ(sum.At(GLIntBranch::Plus, 9, 1, 4), 6);
    EXPECT_EQ(sum.At(GLIntBranch::Minus, 9, 3, 4), 10);
    const auto difference = evaluator.Decrypt(
        primary, evaluator.Subtract(encryptedLeft, encryptedRight));
    EXPECT_EQ(difference.At(GLIntBranch::Plus, 9, 1, 4), 6);
    EXPECT_EQ(difference.At(GLIntBranch::Minus, 9, 3, 4), 1579009 - 10);
    const auto negated =
        evaluator.Decrypt(primary, evaluator.Negate(encryptedLeft));
    EXPECT_EQ(negated.At(GLIntBranch::Plus, 9, 1, 4), 1579009 - 6);
    const auto rotatedColumns = evaluator.Decrypt(
        primary, evaluator.RotateColumns(encryptedLeft, 1));
    EXPECT_EQ(rotatedColumns.At(GLIntBranch::Plus, 9, 1, 3), 6);
    EXPECT_EQ(rotatedColumns.At(GLIntBranch::Minus, 9, 2, 4), 7);
    const auto matrixKeys = evaluator.EvalKeyGen(
        primary, encryptedLeft, encryptedRight, 0x4d41544b455953ULL);
    EXPECT_GT(matrixKeys.GetDigitCount(), 32u);
    EXPECT_EQ(matrixKeys.GetEntryCount(), 4u);
    EXPECT_TRUE(matrixKeys.UsesTErrors());
    EXPECT_FALSE(matrixKeys.IsSecurityAuthorized());

    const auto encryptedProduct = evaluator.MatrixMultiply(
        encryptedLeft, encryptedRight, matrixKeys);
    EXPECT_EQ(encryptedProduct.GetPlaintextScale(), 128u);
    const auto product = evaluator.Decrypt(primary, encryptedProduct);
    const auto expectedProduct = codec.MatrixMultiplyTrace(left, right);
    ASSERT_EQ(product.GetValues().size(), 2u);
    EXPECT_EQ(product.At(GLIntBranch::Plus, 9, 1, 3),
              expectedProduct.At(GLIntBranch::Plus, 9, 1, 3));
    EXPECT_EQ(product.At(GLIntBranch::Minus, 9, 2, 6),
              expectedProduct.At(GLIntBranch::Minus, 9, 2, 6));
    EXPECT_EQ(product.At(GLIntBranch::Plus, 9, 1, 6), 0);

    const GLIntProductionSparsePlaintext hadamardLeft(
        evaluator.GetParameters(),
        {{GLIntBranch::Plus, 4, 2, 3, 5}});
    const GLIntProductionSparsePlaintext hadamardRight(
        evaluator.GetParameters(),
        {{GLIntBranch::Plus, 4, 2, 3, 9}});
    const auto encryptedHadamardLeft =
        evaluator.Encrypt(primary, hadamardLeft, 0x4841444c454654ULL);
    const auto encryptedHadamardRight =
        evaluator.Encrypt(primary, hadamardRight, 0x48414452494748ULL);
    const auto hadamardKeys = evaluator.EvalKeyGen(
        primary, encryptedHadamardLeft, encryptedHadamardRight,
        0x4841444b455953ULL);
    EXPECT_EQ(hadamardKeys.GetEntryCount(), 1u);

    const auto encryptedHadamard = evaluator.Hadamard(
        encryptedHadamardLeft, encryptedHadamardRight, hadamardKeys);
    const auto hadamard = evaluator.Decrypt(primary, encryptedHadamard);
    ASSERT_EQ(hadamard.GetValues().size(), 1u);
    EXPECT_EQ(hadamard.At(GLIntBranch::Plus, 4, 2, 3), 45);

    EXPECT_THROW((void)evaluator.Hadamard(encryptedHadamardLeft,
                                          encryptedHadamardRight,
                                          matrixKeys),
                 GLMissingEvaluationKeyError);
}

}  // namespace
}  // namespace lbcrypto
