//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "gtest/gtest.h"

#include "scheme/gl/gl-int-production-switch.h"

namespace lbcrypto {
namespace {

TEST(GLIntProductionSwitch, ExactBoundedSmallAndBigEquations) {
    const GLIntProductionRLWECore rlwe;
    const GLIntProductionSwitchCore switching;
    const auto primary = rlwe.KeyGen(1, 0x5052494d415259ULL);

    const auto capabilities = switching.GetCapabilities();
    EXPECT_TRUE(capabilities.denseRPrimeInput);
    EXPECT_TRUE(capabilities.boundedSparseEvaluationKey);
    EXPECT_TRUE(capabilities.switchIntSmall);
    EXPECT_TRUE(capabilities.switchIntBig);
    EXPECT_FALSE(capabilities.gadgetDecomposition);
    EXPECT_FALSE(capabilities.noisyEvaluationKey);
    EXPECT_FALSE(capabilities.securityAuthorized);
    EXPECT_FALSE(capabilities.ciphertextMatMul);

    const auto smallKey = switching.EvalKeyGenSmallSquare(
        primary, 0x534d414c4c4b4559ULL);
    const auto bigKey = switching.EvalKeyGenBigTranspose(
        primary, 0x4249475452414e53ULL);
    EXPECT_EQ(smallKey.GetDirection(),
              GLIntProductionSwitchDirection::SmallSquareToPrimary);
    EXPECT_EQ(bigKey.GetDirection(),
              GLIntProductionSwitchDirection::BigTransposeToPrimary);
    EXPECT_TRUE(smallKey.IsNoiseFree());
    EXPECT_TRUE(bigKey.IsNoiseFree());
    EXPECT_FALSE(smallKey.IsSecurityAuthorized());
    EXPECT_FALSE(bigKey.IsSecurityAuthorized());
    EXPECT_GT(smallKey.GetK1TermCount(), 0u);
    EXPECT_GT(bigKey.GetK1TermCount(), 0u);
    EXPECT_TRUE(switching.VerifyEvaluationKeyOwner(smallKey, primary));
    EXPECT_TRUE(switching.VerifyEvaluationKeyOwner(bigKey, primary));

    const auto input = switching.MakeMonomial(1, 2, 3, 4, 7, -5);
    ASSERT_EQ(input.GetPlanes().size(), 1u);
    EXPECT_EQ(input.GetLevel(), 1u);
    EXPECT_EQ(input.GetPlanes().front().coefficients.size(),
              128u * 128u * 256u);

    {
        const auto result = switching.SwitchIntSmall(input, smallKey);
        EXPECT_EQ(result.GetDestinationKeyTag(), primary.GetKeyTag());
        ASSERT_EQ(result.GetB().GetPlanes().size(), 1u);
        ASSERT_EQ(result.GetA().GetPlanes().size(), 1u);
        EXPECT_TRUE(switching.VerifySwitchResultOwner(
            input, result, smallKey, primary));
        EXPECT_THROW((void)switching.SwitchIntBig(input, smallKey),
                     GLMissingEvaluationKeyError);
    }
    {
        const auto result = switching.SwitchIntBig(input, bigKey);
        EXPECT_EQ(result.GetDestinationKeyTag(), primary.GetKeyTag());
        EXPECT_TRUE(switching.VerifySwitchResultOwner(
            input, result, bigKey, primary));
        EXPECT_THROW((void)switching.SwitchIntSmall(input, bigKey),
                     GLMissingEvaluationKeyError);
    }

    const auto wrongPrimary = rlwe.KeyGen(1, 0x57524f4e47505249ULL);
    EXPECT_FALSE(switching.VerifyEvaluationKeyOwner(smallKey, wrongPrimary));
}

}  // namespace
}  // namespace lbcrypto
