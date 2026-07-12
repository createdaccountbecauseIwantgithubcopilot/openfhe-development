//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "gtest/gtest.h"

#include "scheme/gl/gl-int-production-rlwe.h"

#include <utility>

namespace lbcrypto {
namespace {

TEST(GLIntProductionRLWE, ExactTErrEncryptDecryptAndBoundedModulusDrop) {
    const GLIntProductionCore codec;
    const GLIntProductionRLWECore rlwe;
    ASSERT_EQ(rlwe.GetModuli().size(), kGLIntProductionRLWEPlaneCount);
    for (const auto modulus : rlwe.GetModuli()) {
        EXPECT_EQ((modulus - 1) % (4u * 128u * 257u), 0u);
        EXPECT_GT(modulus, 4u * 1579009u);
    }

    const auto capabilities = rlwe.GetCapabilities();
    EXPECT_TRUE(capabilities.exactProductionRPrimeCiphertext);
    EXPECT_TRUE(capabilities.symmetricTErrEncryption);
    EXPECT_TRUE(capabilities.exactDecryptionModT);
    EXPECT_TRUE(capabilities.boundedRnsModulusDrop);
    EXPECT_FALSE(capabilities.noiseScalingModSwitch);
    EXPECT_FALSE(capabilities.publicKeyEncryption);
    EXPECT_FALSE(capabilities.switchIntSmall);
    EXPECT_FALSE(capabilities.switchIntBig);
    EXPECT_FALSE(capabilities.securityAuthorized);
    EXPECT_FALSE(capabilities.ciphertextMatMul);
    EXPECT_FALSE(capabilities.bootstrap);

    const GLIntProductionSparsePlaintext sparse(
        codec.GetParameters(),
        {{GLIntBranch::Plus, 3, 1, 2, 29},
         {GLIntBranch::Minus, 5, 7, 11, -41}});
    const auto plaintext = codec.EncodeSparse(sparse);
    const auto secretKey = rlwe.KeyGen(1, 0x534543524554ULL);
    EXPECT_EQ(secretKey.GetHammingWeight(), 1u);

    auto ciphertext =
        rlwe.Encrypt(secretKey, plaintext, 0x454e4352595054ULL);
    ASSERT_EQ(ciphertext.GetPlanes().size(), 2u);
    EXPECT_EQ(ciphertext.GetLevel(), 0u);
    EXPECT_EQ(ciphertext.GetKeyTag(), secretKey.GetKeyTag());
    EXPECT_EQ(ciphertext.GetPlanes().front().b.size(), 128u * 128u * 256u);
    {
        const auto decrypted = rlwe.Decrypt(secretKey, ciphertext);
        EXPECT_EQ(decrypted.GetCoefficients(), plaintext.GetCoefficients());
    }
    const auto wrongKey = rlwe.KeyGen(1, 0x57524f4e474b4559ULL);
    EXPECT_THROW((void)rlwe.Decrypt(wrongKey, ciphertext), GLKeyMismatchError);

    auto dropped = rlwe.ModSwitchDrop(std::move(ciphertext));
    ASSERT_EQ(dropped.GetPlanes().size(), 1u);
    EXPECT_EQ(dropped.GetLevel(), 1u);
    {
        const auto decrypted = rlwe.Decrypt(secretKey, dropped);
        EXPECT_EQ(decrypted.GetCoefficients(), plaintext.GetCoefficients());
    }
    EXPECT_THROW((void)rlwe.ModSwitchDrop(std::move(dropped)), GLDepthError);
}

}  // namespace
}  // namespace lbcrypto
