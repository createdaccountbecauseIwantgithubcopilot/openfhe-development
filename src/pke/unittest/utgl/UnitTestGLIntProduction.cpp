//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "gtest/gtest.h"

#include "scheme/gl/gl-int-production.h"

#include <cstdint>
#include <vector>

namespace lbcrypto {
namespace {

uint64_t ProductionPowMod(uint64_t base, uint64_t exponent, uint64_t modulus) {
    uint64_t result = 1;
    while (exponent != 0) {
        if ((exponent & 1) != 0) {
            result = static_cast<uint64_t>(
                (static_cast<unsigned __int128>(result) * base) % modulus);
        }
        base = static_cast<uint64_t>(
            (static_cast<unsigned __int128>(base) * base) % modulus);
        exponent >>= 1;
    }
    return result;
}

TEST(GLIntProduction, SparseSigmaIntDenseRPrimeRoundTrip) {
    const GLIntProductionCore core;
    const auto& parameters = core.GetParameters();
    EXPECT_TRUE(parameters.IsGL128257N32Geometry());
    EXPECT_EQ(parameters.plaintextModulus, 1579009u);
    EXPECT_EQ(ProductionPowMod(core.GetRoots().zeta, 512, 1579009), 1u);
    EXPECT_EQ(ProductionPowMod(core.GetRoots().eta, 257, 1579009), 1u);

    const auto capabilities = core.GetCapabilities();
    EXPECT_TRUE(capabilities.exactGL128257N32Geometry);
    EXPECT_TRUE(capabilities.sparseLogicalValuePath);
    EXPECT_TRUE(capabilities.denseRPrimeEncoding);
    EXPECT_TRUE(capabilities.selectedSlotDecode);
    EXPECT_TRUE(capabilities.exactIntegerTraceMatMul);
    EXPECT_FALSE(capabilities.ciphertextEncryption);
    EXPECT_FALSE(capabilities.switchIntSmall);
    EXPECT_FALSE(capabilities.switchIntBig);
    EXPECT_FALSE(capabilities.securityAuthorized);
    EXPECT_FALSE(capabilities.bootstrap);

    const GLIntProductionSparsePlaintext sparse(
        parameters,
        {{GLIntBranch::Plus, 7, 2, 3, 12345},
         {GLIntBranch::Minus, 19, 5, 11, -77}});
    const auto encoded = core.EncodeSparse(sparse);
    EXPECT_EQ(encoded.GetCoefficients().size(), 128u * 128u * 256u);
    EXPECT_EQ(encoded.GetCoefficients().size() * sizeof(GLIntGaussianResidue),
              64u * 1024u * 1024u);
    EXPECT_EQ(core.DecodeAt(encoded, GLIntBranch::Plus, 7, 2, 3), 12345);
    EXPECT_EQ(core.DecodeAt(encoded, GLIntBranch::Minus, 19, 5, 11),
              1579009 - 77);
    EXPECT_EQ(core.DecodeAt(encoded, GLIntBranch::Plus, 7, 2, 4), 0);
}

TEST(GLIntProduction, ExactSparseIntegerMatrixSemantics) {
    const GLIntProductionCore core;
    const auto& parameters = core.GetParameters();
    constexpr uint64_t t = 1579009;
    const auto inverseN = ProductionPowMod(128, t - 2, t);

    const GLIntProductionSparsePlaintext lhs(
        parameters,
        {{GLIntBranch::Plus, 9, 1, 4, 6},
         {GLIntBranch::Minus, 9, 2, 5, 7}});
    const GLIntProductionSparsePlaintext rhs(
        parameters,
        {{GLIntBranch::Minus, 9, 3, 4, 10},
         {GLIntBranch::Plus, 9, 6, 5, 11}});
    const auto product = core.MatrixMultiplyTrace(lhs, rhs);
    EXPECT_EQ(product.At(GLIntBranch::Plus, 9, 1, 3),
              static_cast<int64_t>((60 * inverseN) % t));
    EXPECT_EQ(product.At(GLIntBranch::Minus, 9, 2, 6),
              static_cast<int64_t>((77 * inverseN) % t));
    EXPECT_EQ(product.GetValues().size(), 2u);

    const auto sum = core.Add(lhs, lhs);
    EXPECT_EQ(sum.At(GLIntBranch::Plus, 9, 1, 4), 12);
    const auto difference = core.Subtract(lhs, lhs);
    EXPECT_TRUE(difference.GetValues().empty());
    const auto negated = core.Negate(lhs);
    EXPECT_EQ(negated.At(GLIntBranch::Minus, 9, 2, 5), t - 7);

    const GLIntProductionSparsePlaintext mask(
        parameters, {{GLIntBranch::Plus, 9, 1, 4, 9}});
    const auto hadamard = core.Hadamard(lhs, mask);
    EXPECT_EQ(hadamard.GetValues().size(), 1u);
    EXPECT_EQ(hadamard.At(GLIntBranch::Plus, 9, 1, 4), 54);

    std::vector<GLIntProductionSlotValue> tooMany;
    for (uint32_t index = 0;
         index < kGLIntProductionMaxEncodedLogicalValues + 1; ++index) {
        tooMany.push_back(
            {GLIntBranch::Plus, index, 0, 0, static_cast<int64_t>(index + 1)});
    }
    const GLIntProductionSparsePlaintext bounded(parameters,
                                                  std::move(tooMany));
    EXPECT_THROW((void)core.EncodeSparse(bounded), GLDimensionError);
}

}  // namespace
}  // namespace lbcrypto
