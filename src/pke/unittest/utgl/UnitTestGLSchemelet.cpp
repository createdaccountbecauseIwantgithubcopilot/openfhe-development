//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "gtest/gtest.h"

#include "scheme/gl/gl-schemelet.h"

#include <complex>
#include <cstddef>
#include <cstdint>
#include <random>
#include <type_traits>
#include <vector>

namespace lbcrypto {
namespace {

constexpr double kCkksTolerance = 1e-4;

static_assert(!std::is_default_constructible_v<GLNativeEvalKey>,
              "a native GL key bundle cannot be publicly constructed without both key families");
static_assert(!std::is_aggregate_v<GLNativeEvalKey>,
              "native GL key-family invariants must stay behind its validating constructor");

GLParameters TestParameters(std::size_t dimension, uint32_t ringDimension = 512,
                            uint32_t multiplicativeDepth = 1) {
    GLParameters parameters;
    parameters.dimension           = dimension;
    parameters.multiplicativeDepth = multiplicativeDepth;
    parameters.scalingModSize      = 35;
    parameters.firstModSize        = 45;
    parameters.ringDimension       = ringDimension;
    parameters.securityLevel       = HEStd_NotSet;
    parameters.scalingTechnique    = FIXEDAUTO;
    return parameters;
}

std::vector<std::complex<double>> RealValues(std::initializer_list<double> values) {
    std::vector<std::complex<double>> result;
    result.reserve(values.size());
    for (const auto value : values) {
        result.emplace_back(value, 0.0);
    }
    return result;
}

const std::vector<std::complex<double>>& PinnedA() {
    static const auto values = RealValues({
        1, 2, 0, -1,
        0, 1, 3, 0,
        2, 0, 1, 1,
        1, -1, 0, 2,
    });
    return values;
}

const std::vector<std::complex<double>>& PinnedB() {
    static const auto values = RealValues({
        1, 0, 2, 1,
        0, 1, -1, 2,
        1, 2, 0, 0,
        2, 0, 1, 1,
    });
    return values;
}

const std::vector<std::complex<double>>& PinnedSum() {
    static const auto values = RealValues({
        2, 2, 2, 0,
        0, 2, 2, 2,
        3, 2, 1, 1,
        3, -1, 1, 3,
    });
    return values;
}

const std::vector<std::complex<double>>& PinnedProduct() {
    static const auto values = RealValues({
        -1, 2, -1, 4,
        3, 7, -1, 2,
        5, 2, 5, 3,
        5, -1, 5, 1,
    });
    return values;
}

const std::vector<std::complex<double>>& PinnedRawCircledast() {
    // A*B^*/4.  PinnedA and PinnedB are real, so B^*=B^T here.
    static const auto values = RealValues({
        0, 0, 1.25, 0.25,
        1.5, -0.5, 0.5, 0.75,
        1.25, 0.25, 0.5, 1.5,
        0.75, 0.75, -0.25, 1,
    });
    return values;
}

const std::vector<std::complex<double>>& PinnedBAdjoint() {
    static const auto values = RealValues({
        1, 0, 1, 2,
        0, 1, 2, 0,
        2, -1, 0, 1,
        1, 2, 0, 1,
    });
    return values;
}

const std::vector<std::complex<double>>& PinnedAYCoefficientRows() {
    // Coefficient-major c_y(zeta_j), independently pinned from
    // c_y(zeta_j)=(1/4) sum_k A[j,k] zeta_k^{-y},
    // zeta_k=exp(2*pi*i*5^k/16).
    static const std::vector<std::complex<double>> values = {
        {0.5, 0.0},
        {1.0, 0.0},
        {1.0, 0.0},
        {0.5, 0.0},
        {-0.056042691145996, -0.788580507474738},
        {-0.788580507474737, 0.056042691145995},
        {0.326640741219094, 0.135299025036549},
        {0.517982457401639, 0.597238791292193},
        {0.0, 0.0},
        {0.353553390593274, -0.353553390593274},
        {0.353553390593274, -0.353553390593274},
        {0.0, 0.0},
        {0.788580507474738, 0.056042691145995},
        {-0.056042691145996, 0.788580507474737},
        {-0.135299025036549, -0.326640741219094},
        {-0.597238791292193, -0.517982457401639},
    };
    return values;
}

void ExpectMatrixNear(const GLPlaintext& actual, const std::vector<std::complex<double>>& expected,
                      double tolerance = kCkksTolerance) {
    ASSERT_EQ(actual.GetValues().size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_NEAR(actual.GetValues()[i].real(), expected[i].real(), tolerance) << "cell " << i;
        EXPECT_NEAR(actual.GetValues()[i].imag(), expected[i].imag(), tolerance) << "cell " << i;
    }
}

TEST(GLSchemelet, PinnedEncodeDecodeN4) {
    GLSchemelet scheme(TestParameters(4));
    const GLPlaintext input(4, PinnedA());

    const auto encoded = scheme.Encode(input);
    ASSERT_EQ(encoded.GetRows().size(), 4u);
    bool rowsAreSimpleMatrixCopies = true;
    for (std::size_t y = 0; y < encoded.GetRows().size(); ++y) {
        const auto& row = encoded.GetRows()[y];
        ASSERT_NE(row, nullptr);
        EXPECT_EQ(row->GetEncodingType(), CKKS_PACKED_ENCODING);
        EXPECT_GE(row->GetCKKSPackedValue().size(), 4u);
        for (std::size_t j = 0; j < 4; ++j) {
            const auto actual = row->GetCKKSPackedValue()[j];
            const auto expected = PinnedAYCoefficientRows()[y * 4 + j];
            EXPECT_NEAR(actual.real(), expected.real(), 1e-12) << "Y row " << y << ", X slot " << j;
            EXPECT_NEAR(actual.imag(), expected.imag(), 1e-12) << "Y row " << y << ", X slot " << j;
            rowsAreSimpleMatrixCopies =
                rowsAreSimpleMatrixCopies && std::abs(actual - PinnedA()[y * 4 + j]) < 1e-12;
        }
    }
    EXPECT_FALSE(rowsAreSimpleMatrixCopies)
        << "canonical GL Y coefficients must not be raw logical matrix rows";

    const auto decoded = scheme.Decode(encoded);
    ExpectMatrixNear(decoded, PinnedA(), 1e-12);
}

TEST(GLSchemelet, ExactNativeRingTransportN4AndN8) {
    for (const std::size_t n : {std::size_t{4}, std::size_t{8}}) {
        GLSchemelet scheme(TestParameters(n, static_cast<uint32_t>(2 * n)));
        EXPECT_TRUE(scheme.UsesExactNativeRing());
        EXPECT_TRUE(scheme.GetParameters().RequestsExactNativeRing());
        EXPECT_EQ(scheme.GetGeometry().GetNativeRingDimension(), 2 * n);
        EXPECT_EQ(scheme.GetGeometry().GetNativeCyclotomicOrder(), 4 * n);
        EXPECT_EQ(scheme.GetCryptoContext()->GetRingDimension(), 2 * n);
        EXPECT_EQ(scheme.GetCryptoContext()->GetCyclotomicOrder(), 4 * n);

        std::vector<std::complex<double>> values;
        values.reserve(n * n);
        for (std::size_t cell = 0; cell < n * n; ++cell) {
            const auto signedCell = static_cast<double>(cell) - static_cast<double>(n * n) / 2.0;
            values.emplace_back(signedCell / 8.0, static_cast<double>(cell % n) / 16.0);
        }

        const GLPlaintext input(n, values);
        ExpectMatrixNear(scheme.Decode(scheme.Encode(input)), values, 1e-12);
        const auto keys = scheme.KeyGen();
        const auto encrypted = scheme.Encrypt(keys.secretKey, scheme.Encode(input));
        ExpectMatrixNear(scheme.Decrypt(keys.secretKey, encrypted), values);
    }

    auto exactButSecure = TestParameters(4, 8);
    exactButSecure.securityLevel = HEStd_128_classic;
    EXPECT_THROW((void)GLSchemelet(exactButSecure), GLNativeModeError);

    GLSchemelet largerTransport(TestParameters(4, 512));
    EXPECT_FALSE(largerTransport.UsesExactNativeRing());
}

TEST(GLSchemelet, PublicEncryptProducesNRealRandomizedRowsN4) {
    GLSchemelet scheme(TestParameters(4));
    const auto keys    = scheme.KeyGen();
    const auto encoded = scheme.Encode(GLPlaintext(4, PinnedA()));

    const auto first  = scheme.Encrypt(keys.publicKey, encoded);
    const auto second = scheme.Encrypt(keys.publicKey, encoded);

    ASSERT_EQ(first.GetRows().size(), 4u);
    bool anyCiphertextDiffers = false;
    for (std::size_t row = 0; row < first.GetRows().size(); ++row) {
        ASSERT_NE(first.GetRows()[row], nullptr);
        ASSERT_NE(second.GetRows()[row], nullptr);
        EXPECT_EQ(first.GetRows()[row]->GetCryptoContext().get(), scheme.GetCryptoContext().get());
        EXPECT_EQ(first.GetRows()[row]->GetKeyTag(), keys.publicKey->GetKeyTag());
        EXPECT_EQ(first.GetRows()[row]->GetElements().size(), 2u);
        anyCiphertextDiffers = anyCiphertextDiffers ||
                               (*first.GetRows()[row] != *second.GetRows()[row]);
    }
    EXPECT_TRUE(anyCiphertextDiffers)
        << "two public encryptions of the same rows must not be a clear deterministic passthrough";

    const auto decrypted = scheme.Decrypt(keys.secretKey, first);
    ExpectMatrixNear(decrypted, PinnedA());
}

TEST(GLSchemelet, RandomizedComplexSymmetricRoundTripN8) {
    GLSchemelet scheme(TestParameters(8));
    const auto keys = scheme.KeyGen();

    std::mt19937_64 rng(0x474c2d4f50454e46ULL);
    std::uniform_real_distribution<double> distribution(-3.0, 3.0);
    std::vector<std::complex<double>> values;
    values.reserve(64);
    for (std::size_t i = 0; i < 64; ++i) {
        values.emplace_back(distribution(rng), distribution(rng));
    }

    const GLPlaintext input(8, values);
    const auto encrypted = scheme.Encrypt(keys.secretKey, scheme.Encode(input));
    ASSERT_EQ(encrypted.GetRows().size(), 8u);
    for (const auto& row : encrypted.GetRows()) {
        ASSERT_NE(row, nullptr);
        EXPECT_EQ(row->GetElements().size(), 2u);
    }

    const auto decrypted = scheme.Decrypt(keys.secretKey, encrypted);
    ExpectMatrixNear(decrypted, values);
}

TEST(GLSchemelet, PinnedAddN4) {
    GLSchemelet scheme(TestParameters(4));
    const auto keys = scheme.KeyGen();

    const auto a = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));
    const auto b = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));
    const auto sum = scheme.Add(a, b);

    ASSERT_EQ(sum.GetRows().size(), 4u);
    const auto decrypted = scheme.Decrypt(keys.secretKey, sum);
    ExpectMatrixNear(decrypted, PinnedSum());
}

TEST(GLSchemelet, PinnedEvalMatMulPlainN4) {
    for (const uint32_t ringDimension : {8u, 512u}) {
        SCOPED_TRACE(::testing::Message() << "ringDimension=" << ringDimension);
        GLSchemelet scheme(TestParameters(4, ringDimension, 3));
        const auto keys = scheme.KeyGen();
        const auto encryptedA = scheme.Encrypt(
            keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));

        const auto keyTag = keys.publicKey->GetKeyTag();
        EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys().count(keyTag), 0u);
        EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalAutomorphismKeys().count(keyTag), 0u);

        // This path deliberately has no EvalMult/EvalSum key generation: it is
        // an encrypted-left/clear-right oracle made only of linear maps.
        const auto product = scheme.EvalMatMulPlain(encryptedA, GLPlaintext(4, PinnedB()));
        ASSERT_EQ(product.GetRows().size(), 4u);
        for (const auto& row : product.GetRows()) {
            ASSERT_NE(row, nullptr);
            EXPECT_EQ(row->GetElements().size(), 2u);
            EXPECT_EQ(row->GetLevel(), 2u);
        }
        ExpectMatrixNear(scheme.Decrypt(keys.secretKey, product), PinnedProduct(), 2e-3);
        EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys().count(keyTag), 0u);
        EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalAutomorphismKeys().count(keyTag), 0u);
    }

    GLSchemelet shallow(TestParameters(4, 512, 2));
    const auto shallowKeys = shallow.KeyGen();
    const auto shallowA = shallow.Encrypt(
        shallowKeys.publicKey, shallow.Encode(GLPlaintext(4, PinnedA())));
    EXPECT_THROW((void)shallow.EvalMatMulPlain(shallowA, GLPlaintext(4, PinnedB())), GLDepthError);
}

TEST(GLSchemelet, PinnedNativePlainCircledastAndMatMulN4) {
    GLSchemelet scheme(TestParameters(4, 8, 1));
    ASSERT_TRUE(scheme.UsesExactNativeRing());
    const auto keys = scheme.KeyGen();
    const auto encryptedA = scheme.Encrypt(
        keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));

    // Raw section-3.4 circledast has the deliberate conjugate-transpose and
    // 1/n semantics.  This path has no EvalMult, EvalSum, or rotation keys.
    const auto raw = scheme.EvalCircledastPlainNative(
        encryptedA, GLPlaintext(4, PinnedB()));
    ASSERT_EQ(raw.GetRows().size(), 4u);
    for (const auto& row : raw.GetRows()) {
        ASSERT_NE(row, nullptr);
        EXPECT_EQ(row->GetElements().size(), 2u);
        EXPECT_EQ(row->GetLevel(), 1u);
        EXPECT_EQ(row->GetNoiseScaleDeg(), 1u);
    }
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, raw), PinnedRawCircledast(), 2e-3);

    // The ordinary product wrapper evaluates n*(A circledast B^*) and must
    // therefore match the independently pinned A*B matrix.
    const auto product = scheme.EvalMatMulPlainNative(
        encryptedA, GLPlaintext(4, PinnedB()));
    ASSERT_EQ(product.GetRows().size(), 4u);
    for (const auto& row : product.GetRows()) {
        ASSERT_NE(row, nullptr);
        EXPECT_EQ(row->GetElements().size(), 2u);
        EXPECT_EQ(row->GetLevel(), 1u);
        EXPECT_EQ(row->GetNoiseScaleDeg(), 1u);
    }
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, product), PinnedProduct(), 2e-3);

    GLSchemelet transportOnly(TestParameters(4, 512, 1));
    const auto transportKeys = transportOnly.KeyGen();
    const auto transportA = transportOnly.Encrypt(
        transportKeys.publicKey, transportOnly.Encode(GLPlaintext(4, PinnedA())));
    EXPECT_THROW((void)transportOnly.EvalCircledastPlainNative(
                     transportA, GLPlaintext(4, PinnedB())),
                 GLNativeModeError);
    EXPECT_THROW((void)transportOnly.EvalMatMulPlainNative(
                     transportA, GLPlaintext(4, PinnedB())),
                 GLNativeModeError);
}

TEST(GLSchemelet, PinnedNativeCipherCircledastAndMatMulN4) {
    GLSchemelet scheme(TestParameters(4, 8, 1));
    const auto keys = scheme.KeyGen();
    const auto nativeKeys = scheme.EvalMatMulNativeKeyGen(keys.secretKey);
    nativeKeys.Validate();
    EXPECT_EQ(nativeKeys.GetGeometry(), scheme.GetGeometry());
    EXPECT_EQ(nativeKeys.GetCryptoContext().get(), scheme.GetCryptoContext().get());
    EXPECT_EQ(nativeKeys.GetKeyTag(), keys.secretKey->GetKeyTag());
    EXPECT_TRUE(CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys().find(keys.secretKey->GetKeyTag()) ==
                CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys().end());
    EXPECT_TRUE(CryptoContextImpl<DCRTPoly>::GetAllEvalAutomorphismKeys().find(keys.secretKey->GetKeyTag()) ==
                CryptoContextImpl<DCRTPoly>::GetAllEvalAutomorphismKeys().end());

    const auto encryptedA = scheme.Encrypt(
        keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));
    const auto encryptedB = scheme.Encrypt(
        keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));

    const auto adjointB = scheme.EvalAdjointNative(encryptedB, nativeKeys);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, adjointB), PinnedBAdjoint(), 2e-3);
    for (const auto& row : adjointB.GetRows()) {
        EXPECT_EQ(row->GetElements().size(), 2u);
        EXPECT_EQ(row->GetLevel(), 0u);
        EXPECT_EQ(row->GetNoiseScaleDeg(), 1u);
    }

    const auto raw = scheme.EvalCircledastNative(encryptedA, encryptedB, nativeKeys);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, raw), PinnedRawCircledast(), 2e-2);
    for (const auto& row : raw.GetRows()) {
        EXPECT_EQ(row->GetElements().size(), 2u);
        EXPECT_EQ(row->GetLevel(), 1u);
        EXPECT_EQ(row->GetNoiseScaleDeg(), 1u);
    }

    const auto product = scheme.EvalMatMulNative(encryptedA, encryptedB, nativeKeys);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, product), PinnedProduct(), 3e-2);
    for (const auto& row : product.GetRows()) {
        EXPECT_EQ(row->GetElements().size(), 2u);
        EXPECT_EQ(row->GetLevel(), 1u);
        EXPECT_EQ(row->GetNoiseScaleDeg(), 1u);
    }
}

TEST(GLSchemelet, NativeAdjointAndMatMulPreserveComplexConjugationN4) {
    GLSchemelet scheme(TestParameters(4, 8, 1));
    const auto keys = scheme.KeyGen();
    const auto nativeKeys = scheme.EvalMatMulNativeKeyGen(keys.secretKey);

    const auto identity = RealValues({
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 1,
    });
    const std::vector<std::complex<double>> complexB = {
        {1, 1}, {2, -1}, {0, 0}, {0, -1},
        {3, 0}, {0, -2}, {1, 1}, {0, 0},
        {0, 0}, {2, 0}, {-1, 1}, {0, 4},
        {1, -1}, {0, 0}, {3, 0}, {-2, 0},
    };
    const std::vector<std::complex<double>> complexBAdjoint = {
        {1, -1}, {3, 0}, {0, 0}, {1, 1},
        {2, 1}, {0, 2}, {2, 0}, {0, 0},
        {0, 0}, {1, -1}, {-1, -1}, {3, 0},
        {0, 1}, {0, 0}, {0, -4}, {-2, 0},
    };
    std::vector<std::complex<double>> rawExpected = complexBAdjoint;
    for (auto& value : rawExpected) {
        value /= 4.0;
    }

    const auto encryptedIdentity = scheme.Encrypt(
        keys.publicKey, scheme.Encode(GLPlaintext(4, identity)));
    const auto encryptedB = scheme.Encrypt(
        keys.publicKey, scheme.Encode(GLPlaintext(4, complexB)));

    const auto adjoint = scheme.EvalAdjointNative(encryptedB, nativeKeys);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, adjoint), complexBAdjoint, 2e-3);

    const auto raw = scheme.EvalCircledastNative(encryptedIdentity, encryptedB, nativeKeys);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, raw), rawExpected, 2e-2);

    const auto product = scheme.EvalMatMulNative(encryptedIdentity, encryptedB, nativeKeys);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, product), complexB, 3e-2);
}

TEST(GLSchemelet, NativePlainAndCipherIdentityComplexN8) {
    constexpr std::size_t n = 8;
    GLSchemelet scheme(TestParameters(n, 2 * n, 1));
    ASSERT_TRUE(scheme.UsesExactNativeRing());
    const auto keys = scheme.KeyGen();
    const auto nativeKeys = scheme.EvalMatMulNativeKeyGen(keys.secretKey);
    nativeKeys.Validate();

    std::vector<std::complex<double>> identity(n * n, {0.0, 0.0});
    std::vector<std::complex<double>> values;
    values.reserve(n * n);
    for (std::size_t row = 0; row < n; ++row) {
        identity[row * n + row] = {1.0, 0.0};
        for (std::size_t column = 0; column < n; ++column) {
            const auto realNumerator = static_cast<int>((3 * row + 5 * column) % 9) - 4;
            const auto imagNumerator = static_cast<int>((7 * row + 2 * column) % 7) - 3;
            values.emplace_back(static_cast<double>(realNumerator) / 4.0,
                                static_cast<double>(imagNumerator) / 8.0);
        }
    }

    std::vector<std::complex<double>> adjoint(n * n);
    for (std::size_t row = 0; row < n; ++row) {
        for (std::size_t column = 0; column < n; ++column) {
            adjoint[row * n + column] = std::conj(values[column * n + row]);
        }
    }
    auto rawExpected = adjoint;
    for (auto& value : rawExpected) {
        value /= static_cast<double>(n);
    }

    const auto encryptedIdentity = scheme.Encrypt(
        keys.publicKey, scheme.Encode(GLPlaintext(n, identity)));
    const auto encryptedValues = scheme.Encrypt(
        keys.publicKey, scheme.Encode(GLPlaintext(n, values)));

    const auto plainRaw = scheme.EvalCircledastPlainNative(
        encryptedIdentity, GLPlaintext(n, values));
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, plainRaw), rawExpected, 5e-3);
    const auto plainProduct = scheme.EvalMatMulPlainNative(
        encryptedIdentity, GLPlaintext(n, values));
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, plainProduct), values, 5e-3);

    const auto encryptedAdjoint = scheme.EvalAdjointNative(encryptedValues, nativeKeys);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, encryptedAdjoint), adjoint, 5e-3);
    const auto encryptedRaw = scheme.EvalCircledastNative(
        encryptedIdentity, encryptedValues, nativeKeys);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, encryptedRaw), rawExpected, 5e-2);
    const auto encryptedProduct = scheme.EvalMatMulNative(
        encryptedIdentity, encryptedValues, nativeKeys);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, encryptedProduct), values, 7e-2);

    for (const auto& row : encryptedProduct.GetRows()) {
        ASSERT_NE(row, nullptr);
        EXPECT_EQ(row->GetElements().size(), 2u);
        EXPECT_EQ(row->GetLevel(), 1u);
        EXPECT_EQ(row->GetNoiseScaleDeg(), 1u);
    }
}

TEST(GLSchemelet, NativeEvaluationKeyAndModeNegatives) {
    GLSchemelet transportOnly(TestParameters(4, 512, 1));
    const auto transportKeys = transportOnly.KeyGen();
    EXPECT_THROW((void)transportOnly.EvalMatMulNativeKeyGen(transportKeys.secretKey),
                 GLNativeModeError);

    GLSchemelet scheme(TestParameters(4, 8, 1));
    const auto firstKeys = scheme.KeyGen();
    const auto secondKeys = scheme.KeyGen();
    const auto firstNativeKeys = scheme.EvalMatMulNativeKeyGen(firstKeys.secretKey);
    const auto secondNativeKeys = scheme.EvalMatMulNativeKeyGen(secondKeys.secretKey);
    const auto firstA = scheme.Encrypt(
        firstKeys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));
    const auto firstB = scheme.Encrypt(
        firstKeys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));
    const auto secondB = scheme.Encrypt(
        secondKeys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));

    EXPECT_THROW((void)scheme.EvalAdjointNative(firstB, secondNativeKeys), GLKeyMismatchError);
    EXPECT_THROW((void)scheme.EvalCircledastNative(firstA, secondB, firstNativeKeys),
                 GLKeyMismatchError);
    EXPECT_THROW((void)scheme.EvalMatMulNative(firstA, firstB, secondNativeKeys),
                 GLKeyMismatchError);

    auto otherParameters = TestParameters(4, 8, 1);
    otherParameters.firstModSize = 46;
    GLSchemelet other(otherParameters);
    ASSERT_NE(other.GetCryptoContext().get(), scheme.GetCryptoContext().get());
    const auto otherKeys = other.KeyGen();
    const auto otherNativeKeys = other.EvalMatMulNativeKeyGen(otherKeys.secretKey);
    EXPECT_THROW((void)scheme.EvalMatMulNative(firstA, firstB, otherNativeKeys),
                 GLContextMismatchError);
    EXPECT_THROW((void)scheme.EvalMatMulNativeKeyGen(otherKeys.secretKey),
                 GLKeyContextMismatchError);

    GLSchemelet leveled(TestParameters(4, 8, 2));
    const auto leveledKeys = leveled.KeyGen();
    const auto leveledNativeKeys = leveled.EvalMatMulNativeKeyGen(leveledKeys.secretKey);
    const auto levelA = leveled.Encrypt(
        leveledKeys.publicKey, leveled.Encode(GLPlaintext(4, PinnedA())));
    const auto levelB = leveled.Encrypt(
        leveledKeys.publicKey, leveled.Encode(GLPlaintext(4, PinnedB())));

    auto reducedRows = levelB.GetRows();
    for (auto& row : reducedRows) {
        row = row->Clone();
        leveled.GetCryptoContext()->GetScheme()->ModReduceInternalInPlace(row, 1);
    }
    const GLCiphertext reducedB(leveled.GetGeometry(), leveled.GetCryptoContext(),
                                std::move(reducedRows));
    ASSERT_EQ(reducedB.GetRows().front()->GetLevel(), 1u);
    EXPECT_THROW((void)leveled.EvalCircledastNative(
                     levelA, reducedB, leveledNativeKeys),
                 GLCiphertextError);
    EXPECT_THROW((void)leveled.EvalMatMulNative(
                     levelA, reducedB, leveledNativeKeys),
                 GLCiphertextError);

    auto wrongScaleRows = levelB.GetRows();
    for (auto& row : wrongScaleRows) {
        row = row->Clone();
        row->SetScalingFactor(row->GetScalingFactor() * 2.0);
    }
    const GLCiphertext wrongScaleB(leveled.GetGeometry(), leveled.GetCryptoContext(),
                                   std::move(wrongScaleRows));
    ASSERT_EQ(wrongScaleB.GetRows().front()->GetLevel(), levelB.GetRows().front()->GetLevel());
    EXPECT_NE(wrongScaleB.GetRows().front()->GetScalingFactor(),
              levelB.GetRows().front()->GetScalingFactor());
    EXPECT_THROW((void)leveled.EvalCircledastNative(
                     levelA, wrongScaleB, leveledNativeKeys),
                 GLCiphertextError);
    EXPECT_THROW((void)leveled.EvalMatMulNative(
                     levelA, wrongScaleB, leveledNativeKeys),
                 GLCiphertextError);
}

TEST(GLSchemelet, PinnedEvalMatMulReferenceN4) {
    for (const uint32_t ringDimension : {8u, 512u}) {
        SCOPED_TRACE(::testing::Message() << "ringDimension=" << ringDimension);
        auto parameters = TestParameters(4, ringDimension, 4);
        parameters.scalingTechnique = (ringDimension == 8u) ? FLEXIBLEAUTO : FIXEDAUTO;
        GLSchemelet scheme(parameters);
        const auto keys = scheme.KeyGen();
        scheme.EvalMatMulReferenceKeyGen(keys.secretKey);

        const auto encryptedA = scheme.Encrypt(
            keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));
        const auto encryptedB = scheme.Encrypt(
            keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));
        const auto product = scheme.EvalMatMulReference(encryptedA, encryptedB);

        ASSERT_EQ(product.GetRows().size(), 4u);
        for (const auto& row : product.GetRows()) {
            ASSERT_NE(row, nullptr);
            EXPECT_EQ(row->GetElements().size(), 2u);
            EXPECT_EQ(row->GetLevel(), 3u);
        }
        ExpectMatrixNear(scheme.Decrypt(keys.secretKey, product), PinnedProduct(), 2e-2);
    }
}

TEST(GLSchemelet, EvalMatMulIdentityN8) {
    constexpr std::size_t n = 8;
    std::vector<std::complex<double>> values(n * n);
    std::vector<std::complex<double>> identity(n * n, {0.0, 0.0});
    for (std::size_t row = 0; row < n; ++row) {
        identity[row * n + row] = {1.0, 0.0};
        for (std::size_t column = 0; column < n; ++column) {
            const auto realPart = static_cast<double>(static_cast<int>((3 * row + column) % 9) - 4) / 4.0;
            const auto imagPart = static_cast<double>(static_cast<int>((row + 2 * column) % 7) - 3) / 8.0;
            values[row * n + column] = {realPart, imagPart};
        }
    }

    // Exact N=2n is a fast toy/native-layout check, not a security claim.
    GLSchemelet scheme(TestParameters(n, 2 * n, 4));
    const auto keys = scheme.KeyGen();
    const auto encryptedValues = scheme.Encrypt(
        keys.publicKey, scheme.Encode(GLPlaintext(n, values)));

    const auto plainProduct = scheme.EvalMatMulPlain(
        encryptedValues, GLPlaintext(n, identity));
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, plainProduct), values, 5e-3);

    scheme.EvalMatMulReferenceKeyGen(keys.secretKey);
    const auto encryptedIdentity = scheme.Encrypt(
        keys.publicKey, scheme.Encode(GLPlaintext(n, identity)));
    const auto referenceProduct = scheme.EvalMatMulReference(encryptedValues, encryptedIdentity);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, referenceProduct), values, 5e-2);
}

TEST(GLSchemelet, EvalMatMulReferenceNegatives) {
    GLSchemelet scheme(TestParameters(4, 512, 4));

    const auto noMultKeys = scheme.KeyGen();
    scheme.GetCryptoContext()->EvalSumKeyGen(noMultKeys.secretKey);
    const auto noMultA = scheme.Encrypt(
        noMultKeys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));
    const auto noMultB = scheme.Encrypt(
        noMultKeys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));
    EXPECT_THROW((void)scheme.EvalMatMulReference(noMultA, noMultB), GLMissingEvaluationKeyError);

    const auto noSumKeys = scheme.KeyGen();
    scheme.GetCryptoContext()->EvalMultKeyGen(noSumKeys.secretKey);
    const auto noSumA = scheme.Encrypt(
        noSumKeys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));
    const auto noSumB = scheme.Encrypt(
        noSumKeys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));
    EXPECT_THROW((void)scheme.EvalMatMulReference(noSumA, noSumB), GLMissingEvaluationKeyError);

    const auto firstKeys = scheme.KeyGen();
    const auto secondKeys = scheme.KeyGen();
    const auto firstA = scheme.Encrypt(
        firstKeys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));
    const auto secondB = scheme.Encrypt(
        secondKeys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));
    EXPECT_THROW((void)scheme.EvalMatMulReference(firstA, secondB), GLKeyMismatchError);

    GLSchemelet other(TestParameters(4, 1024, 4));
    const auto otherKeys = other.KeyGen();
    const auto otherB = other.Encrypt(
        otherKeys.publicKey, other.Encode(GLPlaintext(4, PinnedB())));
    EXPECT_THROW((void)scheme.EvalMatMulReference(firstA, otherB), GLContextMismatchError);
    EXPECT_THROW((void)scheme.EvalMatMulReferenceKeyGen(otherKeys.secretKey), GLKeyContextMismatchError);

    GLSchemelet shallow(TestParameters(4, 512, 3));
    const auto shallowKeys = shallow.KeyGen();
    const auto shallowA = shallow.Encrypt(
        shallowKeys.publicKey, shallow.Encode(GLPlaintext(4, PinnedA())));
    const auto shallowB = shallow.Encrypt(
        shallowKeys.publicKey, shallow.Encode(GLPlaintext(4, PinnedB())));
    EXPECT_THROW((void)shallow.EvalMatMulReference(shallowA, shallowB), GLDepthError);

    auto manualParameters = TestParameters(4, 512, 3);
    manualParameters.scalingTechnique = FIXEDMANUAL;
    GLSchemelet manual(manualParameters);
    const auto manualKeys = manual.KeyGen();
    const auto manualA = manual.Encrypt(
        manualKeys.publicKey, manual.Encode(GLPlaintext(4, PinnedA())));
    EXPECT_THROW((void)manual.EvalMatMulPlain(manualA, GLPlaintext(4, PinnedB())),
                 GLReferenceCircuitError);
}

TEST(GLSchemelet, DimensionAndMissingRowNegatives) {
    EXPECT_THROW((void)GLGeometry(2), GLDimensionError);
    EXPECT_THROW((void)GLGeometry(32), GLDimensionError);
    EXPECT_THROW((void)GLPlaintext(4, std::vector<std::complex<double>>(15)), GLDimensionError);

    auto tooSmallRing = TestParameters(8, 8);
    EXPECT_THROW((void)GLSchemelet(tooSmallRing), GLDimensionError);
    EXPECT_THROW((void)GLSchemelet(TestParameters(16, 512)),
                 GLNativeModeError);

    GLSchemelet scheme4(TestParameters(4));
    GLSchemelet scheme8(TestParameters(8));
    const auto keys4 = scheme4.KeyGen();
    const auto encoded8 = scheme8.Encode(GLPlaintext(8, std::vector<std::complex<double>>(64)));
    EXPECT_THROW((void)scheme4.Encrypt(keys4.publicKey, encoded8), GLDimensionError);

    const auto ciphertext =
        scheme4.Encrypt(keys4.publicKey, scheme4.Encode(GLPlaintext(4, PinnedA())));
    auto missingRows = ciphertext.GetRows();
    missingRows.pop_back();
    EXPECT_THROW(
        (void)GLCiphertext(scheme4.GetGeometry(), scheme4.GetCryptoContext(), std::move(missingRows)),
        GLMissingRowError);

    auto nullRows = ciphertext.GetRows();
    nullRows[2] = nullptr;
    EXPECT_THROW(
        (void)GLCiphertext(scheme4.GetGeometry(), scheme4.GetCryptoContext(), std::move(nullRows)),
        GLMissingRowError);

    auto extraComponentRows = ciphertext.GetRows();
    extraComponentRows[1] = scheme4.GetCryptoContext()->EvalMultNoRelin(
        extraComponentRows[1], extraComponentRows[1]);
    ASSERT_EQ(extraComponentRows[1]->GetElements().size(), 3u);
    EXPECT_THROW(
        (void)GLCiphertext(scheme4.GetGeometry(), scheme4.GetCryptoContext(),
                           std::move(extraComponentRows)),
        GLCiphertextError);
}

TEST(GLSchemelet, ContextAndKeyMismatchNegatives) {
    GLSchemelet first(TestParameters(4, 512));
    GLSchemelet second(TestParameters(4, 1024));
    ASSERT_NE(first.GetCryptoContext().get(), second.GetCryptoContext().get());

    const auto firstKeys  = first.KeyGen();
    const auto secondKeys = second.KeyGen();
    const auto firstEncoded = first.Encode(GLPlaintext(4, PinnedA()));
    const auto secondEncoded = second.Encode(GLPlaintext(4, PinnedB()));
    const auto firstCiphertext = first.Encrypt(firstKeys.publicKey, firstEncoded);
    const auto secondCiphertext = second.Encrypt(secondKeys.publicKey, secondEncoded);

    EXPECT_THROW((void)first.Encrypt(secondKeys.publicKey, firstEncoded), GLKeyContextMismatchError);
    EXPECT_THROW((void)first.Decrypt(secondKeys.secretKey, firstCiphertext), GLKeyContextMismatchError);
    EXPECT_THROW((void)first.Add(firstCiphertext, secondCiphertext), GLContextMismatchError);

    auto mixedRows = firstCiphertext.GetRows();
    mixedRows[1] = secondCiphertext.GetRows()[1];
    EXPECT_THROW(
        (void)GLCiphertext(first.GetGeometry(), first.GetCryptoContext(), std::move(mixedRows)),
        GLContextMismatchError);

    const auto otherFirstKeys = first.KeyGen();
    const auto otherFirstCiphertext = first.Encrypt(otherFirstKeys.publicKey, firstEncoded);
    EXPECT_THROW((void)first.Add(firstCiphertext, otherFirstCiphertext), GLKeyMismatchError);
    EXPECT_THROW((void)first.Decrypt(otherFirstKeys.secretKey, firstCiphertext), GLKeyMismatchError);
}

}  // namespace
}  // namespace lbcrypto
