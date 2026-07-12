//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

// GL section-3.6 operation set: Negate/Sub, Hadamard, row/column rotation,
// conjugation, native transpose, and the Remark 3.13 transposed encoding.
// n=4 pins the shared cross-port contract vectors; n=8 checks every operation
// against a clear oracle computed in-test; n=16 has a bounded exact-ring
// codec/rotation composition gate. Toy dims n=4/8/16/32/64 with HEStd_NotSet remain
// conformance geometry, not a security claim.

#include "gtest/gtest.h"

#include "scheme/gl/gl-schemelet.h"

#include <algorithm>
#include <complex>
#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

namespace lbcrypto {
namespace {

// 0-level relabelings/rotations and single-rescale products at 45-bit scale.
constexpr double kExactOpTolerance = 1e-6;
// Compositions on top of native big-switch products accumulate their noise.
constexpr double kCompositionTolerance = 5e-3;

static_assert(!std::is_default_constructible_v<GLRotationEvalKey>,
              "a GL rotation key bundle cannot be publicly constructed without key material");
static_assert(!std::is_default_constructible_v<GLConjugationEvalKey>,
              "a GL conjugation key bundle cannot be publicly constructed without key material");
static_assert(!std::is_default_constructible_v<GLTransposeEvalKey>,
              "a GL transpose key bundle cannot be publicly constructed without the K_transpose family");
static_assert(!std::is_aggregate_v<GLRotationEvalKey> && !std::is_aggregate_v<GLConjugationEvalKey> &&
                  !std::is_aggregate_v<GLTransposeEvalKey>,
              "GL key-family invariants must stay behind validating constructors");

using Matrix = std::vector<std::complex<double>>;

GLParameters OpsParameters(std::size_t dimension, uint32_t ringDimension,
                           uint32_t multiplicativeDepth = 1,
                           ScalingTechnique scalingTechnique = FIXEDAUTO) {
    GLParameters parameters;
    parameters.dimension           = dimension;
    parameters.multiplicativeDepth = multiplicativeDepth;
    parameters.scalingModSize      = 45;
    parameters.firstModSize        = 55;
    parameters.ringDimension       = ringDimension;
    parameters.securityLevel       = HEStd_NotSet;
    parameters.scalingTechnique    = scalingTechnique;
    return parameters;
}

Matrix RealValues(std::initializer_list<double> values) {
    Matrix result;
    result.reserve(values.size());
    for (const auto value : values) {
        result.emplace_back(value, 0.0);
    }
    return result;
}

// Shared cross-port contract matrices (conventions.md).
const Matrix& PinnedA() {
    static const auto values = RealValues({
        1, 2, 0, -1,
        0, 1, 3, 0,
        2, 0, 1, 1,
        1, -1, 0, 2,
    });
    return values;
}

const Matrix& PinnedB() {
    static const auto values = RealValues({
        1, 0, 2, 1,
        0, 1, -1, 2,
        1, 2, 0, 0,
        2, 0, 1, 1,
    });
    return values;
}

const Matrix& PinnedSubAB() {
    static const auto values = RealValues({
        0, 2, -2, -2,
        0, 0, 4, -2,
        1, -2, 1, 1,
        -1, -1, -1, 1,
    });
    return values;
}

const Matrix& PinnedHadamardAB() {
    static const auto values = RealValues({
        1, 0, 0, -1,
        0, 1, -3, 0,
        2, 0, 0, 0,
        2, 0, 0, 2,
    });
    return values;
}

const Matrix& PinnedRowRotateA1() {
    static const auto values = RealValues({
        0, 1, 3, 0,
        2, 0, 1, 1,
        1, -1, 0, 2,
        1, 2, 0, -1,
    });
    return values;
}

const Matrix& PinnedColumnRotateA1() {
    static const auto values = RealValues({
        2, 0, -1, 1,
        1, 3, 0, 0,
        0, 1, 1, 2,
        -1, 0, 2, 1,
    });
    return values;
}

const Matrix& PinnedTransposeA() {
    static const auto values = RealValues({
        1, 0, 2, 1,
        2, 1, 0, -1,
        0, 3, 1, 0,
        -1, 0, 1, 2,
    });
    return values;
}

Matrix ComplexJoin(const Matrix& realPart, const Matrix& imaginaryPart) {
    Matrix result(realPart.size());
    for (std::size_t cell = 0; cell < realPart.size(); ++cell) {
        result[cell] = realPart[cell] + std::complex<double>(0.0, 1.0) * imaginaryPart[cell];
    }
    return result;
}

Matrix OracleNegate(const Matrix& m) {
    Matrix result(m.size());
    std::transform(m.begin(), m.end(), result.begin(), [](const std::complex<double>& v) { return -v; });
    return result;
}

Matrix OracleSub(const Matrix& a, const Matrix& b) {
    Matrix result(a.size());
    for (std::size_t cell = 0; cell < a.size(); ++cell) {
        result[cell] = a[cell] - b[cell];
    }
    return result;
}

Matrix OracleHadamard(const Matrix& a, const Matrix& b) {
    Matrix result(a.size());
    for (std::size_t cell = 0; cell < a.size(); ++cell) {
        result[cell] = a[cell] * b[cell];
    }
    return result;
}

Matrix OracleRowRotate(const Matrix& m, std::size_t n, std::size_t nu) {
    Matrix result(m.size());
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            result[j * n + k] = m[((j + nu) % n) * n + k];
        }
    }
    return result;
}

Matrix OracleColumnRotate(const Matrix& m, std::size_t n, std::size_t nu) {
    Matrix result(m.size());
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            result[j * n + k] = m[j * n + ((k + nu) % n)];
        }
    }
    return result;
}

Matrix OracleTranspose(const Matrix& m, std::size_t n) {
    Matrix result(m.size());
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            result[j * n + k] = m[k * n + j];
        }
    }
    return result;
}

Matrix OracleConjugate(const Matrix& m) {
    Matrix result(m.size());
    std::transform(m.begin(), m.end(), result.begin(),
                   [](const std::complex<double>& v) { return std::conj(v); });
    return result;
}

// Clear triple loop for scale * V^* U (Remark 3.13 left product).
Matrix OracleLeftAdjointProduct(const Matrix& v, const Matrix& u, std::size_t n, double scale) {
    Matrix result(n * n, {0.0, 0.0});
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            for (std::size_t inner = 0; inner < n; ++inner) {
                result[j * n + k] += std::conj(v[inner * n + j]) * u[inner * n + k];
            }
            result[j * n + k] *= scale;
        }
    }
    return result;
}

// Clear triple loop for V^T U (real V makes this the same as V^* U).
Matrix OracleLeftTransposeProduct(const Matrix& v, const Matrix& u, std::size_t n) {
    Matrix result(n * n, {0.0, 0.0});
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            for (std::size_t inner = 0; inner < n; ++inner) {
                result[j * n + k] += v[inner * n + j] * u[inner * n + k];
            }
        }
    }
    return result;
}

Matrix OracleMatMul(const Matrix& a, const Matrix& b, std::size_t n) {
    Matrix result(n * n, {0.0, 0.0});
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            for (std::size_t inner = 0; inner < n; ++inner) {
                result[j * n + k] += a[j * n + inner] * b[inner * n + k];
            }
        }
    }
    return result;
}

// Deterministic non-symmetric n=8 matrix (conventions.md):
// M[j,k] = ((j + 2k) mod 7) - 3 + i*((3j - k mod 5) - 2)/4, with the
// mathematical (nonnegative) mod for the possibly negative 3j - k.
Matrix DeterministicN8() {
    Matrix values(64);
    for (std::size_t j = 0; j < 8; ++j) {
        for (std::size_t k = 0; k < 8; ++k) {
            const auto realPart = static_cast<double>((j + 2 * k) % 7) - 3.0;
            const int imagMod   = ((3 * static_cast<int>(j) - static_cast<int>(k)) % 5 + 5) % 5;
            values[j * 8 + k]   = {realPart, (static_cast<double>(imagMod) - 2.0) / 4.0};
        }
    }
    return values;
}

// A second deterministic n=8 matrix for the two-operand oracles.
Matrix DeterministicN8Second() {
    Matrix values(64);
    for (std::size_t j = 0; j < 8; ++j) {
        for (std::size_t k = 0; k < 8; ++k) {
            const auto realPart = static_cast<double>((2 * j + 3 * k) % 5) - 2.0;
            const auto imagPart = (static_cast<double>((j + 3 * k) % 7) - 3.0) / 8.0;
            values[j * 8 + k]   = {realPart, imagPart};
        }
    }
    return values;
}

Matrix DeterministicN16() {
    constexpr std::size_t n = 16;
    Matrix values(n * n);
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            const auto realNumerator =
                static_cast<int>((3 * j + 5 * k) % 13) - 6;
            const auto imagNumerator =
                static_cast<int>((7 * j + 2 * k) % 11) - 5;
            values[j * n + k] = {
                static_cast<double>(realNumerator) / 16.0,
                static_cast<double>(imagNumerator) / 32.0};
        }
    }
    return values;
}

void ExpectMatrixNear(const GLPlaintext& actual, const Matrix& expected, double tolerance) {
    ASSERT_EQ(actual.GetValues().size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_NEAR(actual.GetValues()[i].real(), expected[i].real(), tolerance) << "cell " << i;
        EXPECT_NEAR(actual.GetValues()[i].imag(), expected[i].imag(), tolerance) << "cell " << i;
    }
}

void ExpectRowMetadata(const GLCiphertext& ciphertext, std::size_t n, const std::string& keyTag,
                       uint32_t level, uint32_t noiseScaleDeg) {
    ASSERT_EQ(ciphertext.GetRows().size(), n);
    EXPECT_EQ(ciphertext.GetKeyTag(), keyTag);
    for (const auto& row : ciphertext.GetRows()) {
        ASSERT_NE(row, nullptr);
        EXPECT_EQ(row->GetElements().size(), 2u);
        EXPECT_EQ(row->GetLevel(), level);
        EXPECT_EQ(row->GetNoiseScaleDeg(), noiseScaleDeg);
        EXPECT_GE(row->GetSlots(), n);
    }
}

void ExpectSameScalingFactor(const GLCiphertext& actual, const GLCiphertext& reference) {
    ASSERT_FALSE(actual.GetRows().empty());
    ASSERT_FALSE(reference.GetRows().empty());
    for (const auto& row : actual.GetRows()) {
        EXPECT_EQ(row->GetScalingFactor(), reference.GetRows().front()->GetScalingFactor());
    }
}

TEST(GLOps, PinnedNegateAndSubN4BothModes) {
    for (const uint32_t ringDimension : {8u, 512u}) {
        SCOPED_TRACE(::testing::Message() << "ringDimension=" << ringDimension);
        GLSchemelet scheme(OpsParameters(4, ringDimension));
        const auto keys = scheme.KeyGen();
        const auto encryptedA = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));
        const auto encryptedB = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));

        const auto negated = scheme.Negate(encryptedA);
        ExpectRowMetadata(negated, 4, keys.publicKey->GetKeyTag(), 0, 1);
        ExpectSameScalingFactor(negated, encryptedA);
        ExpectMatrixNear(scheme.Decrypt(keys.secretKey, negated), OracleNegate(PinnedA()),
                         kExactOpTolerance);

        const auto difference = scheme.Sub(encryptedA, encryptedB);
        ExpectRowMetadata(difference, 4, keys.publicKey->GetKeyTag(), 0, 1);
        ExpectSameScalingFactor(difference, encryptedA);
        ExpectMatrixNear(scheme.Decrypt(keys.secretKey, difference), PinnedSubAB(), kExactOpTolerance);
    }
}

TEST(GLOps, PinnedHadamardN4BothModesAndTechniques) {
    for (const uint32_t ringDimension : {8u, 512u}) {
        for (const auto technique : {FIXEDAUTO, FLEXIBLEAUTO}) {
            SCOPED_TRACE(::testing::Message()
                         << "ringDimension=" << ringDimension << " technique=" << technique);
            GLSchemelet scheme(OpsParameters(4, ringDimension, 1, technique));
            const auto keys = scheme.KeyGen();
            scheme.EvalHadamardKeyGen(keys.secretKey);
            // The Hadamard relinearization key is the framework's own
            // registry-based s^2 Switch_small; no rotation keys appear.
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys().count(
                          keys.secretKey->GetKeyTag()),
                      1u);
            EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalAutomorphismKeys().count(
                          keys.secretKey->GetKeyTag()),
                      0u);

            const auto encryptedA =
                scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));
            const auto encryptedB =
                scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));

            const auto hadamard = scheme.EvalHadamard(encryptedA, encryptedB);
            ExpectRowMetadata(hadamard, 4, keys.publicKey->GetKeyTag(), 1, 1);
            ExpectMatrixNear(scheme.Decrypt(keys.secretKey, hadamard), PinnedHadamardAB(),
                             kExactOpTolerance);
        }
    }
}

TEST(GLOps, PinnedRowRotateN4BothModes) {
    for (const uint32_t ringDimension : {8u, 512u}) {
        SCOPED_TRACE(::testing::Message() << "ringDimension=" << ringDimension);
        GLSchemelet scheme(OpsParameters(4, ringDimension));
        const auto keys = scheme.KeyGen();
        const auto rotationKey = scheme.EvalRowRotateKeyGen(keys.secretKey, {1, 2, 3});
        rotationKey.Validate();
        EXPECT_EQ(rotationKey.GetKeyTag(), keys.secretKey->GetKeyTag());
        EXPECT_EQ(rotationKey.GetRotationAmounts(), (std::set<uint32_t>{1, 2, 3}));
        // Owned key object: the ambient automorphism registry stays empty.
        EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalAutomorphismKeys().count(
                      keys.secretKey->GetKeyTag()),
                  0u);

        const auto encryptedA = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));

        const auto rotated1 = scheme.EvalRowRotate(encryptedA, 1, rotationKey);
        ExpectRowMetadata(rotated1, 4, keys.publicKey->GetKeyTag(), 0, 1);
        ExpectSameScalingFactor(rotated1, encryptedA);
        ExpectMatrixNear(scheme.Decrypt(keys.secretKey, rotated1), PinnedRowRotateA1(),
                         kExactOpTolerance);

        for (const uint32_t nu : {2u, 3u}) {
            const auto rotated = scheme.EvalRowRotate(encryptedA, nu, rotationKey);
            ExpectMatrixNear(scheme.Decrypt(keys.secretKey, rotated),
                             OracleRowRotate(PinnedA(), 4, nu), kExactOpTolerance);
        }

        const auto identity = scheme.EvalRowRotate(encryptedA, 0, rotationKey);
        ExpectRowMetadata(identity, 4, keys.publicKey->GetKeyTag(), 0, 1);
        ExpectMatrixNear(scheme.Decrypt(keys.secretKey, identity), PinnedA(), kExactOpTolerance);
    }
}

TEST(GLOps, PinnedColumnRotateN4BothModes) {
    for (const uint32_t ringDimension : {8u, 512u}) {
        SCOPED_TRACE(::testing::Message() << "ringDimension=" << ringDimension);
        GLSchemelet scheme(OpsParameters(4, ringDimension));
        const auto keys = scheme.KeyGen();
        const auto encryptedA = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));

        const auto rotated1 = scheme.EvalColumnRotate(encryptedA, 1);
        ExpectRowMetadata(rotated1, 4, keys.publicKey->GetKeyTag(), 0, 1);
        ExpectSameScalingFactor(rotated1, encryptedA);
        ExpectMatrixNear(scheme.Decrypt(keys.secretKey, rotated1), PinnedColumnRotateA1(),
                         kExactOpTolerance);

        for (const uint32_t nu : {0u, 2u, 3u}) {
            const auto rotated = scheme.EvalColumnRotate(encryptedA, nu);
            ExpectMatrixNear(scheme.Decrypt(keys.secretKey, rotated),
                             OracleColumnRotate(PinnedA(), 4, nu), kExactOpTolerance);
        }

        // Column rotation is keyless: no registry entry of any kind appears.
        EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys().count(
                      keys.secretKey->GetKeyTag()),
                  0u);
        EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalAutomorphismKeys().count(
                      keys.secretKey->GetKeyTag()),
                  0u);
    }
}

TEST(GLOps, PinnedConjugateN4BothModes) {
    const auto pinnedC          = ComplexJoin(PinnedA(), PinnedB());
    const auto pinnedConjugateC = OracleConjugate(pinnedC);  // A - i*B by construction
    for (const uint32_t ringDimension : {8u, 512u}) {
        SCOPED_TRACE(::testing::Message() << "ringDimension=" << ringDimension);
        GLSchemelet scheme(OpsParameters(4, ringDimension));
        const auto keys = scheme.KeyGen();
        const auto conjugationKey = scheme.EvalConjugateKeyGen(keys.secretKey);
        conjugationKey.Validate();
        EXPECT_EQ(conjugationKey.GetKeyTag(), keys.secretKey->GetKeyTag());
        EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalAutomorphismKeys().count(
                      keys.secretKey->GetKeyTag()),
                  0u);

        const auto encryptedC = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, pinnedC)));
        const auto conjugated = scheme.EvalConjugate(encryptedC, conjugationKey);
        ExpectRowMetadata(conjugated, 4, keys.publicKey->GetKeyTag(), 0, 1);
        ExpectSameScalingFactor(conjugated, encryptedC);
        ExpectMatrixNear(scheme.Decrypt(keys.secretKey, conjugated), pinnedConjugateC,
                         kExactOpTolerance);
    }
}

TEST(GLOps, PinnedTransposeNativeN4) {
    GLSchemelet scheme(OpsParameters(4, 8));
    ASSERT_TRUE(scheme.UsesExactNativeRing());
    const auto keys = scheme.KeyGen();
    const auto transposeKey = scheme.EvalTransposeNativeKeyGen(keys.secretKey);
    transposeKey.Validate();
    EXPECT_EQ(transposeKey.GetGeometry(), scheme.GetGeometry());
    EXPECT_EQ(transposeKey.GetCryptoContext().get(), scheme.GetCryptoContext().get());
    EXPECT_EQ(transposeKey.GetKeyTag(), keys.secretKey->GetKeyTag());
    // The K_transpose family is owned; ambient registries stay empty.
    EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys().count(keys.secretKey->GetKeyTag()),
              0u);
    EXPECT_EQ(CryptoContextImpl<DCRTPoly>::GetAllEvalAutomorphismKeys().count(
                  keys.secretKey->GetKeyTag()),
              0u);

    const auto encryptedA = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));
    const auto transposed = scheme.EvalTransposeNative(encryptedA, transposeKey);
    ExpectRowMetadata(transposed, 4, keys.publicKey->GetKeyTag(), 0, 1);
    ExpectSameScalingFactor(transposed, encryptedA);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, transposed), PinnedTransposeA(),
                     kExactOpTolerance);

    const auto pinnedC = ComplexJoin(PinnedA(), PinnedB());
    const auto encryptedC = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, pinnedC)));
    const auto transposedC = scheme.EvalTransposeNative(encryptedC, transposeKey);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, transposedC), OracleTranspose(pinnedC, 4),
                     kExactOpTolerance);
}

TEST(GLOps, TransposeMatchesConjugateOfAdjointN4) {
    GLSchemelet scheme(OpsParameters(4, 8));
    const auto keys = scheme.KeyGen();
    const auto transposeKey   = scheme.EvalTransposeNativeKeyGen(keys.secretKey);
    const auto conjugationKey = scheme.EvalConjugateKeyGen(keys.secretKey);
    const auto nativeKeys     = scheme.EvalMatMulNativeKeyGen(keys.secretKey);

    const auto pinnedC = ComplexJoin(PinnedA(), PinnedB());
    const auto encryptedC = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, pinnedC)));

    // Contract pin: Adjoint(C) = A^T - i*B^T for C = A + i*B.
    const auto adjoint = scheme.EvalAdjointNative(encryptedC, nativeKeys);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, adjoint),
                     OracleConjugate(OracleTranspose(pinnedC, 4)), kExactOpTolerance);

    // Paper's memory optimization (GL_scheme.md 3.6): the dedicated transpose
    // equals conjugation composed with the conjugate transpose that reuses
    // the matmul key family.
    const auto direct   = scheme.EvalTransposeNative(encryptedC, transposeKey);
    const auto combined = scheme.EvalConjugate(scheme.EvalAdjointNative(encryptedC, nativeKeys),
                                               conjugationKey);

    const auto directClear   = scheme.Decrypt(keys.secretKey, direct);
    const auto combinedClear = scheme.Decrypt(keys.secretKey, combined);
    const auto expected      = OracleTranspose(pinnedC, 4);
    ExpectMatrixNear(directClear, expected, kExactOpTolerance);
    ExpectMatrixNear(combinedClear, expected, kExactOpTolerance);
    for (std::size_t cell = 0; cell < expected.size(); ++cell) {
        EXPECT_NEAR(directClear.GetValues()[cell].real(), combinedClear.GetValues()[cell].real(),
                    kExactOpTolerance)
            << "cell " << cell;
        EXPECT_NEAR(directClear.GetValues()[cell].imag(), combinedClear.GetValues()[cell].imag(),
                    kExactOpTolerance)
            << "cell " << cell;
    }
}

TEST(GLOps, PinnedTransposedEncodingLeftProductN4) {
    GLSchemelet scheme(OpsParameters(4, 8));
    const auto keys = scheme.KeyGen();

    // Codec pins: Encode_T(M) = Encode(M^T) and DecodeTransposed undoes it.
    const GLPlaintext inputA(4, PinnedA());
    ExpectMatrixNear(scheme.DecodeTransposed(scheme.EncodeTransposed(inputA)), PinnedA(), 1e-12);
    ExpectMatrixNear(scheme.Decode(scheme.EncodeTransposed(inputA)), PinnedTransposeA(), 1e-12);
    ExpectMatrixNear(scheme.DecodeTransposed(scheme.Encode(inputA)), PinnedTransposeA(), 1e-12);
    EXPECT_THROW((void)scheme.EncodeTransposed(GLPlaintext(8, Matrix(64, {1.0, 0.0}))),
                 GLDimensionError);

    const auto& clearV = PinnedB();  // real V, so V^* = V^T
    const auto encryptedTransposedA =
        scheme.Encrypt(keys.publicKey, scheme.EncodeTransposed(inputA));

    // Remark 3.13, raw circledast route: with u and v both under the
    // sigma-transpose encoding, the SAME u circledast v now computes
    // V^* U / n instead of U V^* / n.  The right plaintext enters the
    // transposed convention by encoding V^T.
    const auto rawLeft = scheme.EvalCircledastPlainNative(
        encryptedTransposedA, GLPlaintext(4, OracleTranspose(clearV, 4)));
    const auto rawLeftClear = scheme.Decrypt(keys.secretKey, rawLeft);
    ExpectMatrixNear(GLPlaintext(4, OracleTranspose(rawLeftClear.GetValues(), 4)),
                     OracleLeftAdjointProduct(clearV, PinnedA(), 4, 0.25), kExactOpTolerance);

    // n-scaled wrapper route: EvalMatMulPlainNative under the transposed
    // convention computes the exact left product V^T * A (triple loop).
    const auto leftProduct = scheme.EvalMatMulPlainNative(encryptedTransposedA,
                                                          GLPlaintext(4, clearV));
    const auto leftProductClear = scheme.Decrypt(keys.secretKey, leftProduct);
    ExpectMatrixNear(GLPlaintext(4, OracleTranspose(leftProductClear.GetValues(), 4)),
                     OracleLeftTransposeProduct(clearV, PinnedA(), 4), kExactOpTolerance);
}

TEST(GLOps, OracleAllOpsN8) {
    constexpr std::size_t n = 8;
    GLSchemelet scheme(OpsParameters(n, 2 * n, 2));
    ASSERT_TRUE(scheme.UsesExactNativeRing());
    const auto keys = scheme.KeyGen();
    scheme.EvalHadamardKeyGen(keys.secretKey);
    const auto rotationKey    = scheme.EvalRowRotateKeyGen(keys.secretKey, {3});
    const auto conjugationKey = scheme.EvalConjugateKeyGen(keys.secretKey);
    const auto transposeKey   = scheme.EvalTransposeNativeKeyGen(keys.secretKey);

    const auto m1 = DeterministicN8();
    const auto m2 = DeterministicN8Second();
    const auto encrypted1 = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(n, m1)));
    const auto encrypted2 = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(n, m2)));

    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, scheme.Negate(encrypted1)), OracleNegate(m1),
                     kExactOpTolerance);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, scheme.Sub(encrypted1, encrypted2)),
                     OracleSub(m1, m2), kExactOpTolerance);

    const auto hadamard = scheme.EvalHadamard(encrypted1, encrypted2);
    ExpectRowMetadata(hadamard, n, keys.publicKey->GetKeyTag(), 1, 1);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, hadamard), OracleHadamard(m1, m2),
                     kExactOpTolerance);

    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, scheme.EvalRowRotate(encrypted1, 3, rotationKey)),
                     OracleRowRotate(m1, n, 3), kExactOpTolerance);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, scheme.EvalColumnRotate(encrypted1, 5)),
                     OracleColumnRotate(m1, n, 5), kExactOpTolerance);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey,
                                    scheme.EvalConjugate(encrypted1, conjugationKey)),
                     OracleConjugate(m1), kExactOpTolerance);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey,
                                    scheme.EvalTransposeNative(encrypted1, transposeKey)),
                     OracleTranspose(m1, n), kExactOpTolerance);

    // Transposed-encoding oracle with a genuinely complex V: the raw
    // circledast under the sigma-transpose convention computes V^* U / n.
    ExpectMatrixNear(scheme.DecodeTransposed(scheme.EncodeTransposed(GLPlaintext(n, m1))), m1,
                     1e-12);
    const auto encryptedTransposed1 =
        scheme.Encrypt(keys.publicKey, scheme.EncodeTransposed(GLPlaintext(n, m1)));
    const auto rawLeft = scheme.EvalCircledastPlainNative(
        encryptedTransposed1, GLPlaintext(n, OracleTranspose(m2, n)));
    const auto rawLeftClear = scheme.Decrypt(keys.secretKey, rawLeft);
    ExpectMatrixNear(GLPlaintext(n, OracleTranspose(rawLeftClear.GetValues(), n)),
                     OracleLeftAdjointProduct(m2, m1, n, 1.0 / static_cast<double>(n)),
                     kExactOpTolerance);
}

TEST(GLOps, CompositionRowColTransposeN8) {
    constexpr std::size_t n = 8;
    GLSchemelet scheme(OpsParameters(n, 2 * n, 3));
    const auto keys = scheme.KeyGen();
    const auto rotationKey  = scheme.EvalRowRotateKeyGen(keys.secretKey, {1});
    const auto transposeKey = scheme.EvalTransposeNativeKeyGen(keys.secretKey);

    const auto m1 = DeterministicN8();
    const auto encrypted1 = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(n, m1)));

    const auto composed = scheme.EvalRowRotate(
        scheme.EvalColumnRotate(scheme.EvalTransposeNative(encrypted1, transposeKey), 1), 1,
        rotationKey);
    // The whole chain is 0-level: transpose, column, and row rotation all
    // preserve level and scale.
    ExpectRowMetadata(composed, n, keys.publicKey->GetKeyTag(), 0, 1);
    ExpectSameScalingFactor(composed, encrypted1);

    const auto expected =
        OracleRowRotate(OracleColumnRotate(OracleTranspose(m1, n), n, 1), n, 1);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, composed), expected, kExactOpTolerance);
}

TEST(GLOps, ExactN16CodecAndRotationCompositionOracle) {
    constexpr std::size_t n = 16;
    GLSchemelet scheme(OpsParameters(n, 2 * n));
    ASSERT_TRUE(scheme.UsesExactNativeRing());
    EXPECT_EQ(scheme.GetCryptoContext()->GetRingDimension(), 2 * n);
    EXPECT_EQ(scheme.GetCryptoContext()->GetCyclotomicOrder(), 4 * n);

    const auto values = DeterministicN16();
    const GLPlaintext plaintext(n, values);
    ExpectMatrixNear(scheme.Decode(scheme.Encode(plaintext)), values, 1e-12);
    ExpectMatrixNear(scheme.DecodeTransposed(scheme.EncodeTransposed(plaintext)),
                     values, 1e-12);

    const auto keys = scheme.KeyGen();
    const auto rotationKey = scheme.EvalRowRotateKeyGen(keys.secretKey, {5});
    const auto encrypted = scheme.Encrypt(keys.publicKey, scheme.Encode(plaintext));
    const auto composed = scheme.EvalRowRotate(
        scheme.EvalColumnRotate(encrypted, 7), 5, rotationKey);
    ExpectRowMetadata(composed, n, keys.publicKey->GetKeyTag(), 0, 1);
    ExpectSameScalingFactor(composed, encrypted);

    const auto expected =
        OracleRowRotate(OracleColumnRotate(values, n, 7), n, 5);
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, composed), expected,
                     kExactOpTolerance);
}

TEST(GLOps, HadamardAfterMatMulLevelBookkeepingN4) {
    GLSchemelet scheme(OpsParameters(4, 8, 3));
    const auto keys = scheme.KeyGen();
    scheme.EvalHadamardKeyGen(keys.secretKey);
    const auto nativeKeys = scheme.EvalMatMulNativeKeyGen(keys.secretKey);

    const auto clearG = OracleSub(PinnedA(), OracleNegate(PinnedB()));  // A + B
    const auto clearH = OracleSub(PinnedA(), PinnedB());                // A - B
    const auto encryptedA = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));
    const auto encryptedB = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));
    const auto encryptedG = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, clearG)));
    const auto encryptedH = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, clearH)));

    const auto productAB = scheme.EvalMatMulNative(encryptedA, encryptedB, nativeKeys);
    const auto productGH = scheme.EvalMatMulNative(encryptedG, encryptedH, nativeKeys);
    ExpectRowMetadata(productAB, 4, keys.publicKey->GetKeyTag(), 1, 1);
    ExpectRowMetadata(productGH, 4, keys.publicKey->GetKeyTag(), 1, 1);

    const auto hadamard = scheme.EvalHadamard(productAB, productGH);
    ExpectRowMetadata(hadamard, 4, keys.publicKey->GetKeyTag(), 2, 1);

    const auto expected = OracleHadamard(OracleMatMul(PinnedA(), PinnedB(), 4),
                                         OracleMatMul(clearG, clearH, 4));
    ExpectMatrixNear(scheme.Decrypt(keys.secretKey, hadamard), expected, kCompositionTolerance);
}

TEST(GLOps, HadamardNegatives) {
    GLSchemelet scheme(OpsParameters(4, 512, 2));
    const auto keys = scheme.KeyGen();
    const auto encryptedA = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));
    const auto encryptedB = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));

    // No EvalHadamardKeyGen yet: the registry probe must fail closed.
    EXPECT_THROW((void)scheme.EvalHadamard(encryptedA, encryptedB), GLMissingEvaluationKeyError);

    scheme.EvalHadamardKeyGen(keys.secretKey);
    (void)scheme.EvalHadamard(encryptedA, encryptedB);

    const auto otherKeys = scheme.KeyGen();
    const auto otherB = scheme.Encrypt(otherKeys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));
    EXPECT_THROW((void)scheme.EvalHadamard(encryptedA, otherB), GLKeyMismatchError);

    GLSchemelet foreign(OpsParameters(4, 1024, 2));
    const auto foreignKeys = foreign.KeyGen();
    const auto foreignB = foreign.Encrypt(foreignKeys.publicKey, foreign.Encode(GLPlaintext(4, PinnedB())));
    EXPECT_THROW((void)scheme.EvalHadamard(encryptedA, foreignB), GLContextMismatchError);
    EXPECT_THROW((void)scheme.EvalHadamardKeyGen(foreignKeys.secretKey), GLKeyContextMismatchError);

    // A level-reduced right operand no longer shares the left level/scale.
    auto reducedRows = encryptedB.GetRows();
    for (auto& row : reducedRows) {
        row = row->Clone();
        scheme.GetCryptoContext()->GetScheme()->ModReduceInternalInPlace(row, 1);
    }
    const GLCiphertext reducedB(scheme.GetGeometry(), scheme.GetCryptoContext(),
                                std::move(reducedRows));
    EXPECT_THROW((void)scheme.EvalHadamard(encryptedA, reducedB), GLCiphertextError);

    // Unrescaled scale-degree-two operands are rejected before any product.
    auto degreeTwoRows = encryptedA.GetRows();
    for (auto& row : degreeTwoRows) {
        row = scheme.GetCryptoContext()->EvalMult(row, encryptedB.GetRows().front());
    }
    const GLCiphertext degreeTwo(scheme.GetGeometry(), scheme.GetCryptoContext(),
                                 std::move(degreeTwoRows));
    ASSERT_EQ(degreeTwo.GetRows().front()->GetNoiseScaleDeg(), 2u);
    EXPECT_THROW((void)scheme.EvalHadamard(degreeTwo, degreeTwo), GLCiphertextError);

    // FIXEDMANUAL cannot honor the single deferred-rescale contract.
    auto manualParameters = OpsParameters(4, 512, 2);
    manualParameters.scalingTechnique = FIXEDMANUAL;
    GLSchemelet manual(manualParameters);
    const auto manualKeys = manual.KeyGen();
    manual.GetCryptoContext()->EvalMultKeyGen(manualKeys.secretKey);
    const auto manualA = manual.Encrypt(manualKeys.publicKey, manual.Encode(GLPlaintext(4, PinnedA())));
    const auto manualB = manual.Encrypt(manualKeys.publicKey, manual.Encode(GLPlaintext(4, PinnedB())));
    EXPECT_THROW((void)manual.EvalHadamard(manualA, manualB), GLReferenceCircuitError);
}

TEST(GLOps, RowRotateNegatives) {
    GLSchemelet scheme(OpsParameters(4, 512));
    const auto keys = scheme.KeyGen();
    const auto encryptedA = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));

    EXPECT_THROW((void)scheme.EvalRowRotateKeyGen(keys.secretKey, {}), GLDimensionError);
    EXPECT_THROW((void)scheme.EvalRowRotateKeyGen(keys.secretKey, {0}), GLDimensionError);
    EXPECT_THROW((void)scheme.EvalRowRotateKeyGen(keys.secretKey, {4}), GLDimensionError);

    const auto partialKey = scheme.EvalRowRotateKeyGen(keys.secretKey, {1});
    EXPECT_THROW((void)scheme.EvalRowRotate(encryptedA, 2, partialKey),
                 GLMissingEvaluationKeyError);
    EXPECT_THROW((void)scheme.EvalRowRotate(encryptedA, 4, partialKey), GLDimensionError);

    const auto otherKeys = scheme.KeyGen();
    const auto wrongKey = scheme.EvalRowRotateKeyGen(otherKeys.secretKey, {1});
    EXPECT_THROW((void)scheme.EvalRowRotate(encryptedA, 1, wrongKey), GLKeyMismatchError);

    GLSchemelet foreign(OpsParameters(4, 1024));
    const auto foreignKeys = foreign.KeyGen();
    const auto foreignRotationKey = foreign.EvalRowRotateKeyGen(foreignKeys.secretKey, {1});
    EXPECT_THROW((void)scheme.EvalRowRotate(encryptedA, 1, foreignRotationKey),
                 GLContextMismatchError);
    EXPECT_THROW((void)scheme.EvalRowRotateKeyGen(foreignKeys.secretKey, {1}),
                 GLKeyContextMismatchError);
}

TEST(GLOps, ColumnRotateSubAndNegateNegatives) {
    GLSchemelet scheme(OpsParameters(4, 512));
    GLSchemelet other(OpsParameters(4, 1024));
    const auto keys      = scheme.KeyGen();
    const auto otherKeys = other.KeyGen();
    const auto encryptedA = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));
    const auto otherB = other.Encrypt(otherKeys.publicKey, other.Encode(GLPlaintext(4, PinnedB())));

    EXPECT_THROW((void)scheme.EvalColumnRotate(encryptedA, 4), GLDimensionError);
    EXPECT_THROW((void)scheme.EvalColumnRotate(otherB, 1), GLContextMismatchError);
    EXPECT_THROW((void)scheme.Negate(otherB), GLContextMismatchError);
    EXPECT_THROW((void)scheme.Sub(encryptedA, otherB), GLContextMismatchError);

    const auto secondKeys = scheme.KeyGen();
    const auto secondB = scheme.Encrypt(secondKeys.publicKey, scheme.Encode(GLPlaintext(4, PinnedB())));
    EXPECT_THROW((void)scheme.Sub(encryptedA, secondB), GLKeyMismatchError);

    GLSchemelet scheme8(OpsParameters(8, 512));
    const auto keys8 = scheme8.KeyGen();
    const auto encrypted8 = scheme8.Encrypt(
        keys8.publicKey, scheme8.Encode(GLPlaintext(8, DeterministicN8())));
    EXPECT_THROW((void)scheme.Negate(encrypted8), GLDimensionError);
    EXPECT_THROW((void)scheme.EvalColumnRotate(encrypted8, 1), GLDimensionError);
}

TEST(GLOps, ConjugateAndTransposeNegatives) {
    GLSchemelet transport(OpsParameters(4, 512));
    const auto transportKeys = transport.KeyGen();
    const auto transportA = transport.Encrypt(
        transportKeys.publicKey, transport.Encode(GLPlaintext(4, PinnedA())));

    // Native-named transpose keeps rejecting transport rings on both sides.
    EXPECT_THROW((void)transport.EvalTransposeNativeKeyGen(transportKeys.secretKey),
                 GLNativeModeError);

    GLSchemelet scheme(OpsParameters(4, 8));
    const auto keys = scheme.KeyGen();
    const auto secondKeys = scheme.KeyGen();
    const auto transposeKey    = scheme.EvalTransposeNativeKeyGen(keys.secretKey);
    const auto wrongTranspose  = scheme.EvalTransposeNativeKeyGen(secondKeys.secretKey);
    const auto conjugationKey  = scheme.EvalConjugateKeyGen(keys.secretKey);
    const auto wrongConjugation = scheme.EvalConjugateKeyGen(secondKeys.secretKey);
    const auto encryptedA = scheme.Encrypt(keys.publicKey, scheme.Encode(GLPlaintext(4, PinnedA())));

    EXPECT_THROW((void)transport.EvalTransposeNative(transportA, transposeKey), GLNativeModeError);
    EXPECT_THROW((void)scheme.EvalTransposeNative(encryptedA, wrongTranspose), GLKeyMismatchError);
    EXPECT_THROW((void)scheme.EvalConjugate(encryptedA, wrongConjugation), GLKeyMismatchError);

    GLSchemelet foreignExact(OpsParameters(4, 8, 2));
    ASSERT_NE(foreignExact.GetCryptoContext().get(), scheme.GetCryptoContext().get());
    const auto foreignKeys = foreignExact.KeyGen();
    const auto foreignTranspose   = foreignExact.EvalTransposeNativeKeyGen(foreignKeys.secretKey);
    const auto foreignConjugation = foreignExact.EvalConjugateKeyGen(foreignKeys.secretKey);
    EXPECT_THROW((void)scheme.EvalTransposeNative(encryptedA, foreignTranspose),
                 GLContextMismatchError);
    EXPECT_THROW((void)scheme.EvalConjugate(encryptedA, foreignConjugation),
                 GLContextMismatchError);
    EXPECT_THROW((void)scheme.EvalTransposeNativeKeyGen(foreignKeys.secretKey),
                 GLKeyContextMismatchError);
    EXPECT_THROW((void)scheme.EvalConjugateKeyGen(foreignKeys.secretKey),
                 GLKeyContextMismatchError);
}

}  // namespace
}  // namespace lbcrypto
