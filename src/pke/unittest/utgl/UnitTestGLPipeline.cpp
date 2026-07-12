//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

// Full-pipeline exact-ring GL end-to-end conformance: encrypted matmul ->
// Hadamard -> row/column rotation -> conjugation -> native transpose ->
// SHIP RefreshOnly (hybrid masked-column selection) -> native plaintext
// matmul, decrypted against the clear oracle of the identical pipeline.
// n=4/8, HEStd_NotSet toy dimensions only; no security claim.

#include "scheme/gl/gl-ship.h"

#include "gtest/gtest.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

namespace lbcrypto {
namespace {

using Matrix = std::vector<std::complex<double>>;

GLParameters PipelineParameters(std::size_t n, uint32_t multiplicativeDepth) {
    GLParameters parameters;
    parameters.dimension = n;
    parameters.multiplicativeDepth = multiplicativeDepth;
    parameters.scalingModSize = 40;
    parameters.firstModSize = 50;
    parameters.ringDimension = static_cast<uint32_t>(2 * n);
    parameters.securityLevel = HEStd_NotSet;
    parameters.scalingTechnique = FLEXIBLEAUTO;
    return parameters;
}

GLShipParameters HybridParameters(std::size_t n, std::size_t hammingWeight,
                                  std::size_t coarseBlockSize) {
    GLShipParameters parameters;
    parameters.dimension = n;
    parameters.gamma = 64.0;
    parameters.hammingWeight = hammingWeight;
    parameters.reservedLevels = 1;
    parameters.selection = GLShipSelection::HYBRID_MASKED_COLUMN;
    parameters.coarseBlockSize = coarseBlockSize;
    return parameters;
}

GLShipParameters DirectParameters(std::size_t n, std::size_t hammingWeight) {
    GLShipParameters parameters;
    parameters.dimension = n;
    parameters.gamma = 64.0;
    parameters.hammingWeight = hammingWeight;
    parameters.reservedLevels = 1;
    parameters.selection = GLShipSelection::DIRECT_COLUMN;
    return parameters;
}

std::vector<GLShipMonomial> PipelineSupport(std::size_t n) {
    if (n == 4) {
        return {{0, 1}, {2, -1}};
    }
    return {{0, 1}, {3, -1}, {6, 1}};
}

// --- deterministic pipeline matrices (entries scaled so the pre-refresh ----
// --- Gaussian coefficient lanes stay well inside the SHIP |.| <= 1 bound) --

int64_t NonNegativeMod(int64_t value, int64_t modulus) {
    return ((value % modulus) + modulus) % modulus;
}

Matrix MatrixU(std::size_t n) {
    Matrix values(n * n);
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            const auto jj = static_cast<int64_t>(j);
            const auto kk = static_cast<int64_t>(k);
            values[j * n + k] = {
                static_cast<double>(NonNegativeMod(jj + 2 * kk, 7) - 3) / 4.0,
                static_cast<double>(NonNegativeMod(3 * jj - kk, 5) - 2) / 4.0};
        }
    }
    return values;
}

Matrix MatrixV(std::size_t n) {
    Matrix values(n * n);
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            const auto jj = static_cast<int64_t>(j);
            const auto kk = static_cast<int64_t>(k);
            values[j * n + k] = {
                static_cast<double>(NonNegativeMod(2 * jj + kk, 5) - 2) / 4.0,
                static_cast<double>(NonNegativeMod(jj + 3 * kk, 7) - 3) / 8.0};
        }
    }
    return values;
}

Matrix MatrixW(std::size_t n) {
    Matrix values(n * n);
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            const auto jj = static_cast<int64_t>(j);
            const auto kk = static_cast<int64_t>(k);
            values[j * n + k] = {
                static_cast<double>(NonNegativeMod(jj + kk, 3) - 1) / 2.0,
                static_cast<double>(NonNegativeMod(2 * jj - kk, 3) - 1) / 4.0};
        }
    }
    return values;
}

Matrix MatrixP(std::size_t n) {
    Matrix values(n * n);
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            const auto jj = static_cast<int64_t>(j);
            const auto kk = static_cast<int64_t>(k);
            values[j * n + k] = {
                static_cast<double>(NonNegativeMod(jj + 2 * kk, 5) - 2) / 8.0,
                static_cast<double>(NonNegativeMod(3 * jj + kk, 3) - 1) / 8.0};
        }
    }
    return values;
}

Matrix IdentityMatrix(std::size_t n) {
    Matrix values(n * n, {0.0, 0.0});
    for (std::size_t index = 0; index < n; ++index) {
        values[index * n + index] = {1.0, 0.0};
    }
    return values;
}

// --- clear oracles (independent triple loops; no encrypted code reused) ----

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

Matrix OracleConjugate(const Matrix& m) {
    Matrix result(m.size());
    std::transform(m.begin(), m.end(), result.begin(),
                   [](const std::complex<double>& v) { return std::conj(v); });
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

// Clear pipeline: (U*V) o (W*I) -> RowRotate(1) -> ColRotate(1) -> conj ->
// transpose.  Returns the pre-refresh logical matrix.
Matrix ClearPreRefresh(const Matrix& u, const Matrix& v, const Matrix& w, std::size_t n) {
    const auto product = OracleMatMul(u, v, n);
    const auto hadamard = OracleHadamard(product, w);
    const auto rowRotated = OracleRowRotate(hadamard, n, 1);
    const auto columnRotated = OracleColumnRotate(rowRotated, n, 1);
    return OracleTranspose(OracleConjugate(columnRotated), n);
}

// Contract-formula Gaussian coefficient lanes of every row of the logical
// matrix: c_{y,j} = (1/n) sum_k M[j,k] zeta_k^{-y},
// d_{x,y} = (1/n) sum_j c_{y,j} r_j^{-x}, zeta_k = r_k = zeta^{5^k}.
double MaxCoefficientLaneMagnitude(const Matrix& m, std::size_t n) {
    const long double pi = std::acos(-1.0L);
    const auto order = 4 * n;
    std::vector<std::complex<long double>> roots(n);
    std::size_t exponent = 1;
    for (std::size_t slot = 0; slot < n; ++slot) {
        roots[slot] = std::polar(
            1.0L, 2.0L * pi * static_cast<long double>(exponent) /
                      static_cast<long double>(order));
        exponent = (exponent * 5) % order;
    }
    double worst = 0.0;
    for (std::size_t y = 0; y < n; ++y) {
        std::vector<std::complex<long double>> slots(n, {0.0L, 0.0L});
        for (std::size_t j = 0; j < n; ++j) {
            for (std::size_t k = 0; k < n; ++k) {
                slots[j] += std::complex<long double>(m[j * n + k].real(),
                                                      m[j * n + k].imag()) *
                            std::pow(roots[k], -static_cast<int>(y));
            }
            slots[j] /= static_cast<long double>(n);
        }
        for (std::size_t x = 0; x < n; ++x) {
            std::complex<long double> coefficient(0.0L, 0.0L);
            for (std::size_t j = 0; j < n; ++j) {
                coefficient += slots[j] * std::pow(roots[j], -static_cast<int>(x));
            }
            coefficient /= static_cast<long double>(n);
            worst = std::max(worst, static_cast<double>(std::abs(coefficient.real())));
            worst = std::max(worst, static_cast<double>(std::abs(coefficient.imag())));
        }
    }
    return worst;
}

double MaxError(const Matrix& actual, const Matrix& expected) {
    EXPECT_EQ(actual.size(), expected.size());
    double error = 0.0;
    for (std::size_t index = 0; index < actual.size(); ++index) {
        error = std::max(error, std::abs(actual[index] - expected[index]));
    }
    return error;
}

std::size_t TowerCount(const Ciphertext<DCRTPoly>& ciphertext) {
    return ciphertext && !ciphertext->GetElements().empty()
               ? ciphertext->GetElements().front().GetNumOfElements()
               : 0;
}

GLCiphertext DepleteToTwoTowers(const GLSchemelet& gl, const GLCiphertext& input) {
    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(input.GetRows().size());
    for (const auto& source : input.GetRows()) {
        auto row = source->Clone();
        const auto towers = TowerCount(row);
        if (towers < 2) {
            throw GLShipStateError("pipeline test input has fewer than two towers");
        }
        if (towers > 2) {
            gl.GetCryptoContext()->GetScheme()->LevelReduceInternalInPlace(row,
                                                                           towers - 2);
        }
        rows.push_back(std::move(row));
    }
    return GLCiphertext(input.GetGeometry(), input.GetCryptoContext(), std::move(rows));
}

// Encrypted pipeline prefix: Encrypt(U), Encrypt(V) -> EvalMatMulNative ->
// EvalHadamard with Encrypt(W) (aligned by one exact identity matmul, the
// same one-level consumption as the ct-ct product) -> EvalRowRotate(1) ->
// EvalColumnRotate(1) -> EvalConjugate -> EvalTransposeNative, then a
// test-side depletion to two towers standing in for the surrounding
// computation having spent the budget.
GLCiphertext BuildDepletedPreRefresh(const GLSchemelet& gl, const KeyPair<DCRTPoly>& keys,
                                     const GLNativeEvalKey& nativeKey,
                                     const GLRotationEvalKey& rotationKey,
                                     const GLConjugationEvalKey& conjugationKey,
                                     const GLTransposeEvalKey& transposeKey,
                                     const Matrix& u, const Matrix& v, const Matrix& w) {
    const auto n = gl.GetGeometry().GetDimension();
    const auto encryptedU = gl.Encrypt(keys.publicKey, gl.Encode(GLPlaintext(n, u)));
    const auto encryptedV = gl.Encrypt(keys.publicKey, gl.Encode(GLPlaintext(n, v)));
    const auto encryptedW = gl.Encrypt(keys.publicKey, gl.Encode(GLPlaintext(n, w)));

    const auto product = gl.EvalMatMulNative(encryptedU, encryptedV, nativeKey);
    const auto alignedW = gl.EvalMatMulPlainNative(encryptedW, GLPlaintext(n, IdentityMatrix(n)));
    const auto hadamard = gl.EvalHadamard(product, alignedW);
    const auto rowRotated = gl.EvalRowRotate(hadamard, 1, rotationKey);
    const auto columnRotated = gl.EvalColumnRotate(rowRotated, 1);
    const auto conjugated = gl.EvalConjugate(columnRotated, conjugationKey);
    const auto transposed = gl.EvalTransposeNative(conjugated, transposeKey);
    return DepleteToTwoTowers(gl, transposed);
}

void RunHybridPipeline(std::size_t n, std::size_t theta, double refreshTolerance,
                       double finalTolerance) {
    const auto support = PipelineSupport(n);
    const auto hybridParameters = HybridParameters(n, support.size(), theta);
    const auto depth = hybridParameters.RequiredMultiplicativeDepth() + 3;
    GLSchemelet gl(PipelineParameters(n, depth));
    GLShipSchemelet ship(gl, hybridParameters);
    const auto keys = gl.KeyGen();

    const auto nativeKey = gl.EvalMatMulNativeKeyGen(keys.secretKey);
    gl.EvalHadamardKeyGen(keys.secretKey);
    const auto rotationKey = gl.EvalRowRotateKeyGen(keys.secretKey, {1});
    const auto conjugationKey = gl.EvalConjugateKeyGen(keys.secretKey);
    const auto transposeKey = gl.EvalTransposeNativeKeyGen(keys.secretKey);
    auto client = ship.KeyGen(keys, support);

    // Clear pipeline first: the SHIP sine range is a declared input contract,
    // so the independently computed pre-refresh coefficient lanes must fit
    // |Re|, |Im| <= 1 with margin BEFORE anything encrypted runs.
    const auto u = MatrixU(n);
    const auto v = MatrixV(n);
    const auto w = MatrixW(n);
    const auto p = MatrixP(n);
    const auto clearPreRefresh = ClearPreRefresh(u, v, w, n);
    const auto clearFinal = OracleMatMul(clearPreRefresh, p, n);
    ASSERT_LT(MaxCoefficientLaneMagnitude(clearPreRefresh, n), 0.9);

    const auto depleted = BuildDepletedPreRefresh(gl, keys, nativeKey, rotationKey,
                                                  conjugationKey, transposeKey, u, v, w);
    ASSERT_EQ(TowerCount(depleted.GetRows().front()), 2u);
    // Mid-pipeline client-side sanity: the prefix agrees with its oracle.
    EXPECT_LT(MaxError(gl.Decrypt(keys.secretKey, depleted).GetValues(), clearPreRefresh),
              1e-2);

    // RefreshOnly owns every evaluation key it needs; ambient registries are
    // cleared so that ownership is load-bearing.
    CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys(keys.secretKey->GetKeyTag());
    CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(keys.secretKey->GetKeyTag());

    const auto refreshed = ship.RefreshOnly(depleted, client.GetEvaluationKey());
    ASSERT_EQ(refreshed.GetRows().size(), n);
    EXPECT_EQ(refreshed.GetKeyTag(), keys.secretKey->GetKeyTag());
    // The refreshed aggregate carries MORE live modulus than its pre-refresh
    // input, at the exact hybrid budget level.
    EXPECT_GT(TowerCount(refreshed.GetRows().front()),
              TowerCount(depleted.GetRows().front()));
    const auto expectedRefreshedLevel =
        hybridParameters.RequiredMultiplicativeDepth() - hybridParameters.reservedLevels;
    for (const auto& row : refreshed.GetRows()) {
        ASSERT_TRUE(row);
        EXPECT_EQ(row->NumberCiphertextElements(), 2u);
        EXPECT_EQ(row->GetLevel(), expectedRefreshedLevel);
        EXPECT_EQ(row->GetNoiseScaleDeg(), 1u);
        EXPECT_EQ(row->GetEncodingType(), CKKS_PACKED_ENCODING);
        DCRTPoly zero(row->GetElements()[1].GetParams(), Format::EVALUATION, true);
        EXPECT_NE(row->GetElements()[1], zero);
    }
    const auto refreshError =
        MaxError(gl.Decrypt(keys.secretKey, refreshed).GetValues(), clearPreRefresh);
    EXPECT_LT(refreshError, refreshTolerance);

    // Post-refresh native plaintext matmul consumes exactly one level.
    const auto finalProduct = gl.EvalMatMulPlainNative(refreshed, GLPlaintext(n, p));
    EXPECT_EQ(finalProduct.GetRows().front()->GetLevel(), expectedRefreshedLevel + 1);
    EXPECT_EQ(TowerCount(finalProduct.GetRows().front()),
              TowerCount(refreshed.GetRows().front()) - 1);
    const auto finalError =
        MaxError(gl.Decrypt(keys.secretKey, finalProduct).GetValues(), clearFinal);
    EXPECT_LT(finalError, finalTolerance);
    std::cout << "[ pipeline n=" << n << " ] refresh err " << refreshError << " (tol "
              << refreshTolerance << "), final err " << finalError << " (tol "
              << finalTolerance << ")" << std::endl;
    // The reserved post-refresh budget is real: one more multiplicative stage
    // still succeeds on the refreshed lane.
    EXPECT_NO_THROW((void)gl.EvalMatMulPlainNative(finalProduct, GLPlaintext(n, p)));

    // Negative: the same pipeline WITHOUT RefreshOnly exhausts its levels.
    // The unrefreshed final matmul burns the last usable level down to the
    // one-tower floor, where the follow-on stage the refreshed lane just
    // performed throws, and a refresh is no longer possible either -- the
    // bootstrap is load-bearing, not decorative.
    const auto unrefreshed = gl.EvalMatMulPlainNative(depleted, GLPlaintext(n, p));
    ASSERT_EQ(TowerCount(unrefreshed.GetRows().front()), 1u);
    EXPECT_ANY_THROW((void)gl.EvalMatMulPlainNative(unrefreshed, GLPlaintext(n, p)));
    EXPECT_THROW((void)ship.RefreshOnly(unrefreshed, client.GetEvaluationKey()),
                 GLShipStateError);
}

}  // namespace

TEST(GLPipeline, FullPipelineWithHybridRefreshN4) {
    RunHybridPipeline(4, 2, 4e-2, 6e-2);
}

TEST(GLPipeline, FullPipelineWithHybridRefreshN8) {
    RunHybridPipeline(8, 4, 1e-1, 1.5e-1);
}

TEST(GLPipeline, HybridAndDirectRefreshVariantsAgreeN4) {
    constexpr std::size_t n = 4;
    const auto support = PipelineSupport(n);
    const auto hybridParameters = HybridParameters(n, support.size(), 2);
    const auto depth = hybridParameters.RequiredMultiplicativeDepth() + 3;
    GLSchemelet gl(PipelineParameters(n, depth));
    GLShipSchemelet hybridShip(gl, hybridParameters);
    GLShipSchemelet directShip(gl, DirectParameters(n, support.size()));
    const auto keys = gl.KeyGen();

    const auto nativeKey = gl.EvalMatMulNativeKeyGen(keys.secretKey);
    gl.EvalHadamardKeyGen(keys.secretKey);
    const auto rotationKey = gl.EvalRowRotateKeyGen(keys.secretKey, {1});
    const auto conjugationKey = gl.EvalConjugateKeyGen(keys.secretKey);
    const auto transposeKey = gl.EvalTransposeNativeKeyGen(keys.secretKey);
    auto hybridClient = hybridShip.KeyGen(keys, support);
    auto directClient = directShip.KeyGen(keys, support);

    const auto u = MatrixU(n);
    const auto v = MatrixV(n);
    const auto w = MatrixW(n);
    const auto clearPreRefresh = ClearPreRefresh(u, v, w, n);
    ASSERT_LT(MaxCoefficientLaneMagnitude(clearPreRefresh, n), 0.9);

    // One shared encrypted prefix; the pre-refresh aggregate is under the
    // primary key, so the SAME input legally feeds both selection modes.
    const auto depleted = BuildDepletedPreRefresh(gl, keys, nativeKey, rotationKey,
                                                  conjugationKey, transposeKey, u, v, w);
    CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys(keys.secretKey->GetKeyTag());
    CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(keys.secretKey->GetKeyTag());

    const auto hybridRefreshed =
        hybridShip.RefreshOnly(depleted, hybridClient.GetEvaluationKey());
    const auto directRefreshed =
        directShip.RefreshOnly(depleted, directClient.GetEvaluationKey());
    const auto hybridValues = gl.Decrypt(keys.secretKey, hybridRefreshed).GetValues();
    const auto directValues = gl.Decrypt(keys.secretKey, directRefreshed).GetValues();
    EXPECT_LT(MaxError(hybridValues, clearPreRefresh), 4e-2);
    EXPECT_LT(MaxError(directValues, clearPreRefresh), 2e-2);
    const auto crossModeError = MaxError(hybridValues, directValues);
    EXPECT_LT(crossModeError, 6e-2);
    std::cout << "[ pipeline n=4 variants ] cross-mode err " << crossModeError
              << " (tol 6e-2)" << std::endl;
}

}  // namespace lbcrypto
