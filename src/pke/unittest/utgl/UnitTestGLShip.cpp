//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "scheme/gl/gl-ship.h"

#include "gtest/gtest.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

namespace lbcrypto {

class GLShipTestAccess {
public:
    static GLShipEvaluationKey SwapSelectors(const GLShipEvaluationKey& source,
                                             std::size_t first, std::size_t second) {
        auto result = source;
        if (first >= result.m_selectors.size() || second >= result.m_selectors.size()) {
            throw GLShipEvaluationKeyError("test selector index is out of range");
        }
        std::swap(result.m_selectors[first], result.m_selectors[second]);
        return result;
    }

    static GLShipEvaluationKey WithoutRelinearizationKey(
        const GLShipEvaluationKey& source) {
        auto result = source;
        result.m_relinearizationKeys.clear();
        return result;
    }

    static GLShipEvaluationKey WithRelinearizationKeyFrom(
        const GLShipEvaluationKey& source, const GLShipEvaluationKey& donor) {
        auto result = source;
        result.m_relinearizationKeys = donor.m_relinearizationKeys;
        return result;
    }

    static GLShipEvaluationKey WithoutSelector(const GLShipEvaluationKey& source) {
        auto result = source;
        result.m_selectors.pop_back();
        return result;
    }

    static GLShipEvaluationKey WithSelectorFrom(
        const GLShipEvaluationKey& source, const GLShipEvaluationKey& donor) {
        auto result = source;
        result.m_selectors.front() = donor.m_selectors.front();
        return result;
    }

    static GLShipEvaluationKey WithSelectorScalingFactor(
        const GLShipEvaluationKey& source, double scalingFactor) {
        auto result = source;
        result.m_selectors.front() = result.m_selectors.front()->Clone();
        result.m_selectors.front()->SetScalingFactor(scalingFactor);
        return result;
    }

    static GLShipEvaluationKey WithoutFineSelector(const GLShipEvaluationKey& source) {
        auto result = source;
        if (result.m_fineSelectors.empty()) {
            throw GLShipEvaluationKeyError("test fine-selector bank is already empty");
        }
        result.m_fineSelectors.pop_back();
        return result;
    }

    static GLShipEvaluationKey WithFineSelector(const GLShipEvaluationKey& source,
                                                std::size_t index,
                                                Ciphertext<DCRTPoly> replacement) {
        auto result = source;
        if (index >= result.m_fineSelectors.size()) {
            throw GLShipEvaluationKeyError("test fine-selector index is out of range");
        }
        result.m_fineSelectors[index] = std::move(replacement);
        return result;
    }

    static GLShipEvaluationKey WithAppendedFineSelector(const GLShipEvaluationKey& source,
                                                        Ciphertext<DCRTPoly> extra) {
        auto result = source;
        result.m_fineSelectors.push_back(std::move(extra));
        return result;
    }

    static GLShipEvaluationKey WithFineSelectorScalingFactor(
        const GLShipEvaluationKey& source, double scalingFactor) {
        auto result = source;
        if (result.m_fineSelectors.empty()) {
            throw GLShipEvaluationKeyError("test fine-selector bank is already empty");
        }
        result.m_fineSelectors.front() = result.m_fineSelectors.front()->Clone();
        result.m_fineSelectors.front()->SetScalingFactor(scalingFactor);
        return result;
    }

    static const std::vector<Ciphertext<DCRTPoly>>& Selectors(
        const GLShipEvaluationKey& key) {
        return key.m_selectors;
    }

    static const std::vector<Ciphertext<DCRTPoly>>& FineSelectors(
        const GLShipEvaluationKey& key) {
        return key.m_fineSelectors;
    }

    static GLShipEvaluationKey WithoutConjugationKey(
        const GLShipEvaluationKey& source) {
        auto result = source;
        result.m_conjugationKeys.reset();
        return result;
    }

    static GLShipEvaluationKey WithoutBottomSwitch(
        const GLShipEvaluationKey& source) {
        auto result = source;
        result.m_bottomPrimaryToSparseKey.reset();
        return result;
    }

    static GLShipEvaluationKey WithoutXForwardKey(
        const GLShipEvaluationKey& source) {
        auto result = source;
        if (result.m_xForwardKeys && !result.m_xForwardKeys->empty()) {
            result.m_xForwardKeys =
                std::make_shared<std::map<uint32_t, EvalKey<DCRTPoly>>>(
                    *result.m_xForwardKeys);
            result.m_xForwardKeys->erase(result.m_xForwardKeys->begin());
        }
        return result;
    }

    static GLShipEvaluationKey WithSparseTag(const GLShipEvaluationKey& source,
                                             std::string sparseTag) {
        auto result = source;
        result.m_sparseKeyTag = std::move(sparseTag);
        return result;
    }

    static GLShipLowSliceCiphertext WithRepresentation(
        const GLShipLowSliceCiphertext& source, GLShipRepresentation representation) {
        auto result = source;
        result.m_representation = representation;
        return result;
    }

    static GLShipLowSliceCiphertext WithTopLevelSelector(
        const GLShipLowSliceCiphertext& source, const GLShipEvaluationKey& key) {
        return GLShipLowSliceCiphertext(source.m_dimension, source.m_q0, source.m_context,
                                        key.m_selectors.front()->Clone());
    }

    static GLShipLowSliceCiphertext WithScalingFactor(
        const GLShipLowSliceCiphertext& source, double scalingFactor) {
        auto ciphertext = source.m_ciphertext->Clone();
        ciphertext->SetScalingFactor(scalingFactor);
        return GLShipLowSliceCiphertext(source.m_dimension, source.m_q0, source.m_context,
                                        std::move(ciphertext));
    }

    static GLShipLowSliceCiphertext NormalizeAndSwitchRow(
        const GLShipSchemelet& ship, const Ciphertext<DCRTPoly>& input,
        const GLShipEvaluationKey& key) {
        return ship.NormalizeAndSwitchRow(input, key, 0);
    }

    static const PrivateKey<DCRTPoly>& SparseSecret(
        const GLShipClientMaterial& client) {
        return client.m_sparseSecretKey;
    }
};

namespace {

GLParameters ExactParameters(std::size_t n, uint32_t multiplicativeDepth) {
    GLParameters parameters;
    parameters.dimension = n;
    parameters.multiplicativeDepth = multiplicativeDepth;
    parameters.scalingModSize = 40;
    parameters.firstModSize = 50;
    parameters.ringDimension = 2 * n;
    parameters.securityLevel = HEStd_NotSet;
    parameters.scalingTechnique = FLEXIBLEAUTO;
    return parameters;
}

GLShipParameters ShipParameters(std::size_t n, std::size_t hammingWeight,
                                uint32_t reservedLevels = 1) {
    GLShipParameters parameters;
    parameters.dimension = n;
    parameters.gamma = 64.0;
    parameters.hammingWeight = hammingWeight;
    parameters.reservedLevels = reservedLevels;
    parameters.selection = GLShipSelection::DIRECT_COLUMN;
    return parameters;
}

std::vector<std::complex<double>> DecodeSlots(
    const CryptoContext<DCRTPoly>& context, const PrivateKey<DCRTPoly>& secretKey,
    const Ciphertext<DCRTPoly>& ciphertext, std::size_t length) {
    Plaintext plaintext;
    const auto result = context->Decrypt(secretKey, ciphertext, &plaintext);
    if (!result.isValid || !plaintext) {
        throw GLShipStateError("test output decryption failed");
    }
    plaintext->SetLength(length);
    const auto values = plaintext->GetCKKSPackedValue();
    return std::vector<std::complex<double>>(values.begin(), values.begin() + length);
}

int64_t CenteredCoefficient(const NativeInteger& value, uint64_t modulus) {
    const auto raw = static_cast<uint64_t>(value.ConvertToInt());
    return raw > modulus / 2 ? -static_cast<int64_t>(modulus - raw)
                             : static_cast<int64_t>(raw);
}

std::vector<std::complex<double>> SineOracle(
    const std::vector<std::complex<double>>& input, uint64_t q0, double gamma) {
    const long double pi = std::acos(-1.0L);
    const long double multiplier = static_cast<long double>(q0) /
                                   static_cast<long double>(gamma);
    std::vector<std::complex<double>> output(input.size());
    for (std::size_t index = 0; index < input.size(); ++index) {
        const auto real = static_cast<int64_t>(
            std::llround(multiplier * static_cast<long double>(input[index].real())));
        const auto imag = static_cast<int64_t>(
            std::llround(multiplier * static_cast<long double>(input[index].imag())));
        const auto realValue = static_cast<long double>(gamma) / (2.0L * pi) *
                               std::sin(2.0L * pi * static_cast<long double>(real) /
                                        static_cast<long double>(q0));
        const auto imagValue = static_cast<long double>(gamma) / (2.0L * pi) *
                               std::sin(2.0L * pi * static_cast<long double>(imag) /
                                        static_cast<long double>(q0));
        output[index] = {static_cast<double>(realValue), static_cast<double>(imagValue)};
    }
    return output;
}

double MaxError(const std::vector<std::complex<double>>& actual,
                const std::vector<std::complex<double>>& expected) {
    if (actual.size() != expected.size()) {
        throw GLDimensionError("test vectors have mismatched sizes");
    }
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

GLCiphertext DepleteToTwoTowers(const GLCiphertext& input) {
    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(input.GetRows().size());
    for (const auto& source : input.GetRows()) {
        auto row = source->Clone();
        const auto towers = TowerCount(row);
        if (towers < 2) {
            throw GLShipStateError("test input has fewer than two towers");
        }
        if (towers > 2) {
            input.GetCryptoContext()->GetScheme()->LevelReduceInternalInPlace(
                row, towers - 2);
        }
        rows.push_back(std::move(row));
    }
    return GLCiphertext(input.GetGeometry(), input.GetCryptoContext(), std::move(rows));
}

std::vector<std::complex<double>> RefreshMatrix(std::size_t n) {
    std::vector<std::complex<double>> result(n * n);
    for (std::size_t row = 0; row < n; ++row) {
        for (std::size_t column = 0; column < n; ++column) {
            const double real =
                (static_cast<double>(2 * row) - static_cast<double>(column) + 1.0) / 64.0;
            const int imagIndex = static_cast<int>((row + 2 * column) % 5) - 2;
            const double imag = static_cast<double>(imagIndex) / 128.0;
            result[row * n + column] = {real, imag};
        }
    }
    return result;
}

std::vector<std::complex<double>> ScaledMatrix(
    const std::vector<std::complex<double>>& input, double factor) {
    auto result = input;
    for (auto& value : result) {
        value *= factor;
    }
    return result;
}

bool NativeElementsDiffer(const Ciphertext<DCRTPoly>& lhs,
                          const Ciphertext<DCRTPoly>& rhs) {
    if (!lhs || !rhs || lhs->GetElements().size() != rhs->GetElements().size()) {
        return true;
    }
    for (std::size_t index = 0; index < lhs->GetElements().size(); ++index) {
        if (lhs->GetElements()[index] != rhs->GetElements()[index]) {
            return true;
        }
    }
    return false;
}

std::size_t SelectorIndex(std::size_t n, std::size_t ordinal,
                          std::size_t alpha, int8_t sign) {
    return (ordinal * n + alpha) * 2 + (sign == -1 ? 0 : 1);
}

// ---------------------------------------------------------------------------
// Hybrid masked-column helpers (design lane A3; both ports pin these).
// ---------------------------------------------------------------------------

GLShipParameters HybridShipParameters(std::size_t n, std::size_t hammingWeight,
                                      std::size_t coarseBlockSize,
                                      uint32_t reservedLevels = 1,
                                      std::vector<GLShipCoarseWindow> windows = {}) {
    GLShipParameters parameters;
    parameters.dimension = n;
    parameters.gamma = 64.0;
    parameters.hammingWeight = hammingWeight;
    parameters.reservedLevels = reservedLevels;
    parameters.selection = GLShipSelection::HYBRID_MASKED_COLUMN;
    parameters.coarseBlockSize = coarseBlockSize;
    parameters.coarseWindows = std::move(windows);
    return parameters;
}

using GaussianVector = std::vector<GLShipGaussianInteger>;
using ComplexVector = std::vector<std::complex<double>>;

GaussianVector MultiplyByMinusI(const GaussianVector& input) {
    GaussianVector result;
    result.reserve(input.size());
    for (const auto& value : input) {
        result.emplace_back(value.imag(), -value.real());
    }
    return result;
}

std::vector<int64_t> RealLane(const GaussianVector& input) {
    std::vector<int64_t> result;
    result.reserve(input.size());
    for (const auto& value : input) {
        result.push_back(value.real());
    }
    return result;
}

// Direct-column factor g^{(b)}_{t,alpha,sigma,k} = omega^{[A^{(b)} sigma T^alpha]_k}.
ComplexVector DirectFactor(const GaussianVector& branchA, uint32_t alpha, int8_t sign,
                           uint64_t q0) {
    return GLShipAlgebra::RootVector(
        q0, RealLane(GLShipAlgebra::MultiplyMonomial(branchA, alpha, sign)));
}

struct ClearHybridResult {
    ComplexVector leaf;
    double laneAuditError{0.0};
};

// Clear mirror of the encrypted hybrid dataflow: coarse (block, sign) one-hot
// masked-column accumulation over both factor lanes, then the LSB-first fine
// digit chain with the three mask-fused pieces per digit and the final-digit
// V-lane skip.  Includes the mandatory per-digit lane audit: under the pinned
// LSB-first schedule the conj(u) wrap entries of V are provably never
// consumed by the U lane (Remark H3), so end-to-end results CANNOT gate the
// conjugation law -- this audit is its only clear gate.  breakConjugation
// deliberately replaces conj(Rot(U)) by Rot(U) for the negative control.
ClearHybridResult ClearHybridLeaf(const GaussianVector& branchA, uint32_t alphaLive,
                                  int8_t signLive, std::size_t theta, uint64_t q0,
                                  bool breakConjugation = false) {
    const auto n = branchA.size();
    std::size_t digits = 0;
    while ((std::size_t{1} << digits) < theta) {
        ++digits;
    }
    const auto alpha1 = alphaLive / static_cast<uint32_t>(theta);
    const auto alpha0 = alphaLive % static_cast<uint32_t>(theta);
    const auto blocks = n / theta;

    ComplexVector laneU(n, {0.0, 0.0});
    ComplexVector laneV(n, {0.0, 0.0});
    for (std::size_t block = 0; block < blocks; ++block) {
        for (const int8_t sign : {int8_t(-1), int8_t(1)}) {
            const double bit =
                block == alpha1 && sign == signLive ? 1.0 : 0.0;
            const auto shifted = GLShipAlgebra::MultiplyMonomial(
                branchA, static_cast<uint32_t>(theta * block), sign);
            const auto uTable = GLShipAlgebra::RootVector(q0, RealLane(shifted));
            const auto vTable = GLShipAlgebra::RootVector(
                q0, RealLane(GLShipAlgebra::MultiplyGaussianI(shifted)));
            for (std::size_t slot = 0; slot < n; ++slot) {
                laneU[slot] += bit * uTable[slot];
                laneV[slot] += bit * vTable[slot];
            }
        }
    }

    double audit = 0.0;
    const auto g0 = GLShipAlgebra::MultiplyMonomial(
        branchA, static_cast<uint32_t>(theta) * alpha1, signLive);
    for (std::size_t digit = 0; digit < digits; ++digit) {
        const std::size_t delta = std::size_t{1} << digit;
        const double bit = static_cast<double>((alpha0 >> digit) & 1u);
        const bool finalDigit = digit + 1 == digits;
        ComplexVector rotatedU(n);
        ComplexVector rotatedV(n);
        for (std::size_t slot = 0; slot < n; ++slot) {
            rotatedU[slot] = laneU[(slot + n - delta) % n];
            rotatedV[slot] = laneV[(slot + n - delta) % n];
        }
        ComplexVector nextU(n);
        for (std::size_t slot = 0; slot < n; ++slot) {
            const double maskHigh = slot >= delta ? 1.0 : 0.0;
            const double maskLow = 1.0 - maskHigh;
            nextU[slot] = bit * (maskHigh * rotatedU[slot] + maskLow * rotatedV[slot]) +
                          (1.0 - bit) * laneU[slot];
        }
        if (!finalDigit) {
            ComplexVector nextV(n);
            for (std::size_t slot = 0; slot < n; ++slot) {
                const double maskHigh = slot >= delta ? 1.0 : 0.0;
                const double maskLow = 1.0 - maskHigh;
                const auto wrapTerm =
                    breakConjugation ? rotatedU[slot] : std::conj(rotatedU[slot]);
                nextV[slot] = bit * (maskHigh * rotatedV[slot] + maskLow * wrapTerm) +
                              (1.0 - bit) * laneV[slot];
            }
            laneV = std::move(nextV);
        }
        laneU = std::move(nextU);

        // Per-digit lane invariant vs the exact partial product
        // G_d = X^{alpha0 mod 2^{d+1}} G_0.
        const uint32_t partial = alpha0 % (1u << (digit + 1));
        const auto gPartial =
            partial ? GLShipAlgebra::MultiplyMonomial(g0, partial, 1) : g0;
        audit = std::max(audit,
                         MaxError(laneU, GLShipAlgebra::RootVector(q0, RealLane(gPartial))));
        if (!finalDigit) {
            audit = std::max(
                audit,
                MaxError(laneV, GLShipAlgebra::RootVector(
                                    q0, RealLane(GLShipAlgebra::MultiplyGaussianI(gPartial)))));
        }
    }
    return {std::move(laneU), audit};
}

// Deterministic n=8 pinned clear vectors (design section 7.2, test 1):
// A8[k] = (k+1) + (3-k)i, B8[k] = (2k-5) + (-1)^k (k+2)i.
GaussianVector PinnedHybridA8() {
    GaussianVector values;
    values.reserve(8);
    for (int64_t k = 0; k < 8; ++k) {
        values.emplace_back(k + 1, 3 - k);
    }
    return values;
}

GaussianVector PinnedHybridB8() {
    GaussianVector values;
    values.reserve(8);
    for (int64_t k = 0; k < 8; ++k) {
        values.emplace_back(2 * k - 5, (k % 2 == 0 ? 1 : -1) * (k + 2));
    }
    return values;
}

}  // namespace

TEST(GLShip, GaussianWrapAndRootFactorOracles) {
    const std::vector<GLShipGaussianInteger> z = {
        {1, 2}, {-3, 1}, {2, -2}, {4, 0},
    };
    const std::vector<GLShipGaussianInteger> expectedWrapped = {
        {1, 3}, {-2, -2}, {0, -4}, {-1, -2},
    };
    EXPECT_EQ(GLShipAlgebra::MultiplyMonomial(z, 3, -1), expectedWrapped);

    const std::vector<GLShipGaussianInteger> a = {
        {1, 1}, {2, -1}, {-1, 2}, {0, -1},
    };
    const std::vector<GLShipGaussianInteger> b = {
        {3, -1}, {-2, 0}, {1, 1}, {2, -2},
    };
    const std::vector<GLShipMonomial> support = {{0, 1}, {2, -1}};
    const std::vector<GLShipGaussianInteger> expectedRelation = {
        {6, 1}, {-1, -1}, {-1, 2}, {0, -2},
    };
    const auto relation = GLShipAlgebra::DecryptionRelation(b, a, support);
    EXPECT_EQ(relation, expectedRelation);

    constexpr uint64_t q0 = 257;
    for (std::size_t branch = 0; branch < 2; ++branch) {
        std::vector<int64_t> directExponents;
        directExponents.reserve(relation.size());
        for (const auto& value : relation) {
            directExponents.push_back(branch == 0 ? value.real() : value.imag());
        }
        const auto directRoots = GLShipAlgebra::RootVector(q0, directExponents);

        std::vector<int64_t> baseExponents;
        baseExponents.reserve(b.size());
        for (const auto& value : b) {
            baseExponents.push_back(branch == 0 ? value.real() : value.imag());
        }
        auto factored = GLShipAlgebra::RootVector(q0, baseExponents);
        for (const auto& monomial : support) {
            const auto term = GLShipAlgebra::MultiplyMonomial(
                a, monomial.alpha, monomial.sign);
            std::vector<int64_t> exponents;
            exponents.reserve(term.size());
            for (const auto& value : term) {
                exponents.push_back(branch == 0 ? value.real() : value.imag());
            }
            const auto roots = GLShipAlgebra::RootVector(q0, exponents);
            for (std::size_t index = 0; index < factored.size(); ++index) {
                factored[index] *= roots[index];
            }
        }
        EXPECT_LT(MaxError(factored, directRoots), 1e-12);
    }
}

TEST(GLShip, CanonicalRowBackingPolynomialIsXInverseAndNormalizesAtQ0) {
    GLSchemelet gl(ExactParameters(4, 4));
    GLShipSchemelet ship(gl, ShipParameters(4, 2));
    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {2, -1}});

    const std::vector<std::complex<double>> coefficients = {
        {0.075, 0.0025}, {-0.016, -0.007}, {0.005, 0.0055}, {0.007, 0.016},
    };
    const long double pi = std::acos(-1.0L);
    std::vector<std::complex<double>> slots(4);
    std::size_t exponent = 1;
    for (std::size_t slot = 0; slot < 4; ++slot) {
        const auto root = std::polar(
            1.0L, 2.0L * pi * static_cast<long double>(exponent) / 16.0L);
        std::complex<long double> value(0.0L, 0.0L);
        for (std::size_t coefficient = 0; coefficient < 4; ++coefficient) {
            const auto& input = coefficients[coefficient];
            value += std::complex<long double>(input.real(), input.imag()) *
                     std::pow(root, static_cast<int>(coefficient));
        }
        slots[slot] = {static_cast<double>(value.real()),
                       static_cast<double>(value.imag())};
        exponent = exponent * 5 % 16;
    }

    auto plaintext = gl.GetCryptoContext()->MakeCKKSPackedPlaintext(slots, 1, 0, nullptr, 4);
    ASSERT_TRUE(plaintext);
    auto backing = plaintext->GetElement<DCRTPoly>();
    backing.SetFormat(Format::COEFFICIENT);
    const auto& topTower = backing.GetElementAtIndex(0);
    const auto topModulus = static_cast<uint64_t>(topTower.GetModulus().ConvertToInt());
    const auto sourceScale = plaintext->GetScalingFactor();
    double maxBackingError = 0.0;
    for (std::size_t coefficient = 0; coefficient < 4; ++coefficient) {
        const std::complex<double> actual(
            CenteredCoefficient(topTower[coefficient], topModulus) / sourceScale,
            CenteredCoefficient(topTower[coefficient + 4], topModulus) / sourceScale);
        maxBackingError = std::max(maxBackingError,
                                   std::abs(actual - coefficients[coefficient]));
    }
    EXPECT_LT(maxBackingError, 2e-12);

    const auto encrypted = gl.GetCryptoContext()->Encrypt(primary.publicKey, plaintext);
    const auto low = GLShipTestAccess::NormalizeAndSwitchRow(
        ship, encrypted, client.GetEvaluationKey());
    ASSERT_EQ(low.GetRepresentation(), GLShipRepresentation::POST_XINV_COEFFICIENT);
    ASSERT_EQ(TowerCount(low.GetNativeCiphertext()), 1U);
    auto relation = gl.GetCryptoContext()->GetScheme()->DecryptCore(
        low.GetNativeCiphertext(), GLShipTestAccess::SparseSecret(client));
    relation.SetFormat(Format::COEFFICIENT);
    const auto q0 = client.GetEvaluationKey().GetBottomModulus();
    const auto& lowTower = relation.GetElementAtIndex(0);
    double maxPhysicalError = 0.0;
    for (std::size_t coefficient = 0; coefficient < 4; ++coefficient) {
        const auto expectedReal = static_cast<double>(std::llround(
            static_cast<long double>(q0) * coefficients[coefficient].real() / 64.0L));
        const auto expectedImag = static_cast<double>(std::llround(
            static_cast<long double>(q0) * coefficients[coefficient].imag() / 64.0L));
        maxPhysicalError = std::max(
            maxPhysicalError,
            std::abs(static_cast<double>(CenteredCoefficient(lowTower[coefficient], q0)) -
                     expectedReal));
        maxPhysicalError = std::max(
            maxPhysicalError,
            std::abs(static_cast<double>(CenteredCoefficient(lowTower[coefficient + 4], q0)) -
                     expectedImag));
    }
    EXPECT_LT(maxPhysicalError, 2e3);
}

TEST(GLShip, ExactN4EncryptedHalfBootstrapAndPostOperation) {
    GLSchemelet gl(ExactParameters(4, 4));
    GLShipSchemelet ship(gl, ShipParameters(4, 2));
    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {2, -1}});

    const std::vector<std::complex<double>> coefficients = {
        {0.125, -0.375}, {-0.25, 0.25}, {0.375, 0.125}, {-0.5, -0.125},
    };
    const auto input = ship.EncryptLowSlice(client, coefficients);
    const auto secondInput = ship.EncryptLowSlice(client, coefficients);
    EXPECT_TRUE(NativeElementsDiffer(input.GetNativeCiphertext(),
                                     secondInput.GetNativeCiphertext()));
    ASSERT_EQ(input.GetNativeCiphertext()->NumberCiphertextElements(), 2U);
    EXPECT_EQ(TowerCount(input.GetNativeCiphertext()), 1U);
    EXPECT_EQ(input.GetRepresentation(), GLShipRepresentation::POST_XINV_COEFFICIENT);
    EXPECT_EQ(input.GetNativeCiphertext()->GetEncodingType(), INVALID_ENCODING);
    EXPECT_EQ(input.GetNativeCiphertext()->GetScalingFactor(), 1.0);
    EXPECT_EQ(input.GetNativeCiphertext()->GetScalingFactorInt(), NativeInteger(1));
    EXPECT_EQ(input.GetNativeCiphertext()->GetNoiseScaleDeg(), 1U);
    EXPECT_EQ(input.GetNativeCiphertext()->GetSlots(), 0U);

    const auto result = ship.EvalHalfBootstrap(input, client.GetEvaluationKey());
    ASSERT_TRUE(result.GetNativeCiphertext());
    EXPECT_EQ(result.GetRepresentation(), GLShipRepresentation::X_COEFFICIENT_SLOTS);
    EXPECT_EQ(result.GetNativeCiphertext()->NumberCiphertextElements(), 2U);
    EXPECT_EQ(result.GetKeyTag(), primary.secretKey->GetKeyTag());
    EXPECT_GT(TowerCount(result.GetNativeCiphertext()),
              TowerCount(input.GetNativeCiphertext()));
    DCRTPoly zeroA(result.GetNativeCiphertext()->GetElements()[1].GetParams(),
                   Format::EVALUATION, true);
    EXPECT_NE(result.GetNativeCiphertext()->GetElements()[1], zeroA);

    const auto decoded = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                     result.GetNativeCiphertext(), 4);
    const auto expected = SineOracle(coefficients,
                                     client.GetEvaluationKey().GetBottomModulus(), 64.0);
    EXPECT_LT(MaxError(decoded, expected), 2e-3);
    EXPECT_LT(MaxError(decoded, coefficients), 5e-3);

    std::vector<std::complex<double>> half(4, {0.5, 0.0});
    auto postPlaintext = gl.GetCryptoContext()->MakeCKKSPackedPlaintext(
        half, 1, result.GetNativeCiphertext()->GetLevel(), nullptr, 4);
    ASSERT_TRUE(postPlaintext);
    auto postProduct = gl.GetCryptoContext()->EvalMult(
        result.GetNativeCiphertext(), postPlaintext);
    ASSERT_TRUE(postProduct);
    const auto preDropTowers = TowerCount(postProduct);
    const auto preDropLevel = postProduct->GetLevel();
    gl.GetCryptoContext()->GetScheme()->ModReduceInternalInPlace(postProduct, 1);
    EXPECT_EQ(postProduct->NumberCiphertextElements(), 2U);
    EXPECT_EQ(TowerCount(postProduct), preDropTowers - 1);
    EXPECT_EQ(postProduct->GetLevel(), preDropLevel + 1);
    auto expectedHalf = expected;
    for (auto& value : expectedHalf) {
        value *= 0.5;
    }
    const auto decodedHalf = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                         postProduct, 4);
    EXPECT_LT(MaxError(decodedHalf, expectedHalf), 3e-3);
}

TEST(GLShip, ExactN8EncryptedHalfBootstrap) {
    GLSchemelet gl(ExactParameters(8, 5));
    GLShipSchemelet ship(gl, ShipParameters(8, 3));
    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {3, -1}, {6, 1}});

    std::vector<std::complex<double>> coefficients(8);
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        const double real = (static_cast<double>(index) - 3.5) / 16.0;
        const double imag = (index % 2 == 0 ? 1.0 : -1.0) *
                            static_cast<double>(index + 1) / 64.0;
        coefficients[index] = {real, imag};
    }

    const auto input = ship.EncryptLowSlice(client, coefficients);
    const auto result = ship.EvalHalfBootstrap(input, client.GetEvaluationKey());
    const auto decoded = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                     result.GetNativeCiphertext(), 8);
    const auto expected = SineOracle(coefficients,
                                     client.GetEvaluationKey().GetBottomModulus(), 64.0);
    EXPECT_LT(MaxError(decoded, expected), 5e-3);
    EXPECT_LT(MaxError(decoded, coefficients), 8e-3);
    EXPECT_GT(TowerCount(result.GetNativeCiphertext()), 1U);
}

TEST(GLShip, ExactN4RefreshOnlyAllYAndNativePostMultiply) {
    GLSchemelet gl(ExactParameters(4, 5));
    GLShipSchemelet ship(gl, ShipParameters(4, 2));
    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {2, -1}});

    const auto values = RefreshMatrix(4);
    const auto encrypted = gl.Encrypt(primary.publicKey, gl.Encode(GLPlaintext(4, values)));
    const auto depleted = DepleteToTwoTowers(encrypted);
    ASSERT_EQ(TowerCount(depleted.GetRows().front()), 2U);

    // RefreshOnly owns every evaluation key it needs.  Ambient context
    // registries are deliberately cleared to make that trust boundary
    // load-bearing rather than accidental global state.
    CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys(primary.secretKey->GetKeyTag());
    CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(primary.secretKey->GetKeyTag());

    const auto refreshed = ship.RefreshOnly(depleted, client.GetEvaluationKey());
    ASSERT_EQ(refreshed.GetRows().size(), 4U);
    EXPECT_EQ(refreshed.GetKeyTag(), primary.secretKey->GetKeyTag());
    EXPECT_GT(TowerCount(refreshed.GetRows().front()),
              TowerCount(depleted.GetRows().front()));
    for (const auto& row : refreshed.GetRows()) {
        ASSERT_TRUE(row);
        EXPECT_EQ(row->NumberCiphertextElements(), 2U);
        EXPECT_EQ(row->GetEncodingType(), CKKS_PACKED_ENCODING);
        EXPECT_EQ(row->GetSlots(), 4U);
        EXPECT_EQ(row->GetKeyTag(), primary.secretKey->GetKeyTag());
        DCRTPoly zero(row->GetElements()[1].GetParams(), Format::EVALUATION, true);
        EXPECT_NE(row->GetElements()[1], zero);
    }

    const auto decoded = gl.Decrypt(primary.secretKey, refreshed);
    EXPECT_LT(MaxError(decoded.GetValues(), values), 2e-2);

    std::vector<std::complex<double>> halfIdentity(16, {0.0, 0.0});
    for (std::size_t index = 0; index < 4; ++index) {
        halfIdentity[index * 4 + index] = {0.5, 0.0};
    }
    const auto postProduct = gl.EvalMatMulPlainNative(
        refreshed, GLPlaintext(4, std::move(halfIdentity)));
    const auto postDecoded = gl.Decrypt(primary.secretKey, postProduct);
    EXPECT_LT(MaxError(postDecoded.GetValues(), ScaledMatrix(values, 0.5)), 3e-2);
}

TEST(GLShip, ExactN8RefreshOnlyAllY) {
    GLSchemelet gl(ExactParameters(8, 6));
    GLShipSchemelet ship(gl, ShipParameters(8, 3));
    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {3, -1}, {6, 1}});

    const auto values = RefreshMatrix(8);
    const auto encrypted = gl.Encrypt(primary.publicKey, gl.Encode(GLPlaintext(8, values)));
    std::vector<Ciphertext<DCRTPoly>> threeTowerRows;
    threeTowerRows.reserve(encrypted.GetRows().size());
    for (const auto& source : encrypted.GetRows()) {
        auto row = source->Clone();
        ASSERT_GE(TowerCount(row), 3U);
        gl.GetCryptoContext()->GetScheme()->LevelReduceInternalInPlace(
            row, TowerCount(row) - 3);
        threeTowerRows.push_back(std::move(row));
    }
    const GLCiphertext threeTowerInput(
        gl.GetGeometry(), gl.GetCryptoContext(), std::move(threeTowerRows));
    ASSERT_EQ(TowerCount(threeTowerInput.GetRows().front()), 3U);
    const auto refreshed = ship.RefreshOnly(threeTowerInput, client.GetEvaluationKey());

    ASSERT_EQ(refreshed.GetRows().size(), 8U);
    EXPECT_EQ(refreshed.GetKeyTag(), primary.secretKey->GetKeyTag());
    EXPECT_GT(TowerCount(refreshed.GetRows().front()), 1U);
    const auto decoded = gl.Decrypt(primary.secretKey, refreshed);
    EXPECT_LT(MaxError(decoded.GetValues(), values), 5e-2);
}

TEST(GLShip, EncryptedSelectorIsLoadBearing) {
    GLSchemelet gl(ExactParameters(4, 4));
    GLShipSchemelet ship(gl, ShipParameters(4, 2));
    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {2, -1}});
    const std::vector<std::complex<double>> coefficients = {
        {0.125, -0.375}, {-0.25, 0.25}, {0.375, 0.125}, {-0.5, -0.125},
    };
    const auto input = ship.EncryptLowSlice(client, coefficients);
    const auto correct = ship.EvalHalfBootstrap(input, client.GetEvaluationKey());

    const auto live = SelectorIndex(4, 1, 2, -1);
    const auto dead = SelectorIndex(4, 1, 2, 1);
    const auto corruptedKey = GLShipTestAccess::SwapSelectors(
        client.GetEvaluationKey(), live, dead);
    const auto corrupted = ship.EvalHalfBootstrap(input, corruptedKey);

    const auto correctValues = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                           correct.GetNativeCiphertext(), 4);
    const auto corruptedValues = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                             corrupted.GetNativeCiphertext(), 4);
    EXPECT_GT(MaxError(correctValues, corruptedValues), 5e-2);
}

TEST(GLShip, FailsClosedOnUnsupportedStateKeysTowersDepthAndMalformedRefresh) {
    const auto exactDepthParameters = ShipParameters(4, 2);
    EXPECT_EQ(exactDepthParameters.RequiredMultiplicativeDepth(), 4u);

    GLParameters transportParameters = ExactParameters(4, 4);
    transportParameters.ringDimension = 16;
    GLSchemelet transport(transportParameters);
    EXPECT_THROW(GLShipSchemelet(transport, ShipParameters(4, 2)), GLNativeModeError);

    GLSchemelet shallow(ExactParameters(4, 3));
    EXPECT_THROW(GLShipSchemelet(shallow, ShipParameters(4, 2)), GLDepthError);

    auto unsupportedScalingParameters = ExactParameters(4, 4);
    unsupportedScalingParameters.scalingTechnique = FLEXIBLEAUTOEXT;
    GLSchemelet unsupportedScaling(unsupportedScalingParameters);
    EXPECT_THROW(GLShipSchemelet(unsupportedScaling, ShipParameters(4, 2)),
                 GLShipUnsupportedError);

    GLSchemelet gl(ExactParameters(4, 4));
    EXPECT_NO_THROW(GLShipSchemelet(gl, exactDepthParameters));

    auto tooSmallGamma = ShipParameters(4, 2);
    tooSmallGamma.gamma = 2.0;
    EXPECT_THROW(GLShipSchemelet(gl, tooSmallGamma), GLShipParameterError);
    auto nonfiniteGamma = ShipParameters(4, 2);
    nonfiniteGamma.gamma = std::numeric_limits<double>::infinity();
    EXPECT_THROW(GLShipSchemelet(gl, nonfiniteGamma), GLShipParameterError);
    auto zeroHammingWeight = ShipParameters(4, 2);
    zeroHammingWeight.hammingWeight = 0;
    EXPECT_THROW(GLShipSchemelet(gl, zeroHammingWeight), GLShipParameterError);
    auto oversizedHammingWeight = ShipParameters(4, 2);
    oversizedHammingWeight.hammingWeight = 5;
    EXPECT_THROW(GLShipSchemelet(gl, oversizedHammingWeight), GLShipParameterError);

    GLShipSchemelet ship(gl, ShipParameters(4, 2));
    auto overflowingDepth = ShipParameters(4, 2);
    overflowingDepth.reservedLevels = std::numeric_limits<uint32_t>::max();
    EXPECT_THROW(GLShipSchemelet(gl, overflowingDepth), GLShipParameterError);

    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {2, -1}});
    const std::vector<std::complex<double>> coefficients(4, {0.125, -0.125});
    const auto input = ship.EncryptLowSlice(client, coefficients);

    auto wrongCoefficientCount = coefficients;
    wrongCoefficientCount.pop_back();
    EXPECT_THROW(ship.EncryptLowSlice(client, wrongCoefficientCount), GLDimensionError);
    auto nonfiniteCoefficient = coefficients;
    nonfiniteCoefficient.front() = {
        std::numeric_limits<double>::quiet_NaN(), 0.0};
    EXPECT_THROW(ship.EncryptLowSlice(client, nonfiniteCoefficient),
                 GLShipParameterError);
    auto oversizedCoefficient = coefficients;
    oversizedCoefficient.front() = {0.0, 1.0001};
    EXPECT_THROW(ship.EncryptLowSlice(client, oversizedCoefficient),
                 GLShipParameterError);

    EXPECT_THROW(ship.KeyGen(primary, {{0, 1}, {0, -1}}), GLShipParameterError);
    EXPECT_THROW(ship.KeyGen(primary, {{0, 1}, {4, -1}}), GLShipParameterError);
    EXPECT_THROW(ship.KeyGen(primary, {{0, 1}, {2, 0}}), GLShipParameterError);

    const auto missingSelector =
        GLShipTestAccess::WithoutSelector(client.GetEvaluationKey());
    EXPECT_THROW(ship.EvalHalfBootstrap(input, missingSelector), GLShipEvaluationKeyError);

    const auto malformedSelectorScale =
        GLShipTestAccess::WithSelectorScalingFactor(client.GetEvaluationKey(), 2.0);
    EXPECT_THROW(ship.EvalHalfBootstrap(input, malformedSelectorScale),
                 GLShipEvaluationKeyError);

    const auto missingConjugation =
        GLShipTestAccess::WithoutConjugationKey(client.GetEvaluationKey());
    EXPECT_THROW(ship.EvalHalfBootstrap(input, missingConjugation),
                 GLShipEvaluationKeyError);

    const auto sameContextPrimary = gl.KeyGen();
    auto sameContextClient = ship.KeyGen(sameContextPrimary, {{0, 1}, {2, -1}});
    const auto wrongSelectorTag = GLShipTestAccess::WithSelectorFrom(
        client.GetEvaluationKey(), sameContextClient.GetEvaluationKey());
    EXPECT_THROW(ship.EvalHalfBootstrap(input, wrongSelectorTag),
                 GLShipEvaluationKeyError);

    const auto missingRelin =
        GLShipTestAccess::WithoutRelinearizationKey(client.GetEvaluationKey());
    EXPECT_THROW(ship.EvalHalfBootstrap(input, missingRelin), GLShipEvaluationKeyError);

    // A distinct depth prevents CryptoContextFactory from deduplicating this
    // fixture with the primary context and makes the context gate load-bearing.
    GLSchemelet otherGL(ExactParameters(4, 5));
    GLShipSchemelet otherShip(otherGL, ShipParameters(4, 2));
    const auto otherPrimary = otherGL.KeyGen();
    auto otherClient = otherShip.KeyGen(otherPrimary, {{0, 1}, {2, -1}});
    const auto wrongSelectorContext = GLShipTestAccess::WithSelectorFrom(
        client.GetEvaluationKey(), otherClient.GetEvaluationKey());
    EXPECT_THROW(ship.EvalHalfBootstrap(input, wrongSelectorContext),
                 GLShipEvaluationKeyError);

    const auto replacedRelin = GLShipTestAccess::WithRelinearizationKeyFrom(
        client.GetEvaluationKey(), otherClient.GetEvaluationKey());
    EXPECT_THROW(ship.EvalHalfBootstrap(input, replacedRelin), GLShipEvaluationKeyError);

    const auto wrongTag = GLShipTestAccess::WithSparseTag(
        client.GetEvaluationKey(), "wrong-sparse-key-tag");
    EXPECT_THROW(ship.EvalHalfBootstrap(input, wrongTag), GLShipEvaluationKeyError);

    const auto wrongState = GLShipTestAccess::WithRepresentation(
        input, GLShipRepresentation::X_COEFFICIENT_SLOTS);
    EXPECT_THROW(ship.EvalHalfBootstrap(wrongState, client.GetEvaluationKey()),
                 GLShipStateError);

    const auto wrongTowers = GLShipTestAccess::WithTopLevelSelector(
        input, client.GetEvaluationKey());
    EXPECT_THROW(ship.EvalHalfBootstrap(wrongTowers, client.GetEvaluationKey()),
                 GLShipStateError);

    const auto wrongScale = GLShipTestAccess::WithScalingFactor(input, 2.0);
    EXPECT_THROW(ship.EvalHalfBootstrap(wrongScale, client.GetEvaluationKey()),
                 GLShipStateError);

    auto malformedLowFormat = ship.EncryptLowSlice(client, coefficients);
    malformedLowFormat.GetNativeCiphertext()->GetElements()[1].SetFormat(
        Format::COEFFICIENT);
    EXPECT_THROW(ship.EvalHalfBootstrap(malformedLowFormat,
                                        client.GetEvaluationKey()),
                 GLShipStateError);

    GLPlaintext zeroMatrix(4, std::vector<std::complex<double>>(16, {0.0, 0.0}));
    const auto encryptedMatrix = gl.Encrypt(primary.publicKey, gl.Encode(zeroMatrix));
    const auto depletedMatrix = DepleteToTwoTowers(encryptedMatrix);

    const auto wrongPrimaryMatrix =
        gl.Encrypt(sameContextPrimary.publicKey, gl.Encode(zeroMatrix));
    EXPECT_THROW(ship.RefreshOnly(wrongPrimaryMatrix, client.GetEvaluationKey()),
                 GLKeyMismatchError);
    const auto wrongContextMatrix =
        otherGL.Encrypt(otherPrimary.publicKey, otherGL.Encode(zeroMatrix));
    EXPECT_THROW(ship.RefreshOnly(wrongContextMatrix, client.GetEvaluationKey()),
                 GLContextMismatchError);

    const auto missingBottomSwitch =
        GLShipTestAccess::WithoutBottomSwitch(client.GetEvaluationKey());
    EXPECT_THROW(ship.RefreshOnly(depletedMatrix, missingBottomSwitch),
                 GLShipEvaluationKeyError);

    const auto missingXForward =
        GLShipTestAccess::WithoutXForwardKey(client.GetEvaluationKey());
    EXPECT_THROW(ship.RefreshOnly(depletedMatrix, missingXForward),
                 GLShipEvaluationKeyError);

    auto oneTowerRows = depletedMatrix.GetRows();
    for (auto& row : oneTowerRows) {
        row = row->Clone();
        gl.GetCryptoContext()->GetScheme()->LevelReduceInternalInPlace(row, 1);
    }
    const GLCiphertext oneTowerMatrix(
        gl.GetGeometry(), gl.GetCryptoContext(), std::move(oneTowerRows));
    EXPECT_THROW(ship.RefreshOnly(oneTowerMatrix, client.GetEvaluationKey()),
                 GLShipStateError);

    auto malformedScaleInt = depletedMatrix.GetRows().front()->Clone();
    malformedScaleInt->SetScalingFactorInt(NativeInteger(2));
    EXPECT_THROW(GLShipTestAccess::NormalizeAndSwitchRow(
                     ship, malformedScaleInt, client.GetEvaluationKey()),
                 GLShipStateError);

    auto malformedLevel = depletedMatrix.GetRows().front()->Clone();
    malformedLevel->SetLevel(malformedLevel->GetLevel() + 1);
    EXPECT_THROW(GLShipTestAccess::NormalizeAndSwitchRow(
                     ship, malformedLevel, client.GetEvaluationKey()),
                 GLShipStateError);

    auto malformedFormat = depletedMatrix.GetRows().front()->Clone();
    malformedFormat->GetElements()[1].SetFormat(Format::COEFFICIENT);
    EXPECT_THROW(GLShipTestAccess::NormalizeAndSwitchRow(
                     ship, malformedFormat, client.GetEvaluationKey()),
                 GLShipStateError);

    auto misalignedRows = depletedMatrix.GetRows();
    misalignedRows.front() = misalignedRows.front()->Clone();
    misalignedRows.front()->SetScalingFactor(
        misalignedRows.front()->GetScalingFactor() * 2.0);
    const GLCiphertext misalignedMatrix(
        gl.GetGeometry(), gl.GetCryptoContext(), std::move(misalignedRows));
    EXPECT_THROW(ship.RefreshOnly(misalignedMatrix, client.GetEvaluationKey()),
                 GLShipStateError);
}

// ---------------------------------------------------------------------------
// HYBRID_MASKED_COLUMN selection (GL_bootstrap Alg. 3 lines 10-12)
// ---------------------------------------------------------------------------

TEST(GLShip, HybridClearAlgebraCoarseFineComposition) {
    constexpr uint64_t q0 = 257;

    // Contract n=4 oracle: A, B, s = 1 - X^2.
    const GaussianVector a4 = {{1, 1}, {2, -1}, {-1, 2}, {0, -1}};
    const GaussianVector b4 = {{3, -1}, {-2, 0}, {1, 1}, {2, -2}};
    const std::vector<GLShipMonomial> support4 = {{0, 1}, {2, -1}};

    // Pinned branch first lanes of Z = B + A*s.
    const auto z4 = GLShipAlgebra::DecryptionRelation(b4, a4, support4);
    EXPECT_EQ(RealLane(z4), (std::vector<int64_t>{6, -1, -1, 0}));
    EXPECT_EQ(RealLane(MultiplyByMinusI(z4)), (std::vector<int64_t>{1, -1, 2, -2}));

    // Every candidate (alpha, sigma), both branches, theta in {2, 4}:
    // the hybrid coarse+fine composition equals the direct factor, and the
    // per-digit lane invariant holds (the ONLY gate for the conj wrap law).
    for (std::size_t branch = 0; branch < 2; ++branch) {
        const auto branchA = branch == 0 ? a4 : MultiplyByMinusI(a4);
        for (uint32_t alpha = 0; alpha < 4; ++alpha) {
            for (const int8_t sign : {int8_t(-1), int8_t(1)}) {
                const auto direct = DirectFactor(branchA, alpha, sign, q0);
                for (const std::size_t theta : {std::size_t{2}, std::size_t{4}}) {
                    const auto hybrid = ClearHybridLeaf(branchA, alpha, sign, theta, q0);
                    EXPECT_LT(MaxError(hybrid.leaf, direct), 1e-12)
                        << "branch=" << branch << " alpha=" << alpha
                        << " sign=" << int(sign) << " theta=" << theta;
                    EXPECT_LT(hybrid.laneAuditError, 1e-12);
                }
            }
        }
    }

    // Contract gate: the selected hybrid factor product equals direct
    // evaluation of omega^{B+As} for both branches.
    for (std::size_t branch = 0; branch < 2; ++branch) {
        const auto branchA = branch == 0 ? a4 : MultiplyByMinusI(a4);
        const auto branchB = branch == 0 ? b4 : MultiplyByMinusI(b4);
        const auto expected = GLShipAlgebra::RootVector(
            q0, RealLane(GLShipAlgebra::DecryptionRelation(branchB, branchA, support4)));
        for (const std::size_t theta : {std::size_t{2}, std::size_t{4}}) {
            auto product = GLShipAlgebra::RootVector(q0, RealLane(branchB));
            for (const auto& monomial : support4) {
                const auto leaf =
                    ClearHybridLeaf(branchA, monomial.alpha, monomial.sign, theta, q0);
                for (std::size_t slot = 0; slot < product.size(); ++slot) {
                    product[slot] *= leaf.leaf[slot];
                }
            }
            EXPECT_LT(MaxError(product, expected), 1e-12);
        }
    }

    // Pinned n=8 sweep at theta in {2, 4, 8}.
    const auto a8 = PinnedHybridA8();
    const auto b8 = PinnedHybridB8();
    const std::vector<GLShipMonomial> support8 = {{1, 1}, {4, -1}, {6, 1}};
    for (std::size_t branch = 0; branch < 2; ++branch) {
        const auto branchA = branch == 0 ? a8 : MultiplyByMinusI(a8);
        const auto branchB = branch == 0 ? b8 : MultiplyByMinusI(b8);
        const auto expected = GLShipAlgebra::RootVector(
            q0, RealLane(GLShipAlgebra::DecryptionRelation(branchB, branchA, support8)));
        for (const std::size_t theta :
             {std::size_t{2}, std::size_t{4}, std::size_t{8}}) {
            auto product = GLShipAlgebra::RootVector(q0, RealLane(branchB));
            for (const auto& monomial : support8) {
                const auto direct = DirectFactor(branchA, monomial.alpha, monomial.sign, q0);
                const auto hybrid =
                    ClearHybridLeaf(branchA, monomial.alpha, monomial.sign, theta, q0);
                EXPECT_LT(MaxError(hybrid.leaf, direct), 1e-12);
                EXPECT_LT(hybrid.laneAuditError, 1e-12);
                for (std::size_t slot = 0; slot < product.size(); ++slot) {
                    product[slot] *= hybrid.leaf[slot];
                }
            }
            EXPECT_LT(MaxError(product, expected), 1e-12);
        }
    }

    // Negative control (Remark H3): breaking the conjugation leaves the
    // end-to-end leaf bit-identical -- the wrap entries of V are never
    // consumed under the pinned schedule -- but the per-digit lane audit
    // catches it.  Only the audit gates the conjugation law.
    const auto intact = ClearHybridLeaf(a8, 1, 1, 4, q0, false);
    const auto broken = ClearHybridLeaf(a8, 1, 1, 4, q0, true);
    EXPECT_LT(MaxError(broken.leaf, intact.leaf), 1e-12);
    EXPECT_LT(intact.laneAuditError, 1e-12);
    EXPECT_GT(broken.laneAuditError, 0.3);
}

TEST(GLShip, HybridParametersValidateAndDepth) {
    EXPECT_EQ(HybridShipParameters(4, 2, 2).RequiredMultiplicativeDepth(), 6u);
    EXPECT_EQ(HybridShipParameters(8, 3, 4).RequiredMultiplicativeDepth(), 7u);
    // theta = 2 saves a digit; theta = 8 costs one more digit than its
    // smaller tree round refunds.
    EXPECT_EQ(HybridShipParameters(8, 3, 2).RequiredMultiplicativeDepth(), 6u);
    EXPECT_EQ(HybridShipParameters(8, 3, 8).RequiredMultiplicativeDepth(), 8u);

    GLSchemelet gl4(ExactParameters(4, 6));
    GLSchemelet gl8(ExactParameters(8, 7));
    EXPECT_NO_THROW(GLShipSchemelet(gl4, HybridShipParameters(4, 2, 2)));
    EXPECT_NO_THROW(GLShipSchemelet(gl8, HybridShipParameters(8, 3, 4)));
    EXPECT_NO_THROW(GLShipSchemelet(gl8, HybridShipParameters(8, 3, 2)));
    EXPECT_THROW(GLShipSchemelet(gl8, HybridShipParameters(8, 3, 8)), GLDepthError);
    GLSchemelet gl8Deep(ExactParameters(8, 8));
    EXPECT_NO_THROW(GLShipSchemelet(gl8Deep, HybridShipParameters(8, 3, 8)));
    // Both selection modes stay legal on the same deeper context.
    EXPECT_NO_THROW(GLShipSchemelet(gl4, ShipParameters(4, 2)));
    EXPECT_NO_THROW(GLShipSchemelet(gl8, ShipParameters(8, 3)));

    // Negative #1: direct parameters take no hybrid coarse fields.
    auto directWithTheta = ShipParameters(4, 2);
    directWithTheta.coarseBlockSize = 2;
    EXPECT_THROW(GLShipSchemelet(gl4, directWithTheta), GLShipParameterError);
    auto directWithWindow = ShipParameters(4, 2);
    directWithWindow.coarseWindows = {{0, 1}, {0, 1}};
    EXPECT_THROW(GLShipSchemelet(gl4, directWithWindow), GLShipParameterError);

    // Negative #2: theta must be a power of two in [2, n] dividing n.
    for (const std::size_t badTheta : {std::size_t{0}, std::size_t{1}, std::size_t{3},
                                       std::size_t{6}, std::size_t{16}}) {
        EXPECT_THROW(GLShipSchemelet(gl8, HybridShipParameters(8, 3, badTheta)),
                     GLShipParameterError)
            << "theta=" << badTheta;
    }

    // Negative #3: windows must be empty or exactly one per support ordinal.
    EXPECT_THROW(GLShipSchemelet(gl4, HybridShipParameters(4, 2, 2, 1, {{0, 1}})),
                 GLShipParameterError);

    // Negative #4: windows must be nonempty and inside [0, n/theta).
    EXPECT_THROW(GLShipSchemelet(gl4, HybridShipParameters(4, 2, 2, 1, {{0, 0}, {0, 1}})),
                 GLShipParameterError);
    EXPECT_THROW(GLShipSchemelet(gl4, HybridShipParameters(4, 2, 2, 1, {{2, 1}, {0, 1}})),
                 GLShipParameterError);
    EXPECT_THROW(GLShipSchemelet(gl4, HybridShipParameters(4, 2, 2, 1, {{1, 2}, {0, 1}})),
                 GLShipParameterError);

    // Overflow guard on the hybrid depth requirement.
    auto overflowing = HybridShipParameters(4, 2, 2);
    overflowing.reservedLevels = std::numeric_limits<uint32_t>::max();
    EXPECT_EQ(overflowing.RequiredMultiplicativeDepth(),
              std::numeric_limits<uint32_t>::max());
    EXPECT_THROW(GLShipSchemelet(gl4, overflowing), GLShipParameterError);

    // Hybrid on a depth-(required-1) context is refused up front.
    GLSchemelet shallow(ExactParameters(4, 5));
    EXPECT_THROW(GLShipSchemelet(shallow, HybridShipParameters(4, 2, 2)), GLDepthError);

    // n=4096 hybrid parameters keep failing closed at the dimension gate.
    auto production = HybridShipParameters(4096, 2, 2);
    EXPECT_THROW(GLShipSchemelet(gl4, production), GLShipParameterError);
}

TEST(GLShip, HybridKeyGenBankShapesAndPrivacy) {
    GLSchemelet gl(ExactParameters(4, 6));
    GLShipSchemelet ship(gl, HybridShipParameters(4, 2, 2));
    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {2, -1}});
    const auto& key = client.GetEvaluationKey();

    // Coarse bank: sum_t 2*count_t = 2*h*(n/theta); fine: 3*h*log2(theta).
    EXPECT_EQ(key.GetSelectorCount(), 8u);
    EXPECT_EQ(key.GetFineSelectorCount(), 6u);

    const auto fullTowerCount =
        TowerCount(GLShipTestAccess::Selectors(key).front());
    const auto assertSelectorClass = [&](const Ciphertext<DCRTPoly>& selector) {
        ASSERT_TRUE(selector);
        EXPECT_EQ(selector->NumberCiphertextElements(), 2u);
        EXPECT_EQ(selector->GetLevel(), 0u);
        EXPECT_EQ(selector->GetNoiseScaleDeg(), 1u);
        EXPECT_EQ(selector->GetSlots(), 4u);
        EXPECT_EQ(selector->GetEncodingType(), CKKS_PACKED_ENCODING);
        EXPECT_EQ(selector->GetKeyTag(), primary.publicKey->GetKeyTag());
        EXPECT_EQ(TowerCount(selector), fullTowerCount);
    };
    for (const auto& selector : GLShipTestAccess::Selectors(key)) {
        assertSelectorClass(selector);
    }
    for (const auto& fineSelector : GLShipTestAccess::FineSelectors(key)) {
        assertSelectorClass(fineSelector);
    }

    // Two client materials for DIFFERENT supports but identical public
    // (n, h, theta, windows) yield identical bank shapes and metadata: no
    // support leakage through shape.  The per-digit sum-to-one invariant of
    // the fine pieces is deliberately NOT evaluator-checkable (the pieces are
    // semantically secure encryptions); it is pinned by the clear-algebra
    // composition test instead.
    auto otherClient = ship.KeyGen(primary, {{1, -1}, {3, 1}});
    const auto& otherKey = otherClient.GetEvaluationKey();
    EXPECT_EQ(otherKey.GetSelectorCount(), key.GetSelectorCount());
    EXPECT_EQ(otherKey.GetFineSelectorCount(), key.GetFineSelectorCount());
    for (const auto& selector : GLShipTestAccess::Selectors(otherKey)) {
        assertSelectorClass(selector);
    }
    for (const auto& fineSelector : GLShipTestAccess::FineSelectors(otherKey)) {
        assertSelectorClass(fineSelector);
    }
}

TEST(GLShip, ExactN4HybridEncryptedHalfBootstrapAndPostOperation) {
    GLSchemelet gl(ExactParameters(4, 6));
    GLShipSchemelet ship(gl, HybridShipParameters(4, 2, 2));
    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {2, -1}});

    const std::vector<std::complex<double>> coefficients = {
        {0.125, -0.375}, {-0.25, 0.25}, {0.375, 0.125}, {-0.5, -0.125},
    };
    const auto input = ship.EncryptLowSlice(client, coefficients);
    const auto secondInput = ship.EncryptLowSlice(client, coefficients);
    EXPECT_TRUE(NativeElementsDiffer(input.GetNativeCiphertext(),
                                     secondInput.GetNativeCiphertext()));
    ASSERT_EQ(input.GetNativeCiphertext()->NumberCiphertextElements(), 2U);
    EXPECT_EQ(TowerCount(input.GetNativeCiphertext()), 1U);

    const auto result = ship.EvalHalfBootstrap(input, client.GetEvaluationKey());
    ASSERT_TRUE(result.GetNativeCiphertext());
    EXPECT_EQ(result.GetRepresentation(), GLShipRepresentation::X_COEFFICIENT_SLOTS);
    EXPECT_EQ(result.GetNativeCiphertext()->NumberCiphertextElements(), 2U);
    EXPECT_EQ(result.GetKeyTag(), primary.secretKey->GetKeyTag());
    EXPECT_GT(TowerCount(result.GetNativeCiphertext()),
              TowerCount(input.GetNativeCiphertext()));
    DCRTPoly zeroA(result.GetNativeCiphertext()->GetElements()[1].GetParams(),
                   Format::EVALUATION, true);
    EXPECT_NE(result.GetNativeCiphertext()->GetElements()[1], zeroA);

    const auto decoded = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                     result.GetNativeCiphertext(), 4);
    const auto expected = SineOracle(coefficients,
                                     client.GetEvaluationKey().GetBottomModulus(), 64.0);
    EXPECT_LT(MaxError(decoded, expected), 4e-3);
    EXPECT_LT(MaxError(decoded, coefficients), 7e-3);

    // Reserved post-operation: one plaintext multiply plus one exact rescale.
    std::vector<std::complex<double>> half(4, {0.5, 0.0});
    auto postPlaintext = gl.GetCryptoContext()->MakeCKKSPackedPlaintext(
        half, 1, result.GetNativeCiphertext()->GetLevel(), nullptr, 4);
    ASSERT_TRUE(postPlaintext);
    auto postProduct = gl.GetCryptoContext()->EvalMult(
        result.GetNativeCiphertext(), postPlaintext);
    ASSERT_TRUE(postProduct);
    const auto preDropTowers = TowerCount(postProduct);
    const auto preDropLevel = postProduct->GetLevel();
    gl.GetCryptoContext()->GetScheme()->ModReduceInternalInPlace(postProduct, 1);
    EXPECT_EQ(postProduct->NumberCiphertextElements(), 2U);
    EXPECT_EQ(TowerCount(postProduct), preDropTowers - 1);
    EXPECT_EQ(postProduct->GetLevel(), preDropLevel + 1);
    auto expectedHalf = expected;
    for (auto& value : expectedHalf) {
        value *= 0.5;
    }
    const auto decodedHalf = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                         postProduct, 4);
    EXPECT_LT(MaxError(decodedHalf, expectedHalf), 6e-3);
}

TEST(GLShip, ExactN8HybridEncryptedHalfBootstrap) {
    GLSchemelet gl(ExactParameters(8, 7));
    GLShipSchemelet ship(gl, HybridShipParameters(8, 3, 4));
    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {3, -1}, {6, 1}});

    std::vector<std::complex<double>> coefficients(8);
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        const double real = (static_cast<double>(index) - 3.5) / 16.0;
        const double imag = (index % 2 == 0 ? 1.0 : -1.0) *
                            static_cast<double>(index + 1) / 64.0;
        coefficients[index] = {real, imag};
    }

    const auto input = ship.EncryptLowSlice(client, coefficients);
    const auto result = ship.EvalHalfBootstrap(input, client.GetEvaluationKey());
    const auto decoded = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                     result.GetNativeCiphertext(), 8);
    const auto expected = SineOracle(coefficients,
                                     client.GetEvaluationKey().GetBottomModulus(), 64.0);
    EXPECT_LT(MaxError(decoded, expected), 1e-2);
    EXPECT_LT(MaxError(decoded, coefficients), 1.3e-2);
    EXPECT_GT(TowerCount(result.GetNativeCiphertext()), 1U);
}

TEST(GLShip, HybridMatchesDirectColumnWithinTolerance) {
    // One context, one primary keypair, one support and coefficient set per
    // dimension; two client materials (the sparse tags necessarily differ, so
    // each mode encrypts its own low slice) compared decrypt-side against the
    // shared analytic oracle and against each other.
    {
        GLSchemelet gl(ExactParameters(4, 6));
        GLShipSchemelet direct(gl, ShipParameters(4, 2));
        GLShipSchemelet hybrid(gl, HybridShipParameters(4, 2, 2));
        const auto primary = gl.KeyGen();
        auto directClient = direct.KeyGen(primary, {{0, 1}, {2, -1}});
        auto hybridClient = hybrid.KeyGen(primary, {{0, 1}, {2, -1}});
        const std::vector<std::complex<double>> coefficients = {
            {0.125, -0.375}, {-0.25, 0.25}, {0.375, 0.125}, {-0.5, -0.125},
        };
        const auto directResult = direct.EvalHalfBootstrap(
            direct.EncryptLowSlice(directClient, coefficients),
            directClient.GetEvaluationKey());
        const auto hybridResult = hybrid.EvalHalfBootstrap(
            hybrid.EncryptLowSlice(hybridClient, coefficients),
            hybridClient.GetEvaluationKey());
        const auto expected = SineOracle(
            coefficients, directClient.GetEvaluationKey().GetBottomModulus(), 64.0);
        const auto directDecoded = DecodeSlots(
            gl.GetCryptoContext(), primary.secretKey, directResult.GetNativeCiphertext(), 4);
        const auto hybridDecoded = DecodeSlots(
            gl.GetCryptoContext(), primary.secretKey, hybridResult.GetNativeCiphertext(), 4);
        EXPECT_LT(MaxError(directDecoded, expected), 2e-3);
        EXPECT_LT(MaxError(hybridDecoded, expected), 4e-3);
        EXPECT_LT(MaxError(hybridDecoded, directDecoded), 6e-3);
    }
    {
        GLSchemelet gl(ExactParameters(8, 7));
        GLShipSchemelet direct(gl, ShipParameters(8, 3));
        GLShipSchemelet hybrid(gl, HybridShipParameters(8, 3, 4));
        const auto primary = gl.KeyGen();
        auto directClient = direct.KeyGen(primary, {{0, 1}, {3, -1}, {6, 1}});
        auto hybridClient = hybrid.KeyGen(primary, {{0, 1}, {3, -1}, {6, 1}});
        std::vector<std::complex<double>> coefficients(8);
        for (std::size_t index = 0; index < coefficients.size(); ++index) {
            coefficients[index] = {(static_cast<double>(index) - 3.5) / 16.0,
                                   (index % 2 == 0 ? 1.0 : -1.0) *
                                       static_cast<double>(index + 1) / 64.0};
        }
        const auto directResult = direct.EvalHalfBootstrap(
            direct.EncryptLowSlice(directClient, coefficients),
            directClient.GetEvaluationKey());
        const auto hybridResult = hybrid.EvalHalfBootstrap(
            hybrid.EncryptLowSlice(hybridClient, coefficients),
            hybridClient.GetEvaluationKey());
        const auto expected = SineOracle(
            coefficients, directClient.GetEvaluationKey().GetBottomModulus(), 64.0);
        const auto directDecoded = DecodeSlots(
            gl.GetCryptoContext(), primary.secretKey, directResult.GetNativeCiphertext(), 8);
        const auto hybridDecoded = DecodeSlots(
            gl.GetCryptoContext(), primary.secretKey, hybridResult.GetNativeCiphertext(), 8);
        EXPECT_LT(MaxError(directDecoded, expected), 5e-3);
        EXPECT_LT(MaxError(hybridDecoded, expected), 1e-2);
        EXPECT_LT(MaxError(hybridDecoded, directDecoded), 1.5e-2);
    }
}

TEST(GLShip, HybridCoarseSelectorIsLoadBearing) {
    GLSchemelet gl(ExactParameters(4, 6));
    GLShipSchemelet ship(gl, HybridShipParameters(4, 2, 2));
    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {2, -1}});
    const std::vector<std::complex<double>> coefficients = {
        {0.125, -0.375}, {-0.25, 0.25}, {0.375, 0.125}, {-0.5, -0.125},
    };
    const auto input = ship.EncryptLowSlice(client, coefficients);
    const auto correct = ship.EvalHalfBootstrap(input, client.GetEvaluationKey());

    // Coarse bank layout: ordinal-major, block-major, sign -1 then +1 with
    // 2*(n/theta) entries per ordinal.  Ordinal 1 (alpha=2, theta=2) lives at
    // block 1 with sign -1; its sign-+1 sibling is a dead fresh Enc(0).
    const std::size_t live = 2 * 2 + 2 * 1 + 0;
    const std::size_t dead = 2 * 2 + 2 * 1 + 1;
    const auto corruptedKey =
        GLShipTestAccess::SwapSelectors(client.GetEvaluationKey(), live, dead);
    const auto corrupted = ship.EvalHalfBootstrap(input, corruptedKey);

    const auto correctValues = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                           correct.GetNativeCiphertext(), 4);
    const auto corruptedValues = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                             corrupted.GetNativeCiphertext(), 4);
    EXPECT_GT(MaxError(correctValues, corruptedValues), 5e-2);
}

TEST(GLShip, HybridFineMuxPolarityIsLoadBearing) {
    GLSchemelet gl(ExactParameters(4, 6));
    GLShipSchemelet ship(gl, HybridShipParameters(4, 2, 2));
    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {2, -1}});
    const std::vector<std::complex<double>> coefficients = {
        {0.125, -0.375}, {-0.25, 0.25}, {0.375, 0.125}, {-0.5, -0.125},
    };
    const auto input = ship.EncryptLowSlice(client, coefficients);
    const auto correct = ship.EvalHalfBootstrap(input, client.GetEvaluationKey());

    // Replace ordinal 0's single digit (alpha0 = 0, so a = 0) with fixture
    // encryptions of the complement bit 1-a: PH' = Enc(mHigh), PL' = Enc(mLow),
    // NG' = Enc(0).  The fixture encrypts under the primary PUBLIC key with
    // keygen's exact metadata class, so the tampered key still validates; the
    // complemented digit selects alpha_t + 1, a different leaf.
    const auto encryptFixture = [&](const std::vector<std::complex<double>>& values) {
        auto plaintext = gl.GetCryptoContext()->MakeCKKSPackedPlaintext(
            values, 1, 0, nullptr, 4);
        return gl.GetCryptoContext()->Encrypt(primary.publicKey, plaintext);
    };
    std::vector<std::complex<double>> maskHigh(4);
    std::vector<std::complex<double>> maskLow(4);
    for (std::size_t slot = 0; slot < 4; ++slot) {
        maskHigh[slot] = {slot >= 1 ? 1.0 : 0.0, 0.0};
        maskLow[slot] = {slot < 1 ? 1.0 : 0.0, 0.0};
    }
    auto tamperedKey = GLShipTestAccess::WithFineSelector(
        client.GetEvaluationKey(), 0, encryptFixture(maskHigh));
    tamperedKey = GLShipTestAccess::WithFineSelector(tamperedKey, 1, encryptFixture(maskLow));
    tamperedKey = GLShipTestAccess::WithFineSelector(
        tamperedKey, 2,
        encryptFixture(std::vector<std::complex<double>>(4, {0.0, 0.0})));

    const auto corrupted = ship.EvalHalfBootstrap(input, tamperedKey);
    const auto correctValues = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                           correct.GetNativeCiphertext(), 4);
    const auto corruptedValues = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                             corrupted.GetNativeCiphertext(), 4);
    EXPECT_GT(MaxError(correctValues, corruptedValues), 5e-2);
}

TEST(GLShip, ExactN4HybridRefreshOnlyAllYAndNativePostMultiply) {
    GLSchemelet gl(ExactParameters(4, 7));
    GLShipSchemelet ship(gl, HybridShipParameters(4, 2, 2));
    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {2, -1}});

    const auto values = RefreshMatrix(4);
    const auto encrypted = gl.Encrypt(primary.publicKey, gl.Encode(GLPlaintext(4, values)));
    const auto depleted = DepleteToTwoTowers(encrypted);
    ASSERT_EQ(TowerCount(depleted.GetRows().front()), 2U);

    CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys(primary.secretKey->GetKeyTag());
    CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(primary.secretKey->GetKeyTag());

    const auto refreshed = ship.RefreshOnly(depleted, client.GetEvaluationKey());
    ASSERT_EQ(refreshed.GetRows().size(), 4U);
    EXPECT_EQ(refreshed.GetKeyTag(), primary.secretKey->GetKeyTag());
    EXPECT_GT(TowerCount(refreshed.GetRows().front()),
              TowerCount(depleted.GetRows().front()));
    for (const auto& row : refreshed.GetRows()) {
        ASSERT_TRUE(row);
        EXPECT_EQ(row->NumberCiphertextElements(), 2U);
        EXPECT_EQ(row->GetEncodingType(), CKKS_PACKED_ENCODING);
        EXPECT_EQ(row->GetSlots(), 4U);
        EXPECT_EQ(row->GetKeyTag(), primary.secretKey->GetKeyTag());
        DCRTPoly zero(row->GetElements()[1].GetParams(), Format::EVALUATION, true);
        EXPECT_NE(row->GetElements()[1], zero);
    }

    const auto decoded = gl.Decrypt(primary.secretKey, refreshed);
    EXPECT_LT(MaxError(decoded.GetValues(), values), 4e-2);

    std::vector<std::complex<double>> halfIdentity(16, {0.0, 0.0});
    for (std::size_t index = 0; index < 4; ++index) {
        halfIdentity[index * 4 + index] = {0.5, 0.0};
    }
    const auto postProduct = gl.EvalMatMulPlainNative(
        refreshed, GLPlaintext(4, std::move(halfIdentity)));
    const auto postDecoded = gl.Decrypt(primary.secretKey, postProduct);
    EXPECT_LT(MaxError(postDecoded.GetValues(), ScaledMatrix(values, 0.5)), 6e-2);
}

TEST(GLShip, ExactN8HybridRefreshOnlyAllY) {
    GLSchemelet gl(ExactParameters(8, 7));
    GLShipSchemelet ship(gl, HybridShipParameters(8, 3, 4));
    const auto primary = gl.KeyGen();
    auto client = ship.KeyGen(primary, {{0, 1}, {3, -1}, {6, 1}});

    const auto values = RefreshMatrix(8);
    const auto encrypted = gl.Encrypt(primary.publicKey, gl.Encode(GLPlaintext(8, values)));
    std::vector<Ciphertext<DCRTPoly>> threeTowerRows;
    threeTowerRows.reserve(encrypted.GetRows().size());
    for (const auto& source : encrypted.GetRows()) {
        auto row = source->Clone();
        ASSERT_GE(TowerCount(row), 3U);
        gl.GetCryptoContext()->GetScheme()->LevelReduceInternalInPlace(
            row, TowerCount(row) - 3);
        threeTowerRows.push_back(std::move(row));
    }
    const GLCiphertext threeTowerInput(
        gl.GetGeometry(), gl.GetCryptoContext(), std::move(threeTowerRows));
    ASSERT_EQ(TowerCount(threeTowerInput.GetRows().front()), 3U);
    const auto refreshed = ship.RefreshOnly(threeTowerInput, client.GetEvaluationKey());

    ASSERT_EQ(refreshed.GetRows().size(), 8U);
    EXPECT_EQ(refreshed.GetKeyTag(), primary.secretKey->GetKeyTag());
    EXPECT_GT(TowerCount(refreshed.GetRows().front()), 1U);
    const auto decoded = gl.Decrypt(primary.secretKey, refreshed);
    EXPECT_LT(MaxError(decoded.GetValues(), values), 1e-1);
}

TEST(GLShip, HybridFailsClosedOnBankShapeKeyAndWindowErrors) {
    GLSchemelet gl(ExactParameters(4, 6));
    GLShipSchemelet hybridShip(gl, HybridShipParameters(4, 2, 2));
    GLShipSchemelet directShip(gl, ShipParameters(4, 2));
    const auto primary = gl.KeyGen();
    auto hybridClient = hybridShip.KeyGen(primary, {{0, 1}, {2, -1}});
    auto directClient = directShip.KeyGen(primary, {{0, 1}, {2, -1}});
    const std::vector<std::complex<double>> coefficients(4, {0.125, -0.125});
    const auto hybridInput = hybridShip.EncryptLowSlice(hybridClient, coefficients);
    const auto directInput = directShip.EncryptLowSlice(directClient, coefficients);

    // #7: truncated fine bank (missing digit/polarity piece).
    const auto missingFine =
        GLShipTestAccess::WithoutFineSelector(hybridClient.GetEvaluationKey());
    EXPECT_THROW(hybridShip.EvalHalfBootstrap(hybridInput, missingFine),
                 GLShipEvaluationKeyError);

    // #8: tampered fine mux-key metadata.
    const auto tamperedFineScale = GLShipTestAccess::WithFineSelectorScalingFactor(
        hybridClient.GetEvaluationKey(), 2.0);
    EXPECT_THROW(hybridShip.EvalHalfBootstrap(hybridInput, tamperedFineScale),
                 GLShipEvaluationKeyError);

    // Cross-mode key/schemelet mixes fail the parameter fingerprint.
    EXPECT_THROW(hybridShip.EvalHalfBootstrap(hybridInput,
                                              directClient.GetEvaluationKey()),
                 GLShipEvaluationKeyError);
    EXPECT_THROW(directShip.EvalHalfBootstrap(directInput,
                                              hybridClient.GetEvaluationKey()),
                 GLShipEvaluationKeyError);

    // #6: truncated coarse bank.
    const auto missingCoarse =
        GLShipTestAccess::WithoutSelector(hybridClient.GetEvaluationKey());
    EXPECT_THROW(hybridShip.EvalHalfBootstrap(hybridInput, missingCoarse),
                 GLShipEvaluationKeyError);

    // #5: key generation refuses a window that cannot contain its support
    // ordinal (client-side rule; the evaluator never learns the live block).
    GLShipSchemelet windowedShip(
        gl, HybridShipParameters(4, 2, 2, 1, {{1, 1}, {0, 2}}));
    EXPECT_THROW(windowedShip.KeyGen(primary, {{0, 1}, {2, -1}}),
                 GLShipParameterError);

    // #9: a direct-column key must not carry hybrid fine mux material.
    const auto directWithFine = GLShipTestAccess::WithAppendedFineSelector(
        directClient.GetEvaluationKey(),
        GLShipTestAccess::Selectors(directClient.GetEvaluationKey()).front()->Clone());
    EXPECT_THROW(directShip.EvalHalfBootstrap(directInput, directWithFine),
                 GLShipEvaluationKeyError);
}

TEST(GLShip, HybridWindowedCoarseBankMatchesFullWindow) {
    GLSchemelet gl(ExactParameters(8, 7));
    GLShipSchemelet fullShip(gl, HybridShipParameters(8, 3, 4));
    // Support {(0,+1),(3,-1),(6,+1)} lives in blocks {0, 0, 1} at theta = 4.
    GLShipSchemelet windowedShip(
        gl, HybridShipParameters(8, 3, 4, 1, {{0, 1}, {0, 1}, {1, 1}}));
    const auto primary = gl.KeyGen();
    auto fullClient = fullShip.KeyGen(primary, {{0, 1}, {3, -1}, {6, 1}});
    auto windowedClient = windowedShip.KeyGen(primary, {{0, 1}, {3, -1}, {6, 1}});

    EXPECT_EQ(fullClient.GetEvaluationKey().GetSelectorCount(), 12u);
    EXPECT_EQ(windowedClient.GetEvaluationKey().GetSelectorCount(), 6u);
    EXPECT_EQ(fullClient.GetEvaluationKey().GetFineSelectorCount(), 18u);
    EXPECT_EQ(windowedClient.GetEvaluationKey().GetFineSelectorCount(), 18u);

    std::vector<std::complex<double>> coefficients(8);
    for (std::size_t index = 0; index < coefficients.size(); ++index) {
        coefficients[index] = {(static_cast<double>(index) - 3.5) / 16.0,
                               (index % 2 == 0 ? 1.0 : -1.0) *
                                   static_cast<double>(index + 1) / 64.0};
    }
    const auto fullResult = fullShip.EvalHalfBootstrap(
        fullShip.EncryptLowSlice(fullClient, coefficients),
        fullClient.GetEvaluationKey());
    const auto windowedResult = windowedShip.EvalHalfBootstrap(
        windowedShip.EncryptLowSlice(windowedClient, coefficients),
        windowedClient.GetEvaluationKey());
    const auto fullDecoded = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                         fullResult.GetNativeCiphertext(), 8);
    const auto windowedDecoded = DecodeSlots(gl.GetCryptoContext(), primary.secretKey,
                                             windowedResult.GetNativeCiphertext(), 8);
    EXPECT_LT(MaxError(windowedDecoded, fullDecoded), 1.5e-2);
}

}  // namespace lbcrypto
