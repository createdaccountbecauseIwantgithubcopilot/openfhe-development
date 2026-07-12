//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

// Integer (BGV-like) GL mode, GL_scheme.md section 4, W-free profile (p = 1).
// OpenFHE-only sibling of the CKKS GLSchemelet: one plaintext is the pair
// (M+, M-) of n x n matrices over Z_t, t prime with t = 1 (mod 4n), and every
// operation is exact mod t.  Exact ring dimension 2n / cyclotomic order 4n,
// HEStd_NotSet, toy dims n = 4/8 only: conformance geometry, not a security
// claim.  The coefficient-domain trace/adjoint/transpose kernels are the
// complex port's kernels verbatim, operating on BGV DCRT towers mod q_i;
// mod-t correctness emerges at decryption, never by reducing tower values.

#include "scheme/gl/gl-int.h"

#include <algorithm>
#include <limits>
#include <sstream>
#include <utility>

namespace lbcrypto {

namespace {

std::string DimensionMessage(const char* objectName, std::size_t expected, std::size_t actual) {
    std::ostringstream os;
    os << objectName << " dimension mismatch: expected " << expected << ", got " << actual;
    return os.str();
}

std::string RowMessage(const char* prefix, std::size_t row) {
    std::ostringstream os;
    os << prefix << " at row " << row;
    return os.str();
}

void RequireSameGeometry(const GLGeometry& expected, const GLGeometry& actual, const char* objectName) {
    if (expected != actual) {
        throw GLDimensionError(
            DimensionMessage(objectName, expected.GetDimension(), actual.GetDimension()));
    }
}

// ---------------------------------------------------------------------------
// Exact mod-t integer helpers (t < 2^32 is enforced by GLIntParameters, so
// every product below fits uint64_t without overflow).
// ---------------------------------------------------------------------------

int64_t CanonicalModT(int64_t value, uint64_t modulus) {
    const auto m = static_cast<int64_t>(modulus);
    return ((value % m) + m) % m;
}

uint64_t PowModT(uint64_t base, uint64_t exponent, uint64_t modulus) {
    uint64_t result = 1;
    base %= modulus;
    while (exponent > 0) {
        if (exponent & 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent >>= 1;
    }
    return result;
}

bool IsSmallPrime(uint64_t value) {
    if (value < 2) {
        return false;
    }
    if (value < 4) {
        return true;
    }
    if (value % 2 == 0) {
        return false;
    }
    for (uint64_t divisor = 3; divisor * divisor <= value; divisor += 2) {
        if (value % divisor == 0) {
            return false;
        }
    }
    return true;
}

bool IsPowerOfTwoIntCensus(uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

bool IsGeneratorModPrime(uint64_t generator, uint64_t prime) {
    if (generator < 2 || generator >= prime || !IsSmallPrime(prime)) {
        return false;
    }
    const auto order = prime - 1;
    auto remaining   = order;
    for (uint64_t factor = 2; factor * factor <= remaining; ++factor) {
        if (remaining % factor != 0) {
            continue;
        }
        if (PowModT(generator, order / factor, prime) == 1) {
            return false;
        }
        do {
            remaining /= factor;
        } while (remaining % factor == 0);
    }
    return remaining == 1 || PowModT(generator, order / remaining, prime) != 1;
}

bool HasExactMultiplicativeOrder(uint64_t value, uint64_t order, uint64_t modulus) {
    if (value == 0 || value >= modulus || order == 0 || PowModT(value, order, modulus) != 1) {
        return false;
    }
    auto remaining = order;
    for (uint64_t factor = 2; factor * factor <= remaining; ++factor) {
        if (remaining % factor != 0) {
            continue;
        }
        if (PowModT(value, order / factor, modulus) == 1) {
            return false;
        }
        do {
            remaining /= factor;
        } while (remaining % factor == 0);
    }
    return remaining == 1 || PowModT(value, order / remaining, modulus) != 1;
}

uint64_t MinimumElementOfOrder(uint64_t order, uint64_t modulus) {
    for (uint64_t candidate = 2; candidate < modulus; ++candidate) {
        if (HasExactMultiplicativeOrder(candidate, order, modulus)) {
            return candidate;
        }
    }
    return 0;
}

uint64_t AddModT(uint64_t lhs, uint64_t rhs, uint64_t modulus) {
    return (lhs + rhs) % modulus;
}

uint64_t SubModT(uint64_t lhs, uint64_t rhs, uint64_t modulus) {
    return lhs >= rhs ? lhs - rhs : modulus - (rhs - lhs);
}

uint64_t MulModT(uint64_t lhs, uint64_t rhs, uint64_t modulus) {
    return (lhs * rhs) % modulus;
}

bool SameWBatchedParameters(const GLIntWBatchedParameters& lhs,
                            const GLIntWBatchedParameters& rhs) {
    return lhs.dimension == rhs.dimension && lhs.cyclotomicPrime == rhs.cyclotomicPrime &&
           lhs.wGenerator == rhs.wGenerator && lhs.plaintextModulus == rhs.plaintextModulus &&
           lhs.multiplicativeDepth == rhs.multiplicativeDepth &&
           lhs.nativeRnsWordBits == rhs.nativeRnsWordBits;
}

void RequireConformanceWBatchedCodec(const GLIntWBatchedParameters& parameters) {
    parameters.Validate();
    if (!parameters.IsConformanceN4P3T97()) {
        throw GLIntParameterError(
            "GL integer W-batched value codec supports only n=4,p=3,gamma=2,t=97,N32");
    }
}

std::size_t WBatchedValueIndex(std::size_t n, std::size_t matrix, std::size_t row,
                               std::size_t column) {
    return (matrix * n + row) * n + column;
}

std::size_t WBatchedCoefficientIndex(std::size_t n, std::size_t phi, std::size_t x,
                                     std::size_t y, std::size_t w) {
    return (x * n + y) * phi + w;
}

uint64_t CheckedMultiply(uint64_t lhs, uint64_t rhs, const char* quantity) {
    if (rhs != 0 && lhs > std::numeric_limits<uint64_t>::max() / rhs) {
        throw GLIntParameterError(std::string("GL integer W-batched ") + quantity + " overflows uint64");
    }
    return lhs * rhs;
}

GLIntOperationCensusEntry CensusEntry(GLIntOperation operation, GLIntWFreeCoverage coverage,
                                      uint8_t consumedLevels, uint16_t keyRequirements,
                                      bool section4Required = true) {
    return GLIntOperationCensusEntry{operation, coverage, consumedLevels, keyRequirements,
                                     section4Required, false, false};
}

std::array<GLIntOperationCensusEntry, kGLIntOperationCensusSize> WFreeOperationCensus() {
    using Coverage = GLIntWFreeCoverage;
    return {{
        CensusEntry(GLIntOperation::Encode, Coverage::PublicValuePath, 0, GLIntKeyNone),
        CensusEntry(GLIntOperation::Decode, Coverage::PublicValuePath, 0, GLIntKeyNone),
        CensusEntry(GLIntOperation::EncryptPublic, Coverage::PublicValuePath, 0, GLIntKeyNone),
        CensusEntry(GLIntOperation::EncryptSecret, Coverage::PublicValuePath, 0, GLIntKeyNone),
        CensusEntry(GLIntOperation::Decrypt, Coverage::PublicValuePath, 0, GLIntKeyNone),
        CensusEntry(GLIntOperation::ModSwitch, Coverage::InternalOnly, 1, GLIntKeyNone),
        CensusEntry(GLIntOperation::Add, Coverage::PublicValuePath, 0, GLIntKeyNone),
        CensusEntry(GLIntOperation::Subtract, Coverage::PublicValuePath, 0, GLIntKeyNone),
        CensusEntry(GLIntOperation::Negate, Coverage::PublicValuePath, 0, GLIntKeyNone),
        CensusEntry(GLIntOperation::Hadamard, Coverage::PublicValuePath, 1,
                    GLIntKeySmallRelinearize),
        CensusEntry(GLIntOperation::RowRotate, Coverage::PublicValuePath, 0,
                    GLIntKeyXYAutomorphism),
        CensusEntry(GLIntOperation::ColumnRotate, Coverage::PublicValuePath, 0, GLIntKeyNone),
        CensusEntry(GLIntOperation::InterMatrixRotate, Coverage::NotApplicable, 0,
                    GLIntKeyWAutomorphism),
        CensusEntry(GLIntOperation::ConjugationSwap, Coverage::PublicValuePath, 0,
                    GLIntKeyXYAutomorphism),
        CensusEntry(GLIntOperation::Transpose, Coverage::PublicValuePath, 0,
                    GLIntKeyBigTransposeK3),
        CensusEntry(GLIntOperation::Adjoint, Coverage::PublicValuePath, 0,
                    GLIntKeyBigConjugateK1),
        CensusEntry(GLIntOperation::CircledastPlain, Coverage::PublicValuePath, 1, GLIntKeyNone),
        CensusEntry(GLIntOperation::MatrixMultiplyPlain, Coverage::PublicValuePath, 1,
                    GLIntKeyNone),
        CensusEntry(GLIntOperation::CircledastCipher, Coverage::PublicValuePath, 1,
                    GLIntKeyBigConjugateK1 | GLIntKeyBigProductK2),
        CensusEntry(GLIntOperation::MatrixMultiplyCipher, Coverage::PublicValuePath, 1,
                    GLIntKeyBigConjugateK1 | GLIntKeyBigProductK2),
        CensusEntry(GLIntOperation::BootstrapRows, Coverage::Missing, 0, GLIntKeyBootstrap),
        CensusEntry(GLIntOperation::SerializeAggregate, Coverage::Missing, 0, GLIntKeyNone, false),
    }};
}

/**
 * The OpenFHE RootOfUnity rule for power-of-two order: the MINIMUM primitive
 * order-th root of unity mod the prime t ("minimum root ... to avoid
 * different crypto contexts having different roots").  Returns 0 when none
 * exists (unreachable after parameter validation; the caller fails closed).
 */
uint64_t MinimumPrimitiveRootModT(uint64_t order, uint64_t modulus) {
    for (uint64_t candidate = 2; candidate < modulus; ++candidate) {
        if (PowModT(candidate, order, modulus) == 1 && PowModT(candidate, order / 2, modulus) != 1) {
            return candidate;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Clear-side plaintext transforms (matrix pairs over Z_t).
// ---------------------------------------------------------------------------

GLIntPlaintext TransposeBranches(const GLIntPlaintext& plaintext) {
    const auto& geometry = plaintext.GetGeometry();
    const auto n         = geometry.GetDimension();
    std::vector<int64_t> plus(geometry.GetCellCount());
    std::vector<int64_t> minus(geometry.GetCellCount());
    for (std::size_t row = 0; row < n; ++row) {
        for (std::size_t column = 0; column < n; ++column) {
            plus[row * n + column]  = plaintext.AtPlus(column, row);
            minus[row * n + column] = plaintext.AtMinus(column, row);
        }
    }
    return GLIntPlaintext(geometry, plaintext.GetModulus(), std::move(plus), std::move(minus));
}

/**
 * The clear adjoint-analog (I,X,Y) -> (I^{-1},Y^{-1},X^{-1}) on a plaintext
 * pair: branch swap plus per-branch transpose, (V+,V-) -> (V-^T, V+^T).
 * Entries are plain Z_t scalars, so no entrywise change occurs.
 */
GLIntPlaintext AdjointIntPlaintext(const GLIntPlaintext& plaintext) {
    const auto& geometry = plaintext.GetGeometry();
    const auto n         = geometry.GetDimension();
    std::vector<int64_t> plus(geometry.GetCellCount());
    std::vector<int64_t> minus(geometry.GetCellCount());
    for (std::size_t row = 0; row < n; ++row) {
        for (std::size_t column = 0; column < n; ++column) {
            plus[row * n + column]  = plaintext.AtMinus(column, row);
            minus[row * n + column] = plaintext.AtPlus(column, row);
        }
    }
    return GLIntPlaintext(geometry, plaintext.GetModulus(), std::move(plus), std::move(minus));
}

// ---------------------------------------------------------------------------
// Coefficient-domain kernels: the complex port's W-free GL kernels verbatim,
// running on BGV DCRT towers.  With native ring dimension 2n, COEFFICIENT
// degrees x and x+n are the two lanes of one Gaussian coefficient (real at x,
// imaginary at x+n); DCRTPoly::Transpose() is the T -> T^{-1} automorphism.
// ---------------------------------------------------------------------------

std::vector<DCRTPoly> NativeCircledastComponentRowsInt(const std::vector<DCRTPoly>& leftRows,
                                                       const std::vector<DCRTPoly>& rightRows,
                                                       std::size_t n) {
    if (leftRows.size() != n || rightRows.size() != n) {
        throw GLDimensionError("integer GL trace requires exactly n component rows");
    }
    if (leftRows.empty()) {
        throw GLDimensionError("integer GL trace requires nonempty component rows");
    }

    const auto params = leftRows.front().GetParams();
    if (!params || params->GetRingDimension() != 2 * n) {
        throw GLNativeModeError("integer GL trace requires DCRT ring dimension 2n");
    }
    const auto towerCount = leftRows.front().GetNumOfElements();

    std::vector<DCRTPoly> leftCoefficientRows;
    leftCoefficientRows.reserve(n);
    std::vector<DCRTPoly> rightInverseRows;
    rightInverseRows.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        if (leftRows[row].GetNumOfElements() != towerCount ||
            rightRows[row].GetNumOfElements() != towerCount ||
            leftRows[row].GetRingDimension() != 2 * n ||
            rightRows[row].GetRingDimension() != 2 * n) {
            throw GLDimensionError(RowMessage("integer GL trace row parameters mismatch", row));
        }

        auto left = leftRows[row];
        left.SetFormat(Format::COEFFICIENT);
        leftCoefficientRows.push_back(std::move(left));

        auto right = rightRows[row];
        right.SetFormat(Format::EVALUATION);
        right = right.Transpose();
        right.SetFormat(Format::COEFFICIENT);
        rightInverseRows.push_back(std::move(right));
    }

    std::vector<DCRTPoly> outputRows;
    outputRows.reserve(n);
    for (std::size_t outputRow = 0; outputRow < n; ++outputRow) {
        outputRows.emplace_back(params, Format::COEFFICIENT, true);
    }

    for (std::size_t towerIndex = 0; towerIndex < towerCount; ++towerIndex) {
        const auto modulus = leftCoefficientRows.front().GetElementAtIndex(towerIndex).GetModulus();
        for (std::size_t outputRow = 0; outputRow < n; ++outputRow) {
            auto outputTower = outputRows[outputRow].GetElementAtIndex(towerIndex);
            for (std::size_t x = 0; x < n; ++x) {
                NativeInteger real(0);
                NativeInteger imag(0);
                for (std::size_t inner = 0; inner < n; ++inner) {
                    const auto& leftTower  = leftCoefficientRows[inner].GetElementAtIndex(towerIndex);
                    const auto& rightTower = rightInverseRows[inner].GetElementAtIndex(towerIndex);
                    const auto& leftReal   = leftTower[x];
                    const auto& leftImag   = leftTower[x + n];
                    const auto& rightReal  = rightTower[outputRow];
                    const auto& rightImag  = rightTower[outputRow + n];

                    const auto productReal = leftReal.ModMul(rightReal, modulus)
                                                 .ModSub(leftImag.ModMul(rightImag, modulus), modulus);
                    const auto productImag = leftReal.ModMul(rightImag, modulus)
                                                 .ModAdd(leftImag.ModMul(rightReal, modulus), modulus);
                    real = real.ModAdd(productReal, modulus);
                    imag = imag.ModAdd(productImag, modulus);
                }
                outputTower[x]     = real;
                outputTower[x + n] = imag;
            }
            outputRows[outputRow].SetElementAtIndex(towerIndex, std::move(outputTower));
        }
    }

    for (auto& row : outputRows) {
        row.SetFormat(Format::EVALUATION);
    }
    return outputRows;
}

void MultiplyRowsByExactIntegerInt(std::vector<DCRTPoly>& rows, int64_t factor) {
    for (auto& row : rows) {
        row = row.Times(factor);
    }
}

DCRTPoly GaussianConstantFromCoefficientInt(const DCRTPoly& coefficientPolynomial,
                                            std::size_t coefficient, std::size_t n) {
    auto source = coefficientPolynomial;
    source.SetFormat(Format::COEFFICIENT);
    DCRTPoly result(source.GetParams(), Format::COEFFICIENT, true);
    for (std::size_t towerIndex = 0; towerIndex < source.GetNumOfElements(); ++towerIndex) {
        const auto& sourceTower = source.GetElementAtIndex(towerIndex);
        auto resultTower        = result.GetElementAtIndex(towerIndex);
        resultTower[0] = sourceTower[coefficient];
        resultTower[n] = sourceTower[coefficient + n];
        result.SetElementAtIndex(towerIndex, std::move(resultTower));
    }
    result.SetFormat(Format::EVALUATION);
    return result;
}

DCRTPoly NativeGaussianIInt(const std::shared_ptr<DCRTPoly::Params>& params, std::size_t n) {
    DCRTPoly result(params, Format::COEFFICIENT, true);
    for (std::size_t towerIndex = 0; towerIndex < result.GetNumOfElements(); ++towerIndex) {
        auto tower = result.GetElementAtIndex(towerIndex);
        tower[n]   = NativeInteger(1);
        result.SetElementAtIndex(towerIndex, std::move(tower));
    }
    result.SetFormat(Format::EVALUATION);
    return result;
}

std::vector<DCRTPoly> NativeAdjointComponentRowsInt(const std::vector<DCRTPoly>& inputRows,
                                                    std::size_t n) {
    if (inputRows.size() != n || inputRows.empty()) {
        throw GLDimensionError("integer GL adjoint requires exactly n component rows");
    }
    const auto params = inputRows.front().GetParams();
    if (!params || params->GetRingDimension() != 2 * n) {
        throw GLNativeModeError("integer GL adjoint requires DCRT ring dimension 2n");
    }

    std::vector<DCRTPoly> coefficientRows;
    coefficientRows.reserve(n);
    for (const auto& input : inputRows) {
        auto coefficient = input;
        coefficient.SetFormat(Format::COEFFICIENT);
        coefficientRows.push_back(std::move(coefficient));
    }

    std::vector<DCRTPoly> outputRows;
    outputRows.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        outputRows.emplace_back(params, Format::COEFFICIENT, true);
    }

    const auto inverseIndex = [n](std::size_t index) {
        return index == 0 ? std::size_t{0} : n - index;
    };
    for (std::size_t towerIndex = 0; towerIndex < inputRows.front().GetNumOfElements(); ++towerIndex) {
        const auto modulus = coefficientRows.front().GetElementAtIndex(towerIndex).GetModulus();
        const NativeInteger zero(0);
        std::vector<NativePoly> outputTowers;
        outputTowers.reserve(n);
        for (std::size_t row = 0; row < n; ++row) {
            outputTowers.push_back(outputRows[row].GetElementAtIndex(towerIndex));
        }

        for (std::size_t inputRow = 0; inputRow < n; ++inputRow) {
            const auto& inputTower = coefficientRows[inputRow].GetElementAtIndex(towerIndex);
            for (std::size_t x = 0; x < n; ++x) {
                const auto& real        = inputTower[x];
                const auto& imag        = inputTower[x + n];
                const auto negativeReal = zero.ModSub(real, modulus);
                const auto negativeImag = zero.ModSub(imag, modulus);
                const auto twistCount   = (inputRow == 0 ? 0U : 1U) + (x == 0 ? 0U : 1U);

                NativeInteger outputReal;
                NativeInteger outputImag;
                if (twistCount == 0) {
                    outputReal = real;
                    outputImag = negativeImag;
                }
                else if (twistCount == 1) {
                    outputReal = negativeImag;
                    outputImag = negativeReal;
                }
                else {
                    outputReal = negativeReal;
                    outputImag = imag;
                }

                const auto outputRow = inverseIndex(x);
                const auto outputX   = inverseIndex(inputRow);
                outputTowers[outputRow][outputX]     = outputReal;
                outputTowers[outputRow][outputX + n] = outputImag;
            }
        }
        for (std::size_t row = 0; row < n; ++row) {
            outputRows[row].SetElementAtIndex(towerIndex, std::move(outputTowers[row]));
        }
    }

    for (auto& row : outputRows) {
        row.SetFormat(Format::EVALUATION);
    }
    return outputRows;
}

/**
 * Step 1 of the native integer GL transpose: the pure public coefficient
 * relabeling p'(X,Y) = p(Y,X) on one R' component.  Gaussian coefficient x
 * of new row y' equals Gaussian coefficient y' of old row x; both T-lanes
 * move together, all degrees stay below n, so no wrap units appear.
 */
std::vector<DCRTPoly> NativeTransposeComponentRowsInt(const std::vector<DCRTPoly>& inputRows,
                                                      std::size_t n) {
    if (inputRows.size() != n || inputRows.empty()) {
        throw GLDimensionError("integer GL transpose requires exactly n component rows");
    }
    const auto params = inputRows.front().GetParams();
    if (!params || params->GetRingDimension() != 2 * n) {
        throw GLNativeModeError("integer GL transpose requires DCRT ring dimension 2n");
    }

    std::vector<DCRTPoly> coefficientRows;
    coefficientRows.reserve(n);
    for (const auto& input : inputRows) {
        auto coefficient = input;
        coefficient.SetFormat(Format::COEFFICIENT);
        coefficientRows.push_back(std::move(coefficient));
    }

    std::vector<DCRTPoly> outputRows;
    outputRows.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        outputRows.emplace_back(params, Format::COEFFICIENT, true);
    }

    for (std::size_t towerIndex = 0; towerIndex < inputRows.front().GetNumOfElements(); ++towerIndex) {
        std::vector<NativePoly> outputTowers;
        outputTowers.reserve(n);
        for (std::size_t row = 0; row < n; ++row) {
            outputTowers.push_back(outputRows[row].GetElementAtIndex(towerIndex));
        }
        for (std::size_t inputRow = 0; inputRow < n; ++inputRow) {
            const auto& inputTower = coefficientRows[inputRow].GetElementAtIndex(towerIndex);
            for (std::size_t coefficient = 0; coefficient < n; ++coefficient) {
                outputTowers[coefficient][inputRow]     = inputTower[coefficient];
                outputTowers[coefficient][inputRow + n] = inputTower[coefficient + n];
            }
        }
        for (std::size_t row = 0; row < n; ++row) {
            outputRows[row].SetElementAtIndex(towerIndex, std::move(outputTowers[row]));
        }
    }

    for (auto& row : outputRows) {
        row.SetFormat(Format::EVALUATION);
    }
    return outputRows;
}

struct IntSwitchedRows {
    std::vector<DCRTPoly> b;
    std::vector<DCRTPoly> a;
};

IntSwitchedRows NativeBigSwitchInt(const CryptoContext<DCRTPoly>& context,
                                   const std::vector<DCRTPoly>& sourceRows,
                                   const std::vector<EvalKey<DCRTPoly>>& evaluationKeyRows,
                                   std::size_t n) {
    if (sourceRows.size() != n || evaluationKeyRows.size() != n || sourceRows.empty()) {
        throw GLDimensionError("integer GL big switch requires n source and evaluation-key rows");
    }
    const auto params    = sourceRows.front().GetParams();
    const auto gaussianI = NativeGaussianIInt(params, n);

    IntSwitchedRows result;
    result.b.reserve(n);
    result.a.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        result.b.emplace_back(params, Format::EVALUATION, true);
        result.a.emplace_back(params, Format::EVALUATION, true);
    }

    for (std::size_t sourceRow = 0; sourceRow < n; ++sourceRow) {
        for (std::size_t keyRow = 0; keyRow < n; ++keyRow) {
            auto switched = context->GetScheme()->KeySwitchCore(sourceRows[sourceRow],
                                                                evaluationKeyRows[keyRow]);
            if (!switched || switched->size() != 2) {
                throw GLCiphertextError(
                    "OpenFHE integer GL big key switch returned an invalid component pair");
            }

            auto switchedB      = std::move((*switched)[0]);
            auto switchedA      = std::move((*switched)[1]);
            const auto exponent = sourceRow + keyRow;
            if (exponent >= n) {
                switchedB *= gaussianI;
                switchedA *= gaussianI;
            }
            const auto outputRow = exponent % n;
            result.b[outputRow] += switchedB;
            result.a[outputRow] += switchedA;
        }
    }
    return result;
}

/** Rows of one aggregate must share level/degree/tower metadata before they may mix. */
void RequireUniformRowMetadataInt(const GLIntCiphertext& ciphertext, const char* operation) {
    const auto& first = ciphertext.GetRows().front();
    for (std::size_t row = 1; row < ciphertext.GetRows().size(); ++row) {
        const auto& current = ciphertext.GetRows()[row];
        if (current->GetLevel() != first->GetLevel() ||
            current->GetNoiseScaleDeg() != first->GetNoiseScaleDeg() ||
            current->GetElements().front().GetNumOfElements() !=
                first->GetElements().front().GetNumOfElements()) {
            throw GLCiphertextError(
                RowMessage((std::string(operation) + " row metadata mismatch").c_str(), row));
        }
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// Allocation-free p>1 / W-batched parameter and coverage census
// ---------------------------------------------------------------------------

GLIntWBatchedParameters GLIntWBatchedParameters::GL128257N32(uint64_t plaintextModulus,
                                                             uint32_t multiplicativeDepth) {
    GLIntWBatchedParameters parameters;
    parameters.dimension           = 128;
    parameters.cyclotomicPrime     = 257;
    parameters.wGenerator          = 3;
    parameters.plaintextModulus    = plaintextModulus;
    parameters.multiplicativeDepth = multiplicativeDepth;
    parameters.nativeRnsWordBits   = 32;
    return parameters;
}

GLIntWBatchedParameters GLIntWBatchedParameters::ConformanceN4P3T97(
    uint32_t multiplicativeDepth) {
    GLIntWBatchedParameters parameters;
    parameters.dimension           = 4;
    parameters.cyclotomicPrime     = 3;
    parameters.wGenerator          = 2;
    parameters.plaintextModulus    = 97;
    parameters.multiplicativeDepth = multiplicativeDepth;
    parameters.nativeRnsWordBits   = 32;
    return parameters;
}

void GLIntWBatchedParameters::Validate() const {
    if (!IsPowerOfTwoIntCensus(dimension)) {
        throw GLDimensionError("GL integer W-batched mode requires power-of-two n");
    }
    if (dimension < 2) {
        throw GLDimensionError("GL integer W-batched mode requires n >= 2");
    }
    if (multiplicativeDepth < 1) {
        throw GLDepthError("GL integer W-batched mode requires multiplicativeDepth >= 1");
    }
    if (nativeRnsWordBits != 32 && nativeRnsWordBits != 64) {
        throw GLIntParameterError("GL integer W-batched census requires a 32- or 64-bit RNS width");
    }
    if (cyclotomicPrime < 3 || cyclotomicPrime % 2 == 0 || !IsSmallPrime(cyclotomicPrime)) {
        throw GLIntParameterError("GL integer W-batched mode requires an odd prime p");
    }
    if (!IsGeneratorModPrime(wGenerator, cyclotomicPrime)) {
        throw GLIntParameterError("GL integer W-batched mode requires gamma to generate Z_p^*");
    }
    if (plaintextModulus < 3 || plaintextModulus >= (uint64_t{1} << 32) ||
        !IsSmallPrime(plaintextModulus)) {
        throw GLIntParameterError(
            "GL integer W-batched census requires a prime plaintext modulus t below 2^32");
    }

    const auto fourN = CheckedMultiply(4, dimension, "4n root order");
    const auto order = CheckedMultiply(fourN, cyclotomicPrime, "4np root order");
    if (plaintextModulus % order != 1) {
        std::ostringstream os;
        os << "GL integer W-batched mode requires t = 1 (mod 4np); got t="
           << plaintextModulus << ", 4np=" << order;
        throw GLIntParameterError(os.str());
    }
}

bool GLIntWBatchedParameters::IsGL128257N32Geometry() const noexcept {
    return dimension == 128 && cyclotomicPrime == 257 && wGenerator == 3 &&
           nativeRnsWordBits == 32;
}

bool GLIntWBatchedParameters::IsConformanceN4P3T97() const noexcept {
    return dimension == 4 && cyclotomicPrime == 3 && wGenerator == 2 &&
           plaintextModulus == 97 && nativeRnsWordBits == 32;
}

GLIntWBatchedCensus MakeGLIntWBatchedCensus(const GLIntWBatchedParameters& parameters) {
    parameters.Validate();

    GLIntWBatchedCensus census;
    census.parameters    = parameters;
    census.phi           = static_cast<uint64_t>(parameters.cyclotomicPrime) - 1;
    census.rootOrder     = CheckedMultiply(
        CheckedMultiply(4, parameters.dimension, "4n root order"),
        parameters.cyclotomicPrime, "4np root order");
    census.rowRingDimension = CheckedMultiply(
        CheckedMultiply(2, parameters.dimension, "2n row dimension"), census.phi,
        "2n*phi(p) row dimension");
    census.ciphertextRowCount = parameters.dimension;
    census.matrixCount        = CheckedMultiply(2, census.phi, "2*phi(p) matrix count");
    census.matrixCellCount    = CheckedMultiply(parameters.dimension, parameters.dimension,
                                                "n*n matrix cell count");
    census.aggregatePlaintextValueCount = CheckedMultiply(
        census.matrixCount, census.matrixCellCount, "aggregate plaintext value count");
    census.gaussianCoefficientCount = CheckedMultiply(
        census.matrixCellCount, census.phi, "Gaussian coefficient count");
    census.encodedCoefficientStorageBytes = CheckedMultiply(
        census.gaussianCoefficientCount, sizeof(GLIntGaussianResidue),
        "encoded Gaussian coefficient storage bytes");
    census.decodedBranchPairStorageBytes = CheckedMultiply(
        census.aggregatePlaintextValueCount, sizeof(int64_t),
        "decoded branch storage bytes");
    const auto rowRepresentationValueCount = CheckedMultiply(
        census.rowRingDimension, census.ciphertextRowCount,
        "row-representation plaintext value count");
    if (rowRepresentationValueCount != census.aggregatePlaintextValueCount) {
        throw GLIntParameterError(
            "GL integer W-batched row representation does not match 2*phi(p) matrix payload");
    }

    census.nonIdentityRowRotations         = parameters.dimension - 1;
    census.nonIdentityColumnRotations      = parameters.dimension - 1;
    census.nonIdentityInterMatrixRotations = census.phi - 1;
    census.independentRowBootstrapCount   = parameters.dimension;
    census.operations                     = WFreeOperationCensus();
    if (parameters.IsConformanceN4P3T97()) {
        census.boundedPlaintextCodecImplemented = true;
        census.operations[static_cast<std::size_t>(GLIntOperation::Encode)]
            .boundedPlaintextPathImplemented = true;
        census.operations[static_cast<std::size_t>(GLIntOperation::Decode)]
            .boundedPlaintextPathImplemented = true;
        census.operations[static_cast<std::size_t>(GLIntOperation::InterMatrixRotate)]
            .boundedPlaintextPathImplemented = true;
    }
    return census;
}

// ---------------------------------------------------------------------------
// Exact n=4,p=3,t=97 W-batched plaintext codec
// ---------------------------------------------------------------------------

GLIntWBatchedCodecRoots GLIntWBatchedCodecRoots::Pinned(
    const GLIntWBatchedParameters& parameters) {
    RequireConformanceWBatchedCodec(parameters);
    GLIntWBatchedCodecRoots roots;
    roots.zeta = MinimumElementOfOrder(4 * parameters.dimension, parameters.plaintextModulus);
    roots.eta  = MinimumElementOfOrder(parameters.cyclotomicPrime, parameters.plaintextModulus);
    if (roots.zeta == 0 || roots.eta == 0) {
        throw GLIntParameterError("GL integer W-batched codec could not find its pinned roots");
    }
    roots.Validate(parameters);
    return roots;
}

void GLIntWBatchedCodecRoots::Validate(const GLIntWBatchedParameters& parameters) const {
    parameters.Validate();
    const auto t          = parameters.plaintextModulus;
    const auto zetaOrder  = CheckedMultiply(4, parameters.dimension, "codec zeta order");
    if (!HasExactMultiplicativeOrder(zeta, zetaOrder, t)) {
        throw GLIntParameterError(
            "GL integer W-batched codec zeta does not have exact order 4n mod t");
    }
    if (!HasExactMultiplicativeOrder(eta, parameters.cyclotomicPrime, t)) {
        throw GLIntParameterError(
            "GL integer W-batched codec eta does not have exact order p mod t");
    }
    const auto gaussianUnit = PowModT(zeta, parameters.dimension, t);
    if (MulModT(gaussianUnit, gaussianUnit, t) != t - 1) {
        throw GLIntParameterError(
            "GL integer W-batched codec zeta^n does not square to -1 mod t");
    }
}

bool GLIntWBatchedCodecRoots::operator==(const GLIntWBatchedCodecRoots& other) const noexcept {
    return zeta == other.zeta && eta == other.eta;
}

bool GLIntWBatchedCodecRoots::operator!=(const GLIntWBatchedCodecRoots& other) const noexcept {
    return !(*this == other);
}

GLIntWBatchedPlaintext::GLIntWBatchedPlaintext(GLIntWBatchedParameters parameters,
                                               std::vector<int64_t> plusValues,
                                               std::vector<int64_t> minusValues)
    : m_parameters(std::move(parameters)),
      m_plusValues(std::move(plusValues)),
      m_minusValues(std::move(minusValues)) {
    RequireConformanceWBatchedCodec(m_parameters);
    const auto t = m_parameters.plaintextModulus;
    for (auto& value : m_plusValues) {
        value = CanonicalModT(value, t);
    }
    for (auto& value : m_minusValues) {
        value = CanonicalModT(value, t);
    }
    Validate();
}

const GLIntWBatchedParameters& GLIntWBatchedPlaintext::GetParameters() const noexcept {
    return m_parameters;
}

const std::vector<int64_t>& GLIntWBatchedPlaintext::GetValues(GLIntBranch branch) const noexcept {
    return branch == GLIntBranch::Plus ? m_plusValues : m_minusValues;
}

int64_t GLIntWBatchedPlaintext::At(GLIntBranch branch, std::size_t matrix, std::size_t row,
                                   std::size_t column) const {
    const auto n   = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi = static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    if (matrix >= phi || row >= n || column >= n) {
        throw GLDimensionError("GL integer W-batched plaintext index is outside its matrix batch");
    }
    return GetValues(branch)[WBatchedValueIndex(n, matrix, row, column)];
}

void GLIntWBatchedPlaintext::Validate() const {
    RequireConformanceWBatchedCodec(m_parameters);
    const auto n        = static_cast<uint64_t>(m_parameters.dimension);
    const auto phi      = static_cast<uint64_t>(m_parameters.cyclotomicPrime - 1);
    const auto expected = CheckedMultiply(CheckedMultiply(n, n, "plaintext n*n cells"), phi,
                                          "plaintext branch values");
    if (m_plusValues.size() != expected || m_minusValues.size() != expected) {
        throw GLDimensionError("GL integer W-batched plaintext requires phi(p)*n*n values per branch");
    }
    for (const auto* values : {&m_plusValues, &m_minusValues}) {
        for (const auto value : *values) {
            if (value < 0 || static_cast<uint64_t>(value) >= m_parameters.plaintextModulus) {
                throw GLIntParameterError(
                    "GL integer W-batched plaintext contains a noncanonical residue");
            }
        }
    }
}

GLIntWBatchedEncodedPlaintext::GLIntWBatchedEncodedPlaintext(
    GLIntWBatchedParameters parameters, GLIntWBatchedCodecRoots roots,
    std::vector<GLIntGaussianResidue> coefficients)
    : m_parameters(std::move(parameters)),
      m_roots(std::move(roots)),
      m_coefficients(std::move(coefficients)) {
    RequireConformanceWBatchedCodec(m_parameters);
    m_roots.Validate(m_parameters);
    const auto t = m_parameters.plaintextModulus;
    for (auto& coefficient : m_coefficients) {
        coefficient.real      = CanonicalModT(coefficient.real, t);
        coefficient.imaginary = CanonicalModT(coefficient.imaginary, t);
    }
    Validate();
}

const GLIntWBatchedParameters& GLIntWBatchedEncodedPlaintext::GetParameters() const noexcept {
    return m_parameters;
}

const GLIntWBatchedCodecRoots& GLIntWBatchedEncodedPlaintext::GetRoots() const noexcept {
    return m_roots;
}

const std::vector<GLIntGaussianResidue>&
GLIntWBatchedEncodedPlaintext::GetCoefficients() const noexcept {
    return m_coefficients;
}

const GLIntGaussianResidue& GLIntWBatchedEncodedPlaintext::At(std::size_t x, std::size_t y,
                                                              std::size_t w) const {
    const auto n   = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi = static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    if (x >= n || y >= n || w >= phi) {
        throw GLDimensionError("GL integer W-batched coefficient index is outside R'_t");
    }
    return m_coefficients[WBatchedCoefficientIndex(n, phi, x, y, w)];
}

void GLIntWBatchedEncodedPlaintext::Validate() const {
    RequireConformanceWBatchedCodec(m_parameters);
    m_roots.Validate(m_parameters);
    const auto n        = static_cast<uint64_t>(m_parameters.dimension);
    const auto phi      = static_cast<uint64_t>(m_parameters.cyclotomicPrime - 1);
    const auto expected = CheckedMultiply(CheckedMultiply(n, n, "encoded n*n cells"), phi,
                                          "encoded Gaussian coefficients");
    if (m_coefficients.size() != expected) {
        throw GLDimensionError(
            "GL integer W-batched encoded plaintext requires n*n*phi(p) Gaussian coefficients");
    }
    for (const auto& coefficient : m_coefficients) {
        if (coefficient.real < 0 || coefficient.imaginary < 0 ||
            static_cast<uint64_t>(coefficient.real) >= m_parameters.plaintextModulus ||
            static_cast<uint64_t>(coefficient.imaginary) >= m_parameters.plaintextModulus) {
            throw GLIntParameterError(
                "GL integer W-batched encoded plaintext contains a noncanonical residue");
        }
    }
}

GLIntWBatchedPlaintextCodec::GLIntWBatchedPlaintextCodec(GLIntWBatchedParameters parameters)
    : GLIntWBatchedPlaintextCodec(parameters, GLIntWBatchedCodecRoots::Pinned(parameters)) {}

GLIntWBatchedPlaintextCodec::GLIntWBatchedPlaintextCodec(GLIntWBatchedParameters parameters,
                                                         GLIntWBatchedCodecRoots roots)
    : m_parameters(std::move(parameters)), m_roots(std::move(roots)) {
    RequireConformanceWBatchedCodec(m_parameters);
    m_roots.Validate(m_parameters);

    const auto n     = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi   = static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    const auto t     = m_parameters.plaintextModulus;
    const auto order = static_cast<uint64_t>(4 * n);
    const auto invN  = PowModT(n, t - 2, t);
    const auto invP  = PowModT(m_parameters.cyclotomicPrime, t - 2, t);

    m_gaussianUnit        = PowModT(m_roots.zeta, n, t);
    m_inverseGaussianUnit = PowModT(m_gaussianUnit, t - 2, t);
    m_inverseTwo          = PowModT(2, t - 2, t);

    uint64_t exponent = 1;
    for (std::size_t j = 0; j < n; ++j) {
        const auto point        = PowModT(m_roots.zeta, exponent, t);
        const auto inversePoint = PowModT(point, t - 2, t);
        for (std::size_t x = 0; x < n; ++x) {
            m_xPlusEval[j * n + x]  = PowModT(point, x, t);
            m_xMinusEval[j * n + x] = PowModT(inversePoint, x, t);
            m_xPlusInv[x * n + j] = MulModT(invN, PowModT(inversePoint, x, t), t);
            m_xMinusInv[x * n + j] = MulModT(invN, PowModT(point, x, t), t);
        }
        exponent = (exponent * 5) % order;
    }

    exponent = 1;
    for (std::size_t ell = 0; ell < phi; ++ell) {
        const auto plusBase  = PowModT(m_roots.eta, exponent, t);
        const auto minusBase = PowModT(plusBase, t - 2, t);
        for (std::size_t w = 0; w < phi; ++w) {
            m_wPlusEval[ell * phi + w]  = PowModT(plusBase, w, t);
            m_wMinusEval[ell * phi + w] = PowModT(minusBase, w, t);
            // Same exact inverse used by the core RNS W-axis plan:
            // F^-1[w,l] = p^-1(eta_l^-w - eta_l).  The minus lane simply
            // replaces eta with eta^-1, exactly as Eq. (5) requires.
            const auto plusInversePower  = PowModT(plusBase, (t - 1 - w) % (t - 1), t);
            const auto minusInversePower = PowModT(minusBase, (t - 1 - w) % (t - 1), t);
            m_wPlusInv[w * phi + ell] =
                MulModT(invP, SubModT(plusInversePower, plusBase, t), t);
            m_wMinusInv[w * phi + ell] =
                MulModT(invP, SubModT(minusInversePower, minusBase, t), t);
        }
        exponent = (exponent * m_parameters.wGenerator) % m_parameters.cyclotomicPrime;
    }
}

const GLIntWBatchedParameters& GLIntWBatchedPlaintextCodec::GetParameters() const noexcept {
    return m_parameters;
}

const GLIntWBatchedCodecRoots& GLIntWBatchedPlaintextCodec::GetRoots() const noexcept {
    return m_roots;
}

uint64_t GLIntWBatchedPlaintextCodec::GetGaussianUnit() const noexcept {
    return m_gaussianUnit;
}

void GLIntWBatchedPlaintextCodec::ValidatePlaintext(const GLIntWBatchedPlaintext& plaintext,
                                                    const char* objectName) const {
    plaintext.Validate();
    if (!SameWBatchedParameters(m_parameters, plaintext.GetParameters())) {
        throw GLContextMismatchError(std::string(objectName) + " parameters do not match the codec");
    }
}

void GLIntWBatchedPlaintextCodec::ValidateEncoded(
    const GLIntWBatchedEncodedPlaintext& plaintext, const char* objectName) const {
    plaintext.Validate();
    if (!SameWBatchedParameters(m_parameters, plaintext.GetParameters())) {
        throw GLContextMismatchError(std::string(objectName) + " parameters do not match the codec");
    }
    if (m_roots != plaintext.GetRoots()) {
        throw GLContextMismatchError(std::string(objectName) + " roots do not match the codec");
    }
}

GLIntWBatchedEncodedPlaintext GLIntWBatchedPlaintextCodec::Encode(
    const GLIntWBatchedPlaintext& plaintext) const {
    ValidatePlaintext(plaintext, "GL integer W-batched plaintext");
    const auto n   = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi = static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    const auto t   = m_parameters.plaintextModulus;
    const auto coefficientCount = n * n * phi;

    const auto inverseBranch = [&](const std::vector<int64_t>& values,
                                   const std::array<uint64_t, 16>& xInverse,
                                   const std::array<uint64_t, 4>& wInverse) {
        // Reuse the complex codec's separable inverse order W -> Y -> X;
        // every multiply/add here is exact in Z_t rather than approximate.
        std::vector<uint64_t> afterW(coefficientCount, 0);
        std::vector<uint64_t> afterY(coefficientCount, 0);
        std::vector<uint64_t> coefficients(coefficientCount, 0);
        for (std::size_t row = 0; row < n; ++row) {
            for (std::size_t column = 0; column < n; ++column) {
                for (std::size_t w = 0; w < phi; ++w) {
                    uint64_t sum = 0;
                    for (std::size_t ell = 0; ell < phi; ++ell) {
                        const auto value = static_cast<uint64_t>(
                            values[WBatchedValueIndex(n, ell, row, column)]);
                        sum = AddModT(sum, MulModT(wInverse[w * phi + ell], value, t), t);
                    }
                    afterW[WBatchedCoefficientIndex(n, phi, row, column, w)] = sum;
                }
            }
        }
        for (std::size_t row = 0; row < n; ++row) {
            for (std::size_t y = 0; y < n; ++y) {
                for (std::size_t w = 0; w < phi; ++w) {
                    uint64_t sum = 0;
                    for (std::size_t column = 0; column < n; ++column) {
                        sum = AddModT(
                            sum,
                            MulModT(xInverse[y * n + column],
                                    afterW[WBatchedCoefficientIndex(n, phi, row, column, w)], t),
                            t);
                    }
                    afterY[WBatchedCoefficientIndex(n, phi, row, y, w)] = sum;
                }
            }
        }
        for (std::size_t x = 0; x < n; ++x) {
            for (std::size_t y = 0; y < n; ++y) {
                for (std::size_t w = 0; w < phi; ++w) {
                    uint64_t sum = 0;
                    for (std::size_t row = 0; row < n; ++row) {
                        sum = AddModT(
                            sum,
                            MulModT(xInverse[x * n + row],
                                    afterY[WBatchedCoefficientIndex(n, phi, row, y, w)], t),
                            t);
                    }
                    coefficients[WBatchedCoefficientIndex(n, phi, x, y, w)] = sum;
                }
            }
        }
        return coefficients;
    };

    const auto plus = inverseBranch(plaintext.GetValues(GLIntBranch::Plus), m_xPlusInv,
                                    m_wPlusInv);
    const auto minus = inverseBranch(plaintext.GetValues(GLIntBranch::Minus), m_xMinusInv,
                                     m_wMinusInv);
    std::vector<GLIntGaussianResidue> coefficients(coefficientCount);
    for (std::size_t index = 0; index < coefficientCount; ++index) {
        const auto real = MulModT(AddModT(plus[index], minus[index], t), m_inverseTwo, t);
        const auto difference = SubModT(plus[index], minus[index], t);
        const auto imaginary =
            MulModT(MulModT(difference, m_inverseTwo, t), m_inverseGaussianUnit, t);
        coefficients[index] =
            GLIntGaussianResidue{static_cast<int64_t>(real), static_cast<int64_t>(imaginary)};
    }
    return GLIntWBatchedEncodedPlaintext(m_parameters, m_roots, std::move(coefficients));
}

GLIntWBatchedPlaintext GLIntWBatchedPlaintextCodec::Decode(
    const GLIntWBatchedEncodedPlaintext& plaintext) const {
    ValidateEncoded(plaintext, "GL integer W-batched encoded plaintext");
    const auto n   = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi = static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    const auto t   = m_parameters.plaintextModulus;
    const auto coefficientCount = n * n * phi;

    std::vector<uint64_t> plusCoefficients(coefficientCount);
    std::vector<uint64_t> minusCoefficients(coefficientCount);
    for (std::size_t index = 0; index < coefficientCount; ++index) {
        const auto real = static_cast<uint64_t>(plaintext.GetCoefficients()[index].real);
        const auto imaginary =
            static_cast<uint64_t>(plaintext.GetCoefficients()[index].imaginary);
        const auto iImaginary = MulModT(m_gaussianUnit, imaginary, t);
        plusCoefficients[index]  = AddModT(real, iImaginary, t);
        minusCoefficients[index] = SubModT(real, iImaginary, t);
    }

    const auto forwardBranch = [&](const std::vector<uint64_t>& coefficients,
                                   const std::array<uint64_t, 16>& xEvaluation,
                                   const std::array<uint64_t, 4>& wEvaluation) {
        std::vector<uint64_t> afterX(coefficientCount, 0);
        std::vector<uint64_t> afterY(coefficientCount, 0);
        std::vector<int64_t> values(coefficientCount, 0);
        for (std::size_t row = 0; row < n; ++row) {
            for (std::size_t y = 0; y < n; ++y) {
                for (std::size_t w = 0; w < phi; ++w) {
                    uint64_t sum = 0;
                    for (std::size_t x = 0; x < n; ++x) {
                        sum = AddModT(
                            sum,
                            MulModT(xEvaluation[row * n + x],
                                    coefficients[WBatchedCoefficientIndex(n, phi, x, y, w)], t),
                            t);
                    }
                    afterX[WBatchedCoefficientIndex(n, phi, row, y, w)] = sum;
                }
            }
        }
        for (std::size_t row = 0; row < n; ++row) {
            for (std::size_t column = 0; column < n; ++column) {
                for (std::size_t w = 0; w < phi; ++w) {
                    uint64_t sum = 0;
                    for (std::size_t y = 0; y < n; ++y) {
                        sum = AddModT(
                            sum,
                            MulModT(xEvaluation[column * n + y],
                                    afterX[WBatchedCoefficientIndex(n, phi, row, y, w)], t),
                            t);
                    }
                    afterY[WBatchedCoefficientIndex(n, phi, row, column, w)] = sum;
                }
            }
        }
        for (std::size_t ell = 0; ell < phi; ++ell) {
            for (std::size_t row = 0; row < n; ++row) {
                for (std::size_t column = 0; column < n; ++column) {
                    uint64_t sum = 0;
                    for (std::size_t w = 0; w < phi; ++w) {
                        sum = AddModT(
                            sum,
                            MulModT(wEvaluation[ell * phi + w],
                                    afterY[WBatchedCoefficientIndex(n, phi, row, column, w)], t),
                            t);
                    }
                    values[WBatchedValueIndex(n, ell, row, column)] = static_cast<int64_t>(sum);
                }
            }
        }
        return values;
    };

    auto plus  = forwardBranch(plusCoefficients, m_xPlusEval, m_wPlusEval);
    auto minus = forwardBranch(minusCoefficients, m_xMinusEval, m_wMinusEval);
    return GLIntWBatchedPlaintext(m_parameters, std::move(plus), std::move(minus));
}

GLIntWBatchedPlaintext GLIntWBatchedPlaintextCodec::RotateInterMatrix(
    const GLIntWBatchedPlaintext& plaintext, std::size_t amount) const {
    ValidatePlaintext(plaintext, "GL integer W-batched plaintext");
    const auto n   = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi = static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    if (amount >= phi) {
        throw GLDimensionError("GL integer W-batched inter-matrix rotation amount is out of range");
    }
    std::vector<int64_t> plus(phi * n * n);
    std::vector<int64_t> minus(phi * n * n);
    for (std::size_t ell = 0; ell < phi; ++ell) {
        const auto source = (ell + amount) % phi;
        for (std::size_t row = 0; row < n; ++row) {
            for (std::size_t column = 0; column < n; ++column) {
                plus[WBatchedValueIndex(n, ell, row, column)] =
                    plaintext.At(GLIntBranch::Plus, source, row, column);
                minus[WBatchedValueIndex(n, ell, row, column)] =
                    plaintext.At(GLIntBranch::Minus, source, row, column);
            }
        }
    }
    return GLIntWBatchedPlaintext(m_parameters, std::move(plus), std::move(minus));
}

GLIntWBatchedEncodedPlaintext GLIntWBatchedPlaintextCodec::ApplyWAutomorphism(
    const GLIntWBatchedEncodedPlaintext& plaintext, std::size_t amount) const {
    ValidateEncoded(plaintext, "GL integer W-batched encoded plaintext");
    const auto n   = static_cast<std::size_t>(m_parameters.dimension);
    const auto p   = static_cast<std::size_t>(m_parameters.cyclotomicPrime);
    const auto phi = p - 1;
    const auto t   = m_parameters.plaintextModulus;
    if (amount >= phi) {
        throw GLDimensionError("GL integer W-batched W-automorphism amount is out of range");
    }
    const auto multiplier = PowModT(m_parameters.wGenerator, amount, p);
    std::vector<GLIntGaussianResidue> output(n * n * phi);
    const auto add = [t](GLIntGaussianResidue& destination,
                         const GLIntGaussianResidue& source) {
        destination.real = static_cast<int64_t>(AddModT(
            static_cast<uint64_t>(destination.real), static_cast<uint64_t>(source.real), t));
        destination.imaginary = static_cast<int64_t>(AddModT(
            static_cast<uint64_t>(destination.imaginary),
            static_cast<uint64_t>(source.imaginary), t));
    };
    const auto subtract = [t](GLIntGaussianResidue& destination,
                              const GLIntGaussianResidue& source) {
        destination.real = static_cast<int64_t>(SubModT(
            static_cast<uint64_t>(destination.real), static_cast<uint64_t>(source.real), t));
        destination.imaginary = static_cast<int64_t>(SubModT(
            static_cast<uint64_t>(destination.imaginary),
            static_cast<uint64_t>(source.imaginary), t));
    };

    for (std::size_t x = 0; x < n; ++x) {
        for (std::size_t y = 0; y < n; ++y) {
            for (std::size_t w = 0; w < phi; ++w) {
                const auto& source = plaintext.At(x, y, w);
                const auto exponent = (w * multiplier) % p;
                if (exponent < phi) {
                    add(output[WBatchedCoefficientIndex(n, phi, x, y, exponent)], source);
                }
                else {
                    // W^(p-1) = -(1+W+...+W^(p-2)) modulo Phi_p(W).
                    for (std::size_t target = 0; target < phi; ++target) {
                        subtract(output[WBatchedCoefficientIndex(n, phi, x, y, target)], source);
                    }
                }
            }
        }
    }
    return GLIntWBatchedEncodedPlaintext(m_parameters, m_roots, std::move(output));
}

// ---------------------------------------------------------------------------
// GLIntParameters
// ---------------------------------------------------------------------------

GLGeometry GLIntParameters::GetGeometry() const {
    if (dimension != 4 && dimension != 8) {
        throw GLDimensionError("GL integer conformance supports only n=4 or n=8");
    }
    return GLGeometry(dimension);
}

void GLIntParameters::Validate() const {
    if (dimension != 4 && dimension != 8) {
        throw GLDimensionError("GL integer conformance supports only n=4 or n=8");
    }
    const GLGeometry geometry(dimension);
    if (multiplicativeDepth < 1) {
        throw GLDepthError("GL integer mode requires multiplicativeDepth >= 1");
    }
    if (plaintextModulus >= (uint64_t{1} << 32)) {
        throw GLIntParameterError(
            "GL integer mode is a toy conformance slice and requires a plaintext modulus below 2^32");
    }
    if (plaintextModulus < 3 || !IsSmallPrime(plaintextModulus)) {
        throw GLIntParameterError("GL integer mode requires a prime plaintext modulus");
    }
    const auto order = static_cast<uint64_t>(geometry.GetNativeCyclotomicOrder());
    if (plaintextModulus % order != 1) {
        std::ostringstream os;
        os << "GL integer mode requires t = 1 (mod 4n); got t=" << plaintextModulus
           << ", 4n=" << order;
        throw GLIntParameterError(os.str());
    }
}

// ---------------------------------------------------------------------------
// GLIntPlaintext
// ---------------------------------------------------------------------------

GLIntPlaintext::GLIntPlaintext(GLGeometry geometry, uint64_t plaintextModulus,
                               std::vector<int64_t> plusValues, std::vector<int64_t> minusValues)
    : m_geometry(std::move(geometry)),
      m_modulus(plaintextModulus),
      m_plusValues(std::move(plusValues)),
      m_minusValues(std::move(minusValues)) {
    if (m_modulus < 3 || m_modulus >= (uint64_t{1} << 32)) {
        throw GLIntParameterError("GL integer plaintext requires a toy modulus in [3, 2^32)");
    }
    if (m_plusValues.size() != m_geometry.GetCellCount() ||
        m_minusValues.size() != m_geometry.GetCellCount()) {
        throw GLDimensionError(DimensionMessage("GL integer plaintext cell count",
                                                m_geometry.GetCellCount(),
                                                m_plusValues.size() != m_geometry.GetCellCount()
                                                    ? m_plusValues.size()
                                                    : m_minusValues.size()));
    }
    for (auto& value : m_plusValues) {
        value = CanonicalModT(value, m_modulus);
    }
    for (auto& value : m_minusValues) {
        value = CanonicalModT(value, m_modulus);
    }
}

const GLGeometry& GLIntPlaintext::GetGeometry() const noexcept {
    return m_geometry;
}

uint64_t GLIntPlaintext::GetModulus() const noexcept {
    return m_modulus;
}

int64_t GLIntPlaintext::AtPlus(std::size_t row, std::size_t column) const {
    if (row >= m_geometry.GetRowCount() || column >= m_geometry.GetColumnsPerRow()) {
        throw GLDimensionError("GL integer plaintext index is outside the n x n matrix");
    }
    return m_plusValues[row * m_geometry.GetColumnsPerRow() + column];
}

int64_t GLIntPlaintext::AtMinus(std::size_t row, std::size_t column) const {
    if (row >= m_geometry.GetRowCount() || column >= m_geometry.GetColumnsPerRow()) {
        throw GLDimensionError("GL integer plaintext index is outside the n x n matrix");
    }
    return m_minusValues[row * m_geometry.GetColumnsPerRow() + column];
}

const std::vector<int64_t>& GLIntPlaintext::GetPlusValues() const noexcept {
    return m_plusValues;
}

const std::vector<int64_t>& GLIntPlaintext::GetMinusValues() const noexcept {
    return m_minusValues;
}

// ---------------------------------------------------------------------------
// GLIntEncodedPlaintext
// ---------------------------------------------------------------------------

GLIntEncodedPlaintext::GLIntEncodedPlaintext(GLGeometry geometry, CryptoContext<DCRTPoly> context,
                                             std::vector<Plaintext> rows)
    : m_geometry(std::move(geometry)), m_context(std::move(context)), m_rows(std::move(rows)) {
    Validate();
}

const GLGeometry& GLIntEncodedPlaintext::GetGeometry() const noexcept {
    return m_geometry;
}

const CryptoContext<DCRTPoly>& GLIntEncodedPlaintext::GetCryptoContext() const noexcept {
    return m_context;
}

const std::vector<Plaintext>& GLIntEncodedPlaintext::GetRows() const noexcept {
    return m_rows;
}

void GLIntEncodedPlaintext::Validate() const {
    if (!m_context) {
        throw GLContextMismatchError("GL integer encoded plaintext has no CryptoContext");
    }
    if (m_rows.size() != m_geometry.GetRowCount()) {
        throw GLMissingRowError(DimensionMessage("GL integer encoded plaintext row count",
                                                 m_geometry.GetRowCount(), m_rows.size()));
    }
    for (std::size_t row = 0; row < m_rows.size(); ++row) {
        if (!m_rows[row]) {
            throw GLMissingRowError(RowMessage("GL integer encoded plaintext is null", row));
        }
        if (m_rows[row]->GetEncodingType() != PACKED_ENCODING) {
            throw GLDimensionError(RowMessage("GL integer encoded plaintext is not BGV-packed", row));
        }
    }
}

// ---------------------------------------------------------------------------
// GLIntCiphertext
// ---------------------------------------------------------------------------

GLIntCiphertext::GLIntCiphertext(GLGeometry geometry, CryptoContext<DCRTPoly> context,
                                 std::vector<Ciphertext<DCRTPoly>> rows)
    : m_geometry(std::move(geometry)), m_context(std::move(context)), m_rows(std::move(rows)) {
    Validate();
}

const GLGeometry& GLIntCiphertext::GetGeometry() const noexcept {
    return m_geometry;
}

const CryptoContext<DCRTPoly>& GLIntCiphertext::GetCryptoContext() const noexcept {
    return m_context;
}

const std::vector<Ciphertext<DCRTPoly>>& GLIntCiphertext::GetRows() const noexcept {
    return m_rows;
}

const std::string& GLIntCiphertext::GetKeyTag() const {
    Validate();
    return m_rows.front()->GetKeyTag();
}

void GLIntCiphertext::Validate() const {
    if (!m_context) {
        throw GLContextMismatchError("GL integer ciphertext has no CryptoContext");
    }
    if (m_rows.size() < m_geometry.GetRowCount()) {
        throw GLMissingRowError(
            DimensionMessage("GL integer ciphertext row count", m_geometry.GetRowCount(), m_rows.size()));
    }
    if (m_rows.size() > m_geometry.GetRowCount()) {
        throw GLDimensionError(
            DimensionMessage("GL integer ciphertext row count", m_geometry.GetRowCount(), m_rows.size()));
    }

    std::string keyTag;
    for (std::size_t row = 0; row < m_rows.size(); ++row) {
        const auto& ciphertext = m_rows[row];
        if (!ciphertext) {
            throw GLMissingRowError(RowMessage("GL integer ciphertext is null", row));
        }
        if (ciphertext->GetCryptoContext().get() != m_context.get()) {
            throw GLContextMismatchError(
                RowMessage("GL integer ciphertext row belongs to a different CryptoContext", row));
        }
        if (ciphertext->GetEncodingType() != PACKED_ENCODING) {
            throw GLCiphertextError(RowMessage("GL integer ciphertext row is not BGV-packed", row));
        }
        if (ciphertext->GetElements().size() != 2) {
            throw GLCiphertextError(
                RowMessage("GL integer ciphertext row is not a relinearized two-component encryption", row));
        }
        if (row == 0) {
            keyTag = ciphertext->GetKeyTag();
            if (keyTag.empty()) {
                throw GLKeyMismatchError("GL integer ciphertext rows must carry a nonempty shared key tag");
            }
        }
        else if (ciphertext->GetKeyTag() != keyTag) {
            throw GLKeyMismatchError(RowMessage("GL integer ciphertext row uses a different key", row));
        }
    }
}

// ---------------------------------------------------------------------------
// GLIntEvalKey
// ---------------------------------------------------------------------------

GLIntEvalKey::GLIntEvalKey(GLGeometry geometry, CryptoContext<DCRTPoly> context, std::string keyTag,
                           std::vector<EvalKey<DCRTPoly>> conjugateRows,
                           std::vector<EvalKey<DCRTPoly>> productRows,
                           std::vector<EvalKey<DCRTPoly>> transposeRows,
                           std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> automorphismKeys)
    : m_geometry(std::move(geometry)),
      m_context(std::move(context)),
      m_keyTag(std::move(keyTag)),
      m_conjugateRows(std::move(conjugateRows)),
      m_productRows(std::move(productRows)),
      m_transposeRows(std::move(transposeRows)),
      m_automorphismKeys(std::move(automorphismKeys)) {
    Validate();
}

const GLGeometry& GLIntEvalKey::GetGeometry() const noexcept {
    return m_geometry;
}

const CryptoContext<DCRTPoly>& GLIntEvalKey::GetCryptoContext() const noexcept {
    return m_context;
}

const std::string& GLIntEvalKey::GetKeyTag() const noexcept {
    return m_keyTag;
}

void GLIntEvalKey::Validate() const {
    if (!m_context) {
        throw GLContextMismatchError("GL integer evaluation key has no CryptoContext");
    }
    if (m_keyTag.empty()) {
        throw GLKeyMismatchError("GL integer evaluation key has an empty destination key tag");
    }
    const auto n = m_geometry.GetDimension();
    if (m_conjugateRows.size() != n || m_productRows.size() != n || m_transposeRows.size() != n) {
        throw GLMissingEvaluationKeyError(
            "GL integer evaluation key requires all three n-row sliced key families");
    }
    for (std::size_t row = 0; row < n; ++row) {
        for (const auto* family : {&m_conjugateRows, &m_productRows, &m_transposeRows}) {
            const auto& key = (*family)[row];
            if (!key) {
                throw GLMissingEvaluationKeyError(
                    RowMessage("GL integer evaluation key has a null sliced row", row));
            }
            if (key->GetCryptoContext().get() != m_context.get()) {
                throw GLContextMismatchError(
                    RowMessage("GL integer evaluation-key row belongs to a different CryptoContext", row));
            }
            if (key->GetKeyTag() != m_keyTag) {
                throw GLKeyMismatchError(
                    RowMessage("GL integer evaluation-key row has a different destination key", row));
            }
        }
    }

    if (!m_automorphismKeys) {
        throw GLMissingEvaluationKeyError("GL integer evaluation key holds no automorphism key map");
    }
    const auto order = static_cast<uint64_t>(m_geometry.GetNativeCyclotomicOrder());
    std::vector<uint32_t> requiredIndices;
    uint64_t automorphism = 1;
    for (std::size_t nu = 1; nu < n; ++nu) {
        automorphism = (automorphism * 5) % order;
        requiredIndices.push_back(static_cast<uint32_t>(automorphism));
    }
    requiredIndices.push_back(static_cast<uint32_t>(order - 1));
    for (const auto index : requiredIndices) {
        const auto found = m_automorphismKeys->find(index);
        if (found == m_automorphismKeys->end() || !found->second) {
            throw GLMissingEvaluationKeyError(
                "GL integer evaluation key is missing a required automorphism key");
        }
        if (found->second->GetCryptoContext().get() != m_context.get()) {
            throw GLContextMismatchError(
                "GL integer evaluation-key automorphism entry belongs to a different CryptoContext");
        }
        if (found->second->GetKeyTag() != m_keyTag) {
            throw GLKeyMismatchError(
                "GL integer evaluation-key automorphism entry has a different destination key");
        }
    }
}

// ---------------------------------------------------------------------------
// GLIntSchemelet
// ---------------------------------------------------------------------------

GLIntSchemelet::GLIntSchemelet(GLIntParameters parameters)
    : m_parameters(std::move(parameters)), m_geometry(m_parameters.GetGeometry()) {
    m_parameters.Validate();

    // Pinned, non-negotiable internals: exact ring 2n, HEStd_NotSet,
    // FIXEDMANUAL (every q_i = 1 mod 4n*t, so ModReduce is plaintext-
    // invariant), full 2n batch.  None of these is a knob.
    CCParams<CryptoContextBGVRNS> contextParameters;
    contextParameters.SetPlaintextModulus(m_parameters.plaintextModulus);
    contextParameters.SetMultiplicativeDepth(m_parameters.multiplicativeDepth);
    contextParameters.SetScalingTechnique(FIXEDMANUAL);
    contextParameters.SetSecurityLevel(HEStd_NotSet);
    contextParameters.SetRingDim(static_cast<uint32_t>(m_geometry.GetNativeRingDimension()));
    contextParameters.SetBatchSize(static_cast<uint32_t>(m_geometry.GetNativeRingDimension()));

    m_context = GenCryptoContext(contextParameters);
    if (!m_context) {
        throw GLContextMismatchError("OpenFHE failed to create the GL integer row CryptoContext");
    }
    m_context->Enable(PKE);
    m_context->Enable(KEYSWITCH);
    m_context->Enable(LEVELEDSHE);
    m_context->Enable(ADVANCEDSHE);

    if (m_context->GetRingDimension() != m_geometry.GetNativeRingDimension()) {
        throw GLNativeModeError("OpenFHE did not preserve the exact GL integer ringDimension=2n");
    }
    if (m_context->GetCryptoParameters()->GetPlaintextModulus() != m_parameters.plaintextModulus) {
        throw GLIntParameterError("OpenFHE did not preserve the requested GL integer plaintext modulus");
    }

    const auto t     = m_parameters.plaintextModulus;
    const auto n     = m_geometry.GetDimension();
    const auto order = static_cast<uint64_t>(m_geometry.GetNativeCyclotomicOrder());

    m_zeta = MinimumPrimitiveRootModT(order, t);
    if (m_zeta == 0) {
        throw GLIntParameterError("no primitive 4n-th root of unity exists mod the plaintext modulus");
    }
    m_gaussianUnit = PowModT(m_zeta, n, t);
    if ((m_gaussianUnit * m_gaussianUnit) % t != t - 1) {
        throw GLIntParameterError("pinned Gaussian unit does not square to -1 mod t");
    }
    m_inverseDimension = PowModT(static_cast<uint64_t>(n) % t, t - 2, t);

    m_yRoots.resize(n);
    m_yRootInverses.resize(n);
    uint64_t exponent = 1;
    for (std::size_t k = 0; k < n; ++k) {
        m_yRoots[k]        = PowModT(m_zeta, exponent, t);
        m_yRootInverses[k] = PowModT(m_yRoots[k], t - 2, t);
        exponent           = (exponent * 5) % order;
    }

    VerifyPackingAgainstPinnedCodec();
}

const GLIntParameters& GLIntSchemelet::GetParameters() const noexcept {
    return m_parameters;
}

const GLGeometry& GLIntSchemelet::GetGeometry() const noexcept {
    return m_geometry;
}

const CryptoContext<DCRTPoly>& GLIntSchemelet::GetCryptoContext() const noexcept {
    return m_context;
}

uint64_t GLIntSchemelet::GetPlaintextModulus() const noexcept {
    return m_parameters.plaintextModulus;
}

uint64_t GLIntSchemelet::GetZeta() const noexcept {
    return m_zeta;
}

uint64_t GLIntSchemelet::GetGaussianUnit() const noexcept {
    return m_gaussianUnit;
}

bool GLIntSchemelet::UsesExactNativeRing() const noexcept {
    return m_context && m_context->GetRingDimension() == m_geometry.GetNativeRingDimension();
}

/**
 * Constructor-time fail-closed packing probe: OpenFHE's RootOfUnity minimal-
 * root rule is deliberate library behavior but still a library-internal
 * convention, so the codec re-verifies it end to end.  Every slot indicator
 * is packed through MakePackedPlaintext, its tower-0 coefficients are lifted
 * (centered) to mod t, and the row polynomial is evaluated at all 2n pinned
 * points zeta^{+5^j} / zeta^{-5^j}: exact indicator recovery is required.
 */
void GLIntSchemelet::VerifyPackingAgainstPinnedCodec() const {
    const auto t             = m_parameters.plaintextModulus;
    const auto n             = m_geometry.GetDimension();
    const auto ringDimension = m_geometry.GetNativeRingDimension();

    std::vector<uint64_t> points(ringDimension);
    for (std::size_t j = 0; j < n; ++j) {
        points[j]     = m_yRoots[j];
        points[n + j] = m_yRootInverses[j];
    }

    for (std::size_t slot = 0; slot < ringDimension; ++slot) {
        std::vector<int64_t> indicator(ringDimension, 0);
        indicator[slot] = 1;
        const auto packed = m_context->MakePackedPlaintext(indicator);
        if (!packed) {
            throw GLIntParameterError("OpenFHE failed to pack a GL integer probe indicator row");
        }

        auto element = packed->GetElement<DCRTPoly>();
        element.SetFormat(Format::COEFFICIENT);
        const auto& tower = element.GetElementAtIndex(0);
        const auto q      = tower.GetModulus();
        const auto halfQ  = q >> 1;

        std::vector<uint64_t> coefficients(ringDimension);
        for (std::size_t x = 0; x < ringDimension; ++x) {
            const auto& value = tower[x];
            int64_t centered  = (value > halfQ)
                                    ? -static_cast<int64_t>((q - value).ConvertToInt())
                                    : static_cast<int64_t>(value.ConvertToInt());
            coefficients[x] = static_cast<uint64_t>(CanonicalModT(centered, t));
        }

        for (std::size_t point = 0; point < ringDimension; ++point) {
            uint64_t accumulator = 0;
            uint64_t power       = 1;
            for (std::size_t x = 0; x < ringDimension; ++x) {
                accumulator = (accumulator + coefficients[x] * power) % t;
                power       = (power * points[point]) % t;
            }
            const uint64_t expected = (point == slot) ? 1 : 0;
            if (accumulator != expected) {
                throw GLIntParameterError(
                    "OpenFHE packing root or slot order does not match the pinned GL integer codec");
            }
        }
    }
}

KeyPair<DCRTPoly> GLIntSchemelet::KeyGen() const {
    auto keys = m_context->KeyGen();
    if (!keys.good()) {
        throw GLKeyMismatchError("OpenFHE failed to generate a shared GL integer row key pair");
    }
    return keys;
}

GLIntEvalKey GLIntSchemelet::EvalIntKeyGen(const PrivateKey<DCRTPoly>& privateKey) const {
    ValidateKeyContext(privateKey, "EvalIntKeyGen");

    // The Hadamard product relinearizes with the framework's own ordinary
    // s^2 EvalMult key (the paper's SwitchInt_small).  OpenFHE keeps that key
    // in its key-tag-indexed registry; EvalHadamardInt revalidates the entry
    // per call and fails closed when it is missing.
    m_context->EvalMultKeyGen(privateKey);

    const auto n = m_geometry.GetDimension();
    auto secret  = privateKey->GetPrivateElement();
    secret.SetFormat(Format::EVALUATION);
    auto conjugateInverse = secret.Transpose();

    std::vector<EvalKey<DCRTPoly>> conjugateRows;
    std::vector<EvalKey<DCRTPoly>> productRows;
    std::vector<EvalKey<DCRTPoly>> transposeRows;
    conjugateRows.reserve(n);
    productRows.reserve(n);
    transposeRows.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        // The source-key wrappers are iteration-local.  KeySwitchGen returns
        // destination-bound EvalKeys; no PrivateKeyImpl is stored in the
        // GLIntEvalKey bundle constructed below.
        auto conjugateSource  = GaussianConstantFromCoefficientInt(conjugateInverse, row, n);
        auto conjugatePrivate = std::make_shared<PrivateKeyImpl<DCRTPoly>>(m_context);
        conjugatePrivate->SetPrivateElement(conjugateSource);
        conjugateRows.push_back(m_context->KeySwitchGen(conjugatePrivate, privateKey));

        auto productPrivate = std::make_shared<PrivateKeyImpl<DCRTPoly>>(m_context);
        productPrivate->SetPrivateElement(secret * conjugateSource);
        productRows.push_back(m_context->KeySwitchGen(productPrivate, privateKey));

        // K3 row y switches the CONSTANT polynomial s_y (the y-th Gaussian
        // coefficient of the primary secret itself, no T -> T^{-1}) to s.
        auto transposePrivate = std::make_shared<PrivateKeyImpl<DCRTPoly>>(m_context);
        transposePrivate->SetPrivateElement(GaussianConstantFromCoefficientInt(secret, row, n));
        transposeRows.push_back(m_context->KeySwitchGen(transposePrivate, privateKey));
    }

    const auto order = static_cast<uint64_t>(m_geometry.GetNativeCyclotomicOrder());
    std::vector<uint32_t> indices;
    uint64_t automorphism = 1;
    for (std::size_t nu = 1; nu < n; ++nu) {
        automorphism = (automorphism * 5) % order;
        indices.push_back(static_cast<uint32_t>(automorphism));
    }
    indices.push_back(static_cast<uint32_t>(order - 1));
    auto automorphismKeys = m_context->GetScheme()->EvalAutomorphismKeyGen(privateKey, indices);
    if (!automorphismKeys || automorphismKeys->empty()) {
        throw GLMissingEvaluationKeyError("OpenFHE failed to generate the GL integer automorphism keys");
    }

    return GLIntEvalKey(m_geometry, m_context, privateKey->GetKeyTag(), std::move(conjugateRows),
                        std::move(productRows), std::move(transposeRows), std::move(automorphismKeys));
}

std::vector<std::vector<int64_t>> GLIntSchemelet::EncodeSlotRows(const GLIntPlaintext& plaintext) const {
    const auto t  = m_parameters.plaintextModulus;
    const auto n  = m_geometry.GetDimension();
    const auto rd = m_geometry.GetNativeRingDimension();

    std::vector<std::vector<int64_t>> slotRows(n, std::vector<int64_t>(rd, 0));
    for (std::size_t y = 0; y < n; ++y) {
        for (std::size_t j = 0; j < n; ++j) {
            uint64_t plusSum  = 0;
            uint64_t minusSum = 0;
            for (std::size_t k = 0; k < n; ++k) {
                const auto plusValue  = static_cast<uint64_t>(plaintext.AtPlus(j, k));
                const auto minusValue = static_cast<uint64_t>(plaintext.AtMinus(j, k));
                plusSum  = (plusSum + plusValue * PowModT(m_yRootInverses[k], y, t)) % t;
                minusSum = (minusSum + minusValue * PowModT(m_yRoots[k], y, t)) % t;
            }
            slotRows[y][j]     = static_cast<int64_t>((plusSum * m_inverseDimension) % t);
            slotRows[y][n + j] = static_cast<int64_t>((minusSum * m_inverseDimension) % t);
        }
    }
    return slotRows;
}

std::vector<Plaintext> GLIntSchemelet::PackSlotRows(const std::vector<std::vector<int64_t>>& slotRows,
                                                    uint32_t level) const {
    const auto t    = static_cast<int64_t>(m_parameters.plaintextModulus);
    const auto half = (t - 1) / 2;

    std::vector<Plaintext> rows;
    rows.reserve(slotRows.size());
    for (std::size_t row = 0; row < slotRows.size(); ++row) {
        std::vector<int64_t> centered(slotRows[row].size());
        for (std::size_t index = 0; index < centered.size(); ++index) {
            const auto value = slotRows[row][index];
            centered[index]  = (value > half) ? value - t : value;
        }
        auto encoded = m_context->MakePackedPlaintext(centered, 1, level);
        if (!encoded) {
            throw GLCiphertextError(RowMessage("OpenFHE failed to encode GL integer plaintext", row));
        }
        rows.push_back(std::move(encoded));
    }
    return rows;
}

GLIntPlaintext GLIntSchemelet::DecodeSlotRows(const std::vector<std::vector<int64_t>>& slotRows) const {
    const auto t = m_parameters.plaintextModulus;
    const auto n = m_geometry.GetDimension();

    std::vector<int64_t> plus(m_geometry.GetCellCount());
    std::vector<int64_t> minus(m_geometry.GetCellCount());
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            uint64_t plusSum  = 0;
            uint64_t minusSum = 0;
            uint64_t plusPower  = 1;
            uint64_t minusPower = 1;
            for (std::size_t y = 0; y < n; ++y) {
                plusSum  = (plusSum + static_cast<uint64_t>(slotRows[y][j]) * plusPower) % t;
                minusSum = (minusSum + static_cast<uint64_t>(slotRows[y][n + j]) * minusPower) % t;
                plusPower  = (plusPower * m_yRoots[k]) % t;
                minusPower = (minusPower * m_yRootInverses[k]) % t;
            }
            plus[j * n + k]  = static_cast<int64_t>(plusSum);
            minus[j * n + k] = static_cast<int64_t>(minusSum);
        }
    }
    return GLIntPlaintext(m_geometry, t, std::move(plus), std::move(minus));
}

GLIntEncodedPlaintext GLIntSchemelet::EncodeInt(const GLIntPlaintext& plaintext) const {
    ValidatePlaintextCompatible(plaintext, "GL integer plaintext");
    return GLIntEncodedPlaintext(m_geometry, m_context, PackSlotRows(EncodeSlotRows(plaintext), 0));
}

GLIntPlaintext GLIntSchemelet::DecodeInt(const GLIntEncodedPlaintext& plaintext) const {
    plaintext.Validate();
    RequireSameGeometry(m_geometry, plaintext.GetGeometry(), "GL integer encoded plaintext");
    ValidateOwnedContext(plaintext.GetCryptoContext(), "GL integer encoded plaintext");

    const auto t  = m_parameters.plaintextModulus;
    const auto rd = m_geometry.GetNativeRingDimension();
    std::vector<std::vector<int64_t>> slotRows;
    slotRows.reserve(m_geometry.GetRowCount());
    for (std::size_t row = 0; row < plaintext.GetRows().size(); ++row) {
        const auto& packed = plaintext.GetRows()[row]->GetPackedValue();
        if (packed.size() < rd) {
            throw GLDimensionError(RowMessage("GL integer encoded plaintext has too few slots", row));
        }
        std::vector<int64_t> canonical(rd);
        for (std::size_t index = 0; index < rd; ++index) {
            canonical[index] = CanonicalModT(packed[index], t);
        }
        slotRows.push_back(std::move(canonical));
    }
    return DecodeSlotRows(slotRows);
}

GLIntEncodedPlaintext GLIntSchemelet::EncodeIntTransposed(const GLIntPlaintext& plaintext) const {
    ValidatePlaintextCompatible(plaintext, "GL integer plaintext");
    // Remark 3.13 analog: the transposed encoding satisfies
    // EncodeIntTransposed(M) = EncodeInt(M^T per branch); decoding transposes back.
    return EncodeInt(TransposeBranches(plaintext));
}

GLIntPlaintext GLIntSchemelet::DecodeIntTransposed(const GLIntEncodedPlaintext& plaintext) const {
    return TransposeBranches(DecodeInt(plaintext));
}

GLIntCiphertext GLIntSchemelet::EncryptInt(const PublicKey<DCRTPoly>& publicKey,
                                           const GLIntEncodedPlaintext& plaintext) const {
    plaintext.Validate();
    RequireSameGeometry(m_geometry, plaintext.GetGeometry(), "GL integer encoded plaintext");
    ValidateOwnedContext(plaintext.GetCryptoContext(), "GL integer encoded plaintext");
    ValidateKeyContext(publicKey, "GL integer public encryption");

    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(m_geometry.GetRowCount());
    for (std::size_t row = 0; row < plaintext.GetRows().size(); ++row) {
        auto ciphertext = m_context->Encrypt(publicKey, plaintext.GetRows()[row]);
        if (!ciphertext) {
            throw GLCiphertextError(RowMessage("OpenFHE public encryption returned null", row));
        }
        rows.push_back(std::move(ciphertext));
    }
    return GLIntCiphertext(m_geometry, m_context, std::move(rows));
}

GLIntCiphertext GLIntSchemelet::EncryptInt(const PrivateKey<DCRTPoly>& privateKey,
                                           const GLIntEncodedPlaintext& plaintext) const {
    plaintext.Validate();
    RequireSameGeometry(m_geometry, plaintext.GetGeometry(), "GL integer encoded plaintext");
    ValidateOwnedContext(plaintext.GetCryptoContext(), "GL integer encoded plaintext");
    ValidateKeyContext(privateKey, "GL integer symmetric encryption");

    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(m_geometry.GetRowCount());
    for (std::size_t row = 0; row < plaintext.GetRows().size(); ++row) {
        auto ciphertext = m_context->Encrypt(privateKey, plaintext.GetRows()[row]);
        if (!ciphertext) {
            throw GLCiphertextError(RowMessage("OpenFHE symmetric encryption returned null", row));
        }
        rows.push_back(std::move(ciphertext));
    }
    return GLIntCiphertext(m_geometry, m_context, std::move(rows));
}

GLIntPlaintext GLIntSchemelet::DecryptInt(const PrivateKey<DCRTPoly>& privateKey,
                                          const GLIntCiphertext& ciphertext) const {
    ciphertext.Validate();
    RequireSameGeometry(m_geometry, ciphertext.GetGeometry(), "GL integer ciphertext");
    ValidateOwnedContext(ciphertext.GetCryptoContext(), "GL integer ciphertext");
    ValidateKeyContext(privateKey, "GL integer decryption");
    if (privateKey->GetKeyTag() != ciphertext.GetKeyTag()) {
        throw GLKeyMismatchError("GL integer decryption key does not match the ciphertext row key tag");
    }

    const auto t  = m_parameters.plaintextModulus;
    const auto rd = m_geometry.GetNativeRingDimension();
    std::vector<std::vector<int64_t>> slotRows;
    slotRows.reserve(m_geometry.GetRowCount());
    for (std::size_t row = 0; row < ciphertext.GetRows().size(); ++row) {
        Plaintext decoded;
        const auto result = m_context->Decrypt(privateKey, ciphertext.GetRows()[row], &decoded);
        if (!result.isValid || !decoded) {
            throw GLCiphertextError(RowMessage("OpenFHE failed to decrypt GL integer ciphertext", row));
        }
        decoded->SetLength(rd);
        const auto& packed = decoded->GetPackedValue();
        if (packed.size() < rd) {
            throw GLDimensionError(RowMessage("decrypted GL integer row has too few slots", row));
        }
        std::vector<int64_t> canonical(rd);
        for (std::size_t index = 0; index < rd; ++index) {
            canonical[index] = CanonicalModT(packed[index], t);
        }
        slotRows.push_back(std::move(canonical));
    }
    return DecodeSlotRows(slotRows);
}

GLIntCiphertext GLIntSchemelet::AddInt(const GLIntCiphertext& lhs, const GLIntCiphertext& rhs) const {
    ValidateAggregate(lhs, "left GL integer ciphertext");
    ValidateAggregate(rhs, "right GL integer ciphertext");
    ValidateOperandPair(lhs, rhs, "AddInt");

    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(m_geometry.GetRowCount());
    for (std::size_t row = 0; row < m_geometry.GetRowCount(); ++row) {
        auto sum = m_context->EvalAdd(lhs.GetRows()[row], rhs.GetRows()[row]);
        if (!sum) {
            throw GLCiphertextError(RowMessage("OpenFHE GL integer row addition returned null", row));
        }
        rows.push_back(std::move(sum));
    }
    return GLIntCiphertext(m_geometry, m_context, std::move(rows));
}

GLIntCiphertext GLIntSchemelet::SubInt(const GLIntCiphertext& lhs, const GLIntCiphertext& rhs) const {
    ValidateAggregate(lhs, "left GL integer ciphertext");
    ValidateAggregate(rhs, "right GL integer ciphertext");
    ValidateOperandPair(lhs, rhs, "SubInt");

    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(m_geometry.GetRowCount());
    for (std::size_t row = 0; row < m_geometry.GetRowCount(); ++row) {
        auto difference = m_context->EvalSub(lhs.GetRows()[row], rhs.GetRows()[row]);
        if (!difference) {
            throw GLCiphertextError(RowMessage("OpenFHE GL integer row subtraction returned null", row));
        }
        rows.push_back(std::move(difference));
    }
    return GLIntCiphertext(m_geometry, m_context, std::move(rows));
}

GLIntCiphertext GLIntSchemelet::NegateInt(const GLIntCiphertext& ciphertext) const {
    ValidateAggregate(ciphertext, "GL integer ciphertext");

    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(m_geometry.GetRowCount());
    for (std::size_t row = 0; row < m_geometry.GetRowCount(); ++row) {
        auto negated = m_context->EvalNegate(ciphertext.GetRows()[row]);
        if (!negated) {
            throw GLCiphertextError(RowMessage("OpenFHE GL integer row negation returned null", row));
        }
        rows.push_back(std::move(negated));
    }
    return GLIntCiphertext(m_geometry, m_context, std::move(rows));
}

GLIntCiphertext GLIntSchemelet::EvalHadamardInt(const GLIntCiphertext& lhs,
                                                const GLIntCiphertext& rhs) const {
    ValidateAggregate(lhs, "left GL integer ciphertext");
    ValidateAggregate(rhs, "right GL integer ciphertext");
    ValidateOperandPair(lhs, rhs, "EvalHadamardInt");
    if (lhs.GetRows().front()->GetNoiseScaleDeg() != 1) {
        throw GLCiphertextError("EvalHadamardInt requires ModReduced degree-one operands");
    }
    RequireMultiplicationBudget(lhs, "EvalHadamardInt");
    ValidateHadamardEvaluationKey(lhs.GetKeyTag(), "EvalHadamardInt");

    const auto n = m_geometry.GetDimension();
    std::vector<Ciphertext<DCRTPoly>> outputRows;
    outputRows.reserve(n);
    for (std::size_t outputRow = 0; outputRow < n; ++outputRow) {
        // Direct group: y1 + y2 = outputRow.
        Ciphertext<DCRTPoly> direct;
        for (std::size_t y1 = 0; y1 <= outputRow; ++y1) {
            auto product = m_context->EvalMult(lhs.GetRows()[y1], rhs.GetRows()[outputRow - y1]);
            if (!product) {
                throw GLCiphertextError("OpenFHE returned null during a GL integer Hadamard row product");
            }
            if (direct) {
                m_context->EvalAddInPlace(direct, product);
            }
            else {
                direct = std::move(product);
            }
        }

        // Wrap group: y1 + y2 = outputRow + n, folded in with Y^n = I via the
        // exact monomial T^n (empty for outputRow = n-1).  On sigma_int the
        // monomial multiplies + slots by I and - slots by -I, which is the
        // correct action of the ring element I on both branches at once.
        Ciphertext<DCRTPoly> wrap;
        for (std::size_t y1 = outputRow + 1; y1 < n; ++y1) {
            auto product = m_context->EvalMult(lhs.GetRows()[y1], rhs.GetRows()[outputRow + n - y1]);
            if (!product) {
                throw GLCiphertextError("OpenFHE returned null during a GL integer Hadamard wrap product");
            }
            if (wrap) {
                m_context->EvalAddInPlace(wrap, product);
            }
            else {
                wrap = std::move(product);
            }
        }

        auto output = std::move(direct);
        if (wrap) {
            m_context->GetScheme()->MultByMonomialInPlace(wrap, static_cast<uint32_t>(n));
            m_context->EvalAddInPlace(output, wrap);
        }
        // The degree-2 sums receive exactly one BGV ModReduce (the spec's
        // ModSwitch); FIXEDMANUAL keeps it plaintext-invariant.
        m_context->GetScheme()->ModReduceInternalInPlace(output, 1);
        outputRows.push_back(std::move(output));
    }
    return GLIntCiphertext(m_geometry, m_context, std::move(outputRows));
}

GLIntCiphertext GLIntSchemelet::EvalRowRotateInt(const GLIntCiphertext& ciphertext, std::size_t nu,
                                                 const GLIntEvalKey& evaluationKey) const {
    ValidateAggregate(ciphertext, "GL integer ciphertext");
    RequireRotationAmount(nu, "EvalRowRotateInt");
    ValidateEvaluationKey(evaluationKey, ciphertext.GetKeyTag(), "EvalRowRotateInt");

    if (nu == 0) {
        std::vector<Ciphertext<DCRTPoly>> identityRows;
        identityRows.reserve(m_geometry.GetRowCount());
        for (const auto& row : ciphertext.GetRows()) {
            identityRows.push_back(row->Clone());
        }
        return GLIntCiphertext(m_geometry, m_context, std::move(identityRows));
    }

    const auto order = static_cast<uint64_t>(m_geometry.GetNativeCyclotomicOrder());
    const auto automorphismIndex = static_cast<uint32_t>(PowModT(5, nu, order));
    const auto found = evaluationKey.m_automorphismKeys->find(automorphismIndex);
    if (found == evaluationKey.m_automorphismKeys->end() || !found->second) {
        throw GLMissingEvaluationKeyError(
            "EvalRowRotateInt is missing the automorphism key for the requested rotation amount");
    }

    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(m_geometry.GetRowCount());
    for (std::size_t row = 0; row < m_geometry.GetRowCount(); ++row) {
        auto rotated = m_context->EvalAutomorphism(ciphertext.GetRows()[row], automorphismIndex,
                                                   *evaluationKey.m_automorphismKeys);
        if (!rotated) {
            throw GLCiphertextError(RowMessage("OpenFHE GL integer row rotation returned null", row));
        }
        rows.push_back(std::move(rotated));
    }
    return GLIntCiphertext(m_geometry, m_context, std::move(rows));
}

GLIntCiphertext GLIntSchemelet::EvalColumnRotateInt(const GLIntCiphertext& ciphertext,
                                                    std::size_t nu) const {
    ValidateAggregate(ciphertext, "GL integer ciphertext");
    RequireRotationAmount(nu, "EvalColumnRotateInt");

    const auto n     = m_geometry.GetDimension();
    const auto order = static_cast<uint64_t>(m_geometry.GetNativeCyclotomicOrder());
    const uint64_t alpha = PowModT(5, nu, order);

    std::vector<Ciphertext<DCRTPoly>> rows(n);
    for (std::size_t inputRow = 0; inputRow < n; ++inputRow) {
        const uint64_t exponent  = alpha * static_cast<uint64_t>(inputRow);
        const std::size_t target = static_cast<std::size_t>(exponent % n);
        const uint64_t wraps     = exponent / n;

        auto moved = ciphertext.GetRows()[inputRow]->Clone();
        // I^q via the exact monomial T^{(q mod 4) n}; q mod 4 = 2 is the
        // exact global negation T^{2n}, no key switch and no level anywhere.
        const auto unitPower = static_cast<uint32_t>((wraps % 4) * n);
        if (unitPower != 0) {
            m_context->GetScheme()->MultByMonomialInPlace(moved, unitPower);
        }
        if (rows[target]) {
            // 5^nu is odd and n is a power of two, so y -> (5^nu * y) mod n is
            // a bijection; a collision means the aggregate was malformed.
            throw GLCiphertextError("GL integer column rotation produced a row collision");
        }
        rows[target] = std::move(moved);
    }
    return GLIntCiphertext(m_geometry, m_context, std::move(rows));
}

GLIntCiphertext GLIntSchemelet::EvalConjSwapInt(const GLIntCiphertext& ciphertext,
                                                const GLIntEvalKey& evaluationKey) const {
    ValidateAggregate(ciphertext, "GL integer ciphertext");
    ValidateEvaluationKey(evaluationKey, ciphertext.GetKeyTag(), "EvalConjSwapInt");

    const auto n     = m_geometry.GetDimension();
    const auto order = static_cast<uint64_t>(m_geometry.GetNativeCyclotomicOrder());
    const auto conjugationIndex = static_cast<uint32_t>(order - 1);
    const auto found = evaluationKey.m_automorphismKeys->find(conjugationIndex);
    if (found == evaluationKey.m_automorphismKeys->end() || !found->second) {
        throw GLMissingEvaluationKeyError(
            "EvalConjSwapInt is missing the T -> T^{-1} automorphism key");
    }

    std::vector<Ciphertext<DCRTPoly>> rows(n);
    for (std::size_t inputRow = 0; inputRow < n; ++inputRow) {
        auto conjugated = m_context->EvalAutomorphism(ciphertext.GetRows()[inputRow], conjugationIndex,
                                                      *evaluationKey.m_automorphismKeys);
        if (!conjugated) {
            throw GLCiphertextError(
                RowMessage("OpenFHE GL integer conjugation automorphism returned null", inputRow));
        }
        if (inputRow == 0) {
            rows[0] = std::move(conjugated);
        }
        else {
            // Y^{-y} = (-I) * Y^{n-y} for y = 1..n-1: the exact monomial
            // T^{3n} is the pinned (-I) unit (probe- and reference-pinned sign).
            m_context->GetScheme()->MultByMonomialInPlace(conjugated, static_cast<uint32_t>(3 * n));
            rows[n - inputRow] = std::move(conjugated);
        }
    }
    return GLIntCiphertext(m_geometry, m_context, std::move(rows));
}

GLIntCiphertext GLIntSchemelet::EvalTransposeInt(const GLIntCiphertext& ciphertext,
                                                 const GLIntEvalKey& evaluationKey) const {
    ValidateAggregate(ciphertext, "GL integer ciphertext");
    ValidateEvaluationKey(evaluationKey, ciphertext.GetKeyTag(), "EvalTransposeInt");

    const auto n = m_geometry.GetDimension();
    std::vector<DCRTPoly> inputB;
    std::vector<DCRTPoly> inputA;
    inputB.reserve(n);
    inputA.reserve(n);
    for (const auto& row : ciphertext.GetRows()) {
        inputB.push_back(row->GetElements()[0]);
        inputA.push_back(row->GetElements()[1]);
    }

    auto permutedB = NativeTransposeComponentRowsInt(inputB, n);
    auto permutedA = NativeTransposeComponentRowsInt(inputA, n);
    auto switchedA = NativeBigSwitchInt(m_context, permutedA, evaluationKey.m_transposeRows, n);

    std::vector<Ciphertext<DCRTPoly>> outputRows;
    outputRows.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        permutedB[row] += switchedA.b[row];
        auto output = ciphertext.GetRows()[row]->CloneEmpty();
        output->SetElements(
            std::vector<DCRTPoly>{std::move(permutedB[row]), std::move(switchedA.a[row])});
        outputRows.push_back(std::move(output));
    }
    return GLIntCiphertext(m_geometry, m_context, std::move(outputRows));
}

GLIntCiphertext GLIntSchemelet::EvalAdjointInt(const GLIntCiphertext& ciphertext,
                                               const GLIntEvalKey& evaluationKey) const {
    ValidateAggregate(ciphertext, "GL integer ciphertext");
    ValidateEvaluationKey(evaluationKey, ciphertext.GetKeyTag(), "EvalAdjointInt");
    return EvaluateIntAdjoint(ciphertext, evaluationKey.m_conjugateRows);
}

GLIntCiphertext GLIntSchemelet::EvalCircledastPlainInt(const GLIntCiphertext& lhs,
                                                       const GLIntPlaintext& rhs) const {
    ValidateAggregate(lhs, "left GL integer ciphertext");
    ValidatePlaintextCompatible(rhs, "right GL integer plaintext");
    RequireMultiplicationBudget(lhs, "EvalCircledastPlainInt");
    return EvaluateIntPlainTrace(lhs, rhs, 1);
}

GLIntCiphertext GLIntSchemelet::EvalMatMulPlainInt(const GLIntCiphertext& lhs,
                                                   const GLIntPlaintext& rhs) const {
    ValidateAggregate(lhs, "left GL integer ciphertext");
    ValidatePlaintextCompatible(rhs, "right GL integer plaintext");
    RequireMultiplicationBudget(lhs, "EvalMatMulPlainInt");

    // circledast(U, adjoint-analog(V)) represents n^{-1} (U+ V+, U- V-);
    // the exact public factor n cancels n^{-1} mod t without touching any
    // metadata (the represented value changes, exactly as in the complex port).
    return EvaluateIntPlainTrace(lhs, AdjointIntPlaintext(rhs),
                                 static_cast<int64_t>(m_geometry.GetDimension()));
}

GLIntCiphertext GLIntSchemelet::EvalCircledastInt(const GLIntCiphertext& lhs,
                                                  const GLIntCiphertext& rhs,
                                                  const GLIntEvalKey& evaluationKey) const {
    ValidateAggregate(lhs, "left GL integer ciphertext");
    ValidateAggregate(rhs, "right GL integer ciphertext");
    ValidateOperandPair(lhs, rhs, "EvalCircledastInt");
    RequireMultiplicationBudget(lhs, "EvalCircledastInt");
    ValidateEvaluationKey(evaluationKey, lhs.GetKeyTag(), "EvalCircledastInt");
    return EvaluateIntCipherTrace(lhs, rhs, evaluationKey.m_conjugateRows,
                                  evaluationKey.m_productRows, 1);
}

GLIntCiphertext GLIntSchemelet::EvalMatMulInt(const GLIntCiphertext& lhs, const GLIntCiphertext& rhs,
                                              const GLIntEvalKey& evaluationKey) const {
    ValidateAggregate(lhs, "left GL integer ciphertext");
    ValidateAggregate(rhs, "right GL integer ciphertext");
    ValidateOperandPair(lhs, rhs, "EvalMatMulInt");
    RequireMultiplicationBudget(lhs, "EvalMatMulInt");
    ValidateEvaluationKey(evaluationKey, lhs.GetKeyTag(), "EvalMatMulInt");

    // circledast(U, adjoint(V)) represents n^{-1} (U+ V+, U- V-).  The exact
    // factor n is applied to all four source component combinations before
    // either big key switch and cancels n^{-1} mod t.
    const auto adjoint = EvaluateIntAdjoint(rhs, evaluationKey.m_conjugateRows);
    return EvaluateIntCipherTrace(lhs, adjoint, evaluationKey.m_conjugateRows,
                                  evaluationKey.m_productRows,
                                  static_cast<int64_t>(m_geometry.GetDimension()));
}

// ---------------------------------------------------------------------------
// Private evaluation helpers
// ---------------------------------------------------------------------------

GLIntCiphertext GLIntSchemelet::EvaluateIntPlainTrace(const GLIntCiphertext& lhs,
                                                      const GLIntPlaintext& rhs,
                                                      int64_t exactValueFactor) const {
    const auto n     = m_geometry.GetDimension();
    const auto level = static_cast<uint32_t>(lhs.GetRows().front()->GetLevel());
    // Encode the clear pair at the operand level so both trace inputs carry
    // identical DCRT towers (FIXEDMANUAL performs no automatic adjust).
    const auto plaintextRows = PackSlotRows(EncodeSlotRows(rhs), level);

    std::vector<DCRTPoly> leftB;
    std::vector<DCRTPoly> leftA;
    std::vector<DCRTPoly> right;
    leftB.reserve(n);
    leftA.reserve(n);
    right.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        const auto& elements = lhs.GetRows()[row]->GetElements();
        leftB.push_back(elements[0]);
        leftA.push_back(elements[1]);
        right.push_back(plaintextRows[row]->GetElement<DCRTPoly>());
    }

    auto outputB = NativeCircledastComponentRowsInt(leftB, right, n);
    auto outputA = NativeCircledastComponentRowsInt(leftA, right, n);
    if (exactValueFactor != 1) {
        MultiplyRowsByExactIntegerInt(outputB, exactValueFactor);
        MultiplyRowsByExactIntegerInt(outputA, exactValueFactor);
    }

    std::vector<Ciphertext<DCRTPoly>> outputRows;
    outputRows.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        auto output = lhs.GetRows()[row]->CloneEmpty();
        output->SetElements(std::vector<DCRTPoly>{std::move(outputB[row]), std::move(outputA[row])});
        output->SetNoiseScaleDeg(lhs.GetRows()[row]->GetNoiseScaleDeg() +
                                 plaintextRows[row]->GetNoiseScaleDeg());
        output->SetScalingFactorInt(lhs.GetRows()[row]->GetScalingFactorInt().ModMul(
            plaintextRows[row]->GetScalingFactorInt(),
            lhs.GetRows()[row]->GetCryptoParameters()->GetPlaintextModulus()));
        // This native primitive is itself the multiplication boundary, so it
        // performs the single BGV ModReduce (the spec's ModSwitch) here.
        m_context->GetScheme()->ModReduceInternalInPlace(output, 1);
        outputRows.push_back(std::move(output));
    }
    return GLIntCiphertext(m_geometry, m_context, std::move(outputRows));
}

GLIntCiphertext GLIntSchemelet::EvaluateIntAdjoint(
    const GLIntCiphertext& ciphertext, const std::vector<EvalKey<DCRTPoly>>& conjugateKeyRows) const {
    const auto n = m_geometry.GetDimension();
    std::vector<DCRTPoly> inputB;
    std::vector<DCRTPoly> inputA;
    inputB.reserve(n);
    inputA.reserve(n);
    for (const auto& row : ciphertext.GetRows()) {
        inputB.push_back(row->GetElements()[0]);
        inputA.push_back(row->GetElements()[1]);
    }

    auto transformedB = NativeAdjointComponentRowsInt(inputB, n);
    auto transformedA = NativeAdjointComponentRowsInt(inputA, n);
    auto switchedA    = NativeBigSwitchInt(m_context, transformedA, conjugateKeyRows, n);

    std::vector<Ciphertext<DCRTPoly>> outputRows;
    outputRows.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        transformedB[row] += switchedA.b[row];
        auto output = ciphertext.GetRows()[row]->CloneEmpty();
        output->SetElements(
            std::vector<DCRTPoly>{std::move(transformedB[row]), std::move(switchedA.a[row])});
        outputRows.push_back(std::move(output));
    }
    return GLIntCiphertext(m_geometry, m_context, std::move(outputRows));
}

GLIntCiphertext GLIntSchemelet::EvaluateIntCipherTrace(
    const GLIntCiphertext& lhs, const GLIntCiphertext& rhs,
    const std::vector<EvalKey<DCRTPoly>>& conjugateKeyRows,
    const std::vector<EvalKey<DCRTPoly>>& productKeyRows, int64_t exactValueFactor) const {
    const auto n = m_geometry.GetDimension();
    std::vector<DCRTPoly> leftB;
    std::vector<DCRTPoly> leftA;
    std::vector<DCRTPoly> rightB;
    std::vector<DCRTPoly> rightA;
    leftB.reserve(n);
    leftA.reserve(n);
    rightB.reserve(n);
    rightA.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        leftB.push_back(lhs.GetRows()[row]->GetElements()[0]);
        leftA.push_back(lhs.GetRows()[row]->GetElements()[1]);
        rightB.push_back(rhs.GetRows()[row]->GetElements()[0]);
        rightA.push_back(rhs.GetRows()[row]->GetElements()[1]);
    }

    // Corrected section-3.5/4.3 convention (the printed section-4.3 tuple
    // inherits the section-3.5 middle-component transposition):
    // d0 = bL circledast bR                   basis 1
    // d1 = bL circledast aR                   basis s(-I, Y^{-1})   -> K1
    // d2 = aL circledast bR                   basis s(I, X)
    // d3 = aL circledast aR                   basis s(I,X)*s(-I,Y^{-1}) -> K2
    auto d0 = NativeCircledastComponentRowsInt(leftB, rightB, n);
    auto d1 = NativeCircledastComponentRowsInt(leftB, rightA, n);
    auto d2 = NativeCircledastComponentRowsInt(leftA, rightB, n);
    auto d3 = NativeCircledastComponentRowsInt(leftA, rightA, n);
    if (exactValueFactor != 1) {
        MultiplyRowsByExactIntegerInt(d0, exactValueFactor);
        MultiplyRowsByExactIntegerInt(d1, exactValueFactor);
        MultiplyRowsByExactIntegerInt(d2, exactValueFactor);
        MultiplyRowsByExactIntegerInt(d3, exactValueFactor);
    }

    auto switchedD1 = NativeBigSwitchInt(m_context, d1, conjugateKeyRows, n);
    auto switchedD3 = NativeBigSwitchInt(m_context, d3, productKeyRows, n);

    std::vector<Ciphertext<DCRTPoly>> outputRows;
    outputRows.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        d0[row] += switchedD1.b[row];
        d0[row] += switchedD3.b[row];
        d2[row] += switchedD1.a[row];
        d2[row] += switchedD3.a[row];

        auto output = lhs.GetRows()[row]->CloneEmpty();
        output->SetElements(std::vector<DCRTPoly>{std::move(d0[row]), std::move(d2[row])});
        output->SetNoiseScaleDeg(lhs.GetRows()[row]->GetNoiseScaleDeg() +
                                 rhs.GetRows()[row]->GetNoiseScaleDeg());
        output->SetScalingFactorInt(lhs.GetRows()[row]->GetScalingFactorInt().ModMul(
            rhs.GetRows()[row]->GetScalingFactorInt(),
            lhs.GetRows()[row]->GetCryptoParameters()->GetPlaintextModulus()));
        m_context->GetScheme()->ModReduceInternalInPlace(output, 1);
        outputRows.push_back(std::move(output));
    }
    return GLIntCiphertext(m_geometry, m_context, std::move(outputRows));
}

// ---------------------------------------------------------------------------
// Private validation helpers
// ---------------------------------------------------------------------------

void GLIntSchemelet::ValidateOwnedContext(const CryptoContext<DCRTPoly>& context,
                                          const char* objectName) const {
    if (!context || context.get() != m_context.get()) {
        throw GLContextMismatchError(std::string(objectName) + " belongs to a different CryptoContext");
    }
}

void GLIntSchemelet::ValidateKeyContext(const PublicKey<DCRTPoly>& key, const char* operation) const {
    if (!key) {
        throw GLKeyMismatchError(std::string(operation) + " requires a non-null public key");
    }
    if (key->GetCryptoContext().get() != m_context.get()) {
        throw GLKeyContextMismatchError(std::string(operation) + " key belongs to a different CryptoContext");
    }
}

void GLIntSchemelet::ValidateKeyContext(const PrivateKey<DCRTPoly>& key, const char* operation) const {
    if (!key) {
        throw GLKeyMismatchError(std::string(operation) + " requires a non-null private key");
    }
    if (key->GetCryptoContext().get() != m_context.get()) {
        throw GLKeyContextMismatchError(std::string(operation) + " key belongs to a different CryptoContext");
    }
}

void GLIntSchemelet::ValidatePlaintextCompatible(const GLIntPlaintext& plaintext,
                                                 const char* objectName) const {
    RequireSameGeometry(m_geometry, plaintext.GetGeometry(), objectName);
    if (plaintext.GetModulus() != m_parameters.plaintextModulus) {
        std::ostringstream os;
        os << objectName << " modulus mismatch: expected t=" << m_parameters.plaintextModulus
           << ", got t=" << plaintext.GetModulus();
        throw GLIntParameterError(os.str());
    }
}

void GLIntSchemelet::ValidateAggregate(const GLIntCiphertext& ciphertext, const char* objectName) const {
    ciphertext.Validate();
    RequireSameGeometry(m_geometry, ciphertext.GetGeometry(), objectName);
    ValidateOwnedContext(ciphertext.GetCryptoContext(), objectName);
    if (!UsesExactNativeRing()) {
        // Belt check: no transport-ring construction path exists in the
        // integer mode, and native ops keep re-verifying that invariant.
        throw GLNativeModeError(std::string(objectName) +
                                " requires the exact native ringDimension=2n integer mode");
    }
    RequireUniformRowMetadataInt(ciphertext, objectName);
}

void GLIntSchemelet::ValidateOperandPair(const GLIntCiphertext& lhs, const GLIntCiphertext& rhs,
                                         const char* operation) const {
    if (lhs.GetKeyTag() != rhs.GetKeyTag()) {
        throw GLKeyMismatchError(std::string(operation) + " requires both operands under the same key");
    }
    const auto& left  = lhs.GetRows().front();
    const auto& right = rhs.GetRows().front();
    if (left->GetLevel() != right->GetLevel() ||
        left->GetNoiseScaleDeg() != right->GetNoiseScaleDeg() ||
        left->GetElements().front().GetNumOfElements() !=
            right->GetElements().front().GetNumOfElements()) {
        throw GLCiphertextError(std::string(operation) +
                                " requires operands at identical BGV level and scale degree "
                                "(FIXEDMANUAL performs no automatic adjust)");
    }
}

void GLIntSchemelet::ValidateEvaluationKey(const GLIntEvalKey& evaluationKey, const std::string& keyTag,
                                           const char* operation) const {
    evaluationKey.Validate();
    RequireSameGeometry(m_geometry, evaluationKey.GetGeometry(), "GL integer evaluation key");
    ValidateOwnedContext(evaluationKey.GetCryptoContext(), "GL integer evaluation key");
    if (evaluationKey.GetKeyTag() != keyTag) {
        throw GLKeyMismatchError(std::string(operation) +
                                 " evaluation key does not match the ciphertext key tag");
    }
}

void GLIntSchemelet::ValidateHadamardEvaluationKey(const std::string& keyTag,
                                                   const char* operation) const {
    const auto& allMultKeys = CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys();
    const auto multIt       = allMultKeys.find(keyTag);
    if (multIt == allMultKeys.end() || multIt->second.empty() || !multIt->second.front() ||
        multIt->second.front()->GetCryptoContext().get() != m_context.get()) {
        throw GLMissingEvaluationKeyError(
            std::string(operation) +
            " is missing the framework s^2 relinearization key; call EvalIntKeyGen");
    }
}

void GLIntSchemelet::RequireMultiplicationBudget(const GLIntCiphertext& ciphertext,
                                                 const char* operation) const {
    if (ciphertext.GetRows().front()->GetElements().front().GetNumOfElements() <= 1) {
        throw GLDepthError(std::string(operation) +
                           " requires one available BGV level for its single ModReduce");
    }
}

void GLIntSchemelet::RequireRotationAmount(std::size_t nu, const char* operation) const {
    // nu = 0 is the identity automorphism and is accepted, matching the complex
    // port's rotation convention; key material stays keyed on [1, n-1] only.
    if (nu >= m_geometry.GetDimension()) {
        throw GLDimensionError(std::string(operation) + " rotation amount must lie in [0, n-1]");
    }
}

}  // namespace lbcrypto
