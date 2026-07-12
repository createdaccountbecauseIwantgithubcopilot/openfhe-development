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
// GLIntParameters
// ---------------------------------------------------------------------------

GLGeometry GLIntParameters::GetGeometry() const {
    return GLGeometry(dimension);
}

void GLIntParameters::Validate() const {
    const GLGeometry geometry(dimension);  // rejects everything but n=4/8, including 4096
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
