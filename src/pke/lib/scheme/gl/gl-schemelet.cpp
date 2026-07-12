//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "scheme/gl/gl-schemelet.h"

#include <algorithm>
#include <cmath>
#include <set>
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

using LongComplex = std::complex<long double>;

std::vector<LongComplex> MakeYAxisPowerTable(const GLGeometry& geometry) {
    const auto n     = geometry.GetDimension();
    const auto order = geometry.GetNativeCyclotomicOrder();
    const long double pi = std::acos(-1.0L);

    // powers[k*n+y] = zeta_k^y, where zeta_k = zeta^(5^k) and
    // zeta = exp(2*pi*i/(4n)).  Every zeta_k satisfies zeta_k^n=i.
    std::vector<LongComplex> powers(n * n);
    std::size_t exponent = 1;
    for (std::size_t k = 0; k < n; ++k) {
        const long double angle = 2.0L * pi * static_cast<long double>(exponent) /
                                  static_cast<long double>(order);
        const LongComplex root = std::polar(1.0L, angle);
        powers[k * n]          = LongComplex(1.0L, 0.0L);
        for (std::size_t y = 1; y < n; ++y) {
            powers[k * n + y] = powers[k * n + y - 1] * root;
        }
        exponent = (exponent * 5) % order;
    }
    return powers;
}

std::vector<std::complex<double>> InterpolateYAxis(const GLPlaintext& plaintext) {
    const auto& geometry = plaintext.GetGeometry();
    const auto n         = geometry.GetDimension();
    const auto powers    = MakeYAxisPowerTable(geometry);

    // Coefficient-major layout: output[y*n+j] is c_y(zeta_j).  For each
    // fixed X evaluation point j, orthogonality of all roots of Y^n-i gives
    // c_y(zeta_j) = (1/n) sum_k M[j,k] zeta_k^(-y).
    std::vector<std::complex<double>> coefficients(geometry.GetCellCount());
    for (std::size_t y = 0; y < n; ++y) {
        for (std::size_t j = 0; j < n; ++j) {
            LongComplex sum(0.0L, 0.0L);
            for (std::size_t k = 0; k < n; ++k) {
                const auto& value = plaintext.GetValues()[j * n + k];
                sum += LongComplex(value.real(), value.imag()) * std::conj(powers[k * n + y]);
            }
            sum /= static_cast<long double>(n);
            coefficients[y * n + j] =
                std::complex<double>(static_cast<double>(sum.real()), static_cast<double>(sum.imag()));
        }
    }
    return coefficients;
}

std::vector<Plaintext> EncodeYAxisAtLevel(const CryptoContext<DCRTPoly>& context,
                                          const GLPlaintext& plaintext, uint32_t level) {
    const auto& geometry    = plaintext.GetGeometry();
    const auto coefficients = InterpolateYAxis(plaintext);

    std::vector<Plaintext> rows;
    rows.reserve(geometry.GetRowCount());
    for (std::size_t row = 0; row < geometry.GetRowCount(); ++row) {
        const auto begin =
            coefficients.begin() + static_cast<std::ptrdiff_t>(row * geometry.GetColumnsPerRow());
        const auto end = begin + static_cast<std::ptrdiff_t>(geometry.GetColumnsPerRow());
        std::vector<std::complex<double>> packedRow(begin, end);
        auto encoded = context->MakeCKKSPackedPlaintext(
            packedRow, 1, level, nullptr, static_cast<uint32_t>(geometry.GetColumnsPerRow()));
        if (!encoded) {
            throw GLCiphertextError(RowMessage("OpenFHE failed to encode GL plaintext", row));
        }
        rows.push_back(std::move(encoded));
    }
    return rows;
}

GLPlaintext AdjointPlaintext(const GLPlaintext& plaintext) {
    const auto& geometry = plaintext.GetGeometry();
    const auto n         = geometry.GetDimension();
    std::vector<std::complex<double>> values(geometry.GetCellCount());
    for (std::size_t row = 0; row < n; ++row) {
        for (std::size_t column = 0; column < n; ++column) {
            values[row * n + column] = std::conj(plaintext.At(column, row));
        }
    }
    return GLPlaintext(geometry, std::move(values));
}

/**
 * Direct W-free GL trace on one pair of R' components.
 *
 * Each DCRTPoly is one Y-coefficient row.  With native ring dimension 2n,
 * coefficients x and x+n are the real and imaginary residues of one
 * Gaussian coefficient.  DCRTPoly::Transpose() is the T -> T^{-1}
 * automorphism; under R ~= Z[i][X]/(X^n-i), its coefficient k is precisely
 * the coefficient of X^k in conjugate(p)(X^{-1}).
 */
std::vector<DCRTPoly> NativeCircledastComponentRows(const std::vector<DCRTPoly>& leftRows,
                                                    const std::vector<DCRTPoly>& rightRows,
                                                    std::size_t n) {
    if (leftRows.size() != n || rightRows.size() != n) {
        throw GLDimensionError("native GL trace requires exactly n component rows");
    }
    if (leftRows.empty()) {
        throw GLDimensionError("native GL trace requires nonempty component rows");
    }

    const auto params = leftRows.front().GetParams();
    if (!params || params->GetRingDimension() != 2 * n) {
        throw GLNativeModeError("native GL trace requires DCRT ring dimension 2n");
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
            throw GLDimensionError(RowMessage("native GL trace row parameters mismatch", row));
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
                    const auto& leftTower = leftCoefficientRows[inner].GetElementAtIndex(towerIndex);
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

void MultiplyRowsByExactInteger(std::vector<DCRTPoly>& rows, int64_t factor) {
    for (auto& row : rows) {
        row = row.Times(factor);
    }
}

DCRTPoly GaussianConstantFromCoefficient(const DCRTPoly& coefficientPolynomial,
                                         std::size_t coefficient, std::size_t n) {
    auto source = coefficientPolynomial;
    source.SetFormat(Format::COEFFICIENT);
    DCRTPoly result(source.GetParams(), Format::COEFFICIENT, true);
    for (std::size_t towerIndex = 0; towerIndex < source.GetNumOfElements(); ++towerIndex) {
        const auto& sourceTower = source.GetElementAtIndex(towerIndex);
        auto resultTower = result.GetElementAtIndex(towerIndex);
        resultTower[0] = sourceTower[coefficient];
        resultTower[n] = sourceTower[coefficient + n];
        result.SetElementAtIndex(towerIndex, std::move(resultTower));
    }
    result.SetFormat(Format::EVALUATION);
    return result;
}

DCRTPoly NativeGaussianI(const std::shared_ptr<DCRTPoly::Params>& params, std::size_t n) {
    DCRTPoly result(params, Format::COEFFICIENT, true);
    for (std::size_t towerIndex = 0; towerIndex < result.GetNumOfElements(); ++towerIndex) {
        auto tower = result.GetElementAtIndex(towerIndex);
        tower[n] = NativeInteger(1);
        result.SetElementAtIndex(towerIndex, std::move(tower));
    }
    result.SetFormat(Format::EVALUATION);
    return result;
}

std::vector<DCRTPoly> NativeAdjointComponentRows(const std::vector<DCRTPoly>& inputRows,
                                                std::size_t n) {
    if (inputRows.size() != n || inputRows.empty()) {
        throw GLDimensionError("native GL adjoint requires exactly n component rows");
    }
    const auto params = inputRows.front().GetParams();
    if (!params || params->GetRingDimension() != 2 * n) {
        throw GLNativeModeError("native GL adjoint requires DCRT ring dimension 2n");
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
                const auto& real = inputTower[x];
                const auto& imag = inputTower[x + n];
                const auto negativeReal = zero.ModSub(real, modulus);
                const auto negativeImag = zero.ModSub(imag, modulus);
                const auto twistCount = (inputRow == 0 ? 0U : 1U) + (x == 0 ? 0U : 1U);

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

struct NativeSwitchedRows {
    std::vector<DCRTPoly> b;
    std::vector<DCRTPoly> a;
};

NativeSwitchedRows NativeBigSwitch(const CryptoContext<DCRTPoly>& context,
                                   const std::vector<DCRTPoly>& sourceRows,
                                   const std::vector<EvalKey<DCRTPoly>>& evaluationKeyRows,
                                   std::size_t n) {
    if (sourceRows.size() != n || evaluationKeyRows.size() != n || sourceRows.empty()) {
        throw GLDimensionError("native GL big switch requires n source and evaluation-key rows");
    }
    const auto params = sourceRows.front().GetParams();
    const auto gaussianI = NativeGaussianI(params, n);

    NativeSwitchedRows result;
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
                throw GLCiphertextError("OpenFHE native GL big key switch returned an invalid component pair");
            }

            auto switchedB = std::move((*switched)[0]);
            auto switchedA = std::move((*switched)[1]);
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

GLCiphertext EvaluateNativePlainTrace(const CryptoContext<DCRTPoly>& context, const GLGeometry& geometry,
                                      const GLCiphertext& lhs, const GLPlaintext& rhs,
                                      int64_t exactValueFactor) {
    const auto n = geometry.GetDimension();
    const auto level = static_cast<uint32_t>(lhs.GetRows().front()->GetLevel());
    const auto plaintextRows = EncodeYAxisAtLevel(context, rhs, level);
    const auto cryptoParameters =
        std::dynamic_pointer_cast<CryptoParametersRNS>(context->GetCryptoParameters());
    if (!cryptoParameters) {
        throw GLContextMismatchError("native GL trace requires RNS crypto parameters");
    }

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

    auto outputB = NativeCircledastComponentRows(leftB, right, n);
    auto outputA = NativeCircledastComponentRows(leftA, right, n);
    if (exactValueFactor != 1) {
        MultiplyRowsByExactInteger(outputB, exactValueFactor);
        MultiplyRowsByExactInteger(outputA, exactValueFactor);
    }

    std::vector<Ciphertext<DCRTPoly>> outputRows;
    outputRows.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        auto output = lhs.GetRows()[row]->CloneEmpty();
        output->SetElements(std::vector<DCRTPoly>{std::move(outputB[row]), std::move(outputA[row])});
        output->SetNoiseScaleDeg(lhs.GetRows()[row]->GetNoiseScaleDeg() +
                                 plaintextRows[row]->GetNoiseScaleDeg());
        output->SetScalingFactor(lhs.GetRows()[row]->GetScalingFactor() *
                                 plaintextRows[row]->GetScalingFactor());
        output->SetScalingFactorInt(lhs.GetRows()[row]->GetScalingFactorInt().ModMul(
            plaintextRows[row]->GetScalingFactorInt(),
            lhs.GetRows()[row]->GetCryptoParameters()->GetPlaintextModulus()));
        // The public RescaleInPlace wrapper intentionally defers work for the
        // automatic CKKS scaling modes.  This native primitive is itself the
        // multiplication boundary, so perform the same internal modulus drop
        // that a composed multiplication performs before returning.
        context->GetScheme()->ModReduceInternalInPlace(output, cryptoParameters->GetCompositeDegree());
        outputRows.push_back(std::move(output));
    }
    return GLCiphertext(geometry, context, std::move(outputRows));
}

GLCiphertext EvaluateNativeAdjoint(const CryptoContext<DCRTPoly>& context, const GLGeometry& geometry,
                                   const GLCiphertext& ciphertext,
                                   const std::vector<EvalKey<DCRTPoly>>& conjugateKeyRows) {
    const auto n = geometry.GetDimension();
    std::vector<DCRTPoly> inputB;
    std::vector<DCRTPoly> inputA;
    inputB.reserve(n);
    inputA.reserve(n);
    for (const auto& row : ciphertext.GetRows()) {
        inputB.push_back(row->GetElements()[0]);
        inputA.push_back(row->GetElements()[1]);
    }

    auto transformedB = NativeAdjointComponentRows(inputB, n);
    auto transformedA = NativeAdjointComponentRows(inputA, n);
    auto switchedA    = NativeBigSwitch(context, transformedA, conjugateKeyRows, n);

    std::vector<Ciphertext<DCRTPoly>> outputRows;
    outputRows.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        transformedB[row] += switchedA.b[row];
        auto output = ciphertext.GetRows()[row]->CloneEmpty();
        output->SetElements(
            std::vector<DCRTPoly>{std::move(transformedB[row]), std::move(switchedA.a[row])});
        outputRows.push_back(std::move(output));
    }
    return GLCiphertext(geometry, context, std::move(outputRows));
}

GLCiphertext EvaluateNativeCipherTrace(const CryptoContext<DCRTPoly>& context,
                                       const GLGeometry& geometry, const GLCiphertext& lhs,
                                       const GLCiphertext& rhs,
                                       const std::vector<EvalKey<DCRTPoly>>& conjugateKeyRows,
                                       const std::vector<EvalKey<DCRTPoly>>& productKeyRows,
                                       int64_t exactValueFactor) {
    const auto n = geometry.GetDimension();
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

    // Corrected section-3.5 convention:
    // d0=bL circledast bR, d1=bL circledast aR (conjugate-secret source),
    // d2=aL circledast bR (already under s), and
    // d3=aL circledast aR (s*conjugate-secret source).
    auto d0 = NativeCircledastComponentRows(leftB, rightB, n);
    auto d1 = NativeCircledastComponentRows(leftB, rightA, n);
    auto d2 = NativeCircledastComponentRows(leftA, rightB, n);
    auto d3 = NativeCircledastComponentRows(leftA, rightA, n);
    if (exactValueFactor != 1) {
        MultiplyRowsByExactInteger(d0, exactValueFactor);
        MultiplyRowsByExactInteger(d1, exactValueFactor);
        MultiplyRowsByExactInteger(d2, exactValueFactor);
        MultiplyRowsByExactInteger(d3, exactValueFactor);
    }

    auto switchedD1 = NativeBigSwitch(context, d1, conjugateKeyRows, n);
    auto switchedD3 = NativeBigSwitch(context, d3, productKeyRows, n);
    const auto cryptoParameters =
        std::dynamic_pointer_cast<CryptoParametersRNS>(context->GetCryptoParameters());
    if (!cryptoParameters) {
        throw GLContextMismatchError("native GL trace requires RNS crypto parameters");
    }

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
        output->SetScalingFactor(lhs.GetRows()[row]->GetScalingFactor() *
                                 rhs.GetRows()[row]->GetScalingFactor());
        output->SetScalingFactorInt(lhs.GetRows()[row]->GetScalingFactorInt().ModMul(
            rhs.GetRows()[row]->GetScalingFactorInt(),
            lhs.GetRows()[row]->GetCryptoParameters()->GetPlaintextModulus()));
        context->GetScheme()->ModReduceInternalInPlace(output, cryptoParameters->GetCompositeDegree());
        outputRows.push_back(std::move(output));
    }
    return GLCiphertext(geometry, context, std::move(outputRows));
}

void RequireNativeCipherPairCompatible(const GLCiphertext& lhs, const GLCiphertext& rhs,
                                       const char* operation) {
    if (lhs.GetKeyTag() != rhs.GetKeyTag()) {
        throw GLKeyMismatchError(std::string(operation) + " requires both operands under the same key");
    }
    const auto& left = lhs.GetRows().front();
    const auto& right = rhs.GetRows().front();
    if (left->GetLevel() != right->GetLevel() ||
        left->GetNoiseScaleDeg() != right->GetNoiseScaleDeg() ||
        left->GetScalingFactor() != right->GetScalingFactor() ||
        left->GetElements().front().GetNumOfElements() !=
            right->GetElements().front().GetNumOfElements()) {
        throw GLCiphertextError(std::string(operation) +
                                " requires operands at identical native CKKS level and scale");
    }
}

std::vector<std::complex<double>> EvaluateYAxis(const GLGeometry& geometry,
                                                const std::vector<std::complex<double>>& coefficients) {
    if (coefficients.size() != geometry.GetCellCount()) {
        throw GLDimensionError(
            DimensionMessage("GL Y-coefficient cell count", geometry.GetCellCount(), coefficients.size()));
    }

    const auto n      = geometry.GetDimension();
    const auto powers = MakeYAxisPowerTable(geometry);
    std::vector<std::complex<double>> matrix(geometry.GetCellCount());
    for (std::size_t j = 0; j < n; ++j) {
        for (std::size_t k = 0; k < n; ++k) {
            LongComplex sum(0.0L, 0.0L);
            for (std::size_t y = 0; y < n; ++y) {
                const auto& coefficient = coefficients[y * n + j];
                sum += LongComplex(coefficient.real(), coefficient.imag()) * powers[k * n + y];
            }
            matrix[j * n + k] =
                std::complex<double>(static_cast<double>(sum.real()), static_cast<double>(sum.imag()));
        }
    }
    return matrix;
}

std::complex<double> ToDoubleComplex(const LongComplex& value) {
    return {static_cast<double>(value.real()), static_cast<double>(value.imag())};
}

Ciphertext<DCRTPoly> EvalEncryptedLinearCombination(
    const CryptoContext<DCRTPoly>& context, const std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
    const std::vector<std::complex<double>>& weights, const char* operation) {
    if (ciphertexts.empty() || ciphertexts.size() != weights.size()) {
        throw GLDimensionError(std::string(operation) + " requires one weight per nonempty ciphertext input");
    }

    std::vector<ReadOnlyCiphertext<DCRTPoly>> readOnlyCiphertexts(ciphertexts.begin(), ciphertexts.end());
    auto result = context->EvalLinearWSum(readOnlyCiphertexts, weights);
    if (!result) {
        throw GLCiphertextError(std::string("OpenFHE returned null during ") + operation);
    }
    return result;
}

std::vector<Ciphertext<DCRTPoly>> EvaluateEncryptedYAxis(
    const CryptoContext<DCRTPoly>& context, const GLGeometry& geometry,
    const std::vector<Ciphertext<DCRTPoly>>& coefficientRows) {
    const auto n      = geometry.GetDimension();
    const auto powers = MakeYAxisPowerTable(geometry);

    std::vector<Ciphertext<DCRTPoly>> columns;
    columns.reserve(n);
    for (std::size_t k = 0; k < n; ++k) {
        std::vector<std::complex<double>> weights;
        weights.reserve(n);
        for (std::size_t y = 0; y < n; ++y) {
            weights.push_back(ToDoubleComplex(powers[k * n + y]));
        }
        columns.push_back(EvalEncryptedLinearCombination(
            context, coefficientRows, weights, "encrypted GL Y-axis evaluation"));
    }
    return columns;
}

std::vector<Ciphertext<DCRTPoly>> InterpolateEncryptedYAxis(
    const CryptoContext<DCRTPoly>& context, const GLGeometry& geometry,
    const std::vector<Ciphertext<DCRTPoly>>& columns) {
    const auto n      = geometry.GetDimension();
    const auto powers = MakeYAxisPowerTable(geometry);

    std::vector<Ciphertext<DCRTPoly>> coefficientRows;
    coefficientRows.reserve(n);
    for (std::size_t y = 0; y < n; ++y) {
        std::vector<std::complex<double>> weights;
        weights.reserve(n);
        for (std::size_t k = 0; k < n; ++k) {
            weights.push_back(ToDoubleComplex(std::conj(powers[k * n + y]) /
                                              static_cast<long double>(n)));
        }
        coefficientRows.push_back(EvalEncryptedLinearCombination(
            context, columns, weights, "encrypted GL Y-axis interpolation"));
    }
    return coefficientRows;
}

std::set<uint32_t> RequiredEvalSumIndices(const CryptoContext<DCRTPoly>& context,
                                          const GLGeometry& geometry) {
    const auto cyclotomicOrder = static_cast<uint64_t>(context->GetCyclotomicOrder());
    uint64_t automorphism      = 5;
    std::set<uint32_t> indices;
    for (std::size_t span = 1; span < geometry.GetDimension(); span *= 2) {
        indices.insert(static_cast<uint32_t>(automorphism));
        automorphism = (automorphism * automorphism) % cyclotomicOrder;
    }
    return indices;
}

}  // namespace

GLGeometry::GLGeometry(std::size_t dimension) : m_dimension(dimension) {
    if (dimension != 4 && dimension != 8) {
        throw GLDimensionError("W-free GL vertical slice supports only n=4 or n=8");
    }
}

std::size_t GLGeometry::GetDimension() const noexcept {
    return m_dimension;
}

std::size_t GLGeometry::GetRowCount() const noexcept {
    return m_dimension;
}

std::size_t GLGeometry::GetColumnsPerRow() const noexcept {
    return m_dimension;
}

std::size_t GLGeometry::GetCellCount() const noexcept {
    return m_dimension * m_dimension;
}

std::size_t GLGeometry::GetNativeRingDimension() const noexcept {
    return 2 * m_dimension;
}

std::size_t GLGeometry::GetNativeCyclotomicOrder() const noexcept {
    return 4 * m_dimension;
}

bool GLGeometry::operator==(const GLGeometry& other) const noexcept {
    return m_dimension == other.m_dimension;
}

bool GLGeometry::operator!=(const GLGeometry& other) const noexcept {
    return !(*this == other);
}

GLGeometry GLParameters::GetGeometry() const {
    return GLGeometry(dimension);
}

bool GLParameters::RequestsExactNativeRing() const noexcept {
    return ringDimension != 0 && ringDimension == 2 * dimension;
}

void GLParameters::Validate() const {
    const GLGeometry geometry(dimension);
    if (multiplicativeDepth == 0) {
        throw GLDimensionError("GL CKKS transport requires multiplicativeDepth >= 1");
    }
    if (scalingModSize == 0 || firstModSize == 0) {
        throw GLDimensionError("GL CKKS transport modulus sizes must be nonzero");
    }
    if (ringDimension != 0) {
        if ((ringDimension & (ringDimension - 1)) != 0) {
            throw GLDimensionError("GL CKKS transport ringDimension must be a power of two");
        }
        if (ringDimension / 2 < geometry.GetColumnsPerRow()) {
            throw GLDimensionError("GL CKKS transport ringDimension does not provide n row slots");
        }
    }
    if (securityLevel == HEStd_NotSet && ringDimension == 0) {
        throw GLNativeModeError("HEStd_NotSet GL transport requires an explicit ringDimension");
    }
    if (RequestsExactNativeRing() && securityLevel != HEStd_NotSet) {
        throw GLNativeModeError(
            "exact GL ringDimension=2n is supported only with HEStd_NotSet for n=4/8; "
            "these toy dimensions do not satisfy HE-standard security");
    }
}

GLPlaintext::GLPlaintext(GLGeometry geometry, std::vector<std::complex<double>> values)
    : m_geometry(std::move(geometry)), m_values(std::move(values)) {
    if (m_values.size() != m_geometry.GetCellCount()) {
        throw GLDimensionError(
            DimensionMessage("GL plaintext cell count", m_geometry.GetCellCount(), m_values.size()));
    }
}

GLPlaintext::GLPlaintext(std::size_t dimension, std::vector<std::complex<double>> values)
    : GLPlaintext(GLGeometry(dimension), std::move(values)) {}

const GLGeometry& GLPlaintext::GetGeometry() const noexcept {
    return m_geometry;
}

const std::vector<std::complex<double>>& GLPlaintext::GetValues() const noexcept {
    return m_values;
}

std::complex<double>& GLPlaintext::At(std::size_t row, std::size_t column) {
    if (row >= m_geometry.GetRowCount() || column >= m_geometry.GetColumnsPerRow()) {
        throw GLDimensionError("GL plaintext index is outside the n x n matrix");
    }
    return m_values[row * m_geometry.GetColumnsPerRow() + column];
}

const std::complex<double>& GLPlaintext::At(std::size_t row, std::size_t column) const {
    if (row >= m_geometry.GetRowCount() || column >= m_geometry.GetColumnsPerRow()) {
        throw GLDimensionError("GL plaintext index is outside the n x n matrix");
    }
    return m_values[row * m_geometry.GetColumnsPerRow() + column];
}

GLEncodedPlaintext::GLEncodedPlaintext(GLGeometry geometry, CryptoContext<DCRTPoly> context,
                                       std::vector<Plaintext> rows)
    : m_geometry(std::move(geometry)), m_context(std::move(context)), m_rows(std::move(rows)) {
    Validate();
}

const GLGeometry& GLEncodedPlaintext::GetGeometry() const noexcept {
    return m_geometry;
}

const CryptoContext<DCRTPoly>& GLEncodedPlaintext::GetCryptoContext() const noexcept {
    return m_context;
}

const std::vector<Plaintext>& GLEncodedPlaintext::GetRows() const noexcept {
    return m_rows;
}

void GLEncodedPlaintext::Validate() const {
    if (!m_context) {
        throw GLContextMismatchError("GL encoded plaintext has no CryptoContext");
    }
    if (m_rows.size() != m_geometry.GetRowCount()) {
        throw GLMissingRowError(
            DimensionMessage("GL encoded plaintext row count", m_geometry.GetRowCount(), m_rows.size()));
    }
    for (std::size_t row = 0; row < m_rows.size(); ++row) {
        if (!m_rows[row]) {
            throw GLMissingRowError(RowMessage("GL encoded plaintext is null", row));
        }
        if (m_rows[row]->GetEncodingType() != CKKS_PACKED_ENCODING) {
            throw GLDimensionError(RowMessage("GL encoded plaintext is not CKKS-packed", row));
        }
        if (m_rows[row]->GetCKKSPackedValue().size() < m_geometry.GetColumnsPerRow()) {
            throw GLDimensionError(RowMessage("GL encoded plaintext has too few active columns", row));
        }
    }
}

GLCiphertext::GLCiphertext(GLGeometry geometry, CryptoContext<DCRTPoly> context,
                           std::vector<Ciphertext<DCRTPoly>> rows)
    : m_geometry(std::move(geometry)), m_context(std::move(context)), m_rows(std::move(rows)) {
    Validate();
}

const GLGeometry& GLCiphertext::GetGeometry() const noexcept {
    return m_geometry;
}

const CryptoContext<DCRTPoly>& GLCiphertext::GetCryptoContext() const noexcept {
    return m_context;
}

const std::vector<Ciphertext<DCRTPoly>>& GLCiphertext::GetRows() const noexcept {
    return m_rows;
}

const std::string& GLCiphertext::GetKeyTag() const {
    Validate();
    return m_rows.front()->GetKeyTag();
}

void GLCiphertext::Validate() const {
    if (!m_context) {
        throw GLContextMismatchError("GL ciphertext has no CryptoContext");
    }
    if (m_rows.size() < m_geometry.GetRowCount()) {
        throw GLMissingRowError(
            DimensionMessage("GL ciphertext row count", m_geometry.GetRowCount(), m_rows.size()));
    }
    if (m_rows.size() > m_geometry.GetRowCount()) {
        throw GLDimensionError(
            DimensionMessage("GL ciphertext row count", m_geometry.GetRowCount(), m_rows.size()));
    }

    std::string keyTag;
    for (std::size_t row = 0; row < m_rows.size(); ++row) {
        const auto& ciphertext = m_rows[row];
        if (!ciphertext) {
            throw GLMissingRowError(RowMessage("GL ciphertext is null", row));
        }
        if (ciphertext->GetCryptoContext().get() != m_context.get()) {
            throw GLContextMismatchError(RowMessage("GL ciphertext row belongs to a different CryptoContext", row));
        }
        if (ciphertext->GetEncodingType() != CKKS_PACKED_ENCODING) {
            throw GLCiphertextError(RowMessage("GL ciphertext row is not CKKS-packed", row));
        }
        if (ciphertext->GetSlots() < m_geometry.GetColumnsPerRow()) {
            throw GLDimensionError(RowMessage("GL ciphertext row has too few active slots", row));
        }
        if (ciphertext->GetElements().size() != 2) {
            throw GLCiphertextError(RowMessage("GL ciphertext row is not a relinearized two-component encryption",
                                               row));
        }
        if (row == 0) {
            keyTag = ciphertext->GetKeyTag();
            if (keyTag.empty()) {
                throw GLKeyMismatchError("GL ciphertext rows must carry a nonempty shared key tag");
            }
        }
        else if (ciphertext->GetKeyTag() != keyTag) {
            throw GLKeyMismatchError(RowMessage("GL ciphertext row uses a different key", row));
        }
    }
}

GLNativeEvalKey::GLNativeEvalKey(GLGeometry geometry, CryptoContext<DCRTPoly> context,
                                 std::string keyTag,
                                 std::vector<EvalKey<DCRTPoly>> conjugateRows,
                                 std::vector<EvalKey<DCRTPoly>> productRows)
    : m_geometry(std::move(geometry)),
      m_context(std::move(context)),
      m_keyTag(std::move(keyTag)),
      m_conjugateRows(std::move(conjugateRows)),
      m_productRows(std::move(productRows)) {
    Validate();
}

const GLGeometry& GLNativeEvalKey::GetGeometry() const noexcept {
    return m_geometry;
}

const CryptoContext<DCRTPoly>& GLNativeEvalKey::GetCryptoContext() const noexcept {
    return m_context;
}

const std::string& GLNativeEvalKey::GetKeyTag() const noexcept {
    return m_keyTag;
}

void GLNativeEvalKey::Validate() const {
    if (!m_context) {
        throw GLContextMismatchError("native GL evaluation key has no CryptoContext");
    }
    if (m_keyTag.empty()) {
        throw GLKeyMismatchError("native GL evaluation key has an empty destination key tag");
    }
    const auto n = m_geometry.GetDimension();
    if (m_conjugateRows.size() != n || m_productRows.size() != n) {
        throw GLMissingEvaluationKeyError("native GL evaluation key requires both n-row key families");
    }
    for (std::size_t row = 0; row < n; ++row) {
        if (!m_conjugateRows[row] || !m_productRows[row]) {
            throw GLMissingEvaluationKeyError(RowMessage("native GL evaluation key has a null row", row));
        }
        if (m_conjugateRows[row]->GetCryptoContext().get() != m_context.get() ||
            m_productRows[row]->GetCryptoContext().get() != m_context.get()) {
            throw GLContextMismatchError(
                RowMessage("native GL evaluation-key row belongs to a different CryptoContext", row));
        }
        if (m_conjugateRows[row]->GetKeyTag() != m_keyTag ||
            m_productRows[row]->GetKeyTag() != m_keyTag) {
            throw GLKeyMismatchError(
                RowMessage("native GL evaluation-key row has a different destination key", row));
        }
    }
}

GLSchemelet::GLSchemelet(GLParameters parameters)
    : m_parameters(std::move(parameters)), m_geometry(m_parameters.GetGeometry()) {
    m_parameters.Validate();

    CCParams<CryptoContextCKKSRNS> contextParameters;
    contextParameters.SetMultiplicativeDepth(m_parameters.multiplicativeDepth);
    contextParameters.SetScalingModSize(m_parameters.scalingModSize);
    contextParameters.SetFirstModSize(m_parameters.firstModSize);
    contextParameters.SetBatchSize(static_cast<uint32_t>(m_geometry.GetColumnsPerRow()));
    contextParameters.SetSecurityLevel(m_parameters.securityLevel);
    contextParameters.SetScalingTechnique(m_parameters.scalingTechnique);
    contextParameters.SetCKKSDataType(COMPLEX);
    if (m_parameters.ringDimension != 0) {
        contextParameters.SetRingDim(m_parameters.ringDimension);
    }

    m_context = GenCryptoContext(contextParameters);
    if (!m_context) {
        throw GLContextMismatchError("OpenFHE failed to create the GL row CryptoContext");
    }
    m_context->Enable(PKE);
    m_context->Enable(KEYSWITCH);
    m_context->Enable(LEVELEDSHE);
    m_context->Enable(ADVANCEDSHE);

    if (m_context->GetRingDimension() / 2 < m_geometry.GetColumnsPerRow()) {
        throw GLDimensionError("generated CKKS context does not provide n transport slots per GL row");
    }
    if (m_parameters.RequestsExactNativeRing() &&
        m_context->GetRingDimension() != m_geometry.GetNativeRingDimension()) {
        throw GLNativeModeError("OpenFHE did not preserve the requested exact GL ringDimension=2n");
    }
}

const GLParameters& GLSchemelet::GetParameters() const noexcept {
    return m_parameters;
}

const GLGeometry& GLSchemelet::GetGeometry() const noexcept {
    return m_geometry;
}

const CryptoContext<DCRTPoly>& GLSchemelet::GetCryptoContext() const noexcept {
    return m_context;
}

bool GLSchemelet::UsesExactNativeRing() const noexcept {
    return m_context && m_context->GetRingDimension() == m_geometry.GetNativeRingDimension();
}

KeyPair<DCRTPoly> GLSchemelet::KeyGen() const {
    auto keys = m_context->KeyGen();
    if (!keys.good()) {
        throw GLKeyMismatchError("OpenFHE failed to generate a shared GL row key pair");
    }
    return keys;
}

GLEncodedPlaintext GLSchemelet::Encode(const GLPlaintext& plaintext) const {
    RequireSameGeometry(m_geometry, plaintext.GetGeometry(), "GL plaintext");
    return GLEncodedPlaintext(m_geometry, m_context, EncodeYAxisAtLevel(m_context, plaintext, 0));
}

GLPlaintext GLSchemelet::Decode(const GLEncodedPlaintext& plaintext) const {
    plaintext.Validate();
    RequireSameGeometry(m_geometry, plaintext.GetGeometry(), "GL encoded plaintext");
    ValidateOwnedContext(plaintext.GetCryptoContext(), "GL encoded plaintext");

    std::vector<std::complex<double>> coefficients;
    coefficients.reserve(m_geometry.GetCellCount());
    for (const auto& row : plaintext.GetRows()) {
        const auto& packed = row->GetCKKSPackedValue();
        coefficients.insert(coefficients.end(), packed.begin(),
                            packed.begin() + static_cast<std::ptrdiff_t>(m_geometry.GetColumnsPerRow()));
    }
    return GLPlaintext(m_geometry, EvaluateYAxis(m_geometry, coefficients));
}

GLCiphertext GLSchemelet::Encrypt(const PublicKey<DCRTPoly>& publicKey,
                                  const GLEncodedPlaintext& plaintext) const {
    plaintext.Validate();
    RequireSameGeometry(m_geometry, plaintext.GetGeometry(), "GL encoded plaintext");
    ValidateOwnedContext(plaintext.GetCryptoContext(), "GL encoded plaintext");
    ValidateKeyContext(publicKey, "GL public encryption");

    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(m_geometry.GetRowCount());
    for (std::size_t row = 0; row < plaintext.GetRows().size(); ++row) {
        auto ciphertext = m_context->Encrypt(publicKey, plaintext.GetRows()[row]);
        if (!ciphertext) {
            throw GLCiphertextError(RowMessage("OpenFHE public encryption returned null", row));
        }
        rows.push_back(std::move(ciphertext));
    }
    return GLCiphertext(m_geometry, m_context, std::move(rows));
}

GLCiphertext GLSchemelet::Encrypt(const PrivateKey<DCRTPoly>& privateKey,
                                  const GLEncodedPlaintext& plaintext) const {
    plaintext.Validate();
    RequireSameGeometry(m_geometry, plaintext.GetGeometry(), "GL encoded plaintext");
    ValidateOwnedContext(plaintext.GetCryptoContext(), "GL encoded plaintext");
    ValidateKeyContext(privateKey, "GL symmetric encryption");

    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(m_geometry.GetRowCount());
    for (std::size_t row = 0; row < plaintext.GetRows().size(); ++row) {
        auto ciphertext = m_context->Encrypt(privateKey, plaintext.GetRows()[row]);
        if (!ciphertext) {
            throw GLCiphertextError(RowMessage("OpenFHE symmetric encryption returned null", row));
        }
        rows.push_back(std::move(ciphertext));
    }
    return GLCiphertext(m_geometry, m_context, std::move(rows));
}

GLPlaintext GLSchemelet::Decrypt(const PrivateKey<DCRTPoly>& privateKey, const GLCiphertext& ciphertext) const {
    ciphertext.Validate();
    RequireSameGeometry(m_geometry, ciphertext.GetGeometry(), "GL ciphertext");
    ValidateOwnedContext(ciphertext.GetCryptoContext(), "GL ciphertext");
    ValidateKeyContext(privateKey, "GL decryption");
    if (privateKey->GetKeyTag() != ciphertext.GetKeyTag()) {
        throw GLKeyMismatchError("GL decryption key does not match the ciphertext row key tag");
    }

    std::vector<std::complex<double>> coefficients;
    coefficients.reserve(m_geometry.GetCellCount());
    for (std::size_t row = 0; row < ciphertext.GetRows().size(); ++row) {
        Plaintext decoded;
        const auto result = m_context->Decrypt(privateKey, ciphertext.GetRows()[row], &decoded);
        if (!result.isValid || !decoded) {
            throw GLCiphertextError(RowMessage("OpenFHE failed to decrypt GL ciphertext", row));
        }
        decoded->SetLength(m_geometry.GetColumnsPerRow());
        const auto& packed = decoded->GetCKKSPackedValue();
        if (packed.size() < m_geometry.GetColumnsPerRow()) {
            throw GLDimensionError(RowMessage("decrypted GL row has too few active columns", row));
        }
        coefficients.insert(coefficients.end(), packed.begin(),
                            packed.begin() + static_cast<std::ptrdiff_t>(m_geometry.GetColumnsPerRow()));
    }
    return GLPlaintext(m_geometry, EvaluateYAxis(m_geometry, coefficients));
}

GLCiphertext GLSchemelet::Add(const GLCiphertext& lhs, const GLCiphertext& rhs) const {
    lhs.Validate();
    rhs.Validate();
    RequireSameGeometry(m_geometry, lhs.GetGeometry(), "left GL ciphertext");
    RequireSameGeometry(m_geometry, rhs.GetGeometry(), "right GL ciphertext");
    ValidateOwnedContext(lhs.GetCryptoContext(), "left GL ciphertext");
    ValidateOwnedContext(rhs.GetCryptoContext(), "right GL ciphertext");
    if (lhs.GetKeyTag() != rhs.GetKeyTag()) {
        throw GLKeyMismatchError("GL addition requires every row to use the same shared key");
    }

    std::vector<Ciphertext<DCRTPoly>> rows;
    rows.reserve(m_geometry.GetRowCount());
    for (std::size_t row = 0; row < m_geometry.GetRowCount(); ++row) {
        auto sum = m_context->EvalAdd(lhs.GetRows()[row], rhs.GetRows()[row]);
        if (!sum) {
            throw GLCiphertextError(RowMessage("OpenFHE GL row addition returned null", row));
        }
        rows.push_back(std::move(sum));
    }
    return GLCiphertext(m_geometry, m_context, std::move(rows));
}

GLCiphertext GLSchemelet::EvalCircledastPlainNative(const GLCiphertext& lhs,
                                                    const GLPlaintext& rhs) const {
    ValidateNativeTrace(lhs, "EvalCircledastPlainNative");
    RequireSameGeometry(m_geometry, rhs.GetGeometry(), "right GL plaintext");
    return EvaluateNativePlainTrace(m_context, m_geometry, lhs, rhs, 1);
}

GLCiphertext GLSchemelet::EvalMatMulPlainNative(const GLCiphertext& lhs,
                                               const GLPlaintext& rhs) const {
    ValidateNativeTrace(lhs, "EvalMatMulPlainNative");
    RequireSameGeometry(m_geometry, rhs.GetGeometry(), "right GL plaintext");

    // circledast(A, B^*) represents A*B/n.  Multiplication of both output
    // components by the exact public integer n restores ordinary A*B without
    // changing the CKKS scale metadata.
    return EvaluateNativePlainTrace(m_context, m_geometry, lhs, AdjointPlaintext(rhs),
                                    static_cast<int64_t>(m_geometry.GetDimension()));
}

GLNativeEvalKey GLSchemelet::EvalMatMulNativeKeyGen(
    const PrivateKey<DCRTPoly>& privateKey) const {
    ValidateKeyContext(privateKey, "EvalMatMulNativeKeyGen");
    if (!UsesExactNativeRing()) {
        throw GLNativeModeError("EvalMatMulNativeKeyGen requires exact native ringDimension=2n");
    }

    const auto n = m_geometry.GetDimension();
    auto secret = privateKey->GetPrivateElement();
    secret.SetFormat(Format::EVALUATION);
    auto conjugateInverse = secret.Transpose();

    std::vector<EvalKey<DCRTPoly>> conjugateRows;
    std::vector<EvalKey<DCRTPoly>> productRows;
    conjugateRows.reserve(n);
    productRows.reserve(n);
    for (std::size_t row = 0; row < n; ++row) {
        auto conjugateSource = GaussianConstantFromCoefficient(conjugateInverse, row, n);
        // These source-key wrappers are iteration-local.  KeySwitchGen returns
        // destination-bound EvalKeys; no PrivateKeyImpl is stored in the
        // GLNativeEvalKey bundle constructed below.
        auto conjugatePrivate = std::make_shared<PrivateKeyImpl<DCRTPoly>>(m_context);
        conjugatePrivate->SetPrivateElement(conjugateSource);
        conjugateRows.push_back(m_context->KeySwitchGen(conjugatePrivate, privateKey));

        auto productPrivate = std::make_shared<PrivateKeyImpl<DCRTPoly>>(m_context);
        productPrivate->SetPrivateElement(secret * conjugateSource);
        productRows.push_back(m_context->KeySwitchGen(productPrivate, privateKey));
    }

    return GLNativeEvalKey(m_geometry, m_context, privateKey->GetKeyTag(),
                           std::move(conjugateRows), std::move(productRows));
}

GLCiphertext GLSchemelet::EvalAdjointNative(
    const GLCiphertext& ciphertext, const GLNativeEvalKey& evaluationKey) const {
    ValidateNativeTrace(ciphertext, "EvalAdjointNative");
    ValidateNativeEvaluationKey(evaluationKey, ciphertext.GetKeyTag(), "EvalAdjointNative");
    return EvaluateNativeAdjoint(m_context, m_geometry, ciphertext,
                                 evaluationKey.m_conjugateRows);
}

GLCiphertext GLSchemelet::EvalCircledastNative(
    const GLCiphertext& lhs, const GLCiphertext& rhs,
    const GLNativeEvalKey& evaluationKey) const {
    ValidateNativeTrace(lhs, "EvalCircledastNative left operand");
    ValidateNativeTrace(rhs, "EvalCircledastNative right operand");
    RequireNativeCipherPairCompatible(lhs, rhs, "EvalCircledastNative");
    ValidateNativeEvaluationKey(evaluationKey, lhs.GetKeyTag(), "EvalCircledastNative");
    return EvaluateNativeCipherTrace(m_context, m_geometry, lhs, rhs,
                                     evaluationKey.m_conjugateRows,
                                     evaluationKey.m_productRows, 1);
}

GLCiphertext GLSchemelet::EvalMatMulNative(
    const GLCiphertext& lhs, const GLCiphertext& rhs,
    const GLNativeEvalKey& evaluationKey) const {
    ValidateNativeTrace(lhs, "EvalMatMulNative left operand");
    ValidateNativeTrace(rhs, "EvalMatMulNative right operand");
    RequireNativeCipherPairCompatible(lhs, rhs, "EvalMatMulNative");
    ValidateNativeEvaluationKey(evaluationKey, lhs.GetKeyTag(), "EvalMatMulNative");

    // circledast(A, adjoint(B)) represents A*B/n.  The exact factor is
    // applied to all four source components before either big key switch.
    const auto adjoint = EvaluateNativeAdjoint(m_context, m_geometry, rhs,
                                               evaluationKey.m_conjugateRows);
    return EvaluateNativeCipherTrace(
        m_context, m_geometry, lhs, adjoint, evaluationKey.m_conjugateRows,
        evaluationKey.m_productRows, static_cast<int64_t>(m_geometry.GetDimension()));
}

GLCiphertext GLSchemelet::EvalMatMulPlain(const GLCiphertext& lhs, const GLPlaintext& rhs) const {
    ValidateReferenceCircuit(3, "EvalMatMulPlain");
    ValidateMatMulCiphertext(lhs, "left GL ciphertext");
    RequireSameGeometry(m_geometry, rhs.GetGeometry(), "right GL plaintext");

    const auto n = m_geometry.GetDimension();
    const auto leftColumns = EvaluateEncryptedYAxis(m_context, m_geometry, lhs.GetRows());

    std::vector<Ciphertext<DCRTPoly>> productColumns;
    productColumns.reserve(n);
    for (std::size_t column = 0; column < n; ++column) {
        std::vector<std::complex<double>> weights;
        weights.reserve(n);
        for (std::size_t inner = 0; inner < n; ++inner) {
            weights.push_back(rhs.At(inner, column));
        }
        productColumns.push_back(EvalEncryptedLinearCombination(
            m_context, leftColumns, weights, "clear-right reference matrix product"));
    }

    return GLCiphertext(m_geometry, m_context,
                        InterpolateEncryptedYAxis(m_context, m_geometry, productColumns));
}

void GLSchemelet::EvalMatMulReferenceKeyGen(const PrivateKey<DCRTPoly>& privateKey) const {
    ValidateKeyContext(privateKey, "EvalMatMulReferenceKeyGen");
    m_context->EvalMultKeyGen(privateKey);
    m_context->EvalSumKeyGen(privateKey);
}

GLCiphertext GLSchemelet::EvalMatMulReference(const GLCiphertext& lhs, const GLCiphertext& rhs) const {
    ValidateReferenceCircuit(4, "EvalMatMulReference");
    ValidateMatMulCiphertext(lhs, "left GL ciphertext");
    ValidateMatMulCiphertext(rhs, "right GL ciphertext");
    if (lhs.GetKeyTag() != rhs.GetKeyTag()) {
        throw GLKeyMismatchError("EvalMatMulReference requires both operands to use the same shared key");
    }
    ValidateReferenceEvaluationKeys(lhs.GetKeyTag());

    const auto n = m_geometry.GetDimension();
    const auto leftColumns  = EvaluateEncryptedYAxis(m_context, m_geometry, lhs.GetRows());
    const auto rightColumns = EvaluateEncryptedYAxis(m_context, m_geometry, rhs.GetRows());

    std::vector<Ciphertext<DCRTPoly>> productColumns;
    productColumns.reserve(n);
    for (std::size_t column = 0; column < n; ++column) {
        Ciphertext<DCRTPoly> accumulated;
        for (std::size_t inner = 0; inner < n; ++inner) {
            std::vector<std::complex<double>> oneHot(n, {0.0, 0.0});
            oneHot[inner] = {1.0, 0.0};
            auto mask = m_context->MakeCKKSPackedPlaintext(
                oneHot, 1, rightColumns[column]->GetLevel(), nullptr, static_cast<uint32_t>(n));
            if (!mask) {
                throw GLCiphertextError("OpenFHE failed to encode a reference matrix-product slot mask");
            }

            auto selected = m_context->EvalMult(rightColumns[column], mask);
            auto broadcast = m_context->EvalSum(selected, static_cast<uint32_t>(n));
            auto product = m_context->EvalMultAndRelinearize(leftColumns[inner], broadcast);
            if (!product) {
                throw GLCiphertextError("OpenFHE returned null during reference ciphertext multiplication");
            }
            if (accumulated) {
                m_context->EvalAddInPlace(accumulated, product);
            }
            else {
                accumulated = std::move(product);
            }
        }
        productColumns.push_back(std::move(accumulated));
    }

    return GLCiphertext(m_geometry, m_context,
                        InterpolateEncryptedYAxis(m_context, m_geometry, productColumns));
}

void GLSchemelet::ValidateOwnedContext(const CryptoContext<DCRTPoly>& context, const char* objectName) const {
    if (!context || context.get() != m_context.get()) {
        throw GLContextMismatchError(std::string(objectName) + " belongs to a different CryptoContext");
    }
}

void GLSchemelet::ValidateKeyContext(const PublicKey<DCRTPoly>& key, const char* operation) const {
    if (!key) {
        throw GLKeyMismatchError(std::string(operation) + " requires a non-null public key");
    }
    if (key->GetCryptoContext().get() != m_context.get()) {
        throw GLKeyContextMismatchError(std::string(operation) + " key belongs to a different CryptoContext");
    }
}

void GLSchemelet::ValidateKeyContext(const PrivateKey<DCRTPoly>& key, const char* operation) const {
    if (!key) {
        throw GLKeyMismatchError(std::string(operation) + " requires a non-null private key");
    }
    if (key->GetCryptoContext().get() != m_context.get()) {
        throw GLKeyContextMismatchError(std::string(operation) + " key belongs to a different CryptoContext");
    }
}

void GLSchemelet::ValidateMatMulCiphertext(const GLCiphertext& ciphertext, const char* objectName) const {
    ciphertext.Validate();
    RequireSameGeometry(m_geometry, ciphertext.GetGeometry(), objectName);
    ValidateOwnedContext(ciphertext.GetCryptoContext(), objectName);
}

void GLSchemelet::ValidateReferenceCircuit(uint32_t minimumDepth, const char* operation) const {
    if (m_parameters.multiplicativeDepth < minimumDepth) {
        std::ostringstream os;
        os << operation << " requires multiplicativeDepth >= " << minimumDepth;
        throw GLDepthError(os.str());
    }
    if (m_parameters.scalingTechnique != FIXEDAUTO && m_parameters.scalingTechnique != FLEXIBLEAUTO) {
        throw GLReferenceCircuitError(std::string(operation) +
                                      " supports only FIXEDAUTO or FLEXIBLEAUTO automatic rescaling");
    }
}

void GLSchemelet::ValidateReferenceEvaluationKeys(const std::string& keyTag) const {
    const auto& allMultKeys = CryptoContextImpl<DCRTPoly>::GetAllEvalMultKeys();
    const auto multIt       = allMultKeys.find(keyTag);
    if (multIt == allMultKeys.end() || multIt->second.empty() || !multIt->second.front() ||
        multIt->second.front()->GetCryptoContext().get() != m_context.get()) {
        throw GLMissingEvaluationKeyError(
            "EvalMatMulReference is missing its relinearization key; call EvalMatMulReferenceKeyGen");
    }

    const auto requiredIndices = RequiredEvalSumIndices(m_context, m_geometry);
    const auto& allAutomorphismKeys = CryptoContextImpl<DCRTPoly>::GetAllEvalAutomorphismKeys();
    const auto automorphismIt       = allAutomorphismKeys.find(keyTag);
    if (automorphismIt == allAutomorphismKeys.end() || !automorphismIt->second) {
        throw GLMissingEvaluationKeyError(
            "EvalMatMulReference is missing its slot-sum keys; call EvalMatMulReferenceKeyGen");
    }
    for (const auto index : requiredIndices) {
        const auto keyIt = automorphismIt->second->find(index);
        if (keyIt == automorphismIt->second->end() || !keyIt->second ||
            keyIt->second->GetCryptoContext().get() != m_context.get()) {
            throw GLMissingEvaluationKeyError(
                "EvalMatMulReference is missing a required slot-sum key; call EvalMatMulReferenceKeyGen");
        }
    }
}

void GLSchemelet::ValidateNativeTrace(const GLCiphertext& ciphertext, const char* operation) const {
    ValidateMatMulCiphertext(ciphertext, operation);
    if (!UsesExactNativeRing()) {
        throw GLNativeModeError(std::string(operation) + " requires exact native ringDimension=2n");
    }
    if (m_parameters.multiplicativeDepth < 1) {
        throw GLDepthError(std::string(operation) + " requires multiplicativeDepth >= 1");
    }

    const auto& first = ciphertext.GetRows().front();
    for (std::size_t row = 1; row < ciphertext.GetRows().size(); ++row) {
        const auto& current = ciphertext.GetRows()[row];
        if (current->GetLevel() != first->GetLevel() ||
            current->GetNoiseScaleDeg() != first->GetNoiseScaleDeg() ||
            current->GetScalingFactor() != first->GetScalingFactor() ||
            current->GetElements().front().GetNumOfElements() !=
                first->GetElements().front().GetNumOfElements()) {
            throw GLCiphertextError(RowMessage("native GL trace row metadata mismatch", row));
        }
    }
}

void GLSchemelet::ValidateNativeEvaluationKey(const GLNativeEvalKey& evaluationKey,
                                              const std::string& keyTag,
                                              const char* operation) const {
    evaluationKey.Validate();
    RequireSameGeometry(m_geometry, evaluationKey.GetGeometry(), "native GL evaluation key");
    ValidateOwnedContext(evaluationKey.GetCryptoContext(), "native GL evaluation key");
    if (evaluationKey.GetKeyTag() != keyTag) {
        throw GLKeyMismatchError(std::string(operation) +
                                 " evaluation key does not match the ciphertext key tag");
    }
}

}  // namespace lbcrypto
