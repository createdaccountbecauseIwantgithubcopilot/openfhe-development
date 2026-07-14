//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#include "scheme/ckksrns/ckksrns-paco.h"

#include "encoding/plaintext.h"
#include "math/distributiongenerator.h"
#include "math/nbtheory.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "schemebase/rlwe-cryptoparameters.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <future>
#include <limits>
#include <random>
#include <set>
#include <sstream>
#include <thread>
#include <utility>

namespace lbcrypto {
namespace {

constexpr long double kPi = 3.141592653589793238462643383279502884L;

bool IsPowerOfTwo(uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

uint32_t ExactLog2(uint32_t value) {
    if (!IsPowerOfTwo(value))
        OPENFHE_THROW("PaCo requires a power-of-two value");
    uint32_t result = 0;
    while (value > 1) {
        value >>= 1;
        ++result;
    }
    return result;
}

uint32_t CeilDiv(uint32_t numerator, uint32_t denominator) {
    if (denominator == 0)
        OPENFHE_THROW("PaCo division by zero");
    return numerator == 0 ? 0 : 1 + (numerator - 1) / denominator;
}

uint64_t PowMod(uint64_t base, uint64_t exponent, uint64_t modulus) {
    if (modulus == 0)
        OPENFHE_THROW("PaCo modular exponentiation with zero modulus");
    return NativeInteger(base).ModExp(NativeInteger(exponent), NativeInteger(modulus)).ConvertToInt<uint64_t>();
}

std::complex<double> Root4N(uint32_t dimension, uint64_t exponent) {
    const uint64_t order    = 4ULL * dimension;
    const long double angle = 2.0L * kPi * static_cast<long double>(exponent % order) / static_cast<long double>(order);
    return {static_cast<double>(std::cos(angle)), static_cast<double>(std::sin(angle))};
}

void AddDiagonal(paco::detail::SparseDiagonalMatrix& matrix, int64_t index,
                 const std::vector<std::complex<double>>& values) {
    if (matrix.dimension == 0 || values.size() != matrix.dimension)
        OPENFHE_THROW("PaCo diagonal has the wrong dimension");
    int64_t canonical = index % static_cast<int64_t>(matrix.dimension);
    if (canonical < 0)
        canonical += matrix.dimension;
    auto [it, inserted] = matrix.diagonals.emplace(static_cast<uint32_t>(canonical), values);
    if (!inserted) {
        for (uint32_t i = 0; i < matrix.dimension; ++i)
            it->second[i] += values[i];
    }
}

int32_t SymmetricDiagonal(uint32_t canonical, uint32_t dimension) {
    return canonical <= dimension / 2 ? static_cast<int32_t>(canonical) :
                                        static_cast<int32_t>(canonical) - static_cast<int32_t>(dimension);
}

std::vector<std::complex<double>> ApplyForwardDStages(std::vector<std::complex<double>> values, uint32_t C) {
    const uint32_t logC = ExactLog2(C);
    for (int32_t l = static_cast<int32_t>(logC); l >= 0; --l)
        values = paco::detail::MakeDStage(static_cast<uint32_t>(values.size()), static_cast<uint32_t>(l)).Apply(values);
    return values;
}

uint64_t AddModulo(uint64_t lhs, uint64_t rhs, uint64_t modulus) {
    lhs %= modulus;
    rhs %= modulus;
    return lhs >= modulus - rhs ? lhs - (modulus - rhs) : lhs + rhs;
}

uint64_t NegateModulo(uint64_t value, uint64_t modulus) {
    value %= modulus;
    return value == 0 ? 0 : modulus - value;
}

std::complex<double> CirclePhase(uint64_t residue, uint64_t modulus) {
    residue %= modulus;
    const long double centered = residue > modulus / 2 ?
                                     static_cast<long double>(residue) - static_cast<long double>(modulus) :
                                     static_cast<long double>(residue);
    const long double angle = 2.0L * kPi * centered / static_cast<long double>(modulus);
    return {static_cast<double>(std::cos(angle)), static_cast<double>(std::sin(angle))};
}

std::vector<std::complex<double>> PeriodicExpand(const std::vector<std::complex<double>>& values,
                                                 uint32_t ambientSlots) {
    if (values.empty() || ambientSlots % values.size() != 0)
        OPENFHE_THROW("PaCo logical vector does not divide the ambient slot count");
    std::vector<std::complex<double>> result(ambientSlots);
    for (uint32_t i = 0; i < ambientSlots; ++i)
        result[i] = values[i % values.size()];
    return result;
}

std::shared_ptr<DCRTPoly::Params> PublicKeyParams(const std::shared_ptr<CryptoParametersRLWE<DCRTPoly>>& cryptoParams) {
    auto params = cryptoParams->GetParamsPK();
    return params ? params : cryptoParams->GetElementParams();
}

DCRTPoly StructuredSecret(const std::shared_ptr<DCRTPoly::Params>& params, const std::vector<uint32_t>& shifts,
                          const std::vector<uint8_t>& selectors, uint32_t h) {
    DCRTPoly secret(params, Format::COEFFICIENT, true);
    for (uint32_t towerIndex = 0; towerIndex < secret.GetNumOfElements(); ++towerIndex) {
        auto tower = secret.GetElementAtIndex(towerIndex);
        for (uint32_t v = 0; v < 4 * h; ++v) {
            if (selectors[v] != 0)
                tower[v + shifts[v] * 4 * h] = NativeInteger(1);
        }
        secret.SetElementAtIndex(towerIndex, std::move(tower));
    }
    secret.SetFormat(Format::EVALUATION);
    return secret;
}

uint64_t BottomModulus(ConstCiphertext<DCRTPoly> ciphertext) {
    return ciphertext->GetElements()[0].GetElementAtIndex(0).GetModulus().ConvertToInt();
}

}  // namespace

uint32_t PaCoParameters::CoefficientBudget(uint32_t ringDimension) const {
    Validate(ringDimension);
    return ringDimension / (4 * h);
}

uint32_t PaCoParameters::ResidueBlockCount(uint32_t ringDimension) const {
    Validate(ringDimension);
    return ringDimension / (4 * h * C);
}

uint32_t PaCoParameters::PartialRingSlots() const {
    if (h == 0 || C == 0)
        OPENFHE_THROW("PaCo h and C must be configured");
    const uint64_t result = 2ULL * h * C;
    if (result > std::numeric_limits<uint32_t>::max())
        OPENFHE_THROW("PaCo partial ring size overflows uint32_t");
    return static_cast<uint32_t>(result);
}

uint32_t PaCoParameters::MultiplicativeDepth() const {
    if (!IsPowerOfTwo(h) || !IsPowerOfTwo(C) || C < 2 || g0 == 0 || g1 == 0)
        OPENFHE_THROW("PaCo parameters are not initialized");
    const uint32_t partialLayers = ExactLog2(C) + 1;
    const uint32_t finalLayers   = ExactLog2(C) - 1;
    return CeilDiv(partialLayers, g0) + CeilDiv(finalLayers, g1) + ExactLog2(h) + 3;
}

void PaCoParameters::Validate(uint32_t ringDimension) const {
    if (!IsPowerOfTwo(ringDimension))
        OPENFHE_THROW("PaCo ring dimension N must be a power of two");
    if (!IsPowerOfTwo(h))
        OPENFHE_THROW("PaCo secret weight h must be a power of two");
    if (!IsPowerOfTwo(C) || C < 2)
        OPENFHE_THROW("PaCo coefficient count C must be a power of two at least 2");
    if (g0 == 0 || g1 == 0)
        OPENFHE_THROW("PaCo grouping parameters must be positive");
    const uint64_t denominator = 4ULL * h;
    if (ringDimension % denominator != 0)
        OPENFHE_THROW("PaCo requires 4*h to divide N");
    const uint64_t budget = ringDimension / denominator;
    if (C > budget)
        OPENFHE_THROW("PaCo requires C <= N/(4*h)");
    if (budget % C != 0)
        OPENFHE_THROW("PaCo requires C to divide N/(4*h)");
}

PaCoPaperParameterSet PaCoPaperSetI() {
    return {"PaCo I", 15, 29, 22, 32, 64, 3, 14, 934, 12};
}

PaCoPaperParameterSet PaCoPaperSetII() {
    return {"PaCo II", 16, 44, 32, 48, 64, 3, 15, 1496, 22};
}

namespace paco::detail {

SparseDiagonalMatrix SparseDiagonalMatrix::Identity(uint32_t dimension) {
    if (!IsPowerOfTwo(dimension))
        OPENFHE_THROW("PaCo matrix dimension must be a power of two");
    SparseDiagonalMatrix result;
    result.dimension = dimension;
    result.diagonals.emplace(0, std::vector<std::complex<double>>(dimension, {1.0, 0.0}));
    return result;
}

std::vector<std::complex<double>> SparseDiagonalMatrix::Apply(const std::vector<std::complex<double>>& input) const {
    if (dimension == 0 || input.size() != dimension)
        OPENFHE_THROW("PaCo matrix/vector dimension mismatch");
    std::vector<std::complex<double>> output(dimension, {0.0, 0.0});
    for (const auto& [diagonal, values] : diagonals) {
        if (values.size() != dimension)
            OPENFHE_THROW("PaCo malformed diagonal");
        for (uint32_t row = 0; row < dimension; ++row)
            output[row] += values[row] * input[(row + diagonal) % dimension];
    }
    return output;
}

uint32_t BitReverse(uint32_t value, uint32_t bits) {
    uint32_t result = 0;
    for (uint32_t i = 0; i < bits; ++i) {
        result = (result << 1) | (value & 1U);
        value >>= 1;
    }
    return result;
}

uint32_t ExtendedBitReverse(uint32_t value, uint32_t blockSize) {
    if (!IsPowerOfTwo(blockSize))
        OPENFHE_THROW("PaCo bit-reversal block must be a power of two");
    return (value / blockSize) * blockSize + BitReverse(value % blockSize, ExactLog2(blockSize));
}

std::vector<std::complex<double>> ExtendedBitReverseVector(const std::vector<std::complex<double>>& input,
                                                           uint32_t blockSize) {
    if (!IsPowerOfTwo(blockSize) || input.size() % blockSize != 0)
        OPENFHE_THROW("PaCo extended bit reversal has incompatible dimensions");
    std::vector<std::complex<double>> output(input.size());
    for (uint32_t i = 0; i < input.size(); ++i)
        output[i] = input[ExtendedBitReverse(i, blockSize)];
    return output;
}

SparseDiagonalMatrix Multiply(const SparseDiagonalMatrix& left, const SparseDiagonalMatrix& right) {
    if (left.dimension == 0 || left.dimension != right.dimension)
        OPENFHE_THROW("PaCo matrix multiplication dimension mismatch");
    SparseDiagonalMatrix output;
    output.dimension = left.dimension;
    for (const auto& [leftIndex, leftValues] : left.diagonals) {
        for (const auto& [rightIndex, rightValues] : right.diagonals) {
            std::vector<std::complex<double>> diagonal(output.dimension);
            for (uint32_t row = 0; row < output.dimension; ++row)
                diagonal[row] = leftValues[row] * rightValues[(row + leftIndex) % output.dimension];
            AddDiagonal(output, static_cast<uint64_t>(leftIndex) + rightIndex, diagonal);
        }
    }
    return output;
}

SparseDiagonalMatrix MakeDStage(uint32_t dimension, uint32_t logStride, bool inverse) {
    if (!IsPowerOfTwo(dimension))
        OPENFHE_THROW("PaCo D-stage dimension must be a power of two");
    const uint32_t logDimension = ExactLog2(dimension);
    if (logStride >= logDimension)
        OPENFHE_THROW("PaCo D-stage stride is too large");
    const uint32_t halfStride = 1U << logStride;
    const uint32_t stride     = 2 * halfStride;
    const uint64_t rootOrder  = 4ULL * dimension;

    std::vector<uint64_t> exponents(dimension / stride);
    for (uint32_t block = 0; block < exponents.size(); ++block) {
        const uint32_t reversed = BitReverse(block, logDimension - 1 - logStride);
        exponents[block]        = (static_cast<uint64_t>(halfStride) * PowMod(5, reversed, rootOrder)) % rootOrder;
    }

    std::vector<std::complex<double>> diag0(dimension, {0.0, 0.0});
    std::vector<std::complex<double>> diagPositive(dimension, {0.0, 0.0});
    std::vector<std::complex<double>> diagNegative(dimension, {0.0, 0.0});
    for (uint32_t row = 0; row < dimension; ++row) {
        const uint32_t block = row / stride;
        const bool upper     = (row % stride) >= halfStride;
        if (!inverse) {
            if (!upper) {
                diag0[row]        = {1.0, 0.0};
                diagPositive[row] = Root4N(dimension, exponents[block]);
            }
            else {
                diag0[row]        = -Root4N(dimension, exponents[block]);
                diagNegative[row] = {1.0, 0.0};
            }
        }
        else {
            if (!upper) {
                diag0[row]        = {0.5, 0.0};
                diagPositive[row] = {0.5, 0.0};
            }
            else {
                const auto root   = 0.5 * Root4N(dimension, (rootOrder - exponents[block]) % rootOrder);
                diag0[row]        = -root;
                diagNegative[row] = root;
            }
        }
    }

    SparseDiagonalMatrix result;
    result.dimension = dimension;
    AddDiagonal(result, 0, diag0);
    if (halfStride == dimension / 2) {
        for (uint32_t row = 0; row < dimension; ++row)
            diagPositive[row] += diagNegative[row];
        AddDiagonal(result, halfStride, diagPositive);
    }
    else {
        AddDiagonal(result, halfStride, diagPositive);
        AddDiagonal(result, -static_cast<int64_t>(halfStride), diagNegative);
    }
    return result;
}

SparseDiagonalMatrix MakeEStage(uint32_t dimension, uint32_t logStride, uint32_t reversalBlock, bool inverse) {
    if (!IsPowerOfTwo(dimension) || !IsPowerOfTwo(reversalBlock) || reversalBlock > dimension ||
        dimension % reversalBlock != 0)
        OPENFHE_THROW("PaCo E-stage has invalid dimensions");
    if (logStride >= ExactLog2(dimension))
        OPENFHE_THROW("PaCo E-stage stride is too large");

    const uint64_t divisor    = 2ULL * (1ULL << logStride);
    const uint32_t halfStride = static_cast<uint32_t>(reversalBlock / divisor);
    if (halfStride < 1)
        return MakeDStage(dimension, logStride, inverse);

    const uint32_t stride                = 2 * halfStride;
    const uint32_t dimensionOverBlock    = dimension / reversalBlock;
    const uint32_t logDimensionOverBlock = ExactLog2(dimensionOverBlock);
    const uint64_t rootOrder             = 4ULL * dimension;

    std::vector<std::complex<double>> diag0(dimension, {0.0, 0.0});
    std::vector<std::complex<double>> diagPositive(dimension, {0.0, 0.0});
    std::vector<std::complex<double>> diagNegative(dimension, {0.0, 0.0});
    for (uint32_t row = 0; row < dimension; ++row) {
        const uint32_t rowDiv = row / stride;
        const uint32_t rowMod = row % stride;
        const bool upper      = rowMod >= halfStride;
        const uint32_t local  = upper ? rowMod - halfStride : rowMod;
        const uint64_t exponent =
            static_cast<uint64_t>(local) * dimensionOverBlock + BitReverse(rowDiv >> logStride, logDimensionOverBlock);
        const uint64_t rootExponent = ((1ULL << logStride) * PowMod(5, exponent, rootOrder)) % rootOrder;

        if (!inverse) {
            if (!upper) {
                diag0[row]        = {1.0, 0.0};
                diagPositive[row] = Root4N(dimension, rootExponent);
            }
            else {
                diag0[row]        = -Root4N(dimension, rootExponent);
                diagNegative[row] = {1.0, 0.0};
            }
        }
        else {
            if (!upper) {
                diag0[row]        = {0.5, 0.0};
                diagPositive[row] = {0.5, 0.0};
            }
            else {
                const auto root   = 0.5 * Root4N(dimension, (rootOrder - rootExponent) % rootOrder);
                diag0[row]        = -root;
                diagNegative[row] = root;
            }
        }
    }

    SparseDiagonalMatrix result;
    result.dimension = dimension;
    AddDiagonal(result, 0, diag0);
    if (halfStride == dimension / 2) {
        for (uint32_t row = 0; row < dimension; ++row)
            diagPositive[row] += diagNegative[row];
        AddDiagonal(result, halfStride, diagPositive);
    }
    else {
        AddDiagonal(result, halfStride, diagPositive);
        AddDiagonal(result, -static_cast<int64_t>(halfStride), diagNegative);
    }
    return result;
}

std::vector<SparseDiagonalMatrix> GroupStages(const std::vector<SparseDiagonalMatrix>& stages, uint32_t groupSize,
                                              bool rightToLeft) {
    if (groupSize == 0)
        OPENFHE_THROW("PaCo matrix group size must be positive");
    if (stages.empty())
        return {};
    const uint32_t dimension = stages.front().dimension;
    for (const auto& stage : stages) {
        if (stage.dimension != dimension)
            OPENFHE_THROW("PaCo cannot group matrices of different dimensions");
    }
    const uint32_t blockCount = CeilDiv(static_cast<uint32_t>(stages.size()), groupSize);
    std::vector<SparseDiagonalMatrix> output(blockCount);
    for (uint32_t block = 0; block < blockCount; ++block) {
        const uint32_t begin = block * groupSize;
        const uint32_t end   = std::min<uint32_t>(begin + groupSize, stages.size());
        auto product         = SparseDiagonalMatrix::Identity(dimension);
        if (!rightToLeft) {
            for (uint32_t i = begin; i < end; ++i)
                product = Multiply(product, stages[i]);
            output[blockCount - 1 - block] = std::move(product);
        }
        else {
            for (uint32_t i = begin; i < end; ++i)
                product = Multiply(stages[i], product);
            output[block] = std::move(product);
        }
    }
    return output;
}

}  // namespace paco::detail

PaCoCKKSRNS::PaCoCKKSRNS(CryptoContext<DCRTPoly> context, PaCoParameters parameters)
    : m_context(std::move(context)), m_parameters(parameters) {
#if NATIVEINT != 64
    OPENFHE_THROW("PaCo phase extraction currently requires a 64-bit NativeInteger build");
#endif
    if (!m_context)
        OPENFHE_THROW("PaCo requires a non-null CryptoContext");
    m_ringDimension = m_context->GetRingDimension();
    m_slots         = m_ringDimension / 2;
    m_parameters.Validate(m_ringDimension);
    m_k = m_parameters.ResidueBlockCount(m_ringDimension);
    m_n = m_parameters.PartialRingSlots();

    if (m_context->GetCKKSDataType() != COMPLEX)
        OPENFHE_THROW("PaCo requires CKKSDataType COMPLEX");
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(m_context->GetCryptoParameters());
    if (!cryptoParams)
        OPENFHE_THROW("PaCo requires a CKKS-RNS CryptoContext");
    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
        OPENFHE_THROW("PaCo currently supports only HYBRID key switching");
    if (cryptoParams->GetScalingTechnique() != FLEXIBLEAUTO)
        OPENFHE_THROW("PaCo currently supports only FLEXIBLEAUTO scaling");
    if (cryptoParams->GetCompositeDegree() != 1)
        OPENFHE_THROW("PaCo currently requires one prime per CKKS level");
    m_totalTowers        = cryptoParams->GetElementParams()->GetParams().size();
    const uint32_t depth = m_parameters.MultiplicativeDepth();
    if (m_totalTowers < depth + 2)
        OPENFHE_THROW("PaCo requires enough Q towers to refresh at least one usable output level");
    m_outputBootstrapScale = cryptoParams->GetScalingFactorReal(depth);

    std::vector<paco::detail::SparseDiagonalMatrix> partialStages;
    for (uint32_t l = 0; l <= ExactLog2(m_parameters.C); ++l)
        partialStages.emplace_back(paco::detail::MakeEStage(m_n, l, m_parameters.C / 2, true));
    m_partialInverseStages = paco::detail::GroupStages(partialStages, m_parameters.g0, true);

    std::vector<paco::detail::SparseDiagonalMatrix> finalStages;
    const uint32_t finalLayerCount = ExactLog2(m_parameters.C) - 1;
    for (uint32_t l = 0; l < finalLayerCount; ++l)
        finalStages.emplace_back(paco::detail::MakeEStage(m_parameters.C / 2, l, m_parameters.C / 2, false));
    m_slotToCoefficientStages = paco::detail::GroupStages(finalStages, m_parameters.g1, false);
}

PaCoKeyMaterial PaCoCKKSRNS::KeyGen(CryptoContext<DCRTPoly> context, uint32_t h,
                                    std::optional<uint64_t> deterministicSeed) {
    if (!context)
        OPENFHE_THROW("PaCo KeyGen requires a non-null CryptoContext");
    const uint32_t N = context->GetRingDimension();
    if (!IsPowerOfTwo(h) || 8ULL * h > N)
        OPENFHE_THROW("PaCo KeyGen requires power-of-two h with 8*h <= N so C >= 2 exists");
    const uint32_t B = N / (4 * h);

    std::mt19937_64 deterministicEngine;
    if (deterministicSeed)
        deterministicEngine.seed(*deterministicSeed);
    auto sample = [&](uint32_t bound) {
        if (bound == 0)
            OPENFHE_THROW("PaCo attempted to sample from an empty interval");
        std::uniform_int_distribution<uint32_t> distribution(0, bound - 1);
        return deterministicSeed ? distribution(deterministicEngine) :
                                   distribution(PseudoRandomNumberGenerator::GetPRNG());
    };

    PaCoKeyMaterial result;
    result.h = h;
    result.shiftIndices.resize(4 * h);
    result.selectors.assign(4 * h, 0);
    result.shiftIndices[0] = 0;
    for (uint32_t v = 1; v < 4 * h; ++v)
        result.shiftIndices[v] = sample(B);
    result.selectors[0] = 1;
    for (uint32_t v = 1; v < h; ++v)
        result.selectors[sample(4) * h + v] = 1;

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(context->GetCryptoParameters());
    if (!cryptoParams || !cryptoParams->GetElementParams())
        OPENFHE_THROW("PaCo KeyGen could not obtain RLWE parameters");
    const auto paramsPK = PublicKeyParams(cryptoParams);
    DCRTPoly secretPK   = StructuredSecret(paramsPK, result.shiftIndices, result.selectors, h);

    DCRTPoly::DugType dug;
    DCRTPoly a(dug, paramsPK, Format::EVALUATION);
    DCRTPoly e(cryptoParams->GetDiscreteGaussianGenerator(), paramsPK, Format::EVALUATION);
    const NativeInteger noiseScale = cryptoParams->GetNoiseScale();
    DCRTPoly b(std::move((e *= noiseScale) -= (a * secretPK)));

    DCRTPoly secretQ(secretPK);
    const size_t qTowers = cryptoParams->GetElementParams()->GetParams().size();
    if (secretQ.GetNumOfElements() > qTowers)
        secretQ.DropLastElements(secretQ.GetNumOfElements() - qTowers);

    result.keyPair = KeyPair<DCRTPoly>(std::make_shared<PublicKeyImpl<DCRTPoly>>(context),
                                       std::make_shared<PrivateKeyImpl<DCRTPoly>>(context));
    result.keyPair.secretKey->SetPrivateElement(std::move(secretQ));
    result.keyPair.publicKey->SetPublicElements({std::move(b), std::move(a)});
    result.keyPair.publicKey->SetKeyTag(result.keyPair.secretKey->GetKeyTag());
    return result;
}

void PaCoCKKSRNS::GenerateBootstrapKeys(const PaCoKeyMaterial& ownerMaterial) {
    if (!ownerMaterial.keyPair.good())
        OPENFHE_THROW("PaCo owner key pair is incomplete");
    if (ownerMaterial.keyPair.secretKey->GetCryptoContext() != m_context ||
        ownerMaterial.keyPair.publicKey->GetCryptoContext() != m_context)
        OPENFHE_THROW("PaCo owner keys belong to a different CryptoContext");
    if (ownerMaterial.keyPair.secretKey->GetKeyTag().empty() ||
        ownerMaterial.keyPair.publicKey->GetKeyTag() != ownerMaterial.keyPair.secretKey->GetKeyTag())
        OPENFHE_THROW("PaCo owner public and private key tags do not match");
    if (ownerMaterial.h != m_parameters.h || ownerMaterial.shiftIndices.size() != 4 * m_parameters.h ||
        ownerMaterial.selectors.size() != 4 * m_parameters.h)
        OPENFHE_THROW("PaCo owner structure does not match configured h");

    uint32_t selectorWeight = 0;
    for (uint32_t v = 0; v < 4 * m_parameters.h; ++v) {
        if (ownerMaterial.shiftIndices[v] >= m_parameters.CoefficientBudget(m_ringDimension))
            OPENFHE_THROW("PaCo owner shift index is outside [0,B)");
        if (ownerMaterial.selectors[v] > 1)
            OPENFHE_THROW("PaCo owner selector is not binary");
        selectorWeight += ownerMaterial.selectors[v];
    }
    if (ownerMaterial.shiftIndices[0] != 0 || ownerMaterial.selectors[0] != 1 || selectorWeight != m_parameters.h)
        OPENFHE_THROW("PaCo owner material violates Algorithm 1");
    for (uint32_t v = 0; v < m_parameters.h; ++v) {
        uint32_t selected = 0;
        for (uint32_t t = 0; t < 4; ++t)
            selected += ownerMaterial.selectors[t * m_parameters.h + v];
        if (selected != 1)
            OPENFHE_THROW("PaCo owner material must select exactly one candidate in every block");
    }

    const auto& actualSecret = ownerMaterial.keyPair.secretKey->GetPrivateElement();
    const auto expectedSecret =
        StructuredSecret(actualSecret.GetParams(), ownerMaterial.shiftIndices, ownerMaterial.selectors, m_parameters.h);
    if (actualSecret != expectedSecret)
        OPENFHE_THROW("PaCo owner descriptor does not match the structured private key");

    PaCoBootstrapKeys generated;
    generated.parameters    = m_parameters;
    generated.ringDimension = m_ringDimension;
    generated.totalTowers   = m_totalTowers;

    for (uint32_t t = 0; t < 4; ++t) {
        std::vector<std::complex<double>> sigma(m_slots, {0.0, 0.0});
        for (uint32_t r = 0; r < m_k; ++r) {
            std::vector<std::complex<double>> block(m_n, {0.0, 0.0});
            for (uint32_t v = 0; v < m_parameters.h; ++v) {
                const uint32_t candidate = t * m_parameters.h + v;
                const uint32_t shifted   = ownerMaterial.shiftIndices[candidate] + r;
                if (shifted % m_k == 0)
                    block[v * 2 * m_parameters.C + shifted / m_k] =
                        static_cast<double>(ownerMaterial.selectors[candidate]);
            }
            block = ApplyForwardDStages(std::move(block), m_parameters.C);
            std::copy(block.begin(), block.end(), sigma.begin() + static_cast<size_t>(r) * m_n);
        }
        sigma                            = paco::detail::ExtendedBitReverseVector(sigma, m_parameters.C / 2);
        auto plaintext                   = m_context->MakeCKKSPackedPlaintext(sigma, 1, 0, nullptr, m_slots);
        generated.selectorCiphertexts[t] = m_context->Encrypt(ownerMaterial.keyPair.publicKey, plaintext);
    }

    generated.rotationIndices     = RequiredRotationIndices();
    generated.automorphismIndices = RequiredAutomorphismIndices(generated.rotationIndices);
    auto newlyGenerated =
        m_context->GetScheme()->EvalAutomorphismKeyGen(ownerMaterial.keyPair.secretKey, generated.automorphismIndices);
    generated.automorphismKeys = std::make_shared<std::map<uint32_t, EvalKey<DCRTPoly>>>();
    const auto& globalMaps     = CryptoContextImpl<DCRTPoly>::GetAllEvalAutomorphismKeys();
    const auto globalIt        = globalMaps.find(ownerMaterial.keyPair.secretKey->GetKeyTag());
    for (const uint32_t index : generated.automorphismIndices) {
        auto freshIt = newlyGenerated->find(index);
        if (freshIt != newlyGenerated->end()) {
            generated.automorphismKeys->emplace(index, freshIt->second);
            continue;
        }
        if (globalIt != globalMaps.end() && globalIt->second) {
            auto existingIt = globalIt->second->find(index);
            if (existingIt != globalIt->second->end()) {
                generated.automorphismKeys->emplace(index, existingIt->second);
                continue;
            }
        }
        OPENFHE_THROW("PaCo could not assemble a required automorphism key");
    }
    generated.multiplicationKey = m_context->GetScheme()->EvalMultKeyGen(ownerMaterial.keyPair.secretKey);
    generated.keyTag            = ownerMaterial.keyPair.secretKey->GetKeyTag();
    LoadBootstrapKeys(std::move(generated));
}

void PaCoCKKSRNS::LoadBootstrapKeys(PaCoBootstrapKeys bootstrapKeys) {
    if (bootstrapKeys.formatVersion != 1)
        OPENFHE_THROW("PaCo bootstrap-key format version is unsupported");
    const auto& p = bootstrapKeys.parameters;
    if (p.h != m_parameters.h || p.C != m_parameters.C || p.g0 != m_parameters.g0 || p.g1 != m_parameters.g1 ||
        bootstrapKeys.ringDimension != m_ringDimension || bootstrapKeys.totalTowers != m_totalTowers)
        OPENFHE_THROW("PaCo bootstrap keys do not match the configured context and parameters");
    if (bootstrapKeys.keyTag.empty())
        OPENFHE_THROW("PaCo bootstrap keys have an empty key tag");
    if (!bootstrapKeys.multiplicationKey || !bootstrapKeys.automorphismKeys ||
        bootstrapKeys.automorphismIndices.empty())
        OPENFHE_THROW("PaCo bootstrap key bundle is incomplete");
    if (bootstrapKeys.multiplicationKey->GetCryptoContext() != m_context ||
        bootstrapKeys.multiplicationKey->GetKeyTag() != bootstrapKeys.keyTag)
        OPENFHE_THROW("PaCo multiplication key has the wrong context or key tag");
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(m_context->GetCryptoParameters());
    const auto expectedDCRTParams      = cryptoParams->GetElementParams();
    const auto& expectedTowers         = expectedDCRTParams->GetParams();
    const double expectedSelectorScale = cryptoParams->GetScalingFactorReal(0);
    const auto componentMatches        = [&](const DCRTPoly& component) {
        if (component.GetFormat() != Format::EVALUATION || component.GetNumOfElements() != m_totalTowers ||
            component.GetRingDimension() != m_ringDimension || component.GetCyclotomicOrder() != 2 * m_ringDimension ||
            !component.GetParams() || *component.GetParams() != *expectedDCRTParams)
            return false;
        for (uint32_t towerIndex = 0; towerIndex < m_totalTowers; ++towerIndex) {
            const auto& tower    = component.GetElementAtIndex(towerIndex);
            const auto& expected = expectedTowers[towerIndex];
            if (tower.GetFormat() != Format::EVALUATION || tower.GetRingDimension() != expected->GetRingDimension() ||
                tower.GetCyclotomicOrder() != expected->GetCyclotomicOrder() ||
                tower.GetModulus() != expected->GetModulus() || tower.GetRootOfUnity() != expected->GetRootOfUnity() ||
                !tower.GetParams() || *tower.GetParams() != *expected)
                return false;
        }
        return true;
    };
    for (const auto& ciphertext : bootstrapKeys.selectorCiphertexts) {
        if (!ciphertext || ciphertext->GetCryptoContext() != m_context ||
            ciphertext->GetKeyTag() != bootstrapKeys.keyTag || ciphertext->GetLevel() != 0 ||
            ciphertext->GetElements().size() != 2 || ciphertext->GetEncodingType() != CKKS_PACKED_ENCODING ||
            ciphertext->GetSlots() != m_slots || ciphertext->GetNoiseScaleDeg() != 1 ||
            !std::isfinite(ciphertext->GetScalingFactor()) || ciphertext->GetScalingFactor() != expectedSelectorScale ||
            ciphertext->GetScalingFactorInt() != NativeInteger(1) ||
            !std::all_of(ciphertext->GetElements().begin(), ciphertext->GetElements().end(), componentMatches))
            OPENFHE_THROW("PaCo selector ciphertext metadata or Q basis is invalid");
    }
    const auto requiredRotations     = RequiredRotationIndices();
    const auto requiredAutomorphisms = RequiredAutomorphismIndices(requiredRotations);
    if (bootstrapKeys.rotationIndices != requiredRotations ||
        bootstrapKeys.automorphismIndices != requiredAutomorphisms ||
        bootstrapKeys.automorphismKeys->size() != requiredAutomorphisms.size())
        OPENFHE_THROW("PaCo bootstrap-key automorphism manifest does not match the evaluator schedule");
    for (const uint32_t index : requiredAutomorphisms) {
        const auto it = bootstrapKeys.automorphismKeys->find(index);
        if (it == bootstrapKeys.automorphismKeys->end() || !it->second || it->second->GetCryptoContext() != m_context ||
            it->second->GetKeyTag() != bootstrapKeys.keyTag)
            OPENFHE_THROW("PaCo automorphism manifest is missing a matching evaluation key");
    }
    for (auto& ciphertext : bootstrapKeys.selectorCiphertexts)
        ciphertext = ciphertext->Clone();
    bootstrapKeys.automorphismKeys =
        std::make_shared<std::map<uint32_t, EvalKey<DCRTPoly>>>(*bootstrapKeys.automorphismKeys);
    m_bootstrapKeys = std::move(bootstrapKeys);
}

bool PaCoCKKSRNS::IsSetup() const noexcept {
    return !m_bootstrapKeys.keyTag.empty() && m_bootstrapKeys.automorphismKeys &&
           !m_bootstrapKeys.automorphismIndices.empty() && m_bootstrapKeys.multiplicationKey != nullptr &&
           std::all_of(m_bootstrapKeys.selectorCiphertexts.begin(), m_bootstrapKeys.selectorCiphertexts.end(),
                       [](const auto& ciphertext) { return ciphertext != nullptr; });
}

const PaCoParameters& PaCoCKKSRNS::GetParameters() const noexcept {
    return m_parameters;
}

PaCoBootstrapKeys PaCoCKKSRNS::GetBootstrapKeys() const {
    RequireSetup();
    PaCoBootstrapKeys copy = m_bootstrapKeys;
    for (auto& ciphertext : copy.selectorCiphertexts)
        ciphertext = ciphertext->Clone();
    copy.automorphismKeys = std::make_shared<std::map<uint32_t, EvalKey<DCRTPoly>>>(*m_bootstrapKeys.automorphismKeys);
    return copy;
}

void PaCoCKKSRNS::RequireSetup() const {
    if (!IsSetup())
        OPENFHE_THROW("PaCo bootstrap keys have not been generated");
}

std::vector<int32_t> PaCoCKKSRNS::RequiredRotationIndices() const {
    std::set<int32_t> rotations;
    auto addTraceRotations = [&](uint32_t from, uint32_t to) {
        for (uint32_t current = from; current > to; current /= 2)
            rotations.insert(static_cast<int32_t>(current / 2));
    };
    auto addMatrixRotations = [&](const std::vector<paco::detail::SparseDiagonalMatrix>& matrices) {
        for (const auto& matrix : matrices) {
            for (const auto& entry : matrix.diagonals) {
                const int32_t index = SymmetricDiagonal(entry.first, matrix.dimension);
                if (index != 0)
                    rotations.insert(index);
            }
        }
    };
    addTraceRotations(m_slots, m_n);
    addMatrixRotations(m_partialInverseStages);
    addTraceRotations(m_n, 2 * m_parameters.C);
    addTraceRotations(2 * m_parameters.C, m_parameters.C);
    addTraceRotations(m_parameters.C, m_parameters.C / 2);
    addMatrixRotations(m_slotToCoefficientStages);
    return {rotations.begin(), rotations.end()};
}

std::vector<uint32_t> PaCoCKKSRNS::RequiredAutomorphismIndices(const std::vector<int32_t>& rotations) const {
    const uint32_t M = 2 * m_ringDimension;
    std::set<uint32_t> automorphisms;
    for (const int32_t rotation : rotations)
        automorphisms.insert(FindAutomorphismIndex2nComplex(rotation, M));
    const uint32_t conjugation = M - 1;
    automorphisms.insert(conjugation);
    const uint32_t rotationC = FindAutomorphismIndex2nComplex(static_cast<int32_t>(m_parameters.C), M);
    automorphisms.insert(static_cast<uint32_t>((static_cast<uint64_t>(conjugation) * rotationC) % M));
    return {automorphisms.begin(), automorphisms.end()};
}

void PaCoCKKSRNS::ValidateInput(ConstCiphertext<DCRTPoly> ciphertext) const {
    RequireSetup();
    if (!ciphertext)
        OPENFHE_THROW("PaCo input ciphertext is null");
    if (ciphertext->GetCryptoContext() != m_context)
        OPENFHE_THROW("PaCo input belongs to a different CryptoContext");
    if (ciphertext->GetKeyTag() != m_bootstrapKeys.keyTag)
        OPENFHE_THROW("PaCo input key tag does not match the bootstrap keys");
    if (ciphertext->GetElements().size() != 2)
        OPENFHE_THROW("PaCo input must be a relinearized two-component ciphertext");
    if (ciphertext->GetEncodingType() != CKKS_PACKED_ENCODING || ciphertext->GetSlots() != m_slots)
        OPENFHE_THROW("PaCo input must use full-width periodic COMPLEX CKKS packing");
    if (ciphertext->GetLevel() != m_totalTowers - 1)
        OPENFHE_THROW("PaCo input metadata is not at the bottom CKKS level");
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(m_context->GetCryptoParameters());
    const double inputScale = ciphertext->GetScalingFactor();
    bool configuredScale    = false;
    for (uint32_t level = 0; level < m_totalTowers; ++level) {
        const double expected = cryptoParams->GetScalingFactorReal(level);
        const double tolerance =
            64.0 * std::numeric_limits<double>::epsilon() * std::max({1.0, std::abs(inputScale), std::abs(expected)});
        configuredScale |=
            std::isfinite(inputScale) && inputScale > 0.0 && std::abs(inputScale - expected) <= tolerance;
    }
    if (!configuredScale || ciphertext->GetScalingFactorInt() != NativeInteger(1) ||
        ciphertext->GetNoiseScaleDeg() != 1)
        OPENFHE_THROW("PaCo input must use a configured CKKS scale and noise-scale degree one");
    const auto expectedBottom = cryptoParams->GetElementParams()->GetParams().front();
    for (const auto& element : ciphertext->GetElements()) {
        if (element.GetFormat() != Format::EVALUATION || element.GetNumOfElements() != 1 ||
            element.GetRingDimension() != m_ringDimension || element.GetCyclotomicOrder() != 2 * m_ringDimension ||
            !element.GetParams())
            OPENFHE_THROW("PaCo input component metadata is not the configured bottom Q basis");
        const auto& tower = element.GetElementAtIndex(0);
        if (tower.GetFormat() != Format::EVALUATION || tower.GetRingDimension() != expectedBottom->GetRingDimension() ||
            tower.GetCyclotomicOrder() != expectedBottom->GetCyclotomicOrder() ||
            tower.GetModulus() != expectedBottom->GetModulus() ||
            tower.GetRootOfUnity() != expectedBottom->GetRootOfUnity() || !tower.GetParams() ||
            *tower.GetParams() != *expectedBottom)
            OPENFHE_THROW("PaCo Algorithm 3 requires input at exactly the configured bottom q tower");
    }
}

std::vector<Plaintext> PaCoCKKSRNS::GetCoefficientEncodings(ConstCiphertext<DCRTPoly> ciphertext) const {
    ValidateInput(ciphertext);
    DCRTPoly c0 = ciphertext->GetElements()[0];
    DCRTPoly c1 = ciphertext->GetElements()[1];
    c0.SetFormat(Format::COEFFICIENT);
    c1.SetFormat(Format::COEFFICIENT);
    const auto c0Tower = c0.GetElementAtIndex(0);
    const auto c1Tower = c1.GetElementAtIndex(0);
    const uint64_t q   = c0Tower.GetModulus().ConvertToInt();

    std::vector<std::vector<std::complex<double>>> phasePolynomials(
        static_cast<size_t>(4 * m_parameters.h * m_k),
        std::vector<std::complex<double>>(2 * m_parameters.C, {0.0, 0.0}));
    auto phaseAt = [&](uint32_t v, uint32_t r) -> std::vector<std::complex<double>>& {
        return phasePolynomials[(static_cast<size_t>(v) * m_k) + r];
    };

    for (uint32_t v = 0; v < 4 * m_parameters.h; ++v) {
        for (uint32_t r = 0; r < m_k; ++r) {
            auto& phase = phaseAt(v, r);
            for (uint32_t i = 0; i < m_parameters.C; ++i) {
                const uint32_t baseIndex = 4 * m_parameters.h * (i * m_k + r);
                uint64_t residue         = 0;
                if (v == 0) {
                    residue = AddModulo(c0Tower[baseIndex].ConvertToInt(), c1Tower[baseIndex].ConvertToInt(), q);
                }
                else if (i == 0 && r == 0) {
                    residue = NegateModulo(c1Tower[m_ringDimension - v].ConvertToInt(), q);
                }
                else {
                    residue = c1Tower[baseIndex - v].ConvertToInt();
                }
                phase[i] = CirclePhase(residue, q);
            }
        }
    }

    std::vector<Plaintext> encodings;
    encodings.reserve(4);
    for (uint32_t t = 0; t < 4; ++t) {
        std::vector<std::complex<double>> beta(m_slots, {0.0, 0.0});
        for (uint32_t r = 0; r < m_k; ++r) {
            std::vector<std::complex<double>> block(m_n, {0.0, 0.0});
            for (uint32_t v = 0; v < m_parameters.h; ++v) {
                const auto& phase = phaseAt(t * m_parameters.h + v, r);
                std::copy(phase.begin(), phase.end(), block.begin() + static_cast<size_t>(v) * 2 * m_parameters.C);
            }
            block = ApplyForwardDStages(std::move(block), m_parameters.C);
            std::copy(block.begin(), block.end(), beta.begin() + static_cast<size_t>(r) * m_n);
        }
        beta = paco::detail::ExtendedBitReverseVector(beta, m_parameters.C / 2);
        encodings.emplace_back(m_context->MakeCKKSPackedPlaintext(beta, 1, 0, nullptr, m_slots));
    }
    return encodings;
}

Ciphertext<DCRTPoly> PaCoCKKSRNS::Rotate(ConstCiphertext<DCRTPoly> ciphertext, int32_t index) const {
    if (index == 0)
        return ciphertext->Clone();
    const uint32_t automorphism = FindAutomorphismIndex2nComplex(index, 2 * m_ringDimension);
    return m_context->EvalAutomorphism(ciphertext, automorphism, *m_bootstrapKeys.automorphismKeys);
}

Ciphertext<DCRTPoly> PaCoCKKSRNS::Conjugate(ConstCiphertext<DCRTPoly> ciphertext) const {
    return m_context->EvalAutomorphism(ciphertext, 2 * m_ringDimension - 1, *m_bootstrapKeys.automorphismKeys);
}

Ciphertext<DCRTPoly> PaCoCKKSRNS::ConjugateRotate(ConstCiphertext<DCRTPoly> ciphertext, int32_t index) const {
    const uint32_t M        = 2 * m_ringDimension;
    const uint32_t rotation = FindAutomorphismIndex2nComplex(index, M);
    const uint32_t combined = static_cast<uint32_t>((static_cast<uint64_t>(M - 1) * rotation) % M);
    return m_context->EvalAutomorphism(ciphertext, combined, *m_bootstrapKeys.automorphismKeys);
}

Ciphertext<DCRTPoly> PaCoCKKSRNS::Trace(Ciphertext<DCRTPoly> ciphertext, uint32_t from, uint32_t to) const {
    if (!IsPowerOfTwo(from) || !IsPowerOfTwo(to) || from < to || from % to != 0)
        OPENFHE_THROW("PaCo trace dimensions are invalid");
    for (uint32_t current = from; current > to; current /= 2) {
        auto rotated = Rotate(ciphertext, static_cast<int32_t>(current / 2));
        ciphertext   = m_context->EvalAdd(ciphertext, rotated);
    }
    return ciphertext;
}

Ciphertext<DCRTPoly> PaCoCKKSRNS::Product(Ciphertext<DCRTPoly> ciphertext, uint32_t from, uint32_t to) const {
    if (!IsPowerOfTwo(from) || !IsPowerOfTwo(to) || from < to || from % to != 0)
        OPENFHE_THROW("PaCo product dimensions are invalid");
    for (uint32_t current = from; current > to; current /= 2) {
        auto rotated = Rotate(ciphertext, static_cast<int32_t>(current / 2));
        ciphertext   = m_context->GetScheme()->EvalMult(ciphertext, rotated, m_bootstrapKeys.multiplicationKey);
        RescaleOneLevel(ciphertext, "product");
    }
    return ciphertext;
}

Ciphertext<DCRTPoly> PaCoCKKSRNS::ApplyMatrix(Ciphertext<DCRTPoly> ciphertext,
                                              const paco::detail::SparseDiagonalMatrix& matrix) const {
    if (matrix.dimension == 0 || matrix.diagonals.empty())
        OPENFHE_THROW("PaCo cannot apply an empty matrix");
    Ciphertext<DCRTPoly> result;
    for (const auto& [canonical, diagonal] : matrix.diagonals) {
        const int32_t index = SymmetricDiagonal(canonical, matrix.dimension);
        auto rotated        = index == 0 ? ciphertext->Clone() : Rotate(ciphertext, index);
        auto expanded       = PeriodicExpand(diagonal, m_slots);
        auto plaintext      = m_context->MakeCKKSPackedPlaintext(expanded, 1, ciphertext->GetLevel(), nullptr, m_slots);
        auto term           = m_context->EvalMult(rotated, plaintext);
        result              = result ? m_context->EvalAdd(result, term) : term;
    }
    RescaleOneLevel(result, "sparse diagonal transform");
    return result;
}

Ciphertext<DCRTPoly> PaCoCKKSRNS::MultiplyPlain(Ciphertext<DCRTPoly> ciphertext,
                                                const std::vector<std::complex<double>>& values,
                                                uint32_t activeSlots) const {
    if (values.size() != activeSlots)
        OPENFHE_THROW("PaCo plaintext mask has the wrong slot count");
    auto expanded  = PeriodicExpand(values, m_slots);
    auto plaintext = m_context->MakeCKKSPackedPlaintext(expanded, 1, ciphertext->GetLevel(), nullptr, m_slots);
    auto result    = m_context->EvalMult(ciphertext, plaintext);
    RescaleOneLevel(result, "plaintext multiplication");
    return result;
}

void PaCoCKKSRNS::RescaleOneLevel(Ciphertext<DCRTPoly>& ciphertext, const char* stage) const {
    if (!ciphertext || ciphertext->GetElements().empty())
        OPENFHE_THROW("PaCo attempted to rescale an empty ciphertext");
    const uint32_t towersBefore     = ciphertext->GetElements()[0].GetNumOfElements();
    const uint32_t levelBefore      = ciphertext->GetLevel();
    const uint32_t noiseScaleBefore = ciphertext->GetNoiseScaleDeg();
    const double scaleBefore        = ciphertext->GetScalingFactor();
    if (towersBefore <= 1) {
        std::ostringstream message;
        message << "PaCo exhausted its modulus budget at " << stage;
        OPENFHE_THROW(message.str());
    }
    // The public RescaleInPlace API is intentionally a no-op for automatic
    // scaling techniques.  PaCo has an explicit, paper-defined depth schedule,
    // so consume exactly one RNS tower through the scheme's internal CKKS
    // modulus-reduction primitive (the constructor rejects composite degree > 1).
    m_context->GetScheme()->ModReduceInternalInPlace(ciphertext, 1);
    const auto cryptoParams     = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(m_context->GetCryptoParameters());
    const double expectedScale  = scaleBefore / cryptoParams->GetModReduceFactor(towersBefore - 1);
    const double scaleTolerance = 16.0 * std::numeric_limits<double>::epsilon() *
                                  std::max({1.0, std::abs(expectedScale), std::abs(ciphertext->GetScalingFactor())});
    if (ciphertext->GetElements()[0].GetNumOfElements() + 1 != towersBefore ||
        ciphertext->GetLevel() != levelBefore + 1 || noiseScaleBefore != 2 || ciphertext->GetNoiseScaleDeg() != 1 ||
        !std::isfinite(ciphertext->GetScalingFactor()) || ciphertext->GetScalingFactor() <= 0.0 ||
        ciphertext->GetScalingFactor() >= scaleBefore ||
        std::abs(ciphertext->GetScalingFactor() - expectedScale) > scaleTolerance ||
        std::any_of(ciphertext->GetElements().begin(), ciphertext->GetElements().end(),
                    [towersBefore](const auto& element) { return element.GetNumOfElements() + 1 != towersBefore; })) {
        std::ostringstream message;
        message << "PaCo did not consume exactly one level at " << stage << " (towers " << towersBefore << " -> "
                << ciphertext->GetElements()[0].GetNumOfElements() << ", level " << levelBefore << " -> "
                << ciphertext->GetLevel() << ')';
        OPENFHE_THROW(message.str());
    }
}

Ciphertext<DCRTPoly> PaCoCKKSRNS::EvalSequential(ConstCiphertext<DCRTPoly> ciphertext) const {
    ValidateInput(ciphertext);
    const double inputScale           = ciphertext->GetScalingFactor();
    const NativeInteger inputScaleInt = ciphertext->GetScalingFactorInt();
    const uint32_t inputSlots         = ciphertext->GetSlots();
    const uint64_t q                  = BottomModulus(ciphertext);

    const auto coefficientEncodings = GetCoefficientEncodings(ciphertext);
    Ciphertext<DCRTPoly> refreshed;
    for (uint32_t t = 0; t < 4; ++t) {
        auto term = m_context->EvalMult(m_bootstrapKeys.selectorCiphertexts[t], coefficientEncodings[t]);
        // Algorithm 4 applies the CKKS product operation independently to
        // every cEcd_t * bsk_t pair before summing the four results.  A single
        // lazy rescale after the addition has the same depth but different RNS
        // rounding, so keep the paper/reference operation boundary explicit.
        RescaleOneLevel(term, "coefficient-encoding/bootstrap-key product");
        refreshed = refreshed ? m_context->EvalAdd(refreshed, term) : term;
    }

    refreshed = Trace(std::move(refreshed), m_slots, m_n);
    for (const auto& matrix : m_partialInverseStages)
        refreshed = ApplyMatrix(std::move(refreshed), matrix);

    auto conjugateRotation = ConjugateRotate(refreshed, static_cast<int32_t>(m_parameters.C));
    refreshed              = m_context->EvalAdd(refreshed, conjugateRotation);

    std::vector<std::complex<double>> mu(m_n, {0.0, 0.0});
    for (uint32_t i = 0; i < m_n; ++i) {
        if (i % (2 * m_parameters.C) < m_parameters.C)
            mu[i] = {1.0, 0.0};
    }
    refreshed = MultiplyPlain(std::move(refreshed), mu, m_n);
    refreshed = Product(std::move(refreshed), m_n, 2 * m_parameters.C);
    refreshed = Trace(std::move(refreshed), 2 * m_parameters.C, m_parameters.C);

    auto conjugated = Conjugate(refreshed);
    refreshed       = m_context->EvalSub(refreshed, conjugated);

    const long double etaMagnitude =
        static_cast<long double>(q) / (4.0L * static_cast<long double>(m_outputBootstrapScale) * kPi);
    std::vector<std::complex<double>> eta(m_parameters.C);
    for (uint32_t i = 0; i < m_parameters.C; ++i) {
        eta[i] = i < m_parameters.C / 2 ? std::complex<double>(0.0, -static_cast<double>(etaMagnitude)) :
                                          std::complex<double>(static_cast<double>(etaMagnitude), 0.0);
    }
    refreshed = MultiplyPlain(std::move(refreshed), eta, m_parameters.C);
    refreshed = Trace(std::move(refreshed), m_parameters.C, m_parameters.C / 2);
    for (const auto& matrix : m_slotToCoefficientStages)
        refreshed = ApplyMatrix(std::move(refreshed), matrix);

    const uint32_t expectedLevel      = m_parameters.MultiplicativeDepth();
    const double actualOutputScale    = refreshed->GetScalingFactor();
    const double outputScaleTolerance = 64.0 * std::numeric_limits<double>::epsilon() *
                                        std::max({1.0, std::abs(actualOutputScale), std::abs(m_outputBootstrapScale)});
    if (refreshed->GetLevel() != expectedLevel ||
        refreshed->GetElements()[0].GetNumOfElements() != m_totalTowers - expectedLevel ||
        refreshed->GetNoiseScaleDeg() != 1 || !std::isfinite(actualOutputScale) ||
        std::abs(actualOutputScale - m_outputBootstrapScale) > outputScaleTolerance ||
        std::any_of(refreshed->GetElements().begin(), refreshed->GetElements().end(),
                    [this, expectedLevel](const auto& element) {
                        return element.GetNumOfElements() != m_totalTowers - expectedLevel;
                    }))
        OPENFHE_THROW("PaCo output does not match the configured level ledger");
    // The phase argument contains coefficients scaled by inputScale.  Eta
    // cancels the bootstrap scale, leaving raw coefficients at inputScale;
    // this metadata transition is the native equivalent of boot_to_nonboot.
    refreshed->SetScalingFactor(inputScale);
    refreshed->SetScalingFactorInt(inputScaleInt);
    refreshed->SetSlots(inputSlots);
    return refreshed;
}

Ciphertext<DCRTPoly> PaCoCKKSRNS::EvalParallel(ConstCiphertext<DCRTPoly> ciphertext, uint32_t D, uint32_t kappa,
                                               bool runConcurrently, uint32_t maxConcurrency) const {
    ValidateInput(ciphertext);
    if (!IsPowerOfTwo(D) || D < 2 || D > m_ringDimension)
        OPENFHE_THROW("PaCo parallel coefficient count D must be a power of two in [2,N]");
    if (!IsPowerOfTwo(kappa) || kappa == 0 || kappa > D / 2)
        OPENFHE_THROW("PaCo parallel worker count kappa must be a power of two at most D/2");
    if (D / kappa != m_parameters.C)
        OPENFHE_THROW("PaCo parallel invocation requires D/kappa to equal configured C");
    const uint32_t minimumWorkers = CeilDiv(D, m_parameters.CoefficientBudget(m_ringDimension));
    if (kappa < minimumWorkers)
        OPENFHE_THROW("PaCo parallel worker count is below ceil(D/B)");

    const uint32_t monomialStep  = m_ringDimension / D;
    const uint32_t monomialOrder = 2 * m_ringDimension;
    auto evaluateBranch          = [this, ciphertext, monomialStep, monomialOrder](uint32_t r) {
        const uint32_t positivePower = static_cast<uint32_t>((static_cast<uint64_t>(r) * monomialStep) % monomialOrder);
        const uint32_t negativePower = positivePower == 0 ? 0 : monomialOrder - positivePower;
        auto shifted                 = m_context->GetScheme()->MultByMonomial(ciphertext, negativePower);
        auto result                  = EvalSequential(shifted);
        return m_context->GetScheme()->MultByMonomial(result, positivePower);
    };

    std::vector<Ciphertext<DCRTPoly>> branches(kappa);
    if (runConcurrently && kappa > 1) {
        const uint32_t detected    = std::max<uint32_t>(1, std::thread::hardware_concurrency());
        const uint32_t workerLimit = std::min(kappa, maxConcurrency == 0 ? detected : maxConcurrency);
        if (workerLimit == 0)
            OPENFHE_THROW("PaCo maximum concurrency must be positive when specified");
        for (uint32_t begin = 0; begin < kappa; begin += workerLimit) {
            const uint32_t count = std::min(workerLimit, kappa - begin);
            std::vector<std::future<Ciphertext<DCRTPoly>>> futures;
            futures.reserve(count);
            for (uint32_t offset = 0; offset < count; ++offset)
                futures.emplace_back(std::async(std::launch::async, evaluateBranch, begin + offset));
            for (uint32_t offset = 0; offset < count; ++offset)
                branches[begin + offset] = futures[offset].get();
        }
    }
    else {
        for (uint32_t r = 0; r < kappa; ++r)
            branches[r] = evaluateBranch(r);
    }

    auto result = branches[0];
    for (uint32_t r = 1; r < kappa; ++r)
        result = m_context->EvalAdd(result, branches[r]);
    return result;
}

}  // namespace lbcrypto
