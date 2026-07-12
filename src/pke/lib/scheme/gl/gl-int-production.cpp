//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "scheme/gl/gl-int-production.h"

#include <algorithm>
#include <map>
#include <string>
#include <tuple>
#include <utility>

namespace lbcrypto {
namespace {

using SlotKey = std::tuple<uint8_t, uint32_t, uint32_t, uint32_t>;

uint64_t AddMod(uint64_t lhs, uint64_t rhs, uint64_t modulus) {
    return static_cast<uint64_t>((static_cast<unsigned __int128>(lhs) + rhs) % modulus);
}

uint64_t SubMod(uint64_t lhs, uint64_t rhs, uint64_t modulus) {
    return lhs >= rhs ? lhs - rhs : modulus - (rhs - lhs);
}

uint64_t MulMod(uint64_t lhs, uint64_t rhs, uint64_t modulus) {
    return static_cast<uint64_t>((static_cast<unsigned __int128>(lhs) * rhs) % modulus);
}

uint64_t PowMod(uint64_t base, uint64_t exponent, uint64_t modulus) {
    uint64_t result = 1;
    while (exponent != 0) {
        if ((exponent & 1) != 0) {
            result = MulMod(result, base, modulus);
        }
        base = MulMod(base, base, modulus);
        exponent >>= 1;
    }
    return result;
}

uint64_t Canonical(int64_t value, uint64_t modulus) {
    const auto signedModulus = static_cast<int64_t>(modulus);
    const auto remainder     = value % signedModulus;
    return static_cast<uint64_t>(remainder < 0 ? remainder + signedModulus : remainder);
}

bool SameParameters(const GLIntWBatchedParameters& lhs,
                    const GLIntWBatchedParameters& rhs) noexcept {
    return lhs.dimension == rhs.dimension &&
           lhs.cyclotomicPrime == rhs.cyclotomicPrime &&
           lhs.wGenerator == rhs.wGenerator &&
           lhs.plaintextModulus == rhs.plaintextModulus &&
           lhs.multiplicativeDepth == rhs.multiplicativeDepth &&
           lhs.nativeRnsWordBits == rhs.nativeRnsWordBits;
}

void RequireProductionParameters(const GLIntWBatchedParameters& parameters) {
    parameters.Validate();
    if (!parameters.IsGL128257N32Geometry() ||
        parameters.plaintextModulus != 1579009) {
        throw GLIntParameterError(
            "the production integer value core requires canonical "
            "GL-128-257-N32 with t=1579009");
    }
}

bool HasExactOrder(uint64_t value, uint64_t order, uint64_t modulus) {
    if (value < 2 || value >= modulus || PowMod(value, order, modulus) != 1) {
        return false;
    }
    auto remaining = order;
    for (uint64_t factor = 2; factor * factor <= remaining; ++factor) {
        if (remaining % factor != 0) {
            continue;
        }
        if (PowMod(value, order / factor, modulus) == 1) {
            return false;
        }
        do {
            remaining /= factor;
        } while (remaining % factor == 0);
    }
    return remaining == 1 || PowMod(value, order / remaining, modulus) != 1;
}

uint64_t MinimumElementOfOrder(uint64_t order, uint64_t modulus) {
    for (uint64_t candidate = 2; candidate < modulus; ++candidate) {
        if (HasExactOrder(candidate, order, modulus)) {
            return candidate;
        }
    }
    throw GLIntParameterError(
        "production integer codec could not find its finite-field root");
}

SlotKey KeyOf(const GLIntProductionSlotValue& value) {
    return {static_cast<uint8_t>(value.branch), value.matrix, value.row,
            value.column};
}

bool IsValidBranch(GLIntBranch branch) noexcept {
    return branch == GLIntBranch::Plus || branch == GLIntBranch::Minus;
}

std::size_t CoefficientIndex(std::size_t n, std::size_t phi, std::size_t x,
                             std::size_t y, std::size_t w) {
    return (x * n + y) * phi + w;
}

std::vector<GLIntProductionSlotValue> ValuesFromMap(
    const std::map<SlotKey, uint64_t>& values) {
    if (values.size() > kGLIntProductionMaxLogicalValues) {
        throw GLDimensionError(
            "production integer sparse operation exceeds its live-slot bound");
    }
    std::vector<GLIntProductionSlotValue> output;
    output.reserve(values.size());
    for (const auto& [key, value] : values) {
        if (value == 0) {
            continue;
        }
        output.push_back(GLIntProductionSlotValue{
            static_cast<GLIntBranch>(std::get<0>(key)), std::get<1>(key),
            std::get<2>(key), std::get<3>(key), static_cast<int64_t>(value)});
    }
    return output;
}

}  // namespace

GLIntProductionSparsePlaintext::GLIntProductionSparsePlaintext(
    GLIntWBatchedParameters parameters,
    std::vector<GLIntProductionSlotValue> values)
    : m_parameters(std::move(parameters)) {
    RequireProductionParameters(m_parameters);
    if (values.size() > kGLIntProductionMaxLogicalValues) {
        throw GLDimensionError(
            "production integer sparse plaintext exceeds its live-slot bound");
    }
    const auto n   = m_parameters.dimension;
    const auto phi = m_parameters.cyclotomicPrime - 1;
    const auto t   = m_parameters.plaintextModulus;
    std::map<SlotKey, uint64_t> combined;
    for (const auto& value : values) {
        if (!IsValidBranch(value.branch) || value.matrix >= phi ||
            value.row >= n || value.column >= n) {
            throw GLDimensionError(
                "production integer sparse plaintext slot is outside 256x128x128");
        }
        const auto canonical = Canonical(value.value, t);
        auto& destination    = combined[KeyOf(value)];
        destination          = AddMod(destination, canonical, t);
    }
    m_values = ValuesFromMap(combined);
    Validate();
}

const GLIntWBatchedParameters&
GLIntProductionSparsePlaintext::GetParameters() const noexcept {
    return m_parameters;
}

const std::vector<GLIntProductionSlotValue>&
GLIntProductionSparsePlaintext::GetValues() const noexcept {
    return m_values;
}

int64_t GLIntProductionSparsePlaintext::At(GLIntBranch branch,
                                            std::size_t matrix,
                                            std::size_t row,
                                            std::size_t column) const {
    const auto phi = static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    const auto n   = static_cast<std::size_t>(m_parameters.dimension);
    if (!IsValidBranch(branch) || matrix >= phi || row >= n || column >= n) {
        throw GLDimensionError(
            "production integer sparse plaintext lookup is outside 256x128x128");
    }
    const SlotKey key{static_cast<uint8_t>(branch), static_cast<uint32_t>(matrix),
                      static_cast<uint32_t>(row), static_cast<uint32_t>(column)};
    const auto it = std::lower_bound(
        m_values.begin(), m_values.end(), key,
        [](const GLIntProductionSlotValue& lhs, const SlotKey& rhs) {
            return KeyOf(lhs) < rhs;
        });
    return it != m_values.end() && KeyOf(*it) == key ? it->value : 0;
}

void GLIntProductionSparsePlaintext::Validate() const {
    RequireProductionParameters(m_parameters);
    if (m_values.size() > kGLIntProductionMaxLogicalValues) {
        throw GLDimensionError(
            "production integer sparse plaintext exceeds its live-slot bound");
    }
    SlotKey previous{};
    bool havePrevious = false;
    for (const auto& value : m_values) {
        if (!IsValidBranch(value.branch) ||
            value.matrix >= m_parameters.cyclotomicPrime - 1 ||
            value.row >= m_parameters.dimension ||
            value.column >= m_parameters.dimension || value.value <= 0 ||
            static_cast<uint64_t>(value.value) >= m_parameters.plaintextModulus) {
            throw GLIntParameterError(
                "production integer sparse plaintext is not canonical");
        }
        const auto key = KeyOf(value);
        if (havePrevious && !(previous < key)) {
            throw GLIntParameterError(
                "production integer sparse plaintext keys are not strictly ordered");
        }
        previous     = key;
        havePrevious = true;
    }
}

GLIntProductionEncodedPlaintext::GLIntProductionEncodedPlaintext(
    GLIntWBatchedParameters parameters, GLIntWBatchedCodecRoots roots,
    std::vector<GLIntGaussianResidue> coefficients)
    : m_parameters(std::move(parameters)),
      m_roots(std::move(roots)),
      m_coefficients(std::move(coefficients)) {
    Validate();
}

const GLIntWBatchedParameters&
GLIntProductionEncodedPlaintext::GetParameters() const noexcept {
    return m_parameters;
}

const GLIntWBatchedCodecRoots&
GLIntProductionEncodedPlaintext::GetRoots() const noexcept {
    return m_roots;
}

const std::vector<GLIntGaussianResidue>&
GLIntProductionEncodedPlaintext::GetCoefficients() const noexcept {
    return m_coefficients;
}

const GLIntGaussianResidue& GLIntProductionEncodedPlaintext::At(
    std::size_t x, std::size_t y, std::size_t w) const {
    const auto n   = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi = static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    if (x >= n || y >= n || w >= phi) {
        throw GLDimensionError(
            "production integer encoded coefficient is outside R'_t");
    }
    return m_coefficients[CoefficientIndex(n, phi, x, y, w)];
}

void GLIntProductionEncodedPlaintext::Validate() const {
    RequireProductionParameters(m_parameters);
    m_roots.Validate(m_parameters);
    const auto expected = static_cast<std::size_t>(m_parameters.dimension) *
                          m_parameters.dimension *
                          (m_parameters.cyclotomicPrime - 1);
    if (m_coefficients.size() != expected) {
        throw GLDimensionError(
            "production integer encoded plaintext has the wrong R'_t shape");
    }
    for (const auto& coefficient : m_coefficients) {
        if (coefficient.real < 0 || coefficient.imaginary < 0 ||
            static_cast<uint64_t>(coefficient.real) >=
                m_parameters.plaintextModulus ||
            static_cast<uint64_t>(coefficient.imaginary) >=
                m_parameters.plaintextModulus) {
            throw GLIntParameterError(
                "production integer encoded plaintext has a noncanonical residue");
        }
    }
}

GLIntProductionCore::GLIntProductionCore(GLIntWBatchedParameters parameters)
    : m_parameters(std::move(parameters)) {
    RequireProductionParameters(m_parameters);
    const auto n     = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi   = static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    const auto t     = m_parameters.plaintextModulus;
    const auto order = 4 * n;
    m_roots.zeta     = MinimumElementOfOrder(order, t);
    m_roots.eta      = MinimumElementOfOrder(m_parameters.cyclotomicPrime, t);
    m_roots.Validate(m_parameters);

    m_gaussianUnit        = PowMod(m_roots.zeta, n, t);
    m_inverseGaussianUnit = PowMod(m_gaussianUnit, t - 2, t);
    m_inverseTwo          = PowMod(2, t - 2, t);
    m_inverseDimension    = PowMod(n, t - 2, t);
    const auto inverseP   = PowMod(m_parameters.cyclotomicPrime, t - 2, t);

    m_xPlusInverse.resize(n * n);
    m_xMinusInverse.resize(n * n);
    uint64_t exponent = 1;
    for (std::size_t slot = 0; slot < n; ++slot) {
        const auto point        = PowMod(m_roots.zeta, exponent, t);
        const auto inversePoint = PowMod(point, t - 2, t);
        uint64_t plusPower      = 1;
        uint64_t minusPower     = 1;
        for (std::size_t coefficient = 0; coefficient < n; ++coefficient) {
            m_xPlusInverse[coefficient * n + slot] =
                MulMod(m_inverseDimension, minusPower, t);
            m_xMinusInverse[coefficient * n + slot] =
                MulMod(m_inverseDimension, plusPower, t);
            plusPower  = MulMod(plusPower, point, t);
            minusPower = MulMod(minusPower, inversePoint, t);
        }
        exponent = (exponent * 5) % order;
    }

    m_wPlusInverse.resize(phi * phi);
    m_wMinusInverse.resize(phi * phi);
    exponent = 1;
    for (std::size_t matrix = 0; matrix < phi; ++matrix) {
        const auto plusBase  = PowMod(m_roots.eta, exponent, t);
        const auto minusBase = PowMod(plusBase, t - 2, t);
        auto plusInversePower  = uint64_t{1};
        auto minusInversePower = uint64_t{1};
        const auto plusInverse  = PowMod(plusBase, t - 2, t);
        const auto minusInverse = PowMod(minusBase, t - 2, t);
        for (std::size_t w = 0; w < phi; ++w) {
            m_wPlusInverse[w * phi + matrix] = MulMod(
                inverseP, SubMod(plusInversePower, plusBase, t), t);
            m_wMinusInverse[w * phi + matrix] = MulMod(
                inverseP, SubMod(minusInversePower, minusBase, t), t);
            plusInversePower = MulMod(plusInversePower, plusInverse, t);
            minusInversePower = MulMod(minusInversePower, minusInverse, t);
        }
        exponent =
            (exponent * m_parameters.wGenerator) % m_parameters.cyclotomicPrime;
    }
}

const GLIntWBatchedParameters& GLIntProductionCore::GetParameters() const noexcept {
    return m_parameters;
}

const GLIntWBatchedCodecRoots& GLIntProductionCore::GetRoots() const noexcept {
    return m_roots;
}

GLIntProductionCapabilities GLIntProductionCore::GetCapabilities() const noexcept {
    return {};
}

void GLIntProductionCore::ValidateSparse(
    const GLIntProductionSparsePlaintext& plaintext,
    const char* objectName) const {
    plaintext.Validate();
    if (!SameParameters(m_parameters, plaintext.GetParameters())) {
        throw GLContextMismatchError(std::string(objectName) +
                                     " parameters do not match the core");
    }
}

void GLIntProductionCore::ValidateEncoded(
    const GLIntProductionEncodedPlaintext& plaintext,
    const char* objectName) const {
    plaintext.Validate();
    if (!SameParameters(m_parameters, plaintext.GetParameters()) ||
        plaintext.GetRoots() != m_roots) {
        throw GLContextMismatchError(std::string(objectName) +
                                     " codec binding does not match the core");
    }
}

GLIntProductionEncodedPlaintext GLIntProductionCore::EncodeSparse(
    const GLIntProductionSparsePlaintext& plaintext) const {
    ValidateSparse(plaintext, "production integer sparse plaintext");
    if (plaintext.GetValues().size() >
        kGLIntProductionMaxEncodedLogicalValues) {
        throw GLDimensionError(
            "production integer dense encoding exceeds its sparse work bound");
    }
    const auto n   = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi = static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    const auto t   = m_parameters.plaintextModulus;
    std::vector<GLIntGaussianResidue> coefficients(n * n * phi);

    for (const auto& slot : plaintext.GetValues()) {
        const auto& xInverse = slot.branch == GLIntBranch::Plus
                                   ? m_xPlusInverse
                                   : m_xMinusInverse;
        const auto& wInverse = slot.branch == GLIntBranch::Plus
                                   ? m_wPlusInverse
                                   : m_wMinusInverse;
        const auto value = static_cast<uint64_t>(slot.value);
        for (std::size_t x = 0; x < n; ++x) {
            const auto xFactor = xInverse[x * n + slot.row];
            for (std::size_t y = 0; y < n; ++y) {
                const auto xyFactor =
                    MulMod(xFactor, xInverse[y * n + slot.column], t);
                const auto base = CoefficientIndex(n, phi, x, y, 0);
                for (std::size_t w = 0; w < phi; ++w) {
                    const auto contribution = MulMod(
                        value,
                        MulMod(xyFactor, wInverse[w * phi + slot.matrix], t),
                        t);
                    const auto realContribution =
                        MulMod(contribution, m_inverseTwo, t);
                    const auto imaginaryContribution = MulMod(
                        realContribution, m_inverseGaussianUnit, t);
                    auto& coefficient = coefficients[base + w];
                    coefficient.real = static_cast<int64_t>(AddMod(
                        static_cast<uint64_t>(coefficient.real),
                        realContribution, t));
                    const auto oldImaginary =
                        static_cast<uint64_t>(coefficient.imaginary);
                    coefficient.imaginary = static_cast<int64_t>(
                        slot.branch == GLIntBranch::Plus
                            ? AddMod(oldImaginary, imaginaryContribution, t)
                            : SubMod(oldImaginary, imaginaryContribution, t));
                }
            }
        }
    }
    return GLIntProductionEncodedPlaintext(m_parameters, m_roots,
                                            std::move(coefficients));
}

int64_t GLIntProductionCore::DecodeAt(
    const GLIntProductionEncodedPlaintext& plaintext, GLIntBranch branch,
    std::size_t matrix, std::size_t row, std::size_t column) const {
    ValidateEncoded(plaintext, "production integer encoded plaintext");
    const auto n   = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi = static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    const auto t   = m_parameters.plaintextModulus;
    if (!IsValidBranch(branch) || matrix >= phi || row >= n || column >= n) {
        throw GLDimensionError(
            "production integer decode slot is outside 256x128x128");
    }

    const auto pointExponent = PowMod(5, row, 4 * n);
    const auto columnExponent = PowMod(5, column, 4 * n);
    auto xPoint = PowMod(m_roots.zeta, pointExponent, t);
    auto yPoint = PowMod(m_roots.zeta, columnExponent, t);
    const auto wExponent = PowMod(m_parameters.wGenerator, matrix,
                                  m_parameters.cyclotomicPrime);
    auto wPoint = PowMod(m_roots.eta, wExponent, t);
    if (branch == GLIntBranch::Minus) {
        xPoint = PowMod(xPoint, t - 2, t);
        yPoint = PowMod(yPoint, t - 2, t);
        wPoint = PowMod(wPoint, t - 2, t);
    }
    std::vector<uint64_t> xPowers(n, 1);
    std::vector<uint64_t> yPowers(n, 1);
    std::vector<uint64_t> wPowers(phi, 1);
    for (std::size_t index = 1; index < n; ++index) {
        xPowers[index] = MulMod(xPowers[index - 1], xPoint, t);
        yPowers[index] = MulMod(yPowers[index - 1], yPoint, t);
    }
    for (std::size_t index = 1; index < phi; ++index) {
        wPowers[index] = MulMod(wPowers[index - 1], wPoint, t);
    }

    uint64_t result = 0;
    for (std::size_t x = 0; x < n; ++x) {
        for (std::size_t y = 0; y < n; ++y) {
            const auto xy = MulMod(xPowers[x], yPowers[y], t);
            const auto base = CoefficientIndex(n, phi, x, y, 0);
            for (std::size_t w = 0; w < phi; ++w) {
                const auto& coefficient = plaintext.GetCoefficients()[base + w];
                const auto iImaginary = MulMod(
                    m_gaussianUnit,
                    static_cast<uint64_t>(coefficient.imaginary), t);
                const auto lane = branch == GLIntBranch::Plus
                                      ? AddMod(static_cast<uint64_t>(coefficient.real),
                                               iImaginary, t)
                                      : SubMod(static_cast<uint64_t>(coefficient.real),
                                               iImaginary, t);
                result = AddMod(result,
                                MulMod(lane, MulMod(xy, wPowers[w], t), t), t);
            }
        }
    }
    return static_cast<int64_t>(result);
}

GLIntProductionSparsePlaintext GLIntProductionCore::Add(
    const GLIntProductionSparsePlaintext& lhs,
    const GLIntProductionSparsePlaintext& rhs) const {
    ValidateSparse(lhs, "left production integer plaintext");
    ValidateSparse(rhs, "right production integer plaintext");
    std::map<SlotKey, uint64_t> result;
    for (const auto& value : lhs.GetValues()) {
        result[KeyOf(value)] = static_cast<uint64_t>(value.value);
    }
    for (const auto& value : rhs.GetValues()) {
        auto& destination = result[KeyOf(value)];
        destination = AddMod(destination, static_cast<uint64_t>(value.value),
                             m_parameters.plaintextModulus);
    }
    return GLIntProductionSparsePlaintext(m_parameters, ValuesFromMap(result));
}

GLIntProductionSparsePlaintext GLIntProductionCore::Subtract(
    const GLIntProductionSparsePlaintext& lhs,
    const GLIntProductionSparsePlaintext& rhs) const {
    ValidateSparse(lhs, "left production integer plaintext");
    ValidateSparse(rhs, "right production integer plaintext");
    std::map<SlotKey, uint64_t> result;
    for (const auto& value : lhs.GetValues()) {
        result[KeyOf(value)] = static_cast<uint64_t>(value.value);
    }
    for (const auto& value : rhs.GetValues()) {
        auto& destination = result[KeyOf(value)];
        destination = SubMod(destination, static_cast<uint64_t>(value.value),
                             m_parameters.plaintextModulus);
    }
    return GLIntProductionSparsePlaintext(m_parameters, ValuesFromMap(result));
}

GLIntProductionSparsePlaintext GLIntProductionCore::Negate(
    const GLIntProductionSparsePlaintext& plaintext) const {
    ValidateSparse(plaintext, "production integer plaintext");
    std::vector<GLIntProductionSlotValue> result = plaintext.GetValues();
    for (auto& value : result) {
        value.value = static_cast<int64_t>(
            m_parameters.plaintextModulus - static_cast<uint64_t>(value.value));
    }
    return GLIntProductionSparsePlaintext(m_parameters, std::move(result));
}

GLIntProductionSparsePlaintext GLIntProductionCore::Hadamard(
    const GLIntProductionSparsePlaintext& lhs,
    const GLIntProductionSparsePlaintext& rhs) const {
    ValidateSparse(lhs, "left production integer plaintext");
    ValidateSparse(rhs, "right production integer plaintext");
    std::map<SlotKey, uint64_t> right;
    for (const auto& value : rhs.GetValues()) {
        right[KeyOf(value)] = static_cast<uint64_t>(value.value);
    }
    std::map<SlotKey, uint64_t> result;
    for (const auto& value : lhs.GetValues()) {
        const auto it = right.find(KeyOf(value));
        if (it != right.end()) {
            result[KeyOf(value)] = MulMod(static_cast<uint64_t>(value.value),
                                          it->second,
                                          m_parameters.plaintextModulus);
        }
    }
    return GLIntProductionSparsePlaintext(m_parameters, ValuesFromMap(result));
}

GLIntProductionSparsePlaintext GLIntProductionCore::MatrixMultiplyTrace(
    const GLIntProductionSparsePlaintext& lhs,
    const GLIntProductionSparsePlaintext& rhs) const {
    ValidateSparse(lhs, "left production integer plaintext");
    ValidateSparse(rhs, "right production integer plaintext");
    const auto t = m_parameters.plaintextModulus;
    std::map<SlotKey, uint64_t> result;
    for (const auto& left : lhs.GetValues()) {
        const auto rightBranch = left.branch == GLIntBranch::Plus
                                     ? GLIntBranch::Minus
                                     : GLIntBranch::Plus;
        for (const auto& right : rhs.GetValues()) {
            if (right.branch != rightBranch || right.matrix != left.matrix ||
                right.column != left.column) {
                continue;
            }
            GLIntProductionSlotValue output;
            output.branch = left.branch;
            output.matrix = left.matrix;
            output.row = left.row;
            output.column = right.row;
            auto& destination = result[KeyOf(output)];
            const auto product = MulMod(static_cast<uint64_t>(left.value),
                                        static_cast<uint64_t>(right.value), t);
            destination = AddMod(destination,
                                 MulMod(product, m_inverseDimension, t), t);
            if (result.size() > kGLIntProductionMaxLogicalValues) {
                throw GLDimensionError(
                    "production integer trace product exceeds its sparse output bound");
            }
        }
    }
    return GLIntProductionSparsePlaintext(m_parameters, ValuesFromMap(result));
}

}  // namespace lbcrypto
