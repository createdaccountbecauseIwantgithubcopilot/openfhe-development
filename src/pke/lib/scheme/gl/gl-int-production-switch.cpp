//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "scheme/gl/gl-int-production-switch.h"

#include <algorithm>
#include <limits>
#include <map>
#include <random>
#include <string>
#include <tuple>
#include <utility>

namespace lbcrypto {
namespace {

using ExponentKey = std::tuple<uint32_t, uint32_t, uint32_t>;

struct WideGaussian {
    __int128 real{0};
    __int128 imaginary{0};
};

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
            "production SwitchInt requires canonical GL-128-257-N32 "
            "with t=1579009");
    }
}

uint32_t AddQ(uint32_t lhs, uint32_t rhs, uint32_t modulus) noexcept {
    const auto sum = static_cast<uint64_t>(lhs) + rhs;
    return static_cast<uint32_t>(sum >= modulus ? sum - modulus : sum);
}

uint32_t SubQ(uint32_t lhs, uint32_t rhs, uint32_t modulus) noexcept {
    return lhs >= rhs ? lhs - rhs : modulus - (rhs - lhs);
}

uint32_t MulQ(uint32_t lhs, uint32_t rhs, uint32_t modulus) noexcept {
    return static_cast<uint32_t>((static_cast<uint64_t>(lhs) * rhs) % modulus);
}

uint32_t PowQ(uint32_t base, uint32_t exponent, uint32_t modulus) noexcept {
    uint32_t result = 1;
    while (exponent != 0) {
        if ((exponent & 1) != 0) {
            result = MulQ(result, base, modulus);
        }
        base = MulQ(base, base, modulus);
        exponent >>= 1;
    }
    return result;
}

uint32_t SignedToQ(int64_t value, uint32_t modulus) noexcept {
    const auto remainder = value % static_cast<int64_t>(modulus);
    return static_cast<uint32_t>(
        remainder < 0 ? remainder + modulus : remainder);
}

std::size_t CoefficientIndex(std::size_t n, std::size_t phi, std::size_t x,
                             std::size_t y, std::size_t w) noexcept {
    return (x * n + y) * phi + w;
}

class SplitMix64 final {
public:
    explicit SplitMix64(uint64_t seed) : m_state(seed) {}
    uint64_t Next() noexcept {
        auto z = (m_state += 0x9e3779b97f4a7c15ULL);
        z      = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z      = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }

private:
    uint64_t m_state;
};

uint64_t ResolveSeed(uint64_t seed) {
    if (seed != 0) {
        return seed;
    }
    std::random_device random;
    return (static_cast<uint64_t>(random()) << 32) ^ random();
}

void MultiplyByI(WideGaussian* value) noexcept {
    const auto real = value->real;
    value->real = -value->imaginary;
    value->imaginary = real;
}

int64_t Narrow(__int128 value) {
    if (value < std::numeric_limits<int64_t>::min() ||
        value > std::numeric_limits<int64_t>::max()) {
        throw GLCiphertextError(
            "production SwitchInt sparse coefficient overflows int64");
    }
    return static_cast<int64_t>(value);
}

GLIntProductionModResidue MultiplyGaussian(
    const GLIntProductionModResidue& lhs, int64_t rhsReal,
    int64_t rhsImaginary, uint32_t modulus) noexcept {
    const auto real      = SignedToQ(rhsReal, modulus);
    const auto imaginary = SignedToQ(rhsImaginary, modulus);
    return {SubQ(MulQ(lhs.real, real, modulus),
                 MulQ(lhs.imaginary, imaginary, modulus), modulus),
            AddQ(MulQ(lhs.real, imaginary, modulus),
                 MulQ(lhs.imaginary, real, modulus), modulus)};
}

void MultiplyByI(GLIntProductionModResidue* value,
                 uint32_t modulus) noexcept {
    const auto real = value->real;
    value->real = value->imaginary == 0 ? 0 : modulus - value->imaginary;
    value->imaginary = real;
}

void Accumulate(GLIntProductionModResidue* destination,
                const GLIntProductionModResidue& value, uint32_t modulus,
                bool positive) noexcept {
    if (positive) {
        destination->real = AddQ(destination->real, value.real, modulus);
        destination->imaginary =
            AddQ(destination->imaginary, value.imaginary, modulus);
    }
    else {
        destination->real = SubQ(destination->real, value.real, modulus);
        destination->imaginary =
            SubQ(destination->imaginary, value.imaginary, modulus);
    }
}

}  // namespace

GLIntProductionRNSPolynomial::GLIntProductionRNSPolynomial(
    GLIntWBatchedParameters parameters, GLIntWBatchedCodecRoots roots,
    uint32_t level, std::vector<GLIntProductionRNSPolynomialPlane> planes)
    : m_parameters(std::move(parameters)),
      m_roots(std::move(roots)),
      m_level(level),
      m_planes(std::move(planes)) {
    Validate();
}

const GLIntWBatchedParameters&
GLIntProductionRNSPolynomial::GetParameters() const noexcept {
    return m_parameters;
}

const GLIntWBatchedCodecRoots&
GLIntProductionRNSPolynomial::GetRoots() const noexcept {
    return m_roots;
}

uint32_t GLIntProductionRNSPolynomial::GetLevel() const noexcept {
    return m_level;
}

const std::vector<GLIntProductionRNSPolynomialPlane>&
GLIntProductionRNSPolynomial::GetPlanes() const noexcept {
    return m_planes;
}

void GLIntProductionRNSPolynomial::Validate() const {
    RequireProductionParameters(m_parameters);
    m_roots.Validate(m_parameters);
    if (m_planes.empty() ||
        m_level + m_planes.size() != kGLIntProductionRLWEPlaneCount) {
        throw GLCiphertextError(
            "production SwitchInt polynomial has invalid level/plane metadata");
    }
    const auto expected = static_cast<std::size_t>(m_parameters.dimension) *
                          m_parameters.dimension *
                          (m_parameters.cyclotomicPrime - 1);
    for (const auto& plane : m_planes) {
        if (plane.modulus == 0 || plane.coefficients.size() != expected) {
            throw GLCiphertextError(
                "production SwitchInt polynomial plane has invalid shape");
        }
        for (const auto& coefficient : plane.coefficients) {
            if (coefficient.real >= plane.modulus ||
                coefficient.imaginary >= plane.modulus) {
                throw GLCiphertextError(
                    "production SwitchInt polynomial residue is not canonical");
            }
        }
    }
}

GLIntProductionSwitchKey::GLIntProductionSwitchKey(
    GLIntWBatchedParameters parameters,
    GLIntProductionSwitchDirection direction, std::string destinationKeyTag,
    std::vector<Term> k0, std::vector<Term> k1)
    : m_parameters(std::move(parameters)),
      m_direction(direction),
      m_destinationKeyTag(std::move(destinationKeyTag)),
      m_k0(std::move(k0)),
      m_k1(std::move(k1)) {
    Validate();
}

GLIntProductionSwitchDirection
GLIntProductionSwitchKey::GetDirection() const noexcept {
    return m_direction;
}

const std::string&
GLIntProductionSwitchKey::GetDestinationKeyTag() const noexcept {
    return m_destinationKeyTag;
}

std::size_t GLIntProductionSwitchKey::GetK0TermCount() const noexcept {
    return m_k0.size();
}

std::size_t GLIntProductionSwitchKey::GetK1TermCount() const noexcept {
    return m_k1.size();
}

bool GLIntProductionSwitchKey::IsNoiseFree() const noexcept {
    return true;
}

bool GLIntProductionSwitchKey::IsSecurityAuthorized() const noexcept {
    return false;
}

void GLIntProductionSwitchKey::Validate() const {
    RequireProductionParameters(m_parameters);
    if ((m_direction !=
             GLIntProductionSwitchDirection::SmallSquareToPrimary &&
         m_direction !=
             GLIntProductionSwitchDirection::BigTransposeToPrimary) ||
        m_destinationKeyTag.empty() || m_k1.empty() ||
        m_k0.size() > kGLIntProductionMaxSwitchKeyTerms ||
        m_k1.size() > kGLIntProductionMaxSwitchKeyTerms) {
        throw GLMissingEvaluationKeyError(
            "production SwitchInt evaluation key has invalid bounded material");
    }
    const auto validateTerms = [&](const std::vector<Term>& terms) {
        ExponentKey previous{};
        bool havePrevious = false;
        for (const auto& term : terms) {
            if (term.x >= m_parameters.dimension ||
                term.y >= m_parameters.dimension ||
                term.w >= m_parameters.cyclotomicPrime - 1 ||
                (term.real == 0 && term.imaginary == 0)) {
                throw GLMissingEvaluationKeyError(
                    "production SwitchInt evaluation-key term is invalid");
            }
            if (m_direction ==
                    GLIntProductionSwitchDirection::SmallSquareToPrimary &&
                term.y != 0) {
                throw GLMissingEvaluationKeyError(
                    "SwitchInt_small evaluation key must be Y-constant");
            }
            const ExponentKey key{term.x, term.y, term.w};
            if (havePrevious && !(previous < key)) {
                throw GLMissingEvaluationKeyError(
                    "production SwitchInt evaluation-key terms are not ordered");
            }
            previous     = key;
            havePrevious = true;
        }
    };
    validateTerms(m_k0);
    validateTerms(m_k1);
}

GLIntProductionAuxSwitchKey::GLIntProductionAuxSwitchKey(
    GLIntWBatchedParameters parameters, GLIntWBatchedCodecRoots roots,
    GLIntProductionSwitchDirection direction, std::string destinationKeyTag,
    uint32_t auxiliaryModulus,
    std::vector<GLIntProductionCiphertextPlane> planes)
    : m_parameters(std::move(parameters)),
      m_roots(std::move(roots)),
      m_direction(direction),
      m_destinationKeyTag(std::move(destinationKeyTag)),
      m_auxiliaryModulus(auxiliaryModulus),
      m_planes(std::move(planes)) {
    Validate();
}

GLIntProductionSwitchDirection
GLIntProductionAuxSwitchKey::GetDirection() const noexcept {
    return m_direction;
}

const std::string&
GLIntProductionAuxSwitchKey::GetDestinationKeyTag() const noexcept {
    return m_destinationKeyTag;
}

uint32_t GLIntProductionAuxSwitchKey::GetAuxiliaryModulus() const noexcept {
    return m_auxiliaryModulus;
}

const std::vector<GLIntProductionCiphertextPlane>&
GLIntProductionAuxSwitchKey::GetPlanes() const noexcept {
    return m_planes;
}

bool GLIntProductionAuxSwitchKey::UsesTErrors() const noexcept {
    return true;
}

bool GLIntProductionAuxSwitchKey::UsesNoiseScalingModSwitch() const noexcept {
    return true;
}

bool GLIntProductionAuxSwitchKey::IsSecurityAuthorized() const noexcept {
    return false;
}

void GLIntProductionAuxSwitchKey::Validate() const {
    RequireProductionParameters(m_parameters);
    m_roots.Validate(m_parameters);
    const auto coefficientCount =
        static_cast<std::size_t>(m_parameters.dimension) *
        m_parameters.dimension * (m_parameters.cyclotomicPrime - 1);
    if ((m_direction !=
             GLIntProductionSwitchDirection::SmallSquareToPrimary &&
         m_direction !=
             GLIntProductionSwitchDirection::BigTransposeToPrimary) ||
        m_destinationKeyTag.empty() || m_auxiliaryModulus == 0 ||
        m_planes.size() != kGLIntProductionRLWEPlaneCount ||
        m_planes.back().modulus != m_auxiliaryModulus) {
        throw GLMissingEvaluationKeyError(
            "production auxiliary SwitchInt key has invalid metadata");
    }
    for (const auto& plane : m_planes) {
        if (plane.modulus == 0 || plane.b.size() != coefficientCount ||
            plane.a.size() != coefficientCount) {
            throw GLMissingEvaluationKeyError(
                "production auxiliary SwitchInt key has invalid shape");
        }
        for (const auto* component : {&plane.b, &plane.a}) {
            for (const auto& coefficient : *component) {
                if (coefficient.real >= plane.modulus ||
                    coefficient.imaginary >= plane.modulus) {
                    throw GLMissingEvaluationKeyError(
                        "production auxiliary SwitchInt residue is not canonical");
                }
            }
        }
    }
}

GLIntProductionSwitchResult::GLIntProductionSwitchResult(
    GLIntProductionSwitchDirection direction, std::string destinationKeyTag,
    GLIntProductionRNSPolynomial b, GLIntProductionRNSPolynomial a)
    : m_direction(direction),
      m_destinationKeyTag(std::move(destinationKeyTag)),
      m_b(std::move(b)),
      m_a(std::move(a)) {
    Validate();
}

GLIntProductionSwitchDirection
GLIntProductionSwitchResult::GetDirection() const noexcept {
    return m_direction;
}

const std::string&
GLIntProductionSwitchResult::GetDestinationKeyTag() const noexcept {
    return m_destinationKeyTag;
}

const GLIntProductionRNSPolynomial&
GLIntProductionSwitchResult::GetB() const noexcept {
    return m_b;
}

const GLIntProductionRNSPolynomial&
GLIntProductionSwitchResult::GetA() const noexcept {
    return m_a;
}

void GLIntProductionSwitchResult::Validate() const {
    m_b.Validate();
    m_a.Validate();
    if (m_destinationKeyTag.empty() ||
        !SameParameters(m_b.GetParameters(), m_a.GetParameters()) ||
        m_b.GetRoots() != m_a.GetRoots() ||
        m_b.GetLevel() != m_a.GetLevel() ||
        m_b.GetPlanes().size() != m_a.GetPlanes().size()) {
        throw GLCiphertextError(
            "production SwitchInt result components are incompatible");
    }
    for (std::size_t index = 0; index < m_b.GetPlanes().size(); ++index) {
        if (m_b.GetPlanes()[index].modulus !=
            m_a.GetPlanes()[index].modulus) {
            throw GLCiphertextError(
                "production SwitchInt result RNS bases differ");
        }
    }
}

GLIntProductionSwitchCore::GLIntProductionSwitchCore(
    GLIntWBatchedParameters parameters)
    : m_parameters(std::move(parameters)) {
    RequireProductionParameters(m_parameters);
    const GLIntProductionRLWECore rlwe(m_parameters);
    m_roots   = rlwe.GetRoots();
    m_moduli  = rlwe.GetModuli();
}

const GLIntWBatchedParameters&
GLIntProductionSwitchCore::GetParameters() const noexcept {
    return m_parameters;
}

GLIntProductionSwitchCapabilities
GLIntProductionSwitchCore::GetCapabilities() const noexcept {
    return {};
}

void GLIntProductionSwitchCore::ValidatePrimaryKey(
    const GLIntProductionSecretKey& key, const char* operation) const {
    key.Validate();
    if (!SameParameters(m_parameters, key.GetParameters())) {
        throw GLKeyContextMismatchError(std::string(operation) +
                                        " primary key parameters mismatch");
    }
}

void GLIntProductionSwitchCore::ValidatePolynomial(
    const GLIntProductionRNSPolynomial& polynomial,
    const char* objectName) const {
    polynomial.Validate();
    if (!SameParameters(m_parameters, polynomial.GetParameters()) ||
        polynomial.GetRoots() != m_roots) {
        throw GLContextMismatchError(std::string(objectName) +
                                     " context binding mismatch");
    }
    const auto active = m_moduli.size() - polynomial.GetLevel();
    if (polynomial.GetPlanes().size() != active) {
        throw GLCiphertextError(std::string(objectName) +
                                " active plane count mismatch");
    }
    for (std::size_t index = 0; index < active; ++index) {
        if (polynomial.GetPlanes()[index].modulus != m_moduli[index]) {
            throw GLContextMismatchError(std::string(objectName) +
                                         " modulus prefix mismatch");
        }
    }
}

void GLIntProductionSwitchCore::ValidateEvaluationKey(
    const GLIntProductionSwitchKey& evaluationKey,
    GLIntProductionSwitchDirection direction,
    const char* operation) const {
    evaluationKey.Validate();
    if (!SameParameters(m_parameters, evaluationKey.m_parameters)) {
        throw GLKeyContextMismatchError(std::string(operation) +
                                        " evaluation-key parameters mismatch");
    }
    if (evaluationKey.GetDirection() != direction) {
        throw GLMissingEvaluationKeyError(std::string(operation) +
                                          " received the wrong key direction");
    }
}

void GLIntProductionSwitchCore::ValidateAuxEvaluationKey(
    const GLIntProductionAuxSwitchKey& evaluationKey,
    GLIntProductionSwitchDirection direction, const char* operation) const {
    evaluationKey.Validate();
    if (!SameParameters(m_parameters, evaluationKey.m_parameters) ||
        evaluationKey.m_roots != m_roots ||
        evaluationKey.GetAuxiliaryModulus() != m_moduli.back() ||
        evaluationKey.GetPlanes().size() != m_moduli.size()) {
        throw GLKeyContextMismatchError(std::string(operation) +
                                        " auxiliary-key context mismatch");
    }
    for (std::size_t index = 0; index < m_moduli.size(); ++index) {
        if (evaluationKey.GetPlanes()[index].modulus != m_moduli[index]) {
            throw GLKeyContextMismatchError(std::string(operation) +
                                            " auxiliary-key basis mismatch");
        }
    }
    if (evaluationKey.GetDirection() != direction) {
        throw GLMissingEvaluationKeyError(std::string(operation) +
                                          " received the wrong auxiliary key");
    }
}

std::vector<GLIntProductionSwitchCore::Term>
GLIntProductionSwitchCore::PrimaryTerms(
    const GLIntProductionSecretKey& key) const {
    std::vector<Term> output;
    output.reserve(key.m_terms.size());
    for (const auto& term : key.m_terms) {
        output.push_back(Term{term.x, 0, term.w, term.real, term.imaginary});
    }
    return output;
}

std::vector<GLIntProductionSwitchCore::Term>
GLIntProductionSwitchCore::SourceTerms(
    const GLIntProductionSecretKey& key,
    GLIntProductionSwitchDirection direction) const {
    const auto primary = PrimaryTerms(key);
    if (direction ==
        GLIntProductionSwitchDirection::SmallSquareToPrimary) {
        return MultiplySparse(primary, primary);
    }
    const auto n = m_parameters.dimension;
    const auto p = m_parameters.cyclotomicPrime;
    const auto phi = p - 1;
    std::map<ExponentKey, WideGaussian> transformed;
    for (const auto& term : primary) {
        WideGaussian coefficient{term.real, -term.imaginary};
        const auto y = term.x == 0 ? 0 : n - term.x;
        if (term.x != 0) {
            // Y^{-x}=-I*Y^{n-x} in Z[I,Y]/(I^2+1,Y^n-I).
            const auto real = coefficient.real;
            coefficient.real = coefficient.imaginary;
            coefficient.imaginary = -real;
        }
        const auto inverseW = term.w == 0 ? 0 : p - term.w;
        const auto accumulate = [&](uint32_t w, bool positive) {
            auto& destination = transformed[{0, y, w}];
            destination.real += positive ? coefficient.real
                                         : -coefficient.real;
            destination.imaginary += positive ? coefficient.imaginary
                                              : -coefficient.imaginary;
        };
        if (inverseW < phi) {
            accumulate(inverseW, true);
        }
        else {
            // W^(p-1)=-(1+...+W^(p-2)) modulo Phi_p.
            for (uint32_t w = 0; w < phi; ++w) {
                accumulate(w, false);
            }
        }
    }
    std::vector<Term> output;
    output.reserve(transformed.size());
    for (const auto& [key, coefficient] : transformed) {
        if (coefficient.real == 0 && coefficient.imaginary == 0) {
            continue;
        }
        output.push_back(
            Term{std::get<0>(key), std::get<1>(key), std::get<2>(key),
                 Narrow(coefficient.real), Narrow(coefficient.imaginary)});
    }
    return output;
}

std::vector<GLIntProductionSwitchCore::Term>
GLIntProductionSwitchCore::MultiplySparse(const std::vector<Term>& lhs,
                                           const std::vector<Term>& rhs) const {
    const auto n   = m_parameters.dimension;
    const auto p   = m_parameters.cyclotomicPrime;
    const auto phi = p - 1;
    std::map<ExponentKey, WideGaussian> accumulated;
    for (const auto& left : lhs) {
        for (const auto& right : rhs) {
            WideGaussian product{
                static_cast<__int128>(left.real) * right.real -
                    static_cast<__int128>(left.imaginary) * right.imaginary,
                static_cast<__int128>(left.real) * right.imaginary +
                    static_cast<__int128>(left.imaginary) * right.real};
            const auto xDegree = left.x + right.x;
            const auto yDegree = left.y + right.y;
            const auto x       = xDegree % n;
            const auto y       = yDegree % n;
            if (xDegree >= n) {
                MultiplyByI(&product);
            }
            if (yDegree >= n) {
                MultiplyByI(&product);
            }
            auto w = left.w + right.w;
            if (w >= p) {
                w -= p;
            }
            const auto accumulate = [&](uint32_t targetW, bool positive) {
                auto& destination = accumulated[{x, y, targetW}];
                destination.real += positive ? product.real : -product.real;
                destination.imaginary +=
                    positive ? product.imaginary : -product.imaginary;
            };
            if (w < phi) {
                accumulate(w, true);
            }
            else {
                for (uint32_t targetW = 0; targetW < phi; ++targetW) {
                    accumulate(targetW, false);
                }
            }
            if (accumulated.size() > kGLIntProductionMaxSwitchKeyTerms) {
                throw GLDimensionError(
                    "production SwitchInt sparse product exceeds its term bound");
            }
        }
    }
    std::vector<Term> output;
    output.reserve(accumulated.size());
    for (const auto& [key, value] : accumulated) {
        if (value.real == 0 && value.imaginary == 0) {
            continue;
        }
        output.push_back(Term{std::get<0>(key), std::get<1>(key),
                              std::get<2>(key), Narrow(value.real),
                              Narrow(value.imaginary)});
    }
    return output;
}

std::vector<GLIntProductionSwitchCore::Term>
GLIntProductionSwitchCore::SubtractSparse(const std::vector<Term>& lhs,
                                           const std::vector<Term>& rhs) const {
    std::map<ExponentKey, WideGaussian> accumulated;
    for (const auto& term : lhs) {
        auto& destination = accumulated[{term.x, term.y, term.w}];
        destination.real += term.real;
        destination.imaginary += term.imaginary;
    }
    for (const auto& term : rhs) {
        auto& destination = accumulated[{term.x, term.y, term.w}];
        destination.real -= term.real;
        destination.imaginary -= term.imaginary;
    }
    if (accumulated.size() > kGLIntProductionMaxSwitchKeyTerms) {
        throw GLDimensionError(
            "production SwitchInt sparse difference exceeds its term bound");
    }
    std::vector<Term> output;
    for (const auto& [key, value] : accumulated) {
        if (value.real == 0 && value.imaginary == 0) {
            continue;
        }
        output.push_back(Term{std::get<0>(key), std::get<1>(key),
                              std::get<2>(key), Narrow(value.real),
                              Narrow(value.imaginary)});
    }
    return output;
}

GLIntProductionSwitchKey GLIntProductionSwitchCore::EvalKeyGenSmallSquare(
    const GLIntProductionSecretKey& primaryKey, uint64_t seed) const {
    ValidatePrimaryKey(primaryKey, "EvalKeyGenSmallSquare");
    SplitMix64 rng(ResolveSeed(seed));
    const std::vector<Term> k1{{
        static_cast<uint32_t>(rng.Next() % m_parameters.dimension), 0,
        1 + static_cast<uint32_t>(
                rng.Next() % (m_parameters.cyclotomicPrime - 2)),
        (rng.Next() & 1) != 0 ? 1 : -1, 0}};
    const auto source = SourceTerms(
        primaryKey, GLIntProductionSwitchDirection::SmallSquareToPrimary);
    const auto k0 =
        SubtractSparse(source, MultiplySparse(k1, PrimaryTerms(primaryKey)));
    return GLIntProductionSwitchKey(
        m_parameters, GLIntProductionSwitchDirection::SmallSquareToPrimary,
        primaryKey.GetKeyTag(), k0, k1);
}

GLIntProductionSwitchKey GLIntProductionSwitchCore::EvalKeyGenBigTranspose(
    const GLIntProductionSecretKey& primaryKey, uint64_t seed) const {
    ValidatePrimaryKey(primaryKey, "EvalKeyGenBigTranspose");
    SplitMix64 rng(ResolveSeed(seed));
    const std::vector<Term> k1{{
        static_cast<uint32_t>(rng.Next() % m_parameters.dimension),
        static_cast<uint32_t>(rng.Next() % m_parameters.dimension),
        1 + static_cast<uint32_t>(
                rng.Next() % (m_parameters.cyclotomicPrime - 2)),
        (rng.Next() & 1) != 0 ? 1 : -1, 0}};
    const auto source = SourceTerms(
        primaryKey, GLIntProductionSwitchDirection::BigTransposeToPrimary);
    const auto k0 =
        SubtractSparse(source, MultiplySparse(k1, PrimaryTerms(primaryKey)));
    return GLIntProductionSwitchKey(
        m_parameters, GLIntProductionSwitchDirection::BigTransposeToPrimary,
        primaryKey.GetKeyTag(), k0, k1);
}

GLIntProductionAuxSwitchKey GLIntProductionSwitchCore::AuxEvalKeyGen(
    const GLIntProductionSecretKey& primaryKey,
    GLIntProductionSwitchDirection direction, uint64_t seed) const {
    ValidatePrimaryKey(primaryKey, "auxiliary SwitchInt EvalKeyGen");
    SplitMix64 rng(ResolveSeed(seed));
    const auto n = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi =
        static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    const auto coefficientCount = n * n * phi;
    std::vector<int8_t> errorReal(coefficientCount);
    std::vector<int8_t> errorImaginary(coefficientCount);
    for (std::size_t index = 0; index < coefficientCount; ++index) {
        errorReal[index] = static_cast<int8_t>(rng.Next() % 3) - 1;
        errorImaginary[index] = static_cast<int8_t>(rng.Next() % 3) - 1;
    }
    errorReal.front() = 1;

    const auto primary = PrimaryTerms(primaryKey);
    const auto source = SourceTerms(primaryKey, direction);
    const auto auxiliaryModulus = m_moduli.back();
    std::vector<GLIntProductionCiphertextPlane> planes;
    planes.reserve(m_moduli.size());
    for (const auto modulus : m_moduli) {
        GLIntProductionCiphertextPlane plane;
        plane.modulus = modulus;
        plane.a.resize(coefficientCount);
        for (auto& coefficient : plane.a) {
            coefficient.real = static_cast<uint32_t>(rng.Next() % modulus);
            coefficient.imaginary =
                static_cast<uint32_t>(rng.Next() % modulus);
        }
        const auto destinationProduct =
            MultiplyDenseBySparse(plane.a, primary, modulus);
        plane.b.resize(coefficientCount);
        for (std::size_t index = 0; index < coefficientCount; ++index) {
            const auto noiseReal = SignedToQ(
                static_cast<int64_t>(m_parameters.plaintextModulus) *
                    errorReal[index],
                modulus);
            const auto noiseImaginary = SignedToQ(
                static_cast<int64_t>(m_parameters.plaintextModulus) *
                    errorImaginary[index],
                modulus);
            plane.b[index] = {
                SubQ(noiseReal, destinationProduct[index].real, modulus),
                SubQ(noiseImaginary, destinationProduct[index].imaginary,
                     modulus)};
        }
        const auto auxiliary = auxiliaryModulus % modulus;
        for (const auto& term : source) {
            auto& coefficient =
                plane.b[CoefficientIndex(n, phi, term.x, term.y, term.w)];
            coefficient.real = AddQ(
                coefficient.real,
                MulQ(auxiliary, SignedToQ(term.real, modulus), modulus),
                modulus);
            coefficient.imaginary = AddQ(
                coefficient.imaginary,
                MulQ(auxiliary, SignedToQ(term.imaginary, modulus), modulus),
                modulus);
        }
        planes.push_back(std::move(plane));
    }
    return GLIntProductionAuxSwitchKey(
        m_parameters, m_roots, direction, primaryKey.GetKeyTag(),
        auxiliaryModulus, std::move(planes));
}

GLIntProductionAuxSwitchKey
GLIntProductionSwitchCore::EvalKeyGenAuxSmallSquare(
    const GLIntProductionSecretKey& primaryKey, uint64_t seed) const {
    return AuxEvalKeyGen(
        primaryKey, GLIntProductionSwitchDirection::SmallSquareToPrimary,
        seed);
}

GLIntProductionAuxSwitchKey
GLIntProductionSwitchCore::EvalKeyGenAuxBigTranspose(
    const GLIntProductionSecretKey& primaryKey, uint64_t seed) const {
    return AuxEvalKeyGen(
        primaryKey, GLIntProductionSwitchDirection::BigTransposeToPrimary,
        seed);
}

GLIntProductionRNSPolynomial GLIntProductionSwitchCore::ExtractA(
    const GLIntProductionCiphertext& ciphertext) const {
    ciphertext.Validate();
    if (!SameParameters(m_parameters, ciphertext.GetParameters()) ||
        ciphertext.GetRoots() != m_roots) {
        throw GLContextMismatchError(
            "production SwitchInt ExtractA context mismatch");
    }
    std::vector<GLIntProductionRNSPolynomialPlane> planes;
    planes.reserve(ciphertext.GetPlanes().size());
    for (const auto& plane : ciphertext.GetPlanes()) {
        planes.push_back({plane.modulus, plane.a});
    }
    return GLIntProductionRNSPolynomial(m_parameters, m_roots,
                                        ciphertext.GetLevel(),
                                        std::move(planes));
}

GLIntProductionRNSPolynomial GLIntProductionSwitchCore::MakeMonomial(
    uint32_t level, uint32_t x, uint32_t y, uint32_t w, int64_t real,
    int64_t imaginary) const {
    if (level >= m_moduli.size() || x >= m_parameters.dimension ||
        y >= m_parameters.dimension ||
        w >= m_parameters.cyclotomicPrime - 1) {
        throw GLDimensionError(
            "production SwitchInt monomial is outside the active R'_q ring");
    }
    const auto n   = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi = static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    const auto count = n * n * phi;
    std::vector<GLIntProductionRNSPolynomialPlane> planes;
    for (std::size_t planeIndex = 0; planeIndex < m_moduli.size() - level;
         ++planeIndex) {
        GLIntProductionRNSPolynomialPlane plane;
        plane.modulus = m_moduli[planeIndex];
        plane.coefficients.resize(count);
        plane.coefficients[CoefficientIndex(n, phi, x, y, w)] = {
            SignedToQ(real, plane.modulus),
            SignedToQ(imaginary, plane.modulus)};
        planes.push_back(std::move(plane));
    }
    return GLIntProductionRNSPolynomial(m_parameters, m_roots, level,
                                        std::move(planes));
}

std::vector<GLIntProductionModResidue>
GLIntProductionSwitchCore::MultiplyDenseBySparse(
    const std::vector<GLIntProductionModResidue>& dense,
    const std::vector<Term>& sparse, uint32_t modulus) const {
    const auto n   = static_cast<std::size_t>(m_parameters.dimension);
    const auto p   = static_cast<std::size_t>(m_parameters.cyclotomicPrime);
    const auto phi = p - 1;
    const auto expected = n * n * phi;
    if (dense.size() != expected) {
        throw GLCiphertextError(
            "production SwitchInt dense input has the wrong R'_q shape");
    }
    std::vector<GLIntProductionModResidue> output(expected);
    for (const auto& term : sparse) {
        for (std::size_t x = 0; x < n; ++x) {
            const auto xDegree = x + term.x;
            const auto targetX = xDegree % n;
            const bool xWrap   = xDegree >= n;
            for (std::size_t y = 0; y < n; ++y) {
                const auto yDegree = y + term.y;
                const auto targetY = yDegree % n;
                const bool yWrap   = yDegree >= n;
                for (std::size_t w = 0; w < phi; ++w) {
                    const auto& source = dense[CoefficientIndex(n, phi, x, y, w)];
                    if (source.real == 0 && source.imaginary == 0) {
                        continue;
                    }
                    auto product = MultiplyGaussian(
                        source, term.real, term.imaginary, modulus);
                    if (xWrap) {
                        MultiplyByI(&product, modulus);
                    }
                    if (yWrap) {
                        MultiplyByI(&product, modulus);
                    }
                    auto targetW = w + term.w;
                    if (targetW >= p) {
                        targetW -= p;
                    }
                    if (targetW < phi) {
                        Accumulate(&output[CoefficientIndex(
                                       n, phi, targetX, targetY, targetW)],
                                   product, modulus, true);
                    }
                    else {
                        for (std::size_t reducedW = 0; reducedW < phi;
                             ++reducedW) {
                            Accumulate(&output[CoefficientIndex(
                                           n, phi, targetX, targetY, reducedW)],
                                       product, modulus, false);
                        }
                    }
                }
            }
        }
    }
    return output;
}

GLIntProductionSwitchResult GLIntProductionSwitchCore::Apply(
    const GLIntProductionRNSPolynomial& input,
    const GLIntProductionSwitchKey& evaluationKey) const {
    ValidatePolynomial(input, "production SwitchInt input");
    std::vector<GLIntProductionRNSPolynomialPlane> bPlanes;
    std::vector<GLIntProductionRNSPolynomialPlane> aPlanes;
    bPlanes.reserve(input.GetPlanes().size());
    aPlanes.reserve(input.GetPlanes().size());
    for (const auto& plane : input.GetPlanes()) {
        bPlanes.push_back({plane.modulus, MultiplyDenseBySparse(
                                              plane.coefficients,
                                              evaluationKey.m_k0,
                                              plane.modulus)});
        aPlanes.push_back({plane.modulus, MultiplyDenseBySparse(
                                              plane.coefficients,
                                              evaluationKey.m_k1,
                                              plane.modulus)});
    }
    return GLIntProductionSwitchResult(
        evaluationKey.GetDirection(), evaluationKey.GetDestinationKeyTag(),
        GLIntProductionRNSPolynomial(m_parameters, m_roots, input.GetLevel(),
                                     std::move(bPlanes)),
        GLIntProductionRNSPolynomial(m_parameters, m_roots, input.GetLevel(),
                                     std::move(aPlanes)));
}

std::vector<GLIntProductionSwitchCore::Term>
GLIntProductionSwitchCore::SparseInputTerms(
    const GLIntProductionRNSPolynomial& input) const {
    if (input.GetLevel() != 1 || input.GetPlanes().size() != 1) {
        throw GLDepthError(
            "auxiliary SwitchInt requires a base-q level-1 input");
    }
    const auto modulus = input.GetPlanes().front().modulus;
    const auto n = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi =
        static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    std::vector<Term> terms;
    for (std::size_t x = 0; x < n; ++x) {
        for (std::size_t y = 0; y < n; ++y) {
            for (std::size_t w = 0; w < phi; ++w) {
                const auto& coefficient = input.GetPlanes().front()
                                              .coefficients[CoefficientIndex(
                                                  n, phi, x, y, w)];
                if (coefficient.real == 0 && coefficient.imaginary == 0) {
                    continue;
                }
                const auto real =
                    coefficient.real <= modulus / 2
                        ? static_cast<int64_t>(coefficient.real)
                        : static_cast<int64_t>(coefficient.real) - modulus;
                const auto imaginary =
                    coefficient.imaginary <= modulus / 2
                        ? static_cast<int64_t>(coefficient.imaginary)
                        : static_cast<int64_t>(coefficient.imaginary) - modulus;
                terms.push_back(Term{static_cast<uint32_t>(x),
                                     static_cast<uint32_t>(y),
                                     static_cast<uint32_t>(w), real,
                                     imaginary});
                if (terms.size() >
                    kGLIntProductionMaxAuxSwitchInputTerms) {
                    throw GLDimensionError(
                        "auxiliary SwitchInt input exceeds its sparse-term bound");
                }
            }
        }
    }
    return terms;
}

GLIntProductionSwitchResult GLIntProductionSwitchCore::ApplyAux(
    const GLIntProductionRNSPolynomial& input,
    const GLIntProductionAuxSwitchKey& evaluationKey) const {
    ValidatePolynomial(input, "auxiliary SwitchInt input");
    const auto inputTerms = SparseInputTerms(input);
    std::vector<std::vector<GLIntProductionModResidue>> bProducts;
    std::vector<std::vector<GLIntProductionModResidue>> aProducts;
    bProducts.reserve(evaluationKey.GetPlanes().size());
    aProducts.reserve(evaluationKey.GetPlanes().size());
    for (const auto& plane : evaluationKey.GetPlanes()) {
        bProducts.push_back(
            MultiplyDenseBySparse(plane.b, inputTerms, plane.modulus));
        aProducts.push_back(
            MultiplyDenseBySparse(plane.a, inputTerms, plane.modulus));
    }

    const auto survivingModulus = m_moduli.front();
    const auto droppedModulus = evaluationKey.GetAuxiliaryModulus();
    const auto t = static_cast<uint32_t>(m_parameters.plaintextModulus);
    const auto negTInverse =
        droppedModulus -
        PowQ(t % droppedModulus, droppedModulus - 2, droppedModulus);
    const auto droppedInverse =
        PowQ(droppedModulus % survivingModulus, survivingModulus - 2,
             survivingModulus);
    auto modReduce = [&](std::vector<GLIntProductionModResidue>* surviving,
                         const std::vector<GLIntProductionModResidue>&
                             dropped) {
        const auto reduce = [&](uint32_t survivorValue,
                                uint32_t droppedValue) {
            const auto deltaResidue =
                MulQ(droppedValue, negTInverse, droppedModulus);
            const auto centeredDelta =
                deltaResidue <= droppedModulus / 2
                    ? static_cast<int64_t>(deltaResidue)
                    : static_cast<int64_t>(deltaResidue) - droppedModulus;
            const auto delta = SignedToQ(centeredDelta, survivingModulus);
            return MulQ(
                AddQ(survivorValue,
                     MulQ(t % survivingModulus, delta, survivingModulus),
                     survivingModulus),
                droppedInverse, survivingModulus);
        };
        for (std::size_t index = 0; index < surviving->size(); ++index) {
            (*surviving)[index].real =
                reduce((*surviving)[index].real, dropped[index].real);
            (*surviving)[index].imaginary = reduce(
                (*surviving)[index].imaginary, dropped[index].imaginary);
        }
    };
    modReduce(&bProducts.front(), bProducts.back());
    modReduce(&aProducts.front(), aProducts.back());

    std::vector<GLIntProductionRNSPolynomialPlane> bPlanes;
    std::vector<GLIntProductionRNSPolynomialPlane> aPlanes;
    bPlanes.push_back({survivingModulus, std::move(bProducts.front())});
    aPlanes.push_back({survivingModulus, std::move(aProducts.front())});
    return GLIntProductionSwitchResult(
        evaluationKey.GetDirection(), evaluationKey.GetDestinationKeyTag(),
        GLIntProductionRNSPolynomial(m_parameters, m_roots, 1,
                                     std::move(bPlanes)),
        GLIntProductionRNSPolynomial(m_parameters, m_roots, 1,
                                     std::move(aPlanes)));
}

GLIntProductionSwitchResult GLIntProductionSwitchCore::SwitchIntSmall(
    const GLIntProductionRNSPolynomial& input,
    const GLIntProductionSwitchKey& evaluationKey) const {
    ValidateEvaluationKey(
        evaluationKey,
        GLIntProductionSwitchDirection::SmallSquareToPrimary,
        "SwitchInt_small");
    return Apply(input, evaluationKey);
}

GLIntProductionSwitchResult GLIntProductionSwitchCore::SwitchIntBig(
    const GLIntProductionRNSPolynomial& input,
    const GLIntProductionSwitchKey& evaluationKey) const {
    ValidateEvaluationKey(
        evaluationKey,
        GLIntProductionSwitchDirection::BigTransposeToPrimary,
        "SwitchInt_big");
    return Apply(input, evaluationKey);
}

GLIntProductionSwitchResult GLIntProductionSwitchCore::SwitchIntAuxSmall(
    const GLIntProductionRNSPolynomial& input,
    const GLIntProductionAuxSwitchKey& evaluationKey) const {
    ValidateAuxEvaluationKey(
        evaluationKey,
        GLIntProductionSwitchDirection::SmallSquareToPrimary,
        "SwitchInt_aux_small");
    return ApplyAux(input, evaluationKey);
}

GLIntProductionSwitchResult GLIntProductionSwitchCore::SwitchIntAuxBig(
    const GLIntProductionRNSPolynomial& input,
    const GLIntProductionAuxSwitchKey& evaluationKey) const {
    ValidateAuxEvaluationKey(
        evaluationKey,
        GLIntProductionSwitchDirection::BigTransposeToPrimary,
        "SwitchInt_aux_big");
    return ApplyAux(input, evaluationKey);
}

bool GLIntProductionSwitchCore::VerifyEvaluationKeyOwner(
    const GLIntProductionSwitchKey& evaluationKey,
    const GLIntProductionSecretKey& primaryKey) const {
    ValidatePrimaryKey(primaryKey, "VerifyEvaluationKeyOwner");
    ValidateEvaluationKey(evaluationKey, evaluationKey.GetDirection(),
                          "VerifyEvaluationKeyOwner");
    if (evaluationKey.GetDestinationKeyTag() != primaryKey.GetKeyTag()) {
        return false;
    }
    const auto relation = SubtractSparse(
        SourceTerms(primaryKey, evaluationKey.GetDirection()),
        MultiplySparse(evaluationKey.m_k1, PrimaryTerms(primaryKey)));
    return relation.size() == evaluationKey.m_k0.size() &&
           std::equal(relation.begin(), relation.end(), evaluationKey.m_k0.begin(),
                      [](const auto& lhs, const auto& rhs) {
                          return lhs.x == rhs.x && lhs.y == rhs.y &&
                                 lhs.w == rhs.w && lhs.real == rhs.real &&
                                 lhs.imaginary == rhs.imaginary;
                      });
}

bool GLIntProductionSwitchCore::VerifySwitchResultOwner(
    const GLIntProductionRNSPolynomial& input,
    const GLIntProductionSwitchResult& result,
    const GLIntProductionSwitchKey& evaluationKey,
    const GLIntProductionSecretKey& primaryKey) const {
    ValidatePolynomial(input, "VerifySwitchResultOwner input");
    result.Validate();
    ValidatePolynomial(result.GetB(), "VerifySwitchResultOwner result b");
    ValidatePolynomial(result.GetA(), "VerifySwitchResultOwner result a");
    if (!VerifyEvaluationKeyOwner(evaluationKey, primaryKey) ||
        result.GetDirection() != evaluationKey.GetDirection() ||
        result.GetDestinationKeyTag() != primaryKey.GetKeyTag() ||
        result.GetB().GetLevel() != input.GetLevel()) {
        return false;
    }
    const auto primary = PrimaryTerms(primaryKey);
    const auto source = SourceTerms(primaryKey, evaluationKey.GetDirection());
    for (std::size_t planeIndex = 0; planeIndex < input.GetPlanes().size();
         ++planeIndex) {
        const auto modulus = input.GetPlanes()[planeIndex].modulus;
        auto actual = MultiplyDenseBySparse(
            result.GetA().GetPlanes()[planeIndex].coefficients, primary,
            modulus);
        const auto& switchedB =
            result.GetB().GetPlanes()[planeIndex].coefficients;
        for (std::size_t index = 0; index < actual.size(); ++index) {
            actual[index].real =
                AddQ(actual[index].real, switchedB[index].real, modulus);
            actual[index].imaginary = AddQ(actual[index].imaginary,
                                            switchedB[index].imaginary,
                                            modulus);
        }
        const auto expected = MultiplyDenseBySparse(
            input.GetPlanes()[planeIndex].coefficients, source, modulus);
        if (actual != expected) {
            return false;
        }
    }
    return true;
}

bool GLIntProductionSwitchCore::VerifyAuxEvaluationKeyOwner(
    const GLIntProductionAuxSwitchKey& evaluationKey,
    const GLIntProductionSecretKey& primaryKey) const {
    ValidatePrimaryKey(primaryKey, "VerifyAuxEvaluationKeyOwner");
    ValidateAuxEvaluationKey(evaluationKey, evaluationKey.GetDirection(),
                             "VerifyAuxEvaluationKeyOwner");
    if (evaluationKey.GetDestinationKeyTag() != primaryKey.GetKeyTag()) {
        return false;
    }
    const auto primary = PrimaryTerms(primaryKey);
    const auto source =
        SourceTerms(primaryKey, evaluationKey.GetDirection());
    const auto n = static_cast<std::size_t>(m_parameters.dimension);
    const auto phi =
        static_cast<std::size_t>(m_parameters.cyclotomicPrime - 1);
    const auto t = static_cast<int64_t>(m_parameters.plaintextModulus);
    for (const auto& plane : evaluationKey.GetPlanes()) {
        auto relation =
            MultiplyDenseBySparse(plane.a, primary, plane.modulus);
        for (std::size_t index = 0; index < relation.size(); ++index) {
            relation[index].real =
                AddQ(relation[index].real, plane.b[index].real,
                     plane.modulus);
            relation[index].imaginary =
                AddQ(relation[index].imaginary, plane.b[index].imaginary,
                     plane.modulus);
        }
        const auto auxiliary =
            evaluationKey.GetAuxiliaryModulus() % plane.modulus;
        for (const auto& term : source) {
            auto& coefficient =
                relation[CoefficientIndex(n, phi, term.x, term.y, term.w)];
            coefficient.real = SubQ(
                coefficient.real,
                MulQ(auxiliary, SignedToQ(term.real, plane.modulus),
                     plane.modulus),
                plane.modulus);
            coefficient.imaginary = SubQ(
                coefficient.imaginary,
                MulQ(auxiliary, SignedToQ(term.imaginary, plane.modulus),
                     plane.modulus),
                plane.modulus);
        }
        for (const auto& coefficient : relation) {
            for (const auto residue : {coefficient.real,
                                       coefficient.imaginary}) {
                const auto centered =
                    residue <= plane.modulus / 2
                        ? static_cast<int64_t>(residue)
                        : static_cast<int64_t>(residue) - plane.modulus;
                if (centered % t != 0 || centered < -t || centered > t) {
                    return false;
                }
            }
        }
    }
    return true;
}

bool GLIntProductionSwitchCore::VerifyAuxSwitchResultOwner(
    const GLIntProductionRNSPolynomial& input,
    const GLIntProductionSwitchResult& result,
    const GLIntProductionAuxSwitchKey& evaluationKey,
    const GLIntProductionSecretKey& primaryKey) const {
    ValidatePolynomial(input, "VerifyAuxSwitchResultOwner input");
    result.Validate();
    ValidatePolynomial(result.GetB(), "VerifyAuxSwitchResultOwner result b");
    ValidatePolynomial(result.GetA(), "VerifyAuxSwitchResultOwner result a");
    if (!VerifyAuxEvaluationKeyOwner(evaluationKey, primaryKey) ||
        result.GetDirection() != evaluationKey.GetDirection() ||
        result.GetDestinationKeyTag() != primaryKey.GetKeyTag() ||
        result.GetB().GetLevel() != 1 || result.GetA().GetLevel() != 1) {
        return false;
    }
    const auto modulus = m_moduli.front();
    auto actual = MultiplyDenseBySparse(
        result.GetA().GetPlanes().front().coefficients,
        PrimaryTerms(primaryKey), modulus);
    const auto& switchedB = result.GetB().GetPlanes().front().coefficients;
    for (std::size_t index = 0; index < actual.size(); ++index) {
        actual[index].real =
            AddQ(actual[index].real, switchedB[index].real, modulus);
        actual[index].imaginary = AddQ(
            actual[index].imaginary, switchedB[index].imaginary, modulus);
    }
    const auto expected = MultiplyDenseBySparse(
        input.GetPlanes().front().coefficients,
        SourceTerms(primaryKey, evaluationKey.GetDirection()), modulus);
    const auto t = static_cast<int64_t>(m_parameters.plaintextModulus);
    for (std::size_t index = 0; index < actual.size(); ++index) {
        for (const auto difference : {
                 SubQ(actual[index].real, expected[index].real, modulus),
                 SubQ(actual[index].imaginary, expected[index].imaginary,
                      modulus)}) {
            const auto centered =
                difference <= modulus / 2
                    ? static_cast<int64_t>(difference)
                    : static_cast<int64_t>(difference) - modulus;
            if (centered % t != 0) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace lbcrypto
