//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "scheme/gl/gl-int-production-rlwe.h"

#include "utils/hashutil.h"

#include <algorithm>
#include <limits>
#include <random>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>

namespace lbcrypto {
namespace {

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

uint64_t CanonicalT(int64_t value, uint64_t modulus) noexcept {
    const auto signedModulus = static_cast<int64_t>(modulus);
    const auto remainder     = value % signedModulus;
    return static_cast<uint64_t>(remainder < 0 ? remainder + signedModulus : remainder);
}

uint32_t SignedToQ(int64_t value, uint32_t modulus) noexcept {
    const auto signedModulus = static_cast<int64_t>(modulus);
    const auto remainder     = value % signedModulus;
    return static_cast<uint32_t>(remainder < 0 ? remainder + signedModulus : remainder);
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
            "production integer RLWE requires canonical GL-128-257-N32 "
            "with t=1579009");
    }
}

bool IsPrime32(uint32_t value) {
    if (value < 2 || value % 2 == 0) {
        return value == 2;
    }
    for (uint32_t divisor = 3;
         static_cast<uint64_t>(divisor) * divisor <= value; divisor += 2) {
        if (value % divisor == 0) {
            return false;
        }
    }
    return true;
}

uint32_t FindSplitPrime(uint32_t bits, uint32_t fourNp,
                        const std::vector<uint32_t>& taken) {
    const auto center = uint64_t{1} << bits;
    const auto lower  = uint64_t{1} << (bits - 1);
    const auto upper  = uint64_t{1} << (bits + 1);
    const auto k0     = center / fourNp;
    // Match GLScheme's authoritative N32 scan: below, then above 2^bits.
    for (uint64_t step = 0; step < (uint64_t{1} << 20); ++step) {
        for (uint32_t direction = 0; direction < 2; ++direction) {
            const auto multiplier =
                direction == 0 ? (k0 > step ? k0 - step : 0)
                               : k0 + step + 1;
            if (multiplier == 0) {
                continue;
            }
            const auto candidate64 = multiplier * fourNp + 1;
            if (candidate64 < lower || candidate64 >= upper ||
                candidate64 > std::numeric_limits<uint32_t>::max()) {
                continue;
            }
            const auto candidate = static_cast<uint32_t>(candidate64);
            if (std::find(taken.begin(), taken.end(), candidate) ==
                    taken.end() &&
                IsPrime32(candidate)) {
                return candidate;
            }
        }
    }
    throw GLIntParameterError(
        "production integer RLWE could not find its bounded N32 prime");
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

GLIntProductionModResidue MultiplyGaussian(
    const GLIntProductionModResidue& lhs, int8_t rhsReal,
    int8_t rhsImaginary, uint32_t modulus) noexcept {
    const auto real = SignedToQ(rhsReal, modulus);
    const auto imaginary = SignedToQ(rhsImaginary, modulus);
    return {
        SubQ(MulQ(lhs.real, real, modulus),
             MulQ(lhs.imaginary, imaginary, modulus), modulus),
        AddQ(MulQ(lhs.real, imaginary, modulus),
             MulQ(lhs.imaginary, real, modulus), modulus)};
}

void MultiplyByGaussianUnit(GLIntProductionModResidue* value,
                            uint32_t modulus) noexcept {
    const auto real = value->real;
    value->real = value->imaginary == 0 ? 0 : modulus - value->imaginary;
    value->imaginary = real;
}

void Accumulate(GLIntProductionModResidue* destination,
                const GLIntProductionModResidue& value,
                uint32_t modulus, bool positive) noexcept {
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

GLIntProductionSecretKey::GLIntProductionSecretKey(
    GLIntWBatchedParameters parameters, std::string keyTag,
    std::vector<Term> terms)
    : m_parameters(std::move(parameters)),
      m_keyTag(std::move(keyTag)),
      m_terms(std::move(terms)) {
    Validate();
}

const GLIntWBatchedParameters&
GLIntProductionSecretKey::GetParameters() const noexcept {
    return m_parameters;
}

const std::string& GLIntProductionSecretKey::GetKeyTag() const noexcept {
    return m_keyTag;
}

std::size_t GLIntProductionSecretKey::GetHammingWeight() const noexcept {
    return m_terms.size();
}

void GLIntProductionSecretKey::Validate() const {
    RequireProductionParameters(m_parameters);
    if (m_keyTag.empty() || m_terms.empty() ||
        m_terms.size() > kGLIntProductionMaxSecretTerms) {
        throw GLKeyMismatchError(
            "production integer secret key has an invalid tag or weight");
    }
    std::vector<std::pair<uint32_t, uint32_t>> positions;
    positions.reserve(m_terms.size());
    for (const auto& term : m_terms) {
        const auto magnitude = std::abs(static_cast<int>(term.real)) +
                               std::abs(static_cast<int>(term.imaginary));
        if (term.x >= m_parameters.dimension ||
            term.w >= m_parameters.cyclotomicPrime - 1 || magnitude != 1) {
            throw GLKeyMismatchError(
                "production integer secret key is not sparse ternary R material");
        }
        positions.emplace_back(term.x, term.w);
    }
    std::sort(positions.begin(), positions.end());
    if (std::adjacent_find(positions.begin(), positions.end()) !=
        positions.end()) {
        throw GLKeyMismatchError(
            "production integer secret key repeats a coefficient");
    }
}

GLIntProductionCiphertext::GLIntProductionCiphertext(
    GLIntWBatchedParameters parameters, GLIntWBatchedCodecRoots roots,
    std::string keyTag, uint32_t level, uint64_t plaintextScale,
    std::vector<GLIntProductionCiphertextPlane> planes)
    : m_parameters(std::move(parameters)),
      m_roots(std::move(roots)),
      m_keyTag(std::move(keyTag)),
      m_level(level),
      m_plaintextScale(plaintextScale),
      m_planes(std::move(planes)) {
    Validate();
}

const GLIntWBatchedParameters&
GLIntProductionCiphertext::GetParameters() const noexcept {
    return m_parameters;
}

const GLIntWBatchedCodecRoots&
GLIntProductionCiphertext::GetRoots() const noexcept {
    return m_roots;
}

const std::string& GLIntProductionCiphertext::GetKeyTag() const noexcept {
    return m_keyTag;
}

uint32_t GLIntProductionCiphertext::GetLevel() const noexcept {
    return m_level;
}

uint64_t GLIntProductionCiphertext::GetPlaintextScale() const noexcept {
    return m_plaintextScale;
}

const std::vector<GLIntProductionCiphertextPlane>&
GLIntProductionCiphertext::GetPlanes() const noexcept {
    return m_planes;
}

void GLIntProductionCiphertext::Validate() const {
    RequireProductionParameters(m_parameters);
    m_roots.Validate(m_parameters);
    if (m_keyTag.empty() || m_plaintextScale == 0 ||
        m_plaintextScale >= m_parameters.plaintextModulus || m_planes.empty() ||
        m_planes.size() > kGLIntProductionRLWEPlaneCount ||
        m_level + m_planes.size() != kGLIntProductionRLWEPlaneCount) {
        throw GLCiphertextError(
            "production integer ciphertext has invalid key/level/RNS metadata");
    }
    const auto expected = static_cast<std::size_t>(m_parameters.dimension) *
                          m_parameters.dimension *
                          (m_parameters.cyclotomicPrime - 1);
    std::vector<uint32_t> moduli;
    for (const auto& plane : m_planes) {
        if (!IsPrime32(plane.modulus) || plane.b.size() != expected ||
            plane.a.size() != expected) {
            throw GLCiphertextError(
                "production integer ciphertext plane has invalid shape/modulus");
        }
        for (const auto* component : {&plane.b, &plane.a}) {
            for (const auto& coefficient : *component) {
                if (coefficient.real >= plane.modulus ||
                    coefficient.imaginary >= plane.modulus) {
                    throw GLCiphertextError(
                        "production integer ciphertext residue is not canonical");
                }
            }
        }
        moduli.push_back(plane.modulus);
    }
    std::sort(moduli.begin(), moduli.end());
    if (std::adjacent_find(moduli.begin(), moduli.end()) != moduli.end()) {
        throw GLCiphertextError(
            "production integer ciphertext repeats an RNS modulus");
    }
}

GLIntProductionRLWECore::GLIntProductionRLWECore(
    GLIntWBatchedParameters parameters)
    : m_parameters(std::move(parameters)) {
    RequireProductionParameters(m_parameters);
    const GLIntProductionCore codec(m_parameters);
    m_roots = codec.GetRoots();
    const auto fourNp = static_cast<uint32_t>(
        4 * m_parameters.dimension * m_parameters.cyclotomicPrime);
    m_moduli.push_back(FindSplitPrime(30, fourNp, m_moduli));
    m_moduli.push_back(FindSplitPrime(27, fourNp, m_moduli));
    for (const auto modulus : m_moduli) {
        if (modulus <= 4 * m_parameters.plaintextModulus ||
            (modulus - 1) % fourNp != 0) {
            throw GLIntParameterError(
                "production integer RLWE bounded modulus is incompatible");
        }
    }
}

const GLIntWBatchedParameters&
GLIntProductionRLWECore::GetParameters() const noexcept {
    return m_parameters;
}

const GLIntWBatchedCodecRoots&
GLIntProductionRLWECore::GetRoots() const noexcept {
    return m_roots;
}

const std::vector<uint32_t>& GLIntProductionRLWECore::GetModuli() const noexcept {
    return m_moduli;
}

GLIntProductionRLWECapabilities
GLIntProductionRLWECore::GetCapabilities() const noexcept {
    return {};
}

GLIntProductionSecretKey GLIntProductionRLWECore::KeyGen(
    std::size_t hammingWeight, uint64_t seed) const {
    if (hammingWeight == 0 || hammingWeight > kGLIntProductionMaxSecretTerms) {
        throw GLKeyMismatchError(
            "production integer KeyGen hamming weight is outside its bound");
    }
    const auto resolvedSeed = ResolveSeed(seed);
    SplitMix64 rng(resolvedSeed);
    std::vector<GLIntProductionSecretKey::Term> terms;
    while (terms.size() < hammingWeight) {
        GLIntProductionSecretKey::Term term;
        term.x = static_cast<uint32_t>(rng.Next() % m_parameters.dimension);
        // Keep every bounded key genuinely W-dependent.
        term.w = 1 + static_cast<uint32_t>(
                         rng.Next() % (m_parameters.cyclotomicPrime - 2));
        const auto orientation = static_cast<uint32_t>(rng.Next() % 4);
        term.real = orientation < 2 ? (orientation == 0 ? 1 : -1) : 0;
        term.imaginary =
            orientation >= 2 ? (orientation == 2 ? 1 : -1) : 0;
        const auto duplicate = std::any_of(
            terms.begin(), terms.end(), [&](const auto& existing) {
                return existing.x == term.x && existing.w == term.w;
            });
        if (!duplicate) {
            terms.push_back(term);
        }
    }
    std::sort(terms.begin(), terms.end(), [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.x, lhs.w) < std::tie(rhs.x, rhs.w);
    });
    std::ostringstream binding;
    binding << "GL-128-257-N32:t=1579009:seed=" << resolvedSeed << ":";
    for (const auto& term : terms) {
        binding << term.x << ',' << term.w << ',' << static_cast<int>(term.real)
                << ',' << static_cast<int>(term.imaginary) << ';';
    }
    return GLIntProductionSecretKey(
        m_parameters, HashUtil::HashString(binding.str()), std::move(terms));
}

void GLIntProductionRLWECore::ValidateKey(
    const GLIntProductionSecretKey& key, const char* operation) const {
    key.Validate();
    if (!SameParameters(m_parameters, key.GetParameters())) {
        throw GLKeyContextMismatchError(std::string(operation) +
                                        " key parameters do not match");
    }
}

void GLIntProductionRLWECore::ValidatePlaintext(
    const GLIntProductionEncodedPlaintext& plaintext,
    const char* objectName) const {
    plaintext.Validate();
    if (!SameParameters(m_parameters, plaintext.GetParameters()) ||
        plaintext.GetRoots() != m_roots) {
        throw GLContextMismatchError(std::string(objectName) +
                                     " codec binding does not match");
    }
}

void GLIntProductionRLWECore::ValidateCiphertext(
    const GLIntProductionCiphertext& ciphertext,
    const char* objectName) const {
    ciphertext.Validate();
    if (!SameParameters(m_parameters, ciphertext.GetParameters()) ||
        ciphertext.GetRoots() != m_roots) {
        throw GLContextMismatchError(std::string(objectName) +
                                     " context binding does not match");
    }
    const auto active = m_moduli.size() - ciphertext.GetLevel();
    if (ciphertext.GetPlanes().size() != active) {
        throw GLCiphertextError(std::string(objectName) +
                                " active plane count is inconsistent");
    }
    for (std::size_t index = 0; index < active; ++index) {
        if (ciphertext.GetPlanes()[index].modulus != m_moduli[index]) {
            throw GLContextMismatchError(std::string(objectName) +
                                         " modulus prefix does not match");
        }
    }
}

void GLIntProductionRLWECore::ValidateOperands(
    const GLIntProductionCiphertext& lhs,
    const GLIntProductionCiphertext& rhs, const char* operation) const {
    ValidateCiphertext(lhs, "left production integer ciphertext");
    ValidateCiphertext(rhs, "right production integer ciphertext");
    if (lhs.GetLevel() != rhs.GetLevel()) {
        throw GLCiphertextError(std::string(operation) +
                                " requires equal RNS levels");
    }
    if (lhs.GetPlaintextScale() != rhs.GetPlaintextScale()) {
        throw GLCiphertextError(std::string(operation) +
                                " requires equal plaintext scales");
    }
    if (lhs.GetKeyTag() != rhs.GetKeyTag()) {
        throw GLKeyMismatchError(std::string(operation) +
                                 " requires one destination key");
    }
}

std::vector<GLIntProductionModResidue>
GLIntProductionRLWECore::MultiplyBySecret(
    const std::vector<GLIntProductionModResidue>& polynomial,
    const GLIntProductionSecretKey& secretKey, uint32_t modulus) const {
    const auto n   = static_cast<std::size_t>(m_parameters.dimension);
    const auto p   = static_cast<std::size_t>(m_parameters.cyclotomicPrime);
    const auto phi = p - 1;
    const auto expected = n * n * phi;
    if (polynomial.size() != expected) {
        throw GLCiphertextError(
            "production integer secret product has the wrong R'_q shape");
    }
    std::vector<GLIntProductionModResidue> output(expected);
    for (const auto& term : secretKey.m_terms) {
        for (std::size_t x = 0; x < n; ++x) {
            const auto xDegree = x + term.x;
            const auto targetX = xDegree % n;
            const bool xWrap   = xDegree >= n;
            for (std::size_t y = 0; y < n; ++y) {
                for (std::size_t w = 0; w < phi; ++w) {
                    auto product = MultiplyGaussian(
                        polynomial[CoefficientIndex(n, phi, x, y, w)],
                        term.real, term.imaginary, modulus);
                    if (xWrap) {
                        MultiplyByGaussianUnit(&product, modulus);
                    }
                    auto wDegree = w + term.w;
                    if (wDegree >= p) {
                        wDegree -= p;
                    }
                    if (wDegree < phi) {
                        Accumulate(
                            &output[CoefficientIndex(n, phi, targetX, y,
                                                     wDegree)],
                            product, modulus, true);
                    }
                    else {
                        // W^(p-1) = -(1+W+...+W^(p-2)) modulo Phi_p.
                        for (std::size_t targetW = 0; targetW < phi;
                             ++targetW) {
                            Accumulate(
                                &output[CoefficientIndex(n, phi, targetX, y,
                                                         targetW)],
                                product, modulus, false);
                        }
                    }
                }
            }
        }
    }
    return output;
}

GLIntProductionCiphertext GLIntProductionRLWECore::Encrypt(
    const GLIntProductionSecretKey& secretKey,
    const GLIntProductionEncodedPlaintext& plaintext, uint64_t seed) const {
    ValidateKey(secretKey, "production integer Encrypt");
    ValidatePlaintext(plaintext, "production integer plaintext");
    const auto resolvedSeed = ResolveSeed(seed);
    SplitMix64 rng(resolvedSeed);
    const auto coefficientCount = plaintext.GetCoefficients().size();
    std::vector<int8_t> errorReal(coefficientCount);
    std::vector<int8_t> errorImaginary(coefficientCount);
    for (std::size_t index = 0; index < coefficientCount; ++index) {
        errorReal[index] = static_cast<int8_t>(rng.Next() % 3) - 1;
        errorImaginary[index] = static_cast<int8_t>(rng.Next() % 3) - 1;
    }

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
        auto secretProduct = MultiplyBySecret(plane.a, secretKey, modulus);
        plane.b.resize(coefficientCount);
        for (std::size_t index = 0; index < coefficientCount; ++index) {
            const auto& message = plaintext.GetCoefficients()[index];
            const auto messageReal = static_cast<uint32_t>(message.real);
            const auto messageImaginary =
                static_cast<uint32_t>(message.imaginary);
            const auto noiseReal = SignedToQ(
                static_cast<int64_t>(m_parameters.plaintextModulus) *
                    errorReal[index],
                modulus);
            const auto noiseImaginary = SignedToQ(
                static_cast<int64_t>(m_parameters.plaintextModulus) *
                    errorImaginary[index],
                modulus);
            plane.b[index].real = SubQ(
                AddQ(messageReal, noiseReal, modulus),
                secretProduct[index].real, modulus);
            plane.b[index].imaginary = SubQ(
                AddQ(messageImaginary, noiseImaginary, modulus),
                secretProduct[index].imaginary, modulus);
        }
        planes.push_back(std::move(plane));
    }
    return GLIntProductionCiphertext(
        m_parameters, m_roots, secretKey.GetKeyTag(), 0, 1,
        std::move(planes));
}

GLIntProductionEncodedPlaintext GLIntProductionRLWECore::Decrypt(
    const GLIntProductionSecretKey& secretKey,
    const GLIntProductionCiphertext& ciphertext) const {
    ValidateKey(secretKey, "production integer Decrypt");
    ValidateCiphertext(ciphertext, "production integer ciphertext");
    if (secretKey.GetKeyTag() != ciphertext.GetKeyTag()) {
        throw GLKeyMismatchError(
            "production integer Decrypt key tag does not match ciphertext");
    }
    const auto coefficientCount = ciphertext.GetPlanes().front().b.size();
    const auto t = static_cast<uint32_t>(m_parameters.plaintextModulus);
    const auto inverseScale = PowQ(
        static_cast<uint32_t>(ciphertext.GetPlaintextScale()), t - 2, t);
    std::vector<GLIntGaussianResidue> decoded(coefficientCount);
    bool firstPlane = true;
    for (const auto& plane : ciphertext.GetPlanes()) {
        const auto secretProduct =
            MultiplyBySecret(plane.a, secretKey, plane.modulus);
        for (std::size_t index = 0; index < coefficientCount; ++index) {
            const auto realResidue = AddQ(plane.b[index].real,
                                          secretProduct[index].real,
                                          plane.modulus);
            const auto imaginaryResidue = AddQ(
                plane.b[index].imaginary,
                secretProduct[index].imaginary, plane.modulus);
            const auto centeredReal =
                realResidue <= plane.modulus / 2
                    ? static_cast<int64_t>(realResidue)
                    : static_cast<int64_t>(realResidue) - plane.modulus;
            const auto centeredImaginary =
                imaginaryResidue <= plane.modulus / 2
                    ? static_cast<int64_t>(imaginaryResidue)
                    : static_cast<int64_t>(imaginaryResidue) - plane.modulus;
            const GLIntGaussianResidue coefficient{
                static_cast<int64_t>(MulQ(
                    static_cast<uint32_t>(CanonicalT(centeredReal, t)),
                    inverseScale, t)),
                static_cast<int64_t>(MulQ(
                    static_cast<uint32_t>(CanonicalT(centeredImaginary, t)),
                    inverseScale, t))};
            if (firstPlane) {
                decoded[index] = coefficient;
            }
            else if (!(decoded[index] == coefficient)) {
                throw GLCiphertextError(
                    "production integer RNS planes disagree during decryption");
            }
        }
        firstPlane = false;
    }
    return GLIntProductionEncodedPlaintext(m_parameters, m_roots,
                                            std::move(decoded));
}

GLIntProductionCiphertext GLIntProductionRLWECore::Add(
    const GLIntProductionCiphertext& lhs,
    const GLIntProductionCiphertext& rhs) const {
    ValidateOperands(lhs, rhs, "production integer Add");
    auto planes = lhs.GetPlanes();
    for (std::size_t planeIndex = 0; planeIndex < planes.size(); ++planeIndex) {
        auto& output = planes[planeIndex];
        const auto& right = rhs.GetPlanes()[planeIndex];
        for (std::size_t index = 0; index < output.b.size(); ++index) {
            output.b[index].real =
                AddQ(output.b[index].real, right.b[index].real, output.modulus);
            output.b[index].imaginary = AddQ(output.b[index].imaginary,
                                              right.b[index].imaginary,
                                              output.modulus);
            output.a[index].real =
                AddQ(output.a[index].real, right.a[index].real, output.modulus);
            output.a[index].imaginary = AddQ(output.a[index].imaginary,
                                              right.a[index].imaginary,
                                              output.modulus);
        }
    }
    return GLIntProductionCiphertext(m_parameters, m_roots, lhs.GetKeyTag(),
                                     lhs.GetLevel(), lhs.GetPlaintextScale(),
                                     std::move(planes));
}

GLIntProductionCiphertext GLIntProductionRLWECore::Subtract(
    const GLIntProductionCiphertext& lhs,
    const GLIntProductionCiphertext& rhs) const {
    ValidateOperands(lhs, rhs, "production integer Subtract");
    auto planes = lhs.GetPlanes();
    for (std::size_t planeIndex = 0; planeIndex < planes.size(); ++planeIndex) {
        auto& output = planes[planeIndex];
        const auto& right = rhs.GetPlanes()[planeIndex];
        for (std::size_t index = 0; index < output.b.size(); ++index) {
            output.b[index].real =
                SubQ(output.b[index].real, right.b[index].real, output.modulus);
            output.b[index].imaginary = SubQ(output.b[index].imaginary,
                                              right.b[index].imaginary,
                                              output.modulus);
            output.a[index].real =
                SubQ(output.a[index].real, right.a[index].real, output.modulus);
            output.a[index].imaginary = SubQ(output.a[index].imaginary,
                                              right.a[index].imaginary,
                                              output.modulus);
        }
    }
    return GLIntProductionCiphertext(m_parameters, m_roots, lhs.GetKeyTag(),
                                     lhs.GetLevel(), lhs.GetPlaintextScale(),
                                     std::move(planes));
}

GLIntProductionCiphertext GLIntProductionRLWECore::Negate(
    const GLIntProductionCiphertext& ciphertext) const {
    ValidateCiphertext(ciphertext, "production integer ciphertext");
    auto planes = ciphertext.GetPlanes();
    for (auto& plane : planes) {
        for (auto* component : {&plane.b, &plane.a}) {
            for (auto& coefficient : *component) {
                coefficient.real = coefficient.real == 0
                                       ? 0
                                       : plane.modulus - coefficient.real;
                coefficient.imaginary = coefficient.imaginary == 0
                                            ? 0
                                            : plane.modulus -
                                                  coefficient.imaginary;
            }
        }
    }
    return GLIntProductionCiphertext(
        m_parameters, m_roots, ciphertext.GetKeyTag(), ciphertext.GetLevel(),
        ciphertext.GetPlaintextScale(), std::move(planes));
}

GLIntProductionCiphertext GLIntProductionRLWECore::ModSwitchDrop(
    GLIntProductionCiphertext ciphertext) const {
    ValidateCiphertext(ciphertext, "production integer ciphertext");
    if (ciphertext.m_planes.size() <= 1) {
        throw GLDepthError(
            "production integer bounded modulus-drop chain is exhausted");
    }
    const auto droppedModulus = ciphertext.m_planes.back().modulus;
    const auto t = static_cast<uint32_t>(m_parameters.plaintextModulus);
    const auto negTInverse = droppedModulus -
                             PowQ(t % droppedModulus,
                                  droppedModulus - 2, droppedModulus);
    for (std::size_t planeIndex = 0;
         planeIndex + 1 < ciphertext.m_planes.size(); ++planeIndex) {
        auto& surviving = ciphertext.m_planes[planeIndex];
        const auto dropInverse = PowQ(
            droppedModulus % surviving.modulus,
            surviving.modulus - 2, surviving.modulus);
        const auto& dropped = ciphertext.m_planes.back();
        for (const auto& components : {std::pair{&surviving.b, &dropped.b},
                                       std::pair{&surviving.a, &dropped.a}}) {
            for (std::size_t index = 0; index < components.first->size();
                 ++index) {
                auto reduce = [&](uint32_t survivorValue,
                                  uint32_t droppedValue) {
                    const auto deltaResidue = MulQ(
                        droppedValue, negTInverse, droppedModulus);
                    const auto centeredDelta =
                        deltaResidue <= droppedModulus / 2
                            ? static_cast<int64_t>(deltaResidue)
                            : static_cast<int64_t>(deltaResidue) -
                                  droppedModulus;
                    const auto delta =
                        SignedToQ(centeredDelta, surviving.modulus);
                    return MulQ(
                        AddQ(survivorValue,
                             MulQ(t % surviving.modulus, delta,
                                  surviving.modulus),
                             surviving.modulus),
                        dropInverse, surviving.modulus);
                };
                auto& survivor = (*components.first)[index];
                const auto& drop = (*components.second)[index];
                survivor.real = reduce(survivor.real, drop.real);
                survivor.imaginary =
                    reduce(survivor.imaginary, drop.imaginary);
            }
        }
    }
    ciphertext.m_plaintextScale = MulQ(
        static_cast<uint32_t>(ciphertext.m_plaintextScale),
        PowQ(droppedModulus % t, t - 2, t), t);
    ciphertext.m_planes.pop_back();
    ++ciphertext.m_level;
    ciphertext.Validate();
    return ciphertext;
}

}  // namespace lbcrypto
