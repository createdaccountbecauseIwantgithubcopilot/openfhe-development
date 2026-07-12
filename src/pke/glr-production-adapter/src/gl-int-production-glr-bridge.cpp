//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "openfhe/pke/gl-int-production-glr-bridge.h"

#include "utils/hashutil.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {
namespace {

using glscheme::rns::GlrDomain;
using glscheme::rns::GlrError;
using glscheme::rns::GlrPoly;
using glscheme::rns::GlrRing;

struct GlrRngDeleter {
    void operator()(glscheme::rns::GlrRng* rng) const noexcept {
        if (rng != nullptr) {
            glscheme::rns::glr_rng_destroy(rng);
        }
    }
};

using GlrRngOwner =
    std::unique_ptr<glscheme::rns::GlrRng, GlrRngDeleter>;

struct PolyWipe {
    explicit PolyWipe(GlrPoly& poly) : value(poly) {}
    ~PolyWipe() {
        value.secure_clear();
    }
    GlrPoly& value;
};

constexpr const char* kBootstrapRejection =
    "BootstrapDirect rejected: integer Q2/L23 is not the required randomized "
    "Q7/L18 primary Slot input, and no exact BGV m+t*e lift/SHIP mod-t "
    "correctness theorem is bound";
constexpr const char* kSecurityRejection =
    "production security rejected: the source uses a support-revealing Q2 "
    "ciphertext and sparse h<=4 Gaussian secret, not the admitted dense "
    "primary plus independently certified h40 bootstrap lineage";
constexpr const char* kUntrustedIntegerKeyDomain = "integer-q2-untrusted";

std::size_t CoefficientIndex(std::size_t n, std::size_t phi, std::size_t x,
                             std::size_t y, std::size_t w) noexcept {
    return (x * n + y) * phi + w;
}

std::uint64_t CanonicalCrt(std::uint32_t r0, std::uint32_t r1,
                           std::uint32_t q0, std::uint32_t q1) {
    const auto r0ModQ1 = static_cast<std::uint64_t>(r0) % q1;
    const auto difference =
        r1 >= r0ModQ1 ? static_cast<std::uint64_t>(r1) - r0ModQ1
                      : static_cast<std::uint64_t>(q1) - (r0ModQ1 - r1);
    const auto correction = glscheme::rns::glr_mulmod(
        difference, glscheme::rns::glr_invmod(q0 % q1, q1), q1);
    return static_cast<std::uint64_t>(r0) +
           static_cast<std::uint64_t>(q0) * correction;
}

std::int64_t CenteredCrt(std::uint32_t r0, std::uint32_t r1,
                         std::uint32_t q0, std::uint32_t q1) {
    const auto value = CanonicalCrt(r0, r1, q0, q1);
    const auto modulus = static_cast<std::uint64_t>(q0) * q1;
    if (modulus > static_cast<std::uint64_t>(
                      std::numeric_limits<std::int64_t>::max())) {
        throw GlrError("GL integer Q2 CRT product exceeds int64");
    }
    return value <= modulus / 2
               ? static_cast<std::int64_t>(value)
               : -static_cast<std::int64_t>(modulus - value);
}

std::uint64_t RequireIntegerScale(double scale, std::uint64_t t) {
    if (!std::isfinite(scale) || scale < 1.0 || scale >= t ||
        std::floor(scale) != scale) {
        throw GLContextMismatchError(
            "GL integer bridge requires an exact integral plaintext scale");
    }
    return static_cast<std::uint64_t>(scale);
}

GLIntProductionModResidue GaussianResidueAt(
    const glscheme::rns::GlrContext& context, const GlrPoly& poly,
    std::uint32_t prime, std::uint32_t x, std::uint32_t y,
    std::uint32_t w) {
    const auto& modulus = context.params.q_chain[prime];
    const auto flat =
        (static_cast<std::size_t>(w) * context.n() + x) * context.n() + y;
    const auto plus = poly.lane_ptr(context, prime, 0)[flat];
    const auto minus = poly.lane_ptr(context, prime, 1)[flat];
    const auto sum = plus + minus >= modulus.q
                         ? plus + minus - modulus.q
                         : plus + minus;
    const auto difference =
        plus >= minus ? plus - minus : modulus.q - (minus - plus);
    return {
        static_cast<std::uint32_t>(glscheme::rns::glr_mulmod(
            sum, modulus.two_inv, modulus.q)),
        static_cast<std::uint32_t>(glscheme::rns::glr_mulmod(
            difference,
            glscheme::rns::glr_mulmod(modulus.two_inv, modulus.u_inv,
                                      modulus.q),
            modulus.q))};
}

std::pair<std::uint64_t, std::uint64_t> GaussianAtFlat(
    const glscheme::rns::GlrContext& context, const GlrPoly& poly,
    std::uint32_t plane, const glscheme::rns::GlrModulus& modulus,
    std::size_t flat) {
    const auto plus = poly.lane_ptr(context, plane, 0)[flat];
    const auto minus = poly.lane_ptr(context, plane, 1)[flat];
    const auto sum = plus + minus >= modulus.q
                         ? plus + minus - modulus.q
                         : plus + minus;
    const auto difference =
        plus >= minus ? plus - minus : modulus.q - (minus - plus);
    return {
        glscheme::rns::glr_mulmod(sum, modulus.two_inv, modulus.q),
        glscheme::rns::glr_mulmod(
            difference,
            glscheme::rns::glr_mulmod(modulus.two_inv, modulus.u_inv,
                                      modulus.q),
            modulus.q)};
}

std::uint64_t SignedMod(__int128 value, std::uint64_t modulus) noexcept {
    const auto remainder = value % static_cast<__int128>(modulus);
    return static_cast<std::uint64_t>(
        remainder < 0 ? remainder + modulus : remainder);
}

void SetGaussianAtFlat(const glscheme::rns::GlrContext& context,
                       GlrPoly* poly, std::uint32_t plane,
                       const glscheme::rns::GlrModulus& modulus,
                       std::size_t flat, __int128 real,
                       __int128 imaginary) {
    const auto re = SignedMod(real, modulus.q);
    const auto im = SignedMod(imaginary, modulus.q);
    const auto uim = glscheme::rns::glr_mulmod(modulus.u, im, modulus.q);
    poly->lane_ptr(context, plane, 0)[flat] =
        re + uim >= modulus.q ? re + uim - modulus.q : re + uim;
    poly->lane_ptr(context, plane, 1)[flat] =
        re >= uim ? re - uim : modulus.q - (uim - re);
}

std::int64_t CenterResidue(std::uint64_t value,
                           std::uint64_t modulus) noexcept {
    return value <= modulus / 2
               ? static_cast<std::int64_t>(value)
               : -static_cast<std::int64_t>(modulus - value);
}

std::int64_t ReduceModT(__int128 value, std::int64_t t) noexcept {
    const auto remainder = value % t;
    return static_cast<std::int64_t>(remainder < 0 ? remainder + t
                                                   : remainder);
}

bool IsSha256Text(const std::string& value) {
    if (value.size() != 71 || value.rfind("sha256:", 0) != 0) {
        return false;
    }
    for (auto it = value.begin() + 7; it != value.end(); ++it) {
        if (!((*it >= '0' && *it <= '9') ||
              (*it >= 'a' && *it <= 'f'))) {
            return false;
        }
    }
    return true;
}

std::string DomainSeparatedIntegerLineage(
    const std::string& parameterFingerprint, const std::string& integerKeyTag,
    const std::string& primaryLineageCommitment) {
    const auto payload =
        std::string("openfhe.gl_int.q2_untrusted_lineage.v1|") +
        parameterFingerprint + '|' + integerKeyTag + '|' +
        primaryLineageCommitment;
    return "sha256:" + HashUtil::HashString(payload);
}

}  // namespace

GLIntProductionGLRBridge::OwnerBinding::OwnerBinding(
    NativeSecretKey secret, Receipt receipt,
    std::string primaryLineageCommitment)
    : m_secret(std::move(secret)),
      m_receipt(std::move(receipt)),
      m_primaryLineageCommitment(std::move(primaryLineageCommitment)) {}

GLIntProductionGLRBridge::OwnerBinding::~OwnerBinding() {
    m_secret.secure_clear();
}

const GLIntProductionGLRBridge::NativeSecretKey&
GLIntProductionGLRBridge::OwnerBinding::GetNativeSecretKey() const noexcept {
    return m_secret;
}

const GLIntProductionGLRBridge::Receipt&
GLIntProductionGLRBridge::OwnerBinding::GetReceipt() const noexcept {
    return m_receipt;
}

GLIntProductionGLRBridge::IntegerAutomorphismKey::IntegerAutomorphismKey(
    IntegerAutomorphism operation, std::int32_t amount,
    glscheme::rns::GlrRing ring, glscheme::rns::GlrPoly b,
    glscheme::rns::GlrPoly a, std::string parameterFingerprint,
    std::string nativeKeyLineageCommitment)
    : m_operation(operation),
      m_amount(amount),
      m_ring(ring),
      m_b(std::move(b)),
      m_a(std::move(a)),
      m_parameterFingerprint(std::move(parameterFingerprint)),
      m_nativeKeyLineageCommitment(
          std::move(nativeKeyLineageCommitment)) {}

GLIntProductionGLRBridge::IntegerAutomorphism
GLIntProductionGLRBridge::IntegerAutomorphismKey::GetOperation() const noexcept {
    return m_operation;
}

std::int32_t
GLIntProductionGLRBridge::IntegerAutomorphismKey::GetAmount() const noexcept {
    return m_amount;
}

std::uint32_t
GLIntProductionGLRBridge::IntegerAutomorphismKey::GetKeyLevel() const noexcept {
    return m_b.level;
}

std::uint32_t
GLIntProductionGLRBridge::IntegerAutomorphismKey::GetSpecialPrimeCount() const noexcept {
    return m_b.special_prime_count;
}

const std::string& GLIntProductionGLRBridge::IntegerAutomorphismKey::
    GetNativeKeyLineageCommitment() const noexcept {
    return m_nativeKeyLineageCommitment;
}

bool GLIntProductionGLRBridge::IntegerAutomorphismKey::UsesTErrors() const noexcept {
    return true;
}

bool GLIntProductionGLRBridge::IntegerAutomorphismKey::IsSecurityAuthorized() const noexcept {
    return false;
}

GLIntProductionGLRBridge::GLIntProductionGLRBridge(
    const GLRProductionAdapter& adapter)
    : m_adapter(&adapter) {
    const auto& context = m_adapter->GetContext();
    const auto profile = m_adapter->GetCanonicalProfileReceipt();
    const GLIntProductionRLWECore integerCore;
    const auto& integerModuli = integerCore.GetModuli();
    if (context.n() != 128 || context.p_() != 257 || context.phi() != 256 ||
        context.params.levels() < 2 || integerModuli.size() != 2 ||
        profile.profile_name != "GL-128-257-N32") {
        throw GlrError("GL integer bridge requires canonical GL-128-257-N32");
    }
    m_q2Level = context.params.levels() - 2;
    m_q0 = static_cast<std::uint32_t>(context.params.q_chain[0].q);
    m_q1 = static_cast<std::uint32_t>(context.params.q_chain[1].q);
    if (integerModuli[0] != m_q0 || integerModuli[1] != m_q1 ||
        context.active_q_primes(m_q2Level) != 2) {
        throw GlrError(
            "GL integer and native GLR Q2 prefixes are not byte-compatible");
    }
}

GLIntProductionGLRBridge::Capabilities
GLIntProductionGLRBridge::GetCapabilities() const noexcept {
    return {};
}

std::uint32_t GLIntProductionGLRBridge::GetNativeQ2Level() const noexcept {
    return m_q2Level;
}

GlrPoly GLIntProductionGLRBridge::RestrictToQ2P1(
    const GlrPoly& full) const {
    const auto& context = m_adapter->GetContext();
    if (full.domain != GlrDomain::Coeff || full.level != 0 ||
        !full.extended ||
        full.active_special_prime_count(context) !=
            context.params.p_special.size()) {
        throw GLContextMismatchError(
            "integer hybrid KSK requires a full-QP coefficient source");
    }
    GlrPoly out = GlrPoly::zero(context, full.ring, m_q2Level, true,
                                GlrDomain::Coeff, 1);
    const auto coefficients = full.ring_coeffs(context);
    for (std::uint32_t lane = 0; lane < 2; ++lane) {
        for (std::uint32_t q = 0; q < 2; ++q) {
            const auto* source = full.lane_ptr(context, q, lane);
            std::copy(source, source + coefficients,
                      out.lane_ptr(context, q, lane));
        }
        const auto* source = full.lane_ptr(
            context, context.params.levels(), lane);
        std::copy(source, source + coefficients,
                  out.lane_ptr(context, 2, lane));
    }
    return out;
}

GlrPoly GLIntProductionGLRBridge::ModUpQ2P1(
    const GlrPoly& input) const {
    const auto& context = m_adapter->GetContext();
    if (input.domain != GlrDomain::Coeff || input.level != m_q2Level ||
        input.extended || input.prime_count(context) != 2) {
        throw GLContextMismatchError(
            "integer hybrid ModUp requires a Q2/L23 coefficient polynomial");
    }
    GlrPoly out = GlrPoly::zero(context, input.ring, m_q2Level, true,
                                GlrDomain::Coeff, 1);
    const auto coefficients = input.ring_coeffs(context);
    for (std::uint32_t lane = 0; lane < 2; ++lane) {
        for (std::uint32_t q = 0; q < 2; ++q) {
            const auto* source = input.lane_ptr(context, q, lane);
            std::copy(source, source + coefficients,
                      out.lane_ptr(context, q, lane));
        }
    }
    const auto& q0 = context.params.q_chain[0];
    const auto& q1 = context.params.q_chain[1];
    const auto& special = context.params.p_special[0];
    for (std::size_t flat = 0; flat < coefficients; ++flat) {
        const auto r0 = GaussianAtFlat(context, input, 0, q0, flat);
        const auto r1 = GaussianAtFlat(context, input, 1, q1, flat);
        SetGaussianAtFlat(
            context, &out, 2, special, flat,
            CenteredCrt(static_cast<std::uint32_t>(r0.first),
                        static_cast<std::uint32_t>(r1.first), m_q0, m_q1),
            CenteredCrt(static_cast<std::uint32_t>(r0.second),
                        static_cast<std::uint32_t>(r1.second), m_q0, m_q1));
    }
    return out;
}

GlrPoly GLIntProductionGLRBridge::BGVModDownP1(
    const GlrPoly& input) const {
    const auto& context = m_adapter->GetContext();
    if (input.domain != GlrDomain::Coeff || input.level != m_q2Level ||
        !input.extended || input.active_special_prime_count(context) != 1 ||
        input.prime_count(context) != 3) {
        throw GLContextMismatchError(
            "integer hybrid ModDown requires a Q2P1/L23 coefficient polynomial");
    }
    GlrPoly out = GlrPoly::zero(context, input.ring, m_q2Level, false,
                                GlrDomain::Coeff);
    const auto coefficients = input.ring_coeffs(context);
    const auto& special = context.params.p_special[0];
    constexpr std::uint64_t t = 1579009;
    const auto tInverse =
        glscheme::rns::glr_invmod(t % special.q, special.q);
    const std::array<std::uint64_t, 2> inverseSpecial{
        glscheme::rns::glr_invmod(
            special.q % context.params.q_chain[0].q,
            context.params.q_chain[0].q),
        glscheme::rns::glr_invmod(
            special.q % context.params.q_chain[1].q,
            context.params.q_chain[1].q)};
    for (std::size_t flat = 0; flat < coefficients; ++flat) {
        const auto dropped = GaussianAtFlat(context, input, 2, special, flat);
        const auto deltaFor = [&](std::uint64_t value) {
            const auto product =
                glscheme::rns::glr_mulmod(value, tInverse, special.q);
            const auto residue = product == 0 ? 0 : special.q - product;
            return CenterResidue(residue, special.q);
        };
        const auto deltaReal = deltaFor(dropped.first);
        const auto deltaImaginary = deltaFor(dropped.second);
        for (std::uint32_t qIndex = 0; qIndex < 2; ++qIndex) {
            const auto& modulus = context.params.q_chain[qIndex];
            const auto current =
                GaussianAtFlat(context, input, qIndex, modulus, flat);
            const auto reduce = [&](std::uint64_t value,
                                    std::int64_t delta) {
                const auto correction = glscheme::rns::glr_mulmod(
                    t % modulus.q, SignedMod(delta, modulus.q), modulus.q);
                const auto numerator =
                    value + correction >= modulus.q
                        ? value + correction - modulus.q
                        : value + correction;
                return glscheme::rns::glr_mulmod(
                    numerator, inverseSpecial[qIndex], modulus.q);
            };
            SetGaussianAtFlat(
                context, &out, qIndex, modulus, flat,
                reduce(current.first, deltaReal),
                reduce(current.second, deltaImaginary));
        }
    }
    return out;
}

GLIntProductionGLRBridge::Receipt GLIntProductionGLRBridge::MakeReceipt(
    std::string representation) const {
    Receipt receipt;
    receipt.parameterFingerprint = glscheme::rns::glr_parameter_fingerprint(
        m_adapter->GetContext().params);
    receipt.representation = std::move(representation);
    receipt.admissionRejection = kBootstrapRejection;
    receipt.plaintextModulus = 1579009;
    receipt.nativeLevel = m_q2Level;
    receipt.activeQPrimes = 2;
    receipt.exactModuloT = true;
    return receipt;
}

GLIntProductionGLRBridge::OwnerBinding
GLIntProductionGLRBridge::ImportOwnerSecret(
    const GLIntProductionSecretKey& secretKey) const {
    secretKey.Validate();
    if (!secretKey.GetParameters().IsGL128257N32Geometry() ||
        secretKey.GetParameters().plaintextModulus != 1579009) {
        throw GLKeyContextMismatchError(
            "GL integer owner-secret bridge parameter mismatch");
    }
    const auto& context = m_adapter->GetContext();
    NativeSecretKey native;
    native.s = GlrPoly::zero(context, GlrRing::R, 0, true,
                             GlrDomain::Coeff);
    native.key_id = "primary";
    for (const auto& term : secretKey.m_terms) {
        glscheme::rns::glr_poly_set_gaussian(
            context, native.s, term.x, 0, term.w, term.real,
            term.imaginary);
    }
    auto receipt = MakeReceipt("owner-secret-full-QP-coefficient");
    receipt.integerKeyTag = secretKey.GetKeyTag();
    const auto primaryLineageCommitment =
        glscheme::rns::glr_ship_direct_primary_secret_lineage_commitment(
            context, native);
    if (!IsSha256Text(primaryLineageCommitment)) {
        native.secure_clear();
        throw GLKeyContextMismatchError(
            "GL integer owner-secret bridge failed primary hash derivation");
    }
    native.key_id = kUntrustedIntegerKeyDomain;
    receipt.nativeKeyLineageCommitment = DomainSeparatedIntegerLineage(
        receipt.parameterFingerprint, receipt.integerKeyTag,
        primaryLineageCommitment);
    receipt.ownerSecretLineageBound =
        IsSha256Text(receipt.nativeKeyLineageCommitment);
    if (!receipt.ownerSecretLineageBound) {
        native.secure_clear();
        throw GLKeyContextMismatchError(
            "GL integer owner-secret bridge failed native lineage derivation");
    }
    return OwnerBinding(std::move(native), std::move(receipt),
                        primaryLineageCommitment);
}

GLIntProductionGLRBridge::PlaintextImport
GLIntProductionGLRBridge::ImportEncodedPlaintext(
    const GLIntProductionEncodedPlaintext& plaintext) const {
    plaintext.Validate();
    if (!plaintext.GetParameters().IsGL128257N32Geometry() ||
        plaintext.GetParameters().plaintextModulus != 1579009) {
        throw GLContextMismatchError(
            "GL integer plaintext bridge parameter mismatch");
    }
    const auto& context = m_adapter->GetContext();
    PlaintextImport result;
    result.native.poly = GlrPoly::zero(
        context, GlrRing::Rp, m_q2Level, false, GlrDomain::Coeff);
    const auto n = static_cast<std::size_t>(context.n());
    const auto phi = static_cast<std::size_t>(context.phi());
    for (std::size_t x = 0; x < n; ++x) {
        for (std::size_t y = 0; y < n; ++y) {
            for (std::size_t w = 0; w < phi; ++w) {
                const auto& coefficient = plaintext.GetCoefficients()[
                    CoefficientIndex(n, phi, x, y, w)];
                glscheme::rns::glr_poly_set_gaussian(
                    context, result.native.poly, static_cast<std::uint32_t>(x),
                    static_cast<std::uint32_t>(y),
                    static_cast<std::uint32_t>(w), coefficient.real,
                    coefficient.imaginary);
            }
        }
    }
    result.native.scale = 1.0;
    result.native.level = m_q2Level;
    result.receipt = MakeReceipt("Q2-L23-Rp-coefficient-plaintext");
    return result;
}

GLIntProductionEncodedPlaintext
GLIntProductionGLRBridge::ExportEncodedPlaintextModT(
    const NativePlaintext& plaintext) const {
    const auto& context = m_adapter->GetContext();
    if (plaintext.poly.ring != GlrRing::Rp ||
        plaintext.poly.domain != GlrDomain::Coeff ||
        plaintext.poly.extended || plaintext.poly.level != m_q2Level ||
        plaintext.level != m_q2Level || plaintext.scale != 1.0 ||
        plaintext.poly.prime_count(context) != 2) {
        throw GLContextMismatchError(
            "GL integer export requires an unscaled Q2/L23 Rp coefficient plaintext");
    }
    const auto parameters = GLIntWBatchedParameters::GL128257N32();
    const auto roots = GLIntProductionCore(parameters).GetRoots();
    const auto n = static_cast<std::size_t>(parameters.dimension);
    const auto phi =
        static_cast<std::size_t>(parameters.cyclotomicPrime - 1);
    std::vector<GLIntGaussianResidue> coefficients(n * n * phi);
    for (std::size_t x = 0; x < n; ++x) {
        for (std::size_t y = 0; y < n; ++y) {
            for (std::size_t w = 0; w < phi; ++w) {
                __int128 real = 0;
                __int128 imaginary = 0;
                glscheme::rns::glr_poly_get_gaussian_centered(
                    context, plaintext.poly, static_cast<std::uint32_t>(x),
                    static_cast<std::uint32_t>(y),
                    static_cast<std::uint32_t>(w), real, imaginary);
                coefficients[CoefficientIndex(n, phi, x, y, w)] = {
                    ReduceModT(real, parameters.plaintextModulus),
                    ReduceModT(imaginary, parameters.plaintextModulus)};
            }
        }
    }
    return GLIntProductionEncodedPlaintext(parameters, roots,
                                            std::move(coefficients));
}

void GLIntProductionGLRBridge::ValidateOwner(
    const std::string& keyTag, const OwnerBinding& owner,
    const char* operation) const {
    const auto& receipt = owner.GetReceipt();
    const auto fingerprint = glscheme::rns::glr_parameter_fingerprint(
        m_adapter->GetContext().params);
    const auto& nativeSecret = owner.GetNativeSecretKey();
    const auto lineage = DomainSeparatedIntegerLineage(
        fingerprint, receipt.integerKeyTag,
        owner.m_primaryLineageCommitment);
    if (keyTag != receipt.integerKeyTag ||
        receipt.parameterFingerprint != fingerprint ||
        receipt.nativeKeyLineageCommitment != lineage ||
        !receipt.ownerSecretLineageBound || !IsSha256Text(lineage) ||
        nativeSecret.key_id != kUntrustedIntegerKeyDomain ||
        nativeSecret.s.ring != GlrRing::R ||
        nativeSecret.s.domain != GlrDomain::Coeff ||
        nativeSecret.s.level != 0 || !nativeSecret.s.extended) {
        throw GLKeyMismatchError(std::string(operation) +
                                 " owner lineage/key-tag mismatch");
    }
}

GLIntProductionGLRBridge::CiphertextImport
GLIntProductionGLRBridge::ImportCoefficientCiphertext(
    const GLIntProductionCiphertext& ciphertext,
    const OwnerBinding& owner) const {
    ciphertext.Validate();
    ValidateOwner(ciphertext.GetKeyTag(), owner,
                  "GL integer coefficient bridge");
    if (ciphertext.GetLevel() != 0 || ciphertext.GetPlanes().size() != 2 ||
        ciphertext.GetPlanes()[0].modulus != m_q0 ||
        ciphertext.GetPlanes()[1].modulus != m_q1) {
        throw GLContextMismatchError(
            "GL integer coefficient bridge requires the complete Q2 prefix");
    }
    const auto& context = m_adapter->GetContext();
    CiphertextImport result;
    result.native.b = GlrPoly::zero(
        context, GlrRing::Rp, m_q2Level, false, GlrDomain::Coeff);
    result.native.a = GlrPoly::zero(
        context, GlrRing::Rp, m_q2Level, false, GlrDomain::Coeff);
    const auto n = static_cast<std::size_t>(context.n());
    const auto phi = static_cast<std::size_t>(context.phi());
    for (std::size_t x = 0; x < n; ++x) {
        for (std::size_t y = 0; y < n; ++y) {
            for (std::size_t w = 0; w < phi; ++w) {
                const auto index = CoefficientIndex(n, phi, x, y, w);
                for (const auto& pair : {
                         std::pair{&result.native.b,
                                   std::pair{&ciphertext.GetPlanes()[0].b,
                                             &ciphertext.GetPlanes()[1].b}},
                         std::pair{&result.native.a,
                                   std::pair{&ciphertext.GetPlanes()[0].a,
                                             &ciphertext.GetPlanes()[1].a}}}) {
                    const auto& r0 = (*pair.second.first)[index];
                    const auto& r1 = (*pair.second.second)[index];
                    glscheme::rns::glr_poly_set_gaussian(
                        context, *pair.first, static_cast<std::uint32_t>(x),
                        static_cast<std::uint32_t>(y),
                        static_cast<std::uint32_t>(w),
                        CenteredCrt(r0.real, r1.real, m_q0, m_q1),
                        CenteredCrt(r0.imaginary, r1.imaginary, m_q0, m_q1));
                }
            }
        }
    }
    result.native.scale =
        static_cast<double>(ciphertext.GetPlaintextScale());
    result.native.level = m_q2Level;
    result.native.key_id = kUntrustedIntegerKeyDomain;
    result.native.key_lineage_commitment =
        owner.GetReceipt().nativeKeyLineageCommitment;
    result.receipt = MakeReceipt("Q2-L23-Rp-coefficient-ciphertext");
    result.receipt.integerKeyTag = ciphertext.GetKeyTag();
    result.receipt.nativeKeyLineageCommitment =
        result.native.key_lineage_commitment;
    result.receipt.ownerSecretLineageBound = true;
    return result;
}

GLIntProductionCiphertext
GLIntProductionGLRBridge::ExportCoefficientCiphertext(
    const NativeCiphertext& ciphertext, const OwnerBinding& owner) const {
    ValidateOwner(owner.GetReceipt().integerKeyTag, owner,
                  "native GL integer coefficient export");
    const auto& context = m_adapter->GetContext();
    const auto expectedWords = static_cast<std::size_t>(2) * 2 *
                               context.params.coeffs_Rp();
    if (ciphertext.key_id != kUntrustedIntegerKeyDomain ||
        ciphertext.key_lineage_commitment !=
            owner.GetReceipt().nativeKeyLineageCommitment ||
        ciphertext.level != m_q2Level ||
        ciphertext.b.ring != GlrRing::Rp ||
        ciphertext.a.ring != GlrRing::Rp ||
        ciphertext.b.domain != GlrDomain::Coeff ||
        ciphertext.a.domain != GlrDomain::Coeff || ciphertext.b.extended ||
        ciphertext.a.extended || ciphertext.b.level != m_q2Level ||
        ciphertext.a.level != m_q2Level ||
        ciphertext.b.data.size() != expectedWords ||
        ciphertext.a.data.size() != expectedWords) {
        throw GLContextMismatchError(
            "native GL integer coefficient export requires an authentic untrusted Q2/L23 ciphertext");
    }
    const auto plaintextScale = RequireIntegerScale(ciphertext.scale, 1579009);
    const auto parameters = GLIntWBatchedParameters::GL128257N32();
    const auto roots = GLIntProductionCore(parameters).GetRoots();
    const auto n = static_cast<std::size_t>(parameters.dimension);
    const auto phi =
        static_cast<std::size_t>(parameters.cyclotomicPrime - 1);
    std::vector<GLIntProductionCiphertextPlane> planes(2);
    for (std::uint32_t prime = 0; prime < 2; ++prime) {
        auto& plane = planes[prime];
        plane.modulus =
            static_cast<std::uint32_t>(context.params.q_chain[prime].q);
        plane.b.resize(n * n * phi);
        plane.a.resize(n * n * phi);
        for (std::size_t x = 0; x < n; ++x) {
            for (std::size_t y = 0; y < n; ++y) {
                for (std::size_t w = 0; w < phi; ++w) {
                    const auto index = CoefficientIndex(n, phi, x, y, w);
                    plane.b[index] = GaussianResidueAt(
                        context, ciphertext.b, prime,
                        static_cast<std::uint32_t>(x),
                        static_cast<std::uint32_t>(y),
                        static_cast<std::uint32_t>(w));
                    plane.a[index] = GaussianResidueAt(
                        context, ciphertext.a, prime,
                        static_cast<std::uint32_t>(x),
                        static_cast<std::uint32_t>(y),
                        static_cast<std::uint32_t>(w));
                }
            }
        }
    }
    return GLIntProductionCiphertext(
        parameters, roots, owner.GetReceipt().integerKeyTag, 0,
        plaintextScale, std::move(planes));
}

GLIntProductionGLRBridge::CiphertextImport
GLIntProductionGLRBridge::ImportSlotCiphertext(
    const GLIntProductionSlotCiphertext& ciphertext,
    const OwnerBinding& owner) const {
    ciphertext.Validate();
    ValidateOwner(ciphertext.GetKeyTag(), owner, "GL integer Slot bridge");
    if (ciphertext.GetCompositeModulus() !=
        static_cast<std::uint64_t>(m_q0) * m_q1) {
        throw GLContextMismatchError(
            "GL integer Slot bridge requires the canonical Q2 product");
    }
    const auto& context = m_adapter->GetContext();
    CiphertextImport result;
    result.native.b = GlrPoly::zero(context, GlrRing::Rp, m_q2Level, false,
                                    GlrDomain::Slot);
    result.native.a = GlrPoly::zero(context, GlrRing::Rp, m_q2Level, false,
                                    GlrDomain::Slot);
    const auto n = static_cast<std::size_t>(context.n());
    for (const auto& value : ciphertext.GetValues()) {
        const auto lane = value.branch == GLIntBranch::Plus ? 0U : 1U;
        const auto flat =
            (static_cast<std::size_t>(value.matrix) * n + value.row) * n +
            value.column;
        for (std::uint32_t prime = 0; prime < 2; ++prime) {
            const auto modulus = context.params.q_chain[prime].q;
            result.native.b.lane_ptr(context, prime, lane)[flat] =
                value.b % modulus;
            result.native.a.lane_ptr(context, prime, lane)[flat] =
                value.a % modulus;
        }
    }
    result.native.scale =
        static_cast<double>(ciphertext.GetPlaintextScale());
    result.native.level = m_q2Level;
    result.native.key_id = kUntrustedIntegerKeyDomain;
    result.native.key_lineage_commitment =
        owner.GetReceipt().nativeKeyLineageCommitment;
    result.receipt = MakeReceipt("Q2-L23-Rp-slot-ciphertext");
    result.receipt.integerKeyTag = ciphertext.GetKeyTag();
    result.receipt.nativeKeyLineageCommitment =
        result.native.key_lineage_commitment;
    result.receipt.ownerSecretLineageBound = true;
    return result;
}

GLIntProductionSlotCiphertext GLIntProductionGLRBridge::ExportSlotCiphertext(
    const NativeCiphertext& ciphertext, const OwnerBinding& owner) const {
    ValidateOwner(owner.GetReceipt().integerKeyTag, owner,
                  "native GL integer Slot export");
    const auto& context = m_adapter->GetContext();
    const auto expectedWords = static_cast<std::size_t>(2) * 2 *
                               context.params.coeffs_Rp();
    if (ciphertext.key_id != kUntrustedIntegerKeyDomain ||
        ciphertext.key_lineage_commitment !=
            owner.GetReceipt().nativeKeyLineageCommitment ||
        ciphertext.level != m_q2Level ||
        ciphertext.b.ring != GlrRing::Rp ||
        ciphertext.a.ring != GlrRing::Rp ||
        ciphertext.b.domain != GlrDomain::Slot ||
        ciphertext.a.domain != GlrDomain::Slot || ciphertext.b.extended ||
        ciphertext.a.extended || ciphertext.b.level != m_q2Level ||
        ciphertext.a.level != m_q2Level ||
        ciphertext.b.data.size() != expectedWords ||
        ciphertext.a.data.size() != expectedWords) {
        throw GLContextMismatchError(
            "native GL integer Slot export requires an authentic untrusted Q2/L23 ciphertext");
    }
    const auto plaintextScale = RequireIntegerScale(ciphertext.scale, 1579009);
    const auto n = static_cast<std::size_t>(context.n());
    const auto phi = static_cast<std::size_t>(context.phi());
    std::vector<GLIntProductionSlotCiphertextValue> values;
    for (std::uint32_t lane = 0; lane < 2; ++lane) {
        const auto branch = lane == 0 ? GLIntBranch::Plus
                                      : GLIntBranch::Minus;
        for (std::size_t matrix = 0; matrix < phi; ++matrix) {
            for (std::size_t row = 0; row < n; ++row) {
                for (std::size_t column = 0; column < n; ++column) {
                    const auto flat = (matrix * n + row) * n + column;
                    const auto b0 = static_cast<std::uint32_t>(
                        ciphertext.b.lane_ptr(context, 0, lane)[flat]);
                    const auto b1 = static_cast<std::uint32_t>(
                        ciphertext.b.lane_ptr(context, 1, lane)[flat]);
                    const auto a0 = static_cast<std::uint32_t>(
                        ciphertext.a.lane_ptr(context, 0, lane)[flat]);
                    const auto a1 = static_cast<std::uint32_t>(
                        ciphertext.a.lane_ptr(context, 1, lane)[flat]);
                    if (b0 == 0 && b1 == 0 && a0 == 0 && a1 == 0) {
                        continue;
                    }
                    values.push_back(
                        {branch, static_cast<std::uint32_t>(matrix),
                         static_cast<std::uint32_t>(row),
                         static_cast<std::uint32_t>(column),
                         CanonicalCrt(b0, b1, m_q0, m_q1),
                         CanonicalCrt(a0, a1, m_q0, m_q1)});
                    if (values.size() > kGLIntProductionMaxLogicalValues) {
                        throw GLDimensionError(
                            "native GL integer Slot export exceeds the bounded sparse support");
                    }
                }
            }
        }
    }
    return GLIntProductionSlotCiphertext(
        GLIntWBatchedParameters::GL128257N32(),
        owner.GetReceipt().integerKeyTag,
        static_cast<std::uint64_t>(m_q0) * m_q1, plaintextScale,
        std::move(values));
}

GLIntProductionGLRBridge::IntegerAutomorphismKey
GLIntProductionGLRBridge::GenerateIntegerAutomorphismKey(
    const OwnerBinding& owner, IntegerAutomorphism operation,
    std::int32_t amount, std::uint64_t seed) const {
    ValidateOwner(owner.GetReceipt().integerKeyTag, owner,
                  "integer automorphism key generation");
    const auto& context = m_adapter->GetContext();
    const auto normalize = [](std::int32_t value, std::int32_t modulus) {
        auto out = value % modulus;
        return out < 0 ? out + modulus : out;
    };
    GlrRing ring = GlrRing::R;
    switch (operation) {
        case IntegerAutomorphism::RowRotation:
            amount = normalize(amount, static_cast<std::int32_t>(context.n()));
            if (amount == 0) {
                throw GLDimensionError(
                    "integer row-rotation key requires a nonzero amount");
            }
            break;
        case IntegerAutomorphism::InterMatrixRotation:
            amount = normalize(amount,
                               static_cast<std::int32_t>(context.phi()));
            if (amount == 0) {
                throw GLDimensionError(
                    "integer matrix-rotation key requires a nonzero amount");
            }
            break;
        case IntegerAutomorphism::Transpose:
            if (amount != 0) {
                throw GLDimensionError(
                    "integer transpose key amount must be zero");
            }
            ring = GlrRing::Rp;
            break;
        case IntegerAutomorphism::ConjugationFamilySwap:
            if (amount != 0) {
                throw GLDimensionError(
                    "integer family-swap key amount must be zero");
            }
            break;
    }

    GlrPoly restricted = RestrictToQ2P1(owner.GetNativeSecretKey().s);
    PolyWipe restrictedWipe(restricted);
    GlrPoly source;
    PolyWipe sourceWipe(source);
    if (operation == IntegerAutomorphism::Transpose) {
        GlrPoly embedded =
            glscheme::rns::glr_embed_r_into(context, restricted, GlrRing::Rp);
        PolyWipe embeddedWipe(embedded);
        glscheme::rns::GlrCoeffAutomorphism automorphism;
        automorphism.swap_xy = true;
        source = glscheme::rns::glr_apply_coeff_automorphism(
            context, embedded, automorphism);
    }
    else {
        glscheme::rns::GlrCoeffAutomorphism automorphism;
        if (operation == IntegerAutomorphism::RowRotation) {
            automorphism.x_alpha = static_cast<std::int64_t>(
                glscheme::rns::glr_powmod(5, amount, 4ull * context.n()));
        }
        else if (operation == IntegerAutomorphism::InterMatrixRotation) {
            automorphism.w_alpha = static_cast<std::int64_t>(
                glscheme::rns::glr_powmod(context.params.gamma, amount,
                                          context.p_()));
        }
        else {
            automorphism.x_alpha = -1;
            automorphism.w_alpha = -1;
            automorphism.conjugate = true;
        }
        source = glscheme::rns::glr_apply_coeff_automorphism(
            context, restricted, automorphism);
    }
    GlrPoly destination =
        ring == GlrRing::R
            ? restricted
            : glscheme::rns::glr_embed_r_into(context, restricted, ring);
    PolyWipe destinationWipe(destination);

    std::vector<std::uint64_t> gadget(
        context.params.levels() + context.params.p_special.size(), 0);
    const auto special = context.params.p_special[0].q;
    gadget[0] = special % context.params.q_chain[0].q;
    gadget[1] = special % context.params.q_chain[1].q;
    GlrPoly message = source;
    PolyWipe messageWipe(message);
    glscheme::rns::glr_residue_scalar_mul_inplace(context, message, gadget);
    glscheme::rns::glr_to_slots(context, message);
    glscheme::rns::glr_to_slots(context, destination);

    GlrRngOwner rng(glscheme::rns::glr_rng_create(seed));
    if (!rng) {
        throw GlrError("integer automorphism KSK RNG creation failed");
    }
    GlrPoly a = GlrPoly::zero(context, ring, m_q2Level, true,
                              GlrDomain::Coeff, 1);
    glscheme::rns::glr_sample_uniform(context, a, *rng);
    glscheme::rns::glr_to_slots(context, a);
    GlrPoly product = a;
    PolyWipe productWipe(product);
    glscheme::rns::glr_mul_pointwise_inplace(context, product, destination);
    GlrPoly b = message;
    glscheme::rns::glr_sub_inplace(context, b, product);

    GlrPoly error = GlrPoly::zero(context, ring, m_q2Level, true,
                                  GlrDomain::Coeff, 1);
    PolyWipe errorWipe(error);
    if (ring == GlrRing::R) {
        glscheme::rns::glr_sample_error_r(context, error, 3.2, *rng);
    }
    else {
        for (std::uint32_t y = 0; y < context.n(); ++y) {
            GlrPoly slice = GlrPoly::zero(context, GlrRing::R, m_q2Level,
                                          true, GlrDomain::Coeff, 1);
            PolyWipe sliceWipe(slice);
            glscheme::rns::glr_sample_error_r(context, slice, 3.2, *rng);
            glscheme::rns::glr_insert_y_slice(context, error, slice, y);
        }
    }
    glscheme::rns::glr_scalar_mul_inplace(context, error, 1579009);
    glscheme::rns::glr_to_slots(context, error);
    glscheme::rns::glr_add_inplace(context, b, error);

    return IntegerAutomorphismKey(
        operation, amount, ring, std::move(b), std::move(a),
        owner.GetReceipt().parameterFingerprint,
        owner.GetReceipt().nativeKeyLineageCommitment);
}

std::pair<GlrPoly, GlrPoly>
GLIntProductionGLRBridge::ApplyIntegerSwitch(
    const GlrPoly& input,
    const IntegerAutomorphismKey& evaluationKey) const {
    const auto& context = m_adapter->GetContext();
    if (input.ring != evaluationKey.m_ring || input.extended ||
        input.level != m_q2Level || evaluationKey.m_b.ring != input.ring ||
        evaluationKey.m_a.ring != input.ring ||
        evaluationKey.m_b.domain != GlrDomain::Slot ||
        evaluationKey.m_a.domain != GlrDomain::Slot ||
        evaluationKey.m_b.level != m_q2Level ||
        evaluationKey.m_a.level != m_q2Level ||
        !evaluationKey.m_b.extended || !evaluationKey.m_a.extended ||
        evaluationKey.m_b.active_special_prime_count(context) != 1 ||
        evaluationKey.m_a.active_special_prime_count(context) != 1 ||
        evaluationKey.m_b.data.size() !=
            static_cast<std::size_t>(3) * 2 * input.ring_coeffs(context) ||
        evaluationKey.m_a.data.size() !=
            static_cast<std::size_t>(3) * 2 * input.ring_coeffs(context)) {
        throw GLContextMismatchError(
            "integer hybrid SwitchInt input/key shape mismatch");
    }
    const auto originalDomain = input.domain;
    GlrPoly coefficient = input;
    if (coefficient.domain == GlrDomain::Slot) {
        glscheme::rns::glr_to_coeffs(context, coefficient);
    }
    GlrPoly lifted = ModUpQ2P1(coefficient);
    glscheme::rns::glr_to_slots(context, lifted);
    GlrPoly b = lifted;
    glscheme::rns::glr_mul_pointwise_inplace(context, b,
                                              evaluationKey.m_b);
    GlrPoly a = std::move(lifted);
    glscheme::rns::glr_mul_pointwise_inplace(context, a,
                                              evaluationKey.m_a);
    glscheme::rns::glr_to_coeffs(context, b);
    glscheme::rns::glr_to_coeffs(context, a);
    b = BGVModDownP1(b);
    a = BGVModDownP1(a);
    if (originalDomain == GlrDomain::Slot) {
        glscheme::rns::glr_to_slots(context, b);
        glscheme::rns::glr_to_slots(context, a);
    }
    return {std::move(b), std::move(a)};
}

GLIntProductionGLRBridge::NativeCiphertext
GLIntProductionGLRBridge::EvaluateIntegerAutomorphism(
    const NativeCiphertext& ciphertext,
    const IntegerAutomorphismKey& evaluationKey) const {
    const auto& context = m_adapter->GetContext();
    const auto fingerprint =
        glscheme::rns::glr_parameter_fingerprint(context.params);
    const auto expectedWords = static_cast<std::size_t>(2) * 2 *
                               context.params.coeffs_Rp();
    if (ciphertext.key_id != kUntrustedIntegerKeyDomain ||
        ciphertext.key_lineage_commitment !=
            evaluationKey.m_nativeKeyLineageCommitment ||
        evaluationKey.m_parameterFingerprint != fingerprint ||
        ciphertext.level != m_q2Level ||
        ciphertext.b.ring != GlrRing::Rp ||
        ciphertext.a.ring != GlrRing::Rp ||
        ciphertext.b.domain != GlrDomain::Slot ||
        ciphertext.a.domain != GlrDomain::Slot || ciphertext.b.extended ||
        ciphertext.a.extended || ciphertext.b.level != m_q2Level ||
        ciphertext.a.level != m_q2Level ||
        ciphertext.b.data.size() != expectedWords ||
        ciphertext.a.data.size() != expectedWords) {
        throw GLContextMismatchError(
            "integer keyed automorphism requires an authentic untrusted Q2/L23 Slot ciphertext");
    }
    static_cast<void>(RequireIntegerScale(ciphertext.scale, 1579009));

    glscheme::rns::GlrSlotAutomorphism automorphism;
    switch (evaluationKey.m_operation) {
        case IntegerAutomorphism::RowRotation:
            automorphism = glscheme::rns::glr_slot_automorphism_for(
                context, evaluationKey.m_amount, 0, 0, false, false);
            break;
        case IntegerAutomorphism::InterMatrixRotation:
            automorphism = glscheme::rns::glr_slot_automorphism_for(
                context, 0, 0, evaluationKey.m_amount, false, false);
            break;
        case IntegerAutomorphism::Transpose:
            automorphism = glscheme::rns::glr_slot_automorphism_for(
                context, 0, 0, 0, true, false);
            break;
        case IntegerAutomorphism::ConjugationFamilySwap:
            automorphism = glscheme::rns::glr_slot_automorphism_for(
                context, 0, 0, 0, false, true);
            break;
    }
    NativeCiphertext transformed = ciphertext;
    transformed.b = glscheme::rns::glr_apply_slot_automorphism(
        context, ciphertext.b, automorphism);
    transformed.a = glscheme::rns::glr_apply_slot_automorphism(
        context, ciphertext.a, automorphism);

    std::pair<GlrPoly, GlrPoly> switched;
    if (evaluationKey.m_ring == GlrRing::Rp) {
        switched = ApplyIntegerSwitch(transformed.a, evaluationKey);
    }
    else {
        GlrPoly coefficient = transformed.a;
        glscheme::rns::glr_to_coeffs(context, coefficient);
        GlrPoly b = GlrPoly::zero(context, GlrRing::Rp, m_q2Level, false,
                                  GlrDomain::Coeff);
        GlrPoly a = GlrPoly::zero(context, GlrRing::Rp, m_q2Level, false,
                                  GlrDomain::Coeff);
        for (std::uint32_t y = 0; y < context.n(); ++y) {
            GlrPoly slice =
                glscheme::rns::glr_extract_y_slice(context, coefficient, y);
            auto sliceSwitched = ApplyIntegerSwitch(slice, evaluationKey);
            glscheme::rns::glr_insert_y_slice(context, b,
                                               sliceSwitched.first, y);
            glscheme::rns::glr_insert_y_slice(context, a,
                                               sliceSwitched.second, y);
        }
        glscheme::rns::glr_to_slots(context, b);
        glscheme::rns::glr_to_slots(context, a);
        switched = {std::move(b), std::move(a)};
    }
    glscheme::rns::glr_add_inplace(context, transformed.b, switched.first);
    transformed.a = std::move(switched.second);
    transformed.key_id = kUntrustedIntegerKeyDomain;
    transformed.key_lineage_commitment =
        evaluationKey.m_nativeKeyLineageCommitment;
    return transformed;
}

void GLIntProductionGLRBridge::RequireBootstrapDirectAdmission(
    const Receipt& receipt) const {
    if (receipt.parameterFingerprint !=
            glscheme::rns::glr_parameter_fingerprint(
                m_adapter->GetContext().params) ||
        receipt.nativeLevel != m_q2Level || receipt.activeQPrimes != 2 ||
        receipt.bootstrapDirectAdmitted) {
        throw GLContextMismatchError(
            "malformed GL integer bridge receipt at bootstrap admission");
    }
    throw GlrError(kBootstrapRejection);
}

void GLIntProductionGLRBridge::RequireProductionSecurityAuthorization(
    const Receipt& receipt) const {
    if (receipt.parameterFingerprint !=
            glscheme::rns::glr_parameter_fingerprint(
                m_adapter->GetContext().params) ||
        receipt.productionSecurityAuthorized) {
        throw GLContextMismatchError(
            "malformed GL integer bridge receipt at security admission");
    }
    throw GlrError(kSecurityRejection);
}

}  // namespace lbcrypto
