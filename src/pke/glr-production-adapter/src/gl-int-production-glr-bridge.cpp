//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "openfhe/pke/gl-int-production-glr-bridge.h"

#include "utils/hashutil.h"

#include <cmath>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {
namespace {

using glscheme::rns::GlrDomain;
using glscheme::rns::GlrError;
using glscheme::rns::GlrPoly;
using glscheme::rns::GlrRing;

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
