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
#include <string_view>
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
constexpr const char* kFullChainBootstrapRejection =
    "BootstrapDirect rejected: the dense integer lineage has no certified "
    "Q7/L18 m+t*e to SHIP input lift or mod-t refresh theorem";
constexpr const char* kFullChainSecurityRejection =
    "production security rejected: the dense ternary full-Q integer path has "
    "not completed the profile-bound RLWE/noise/bootstrap admission audit";
constexpr const char* kUntrustedIntegerKeyDomain = "integer-q2-untrusted";

std::size_t CoefficientIndex(std::size_t n, std::size_t phi, std::size_t x,
                             std::size_t y, std::size_t w) noexcept {
    return (x * n + y) * phi + w;
}

std::size_t DenseSlotIndex(GLIntBranch family, std::size_t matrix,
                           std::size_t row, std::size_t column) noexcept {
    const auto lane = family == GLIntBranch::Plus ? std::size_t{0}
                                                  : std::size_t{1};
    return ((lane * 256 + matrix) * 128 + row) * 128 + column;
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

bool IsFullChainIntegerKeyTag(const std::string& value) {
    constexpr std::string_view prefix = "gl-int-full-";
    if (value.size() != prefix.size() + 64 ||
        value.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    return std::all_of(
        value.begin() + static_cast<std::ptrdiff_t>(prefix.size()),
        value.end(), [](char c) {
            return (c >= '0' && c <= '9') ||
                   (c >= 'a' && c <= 'f');
        });
}

bool IsCanonicalFullChainReceipt(
    const glscheme::rns::GlrContext& context,
    const GLIntProductionGLRBridge::Receipt& receipt) {
    return receipt.schema == "openfhe.gl_int.glr_full_chain.v1" &&
           receipt.parameterFingerprint ==
               glscheme::rns::glr_parameter_fingerprint(context.params) &&
           !receipt.representation.empty() &&
           receipt.admissionRejection == kFullChainBootstrapRejection &&
           receipt.plaintextModulus == 1579009 &&
           receipt.nativeLevel < context.params.levels() &&
           receipt.activeQPrimes ==
               context.active_q_primes(receipt.nativeLevel) &&
           receipt.exactModuloT && receipt.denseEq5Layout &&
           receipt.tErrorInvariant && receipt.denseTernaryOwner &&
           receipt.ownerSecretLineageBound &&
           IsSha256Text(receipt.nativeKeyLineageCommitment) &&
           !receipt.productionSecurityAuthorized &&
           !receipt.bootstrapDirectAdmitted;
}

bool IsCanonicalLegacyQ2Receipt(
    const glscheme::rns::GlrContext& context, std::uint32_t q2Level,
    const GLIntProductionGLRBridge::Receipt& receipt) {
    return receipt.schema == "openfhe.gl_int.glr_q2_bridge.v1" &&
           receipt.parameterFingerprint ==
               glscheme::rns::glr_parameter_fingerprint(context.params) &&
           !receipt.representation.empty() &&
           receipt.admissionRejection == kBootstrapRejection &&
           receipt.plaintextModulus == 1579009 &&
           receipt.nativeLevel == q2Level && receipt.activeQPrimes == 2 &&
           receipt.exactModuloT && !receipt.denseEq5Layout &&
           !receipt.tErrorInvariant && !receipt.denseTernaryOwner &&
           !receipt.productionSecurityAuthorized &&
           !receipt.bootstrapDirectAdmitted;
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

std::string DomainSeparatedFullChainIntegerLineage(
    const std::string& parameterFingerprint, const std::string& integerKeyTag,
    const std::string& primaryLineageCommitment) {
    const auto payload =
        std::string("openfhe.gl_int.full_chain_untrusted_lineage.v1|") +
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

GLIntProductionGLRBridge::IntegerPublicKey::IntegerPublicKey(
    GlrPoly b, glscheme::rns::GlrPublicASeed publicASeed,
    std::string parameterFingerprint, std::string integerKeyTag,
    std::string nativeKeyLineageCommitment, bool denseTernaryOwner)
    : m_b(std::move(b)),
      m_publicASeed(std::move(publicASeed)),
      m_parameterFingerprint(std::move(parameterFingerprint)),
      m_integerKeyTag(std::move(integerKeyTag)),
      m_nativeKeyLineageCommitment(
          std::move(nativeKeyLineageCommitment)),
      m_denseTernaryOwner(denseTernaryOwner) {}

std::uint32_t
GLIntProductionGLRBridge::IntegerPublicKey::GetKeyLevel() const noexcept {
    return m_b.level;
}

std::size_t
GLIntProductionGLRBridge::IntegerPublicKey::GetStoredBytes() const noexcept {
    return m_b.data.size() * sizeof(m_b.data.front()) + m_publicASeed.size();
}

const std::string& GLIntProductionGLRBridge::IntegerPublicKey::
    GetParameterFingerprint() const noexcept {
    return m_parameterFingerprint;
}

const std::string& GLIntProductionGLRBridge::IntegerPublicKey::
    GetIntegerKeyTag() const noexcept {
    return m_integerKeyTag;
}

const std::string& GLIntProductionGLRBridge::IntegerPublicKey::
    GetNativeKeyLineageCommitment() const noexcept {
    return m_nativeKeyLineageCommitment;
}

bool GLIntProductionGLRBridge::IntegerPublicKey::UsesSeededPublicA() const noexcept {
    return true;
}

bool GLIntProductionGLRBridge::IntegerPublicKey::UsesTErrors() const noexcept {
    return true;
}

bool GLIntProductionGLRBridge::IntegerPublicKey::
    HasDenseTernaryOwnerLineage() const noexcept {
    return m_denseTernaryOwner;
}

bool GLIntProductionGLRBridge::IntegerPublicKey::IsSecurityAuthorized() const noexcept {
    return false;
}

GLIntProductionGLRBridge::FullChainIntegerSwitchKey::
    FullChainIntegerSwitchKey(
        FullChainSwitchKind kind, std::int32_t amount,
        glscheme::rns::GlrSwitchKey native,
        std::uint32_t activeSpecialPrimeCount,
        std::string nativeKeyLineageCommitment,
        bool denseTernaryOwner)
    : m_kind(kind),
      m_amount(amount),
      m_native(std::move(native)),
      m_activeSpecialPrimeCount(activeSpecialPrimeCount),
      m_nativeKeyLineageCommitment(
          std::move(nativeKeyLineageCommitment)),
      m_denseTernaryOwner(denseTernaryOwner) {}

GLIntProductionGLRBridge::FullChainSwitchKind
GLIntProductionGLRBridge::FullChainIntegerSwitchKey::GetKind() const noexcept {
    return m_kind;
}

std::int32_t GLIntProductionGLRBridge::FullChainIntegerSwitchKey::
    GetAmount() const noexcept {
    return m_amount;
}

std::uint32_t GLIntProductionGLRBridge::FullChainIntegerSwitchKey::
    GetKeyLevel() const noexcept {
    return m_native.key_level;
}

std::uint32_t GLIntProductionGLRBridge::FullChainIntegerSwitchKey::
    GetDigitCount() const noexcept {
    return m_native.dnum;
}

std::uint32_t GLIntProductionGLRBridge::FullChainIntegerSwitchKey::
    GetSpecialPrimeCount() const noexcept {
    return m_activeSpecialPrimeCount;
}

GlrRing GLIntProductionGLRBridge::FullChainIntegerSwitchKey::
    GetRequiredInputRing() const noexcept {
    return m_native.ring;
}

std::size_t GLIntProductionGLRBridge::FullChainIntegerSwitchKey::
    GetMaterializedBytes() const noexcept {
    return static_cast<std::size_t>(m_native.byte_size());
}

std::size_t GLIntProductionGLRBridge::FullChainIntegerSwitchKey::
    GetCompactStoredBytes() const noexcept {
    std::size_t bytes = m_native.public_a_seed.has_value()
                            ? m_native.public_a_seed->size()
                            : 0;
    for (const auto& digit : m_native.b_digits) {
        bytes += digit.data.size() * sizeof(std::uint64_t);
    }
    return bytes;
}

const std::string& GLIntProductionGLRBridge::FullChainIntegerSwitchKey::
    GetParameterFingerprint() const noexcept {
    return m_native.parameter_fingerprint;
}

const std::string& GLIntProductionGLRBridge::FullChainIntegerSwitchKey::
    GetNativeKeyLineageCommitment() const noexcept {
    return m_nativeKeyLineageCommitment;
}

bool GLIntProductionGLRBridge::FullChainIntegerSwitchKey::IsBigSwitch() const noexcept {
    return m_native.ring == GlrRing::Rp;
}

bool GLIntProductionGLRBridge::FullChainIntegerSwitchKey::
    UsesSeededPublicA() const noexcept {
    return m_native.public_a_seed.has_value();
}

bool GLIntProductionGLRBridge::FullChainIntegerSwitchKey::UsesTErrors() const noexcept {
    return true;
}

bool GLIntProductionGLRBridge::FullChainIntegerSwitchKey::
    HasDenseTernaryOwnerLineage() const noexcept {
    return m_denseTernaryOwner;
}

bool GLIntProductionGLRBridge::FullChainIntegerSwitchKey::
    IsSecurityAuthorized() const noexcept {
    return false;
}

void GLIntProductionGLRBridge::DenseIntegerBatch::Validate() const {
    if (values.size() != kDenseIntegerSlotCount) {
        throw GLDimensionError(
            "dense GL integer batch must contain exactly 512x128x128 slots");
    }
    for (const auto value : values) {
        if (value >= 1579009) {
            throw GLDimensionError(
                "dense GL integer batch value is not canonical modulo t");
        }
    }
}

std::uint64_t GLIntProductionGLRBridge::DenseIntegerBatch::At(
    GLIntBranch family, std::uint32_t matrix, std::uint32_t row,
    std::uint32_t column) const {
    if (values.size() != kDenseIntegerSlotCount ||
        (family != GLIntBranch::Plus && family != GLIntBranch::Minus) ||
        matrix >= 256 || row >= 128 || column >= 128) {
        throw GLDimensionError("dense GL integer batch index is out of range");
    }
    return values[DenseSlotIndex(family, matrix, row, column)];
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
    glscheme::rns::GlrParams plaintextParameters;
    plaintextParameters.name = "GL-128-257-T1579009";
    plaintextParameters.n = context.n();
    plaintextParameters.p = context.p_();
    plaintextParameters.phi = context.phi();
    plaintextParameters.gamma = context.params.gamma;
    plaintextParameters.fourNp = context.params.fourNp;
    plaintextParameters.delta = 1.0;
    plaintextParameters.depth = 0;
    plaintextParameters.dnum = 0;
    plaintextParameters.rescale_stride = 1;
    plaintextParameters.q_chain.push_back(
        glscheme::rns::glr_make_modulus(1579009, context.n(), context.p_()));
    m_plaintextContext = glscheme::rns::GlrContext::create(
        std::move(plaintextParameters));
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

GlrPoly GLIntProductionGLRBridge::RestrictSecretToQ(
    const GlrPoly& full, std::uint32_t level) const {
    const auto& context = m_adapter->GetContext();
    if (full.domain != GlrDomain::Coeff || full.level != 0 ||
        !full.extended || level >= context.params.levels()) {
        throw GLContextMismatchError(
            "full-chain integer secret restriction received invalid material");
    }
    GlrPoly out = GlrPoly::zero(context, full.ring, level, false,
                                GlrDomain::Coeff);
    const auto coefficients = full.ring_coeffs(context);
    const auto active = context.active_q_primes(level);
    for (std::uint32_t prime = 0; prime < active; ++prime) {
        for (std::uint32_t lane = 0; lane < 2; ++lane) {
            const auto* source = full.lane_ptr(context, prime, lane);
            std::copy(source, source + coefficients,
                      out.lane_ptr(context, prime, lane));
        }
    }
    return out;
}

GlrPoly GLIntProductionGLRBridge::RingMultiply(
    const GlrPoly& lhs, const GlrPoly& rhs) const {
    const auto& context = m_adapter->GetContext();
    if (lhs.ring != rhs.ring || lhs.level != rhs.level ||
        lhs.extended != rhs.extended) {
        throw GLContextMismatchError(
            "full-chain integer ring multiplication shape mismatch");
    }
    GlrPoly output = lhs;
    if (output.domain == GlrDomain::Coeff) {
        glscheme::rns::glr_to_slots(context, output);
    }
    GlrPoly multiplier = rhs;
    PolyWipe multiplierWipe(multiplier);
    if (multiplier.domain == GlrDomain::Coeff) {
        glscheme::rns::glr_to_slots(context, multiplier);
    }
    glscheme::rns::glr_mul_pointwise_inplace(context, output, multiplier);
    glscheme::rns::glr_to_coeffs(context, output);
    return output;
}

GlrPoly GLIntProductionGLRBridge::SampleTErr(
    GlrRing ring, std::uint32_t level,
    glscheme::rns::GlrRng& rng) const {
    const auto& context = m_adapter->GetContext();
    GlrPoly error = GlrPoly::zero(context, ring, level, false,
                                  GlrDomain::Coeff);
    if (ring == GlrRing::R) {
        glscheme::rns::glr_sample_error_r(context, error, 3.2, rng);
    }
    else if (ring == GlrRing::Rp) {
        for (std::uint32_t y = 0; y < context.n(); ++y) {
            GlrPoly slice = GlrPoly::zero(context, GlrRing::R, level, false,
                                          GlrDomain::Coeff);
            PolyWipe sliceWipe(slice);
            glscheme::rns::glr_sample_error_r(context, slice, 3.2, rng);
            glscheme::rns::glr_insert_y_slice(context, error, slice, y);
        }
    }
    else {
        throw GLContextMismatchError(
            "full-chain integer error sampling does not accept Raux");
    }
    glscheme::rns::glr_scalar_mul_inplace(context, error, 1579009);
    return error;
}

GlrPoly GLIntProductionGLRBridge::SampleTernaryRp(
    std::uint32_t level, glscheme::rns::GlrRng& rng) const {
    const auto& context = m_adapter->GetContext();
    if (level >= context.params.levels()) {
        throw GLDepthError("full-chain integer ternary sample level is invalid");
    }
    GlrPoly output = GlrPoly::zero(context, GlrRing::Rp, level, false,
                                   GlrDomain::Coeff);
    for (std::uint32_t y = 0; y < context.n(); ++y) {
        GlrPoly slice = GlrPoly::zero(context, GlrRing::R, level, false,
                                      GlrDomain::Coeff);
        PolyWipe sliceWipe(slice);
        glscheme::rns::glr_sample_ternary_r(context, slice, rng);
        glscheme::rns::glr_insert_y_slice(context, output, slice, y);
    }
    return output;
}

void GLIntProductionGLRBridge::AddTErrInPlace(
    GlrPoly* target, glscheme::rns::GlrRng& rng) const {
    const auto& context = m_adapter->GetContext();
    if (target == nullptr || target->domain != GlrDomain::Coeff ||
        target->extended || target->level >= context.params.levels() ||
        (target->ring != GlrRing::R && target->ring != GlrRing::Rp)) {
        throw GLContextMismatchError(
            "full-chain integer t*e addition received invalid target");
    }
    if (target->ring == GlrRing::R) {
        GlrPoly error = SampleTErr(GlrRing::R, target->level, rng);
        PolyWipe errorWipe(error);
        glscheme::rns::glr_add_inplace(context, *target, error);
        return;
    }

    const auto rCoefficients =
        static_cast<std::size_t>(context.n()) * context.phi();
    for (std::uint32_t y = 0; y < context.n(); ++y) {
        GlrPoly error = GlrPoly::zero(context, GlrRing::R, target->level,
                                      false, GlrDomain::Coeff);
        PolyWipe errorWipe(error);
        glscheme::rns::glr_sample_error_r(context, error, 3.2, rng);
        glscheme::rns::glr_scalar_mul_inplace(context, error, 1579009);
        for (std::uint32_t plane = 0; plane < target->prime_count(context);
             ++plane) {
            const auto modulus = context.modulus_at(plane).q;
            for (std::uint32_t lane = 0; lane < 2; ++lane) {
                auto* destination = target->lane_ptr(context, plane, lane);
                const auto* source = error.lane_ptr(context, plane, lane);
                for (std::size_t wx = 0; wx < rCoefficients; ++wx) {
                    const auto flat = wx * context.n() + y;
                    destination[flat] = glscheme::rns::glr_mod_add(
                        destination[flat], source[wx], modulus);
                }
            }
        }
    }
}

void GLIntProductionGLRBridge::MultiplyRpByRInSlots(
    GlrPoly* rp, const GlrPoly& r) const {
    const auto& context = m_adapter->GetContext();
    if (rp == nullptr || rp->ring != GlrRing::Rp || r.ring != GlrRing::R ||
        rp->domain != GlrDomain::Slot || r.domain != GlrDomain::Slot ||
        rp->level != r.level || rp->extended != r.extended || rp->extended ||
        rp->prime_count(context) != r.prime_count(context)) {
        throw GLContextMismatchError(
            "full-chain integer Rp-by-R multiplication shape mismatch");
    }
    const auto rCoefficients = r.ring_coeffs(context);
    const auto n = static_cast<std::size_t>(context.n());
    for (std::uint32_t plane = 0; plane < rp->prime_count(context); ++plane) {
        const auto& mont = context.plans_at(plane, 0).w_axis.mont;
        for (std::uint32_t lane = 0; lane < 2; ++lane) {
            auto* destination = rp->lane_ptr(context, plane, lane);
            const auto* multiplier = r.lane_ptr(context, plane, lane);
            for (std::size_t wx = 0; wx < rCoefficients; ++wx) {
                const auto factor =
                    glscheme::rns::glr_to_mont(mont, multiplier[wx]);
                auto* row = destination + wx * n;
                for (std::size_t y = 0; y < n; ++y) {
                    row[y] = glscheme::rns::glr_mont_mul(
                        mont, row[y], factor);
                }
            }
        }
    }
}

std::pair<glscheme::rns::GlrKskId, std::int32_t>
GLIntProductionGLRBridge::NormalizeFullChainSwitchKind(
    FullChainSwitchKind kind, std::int32_t amount) const {
    const auto& context = m_adapter->GetContext();
    const auto normalize = [](std::int32_t value, std::int32_t modulus) {
        auto normalized = value % modulus;
        return normalized < 0 ? normalized + modulus : normalized;
    };
    glscheme::rns::GlrKskId id;
    switch (kind) {
        case FullChainSwitchKind::Square:
            id.direction =
                glscheme::rns::GlrKsDirection::primary_sq_to_primary;
            break;
        case FullChainSwitchKind::ConjugationFamilySwap:
            id.direction =
                glscheme::rns::GlrKsDirection::conjugation_to_primary;
            break;
        case FullChainSwitchKind::RowRotation:
            amount = normalize(amount,
                               static_cast<std::int32_t>(context.n()));
            if (amount == 0) {
                throw GLDimensionError(
                    "full-chain row SwitchInt requires a nonzero amount");
            }
            id.direction = glscheme::rns::GlrKsDirection::row_rotation;
            id.amount = amount;
            break;
        case FullChainSwitchKind::InterMatrixRotation:
            amount = normalize(amount,
                               static_cast<std::int32_t>(context.phi()));
            if (amount == 0) {
                throw GLDimensionError(
                    "full-chain W SwitchInt requires a nonzero amount");
            }
            id.direction = glscheme::rns::GlrKsDirection::w_rotation;
            id.amount = amount;
            break;
        case FullChainSwitchKind::Transpose:
            id.direction =
                glscheme::rns::GlrKsDirection::transpose_to_primary;
            break;
        case FullChainSwitchKind::ConjugateTranspose:
            id.direction = glscheme::rns::GlrKsDirection::
                primary_conjtranspose_to_primary;
            break;
        case FullChainSwitchKind::ProductConjugateTranspose:
            id.direction = glscheme::rns::GlrKsDirection::
                primary_product_conjtranspose_to_primary;
            break;
    }
    if (kind != FullChainSwitchKind::RowRotation &&
        kind != FullChainSwitchKind::InterMatrixRotation && amount != 0) {
        throw GLDimensionError(
            "non-rotation full-chain SwitchInt key amount must be zero");
    }
    return {id, amount};
}

GlrPoly GLIntProductionGLRBridge::BuildFullChainSwitchSource(
    const OwnerBinding& owner, FullChainSwitchKind kind,
    std::int32_t amount, std::uint32_t keyLevel) const {
    const auto& context = m_adapter->GetContext();
    GlrPoly secret = glscheme::rns::glr_restrict_to_key_level(
        context, owner.GetNativeSecretKey().s, keyLevel);
    PolyWipe secretWipe(secret);
    switch (kind) {
        case FullChainSwitchKind::Square:
            return RingMultiply(secret, secret);
        case FullChainSwitchKind::ConjugationFamilySwap: {
            glscheme::rns::GlrCoeffAutomorphism automorphism;
            automorphism.x_alpha = -1;
            automorphism.w_alpha = -1;
            automorphism.conjugate = true;
            return glscheme::rns::glr_apply_coeff_automorphism(
                context, secret, automorphism);
        }
        case FullChainSwitchKind::RowRotation: {
            glscheme::rns::GlrCoeffAutomorphism automorphism;
            automorphism.x_alpha = static_cast<std::int64_t>(
                glscheme::rns::glr_powmod(5, amount,
                                           4ull * context.n()));
            return glscheme::rns::glr_apply_coeff_automorphism(
                context, secret, automorphism);
        }
        case FullChainSwitchKind::InterMatrixRotation: {
            glscheme::rns::GlrCoeffAutomorphism automorphism;
            automorphism.w_alpha = static_cast<std::int64_t>(
                glscheme::rns::glr_powmod(context.params.gamma, amount,
                                           context.p_()));
            return glscheme::rns::glr_apply_coeff_automorphism(
                context, secret, automorphism);
        }
        case FullChainSwitchKind::Transpose: {
            GlrPoly embedded = glscheme::rns::glr_embed_r_into(
                context, secret, GlrRing::Rp);
            PolyWipe embeddedWipe(embedded);
            glscheme::rns::GlrCoeffAutomorphism automorphism;
            automorphism.swap_xy = true;
            return glscheme::rns::glr_apply_coeff_automorphism(
                context, embedded, automorphism);
        }
        case FullChainSwitchKind::ConjugateTranspose:
        case FullChainSwitchKind::ProductConjugateTranspose: {
            GlrPoly embedded = glscheme::rns::glr_embed_r_into(
                context, secret, GlrRing::Rp);
            PolyWipe embeddedWipe(embedded);
            glscheme::rns::GlrCoeffAutomorphism automorphism;
            automorphism.x_alpha = -1;
            automorphism.w_alpha = -1;
            automorphism.swap_xy = true;
            automorphism.conjugate = true;
            GlrPoly conjugated =
                glscheme::rns::glr_apply_coeff_automorphism(
                    context, embedded, automorphism);
            if (kind == FullChainSwitchKind::ConjugateTranspose) {
                return conjugated;
            }
            PolyWipe conjugatedWipe(conjugated);
            return RingMultiply(embedded, conjugated);
        }
    }
    throw GLContextMismatchError("invalid full-chain SwitchInt source kind");
}

void GLIntProductionGLRBridge::ConvertSwitchKeyErrorsToTErr(
    glscheme::rns::GlrSwitchKey* key, const GlrPoly& source,
    const OwnerBinding& owner) const {
    const auto& context = m_adapter->GetContext();
    if (key == nullptr || key->special_prime_count != 0 ||
        key->key_level >= context.params.levels() ||
        source.ring != key->ring || source.level != key->key_level ||
        !source.extended || source.domain != GlrDomain::Coeff ||
        key->b_digits.size() != key->dnum ||
        key->a_digits.size() != key->dnum) {
        throw GLKeyContextMismatchError(
            "full-chain SwitchInt t*e conversion key/source mismatch");
    }
    GlrPoly destination = glscheme::rns::glr_restrict_to_key_level(
        context, owner.GetNativeSecretKey().s, key->key_level);
    PolyWipe destinationWipe(destination);
    if (key->ring != GlrRing::R) {
        GlrPoly embedded = glscheme::rns::glr_embed_r_into(
            context, destination, key->ring);
        PolyWipe embeddedWipe(embedded);
        destination.secure_clear();
        destination = std::move(embedded);
    }
    glscheme::rns::glr_to_slots(context, destination);
    const auto groups =
        glscheme::rns::glr_digit_groups(context.params, key->key_level);
    if (groups.size() != key->dnum) {
        throw GLKeyContextMismatchError(
            "full-chain SwitchInt key digit grouping mismatch");
    }
    const auto chainLength = context.params.levels();
    for (std::size_t digit = 0; digit < groups.size(); ++digit) {
        std::vector<std::uint64_t> gadget(
            chainLength + context.params.p_special.size(), 0);
        for (std::uint32_t q = groups[digit].first;
             q < groups[digit].second; ++q) {
            const auto modulus = context.params.q_chain[q].q;
            auto specialProduct = std::uint64_t{1};
            for (const auto& special : context.params.p_special) {
                specialProduct = glscheme::rns::glr_mulmod(
                    specialProduct, special.q % modulus, modulus);
            }
            gadget[q] = specialProduct;
        }

        GlrPoly residual = key->b_digits[digit];
        PolyWipe residualWipe(residual);
        GlrPoly product = key->a_digits[digit];
        PolyWipe productWipe(product);
        glscheme::rns::glr_mul_pointwise_inplace(
            context, product, destination);
        glscheme::rns::glr_add_inplace(context, residual, product);
        product.secure_clear();

        GlrPoly message = source;
        PolyWipe messageWipe(message);
        glscheme::rns::glr_residue_scalar_mul_inplace(
            context, message, gadget);
        glscheme::rns::glr_to_slots(context, message);
        glscheme::rns::glr_sub_inplace(context, residual, message);
        message.secure_clear();

        glscheme::rns::glr_scalar_mul_inplace(
            context, residual, 1579008);
        glscheme::rns::glr_add_inplace(
            context, key->b_digits[digit], residual);
    }
    key->key_error_sigma *= 1579009.0;
}

void GLIntProductionGLRBridge::AccumulateIntegerSwitchDigit(
    GlrPoly* b, GlrPoly* a, const GlrPoly& lifted,
    const glscheme::rns::GlrSwitchKey& key, std::size_t digit) const {
    const auto& context = m_adapter->GetContext();
    if (b == nullptr || a == nullptr || digit >= key.dnum ||
        b->domain != GlrDomain::Slot || a->domain != GlrDomain::Slot ||
        lifted.domain != GlrDomain::Slot || !b->extended || !a->extended ||
        !lifted.extended || b->level != lifted.level ||
        a->level != lifted.level || b->ring != key.ring ||
        a->ring != key.ring || lifted.ring != key.ring) {
        throw GLContextMismatchError(
            "full-chain SwitchInt digit accumulation shape mismatch");
    }
    const auto activeInputQ = context.active_q_primes(lifted.level);
    const auto activeKeyQ = context.active_q_primes(key.key_level);
    const auto coefficients = lifted.ring_coeffs(context);
    const auto planes = lifted.prime_count(context);
    for (std::uint32_t plane = 0; plane < planes; ++plane) {
        const auto chainIndex =
            plane < activeInputQ
                ? plane
                : static_cast<std::uint32_t>(context.params.levels() +
                                             plane - activeInputQ);
        const auto keyPlane =
            plane < activeInputQ
                ? plane
                : static_cast<std::uint32_t>(activeKeyQ +
                                             plane - activeInputQ);
        const auto modulus = context.modulus_at(chainIndex).q;
        const auto& mont = context.plans_at(chainIndex, 0).w_axis.mont;
        for (std::uint32_t lane = 0; lane < 2; ++lane) {
            const auto* input = lifted.lane_ptr(context, plane, lane);
            const auto* keyB =
                key.b_digits[digit].lane_ptr(context, keyPlane, lane);
            const auto* keyA =
                key.a_digits[digit].lane_ptr(context, keyPlane, lane);
            auto* outputB = b->lane_ptr(context, plane, lane);
            auto* outputA = a->lane_ptr(context, plane, lane);
            for (std::size_t coefficient = 0; coefficient < coefficients;
                 ++coefficient) {
                const auto factor =
                    glscheme::rns::glr_to_mont(mont, input[coefficient]);
                outputB[coefficient] = glscheme::rns::glr_mod_add(
                    outputB[coefficient],
                    glscheme::rns::glr_mont_mul(
                        mont, factor, keyB[coefficient]),
                    modulus);
                outputA[coefficient] = glscheme::rns::glr_mod_add(
                    outputA[coefficient],
                    glscheme::rns::glr_mont_mul(
                        mont, factor, keyA[coefficient]),
                    modulus);
            }
        }
    }
}

GlrPoly GLIntProductionGLRBridge::BGVModDownSpecialPoly(
    const GlrPoly& input) const {
    const auto& context = m_adapter->GetContext();
    if (!input.extended || input.active_special_prime_count(context) == 0) {
        throw GLContextMismatchError(
            "full-chain integer BGV ModDown requires an extended polynomial");
    }
    const auto originalDomain = input.domain;
    GlrPoly current = input;
    if (current.domain == GlrDomain::Slot) {
        glscheme::rns::glr_to_coeffs(context, current);
    }
    auto specialCount = current.active_special_prime_count(context);
    const auto activeQ = context.active_q_primes(current.level);
    constexpr std::uint64_t t = 1579009;
    while (specialCount != 0) {
        const auto droppedSpecial = specialCount - 1;
        const auto droppedPlane = activeQ + droppedSpecial;
        const auto& droppedModulus =
            context.params.p_special[droppedSpecial];
        const auto tInverse = glscheme::rns::glr_invmod(
            t % droppedModulus.q, droppedModulus.q);
        const bool remainsExtended = droppedSpecial != 0;
        GlrPoly output = GlrPoly::zero(
            context, current.ring, current.level, remainsExtended,
            GlrDomain::Coeff,
            remainsExtended ? droppedSpecial : std::uint32_t{0});
        const auto coefficients = current.ring_coeffs(context);
        for (std::size_t flat = 0; flat < coefficients; ++flat) {
            const auto dropped = GaussianAtFlat(
                context, current, droppedPlane, droppedModulus, flat);
            const auto correctionFor = [&](std::uint64_t value) {
                const auto product = glscheme::rns::glr_mulmod(
                    value, tInverse, droppedModulus.q);
                return CenterResidue(
                    product == 0 ? 0 : droppedModulus.q - product,
                    droppedModulus.q);
            };
            const auto realCorrection = correctionFor(dropped.first);
            const auto imaginaryCorrection = correctionFor(dropped.second);
            const auto survivingPlanes = activeQ + droppedSpecial;
            for (std::uint32_t plane = 0; plane < survivingPlanes; ++plane) {
                const auto chainIndex =
                    plane < activeQ
                        ? plane
                        : static_cast<std::uint32_t>(
                              context.params.levels() + plane - activeQ);
                const auto& modulus = context.modulus_at(chainIndex);
                const auto currentValue = GaussianAtFlat(
                    context, current, plane, modulus, flat);
                const auto dropInverse = glscheme::rns::glr_invmod(
                    droppedModulus.q % modulus.q, modulus.q);
                const auto reduce = [&](std::uint64_t value,
                                        std::int64_t correction) {
                    const auto tCorrection = glscheme::rns::glr_mulmod(
                        t % modulus.q, SignedMod(correction, modulus.q),
                        modulus.q);
                    const auto numerator = glscheme::rns::glr_mod_add(
                        value, tCorrection, modulus.q);
                    return glscheme::rns::glr_mulmod(
                        numerator, dropInverse, modulus.q);
                };
                SetGaussianAtFlat(
                    context, &output, plane, modulus, flat,
                    reduce(currentValue.first, realCorrection),
                    reduce(currentValue.second, imaginaryCorrection));
            }
        }
        current = std::move(output);
        --specialCount;
    }
    if (originalDomain == GlrDomain::Slot) {
        glscheme::rns::glr_to_slots(context, current);
    }
    return current;
}

GlrPoly GLIntProductionGLRBridge::BGVModSwitchPoly(
    const GlrPoly& input) const {
    const auto& context = m_adapter->GetContext();
    if (input.extended || input.level + 1 >= context.params.levels()) {
        throw GLDepthError(
            "full-chain integer BGV modulus-switch chain is exhausted");
    }
    const auto originalDomain = input.domain;
    GlrPoly coefficient = input;
    if (coefficient.domain == GlrDomain::Slot) {
        glscheme::rns::glr_to_coeffs(context, coefficient);
    }
    const auto active = context.active_q_primes(coefficient.level);
    const auto droppedIndex = active - 1;
    const auto& droppedModulus = context.params.q_chain[droppedIndex];
    GlrPoly out = GlrPoly::zero(context, coefficient.ring,
                                coefficient.level + 1, false,
                                GlrDomain::Coeff);
    const auto coefficients = coefficient.ring_coeffs(context);
    constexpr std::uint64_t t = 1579009;
    const auto tInverse = glscheme::rns::glr_invmod(
        t % droppedModulus.q, droppedModulus.q);
    std::vector<std::uint64_t> dropInverse(droppedIndex);
    for (std::uint32_t q = 0; q < droppedIndex; ++q) {
        dropInverse[q] = glscheme::rns::glr_invmod(
            droppedModulus.q % context.params.q_chain[q].q,
            context.params.q_chain[q].q);
    }
    for (std::size_t flat = 0; flat < coefficients; ++flat) {
        const auto dropped = GaussianAtFlat(
            context, coefficient, droppedIndex, droppedModulus, flat);
        const auto deltaFor = [&](std::uint64_t value) {
            const auto product = glscheme::rns::glr_mulmod(
                value, tInverse, droppedModulus.q);
            const auto residue =
                product == 0 ? 0 : droppedModulus.q - product;
            return CenterResidue(residue, droppedModulus.q);
        };
        const auto deltaReal = deltaFor(dropped.first);
        const auto deltaImaginary = deltaFor(dropped.second);
        for (std::uint32_t q = 0; q < droppedIndex; ++q) {
            const auto& modulus = context.params.q_chain[q];
            const auto current =
                GaussianAtFlat(context, coefficient, q, modulus, flat);
            const auto reduce = [&](std::uint64_t value,
                                    std::int64_t delta) {
                const auto correction = glscheme::rns::glr_mulmod(
                    t % modulus.q, SignedMod(delta, modulus.q), modulus.q);
                const auto numerator =
                    value + correction >= modulus.q
                        ? value + correction - modulus.q
                        : value + correction;
                return glscheme::rns::glr_mulmod(
                    numerator, dropInverse[q], modulus.q);
            };
            SetGaussianAtFlat(context, &out, q, modulus, flat,
                              reduce(current.first, deltaReal),
                              reduce(current.second, deltaImaginary));
        }
    }
    if (originalDomain == GlrDomain::Slot) {
        glscheme::rns::glr_to_slots(context, out);
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
    auto receipt = MakeReceipt(
        "legacy-bounded-Q2-owner-secret-full-QP-coefficient");
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

GLIntProductionGLRBridge::OwnerBinding
GLIntProductionGLRBridge::GenerateFullChainOwnerBinding(
    std::uint64_t seed) const {
    const auto& context = m_adapter->GetContext();
    GlrRngOwner rng(glscheme::rns::glr_rng_create(seed));
    if (!rng) {
        throw GlrError("full-chain integer owner-key RNG creation failed");
    }
    NativeSecretKey native =
        glscheme::rns::glr_keygen_primary(context, *rng);
    const auto primaryLineageCommitment =
        glscheme::rns::glr_ship_direct_primary_secret_lineage_commitment(
            context, native);
    if (!IsSha256Text(primaryLineageCommitment)) {
        native.secure_clear();
        throw GLKeyContextMismatchError(
            "full-chain integer owner key failed primary hash derivation");
    }
    auto receipt = MakeReceipt("owner-secret-full-QP-dense-ternary");
    receipt.schema = "openfhe.gl_int.glr_full_chain.v1";
    receipt.admissionRejection = kFullChainBootstrapRejection;
    receipt.nativeLevel = 0;
    receipt.activeQPrimes = context.params.levels();
    receipt.denseEq5Layout = true;
    receipt.tErrorInvariant = true;
    receipt.denseTernaryOwner = true;
    receipt.integerKeyTag =
        "gl-int-full-" + HashUtil::HashString(
            receipt.parameterFingerprint + '|' +
            primaryLineageCommitment);
    native.key_id = kUntrustedIntegerKeyDomain;
    receipt.nativeKeyLineageCommitment =
        DomainSeparatedFullChainIntegerLineage(
            receipt.parameterFingerprint, receipt.integerKeyTag,
            primaryLineageCommitment);
    receipt.ownerSecretLineageBound =
        IsSha256Text(receipt.nativeKeyLineageCommitment);
    if (!receipt.ownerSecretLineageBound) {
        native.secure_clear();
        throw GLKeyContextMismatchError(
            "full-chain integer owner key failed lineage derivation");
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
    const auto lineage =
        receipt.denseTernaryOwner
            ? DomainSeparatedFullChainIntegerLineage(
                  fingerprint, receipt.integerKeyTag,
                  owner.m_primaryLineageCommitment)
            : DomainSeparatedIntegerLineage(
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

GLIntProductionGLRBridge::NativePlaintext
GLIntProductionGLRBridge::EncodeDenseIntegerBatch(
    const DenseIntegerBatch& batch) const {
    batch.Validate();
    const auto& context = m_adapter->GetContext();
    GlrPoly plaintextModT = GlrPoly::zero(
        m_plaintextContext, GlrRing::Rp, 0, false, GlrDomain::Slot);
    const auto slotsPerLane = static_cast<std::size_t>(256) * 128 * 128;
    for (std::uint32_t lane = 0; lane < 2; ++lane) {
        auto* destination =
            plaintextModT.lane_ptr(m_plaintextContext, 0, lane);
        std::copy(batch.values.begin() + lane * slotsPerLane,
                  batch.values.begin() + (lane + 1) * slotsPerLane,
                  destination);
    }
    glscheme::rns::glr_to_coeffs(m_plaintextContext, plaintextModT);

    NativePlaintext output;
    output.poly = GlrPoly::zero(context, GlrRing::Rp, 0, false,
                                GlrDomain::Coeff);
    const auto& tModulus = m_plaintextContext.params.q_chain.front();
    const auto coefficients = output.poly.ring_coeffs(context);
    const auto n = static_cast<std::size_t>(context.n());
    for (std::size_t flat = 0; flat < coefficients; ++flat) {
        const auto gaussian = GaussianAtFlat(
            m_plaintextContext, plaintextModT, 0, tModulus, flat);
        const auto w = flat / (n * n);
        const auto remainder = flat % (n * n);
        const auto x = remainder / n;
        const auto y = remainder % n;
        glscheme::rns::glr_poly_set_gaussian(
            context, output.poly, static_cast<std::uint32_t>(x),
            static_cast<std::uint32_t>(y), static_cast<std::uint32_t>(w),
            CenterResidue(gaussian.first, tModulus.q),
            CenterResidue(gaussian.second, tModulus.q));
    }
    output.scale = 1.0;
    output.level = 0;
    return output;
}

GLIntProductionGLRBridge::CiphertextImport
GLIntProductionGLRBridge::EncryptFullChainSymmetric(
    const DenseIntegerBatch& batch, const OwnerBinding& owner,
    std::uint64_t seed) const {
    ValidateOwner(owner.GetReceipt().integerKeyTag, owner,
                  "full-chain integer symmetric encryption");
    const auto& context = m_adapter->GetContext();
    auto plaintext = EncodeDenseIntegerBatch(batch);
    GlrRngOwner rng(glscheme::rns::glr_rng_create(seed));
    if (!rng) {
        throw GlrError("full-chain integer encryption RNG creation failed");
    }
    GlrPoly a = GlrPoly::zero(context, GlrRing::Rp, 0, false,
                              GlrDomain::Coeff);
    glscheme::rns::glr_sample_uniform(context, a, *rng);
    GlrPoly secret = RestrictSecretToQ(owner.GetNativeSecretKey().s, 0);
    PolyWipe secretWipe(secret);
    GlrPoly embedded =
        glscheme::rns::glr_embed_r_into(context, secret, GlrRing::Rp);
    PolyWipe embeddedWipe(embedded);
    GlrPoly product = RingMultiply(a, embedded);
    PolyWipe productWipe(product);
    GlrPoly b = std::move(plaintext.poly);
    glscheme::rns::glr_sub_inplace(context, b, product);
    AddTErrInPlace(&b, *rng);
    glscheme::rns::glr_to_slots(context, b);
    glscheme::rns::glr_to_slots(context, a);

    CiphertextImport result;
    result.native.b = std::move(b);
    result.native.a = std::move(a);
    result.native.scale = 1.0;
    result.native.level = 0;
    result.native.key_id = kUntrustedIntegerKeyDomain;
    result.native.key_lineage_commitment =
        owner.GetReceipt().nativeKeyLineageCommitment;
    result.receipt = MakeReceipt("Q25-L0-dense-Eq5-integer-ciphertext");
    result.receipt.schema = "openfhe.gl_int.glr_full_chain.v1";
    result.receipt.admissionRejection =
        owner.GetReceipt().denseTernaryOwner
            ? kFullChainBootstrapRejection
            : kBootstrapRejection;
    result.receipt.requiredEvaluationKey = "none (fresh symmetric ciphertext)";
    result.receipt.plaintextScale = 1;
    result.receipt.nativeLevel = 0;
    result.receipt.activeQPrimes = context.params.levels();
    result.receipt.denseEq5Layout = true;
    result.receipt.tErrorInvariant = true;
    result.receipt.denseTernaryOwner =
        owner.GetReceipt().denseTernaryOwner;
    result.receipt.integerKeyTag = owner.GetReceipt().integerKeyTag;
    result.receipt.nativeKeyLineageCommitment =
        owner.GetReceipt().nativeKeyLineageCommitment;
    result.receipt.ownerSecretLineageBound = true;
    return result;
}

GLIntProductionGLRBridge::IntegerPublicKey
GLIntProductionGLRBridge::GenerateFullChainPublicKey(
    const OwnerBinding& owner, std::uint64_t seed) const {
    ValidateOwner(owner.GetReceipt().integerKeyTag, owner,
                  "full-chain integer public-key generation");
    const auto& context = m_adapter->GetContext();
    GlrRngOwner ownerRng(glscheme::rns::glr_rng_create(seed));
    if (!ownerRng) {
        throw GlrError("full-chain integer public-key RNG creation failed");
    }
    glscheme::rns::GlrPublicASeed publicASeed{};
    glscheme::rns::glr_rng_fill_bytes(
        *ownerRng, publicASeed.data(), publicASeed.size());
    GlrRngOwner publicARng(
        glscheme::rns::glr_rng_create_from_key(publicASeed));
    if (!publicARng) {
        throw GlrError(
            "full-chain integer public-a expansion RNG creation failed");
    }
    GlrPoly a = GlrPoly::zero(context, GlrRing::R, 0, false,
                              GlrDomain::Coeff);
    glscheme::rns::glr_sample_uniform(context, a, *publicARng);
    GlrPoly secret = RestrictSecretToQ(owner.GetNativeSecretKey().s, 0);
    PolyWipe secretWipe(secret);
    GlrPoly b = RingMultiply(a, secret);
    glscheme::rns::glr_neg_inplace(context, b);
    AddTErrInPlace(&b, *ownerRng);
    glscheme::rns::glr_to_slots(context, b);
    return IntegerPublicKey(
        std::move(b), std::move(publicASeed),
        glscheme::rns::glr_parameter_fingerprint(context.params),
        owner.GetReceipt().integerKeyTag,
        owner.GetReceipt().nativeKeyLineageCommitment,
        owner.GetReceipt().denseTernaryOwner);
}

GLIntProductionGLRBridge::CiphertextImport
GLIntProductionGLRBridge::EncryptFullChainPublic(
    const DenseIntegerBatch& batch, const IntegerPublicKey& publicKey,
    std::uint64_t seed) const {
    const auto& context = m_adapter->GetContext();
    if (publicKey.m_parameterFingerprint !=
            glscheme::rns::glr_parameter_fingerprint(context.params) ||
        publicKey.m_integerKeyTag.empty() ||
        !IsSha256Text(publicKey.m_nativeKeyLineageCommitment) ||
        publicKey.m_b.ring != GlrRing::R ||
        publicKey.m_b.domain != GlrDomain::Slot ||
        publicKey.m_b.level != 0 || publicKey.m_b.extended ||
        publicKey.m_b.prime_count(context) != context.params.levels()) {
        throw GLKeyContextMismatchError(
            "full-chain integer public encryption key mismatch");
    }
    auto plaintext = EncodeDenseIntegerBatch(batch);
    GlrRngOwner encryptionRng(glscheme::rns::glr_rng_create(seed));
    if (!encryptionRng) {
        throw GlrError("full-chain integer public encryption RNG creation failed");
    }
    GlrRngOwner publicARng(
        glscheme::rns::glr_rng_create_from_key(publicKey.m_publicASeed));
    if (!publicARng) {
        throw GlrError(
            "full-chain integer public-a expansion RNG creation failed");
    }
    GlrPoly publicA = GlrPoly::zero(context, GlrRing::R, 0, false,
                                    GlrDomain::Coeff);
    glscheme::rns::glr_sample_uniform(context, publicA, *publicARng);
    glscheme::rns::glr_to_slots(context, publicA);

    GlrPoly ternary = SampleTernaryRp(0, *encryptionRng);
    PolyWipe ternaryWipe(ternary);
    glscheme::rns::glr_to_slots(context, ternary);
    GlrPoly a = ternary;
    GlrPoly b = std::move(ternary);
    MultiplyRpByRInSlots(&b, publicKey.m_b);
    MultiplyRpByRInSlots(&a, publicA);
    glscheme::rns::glr_to_coeffs(context, b);
    glscheme::rns::glr_to_coeffs(context, a);
    glscheme::rns::glr_add_inplace(context, b, plaintext.poly);
    AddTErrInPlace(&b, *encryptionRng);
    AddTErrInPlace(&a, *encryptionRng);
    glscheme::rns::glr_to_slots(context, b);
    glscheme::rns::glr_to_slots(context, a);

    CiphertextImport result;
    result.native.b = std::move(b);
    result.native.a = std::move(a);
    result.native.scale = 1.0;
    result.native.level = 0;
    result.native.key_id = kUntrustedIntegerKeyDomain;
    result.native.key_lineage_commitment =
        publicKey.m_nativeKeyLineageCommitment;
    result.receipt = MakeReceipt(
        "Q25-L0-dense-Eq5-public-integer-ciphertext");
    result.receipt.schema = "openfhe.gl_int.glr_full_chain.v1";
    result.receipt.admissionRejection =
        publicKey.m_denseTernaryOwner
            ? kFullChainBootstrapRejection
            : kBootstrapRejection;
    result.receipt.requiredEvaluationKey =
        "none (fresh compact-public-key ciphertext)";
    result.receipt.plaintextScale = 1;
    result.receipt.nativeLevel = 0;
    result.receipt.activeQPrimes = context.params.levels();
    result.receipt.denseEq5Layout = true;
    result.receipt.tErrorInvariant = true;
    result.receipt.denseTernaryOwner = publicKey.m_denseTernaryOwner;
    result.receipt.integerKeyTag = publicKey.m_integerKeyTag;
    result.receipt.nativeKeyLineageCommitment =
        publicKey.m_nativeKeyLineageCommitment;
    result.receipt.ownerSecretLineageBound = true;
    return result;
}

GLIntProductionGLRBridge::FullChainIntegerSwitchKey
GLIntProductionGLRBridge::GenerateFullChainIntegerSwitchKey(
    const OwnerBinding& owner, FullChainSwitchKind kind,
    std::int32_t amount, std::uint32_t keyLevel,
    std::uint64_t seed) const {
    ValidateOwner(owner.GetReceipt().integerKeyTag, owner,
                  "full-chain SwitchInt key generation");
    const auto& context = m_adapter->GetContext();
    if (keyLevel >= context.params.levels()) {
        throw GLDepthError(
            "full-chain SwitchInt key level is outside the modulus chain");
    }
    const auto normalized = NormalizeFullChainSwitchKind(kind, amount);
    amount = normalized.second;
    GlrRngOwner rng(glscheme::rns::glr_rng_create(seed));
    if (!rng) {
        throw GlrError("full-chain SwitchInt key RNG creation failed");
    }
    GlrPoly source =
        BuildFullChainSwitchSource(owner, kind, amount, keyLevel);
    PolyWipe sourceWipe(source);
    auto native = glscheme::rns::glr_make_switch_key(
        context, std::move(source), owner.GetNativeSecretKey().s,
        normalized.first, 3.2, *rng, keyLevel);

    GlrPoly conversionSource =
        BuildFullChainSwitchSource(owner, kind, amount, keyLevel);
    PolyWipe conversionSourceWipe(conversionSource);
    ConvertSwitchKeyErrorsToTErr(&native, conversionSource, owner);
    return FullChainIntegerSwitchKey(
        kind, amount, std::move(native),
        static_cast<std::uint32_t>(context.params.p_special.size()),
        owner.GetReceipt().nativeKeyLineageCommitment,
        owner.GetReceipt().denseTernaryOwner);
}

GLIntProductionGLRBridge::IntegerSwitchResult
GLIntProductionGLRBridge::ApplyFullChainIntegerSwitch(
    const GlrPoly& input,
    const FullChainIntegerSwitchKey& evaluationKey) const {
    const auto& context = m_adapter->GetContext();
    const auto& key = evaluationKey.m_native;
    const auto normalized = NormalizeFullChainSwitchKind(
        evaluationKey.m_kind, evaluationKey.m_amount);
    if (input.ring != key.ring || input.extended ||
        input.level < key.key_level ||
        input.level >= context.params.levels() || key.special_prime_count != 0 ||
        key.parameter_fingerprint !=
            glscheme::rns::glr_parameter_fingerprint(context.params) ||
        !(key.id == normalized.first) || key.dnum == 0 ||
        key.b_digits.size() != key.dnum ||
        key.a_digits.size() != key.dnum ||
        !key.public_a_seed.has_value() ||
        !IsSha256Text(evaluationKey.m_nativeKeyLineageCommitment) ||
        !key.digit_group_override.empty()) {
        throw GLKeyContextMismatchError(
            "full-chain SwitchInt input/key metadata mismatch");
    }
    const auto groups =
        glscheme::rns::glr_digit_groups(context.params, input.level);
    if (groups.empty() || groups.size() > key.dnum) {
        throw GLDepthError(
            "full-chain SwitchInt key does not cover the active digit groups");
    }
    for (std::size_t digit = 0; digit < key.dnum; ++digit) {
        for (const auto* polynomial :
             {&key.b_digits[digit], &key.a_digits[digit]}) {
            if (polynomial->ring != key.ring ||
                polynomial->domain != GlrDomain::Slot ||
                polynomial->level != key.key_level ||
                !polynomial->extended ||
                polynomial->active_special_prime_count(context) !=
                    context.params.p_special.size()) {
                throw GLKeyContextMismatchError(
                    "full-chain SwitchInt key digit shape mismatch");
            }
        }
    }

    const auto originalDomain = input.domain;
    GlrPoly coefficient = input;
    if (coefficient.domain == GlrDomain::Slot) {
        glscheme::rns::glr_to_coeffs(context, coefficient);
    }
    GlrPoly b = GlrPoly::zero(context, key.ring, input.level, true,
                              GlrDomain::Slot);
    GlrPoly a = GlrPoly::zero(context, key.ring, input.level, true,
                              GlrDomain::Slot);
    for (std::size_t digit = 0; digit < groups.size(); ++digit) {
        GlrPoly lifted = glscheme::rns::glr_mod_up(
            context, coefficient, groups[digit].first,
            groups[digit].second);
        glscheme::rns::glr_to_slots(context, lifted);
        AccumulateIntegerSwitchDigit(&b, &a, lifted, key, digit);
    }
    glscheme::rns::glr_to_coeffs(context, b);
    glscheme::rns::glr_to_coeffs(context, a);
    b = BGVModDownSpecialPoly(b);
    a = BGVModDownSpecialPoly(a);
    if (originalDomain == GlrDomain::Slot) {
        glscheme::rns::glr_to_slots(context, b);
        glscheme::rns::glr_to_slots(context, a);
    }
    return {std::move(b), std::move(a)};
}

glscheme::rns::GlrCompactSwitchKey
GLIntProductionGLRBridge::CompactFullChainIntegerSwitchKey(
    const FullChainIntegerSwitchKey& evaluationKey) const {
    const auto& context = m_adapter->GetContext();
    if (evaluationKey.m_native.parameter_fingerprint !=
            glscheme::rns::glr_parameter_fingerprint(context.params) ||
        !evaluationKey.m_native.public_a_seed.has_value() ||
        !IsSha256Text(evaluationKey.m_nativeKeyLineageCommitment)) {
        throw GLKeyContextMismatchError(
            "full-chain SwitchInt compaction key metadata mismatch");
    }
    return glscheme::rns::glr_compress_switch_key(
        context, evaluationKey.m_native);
}

GLIntProductionGLRBridge::FullChainIntegerSwitchKey
GLIntProductionGLRBridge::RestoreFullChainIntegerSwitchKey(
    FullChainSwitchKind kind, std::int32_t amount,
    const glscheme::rns::GlrCompactSwitchKey& compact,
    const Receipt& ownerReceipt) const {
    const auto& context = m_adapter->GetContext();
    const auto fingerprint =
        glscheme::rns::glr_parameter_fingerprint(context.params);
    if (!IsCanonicalFullChainReceipt(context, ownerReceipt) ||
        !IsFullChainIntegerKeyTag(ownerReceipt.integerKeyTag)) {
        throw GLKeyContextMismatchError(
            "full-chain SwitchInt restore owner receipt mismatch");
    }
    const auto normalized = NormalizeFullChainSwitchKind(kind, amount);
    amount = normalized.second;
    auto native =
        glscheme::rns::glr_expand_switch_key(context, compact);
    if (!(native.id == normalized.first) ||
        native.parameter_fingerprint != fingerprint ||
        native.special_prime_count != 0 ||
        native.key_error_sigma < 1579009.0 ||
        !native.public_a_seed.has_value()) {
        throw GLKeyContextMismatchError(
            "restored full-chain SwitchInt key is not an integer t*e key");
    }
    const auto activeSpecials =
        native.special_prime_count == 0
            ? static_cast<std::uint32_t>(context.params.p_special.size())
            : native.special_prime_count;
    return FullChainIntegerSwitchKey(
        kind, amount, std::move(native), activeSpecials,
        ownerReceipt.nativeKeyLineageCommitment,
        ownerReceipt.denseTernaryOwner);
}

std::uint64_t GLIntProductionGLRBridge::ValidateFullChainCiphertext(
    const NativeCiphertext& ciphertext, const char* operation) const {
    const auto& context = m_adapter->GetContext();
    if (ciphertext.level >= context.params.levels()) {
        throw GLContextMismatchError(
            std::string(operation) +
            " ciphertext level is outside the full integer chain");
    }
    const auto expectedWords =
        static_cast<std::size_t>(context.active_q_primes(ciphertext.level)) *
        2 * context.params.coeffs_Rp();
    if (ciphertext.key_id != kUntrustedIntegerKeyDomain ||
        !IsSha256Text(ciphertext.key_lineage_commitment) ||
        ciphertext.b.ring != GlrRing::Rp ||
        ciphertext.a.ring != GlrRing::Rp ||
        ciphertext.b.domain != GlrDomain::Slot ||
        ciphertext.a.domain != GlrDomain::Slot || ciphertext.b.extended ||
        ciphertext.a.extended || ciphertext.b.level != ciphertext.level ||
        ciphertext.a.level != ciphertext.level ||
        ciphertext.b.data.size() != expectedWords ||
        ciphertext.a.data.size() != expectedWords) {
        throw GLContextMismatchError(
            std::string(operation) +
            " requires an authentic full-chain integer Slot ciphertext");
    }
    return RequireIntegerScale(ciphertext.scale, 1579009);
}

GLIntProductionGLRBridge::IntegerSwitchResult
GLIntProductionGLRBridge::ApplyFullChainIntegerSwitchToRp(
    const GlrPoly& input,
    const FullChainIntegerSwitchKey& evaluationKey) const {
    const auto& context = m_adapter->GetContext();
    if (input.ring != GlrRing::Rp || input.extended ||
        input.level >= context.params.levels()) {
        throw GLContextMismatchError(
            "full-chain Rp SwitchInt received invalid input");
    }
    if (evaluationKey.m_native.ring == GlrRing::Rp) {
        return ApplyFullChainIntegerSwitch(input, evaluationKey);
    }
    if (evaluationKey.m_native.ring != GlrRing::R) {
        throw GLKeyContextMismatchError(
            "full-chain Rp SwitchInt accepts only small-R or big-Rp keys");
    }
    const auto originalDomain = input.domain;
    GlrPoly coefficient = input;
    if (coefficient.domain == GlrDomain::Slot) {
        glscheme::rns::glr_to_coeffs(context, coefficient);
    }
    GlrPoly b = GlrPoly::zero(context, GlrRing::Rp, input.level, false,
                              GlrDomain::Coeff);
    GlrPoly a = GlrPoly::zero(context, GlrRing::Rp, input.level, false,
                              GlrDomain::Coeff);
    for (std::uint32_t y = 0; y < context.n(); ++y) {
        GlrPoly slice =
            glscheme::rns::glr_extract_y_slice(context, coefficient, y);
        auto switched =
            ApplyFullChainIntegerSwitch(slice, evaluationKey);
        glscheme::rns::glr_insert_y_slice(context, b, switched.b, y);
        glscheme::rns::glr_insert_y_slice(context, a, switched.a, y);
    }
    if (originalDomain == GlrDomain::Slot) {
        glscheme::rns::glr_to_slots(context, b);
        glscheme::rns::glr_to_slots(context, a);
    }
    return {std::move(b), std::move(a)};
}

GLIntProductionGLRBridge::NativeCiphertext
GLIntProductionGLRBridge::EvaluateFullChainIntegerAutomorphism(
    const NativeCiphertext& ciphertext,
    const FullChainIntegerSwitchKey& evaluationKey) const {
    static_cast<void>(ValidateFullChainCiphertext(
        ciphertext, "full-chain integer automorphism"));
    if (ciphertext.key_lineage_commitment !=
        evaluationKey.m_nativeKeyLineageCommitment) {
        throw GLKeyContextMismatchError(
            "full-chain integer automorphism key lineage mismatch");
    }
    const auto& context = m_adapter->GetContext();
    glscheme::rns::GlrSlotAutomorphism automorphism;
    switch (evaluationKey.m_kind) {
        case FullChainSwitchKind::ConjugationFamilySwap:
            automorphism = glscheme::rns::glr_slot_automorphism_for(
                context, 0, 0, 0, false, true);
            break;
        case FullChainSwitchKind::RowRotation:
            automorphism = glscheme::rns::glr_slot_automorphism_for(
                context, evaluationKey.m_amount, 0, 0, false, false);
            break;
        case FullChainSwitchKind::InterMatrixRotation:
            automorphism = glscheme::rns::glr_slot_automorphism_for(
                context, 0, 0, evaluationKey.m_amount, false, false);
            break;
        case FullChainSwitchKind::Transpose:
            automorphism = glscheme::rns::glr_slot_automorphism_for(
                context, 0, 0, 0, true, false);
            break;
        case FullChainSwitchKind::ConjugateTranspose:
            automorphism = glscheme::rns::glr_slot_automorphism_for(
                context, 0, 0, 0, true, true);
            break;
        case FullChainSwitchKind::Square:
        case FullChainSwitchKind::ProductConjugateTranspose:
            throw GLKeyContextMismatchError(
                "full-chain integer automorphism received a relinearization key");
    }

    NativeCiphertext output = ciphertext;
    output.b = glscheme::rns::glr_apply_slot_automorphism(
        context, ciphertext.b, automorphism);
    output.a = glscheme::rns::glr_apply_slot_automorphism(
        context, ciphertext.a, automorphism);
    auto switched =
        ApplyFullChainIntegerSwitchToRp(output.a, evaluationKey);
    glscheme::rns::glr_add_inplace(context, output.b, switched.b);
    output.a = std::move(switched.a);
    return output;
}

GLIntProductionGLRBridge::NativeCiphertext
GLIntProductionGLRBridge::RotateFullChainIntegerColumns(
    const NativeCiphertext& ciphertext, std::int32_t amount) const {
    static_cast<void>(ValidateFullChainCiphertext(
        ciphertext, "full-chain integer column rotation"));
    const auto& context = m_adapter->GetContext();
    amount %= static_cast<std::int32_t>(context.n());
    if (amount < 0) {
        amount += static_cast<std::int32_t>(context.n());
    }
    const auto automorphism = glscheme::rns::glr_slot_automorphism_for(
        context, 0, amount, 0, false, false);
    NativeCiphertext output = ciphertext;
    output.b = glscheme::rns::glr_apply_slot_automorphism(
        context, ciphertext.b, automorphism);
    output.a = glscheme::rns::glr_apply_slot_automorphism(
        context, ciphertext.a, automorphism);
    return output;
}

GLIntProductionGLRBridge::NativeCiphertext
GLIntProductionGLRBridge::EvaluateFullChainIntegerHadamard(
    const NativeCiphertext& lhs, const NativeCiphertext& rhs,
    const FullChainIntegerSwitchKey& squareKey) const {
    const auto lhsScale =
        ValidateFullChainCiphertext(lhs, "full-chain integer Hadamard");
    const auto rhsScale =
        ValidateFullChainCiphertext(rhs, "full-chain integer Hadamard");
    if (lhs.level != rhs.level ||
        lhs.key_lineage_commitment != rhs.key_lineage_commitment ||
        squareKey.m_kind != FullChainSwitchKind::Square ||
        squareKey.m_nativeKeyLineageCommitment !=
            lhs.key_lineage_commitment) {
        throw GLKeyContextMismatchError(
            "full-chain integer Hadamard operand/key mismatch");
    }
    const auto& context = m_adapter->GetContext();
    GlrPoly d0 = lhs.b;
    glscheme::rns::glr_mul_pointwise_inplace(context, d0, rhs.b);
    GlrPoly d1 = lhs.b;
    glscheme::rns::glr_mul_pointwise_inplace(context, d1, rhs.a);
    GlrPoly cross = lhs.a;
    glscheme::rns::glr_mul_pointwise_inplace(context, cross, rhs.b);
    glscheme::rns::glr_add_inplace(context, d1, cross);
    GlrPoly d2 = lhs.a;
    glscheme::rns::glr_mul_pointwise_inplace(context, d2, rhs.a);
    auto switched = ApplyFullChainIntegerSwitchToRp(d2, squareKey);
    glscheme::rns::glr_add_inplace(context, d0, switched.b);
    glscheme::rns::glr_add_inplace(context, d1, switched.a);

    NativeCiphertext output;
    output.b = std::move(d0);
    output.a = std::move(d1);
    output.scale = static_cast<double>(glscheme::rns::glr_mulmod(
        lhsScale, rhsScale, 1579009));
    output.level = lhs.level;
    output.key_id = kUntrustedIntegerKeyDomain;
    output.key_lineage_commitment = lhs.key_lineage_commitment;
    return output;
}

GLIntProductionGLRBridge::NativeCiphertext
GLIntProductionGLRBridge::NegateFullChain(
    const NativeCiphertext& ciphertext) const {
    static_cast<void>(ValidateFullChainCiphertext(
        ciphertext, "full-chain integer negation"));
    return glscheme::rns::glr_ct_neg(
        m_adapter->GetContext(), ciphertext);
}

GLIntProductionGLRBridge::NativeCiphertext
GLIntProductionGLRBridge::EvaluateFullChainIntegerTrace(
    const NativeCiphertext& lhs, const NativeCiphertext& rhs,
    const FullChainIntegerSwitchKey& conjugatedRightKey,
    const FullChainIntegerSwitchKey& productKey,
    glscheme::rns::GlrGemmKind gemmKind) const {
    const auto lhsScale =
        ValidateFullChainCiphertext(lhs, "full-chain integer trace product");
    const auto rhsScale =
        ValidateFullChainCiphertext(rhs, "full-chain integer trace product");
    if (lhs.level != rhs.level ||
        lhs.key_lineage_commitment != rhs.key_lineage_commitment ||
        conjugatedRightKey.m_kind !=
            FullChainSwitchKind::ConjugateTranspose ||
        productKey.m_kind !=
            FullChainSwitchKind::ProductConjugateTranspose ||
        conjugatedRightKey.m_nativeKeyLineageCommitment !=
            lhs.key_lineage_commitment ||
        productKey.m_nativeKeyLineageCommitment !=
            lhs.key_lineage_commitment) {
        throw GLKeyContextMismatchError(
            "full-chain integer trace operand/key mismatch");
    }
    const auto& context = m_adapter->GetContext();
    const auto& gemm = glscheme::rns::glr_gemm_backend(gemmKind);
    GlrPoly outputB =
        glscheme::rns::glr_circledast(context, lhs.b, rhs.b, gemm);
    GlrPoly outputA =
        glscheme::rns::glr_circledast(context, lhs.a, rhs.b, gemm);
    {
        GlrPoly d1 =
            glscheme::rns::glr_circledast(context, lhs.b, rhs.a, gemm);
        auto switched = ApplyFullChainIntegerSwitchToRp(
            d1, conjugatedRightKey);
        glscheme::rns::glr_add_inplace(context, outputB, switched.b);
        glscheme::rns::glr_add_inplace(context, outputA, switched.a);
    }
    {
        GlrPoly d3 =
            glscheme::rns::glr_circledast(context, lhs.a, rhs.a, gemm);
        auto switched =
            ApplyFullChainIntegerSwitchToRp(d3, productKey);
        glscheme::rns::glr_add_inplace(context, outputB, switched.b);
        glscheme::rns::glr_add_inplace(context, outputA, switched.a);
    }

    auto scale = glscheme::rns::glr_mulmod(lhsScale, rhsScale, 1579009);
    scale = glscheme::rns::glr_mulmod(scale, context.n(), 1579009);
    NativeCiphertext output;
    output.b = std::move(outputB);
    output.a = std::move(outputA);
    output.scale = static_cast<double>(scale);
    output.level = lhs.level;
    output.key_id = kUntrustedIntegerKeyDomain;
    output.key_lineage_commitment = lhs.key_lineage_commitment;
    return output;
}

GLIntProductionGLRBridge::Receipt
GLIntProductionGLRBridge::InspectFullChainCiphertext(
    const NativeCiphertext& ciphertext) const {
    const auto scale = ValidateFullChainCiphertext(
        ciphertext, "full-chain integer ciphertext inspection");
    const auto& context = m_adapter->GetContext();
    auto receipt = MakeReceipt(
        "Q" + std::to_string(context.active_q_primes(ciphertext.level)) +
        "-L" + std::to_string(ciphertext.level) +
        "-dense-Eq5-m-plus-tE");
    receipt.schema = "openfhe.gl_int.glr_full_chain.v1";
    receipt.admissionRejection = kFullChainBootstrapRejection;
    receipt.requiredEvaluationKey =
        "operation-specific FullChainIntegerSwitchKey with identical lineage "
        "and keyLevel <= ciphertext level";
    receipt.plaintextScale = scale;
    receipt.nativeLevel = ciphertext.level;
    receipt.activeQPrimes =
        context.active_q_primes(ciphertext.level);
    receipt.nativeKeyLineageCommitment =
        ciphertext.key_lineage_commitment;
    receipt.exactModuloT = true;
    receipt.denseEq5Layout = true;
    receipt.tErrorInvariant = true;
    receipt.ownerSecretLineageBound = true;
    receipt.denseTernaryOwner = true;
    return receipt;
}

GLIntProductionGLRBridge::DenseIntegerBatch
GLIntProductionGLRBridge::DecryptDecodeFullChain(
    const NativeCiphertext& ciphertext, const OwnerBinding& owner) const {
    ValidateOwner(owner.GetReceipt().integerKeyTag, owner,
                  "full-chain integer decryption");
    const auto& context = m_adapter->GetContext();
    if (ciphertext.key_id != kUntrustedIntegerKeyDomain ||
        ciphertext.key_lineage_commitment !=
            owner.GetReceipt().nativeKeyLineageCommitment ||
        ciphertext.b.ring != GlrRing::Rp ||
        ciphertext.a.ring != GlrRing::Rp || ciphertext.b.extended ||
        ciphertext.a.extended || ciphertext.b.level != ciphertext.level ||
        ciphertext.a.level != ciphertext.level ||
        ciphertext.b.domain != ciphertext.a.domain ||
        ciphertext.level >= context.params.levels()) {
        throw GLContextMismatchError(
            "full-chain integer decryption ciphertext metadata mismatch");
    }
    const auto scale = RequireIntegerScale(ciphertext.scale, 1579009);
    const auto inverseScale =
        glscheme::rns::glr_invmod(scale, 1579009);
    GlrPoly secret =
        RestrictSecretToQ(owner.GetNativeSecretKey().s, ciphertext.level);
    PolyWipe secretWipe(secret);
    GlrPoly embedded =
        glscheme::rns::glr_embed_r_into(context, secret, GlrRing::Rp);
    PolyWipe embeddedWipe(embedded);
    GlrPoly product = RingMultiply(ciphertext.a, embedded);
    PolyWipe productWipe(product);
    GlrPoly relation = ciphertext.b;
    if (relation.domain == GlrDomain::Slot) {
        glscheme::rns::glr_to_coeffs(context, relation);
    }
    glscheme::rns::glr_add_inplace(context, relation, product);

    GlrPoly plaintextModT = GlrPoly::zero(
        m_plaintextContext, GlrRing::Rp, 0, false, GlrDomain::Coeff);
    const auto& q0 = context.params.q_chain.front();
    const auto& tModulus = m_plaintextContext.params.q_chain.front();
    const auto coefficients = relation.ring_coeffs(context);
    for (std::size_t flat = 0; flat < coefficients; ++flat) {
        const auto gaussian = GaussianAtFlat(context, relation, 0, q0, flat);
        const auto reduce = [&](std::uint64_t value) {
            const auto centered = CenterResidue(value, q0.q);
            return glscheme::rns::glr_mulmod(
                SignedMod(centered, 1579009), inverseScale, 1579009);
        };
        SetGaussianAtFlat(m_plaintextContext, &plaintextModT, 0, tModulus,
                          flat, reduce(gaussian.first),
                          reduce(gaussian.second));
    }
    glscheme::rns::glr_to_slots(m_plaintextContext, plaintextModT);
    DenseIntegerBatch output;
    output.values.resize(kDenseIntegerSlotCount);
    const auto slotsPerLane = static_cast<std::size_t>(256) * 128 * 128;
    for (std::uint32_t lane = 0; lane < 2; ++lane) {
        const auto* source =
            plaintextModT.lane_ptr(m_plaintextContext, 0, lane);
        std::copy(source, source + slotsPerLane,
                  output.values.begin() + lane * slotsPerLane);
    }
    output.Validate();
    return output;
}

GLIntProductionGLRBridge::NativeCiphertext
GLIntProductionGLRBridge::ModSwitchFullChain(
    const NativeCiphertext& ciphertext) const {
    const auto& context = m_adapter->GetContext();
    if (ciphertext.key_id != kUntrustedIntegerKeyDomain ||
        !IsSha256Text(ciphertext.key_lineage_commitment) ||
        ciphertext.b.ring != GlrRing::Rp ||
        ciphertext.a.ring != GlrRing::Rp || ciphertext.b.extended ||
        ciphertext.a.extended || ciphertext.b.level != ciphertext.level ||
        ciphertext.a.level != ciphertext.level ||
        ciphertext.b.domain != ciphertext.a.domain ||
        ciphertext.level + 1 >= context.params.levels()) {
        throw GLContextMismatchError(
            "full-chain integer ModSwitch ciphertext metadata mismatch");
    }
    const auto scale = RequireIntegerScale(ciphertext.scale, 1579009);
    const auto active = context.active_q_primes(ciphertext.level);
    const auto dropped = context.params.q_chain[active - 1].q;
    NativeCiphertext output = ciphertext;
    output.b = BGVModSwitchPoly(ciphertext.b);
    output.a = BGVModSwitchPoly(ciphertext.a);
    ++output.level;
    output.scale = static_cast<double>(glscheme::rns::glr_mulmod(
        scale, glscheme::rns::glr_invmod(dropped % 1579009, 1579009),
        1579009));
    return output;
}

void GLIntProductionGLRBridge::RequireBootstrapDirectAdmission(
    const Receipt& receipt) const {
    const auto& context = m_adapter->GetContext();
    const bool q2Receipt =
        IsCanonicalLegacyQ2Receipt(context, m_q2Level, receipt);
    const bool fullChainReceipt =
        IsCanonicalFullChainReceipt(context, receipt);
    if (!q2Receipt && !fullChainReceipt) {
        throw GLContextMismatchError(
            "malformed GL integer bridge receipt at bootstrap admission");
    }
    throw GlrError(fullChainReceipt ? kFullChainBootstrapRejection
                                    : kBootstrapRejection);
}

void GLIntProductionGLRBridge::RequireProductionSecurityAuthorization(
    const Receipt& receipt) const {
    const auto& context = m_adapter->GetContext();
    const bool q2Receipt =
        IsCanonicalLegacyQ2Receipt(context, m_q2Level, receipt);
    const bool fullChainReceipt =
        IsCanonicalFullChainReceipt(context, receipt);
    if (!q2Receipt && !fullChainReceipt) {
        throw GLContextMismatchError(
            "malformed GL integer bridge receipt at security admission");
    }
    throw GlrError(fullChainReceipt ? kFullChainSecurityRejection
                                    : kSecurityRejection);
}

}  // namespace lbcrypto
