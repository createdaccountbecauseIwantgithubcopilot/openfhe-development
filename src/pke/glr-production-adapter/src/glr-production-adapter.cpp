#include "openfhe/pke/glr-production-adapter.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {
namespace {

using glscheme::rns::GlrError;
using glscheme::rns::GlrRng;
using glscheme::rns::GlrDomain;
using glscheme::rns::GlrKskId;
using glscheme::rns::GlrKsDirection;
using glscheme::rns::GlrPoly;
using glscheme::rns::GlrRing;

struct GlrRngDeleter {
    void operator()(GlrRng* rng) const noexcept {
        if (rng != nullptr) {
            glscheme::rns::glr_rng_destroy(rng);
        }
    }
};

using GlrRngOwner = std::unique_ptr<GlrRng, GlrRngDeleter>;

GlrRngOwner MakeRng(std::uint64_t seed) {
    GlrRngOwner rng(glscheme::rns::glr_rng_create(seed));
    if (!rng) {
        throw GlrError("GLRProductionAdapter: GLScheme RNG creation failed");
    }
    return rng;
}

void RequireCanonicalBatch(const GLRProductionAdapter::MatrixBatch& matrices) {
    constexpr std::uint32_t kN = 128;
    constexpr std::uint32_t kPhi = 256;
    constexpr std::uint64_t kValues = 4194304;
    if (matrices.n != kN || matrices.count != kPhi ||
        matrices.values.size() != kValues) {
        throw GlrError(
            "GLRProductionAdapter: encode requires the native W-batched "
            "256x128x128 GL-128-257-N32 layout; W-free rows are not accepted");
    }
}

std::uint64_t CheckedMul(std::uint64_t lhs, std::uint64_t rhs,
                         const char* what) {
    if (rhs != 0 && lhs > std::numeric_limits<std::uint64_t>::max() / rhs) {
        throw GlrError(std::string("GLRProductionAdapter: overflow while ") +
                       what);
    }
    return lhs * rhs;
}

std::uint64_t CheckedAdd(std::uint64_t lhs, std::uint64_t rhs,
                         const char* what) {
    if (lhs > std::numeric_limits<std::uint64_t>::max() - rhs) {
        throw GlrError(std::string("GLRProductionAdapter: overflow while ") +
                       what);
    }
    return lhs + rhs;
}

std::uint64_t RingCoefficients(const GLRProductionAdapter::Context& context,
                               GlrRing ring) {
    switch (ring) {
        case GlrRing::R:
            return context.params.coeffs_R();
        case GlrRing::Rp:
            return context.params.coeffs_Rp();
        case GlrRing::Raux:
            return context.params.coeffs_Raux();
    }
    throw GlrError("GLRProductionAdapter: invalid native GLR ring");
}

std::uint64_t ExpectedPolyWords(
    const GLRProductionAdapter::Context& context, const GlrPoly& poly) {
    if (poly.level >= context.params.levels()) {
        throw GlrError(
            "GLRProductionAdapter: polynomial level is outside the canonical "
            "N32 Q chain");
    }
    const std::uint64_t planes =
        context.active_q_primes(poly.level) +
        (poly.extended ? context.params.p_special.size() : 0U);
    return CheckedMul(CheckedMul(planes, 2, "sizing an i-split polynomial"),
                      RingCoefficients(context, poly.ring),
                      "sizing a canonical GLR polynomial");
}

void RequireSizedPoly(const GLRProductionAdapter::Context& context,
                      const GlrPoly& poly, GlrRing ring, const char* what) {
    if (poly.ring != ring) {
        throw GlrError(std::string("GLRProductionAdapter: ") + what +
                       " is not in the required native GLR ring");
    }
    if (poly.data.size() != ExpectedPolyWords(context, poly)) {
        throw GlrError(std::string("GLRProductionAdapter: ") + what +
                       " storage does not match the canonical 256x128x128 "
                       "geometry");
    }
}

void RequireProductionPlaintext(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::Plaintext& plaintext) {
    if (plaintext.poly.ring != glscheme::rns::GlrRing::Rp) {
        throw GlrError(
            "GLRProductionAdapter: plaintext must remain in native GLR R' "
            "with physical shape 256x128x128");
    }
    RequireSizedPoly(context, plaintext.poly, GlrRing::Rp, "plaintext");
    if (plaintext.poly.extended || plaintext.level != plaintext.poly.level ||
        !std::isfinite(plaintext.scale) || plaintext.scale <= 0.0) {
        throw GlrError(
            "GLRProductionAdapter: malformed production plaintext metadata");
    }
}

void RequireProductionCiphertext(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::Ciphertext& ciphertext) {
    if (ciphertext.a.ring != glscheme::rns::GlrRing::Rp ||
        ciphertext.b.ring != glscheme::rns::GlrRing::Rp) {
        throw GlrError(
            "GLRProductionAdapter: ciphertext must remain in native GLR R' "
            "with physical shape 256x128x128");
    }
    RequireSizedPoly(context, ciphertext.b, GlrRing::Rp,
                     "ciphertext b component");
    RequireSizedPoly(context, ciphertext.a, GlrRing::Rp,
                     "ciphertext a component");
    if (ciphertext.a.domain != ciphertext.b.domain ||
        ciphertext.a.level != ciphertext.b.level ||
        ciphertext.a.extended || ciphertext.b.extended ||
        ciphertext.level != ciphertext.b.level ||
        ciphertext.key_id != "primary" ||
        !std::isfinite(ciphertext.scale) || ciphertext.scale <= 0.0) {
        throw GlrError(
            "GLRProductionAdapter: malformed primary production ciphertext "
            "metadata");
    }
}

void RequireSlotCiphertext(const GLRProductionAdapter::Context& context,
                           const GLRProductionAdapter::Ciphertext& ciphertext,
                           const char* what) {
    RequireProductionCiphertext(context, ciphertext);
    if (ciphertext.b.domain != GlrDomain::Slot) {
        throw GlrError(std::string("GLRProductionAdapter: ") + what +
                       " requires a native Slot-domain ciphertext");
    }
}

void RequireProductionSecretKey(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::SecretKey& secretKey) {
    RequireSizedPoly(context, secretKey.s, GlrRing::R, "primary secret key");
    if (secretKey.key_id != "primary" ||
        secretKey.s.domain != GlrDomain::Coeff || secretKey.s.level != 0 ||
        !secretKey.s.extended) {
        throw GlrError(
            "GLRProductionAdapter: primary secret key metadata is not the "
            "canonical N32 owner-side QP form");
    }
}

bool IsOrdinaryEvaluationKey(const GlrKskId& id) {
    switch (id.direction) {
        case GlrKsDirection::row_rotation:
        case GlrKsDirection::w_rotation:
        case GlrKsDirection::transpose_to_primary:
        case GlrKsDirection::conjugation_to_primary:
        case GlrKsDirection::primary_conjtranspose_to_primary:
        case GlrKsDirection::primary_product_conjtranspose_to_primary:
        case GlrKsDirection::primary_sq_to_primary:
            return true;
        default:
            return false;
    }
}

void ValidateEvaluationKeyId(
    const GLRProductionAdapter::Context& context, const GlrKskId& id) {
    if (!IsOrdinaryEvaluationKey(id)) {
        throw GlrError(
            "GLRProductionAdapter: evaluation plan contains a SHIP, sparse, "
            "encapsulation, or auxiliary key family");
    }
    if (id.direction == GlrKsDirection::row_rotation) {
        if (id.amount < 1 ||
            static_cast<std::uint32_t>(id.amount) >= context.n()) {
            throw GlrError(
                "GLRProductionAdapter: row rotation key amount must be in "
                "[1,128)");
        }
    }
    else if (id.direction == GlrKsDirection::w_rotation) {
        if (id.amount < 1 ||
            static_cast<std::uint32_t>(id.amount) >= context.phi()) {
            throw GlrError(
                "GLRProductionAdapter: matrix rotation key amount must be in "
                "[1,256)");
        }
    }
    else if (id.amount != 0) {
        throw GlrError(
            "GLRProductionAdapter: non-rotation evaluation key has a nonzero "
            "amount");
    }
}

std::uint64_t ExactEvaluationKeyBytes(
    const GLRProductionAdapter::Context& context, const GlrKskId& id,
    std::uint32_t keyLevel) {
    ValidateEvaluationKeyId(context, id);
    if (keyLevel >= context.params.levels()) {
        throw GlrError(
            "GLRProductionAdapter: evaluation key level is outside the N32 "
            "Q chain");
    }
    const GlrRing ring = glscheme::rns::glr_ks_ring_for(id.direction);
    const std::uint64_t digitCount =
        glscheme::rns::glr_digit_groups(context.params, keyLevel).size();
    const std::uint64_t primeCount = context.active_qp_primes(keyLevel);
    std::uint64_t words = CheckedMul(2, 2, "sizing key components and lanes");
    words = CheckedMul(words, RingCoefficients(context, ring),
                       "sizing evaluation-key ring coefficients");
    words = CheckedMul(words, primeCount,
                       "sizing evaluation-key residue planes");
    words = CheckedMul(words, digitCount,
                       "sizing evaluation-key digit groups");
    return CheckedMul(words, sizeof(std::uint64_t),
                      "sizing evaluation-key bytes");
}

void ValidateEvaluationKeyPlan(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::EvaluationKeyPlan& plan) {
    const auto profile = GLRProductionAdapter::CanonicalProfile();
    const std::string fingerprint =
        glscheme::rns::glr_parameter_fingerprint(context.params);
    if (plan.canonicalProfile != profile.canonical_name ||
        plan.parameterFingerprint != fingerprint) {
        throw GlrError(
            "GLRProductionAdapter: evaluation-key plan is not bound to the "
            "canonical GL-128-257-N32 profile");
    }
    if (plan.keyLevel >= context.params.levels()) {
        throw GlrError(
            "GLRProductionAdapter: evaluation-key plan level is outside the "
            "N32 Q chain");
    }
    std::vector<GlrKskId> seen;
    std::uint64_t total = 0;
    bool requiresLogicalRescale = false;
    for (const auto& entry : plan.entries) {
        ValidateEvaluationKeyId(context, entry.id);
        if (std::find(seen.begin(), seen.end(), entry.id) != seen.end()) {
            throw GlrError(
                "GLRProductionAdapter: duplicate evaluation key in plan");
        }
        seen.push_back(entry.id);
        requiresLogicalRescale =
            requiresLogicalRescale ||
            entry.id.direction ==
                GlrKsDirection::primary_product_conjtranspose_to_primary ||
            entry.id.direction == GlrKsDirection::primary_sq_to_primary;
        const GlrRing expectedRing =
            glscheme::rns::glr_ks_ring_for(entry.id.direction);
        const std::uint64_t expectedBytes =
            ExactEvaluationKeyBytes(context, entry.id, plan.keyLevel);
        if (entry.ring != expectedRing ||
            entry.residentBytes != expectedBytes) {
            throw GlrError(
                "GLRProductionAdapter: forged evaluation-key plan entry "
                "shape or byte estimate");
        }
        total = CheckedAdd(total, entry.residentBytes,
                           "summing evaluation-key plan bytes");
    }
    if (plan.residentBytes != total) {
        throw GlrError(
            "GLRProductionAdapter: evaluation-key plan total does not match "
            "its entries");
    }
    const std::uint32_t rescaleStride =
        std::max<std::uint32_t>(1, context.params.rescale_stride);
    if (requiresLogicalRescale &&
        context.active_q_primes(plan.keyLevel) <= rescaleStride) {
        throw GlrError(
            "GLRProductionAdapter: ct-ct evaluation-key plan leaves no N32 "
            "Q-prime headroom for its logical rescale");
    }
}

const GLRProductionAdapter::NativeKeyProvider& RequireEvaluationKeys(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::EvaluationKeys& keys) {
    const auto& provider = keys.GetNativeProvider();
    if (provider.parameter_fingerprint() !=
            glscheme::rns::glr_parameter_fingerprint(context.params) ||
        provider.secret_material_accessed()) {
        throw GlrError(
            "GLRProductionAdapter: evaluation keys are cross-parameter or "
            "accessed secret material");
    }
    return provider;
}

}  // namespace

GLRProductionAdapter::EvaluationKeys::EvaluationKeys(
    EvaluationKeyPlan plan, KeyManifest manifest,
    std::unique_ptr<NativeKeyProvider> provider)
    : m_plan(std::move(plan)),
      m_manifest(std::move(manifest)),
      m_provider(std::move(provider)) {
    if (!m_provider) {
        throw GlrError(
            "GLRProductionAdapter: null native evaluation-key provider");
    }
}

const GLRProductionAdapter::EvaluationKeyPlan&
GLRProductionAdapter::EvaluationKeys::GetPlan() const noexcept {
    return m_plan;
}

const GLRProductionAdapter::KeyManifest&
GLRProductionAdapter::EvaluationKeys::GetManifest() const noexcept {
    return m_manifest;
}

const GLRProductionAdapter::NativeKeyProvider&
GLRProductionAdapter::EvaluationKeys::GetNativeProvider() const {
    if (!m_provider) {
        throw GlrError(
            "GLRProductionAdapter: moved-from evaluation-key provider");
    }
    return *m_provider;
}

bool GLRProductionAdapter::EvaluationKeys::HasKey(
    const KeyId& id) const noexcept {
    return m_provider != nullptr && m_provider->has_key(id);
}

std::uint64_t GLRProductionAdapter::EvaluationKeys::ResidentBytes() const noexcept {
    return m_plan.residentBytes;
}

GLRProductionAdapter::Profile GLRProductionAdapter::CanonicalProfile() {
    Profile profile = glscheme::production::gl128_257_n32();
    glscheme::production::validate(profile);
    glscheme::production::validate_distinct(
        profile, glscheme::production::dense4096_wfree());
    return profile;
}

GLRProductionAdapter GLRProductionAdapter::Create() {
    const Profile profile = CanonicalProfile();
    glscheme::rns::GlrParams params =
        glscheme::rns::glr_params_gl128_257_n32();
    if (params.name != profile.parameter_source || params.n != profile.n ||
        params.p != profile.p || params.phi != profile.phi ||
        glscheme::rns::glr_parameter_fingerprint(params) !=
            profile.binding_fingerprint) {
        throw GlrError(
            "GLRProductionAdapter: canonical profile/context binding mismatch");
    }
    return GLRProductionAdapter(
        glscheme::rns::GlrContext::create(std::move(params)));
}

GLRProductionAdapter::GLRProductionAdapter(Context context)
    : m_context(std::move(context)) {}

const GLRProductionAdapter::Context& GLRProductionAdapter::GetContext() const noexcept {
    return m_context;
}

GLRProductionAdapter::SecretKey GLRProductionAdapter::KeyGen(
    std::uint64_t seed) const {
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_keygen_primary(m_context, *rng);
}

GLRProductionAdapter::Plaintext GLRProductionAdapter::Encode(
    const MatrixBatch& matrices, double scale, std::uint32_t level,
    bool slotDomain) const {
    RequireCanonicalBatch(matrices);
    Plaintext plaintext =
        glscheme::rns::glr_encode(m_context, matrices, scale, level);
    if (slotDomain) {
        glscheme::rns::glr_to_slots(m_context, plaintext.poly);
    }
    return plaintext;
}

GLRProductionAdapter::MatrixBatch GLRProductionAdapter::Decode(
    const Plaintext& plaintext) const {
    RequireProductionPlaintext(m_context, plaintext);
    if (plaintext.poly.domain == GlrDomain::Coeff) {
        return glscheme::rns::glr_decode(m_context, plaintext);
    }
    Plaintext coefficientPlaintext = plaintext;
    glscheme::rns::glr_to_coeffs(m_context, coefficientPlaintext.poly);
    return glscheme::rns::glr_decode(m_context, coefficientPlaintext);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Encrypt(
    const SecretKey& secretKey, const Plaintext& plaintext, std::uint64_t seed,
    bool slotDomain) const {
    RequireProductionSecretKey(m_context, secretKey);
    RequireProductionPlaintext(m_context, plaintext);
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_encrypt(m_context, secretKey, plaintext, *rng,
                                      slotDomain);
}

GLRProductionAdapter::Plaintext GLRProductionAdapter::Decrypt(
    const SecretKey& secretKey, const Ciphertext& ciphertext) const {
    RequireProductionSecretKey(m_context, secretKey);
    RequireProductionCiphertext(m_context, ciphertext);
    return glscheme::rns::glr_decrypt(m_context, secretKey, ciphertext);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Add(
    const Ciphertext& lhs, const Ciphertext& rhs) const {
    RequireProductionCiphertext(m_context, lhs);
    RequireProductionCiphertext(m_context, rhs);
    return glscheme::rns::glr_ct_add(m_context, lhs, rhs);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Sub(
    const Ciphertext& lhs, const Ciphertext& rhs) const {
    RequireProductionCiphertext(m_context, lhs);
    RequireProductionCiphertext(m_context, rhs);
    return glscheme::rns::glr_ct_sub(m_context, lhs, rhs);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Negate(
    const Ciphertext& ciphertext) const {
    RequireProductionCiphertext(m_context, ciphertext);
    Ciphertext out = ciphertext;
    glscheme::rns::glr_neg_inplace(m_context, out.b);
    glscheme::rns::glr_neg_inplace(m_context, out.a);
    return out;
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Rescale(
    const Ciphertext& ciphertext) const {
    RequireProductionCiphertext(m_context, ciphertext);
    const std::uint32_t stride =
        std::max<std::uint32_t>(1, m_context.params.rescale_stride);
    if (m_context.active_q_primes(ciphertext.level) <= stride) {
        throw GlrError(
            "GLRProductionAdapter: insufficient Q-prime headroom for one "
            "logical rescale");
    }
    Ciphertext out = ciphertext;
    for (std::uint32_t step = 0; step < stride; ++step) {
        out = glscheme::rns::glr_rescale_ct(m_context, out);
    }
    return out;
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::MatMul(
    const Ciphertext& ciphertext, const Plaintext& plaintext) const {
    RequireSlotCiphertext(m_context, ciphertext, "plaintext MatMul");
    RequireProductionPlaintext(m_context, plaintext);
    if (plaintext.level != ciphertext.level) {
        throw GlrError(
            "GLRProductionAdapter: plaintext MatMul level mismatch");
    }
    if (plaintext.poly.domain == GlrDomain::Slot) {
        return glscheme::rns::glr_matmul_pt_ct(m_context, ciphertext,
                                                plaintext);
    }
    Plaintext slotPlaintext = plaintext;
    glscheme::rns::glr_to_slots(m_context, slotPlaintext.poly);
    return glscheme::rns::glr_matmul_pt_ct(m_context, ciphertext,
                                            slotPlaintext);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Hadamard(
    const Ciphertext& ciphertext, const Plaintext& plaintext) const {
    RequireSlotCiphertext(m_context, ciphertext, "plaintext Hadamard");
    RequireProductionPlaintext(m_context, plaintext);
    if (plaintext.level != ciphertext.level) {
        throw GlrError(
            "GLRProductionAdapter: plaintext Hadamard level mismatch");
    }
    if (plaintext.poly.domain == GlrDomain::Slot) {
        return glscheme::rns::glr_hadamard_pt_ct(m_context, ciphertext,
                                                  plaintext);
    }
    Plaintext slotPlaintext = plaintext;
    glscheme::rns::glr_to_slots(m_context, slotPlaintext.poly);
    return glscheme::rns::glr_hadamard_pt_ct(m_context, ciphertext,
                                              slotPlaintext);
}

GLRProductionAdapter::EvaluationKeyPlan
GLRProductionAdapter::PlanEvaluationKeys(
    const EvaluationKeyRequest& request) const {
    if (request.keyLevel >= m_context.params.levels()) {
        throw GlrError(
            "GLRProductionAdapter: requested evaluation key level is outside "
            "the N32 Q chain");
    }

    EvaluationKeyPlan plan;
    plan.canonicalProfile = CanonicalProfile().canonical_name;
    plan.parameterFingerprint =
        glscheme::rns::glr_parameter_fingerprint(m_context.params);
    plan.keyLevel = request.keyLevel;

    const auto append = [&](GlrKskId id) {
        ValidateEvaluationKeyId(m_context, id);
        const auto duplicate = std::find_if(
            plan.entries.begin(), plan.entries.end(),
            [&id](const EvaluationKeyPlanEntry& entry) {
                return entry.id == id;
            });
        if (duplicate != plan.entries.end()) {
            return;
        }
        EvaluationKeyPlanEntry entry;
        entry.id = id;
        entry.ring = glscheme::rns::glr_ks_ring_for(id.direction);
        entry.residentBytes =
            ExactEvaluationKeyBytes(m_context, id, request.keyLevel);
        plan.residentBytes =
            CheckedAdd(plan.residentBytes, entry.residentBytes,
                       "summing planned evaluation-key bytes");
        plan.entries.push_back(std::move(entry));
    };

    for (const std::int32_t amount : request.rowRotations) {
        append({GlrKsDirection::row_rotation, amount});
    }
    for (const std::int32_t amount : request.matrixRotations) {
        append({GlrKsDirection::w_rotation, amount});
    }
    if (request.transpose) {
        append({GlrKsDirection::transpose_to_primary, 0});
    }
    if (request.conjugation) {
        append({GlrKsDirection::conjugation_to_primary, 0});
    }
    if (request.hermitianTranspose || request.ciphertextMatMul) {
        append({GlrKsDirection::primary_conjtranspose_to_primary, 0});
    }
    if (request.ciphertextMatMul) {
        append(
            {GlrKsDirection::primary_product_conjtranspose_to_primary, 0});
    }
    if (request.ciphertextHadamard) {
        append({GlrKsDirection::primary_sq_to_primary, 0});
    }
    ValidateEvaluationKeyPlan(m_context, plan);
    return plan;
}

GLRProductionAdapter::EvaluationKeys
GLRProductionAdapter::MaterializeEvaluationKeys(
    const SecretKey& primaryKey, const EvaluationKeyPlan& plan,
    std::string primaryKeyCommitment, std::uint64_t maxResidentBytes,
    std::uint64_t seed) const {
    ValidateEvaluationKeyPlan(m_context, plan);
    if (plan.residentBytes > maxResidentBytes) {
        throw GlrError(
            "GLRProductionAdapter: evaluation-key plan exceeds the explicit "
            "resident-byte budget; no key material was generated");
    }
    if (primaryKeyCommitment.empty()) {
        throw GlrError(
            "GLRProductionAdapter: a nonempty opaque primary-key commitment "
            "is required");
    }
    RequireProductionSecretKey(m_context, primaryKey);

    GlrRngOwner rng = MakeRng(seed);
    std::vector<glscheme::rns::GlrSwitchKey> nativeKeys;
    nativeKeys.reserve(plan.entries.size());
    std::uint64_t actualBytes = 0;
    for (const auto& entry : plan.entries) {
        auto key = glscheme::rns::glr_make_ksk(
            m_context, entry.id, primaryKey, nullptr, nullptr, *rng,
            plan.keyLevel);
        if (key.ring != entry.ring || key.byte_size() != entry.residentBytes) {
            throw GlrError(
                "GLRProductionAdapter: materialized key disagrees with its "
                "preflight shape or resident-byte estimate");
        }
        actualBytes = CheckedAdd(actualBytes, key.byte_size(),
                                 "summing materialized evaluation-key bytes");
        nativeKeys.push_back(std::move(key));
    }
    if (actualBytes != plan.residentBytes) {
        throw GlrError(
            "GLRProductionAdapter: materialized keyset disagrees with its "
            "preflight resident-byte total");
    }

    KeyManifest manifest;
    manifest.parameter_fingerprint = plan.parameterFingerprint;
    manifest.n = m_context.n();
    manifest.p = m_context.p_();
    manifest.phi = m_context.phi();
    manifest.dnum = m_context.params.dnum;
    for (const auto& modulus : m_context.params.q_chain) {
        manifest.q_primes.push_back(modulus.q);
    }
    for (const auto& modulus : m_context.params.p_special) {
        manifest.special_primes.push_back(modulus.q);
    }
    manifest.key_seed_commitment = std::move(primaryKeyCommitment);
    manifest.ksk_seed_commitment =
        "openfhe-glr-ksk-public-seed-set:v1";
    for (const auto& key : nativeKeys) {
        manifest.ksk_seed_commitment.append("|");
        manifest.ksk_seed_commitment.append(key.public_seed_commitment);
    }
    manifest.sparse_support_commitment =
        "not-applicable:openfhe-glr-ordinary-evaluation-keys:v1";
    for (const auto& key : nativeKeys) {
        glscheme::rns::GlrKskRecord record;
        record.id = key.id;
        record.ring = key.ring;
        record.direction_tag = glscheme::rns::glr_ksk_id_tag(key.id);
        record.source_key_name = key.source_key_name;
        record.destination_key_name = key.destination_key_name;
        record.byte_size = key.byte_size();
        manifest.records.push_back(std::move(record));
    }

    auto provider = glscheme::rns::glr_make_in_memory_ksk_provider(
        std::move(manifest), std::move(nativeKeys),
        "openfhe-glr-production-adapter-in-memory");
    if (!provider || provider->secret_material_accessed() ||
        provider->parameter_fingerprint() != plan.parameterFingerprint) {
        throw GlrError(
            "GLRProductionAdapter: native evaluator provider failed its "
            "secret-free parameter binding");
    }
    KeyManifest canonicalManifest = provider->manifest();
    return EvaluationKeys(plan, std::move(canonicalManifest),
                          std::move(provider));
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::RotateRows(
    const Ciphertext& ciphertext, std::int32_t amount,
    const EvaluationKeys& keys) const {
    RequireSlotCiphertext(m_context, ciphertext, "row rotation");
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_rotate_rows_ct(m_context, ciphertext, amount,
                                             provider);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::RotateColumns(
    const Ciphertext& ciphertext, std::int32_t amount) const {
    RequireSlotCiphertext(m_context, ciphertext, "column rotation");
    return glscheme::rns::glr_rotate_cols_ct(m_context, ciphertext, amount);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::RotateMatrices(
    const Ciphertext& ciphertext, std::int32_t amount,
    const EvaluationKeys& keys) const {
    RequireSlotCiphertext(m_context, ciphertext, "matrix rotation");
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_rotate_matrices_ct(m_context, ciphertext, amount,
                                                 provider);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Transpose(
    const Ciphertext& ciphertext, const EvaluationKeys& keys) const {
    RequireSlotCiphertext(m_context, ciphertext, "transpose");
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_transpose_ct(m_context, ciphertext, provider);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Conjugate(
    const Ciphertext& ciphertext, const EvaluationKeys& keys) const {
    RequireSlotCiphertext(m_context, ciphertext, "conjugation");
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_conjugate_ct(m_context, ciphertext, provider);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::HermitianTranspose(
    const Ciphertext& ciphertext, const EvaluationKeys& keys) const {
    RequireSlotCiphertext(m_context, ciphertext, "Hermitian transpose");
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_hermitian_transpose_ct(m_context, ciphertext,
                                                     provider);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::MatMul(
    const Ciphertext& lhs, const Ciphertext& rhs,
    const EvaluationKeys& keys) const {
    RequireSlotCiphertext(m_context, lhs, "ciphertext MatMul");
    RequireSlotCiphertext(m_context, rhs, "ciphertext MatMul");
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_matmul_ct_ct(m_context, lhs, rhs, provider);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Hadamard(
    const Ciphertext& lhs, const Ciphertext& rhs,
    const EvaluationKeys& keys) const {
    RequireSlotCiphertext(m_context, lhs, "ciphertext Hadamard");
    RequireSlotCiphertext(m_context, rhs, "ciphertext Hadamard");
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_hadamard_ct_ct(m_context, lhs, rhs, provider);
}

}  // namespace lbcrypto
