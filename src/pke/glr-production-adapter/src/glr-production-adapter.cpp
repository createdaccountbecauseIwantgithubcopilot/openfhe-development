#include "openfhe/pke/glr-production-adapter.h"

#include <algorithm>
#include <bit>
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

bool IsCanonicalSha256Root(const std::string& value) {
    return value.size() == 71U && value.rfind("sha256:", 0) == 0 &&
           std::all_of(value.begin() + 7, value.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
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
        !IsCanonicalSha256Root(ciphertext.key_lineage_commitment) ||
        !std::isfinite(ciphertext.scale) || ciphertext.scale <= 0.0) {
        throw GlrError(
            "GLRProductionAdapter: malformed primary production ciphertext "
            "metadata");
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

void RequireCanonicalSchemeKeyPlan(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::NativeGL128SchemeKeyPlan& plan) {
    const std::string fingerprint =
        glscheme::rns::glr_parameter_fingerprint(context.params);
    if (plan.schema != "glscheme.gl128_scheme_key_plan.v1" ||
        plan.parameter_fingerprint != fingerprint || plan.key_level != 0U ||
        !plan.matrix_product_relinearization_complete ||
        !plan.hadamard_relinearization_complete ||
        !plan.automorphism_keys_complete ||
        !plan.seeded_public_a_compaction_planned) {
        throw GlrError(
            "GLRProductionAdapter: malformed canonical GL128 scheme-key "
            "plan");
    }
    std::uint32_t small = 0;
    std::uint32_t big = 0;
    std::uint64_t full = 0;
    std::uint64_t compact = 0;
    std::uint64_t saved = 0;
    for (std::size_t i = 0; i < plan.ids.size(); ++i) {
        ValidateEvaluationKeyId(context, plan.ids[i]);
        if (std::find(plan.ids.begin(), plan.ids.begin() + i, plan.ids[i]) !=
            plan.ids.begin() + i) {
            throw GlrError(
                "GLRProductionAdapter: duplicate key ID in canonical "
                "GL128 scheme-key plan");
        }
        const auto ring =
            glscheme::rns::glr_ks_ring_for(plan.ids[i].direction);
        if (ring == GlrRing::R) {
            ++small;
        } else {
            ++big;
        }
        const auto census =
            glscheme::rns::glr_model_seeded_switch_key_storage_at_level(
                context.params, ring, plan.key_level);
        full = CheckedAdd(full, census.full_materialized_bytes,
                          "validating scheme-key full bytes");
        compact = CheckedAdd(compact, census.compact_material_bytes,
                             "validating scheme-key compact bytes");
        saved = CheckedAdd(saved, census.saved_material_bytes,
                           "validating scheme-key saved bytes");
    }
    if (plan.small_switch_key_count != small ||
        plan.big_switch_key_count != big ||
        plan.full_materialized_bytes != full ||
        plan.compact_persistent_bytes != compact ||
        plan.compact_bytes_saved != saved) {
        throw GlrError(
            "GLRProductionAdapter: forged canonical GL128 scheme-key byte "
            "or direction census");
    }
}

bool DirectBootstrapKeyPlanEquals(
    const GLRProductionAdapter::NativeGL128DirectBootstrapKeyPlan& lhs,
    const GLRProductionAdapter::NativeGL128DirectBootstrapKeyPlan& rhs) {
    if (lhs.schema != rhs.schema ||
        lhs.parameter_fingerprint != rhs.parameter_fingerprint ||
        lhs.selector_level != rhs.selector_level ||
        lhs.first_relinearization_level != rhs.first_relinearization_level ||
        lhs.output_level != rhs.output_level ||
        lhs.forward_return_level != rhs.forward_return_level ||
        lhs.full_materialized_bytes != rhs.full_materialized_bytes ||
        lhs.compact_persistent_bytes != rhs.compact_persistent_bytes ||
        lhs.compact_bytes_saved != rhs.compact_bytes_saved ||
        lhs.exact_h40_corridor != rhs.exact_h40_corridor ||
        lhs.seeded_public_a_compaction_planned !=
            rhs.seeded_public_a_compaction_planned ||
        lhs.requirements.size() != rhs.requirements.size()) {
        return false;
    }
    for (std::size_t i = 0; i < lhs.requirements.size(); ++i) {
        const auto& a = lhs.requirements[i];
        const auto& b = rhs.requirements[i];
        if (!(a.id == b.id) || a.ring != b.ring ||
            a.key_level != b.key_level ||
            a.special_prime_count != b.special_prime_count ||
            a.application_site != b.application_site) {
            return false;
        }
    }
    return true;
}

void RequireCompactGeneration(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::NativeCompactKskSetGenerationResult&
        generation,
    const std::vector<std::pair<GlrKskId, std::uint32_t>>& expected) {
    const std::string fingerprint =
        glscheme::rns::glr_parameter_fingerprint(context.params);
    const auto& manifest = generation.manifest;
    if (manifest.parameter_fingerprint != fingerprint ||
        manifest.n != context.n() || manifest.p != context.p_() ||
        manifest.phi != context.phi() ||
        manifest.dnum != context.params.dnum ||
        manifest.records.size() != expected.size() ||
        generation.compact_records_emitted != expected.size() ||
        generation.public_material_commitment.empty() ||
        !generation.sink_secret_free || generation.full_key_set_materialized ||
        generation.peak_live_full_keys > 1U ||
        generation.peak_live_compact_records > 1U ||
        generation.peak_live_readback_keys > 1U) {
        throw GlrError(
            "GLRProductionAdapter: compact key generation receipt is not a "
            "bounded canonical GL128 key set");
    }
    for (std::size_t i = 0; i < expected.size(); ++i) {
        const auto& record = manifest.records[i];
        if (!(record.id == expected[i].first) ||
            record.key_level != expected[i].second ||
            record.ring !=
                glscheme::rns::glr_ks_ring_for(expected[i].first.direction) ||
            record.direction_tag !=
                glscheme::rns::glr_ksk_id_tag(expected[i].first) ||
            record.payload_commitment.empty()) {
            throw GlrError(
                "GLRProductionAdapter: compact key generation record does "
                "not match the requested GL128 key/level order");
        }
    }
    const auto binding = glscheme::rns::glr_make_leased_ksk_binding(
        manifest, generation.public_material_commitment);
    if (generation.binding.expected_manifest_commitment !=
            binding.expected_manifest_commitment ||
        generation.binding.expected_public_material_commitment !=
            binding.expected_public_material_commitment ||
        generation.binding.expected_parameter_fingerprint !=
            binding.expected_parameter_fingerprint ||
        generation.binding.expected_sparse_support_commitment !=
            binding.expected_sparse_support_commitment ||
        generation.binding.expected_record_count !=
            binding.expected_record_count) {
        throw GlrError(
            "GLRProductionAdapter: compact key binding does not authenticate "
            "its generation manifest");
    }
}

void RequireDirectBootstrapKeyGeneration(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::NativeGL128DirectBootstrapKeyPlan& plan,
    const GLRProductionAdapter::
        NativeGL128DirectBootstrapKeyGenerationResult& generation) {
    std::vector<std::pair<GlrKskId, std::uint32_t>> expected;
    expected.reserve(plan.requirements.size());
    for (const auto& requirement : plan.requirements) {
        expected.emplace_back(requirement.id, requirement.key_level);
    }
    RequireCompactGeneration(context, generation.key_generation, expected);
    const auto& lineage = generation.lineage;
    const auto& manifest = generation.key_generation.manifest;
    const std::string fingerprint =
        glscheme::rns::glr_parameter_fingerprint(context.params);
    const std::string support =
        glscheme::rns::glr_gl128_validate_context(context).support_commitment;
    if (lineage.schema !=
            "glscheme.gl128_direct_bootstrap_key_lineage_binding.v1" ||
        lineage.parameter_fingerprint != fingerprint ||
        lineage.support_commitment != support ||
        lineage.owner_key_seed_commitment !=
            manifest.key_seed_commitment ||
        !IsCanonicalSha256Root(
            lineage.primary_secret_lineage_commitment) ||
        !IsCanonicalSha256Root(
            lineage.sparse_secret_lineage_commitment) ||
        lineage.primary_secret_lineage_commitment ==
            lineage.sparse_secret_lineage_commitment ||
        manifest.schema != "glscheme.rns_hybrid_ksk_manifest.v2" ||
        manifest.primary_secret_lineage_commitment !=
            lineage.primary_secret_lineage_commitment ||
        manifest.sparse_secret_lineage_commitment !=
            lineage.sparse_secret_lineage_commitment ||
        lineage.ksk_manifest_commitment !=
            glscheme::rns::glr_ksk_manifest_commitment(
                manifest) ||
        lineage.ksk_public_material_commitment !=
            generation.key_generation.public_material_commitment ||
        lineage.evaluation_key_records != plan.requirements.size() ||
        !lineage.exact_five_key_plan ||
        !lineage.generated_from_bound_primary_secret ||
        !lineage.generated_from_bound_sparse_secret ||
        !lineage.public_material_roots_bound ||
        lineage.binding_commitment !=
            glscheme::rns::
                glr_gl128_direct_bootstrap_key_lineage_commitment(lineage)) {
        throw GlrError(
            "GLRProductionAdapter: direct-bootstrap compact keys do not "
            "carry an authentic secret-derived lineage binding");
    }
}

const GLRProductionAdapter::NativeKeyProvider& RequireDirectBootstrapKeys(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::CompactDirectBootstrapKeys& keys,
    const GLRProductionAdapter::
        NativeDirectVectorProductionAuthorizationEvidence& authorization) {
    const auto plan =
        glscheme::rns::glr_gl128_direct_bootstrap_key_plan(context);
    RequireDirectBootstrapKeyGeneration(
        context, plan, keys.GetGenerationResult());
    const auto& lineage = keys.GetLineage();
    const auto& provider = keys.GetNativeProvider();
    if (lineage.parameter_fingerprint != authorization.parameter_fingerprint ||
        lineage.support_commitment != authorization.support_commitment ||
        lineage.owner_key_seed_commitment !=
            authorization.owner_key_seed_commitment ||
        lineage.primary_secret_lineage_commitment !=
            authorization.primary_secret_lineage_commitment ||
        lineage.sparse_secret_lineage_commitment !=
            authorization.sparse_secret_lineage_commitment ||
        provider.secret_material_accessed() ||
        provider.parameter_fingerprint() != lineage.parameter_fingerprint ||
        provider.sparse_support_commitment() != lineage.support_commitment ||
        glscheme::rns::glr_ksk_manifest_commitment(provider.manifest()) !=
            lineage.ksk_manifest_commitment ||
        provider.public_material_commitment() !=
            lineage.ksk_public_material_commitment) {
        throw GlrError(
            "GLRProductionAdapter: compact direct-bootstrap provider, "
            "secret-derived lineage, and selector authorization disagree");
    }
    return provider;
}

const GLRProductionAdapter::NativeKeyProvider&
RequireResearchDirectBootstrapKeys(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::CompactDirectBootstrapKeys& keys,
    const GLRProductionAdapter::NativeGL128ResearchOnlySession& session) {
    const auto plan =
        glscheme::rns::glr_gl128_direct_bootstrap_key_plan(context);
    RequireDirectBootstrapKeyGeneration(
        context, plan, keys.GetGenerationResult());
    const auto& lineage = keys.GetLineage();
    const auto& provider = keys.GetNativeProvider();
    if (session.schema !=
            glscheme::rns::kGl128ResearchOnlySessionSchema ||
        session.session_binding_commitment !=
            glscheme::rns::glr_gl128_research_session_binding_commitment(
                session) ||
        !session.exact_owner_lineage_bound ||
        !session.exact_structured_window_geometry_bound ||
        !session.historical_proxy_revalidated ||
        !session.compact_authenticated_streaming_enabled ||
        lineage.parameter_fingerprint != session.parameter_fingerprint ||
        lineage.support_commitment != session.support_commitment ||
        lineage.owner_key_seed_commitment !=
            session.owner_key_seed_commitment ||
        lineage.primary_secret_lineage_commitment !=
            session.primary_secret_lineage_commitment ||
        lineage.sparse_secret_lineage_commitment !=
            session.sparse_secret_lineage_commitment ||
        provider.secret_material_accessed() ||
        provider.parameter_fingerprint() != lineage.parameter_fingerprint ||
        provider.sparse_support_commitment() != lineage.support_commitment ||
        glscheme::rns::glr_ksk_manifest_commitment(provider.manifest()) !=
            lineage.ksk_manifest_commitment ||
        provider.public_material_commitment() !=
            lineage.ksk_public_material_commitment) {
        throw GlrError(
            "GLRProductionAdapter: compact direct-bootstrap keys and the "
            "research-only session disagree");
    }
    return provider;
}

GLRProductionAdapter::FixedProfileBindingText FixedBindingText(
    std::string_view value) {
    GLRProductionAdapter::FixedProfileBindingText out;
    if (value.size() > out.bytes.size()) {
        throw GlrError(
            "GLRProductionAdapter: refresh binding text exceeds "
            "its fixed-capacity representation");
    }
    std::copy(value.begin(), value.end(), out.bytes.begin());
    out.size = static_cast<std::uint32_t>(value.size());
    return out;
}

bool BindingTextEquals(
    const GLRProductionAdapter::FixedProfileBindingText& lhs,
    const GLRProductionAdapter::FixedProfileBindingText& rhs) {
    if (lhs.size > lhs.bytes.size() || rhs.size > rhs.bytes.size() ||
        lhs.size != rhs.size) {
        return false;
    }
    return std::equal(lhs.bytes.begin(), lhs.bytes.begin() + lhs.size,
                      rhs.bytes.begin());
}

bool NativeRefreshPreflightEquals(
    const GLRProductionAdapter::NativeRefreshTracePreflight& lhs,
    const GLRProductionAdapter::NativeRefreshTracePreflight& rhs) {
    return lhs.n == rhs.n && lhs.p == rhs.p && lhs.phi == rhs.phi &&
           lhs.x_trace_schedule == rhs.x_trace_schedule &&
           lhs.w_trace_schedule == rhs.w_trace_schedule &&
           lhs.x_trace_unique_keys == rhs.x_trace_unique_keys &&
           lhs.w_trace_unique_keys == rhs.w_trace_unique_keys &&
           lhs.x_trace_rotations_per_readout ==
               rhs.x_trace_rotations_per_readout &&
           lhs.w_trace_rotations_per_readout ==
               rhs.w_trace_rotations_per_readout &&
           lhs.centered_refreshes == rhs.centered_refreshes &&
           lhs.coefficients_packed == rhs.coefficients_packed &&
           lhs.x_centering_monomial_multiplies ==
               rhs.x_centering_monomial_multiplies &&
           lhs.w_dual_monomial_multiplies ==
               rhs.w_dual_monomial_multiplies &&
           lhs.w_dual_accumulator_additions ==
               rhs.w_dual_accumulator_additions &&
           lhs.trace_key_switches == rhs.trace_key_switches &&
           lhs.exact_prime_w_dual == rhs.exact_prime_w_dual &&
           lhs.heap_allocation_required == rhs.heap_allocation_required;
}

bool NativeRefreshEndpointPreflightEquals(
    const GLRProductionAdapter::NativeRefreshEndpointPreflight& lhs,
    const GLRProductionAdapter::NativeRefreshEndpointPreflight& rhs) {
    return lhs.total_q_primes == rhs.total_q_primes &&
           lhs.rescale_stride == rhs.rescale_stride &&
           lhs.required_input_live_q_primes ==
               rhs.required_input_live_q_primes &&
           lhs.input_level == rhs.input_level &&
           lhs.cts_output_level == rhs.cts_output_level &&
           lhs.normalized_level == rhs.normalized_level &&
           lhs.packed_level == rhs.packed_level &&
           lhs.output_level == rhs.output_level &&
           lhs.cts_rescale_count == rhs.cts_rescale_count &&
           lhs.normalization_rescale_count ==
               rhs.normalization_rescale_count &&
           lhs.stc_rescale_count == rhs.stc_rescale_count &&
           lhs.normalization_multiplier == rhs.normalization_multiplier &&
           lhs.input_scale == rhs.input_scale &&
           lhs.dft_scale == rhs.dft_scale &&
           lhs.cts_output_scale == rhs.cts_output_scale &&
           lhs.normalization_raw_multiplier ==
               rhs.normalization_raw_multiplier &&
           lhs.normalization_target_scale ==
               rhs.normalization_target_scale &&
           lhs.normalized_scale == rhs.normalized_scale &&
           lhs.normalization_relative_error ==
               rhs.normalization_relative_error &&
           lhs.integer_multiplier_exactly_representable ==
               rhs.integer_multiplier_exactly_representable &&
           lhs.strict_normalization_feasible ==
               rhs.strict_normalization_feasible &&
           lhs.would_require_scale_snapping ==
               rhs.would_require_scale_snapping &&
           lhs.scale_snapping_enabled == rhs.scale_snapping_enabled &&
           lhs.canonical_gl128_257_n32 == rhs.canonical_gl128_257_n32 &&
           lhs.context_or_key_allocation_required ==
               rhs.context_or_key_allocation_required &&
           lhs.arithmetic_preflight_only == rhs.arithmetic_preflight_only &&
           lhs.requires_h40_corridor == rhs.requires_h40_corridor &&
           lhs.security_binding_required == rhs.security_binding_required &&
           lhs.production_execution_admitted ==
               rhs.production_execution_admitted &&
           lhs.fold_level == rhs.fold_level &&
           lhs.transform_material_level == rhs.transform_material_level &&
           lhs.transform_material_alignment_safe ==
               rhs.transform_material_alignment_safe &&
           lhs.stc_headroom_valid == rhs.stc_headroom_valid;
}

bool NativeRefreshAllYPreflightEquals(
    const GLRProductionAdapter::NativeRefreshAllYProductionReceipt& lhs,
    const GLRProductionAdapter::NativeRefreshAllYProductionReceipt& rhs) {
    return lhs.schemaVersion == rhs.schemaVersion &&
           NativeRefreshPreflightEquals(lhs.pack, rhs.pack) &&
           NativeRefreshEndpointPreflightEquals(lhs.endpoint, rhs.endpoint) &&
           lhs.y_rows == rhs.y_rows &&
           lhs.branches_per_y_row == rhs.branches_per_y_row &&
           lhs.pair_major_row_tile_width == rhs.pair_major_row_tile_width &&
           lhs.pair_major_row_tiles_per_centered_refresh ==
               rhs.pair_major_row_tiles_per_centered_refresh &&
           lhs.logical_all_y_branch_items == rhs.logical_all_y_branch_items &&
           lhs.scalar_equivalent_branch_invocations ==
               rhs.scalar_equivalent_branch_invocations &&
           lhs.scalar_equivalent_exponent_ladder_nodes ==
               rhs.scalar_equivalent_exponent_ladder_nodes &&
           lhs.scalar_equivalent_gadget_key_applications ==
               rhs.scalar_equivalent_gadget_key_applications &&
           lhs.pair_major_branch_tiles_per_centered_refresh ==
               rhs.pair_major_branch_tiles_per_centered_refresh &&
           lhs.total_pair_major_branch_tile_invocations ==
               rhs.total_pair_major_branch_tile_invocations &&
           lhs.streamed_unsigned_candidate_count ==
               rhs.streamed_unsigned_candidate_count &&
           lhs.streamed_signed_pair_count ==
               rhs.streamed_signed_pair_count &&
           lhs.streamed_signed_pairs_per_window ==
               rhs.streamed_signed_pairs_per_window &&
           lhs.streamed_exponent_leaf_batch_invocations ==
               rhs.streamed_exponent_leaf_batch_invocations &&
           lhs.streamed_exponent_leaf_tables_batched ==
               rhs.streamed_exponent_leaf_tables_batched &&
           lhs.streamed_exponent_leaf_pair_visits ==
               rhs.streamed_exponent_leaf_pair_visits &&
           lhs.streamed_exponent_leaf_scalar_equivalent_pair_visits ==
               rhs.streamed_exponent_leaf_scalar_equivalent_pair_visits &&
           lhs.streamed_exponent_leaf_max_batch_size ==
               rhs.streamed_exponent_leaf_max_batch_size &&
           lhs.streamed_exponent_leaf_peak_accumulators ==
               rhs.streamed_exponent_leaf_peak_accumulators &&
           lhs.streamed_exponent_leaf_peak_scratch_polys ==
               rhs.streamed_exponent_leaf_peak_scratch_polys &&
           lhs.exact_all_y_coverage == rhs.exact_all_y_coverage &&
           lhs.full_streamed_physical_schedule_pinned ==
               rhs.full_streamed_physical_schedule_pinned &&
           lhs.context_ciphertext_or_key_allocation_required ==
               rhs.context_ciphertext_or_key_allocation_required &&
           lhs.material_schedule_metadata_admitted ==
               rhs.material_schedule_metadata_admitted &&
           lhs.ciphertext_value_execution_performed ==
               rhs.ciphertext_value_execution_performed &&
           lhs.value_noise_acceptance_recorded ==
               rhs.value_noise_acceptance_recorded;
}

GLRProductionAdapter::NativeRefreshAllYProductionReceipt
MakeNativeRefreshAllYReceipt(
    const glscheme::rns::GlrShipGl128AllYProductionPreflight& native) {
    GLRProductionAdapter::NativeRefreshAllYProductionReceipt out;
    out.pack = native.pack;
    out.endpoint = native.endpoint;
    out.schemaVersion = native.schema ==
                                "glscheme.glr_ship_gl128_all_y_production_preflight.v1"
                            ? 1U
                            : 0U;
    out.y_rows = native.y_rows;
    out.branches_per_y_row = native.branches_per_y_row;
    out.pair_major_row_tile_width = native.pair_major_row_tile_width;
    out.pair_major_row_tiles_per_centered_refresh =
        native.pair_major_row_tiles_per_centered_refresh;
    out.logical_all_y_branch_items = native.logical_all_y_branch_items;
    out.scalar_equivalent_branch_invocations =
        native.scalar_equivalent_branch_invocations;
    out.scalar_equivalent_exponent_ladder_nodes =
        native.scalar_equivalent_exponent_ladder_nodes;
    out.scalar_equivalent_gadget_key_applications =
        native.scalar_equivalent_gadget_key_applications;
    out.pair_major_branch_tiles_per_centered_refresh =
        native.pair_major_branch_tiles_per_centered_refresh;
    out.total_pair_major_branch_tile_invocations =
        native.total_pair_major_branch_tile_invocations;
    out.streamed_unsigned_candidate_count =
        native.streamed_unsigned_candidate_count;
    out.streamed_signed_pair_count = native.streamed_signed_pair_count;
    out.streamed_signed_pairs_per_window =
        native.streamed_signed_pairs_per_window;
    out.streamed_exponent_leaf_batch_invocations =
        native.streamed_exponent_leaf_batch_invocations;
    out.streamed_exponent_leaf_tables_batched =
        native.streamed_exponent_leaf_tables_batched;
    out.streamed_exponent_leaf_pair_visits =
        native.streamed_exponent_leaf_pair_visits;
    out.streamed_exponent_leaf_scalar_equivalent_pair_visits =
        native.streamed_exponent_leaf_scalar_equivalent_pair_visits;
    out.streamed_exponent_leaf_max_batch_size =
        native.streamed_exponent_leaf_max_batch_size;
    out.streamed_exponent_leaf_peak_accumulators =
        native.streamed_exponent_leaf_peak_accumulators;
    out.streamed_exponent_leaf_peak_scratch_polys =
        native.streamed_exponent_leaf_peak_scratch_polys;
    out.exact_all_y_coverage = native.exact_all_y_coverage;
    out.full_streamed_physical_schedule_pinned =
        native.full_streamed_physical_schedule_pinned;
    out.context_ciphertext_or_key_allocation_required =
        native.context_ciphertext_or_key_allocation_required;
    out.material_schedule_metadata_admitted =
        native.material_schedule_metadata_admitted;
    out.ciphertext_value_execution_performed =
        native.ciphertext_value_execution_performed;
    out.value_noise_acceptance_recorded = native.value_noise_acceptance_recorded;
    return out;
}

GLRProductionAdapter::OrdinaryRefreshPreflight
MakeCanonicalOrdinaryRefreshPreflight(
    const GLRProductionAdapter::Context& context) {
    const auto profile = GLRProductionAdapter::CanonicalProfile();
    const std::string fingerprint =
        glscheme::rns::glr_parameter_fingerprint(context.params);
    if (context.params.name != profile.parameter_source ||
        context.n() != profile.n || context.p_() != profile.p ||
        context.phi() != profile.phi ||
        context.params.rescale_stride != 2 ||
        fingerprint != profile.binding_fingerprint) {
        throw GlrError(
            "GLRProductionAdapter: ordinary-refresh preflight is not bound "
            "to the exact GL-128-257-N32 N32 context");
    }

    GLRProductionAdapter::OrdinaryRefreshPreflight out;
    out.canonicalProfile = FixedBindingText(profile.canonical_name);
    out.parameterFingerprint = FixedBindingText(fingerprint);
    out.layout = profile.layout;
    out.native = glscheme::rns::glr_ship_refresh_only_pack_preflight(
        profile.n, profile.p);
    if (out.native.n != 128 || out.native.p != 257 ||
        out.native.phi != 256 ||
        out.native.centered_refreshes != 32768ULL ||
        out.native.coefficients_packed != 4194304ULL ||
        out.native.x_trace_unique_keys != 7 ||
        out.native.w_trace_unique_keys != 8 ||
        out.native.trace_key_switches != 491520ULL ||
        !out.native.exact_prime_w_dual ||
        out.native.heap_allocation_required) {
        throw GlrError(
            "GLRProductionAdapter: native ordinary-refresh preflight "
            "diverged from the canonical production census");
    }

    constexpr double kRefreshGamma = 64.0;
    constexpr double kNormalizationTolerance = 1.0e-12;
    constexpr std::uint32_t kRefreshedKeyLevel = 18;
    constexpr std::uint32_t kTransformMaterialLevel = 17;
    glscheme::rns::GlrShipRefreshOnlyParameters refreshParameters;
    refreshParameters.gamma = kRefreshGamma;
    out.endpoint =
        glscheme::rns::glr_ship_refresh_only_endpoint_preflight(
            context.params, refreshParameters,
            /*canonical input scale=*/context.params.delta,
            /*public DFT scale=*/std::ldexp(1.0, 46),
            kNormalizationTolerance, kRefreshedKeyLevel,
            kTransformMaterialLevel);
    if (out.endpoint.total_q_primes != 25 ||
        out.endpoint.rescale_stride != 2 ||
        out.endpoint.required_input_live_q_primes != 7 ||
        out.endpoint.input_level != 18 ||
        out.endpoint.cts_output_level != 22 ||
        out.endpoint.normalized_level != 24 ||
        out.endpoint.packed_level != 18 ||
        out.endpoint.output_level != 22 ||
        out.endpoint.cts_rescale_count != 4 ||
        out.endpoint.normalization_rescale_count != 2 ||
        out.endpoint.stc_rescale_count != 4 ||
        out.endpoint.normalization_multiplier != 1154461932539ULL ||
        out.endpoint.input_scale != context.params.delta ||
        out.endpoint.dft_scale != std::ldexp(1.0, 46) ||
        !out.endpoint.integer_multiplier_exactly_representable ||
        !out.endpoint.strict_normalization_feasible ||
        out.endpoint.would_require_scale_snapping ||
        out.endpoint.scale_snapping_enabled ||
        !out.endpoint.canonical_gl128_257_n32 ||
        out.endpoint.context_or_key_allocation_required ||
        !out.endpoint.arithmetic_preflight_only ||
        !out.endpoint.requires_h40_corridor ||
        !out.endpoint.security_binding_required ||
        out.endpoint.production_execution_admitted ||
        out.endpoint.fold_level != kRefreshedKeyLevel ||
        out.endpoint.transform_material_level != kTransformMaterialLevel ||
        !out.endpoint.transform_material_alignment_safe ||
        !out.endpoint.stc_headroom_valid ||
        out.endpoint.normalization_relative_error >
            kNormalizationTolerance) {
        throw GlrError(
            "GLRProductionAdapter: native ordinary-refresh endpoint "
            "preflight diverged from the canonical Q7+P14 corridor ledger");
    }
    out.refreshGamma = kRefreshGamma;
    out.normalizationRelativeTolerance = kNormalizationTolerance;
    out.traceKeyLevel = kRefreshedKeyLevel;
    out.nonTraceKeyLevel = kRefreshedKeyLevel;
    out.corridorQPrimeCount = 7;
    out.corridorSpecialPrimeCount = 14;
    out.requiredSparseHammingWeight = 40;

    std::size_t traceIndex = 0;
    for (std::int32_t amount = 1; amount < 128; amount *= 2) {
        out.traceKeys[traceIndex++] = {
            GlrKskId{GlrKsDirection::row_rotation, amount},
            out.native.centered_refreshes};
    }
    for (std::int32_t amount = 1; amount < 256; amount *= 2) {
        out.traceKeys[traceIndex++] = {
            GlrKskId{GlrKsDirection::w_rotation, amount},
            out.native.centered_refreshes};
    }
    if (traceIndex != out.traceKeys.size()) {
        throw GlrError(
            "GLRProductionAdapter: canonical refresh trace-key census has "
            "the wrong fixed cardinality");
    }
    out.traceKeyCount = static_cast<std::uint32_t>(traceIndex);

    out.endpointKeyDebts = {
        GlrKskId{GlrKsDirection::primary_to_sparse, 0},
        GlrKskId{GlrKsDirection::sparse_to_primary, 0},
        GlrKskId{GlrKsDirection::conjugation_to_sparse, 0},
        GlrKskId{
            GlrKsDirection::primary_conjtranspose_to_primary, 0},
        GlrKskId{GlrKsDirection::aux_conjtranspose_to_primary, 0},
    };
    out.endpointKeyDebtCount =
        static_cast<std::uint32_t>(out.endpointKeyDebts.size());

    const auto keyLevelModel = [&](std::uint32_t keyLevel) {
        GLRProductionAdapter::RefreshKeyLevelByteModel model;
        model.keyLevel = keyLevel;
        model.ringRPerKeyBytes =
            glscheme::rns::glr_model_switch_key_bytes_at_level(
                context.params, GlrRing::R, keyLevel);
        model.ringRpPerKeyBytes =
            glscheme::rns::glr_model_switch_key_bytes_at_level(
                context.params, GlrRing::Rp, keyLevel);
        model.ringRauxPerKeyBytes =
            glscheme::rns::glr_model_switch_key_bytes_at_level(
                context.params, GlrRing::Raux, keyLevel);
        return model;
    };
    out.keyLevelModels = {
        keyLevelModel(kRefreshedKeyLevel),
        keyLevelModel(kTransformMaterialLevel),
    };
    out.keyLevelModelCount =
        static_cast<std::uint32_t>(out.keyLevelModels.size());
    constexpr std::uint64_t kMiB = 1024ULL * 1024ULL;
    constexpr std::uint64_t kGiB = 1024ULL * kMiB;
    const auto& q7Model = out.keyLevelModels[0];
    const auto& q8Model = out.keyLevelModels[1];
    if (q7Model.keyLevel != 18 ||
        q7Model.ringRPerKeyBytes != 21ULL * kMiB ||
        q7Model.ringRpPerKeyBytes != 2ULL * kGiB + 640ULL * kMiB ||
        q7Model.ringRauxPerKeyBytes != 5ULL * kGiB + 256ULL * kMiB ||
        q8Model.keyLevel != 17 ||
        q8Model.ringRPerKeyBytes != 22ULL * kMiB ||
        q8Model.ringRpPerKeyBytes != 2ULL * kGiB + 768ULL * kMiB ||
        q8Model.ringRauxPerKeyBytes != 5ULL * kGiB + 512ULL * kMiB) {
        throw GlrError(
            "GLRProductionAdapter: level-aware Q7/Q8 key-size census "
            "diverged from the one-active-digit canonical model");
    }
    out.traceRotationKeyResidentBytes = CheckedMul(
        out.traceKeyCount, q7Model.ringRPerKeyBytes,
        "summing canonical trace-rotation key bytes");
    for (const GlrKskId& id : out.endpointKeyDebts) {
        std::uint64_t bytes = 0;
        switch (glscheme::rns::glr_ks_ring_for(id.direction)) {
            case GlrRing::R:
                bytes = q7Model.ringRPerKeyBytes;
                break;
            case GlrRing::Rp:
                bytes = q7Model.ringRpPerKeyBytes;
                break;
            case GlrRing::Raux:
                bytes = q7Model.ringRauxPerKeyBytes;
                break;
        }
        out.listedNonTraceKeyDebtResidentBytes = CheckedAdd(
            out.listedNonTraceKeyDebtResidentBytes, bytes,
            "summing canonical listed non-trace key-debt bytes");
    }
    out.availability =
        GLRProductionAdapter::OrdinaryRefreshAvailability::preflight_only;
    out.canonicalProfileBound = true;
    out.reducedExposureCorridorRequired = true;
    out.securityAuthorizationRequired = true;
    out.sparseKeyRequired = true;
    out.encryptedSelectorBankRequired = false;
    out.encryptedGadgetBankRequired = false;
    out.dftBankRequired = false;
    out.productionExecutionExposed = false;
    out.compactSelectorBindingRequired = true;
    out.authenticatedLeasedKskRequired = true;
    out.streamedGadgetProviderRequired = true;
    out.streamedDftProviderRequired = true;
    return out;
}

void RequireCanonicalOrdinaryRefreshPreflight(
    const GLRProductionAdapter::OrdinaryRefreshPreflight& actual,
    const GLRProductionAdapter::OrdinaryRefreshPreflight& expected) {
    bool keysMatch =
        actual.traceKeyCount == expected.traceKeyCount &&
        actual.traceKeyCount == actual.traceKeys.size();
    for (std::size_t i = 0; i < actual.traceKeys.size(); ++i) {
        keysMatch = keysMatch &&
                    actual.traceKeys[i].id == expected.traceKeys[i].id &&
                    actual.traceKeys[i].applications ==
                        expected.traceKeys[i].applications;
    }
    bool debtsMatch =
        actual.endpointKeyDebtCount == expected.endpointKeyDebtCount &&
        actual.endpointKeyDebtCount == actual.endpointKeyDebts.size();
    for (std::size_t i = 0; i < actual.endpointKeyDebts.size(); ++i) {
        debtsMatch = debtsMatch &&
                     actual.endpointKeyDebts[i] ==
                         expected.endpointKeyDebts[i];
    }
    bool keyModelsMatch =
        actual.keyLevelModelCount == expected.keyLevelModelCount &&
        actual.keyLevelModelCount == actual.keyLevelModels.size();
    for (std::size_t i = 0; i < actual.keyLevelModels.size(); ++i) {
        keyModelsMatch =
            keyModelsMatch &&
            actual.keyLevelModels[i].keyLevel ==
                expected.keyLevelModels[i].keyLevel &&
            actual.keyLevelModels[i].ringRPerKeyBytes ==
                expected.keyLevelModels[i].ringRPerKeyBytes &&
            actual.keyLevelModels[i].ringRpPerKeyBytes ==
                expected.keyLevelModels[i].ringRpPerKeyBytes &&
            actual.keyLevelModels[i].ringRauxPerKeyBytes ==
                expected.keyLevelModels[i].ringRauxPerKeyBytes;
    }
    if (!BindingTextEquals(actual.canonicalProfile,
                           expected.canonicalProfile) ||
        !BindingTextEquals(actual.parameterFingerprint,
                           expected.parameterFingerprint) ||
        actual.layout != expected.layout ||
        !NativeRefreshPreflightEquals(actual.native, expected.native) ||
        !NativeRefreshEndpointPreflightEquals(actual.endpoint,
                                              expected.endpoint) ||
        !keysMatch || !debtsMatch || !keyModelsMatch ||
        actual.traceRotationKeyResidentBytes !=
            expected.traceRotationKeyResidentBytes ||
        actual.listedNonTraceKeyDebtResidentBytes !=
            expected.listedNonTraceKeyDebtResidentBytes ||
        actual.refreshGamma != expected.refreshGamma ||
        actual.normalizationRelativeTolerance !=
            expected.normalizationRelativeTolerance ||
        actual.traceKeyLevel != expected.traceKeyLevel ||
        actual.nonTraceKeyLevel != expected.nonTraceKeyLevel ||
        actual.corridorQPrimeCount != expected.corridorQPrimeCount ||
        actual.corridorSpecialPrimeCount !=
            expected.corridorSpecialPrimeCount ||
        actual.requiredSparseHammingWeight !=
            expected.requiredSparseHammingWeight ||
        actual.availability != expected.availability ||
        actual.canonicalProfileBound != expected.canonicalProfileBound ||
        actual.reducedExposureCorridorRequired !=
            expected.reducedExposureCorridorRequired ||
        actual.securityAuthorizationRequired !=
            expected.securityAuthorizationRequired ||
        actual.sparseKeyRequired != expected.sparseKeyRequired ||
        actual.encryptedSelectorBankRequired !=
            expected.encryptedSelectorBankRequired ||
        actual.encryptedGadgetBankRequired !=
            expected.encryptedGadgetBankRequired ||
        actual.dftBankRequired != expected.dftBankRequired ||
        actual.productionExecutionExposed !=
            expected.productionExecutionExposed ||
        actual.compactSelectorBindingRequired !=
            expected.compactSelectorBindingRequired ||
        actual.authenticatedLeasedKskRequired !=
            expected.authenticatedLeasedKskRequired ||
        actual.streamedGadgetProviderRequired !=
            expected.streamedGadgetProviderRequired ||
        actual.streamedDftProviderRequired !=
            expected.streamedDftProviderRequired) {
        throw GlrError(
            "GLRProductionAdapter: ordinary-refresh preflight is forged, "
            "cross-profile, or overstates production execution readiness");
    }
}

GLRProductionAdapter::OrdinaryRefreshAuthorization
MakeOrdinaryRefreshAuthorization(
    const GLRProductionAdapter::Context& context,
    const std::string& supportCommitment,
    const GLRProductionAdapter::SecurityReport& securityReport,
    std::uint32_t sparseHammingWeight,
    bool reducedExposureCorridor) {
    constexpr std::uint32_t kFoldKeyLevel = 18;
    constexpr std::uint32_t kTransformMaterialLevel = 17;
    if (sparseHammingWeight != 40U || !reducedExposureCorridor) {
        throw GlrError(
            "GLRProductionAdapter: ordinary-refresh authorization requires "
            "the exact h40 reduced-exposure corridor");
    }
    const auto allY =
        glscheme::rns::glr_ship_refresh_only_gl128_all_y_production_preflight(
            context.params, supportCommitment, securityReport);
    const auto& native = allY.authorization;
    const std::string parameterFingerprint =
        glscheme::rns::glr_parameter_fingerprint(context.params);
    if (native.schema !=
            "glscheme.glr_ship_refresh_only_endpoint_authorization.v1" ||
        native.profile_binding_fingerprint != parameterFingerprint ||
        native.support_commitment != supportCommitment ||
        native.bootstrap_profile_fingerprint !=
            securityReport.bootstrap_profile_fingerprint ||
        native.estimator_transcript_sha256 !=
            securityReport.estimator_transcript_sha256 ||
        native.sparse_hamming_weight != 40 ||
        native.sparse_hamming_weight != sparseHammingWeight ||
        native.fold_level != kFoldKeyLevel ||
        native.transform_material_level != kTransformMaterialLevel ||
        native.exposed_q_primes != 7 ||
        native.exposed_special_primes != 14 ||
        !native.corridor_exposure_reduced_keys ||
        !native.profile_fingerprint_bound ||
        !native.support_commitment_bound ||
        !native.security_policy_validated ||
        !native.production_execution_admitted) {
        throw GlrError(
            "GLRProductionAdapter: native ordinary-refresh authorization "
            "did not return the exact canonical Q7+P14/h40 binding");
    }

    GLRProductionAdapter::OrdinaryRefreshAuthorization out;
    out.nativeAllYProductionPreflight = MakeNativeRefreshAllYReceipt(allY);
    out.profileBindingFingerprint =
        FixedBindingText(native.profile_binding_fingerprint);
    out.supportCommitment = FixedBindingText(native.support_commitment);
    out.bootstrapProfileFingerprint =
        FixedBindingText(native.bootstrap_profile_fingerprint);
    out.estimatorTranscriptSha256 =
        FixedBindingText(native.estimator_transcript_sha256);
    out.sparseHammingWeight = native.sparse_hamming_weight;
    out.foldKeyLevel = native.fold_level;
    out.transformMaterialLevel = native.transform_material_level;
    out.exposedQPrimeCount = native.exposed_q_primes;
    out.exposedSpecialPrimeCount = native.exposed_special_primes;
    out.reducedExposureCorridor =
        native.corridor_exposure_reduced_keys;
    out.profileFingerprintBound = native.profile_fingerprint_bound;
    out.supportCommitmentBound = native.support_commitment_bound;
    out.securityPolicyValidated = native.security_policy_validated;
    out.productionAuthorizationAdmitted =
        native.production_execution_admitted;
    // Authorization proves policy metadata only.  The separate execution
    // seam must validate actual selector/gadget/DFT/provider material and
    // recompute this authorization; this object cannot enable it.
    out.productionExecutionExposed = false;
    return out;
}

void RequireOrdinaryRefreshAuthorization(
    const GLRProductionAdapter::OrdinaryRefreshAuthorization& actual,
    const GLRProductionAdapter::OrdinaryRefreshAuthorization& expected) {
    if (!NativeRefreshAllYPreflightEquals(
            actual.nativeAllYProductionPreflight,
            expected.nativeAllYProductionPreflight) ||
        !BindingTextEquals(actual.profileBindingFingerprint,
                           expected.profileBindingFingerprint) ||
        !BindingTextEquals(actual.supportCommitment,
                           expected.supportCommitment) ||
        !BindingTextEquals(actual.bootstrapProfileFingerprint,
                           expected.bootstrapProfileFingerprint) ||
        !BindingTextEquals(actual.estimatorTranscriptSha256,
                           expected.estimatorTranscriptSha256) ||
        actual.sparseHammingWeight != expected.sparseHammingWeight ||
        actual.foldKeyLevel != expected.foldKeyLevel ||
        actual.transformMaterialLevel != expected.transformMaterialLevel ||
        actual.exposedQPrimeCount != expected.exposedQPrimeCount ||
        actual.exposedSpecialPrimeCount != expected.exposedSpecialPrimeCount ||
        actual.reducedExposureCorridor !=
            expected.reducedExposureCorridor ||
        actual.profileFingerprintBound != expected.profileFingerprintBound ||
        actual.supportCommitmentBound != expected.supportCommitmentBound ||
        actual.securityPolicyValidated != expected.securityPolicyValidated ||
        actual.productionAuthorizationAdmitted !=
            expected.productionAuthorizationAdmitted ||
        actual.productionExecutionExposed !=
            expected.productionExecutionExposed) {
        throw GlrError(
            "GLRProductionAdapter: ordinary-refresh authorization evidence "
            "is forged, cross-report, or overstates execution readiness");
    }
}

void RequireCanonicalOrdinaryRefreshExecutionEvidence(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::NativeRefreshEndpointResult& result,
    const GLRProductionAdapter::NativeRefreshEndpointEvidence& evidence) {
    const auto expected = MakeCanonicalOrdinaryRefreshPreflight(context);
    const auto& endpoint = expected.endpoint;
    const auto& census = expected.native;
    const auto& pack = evidence.pack;
    const std::uint64_t xTraceRotations =
        census.centered_refreshes * census.x_trace_rotations_per_readout;
    const std::uint64_t wTraceRotations =
        census.centered_refreshes * census.w_trace_rotations_per_readout;
    const std::uint64_t exponentNodes =
        2ULL * context.n() * expected.requiredSparseHammingWeight *
        census.centered_refreshes;
    const bool xCenteringUnderflow =
        pack.x_centering_monomial_multiplies <
        pack.checkpoint_replay_x_centering_monomial_multiplies;
    const bool wDualUnderflow =
        pack.w_dual_monomial_multiplies <
        pack.checkpoint_replay_w_dual_monomial_multiplies;
    const bool wDualAddUnderflow =
        pack.w_dual_accumulator_additions <
        pack.checkpoint_replay_w_dual_accumulator_additions;
    const std::string parameterFingerprint =
        glscheme::rns::glr_parameter_fingerprint(context.params);

    if (result.representation !=
            glscheme::rns::GlrShipRefreshOnlyEndpointRepresentation::refreshed_xy ||
        result.input_level != endpoint.input_level ||
        result.output_level != endpoint.output_level ||
        !evidence.cts_xinv_used ||
        !evidence.public_scale_normalization_used ||
        !evidence.primary_to_sparse_used || !evidence.packed_ship_used ||
        !evidence.stc_xfwd_used || !evidence.provider_secret_free ||
        evidence.normalization_multiplier != endpoint.normalization_multiplier ||
        evidence.input_level != endpoint.input_level ||
        evidence.cts_output_level != endpoint.cts_output_level ||
        evidence.normalized_level != endpoint.normalized_level ||
        evidence.packed_level != endpoint.packed_level ||
        evidence.output_level != endpoint.output_level ||
        evidence.rescale_stride != endpoint.rescale_stride ||
        evidence.required_input_live_q_primes !=
            endpoint.required_input_live_q_primes ||
        evidence.normalization_rescale_count !=
            endpoint.normalization_rescale_count ||
        !evidence.strict_integer_normalization || evidence.scale_snapping_used ||
        evidence.fold_level != endpoint.fold_level ||
        evidence.transform_material_level != endpoint.transform_material_level ||
        evidence.validated_key_level != endpoint.fold_level ||
        evidence.transform_material_level_drop != 1U ||
        !evidence.transform_material_alignment_safe ||
        !evidence.canonical_production_authorized ||
        evidence.pack_parameter_fingerprint != parameterFingerprint ||
        !IsCanonicalSha256Root(
            evidence.pack_input_ciphertext_commitment_sha256) ||
        !IsCanonicalSha256Root(
            evidence.pack_execution_material_commitment_sha256) ||
        !IsCanonicalSha256Root(
            evidence.pack_checkpoint_chain_commitment_sha256) ||
        !evidence.pack_complete_coordinate_cover ||
        !evidence.ciphertext_value_execution_performed ||
        evidence.value_noise_acceptance_recorded ||
        pack.centered_refreshes != census.centered_refreshes ||
        pack.coefficients_packed != census.coefficients_packed ||
        pack.sparse_to_primary_switches != census.centered_refreshes ||
        pack.exponent_ladder_nodes != exponentNodes ||
        pack.gadget_applies != 2ULL * exponentNodes ||
        !pack.streamed_exponent_leaf_batch_used ||
        pack.streamed_exponent_leaf_batch_invocations != 41943040ULL ||
        pack.streamed_exponent_leaf_tables_batched != exponentNodes ||
        pack.streamed_exponent_leaf_pair_visits != 671088640ULL ||
        pack.streamed_exponent_leaf_scalar_equivalent_pair_visits !=
            5368709120ULL ||
        pack.streamed_exponent_leaf_max_batch_size != 8U ||
        pack.streamed_exponent_leaf_peak_accumulators != 8U ||
        pack.streamed_exponent_leaf_peak_scratch_polys != 1U ||
        pack.x_trace_rotations != xTraceRotations ||
        pack.w_trace_rotations != wTraceRotations ||
        xCenteringUnderflow || wDualUnderflow || wDualAddUnderflow ||
        (!xCenteringUnderflow &&
         pack.x_centering_monomial_multiplies -
                 pack.checkpoint_replay_x_centering_monomial_multiplies !=
             census.x_centering_monomial_multiplies) ||
        (!wDualUnderflow &&
         pack.w_dual_monomial_multiplies -
                 pack.checkpoint_replay_w_dual_monomial_multiplies !=
             census.w_dual_monomial_multiplies) ||
        (!wDualAddUnderflow &&
         pack.w_dual_accumulator_additions -
                 pack.checkpoint_replay_w_dual_accumulator_additions !=
             census.w_dual_accumulator_additions) ||
        pack.checkpoint_chunks_merged == 0 ||
        !pack.checkpoint_commitment_validated_merge_used ||
        !pack.public_centering_used ||
        !pack.homomorphic_readout_projection_used ||
        !pack.provider_secret_free || !pack.exact_prime_w_dual_used ||
        !pack.allocation_free_preflight_used) {
        throw GlrError(
            "GLRProductionAdapter: native ordinary-refresh evidence does not "
            "bind the canonical stage ledger and full all-Y pack census");
    }
}

void RequireOrdinaryRefreshEvidenceMatchesAllYReceipt(
    const GLRProductionAdapter::NativeRefreshEndpointEvidence& evidence,
    const GLRProductionAdapter::NativeRefreshAllYProductionReceipt& receipt) {
    if (receipt.schemaVersion != 1U ||
        receipt.y_rows != 128U || receipt.branches_per_y_row != 2U ||
        receipt.logical_all_y_branch_items != 256ULL ||
        receipt.pair_major_row_tile_width != 8U ||
        receipt.pair_major_row_tiles_per_centered_refresh != 16U ||
        receipt.pair_major_branch_tiles_per_centered_refresh != 32ULL ||
        receipt.total_pair_major_branch_tile_invocations != 1048576ULL ||
        receipt.streamed_unsigned_candidate_count != 320U ||
        receipt.streamed_signed_pair_count != 640U ||
        receipt.streamed_signed_pairs_per_window != 16U ||
        receipt.streamed_exponent_leaf_batch_invocations != 41943040ULL ||
        receipt.streamed_exponent_leaf_tables_batched != 335544320ULL ||
        receipt.streamed_exponent_leaf_pair_visits != 671088640ULL ||
        receipt.streamed_exponent_leaf_scalar_equivalent_pair_visits !=
            5368709120ULL ||
        receipt.streamed_exponent_leaf_max_batch_size != 8U ||
        receipt.streamed_exponent_leaf_peak_accumulators != 8U ||
        receipt.streamed_exponent_leaf_peak_scratch_polys != 1U ||
        !receipt.exact_all_y_coverage ||
        !receipt.full_streamed_physical_schedule_pinned ||
        receipt.context_ciphertext_or_key_allocation_required ||
        !receipt.material_schedule_metadata_admitted ||
        receipt.ciphertext_value_execution_performed ||
        receipt.value_noise_acceptance_recorded ||
        evidence.pack.centered_refreshes != receipt.pack.centered_refreshes ||
        evidence.pack.coefficients_packed != receipt.pack.coefficients_packed ||
        evidence.pack.exponent_ladder_nodes !=
            receipt.scalar_equivalent_exponent_ladder_nodes ||
        evidence.pack.gadget_applies !=
            receipt.scalar_equivalent_gadget_key_applications ||
        !evidence.pack.streamed_exponent_leaf_batch_used ||
        evidence.pack.streamed_exponent_leaf_batch_invocations !=
            receipt.streamed_exponent_leaf_batch_invocations ||
        evidence.pack.streamed_exponent_leaf_tables_batched !=
            receipt.streamed_exponent_leaf_tables_batched ||
        evidence.pack.streamed_exponent_leaf_pair_visits !=
            receipt.streamed_exponent_leaf_pair_visits ||
        evidence.pack.streamed_exponent_leaf_scalar_equivalent_pair_visits !=
            receipt.streamed_exponent_leaf_scalar_equivalent_pair_visits ||
        evidence.pack.streamed_exponent_leaf_max_batch_size !=
            receipt.streamed_exponent_leaf_max_batch_size ||
        evidence.pack.streamed_exponent_leaf_peak_accumulators !=
            receipt.streamed_exponent_leaf_peak_accumulators ||
        evidence.pack.streamed_exponent_leaf_peak_scratch_polys !=
            receipt.streamed_exponent_leaf_peak_scratch_polys) {
        throw GlrError(
            "GLRProductionAdapter: native ordinary-refresh evidence is not "
            "bound to the canonical all-Y production preflight receipt");
    }
}

bool DirectVectorPlanEquals(
    const GLRProductionAdapter::NativeDirectVectorPlan& lhs,
    const GLRProductionAdapter::NativeDirectVectorPlan& rhs) {
    return lhs.n == rhs.n && lhs.p == rhs.p && lhs.phi == rhs.phi &&
           lhs.hamming_weight == rhs.hamming_weight &&
           lhs.selector_level == rhs.selector_level &&
           lhs.active_q_primes == rhs.active_q_primes &&
           lhs.logical_slots == rhs.logical_slots &&
           lhs.unsigned_candidate_count == rhs.unsigned_candidate_count &&
           lhs.max_unsigned_candidates_per_ordinal ==
               rhs.max_unsigned_candidates_per_ordinal &&
           lhs.signed_selector_count == rhs.signed_selector_count &&
           lhs.bytes_per_selector_ciphertext ==
               rhs.bytes_per_selector_ciphertext &&
           lhs.exact_resident_selector_bytes ==
               rhs.exact_resident_selector_bytes &&
           lhs.streamed_peak_selector_bytes ==
               rhs.streamed_peak_selector_bytes &&
           lhs.bytes_per_compact_selector_record ==
               rhs.bytes_per_compact_selector_record &&
           lhs.exact_compact_selector_bytes ==
               rhs.exact_compact_selector_bytes &&
           lhs.bytes_per_encoded_compact_selector_record ==
               rhs.bytes_per_encoded_compact_selector_record &&
           lhs.exact_encoded_compact_selector_bytes ==
               rhs.exact_encoded_compact_selector_bytes &&
           lhs.compact_streamed_peak_selector_bytes ==
               rhs.compact_streamed_peak_selector_bytes &&
           lhs.compact_payload_reduction_bytes ==
               rhs.compact_payload_reduction_bytes &&
           lhs.plaintext_ciphertext_products ==
               rhs.plaintext_ciphertext_products &&
           lhs.tree_product_nodes == rhs.tree_product_nodes &&
           lhs.multiplicative_depth == rhs.multiplicative_depth &&
           lhs.rescale_stride == rhs.rescale_stride &&
           lhs.physical_q_prime_drops == rhs.physical_q_prime_drops &&
           lhs.output_level == rhs.output_level &&
           lhs.q_depth_sufficient == rhs.q_depth_sufficient;
}

GLRProductionAdapter::DirectVectorAllYReturnPreflight
MakeDirectVectorPrimaryAllYReturnPreflight(
    const GLRProductionAdapter::Context& context) {
    constexpr std::uint32_t kHammingWeight = 40;
    constexpr std::uint32_t kSelectorLevel =
        glscheme::rns::kGl128DirectSelectorLevel;
    const auto windows = glscheme::rns::glr_ship_make_windows(
        128, 256, kHammingWeight, 0, 2, 2, 2);
    const auto plan = glscheme::rns::glr_model_ship_direct_vector_plan(
        context.params, kHammingWeight, kSelectorLevel, windows);
    if (plan.n != 128 || plan.p != 257 || plan.phi != 256 ||
        plan.hamming_weight != 40 ||
        plan.selector_level != glscheme::rns::kGl128DirectSelectorLevel ||
        plan.active_q_primes != context.active_q_primes(kSelectorLevel) ||
        plan.logical_slots != 32768ULL ||
        plan.unsigned_candidate_count != 320ULL ||
        plan.signed_selector_count != 640ULL ||
        plan.plaintext_ciphertext_products != 1280ULL ||
        plan.tree_product_nodes != 78ULL ||
        plan.multiplicative_depth != 7 || plan.rescale_stride != 2 ||
        plan.physical_q_prime_drops != 14 ||
        plan.output_level != glscheme::rns::kGl128DirectOutputLevel ||
        !plan.q_depth_sufficient) {
        throw GlrError(
            "GLRProductionAdapter: native direct-vector h40 plan diverged "
            "from the canonical L0/Q25 -> L14 ledger");
    }

    GLRProductionAdapter::DirectVectorAllYReturnPreflight out;
    out.yRows = context.n();
    out.selectorLevel = plan.selector_level;
    out.activeSelectorQPrimes = plan.active_q_primes;
    out.directOutputLevel = plan.output_level;
    out.directMultiplicativeDepth = plan.multiplicative_depth;
    out.rescaleStride = plan.rescale_stride;
    out.physicalQPrimeDropsPerRow = plan.physical_q_prime_drops;
    out.logicalXwSlotsPerRow = plan.logical_slots;
    out.totalXwSlots = CheckedMul(out.yRows, plan.logical_slots,
                                  "modeling direct-vector all-Y slots");
    out.selectorCiphertextsVisited = CheckedMul(
        out.yRows, plan.plaintext_ciphertext_products,
        "modeling direct-vector selector visits");
    out.selectorProviderLeases = out.selectorCiphertextsVisited;
    out.plaintextCiphertextProducts = out.selectorCiphertextsVisited;
    out.leafRescales = CheckedMul(
        out.yRows, 2ULL * kHammingWeight,
        "modeling direct-vector leaf rescales");
    out.treeProductNodes = CheckedMul(
        out.yRows, plan.tree_product_nodes,
        "modeling direct-vector tree products");
    out.treeRelinearizations = out.treeProductNodes;
    // The streamed implementation holds one synchronous relinearization-key
    // lease for each complete branch, independent of its six frontiers.
    out.treeRelinearizationKeyProviderLeases = CheckedMul(
        out.yRows, 2, "modeling direct-vector relin leases");
    // h=40 has one carried node at each of the 5->3 and 3->2 frontiers,
    // independently in both real/imaginary branches.
    out.treeCarryLevelAlignments = CheckedMul(
        out.yRows, 4, "modeling direct-vector carry alignments");
    out.treeRescales = out.treeProductNodes;
    out.conjugationKeySwitches = CheckedMul(
        out.yRows, 2, "modeling direct-vector conjugations");
    out.expectedMaxLiveYRows = 1;
    out.representationScaleFactor =
        CheckedMul(context.n(), context.phi(),
                   "modeling direct-vector trace scale restoration");
    out.packedInputLevel = glscheme::rns::kGl128DirectOutputLevel;
    out.transformMaterialLevel =
        glscheme::rns::kGl128BootstrapForwardTransformMaterialLevel;
    out.transformKeyLevel = glscheme::rns::kGl128DirectOutputLevel;
    out.outputLevel = glscheme::rns::kGl128DirectForwardReturnLevel;
    out.forwardPhysicalQPrimeDrops = 4;
    out.expectedDftPlaintextVisits = 2;
    out.strictYOrderRequired = true;
    out.fullYCoverageRequired = true;
    out.primaryRingRSlotRowsRequired = true;
    out.slotToCoeffPerRowRequired = true;
    out.traceRepresentationScaleRestored = true;
    out.boundedRowPackBoundaryImplemented = true;
    out.fullReturnBoundaryImplemented = true;
    out.canonicalH40CiphertextValueExecutionPerformed = false;
    out.canonicalH40DecryptedValueNoiseAcceptanceRecorded = false;
    return out;
}

bool DirectVectorAllYReturnPreflightEquals(
    const GLRProductionAdapter::DirectVectorAllYReturnPreflight& lhs,
    const GLRProductionAdapter::DirectVectorAllYReturnPreflight& rhs) {
    return lhs.yRows == rhs.yRows &&
           lhs.selectorLevel == rhs.selectorLevel &&
           lhs.activeSelectorQPrimes == rhs.activeSelectorQPrimes &&
           lhs.directOutputLevel == rhs.directOutputLevel &&
           lhs.directMultiplicativeDepth == rhs.directMultiplicativeDepth &&
           lhs.rescaleStride == rhs.rescaleStride &&
           lhs.physicalQPrimeDropsPerRow ==
               rhs.physicalQPrimeDropsPerRow &&
           lhs.logicalXwSlotsPerRow == rhs.logicalXwSlotsPerRow &&
           lhs.totalXwSlots == rhs.totalXwSlots &&
           lhs.selectorCiphertextsVisited ==
               rhs.selectorCiphertextsVisited &&
           lhs.selectorProviderLeases == rhs.selectorProviderLeases &&
           lhs.plaintextCiphertextProducts ==
               rhs.plaintextCiphertextProducts &&
           lhs.leafRescales == rhs.leafRescales &&
           lhs.treeProductNodes == rhs.treeProductNodes &&
           lhs.treeRelinearizations == rhs.treeRelinearizations &&
           lhs.treeRelinearizationKeyProviderLeases ==
               rhs.treeRelinearizationKeyProviderLeases &&
           lhs.treeCarryLevelAlignments ==
               rhs.treeCarryLevelAlignments &&
           lhs.treeRescales == rhs.treeRescales &&
           lhs.conjugationKeySwitches == rhs.conjugationKeySwitches &&
           lhs.expectedMaxLiveYRows == rhs.expectedMaxLiveYRows &&
           lhs.representationScaleFactor == rhs.representationScaleFactor &&
           lhs.packedInputLevel == rhs.packedInputLevel &&
           lhs.transformMaterialLevel == rhs.transformMaterialLevel &&
           lhs.transformKeyLevel == rhs.transformKeyLevel &&
           lhs.outputLevel == rhs.outputLevel &&
           lhs.forwardPhysicalQPrimeDrops ==
               rhs.forwardPhysicalQPrimeDrops &&
           lhs.expectedDftPlaintextVisits ==
               rhs.expectedDftPlaintextVisits &&
           lhs.strictYOrderRequired == rhs.strictYOrderRequired &&
           lhs.fullYCoverageRequired == rhs.fullYCoverageRequired &&
           lhs.primaryRingRSlotRowsRequired ==
               rhs.primaryRingRSlotRowsRequired &&
           lhs.slotToCoeffPerRowRequired == rhs.slotToCoeffPerRowRequired &&
           lhs.traceRepresentationScaleRestored ==
               rhs.traceRepresentationScaleRestored &&
           lhs.boundedRowPackBoundaryImplemented ==
               rhs.boundedRowPackBoundaryImplemented &&
           lhs.fullReturnBoundaryImplemented ==
               rhs.fullReturnBoundaryImplemented &&
           lhs.canonicalH40CiphertextValueExecutionPerformed ==
               rhs.canonicalH40CiphertextValueExecutionPerformed &&
           lhs.canonicalH40DecryptedValueNoiseAcceptanceRecorded ==
               rhs.canonicalH40DecryptedValueNoiseAcceptanceRecorded;
}

GLRProductionAdapter::DirectVectorPrimaryAuthorization
MakeDirectVectorPrimaryAuthorization(
    const GLRProductionAdapter::Context& context,
    const std::string& supportCommitment,
    const GLRProductionAdapter::SecurityReport& sparseReport,
    const GLRProductionAdapter::NativeDirectVectorDensePrimarySecurityEvidence&
        denseEvidence,
    const GLRProductionAdapter::DirectVectorOwnerKeyLineage& ownerKeyLineage) {
    constexpr std::uint32_t kHammingWeight = 40;
    auto windows = glscheme::rns::glr_ship_make_windows(
        128, 256, kHammingWeight, 0, 2, 2, 2);
    const std::string expectedSupport =
        glscheme::rns::glr_ship_support_commitment(128, 256, windows);
    if (supportCommitment != expectedSupport) {
        throw GlrError(
            "GLRProductionAdapter: direct-vector authorization requires "
            "the exact canonical practical h40 support commitment");
    }
    glscheme::rns::GlrShipDirectVectorProductionCandidateMetadata candidate;
    candidate.hamming_weight = kHammingWeight;
    candidate.sparse_public_input_level = context.params.levels() - 1;
    candidate.sparse_public_input_active_q_primes = 1;
    candidate.sparse_public_input_key_domain =
        glscheme::rns::GlrShipDirectVectorCiphertextKeyDomain::sparse;
    candidate.selector_level = glscheme::rns::kGl128DirectSelectorLevel;
    candidate.selector_key_domain =
        glscheme::rns::GlrShipDirectVectorCiphertextKeyDomain::primary;
    candidate.relinearization_key = {
        GlrKsDirection::primary_sq_to_primary, 0};
    candidate.relinearization_first_frontier_level =
        glscheme::rns::kGl128DirectFirstRelinLevel;
    candidate.conjugation_key = {
        GlrKsDirection::conjugation_to_primary, 0};
    candidate.conjugation_level = glscheme::rns::kGl128DirectOutputLevel;
    candidate.reserved_xw_forward_return_output_level =
        glscheme::rns::kGl128DirectForwardReturnLevel;
    candidate.reserved_transform_material_level =
        glscheme::rns::kGl128BootstrapForwardTransformMaterialLevel;
    candidate.windows = std::move(windows);
    candidate.support_commitment = supportCommitment;
    candidate.owner_key_seed_commitment =
        ownerKeyLineage.ownerKskSeedCommitment;
    candidate.primary_secret_lineage_commitment =
        ownerKeyLineage.primarySecretLineageCommitment;
    candidate.sparse_secret_lineage_commitment =
        ownerKeyLineage.sparseSecretLineageCommitment;

    GLRProductionAdapter::DirectVectorPrimaryAuthorization out;
    out.native =
        glscheme::rns::glr_authorize_ship_direct_vector_gl128_primary_candidate(
            context.params, candidate, sparseReport, denseEvidence);
    out.allYReturn = MakeDirectVectorPrimaryAllYReturnPreflight(context);
    out.ownerKeyLineage = ownerKeyLineage;
    out.metadataAuthorizationOnly = true;
    out.ownerKeyLineageBound = true;
    out.productionH40CiphertextValueExecutionPerformed = false;
    out.productionH40DecryptedValueNoiseAcceptanceRecorded = false;
    return out;
}

bool DirectVectorOwnerKeyLineageEquals(
    const GLRProductionAdapter::DirectVectorOwnerKeyLineage& lhs,
    const GLRProductionAdapter::DirectVectorOwnerKeyLineage& rhs) {
    return lhs.ownerKskSeedCommitment == rhs.ownerKskSeedCommitment &&
           lhs.primarySecretLineageCommitment ==
               rhs.primarySecretLineageCommitment &&
           lhs.sparseSecretLineageCommitment ==
               rhs.sparseSecretLineageCommitment;
}

bool DirectSparseSecurityEquals(
    const glscheme::rns::GlrShipDirectVectorSparseH40SecurityEvidence& lhs,
    const glscheme::rns::GlrShipDirectVectorSparseH40SecurityEvidence& rhs) {
    return lhs.report_artifact == rhs.report_artifact &&
           lhs.estimator_transcript_sha256 ==
               rhs.estimator_transcript_sha256 &&
           lhs.estimator_commit == rhs.estimator_commit &&
           lhs.secret_distribution == rhs.secret_distribution &&
           lhs.bootstrap_profile_fingerprint ==
               rhs.bootstrap_profile_fingerprint &&
           lhs.estimated_security_bits == rhs.estimated_security_bits &&
           lhs.sparse_estimate_modulus_bits ==
               rhs.sparse_estimate_modulus_bits &&
           lhs.hamming_weight == rhs.hamming_weight &&
           lhs.exposed_q_primes == rhs.exposed_q_primes &&
           lhs.exposed_special_primes == rhs.exposed_special_primes;
}

bool DirectDenseSecurityEquals(
    const GLRProductionAdapter::NativeDirectVectorDensePrimarySecurityEvidence&
        lhs,
    const GLRProductionAdapter::NativeDirectVectorDensePrimarySecurityEvidence&
        rhs) {
    return lhs.transcript_artifact == rhs.transcript_artifact &&
           lhs.transcript_sha256 == rhs.transcript_sha256 &&
           lhs.estimator_name == rhs.estimator_name &&
           lhs.estimator_commit == rhs.estimator_commit &&
           lhs.estimator_backend == rhs.estimator_backend &&
           lhs.security_model == rhs.security_model &&
           lhs.secret_distribution == rhs.secret_distribution &&
           lhs.estimated_security_bits == rhs.estimated_security_bits &&
           lhs.ring_dimension == rhs.ring_dimension &&
           lhs.q_bits == rhs.q_bits && lhs.qp_bits == rhs.qp_bits;
}

void RequireDirectVectorPrimaryAuthorization(
    const GLRProductionAdapter::DirectVectorPrimaryAuthorization& actual,
    const GLRProductionAdapter::DirectVectorPrimaryAuthorization& expected) {
    const auto& lhs = actual.native;
    const auto& rhs = expected.native;
    if (lhs.schema != rhs.schema ||
        !DirectVectorPlanEquals(lhs.plan, rhs.plan) ||
        !DirectSparseSecurityEquals(lhs.sparse_h40_security,
                                    rhs.sparse_h40_security) ||
        !DirectDenseSecurityEquals(lhs.dense_primary_security,
                                   rhs.dense_primary_security) ||
        lhs.parameter_fingerprint != rhs.parameter_fingerprint ||
        lhs.support_commitment != rhs.support_commitment ||
        lhs.owner_key_seed_commitment != rhs.owner_key_seed_commitment ||
        lhs.primary_secret_lineage_commitment !=
            rhs.primary_secret_lineage_commitment ||
        lhs.sparse_secret_lineage_commitment !=
            rhs.sparse_secret_lineage_commitment ||
        lhs.sparse_public_input_q0 != rhs.sparse_public_input_q0 ||
        lhs.sparse_public_input_level != rhs.sparse_public_input_level ||
        lhs.sparse_public_input_active_q_primes !=
            rhs.sparse_public_input_active_q_primes ||
        lhs.sparse_public_input_key_domain !=
            rhs.sparse_public_input_key_domain ||
        lhs.selector_key_domain != rhs.selector_key_domain ||
        lhs.relinearization_key != rhs.relinearization_key ||
        lhs.relinearization_first_frontier_level !=
            rhs.relinearization_first_frontier_level ||
        lhs.conjugation_key != rhs.conjugation_key ||
        lhs.conjugation_level != rhs.conjugation_level ||
        lhs.reserved_xw_forward_return_output_level !=
            rhs.reserved_xw_forward_return_output_level ||
        lhs.reserved_transform_material_level !=
            rhs.reserved_transform_material_level ||
        lhs.production_candidate_metadata_authorized !=
            rhs.production_candidate_metadata_authorized ||
        lhs.sparse_h40_q7_p14_report_bound !=
            rhs.sparse_h40_q7_p14_report_bound ||
        lhs.dense_primary_full_qp_report_bound !=
            rhs.dense_primary_full_qp_report_bound ||
        lhs.q0_only_sparse_public_input !=
            rhs.q0_only_sparse_public_input ||
        lhs.primary_selector_ciphertexts !=
            rhs.primary_selector_ciphertexts ||
        lhs.primary_relinearization_key != rhs.primary_relinearization_key ||
        lhs.primary_conjugation_key != rhs.primary_conjugation_key ||
        lhs.direct_output_ring_r_slot_state !=
            rhs.direct_output_ring_r_slot_state ||
        lhs.xw_forward_return_composition_implemented !=
            rhs.xw_forward_return_composition_implemented ||
        lhs.y_coefficient_pack_implemented !=
            rhs.y_coefficient_pack_implemented ||
        lhs.context_ciphertext_or_key_allocation_required !=
            rhs.context_ciphertext_or_key_allocation_required ||
        lhs.selector_storage_admitted != rhs.selector_storage_admitted ||
        lhs.selector_material_generated != rhs.selector_material_generated ||
        lhs.value_execution != rhs.value_execution ||
        !DirectVectorAllYReturnPreflightEquals(actual.allYReturn,
                                               expected.allYReturn) ||
        !DirectVectorOwnerKeyLineageEquals(actual.ownerKeyLineage,
                                           expected.ownerKeyLineage) ||
        actual.metadataAuthorizationOnly != expected.metadataAuthorizationOnly ||
        actual.ownerKeyLineageBound != expected.ownerKeyLineageBound ||
        actual.productionH40CiphertextValueExecutionPerformed !=
            expected.productionH40CiphertextValueExecutionPerformed ||
        actual.productionH40DecryptedValueNoiseAcceptanceRecorded !=
            expected.productionH40DecryptedValueNoiseAcceptanceRecorded) {
        throw GlrError(
            "GLRProductionAdapter: direct-vector authorization receipt is "
            "forged, cross-report, or overstates canonical h40 execution");
    }
}

bool DirectVectorSelectorStorageEvidenceEquals(
    const GLRProductionAdapter::
        NativeDirectVectorSelectorStorageAdmissionEvidence& lhs,
    const GLRProductionAdapter::
        NativeDirectVectorSelectorStorageAdmissionEvidence& rhs) {
    return lhs.schema == rhs.schema &&
           lhs.selector_admission.kind == rhs.selector_admission.kind &&
           lhs.selector_admission.full_selector_payload_bytes ==
               rhs.selector_admission.full_selector_payload_bytes &&
           lhs.selector_admission.stored_selector_payload_bytes ==
               rhs.selector_admission.stored_selector_payload_bytes &&
           lhs.selector_admission.streamed_peak_selector_bytes ==
               rhs.selector_admission.streamed_peak_selector_bytes &&
           lhs.selector_admission.full_manifest_commitment ==
               rhs.selector_admission.full_manifest_commitment &&
           lhs.selector_admission.transport_manifest_commitment ==
               rhs.selector_admission.transport_manifest_commitment &&
           lhs.production_authorization_schema ==
               rhs.production_authorization_schema &&
           lhs.parameter_fingerprint == rhs.parameter_fingerprint &&
           lhs.support_commitment == rhs.support_commitment &&
           lhs.owner_key_seed_commitment == rhs.owner_key_seed_commitment &&
           lhs.primary_secret_lineage_commitment ==
               rhs.primary_secret_lineage_commitment &&
           lhs.sparse_secret_lineage_commitment ==
               rhs.sparse_secret_lineage_commitment &&
           lhs.sparse_security_transcript_sha256 ==
               rhs.sparse_security_transcript_sha256 &&
           lhs.dense_security_transcript_sha256 ==
               rhs.dense_security_transcript_sha256 &&
           lhs.selector_level == rhs.selector_level &&
           lhs.active_q_primes == rhs.active_q_primes &&
           lhs.signed_selector_count == rhs.signed_selector_count &&
           lhs.production_metadata_authorization_bound ==
               rhs.production_metadata_authorization_bound &&
           lhs.compact_authenticated_streaming_admitted ==
               rhs.compact_authenticated_streaming_admitted &&
           lhs.generic_512_mib_cap_widened ==
               rhs.generic_512_mib_cap_widened &&
           lhs.production_generator_enabled ==
               rhs.production_generator_enabled &&
           lhs.manifest_or_payload_generated ==
               rhs.manifest_or_payload_generated;
}

GLRProductionAdapter::DirectVectorPrimarySelectorStorageAuthorization
MakeDirectVectorPrimarySelectorStorageAuthorization(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::DirectVectorPrimaryAuthorization&
        authorization) {
    if (!authorization.metadataAuthorizationOnly ||
        !authorization.ownerKeyLineageBound ||
        authorization.productionH40CiphertextValueExecutionPerformed ||
        authorization.productionH40DecryptedValueNoiseAcceptanceRecorded ||
        !DirectVectorOwnerKeyLineageEquals(
            authorization.ownerKeyLineage,
            {authorization.native.owner_key_seed_commitment,
             authorization.native.primary_secret_lineage_commitment,
             authorization.native.sparse_secret_lineage_commitment}) ||
        !DirectVectorAllYReturnPreflightEquals(
            authorization.allYReturn,
            MakeDirectVectorPrimaryAllYReturnPreflight(context))) {
        throw GlrError(
            "GLRProductionAdapter: selector-storage source authorization "
            "overstates h40 execution or has a forged all-Y ledger");
    }

    GLRProductionAdapter::DirectVectorPrimarySelectorStorageAuthorization out;
    out.native =
        glscheme::rns::
            glr_authorize_ship_direct_vector_gl128_selector_storage(
                authorization.native);
    out.canonicalPlan = authorization.native.plan;
    if (out.native.selector_admission.kind !=
            glscheme::rns::GlrShipDirectSelectorAdmissionKind::
                compact_authenticated_production_streamed ||
        out.native.selector_admission.stored_selector_payload_bytes !=
            authorization.native.plan.exact_encoded_compact_selector_bytes ||
        out.native.selector_admission.streamed_peak_selector_bytes !=
            authorization.native.plan.compact_streamed_peak_selector_bytes ||
        out.native.selector_admission.stored_selector_payload_bytes <=
            (UINT64_C(512) << 20) ||
        out.native.selector_level != authorization.native.plan.selector_level ||
        out.native.active_q_primes !=
            authorization.native.plan.active_q_primes ||
        out.native.signed_selector_count !=
            authorization.native.plan.signed_selector_count ||
        out.native.sparse_security_transcript_sha256 !=
            authorization.native.sparse_h40_security
                .estimator_transcript_sha256 ||
        out.native.dense_security_transcript_sha256 !=
            authorization.native.dense_primary_security.transcript_sha256 ||
        out.native.owner_key_seed_commitment !=
            authorization.native.owner_key_seed_commitment ||
        out.native.primary_secret_lineage_commitment !=
            authorization.native.primary_secret_lineage_commitment ||
        out.native.sparse_secret_lineage_commitment !=
            authorization.native.sparse_secret_lineage_commitment ||
        !out.native.production_metadata_authorization_bound ||
        !out.native.compact_authenticated_streaming_admitted ||
        out.native.generic_512_mib_cap_widened ||
        !out.native.production_generator_enabled ||
        out.native.manifest_or_payload_generated) {
        throw GlrError(
            "GLRProductionAdapter: native selector-storage authorization "
            "did not return the exact modeled compact canonical admission");
    }
    out.metadataAuthorizationOnly = true;
    out.ownerKeyLineage = authorization.ownerKeyLineage;
    out.canonicalPlanBound = true;
    out.bothSecurityRootsBound = true;
    out.ownerKeyLineageBound = true;
    out.selectorGenerationEnabled = true;
    out.selectorManifestOrPayloadGenerated = false;
    out.selectorMaterialReady = false;
    out.valueExecution = false;
    return out;
}

void RequireDirectVectorPrimarySelectorStorageAuthorization(
    const GLRProductionAdapter::
        DirectVectorPrimarySelectorStorageAuthorization& actual,
    const GLRProductionAdapter::
        DirectVectorPrimarySelectorStorageAuthorization& expected) {
    if (!DirectVectorSelectorStorageEvidenceEquals(actual.native,
                                                   expected.native) ||
        !DirectVectorPlanEquals(actual.canonicalPlan,
                                expected.canonicalPlan) ||
        !DirectVectorOwnerKeyLineageEquals(actual.ownerKeyLineage,
                                           expected.ownerKeyLineage) ||
        actual.metadataAuthorizationOnly !=
            expected.metadataAuthorizationOnly ||
        actual.canonicalPlanBound != expected.canonicalPlanBound ||
        actual.bothSecurityRootsBound != expected.bothSecurityRootsBound ||
        actual.ownerKeyLineageBound != expected.ownerKeyLineageBound ||
        actual.selectorGenerationEnabled !=
            expected.selectorGenerationEnabled ||
        actual.selectorManifestOrPayloadGenerated !=
            expected.selectorManifestOrPayloadGenerated ||
        actual.selectorMaterialReady != expected.selectorMaterialReady ||
        actual.valueExecution != expected.valueExecution) {
        throw GlrError(
            "GLRProductionAdapter: selector-storage receipt is forged, "
            "cross-authorization, or overstates material/value readiness");
    }
}

GLRProductionAdapter::DirectVectorSelectorRecordPreflight
MakeDirectVectorPrimarySelectorRecordPreflight(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::
        DirectVectorPrimarySelectorStorageAuthorization& storage,
    const GLRProductionAdapter::DirectVectorPrimaryAuthorization&
        authorization) {
    const auto expectedStorage =
        MakeDirectVectorPrimarySelectorStorageAuthorization(
            context, authorization);
    RequireDirectVectorPrimarySelectorStorageAuthorization(
        storage, expectedStorage);
    const auto& plan = storage.canonicalPlan;
    const std::uint64_t returnedBytes =
        plan.bytes_per_compact_selector_record +
        plan.bytes_per_encoded_compact_selector_record;
    if (plan.signed_selector_count != 640 ||
        plan.selector_level != glscheme::rns::kGl128DirectSelectorLevel ||
        plan.active_q_primes != context.active_q_primes(plan.selector_level) ||
        plan.bytes_per_encoded_compact_selector_record == 0 ||
        plan.bytes_per_compact_selector_record == 0 ||
        returnedBytes !=
            plan.bytes_per_compact_selector_record +
                plan.bytes_per_encoded_compact_selector_record ||
        plan.compact_streamed_peak_selector_bytes !=
            plan.bytes_per_compact_selector_record +
                plan.bytes_per_selector_ciphertext) {
        throw GlrError(
            "GLRProductionAdapter: random-access selector record preflight "
            "diverged from the exact canonical record/peak census");
    }

    GLRProductionAdapter::DirectVectorSelectorRecordPreflight out;
    out.schema =
        glscheme::rns::
            kGlrShipDirectVectorGl128SelectorRecordGenerationSchema;
    out.ownerKeyLineage = storage.ownerKeyLineage;
    out.totalRecordCount = plan.signed_selector_count;
    out.selectorLevel = plan.selector_level;
    out.activeQPrimes = plan.active_q_primes;
    out.encodedRecordBytes =
        plan.bytes_per_encoded_compact_selector_record;
    out.expectedReturnedRecordAndEncodingBytes = returnedBytes;
    out.authorizedStreamingPeakBytes =
        plan.compact_streamed_peak_selector_bytes;
    out.productionAuthorizationBound = true;
    out.storageAdmissionBound = true;
    out.ownerKeyLineageBound = true;
    out.deterministicRandomAccessGeneratorAvailable = true;
    out.recordGenerated = false;
    out.manifestOrPayloadGenerated = false;
    out.selectorMaterialReady = false;
    out.valueExecution = false;
    return out;
}

bool DirectVectorSelectorRecordPreflightEquals(
    const GLRProductionAdapter::DirectVectorSelectorRecordPreflight& lhs,
    const GLRProductionAdapter::DirectVectorSelectorRecordPreflight& rhs) {
    return lhs.schema == rhs.schema &&
           DirectVectorOwnerKeyLineageEquals(lhs.ownerKeyLineage,
                                             rhs.ownerKeyLineage) &&
           lhs.totalRecordCount == rhs.totalRecordCount &&
           lhs.selectorLevel == rhs.selectorLevel &&
           lhs.activeQPrimes == rhs.activeQPrimes &&
           lhs.encodedRecordBytes == rhs.encodedRecordBytes &&
           lhs.expectedReturnedRecordAndEncodingBytes ==
               rhs.expectedReturnedRecordAndEncodingBytes &&
           lhs.authorizedStreamingPeakBytes ==
               rhs.authorizedStreamingPeakBytes &&
           lhs.productionAuthorizationBound ==
               rhs.productionAuthorizationBound &&
           lhs.storageAdmissionBound == rhs.storageAdmissionBound &&
           lhs.ownerKeyLineageBound == rhs.ownerKeyLineageBound &&
           lhs.deterministicRandomAccessGeneratorAvailable ==
               rhs.deterministicRandomAccessGeneratorAvailable &&
           lhs.recordGenerated == rhs.recordGenerated &&
           lhs.manifestOrPayloadGenerated ==
               rhs.manifestOrPayloadGenerated &&
           lhs.selectorMaterialReady == rhs.selectorMaterialReady &&
           lhs.valueExecution == rhs.valueExecution;
}

double ExpectedDirectVectorH2OutputScale(
    const GLRProductionAdapter::Context& context) {
    double leafScale = context.params.delta * context.params.delta;
    for (std::uint32_t step = 0; step < 2; ++step) {
        leafScale /= static_cast<double>(
            context.modulus_at(context.active_q_primes(4 + step) - 1).q);
    }
    double outputScale = leafScale * leafScale;
    for (std::uint32_t step = 0; step < 2; ++step) {
        outputScale /= static_cast<double>(
            context.modulus_at(context.active_q_primes(6 + step) - 1).q);
    }
    return outputScale;
}

void RequireDirectVectorH2Evidence(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::NativeDirectVectorEvidence& evidence) {
    if (!evidence.insecure_toy_only || !evidence.evaluator_secret_free ||
        !evidence.all_xw_coefficients_simultaneous ||
        !evidence.simultaneous_x_i_wrap_w_phi_table_covered ||
        !evidence.randomized_nonzero_a || evidence.logical_slots != 32768 ||
        evidence.scalar_center_refreshes != 0 ||
        evidence.selector_ciphertexts_visited != 8 ||
        evidence.selector_provider_leases != 8 ||
        evidence.selector_window_count != 2 ||
        evidence.unsigned_selector_candidates != 2 ||
        !evidence.selector_manifest_authenticated ||
        !evidence.selector_provider_secret_free ||
        evidence.plaintext_ciphertext_products != 8 ||
        evidence.leaf_rescales != 4 || evidence.tree_product_nodes != 2 ||
        evidence.tree_relinearizations != 2 ||
        evidence.tree_relinearization_key_provider_leases != 2 ||
        evidence.tree_carry_level_alignments != 0 ||
        evidence.tree_rescales != 2 ||
        evidence.conjugation_key_switches != 2 ||
        evidence.multiplicative_depth != 2 || evidence.selector_level != 4 ||
        evidence.rescale_stride != 2 ||
        evidence.physical_q_prime_drops != 4 || evidence.output_level != 8 ||
        evidence.output_scale != ExpectedDirectVectorH2OutputScale(context)) {
        throw GlrError(
            "GLRProductionAdapter: insecure h2 smoke evidence does not bind "
            "the exact GL-128-257-N32 L4 -> L8 stride-2 stage");
    }
}

GLRProductionAdapter::DirectVectorH2Stride2SmokeReceipt
MakeDirectVectorH2Stride2SmokeReceipt(
    const GLRProductionAdapter::Context& context,
    const GLRProductionAdapter::NativeDirectVectorEvidence& evidence,
    std::uint64_t ownerCheckedSlots, double worstOwnerSlotError,
    double runtimeSeconds, std::uint64_t peakRssBytes,
    std::uint32_t compactSelectorMaxLive,
    std::uint32_t evaluationKeyMaxLive) {
    constexpr double kErrorCap = 1.0e-6;
    constexpr double kRuntimeCapSeconds = 120.0;
    constexpr std::uint64_t kPeakRssCapBytes = UINT64_C(768) << 20;
    RequireDirectVectorH2Evidence(context, evidence);
    if (ownerCheckedSlots != 32768 ||
        !std::isfinite(worstOwnerSlotError) || worstOwnerSlotError < 0.0 ||
        worstOwnerSlotError >= kErrorCap || !std::isfinite(runtimeSeconds) ||
        runtimeSeconds <= 0.0 || runtimeSeconds >= kRuntimeCapSeconds ||
        peakRssBytes == 0 || peakRssBytes >= kPeakRssCapBytes ||
        compactSelectorMaxLive != 1 || evaluationKeyMaxLive != 1) {
        throw GlrError(
            "GLRProductionAdapter: insecure h2 owner observation exceeds "
            "the exact 32768-slot/error/runtime/RSS/max-live smoke bounds");
    }

    GLRProductionAdapter::DirectVectorH2Stride2SmokeReceipt out;
    out.native = evidence;
    out.ownerCheckedSlots = ownerCheckedSlots;
    out.worstOwnerSlotError = worstOwnerSlotError;
    out.runtimeSeconds = runtimeSeconds;
    out.peakRssBytes = peakRssBytes;
    out.compactSelectorMaxLive = compactSelectorMaxLive;
    out.evaluationKeyMaxLive = evaluationKeyMaxLive;
    out.targetGl128GeometryAndStrideBound = true;
    out.ownerValueObservationBound = true;
    out.explicitlyInsecure = true;
    out.adapterExecutedSmoke = false;
    out.productionH40AuthorizationAdmitted = false;
    out.productionH40ValueExecutionClaimed = false;
    out.productionH40ValueNoiseAcceptanceClaimed = false;
    return out;
}

void RequireDirectVectorH2Stride2SmokeReceipt(
    const GLRProductionAdapter::DirectVectorH2Stride2SmokeReceipt& actual,
    const GLRProductionAdapter::DirectVectorH2Stride2SmokeReceipt& expected) {
    if (actual.ownerCheckedSlots != expected.ownerCheckedSlots ||
        actual.worstOwnerSlotError != expected.worstOwnerSlotError ||
        actual.runtimeSeconds != expected.runtimeSeconds ||
        actual.peakRssBytes != expected.peakRssBytes ||
        actual.compactSelectorMaxLive != expected.compactSelectorMaxLive ||
        actual.evaluationKeyMaxLive != expected.evaluationKeyMaxLive ||
        actual.targetGl128GeometryAndStrideBound !=
            expected.targetGl128GeometryAndStrideBound ||
        actual.ownerValueObservationBound !=
            expected.ownerValueObservationBound ||
        actual.explicitlyInsecure != expected.explicitlyInsecure ||
        actual.adapterExecutedSmoke != expected.adapterExecutedSmoke ||
        actual.productionH40AuthorizationAdmitted !=
            expected.productionH40AuthorizationAdmitted ||
        actual.productionH40ValueExecutionClaimed !=
            expected.productionH40ValueExecutionClaimed ||
        actual.productionH40ValueNoiseAcceptanceClaimed !=
            expected.productionH40ValueNoiseAcceptanceClaimed) {
        throw GlrError(
            "GLRProductionAdapter: insecure h2 smoke receipt is forged or "
            "overstates production execution/security");
    }
}

}  // namespace

GLRProductionAdapter::OrdinaryRefreshPackSession::
    OrdinaryRefreshPackSession(NativeRefreshPackAccumulator accumulator)
    : m_accumulator(std::move(accumulator)) {}

std::uint64_t
GLRProductionAdapter::OrdinaryRefreshPackSession::NextCoordinate()
    const noexcept {
    return m_accumulator.initialized ? m_accumulator.next_coordinate : 0U;
}

std::uint64_t
GLRProductionAdapter::OrdinaryRefreshPackSession::TotalCoordinates()
    const noexcept {
    return m_accumulator.initialized ? m_accumulator.total_coordinates : 0U;
}

bool GLRProductionAdapter::OrdinaryRefreshPackSession::
    CoordinateCoverComplete() const noexcept {
    return m_accumulator.initialized && m_accumulator.total_coordinates != 0U &&
           m_accumulator.next_coordinate ==
               m_accumulator.total_coordinates;
}

GLRProductionAdapter::OrdinaryRefreshPackFacade::
    OrdinaryRefreshPackFacade(const Context& context) noexcept
    : m_context(&context) {}

GLRProductionAdapter::OrdinaryRefreshPackSession
GLRProductionAdapter::OrdinaryRefreshPackFacade::Begin(
    const Ciphertext& sparseCoefficientInput,
    const NativeRefreshPackParameters& parameters,
    const NativeRefreshPackConfig& config,
    std::uint64_t firstCoordinateCount) const {
    const NativeRefreshTracePreflight plan =
        glscheme::rns::glr_ship_refresh_only_pack_preflight(
            m_context->n(), m_context->p_());
    if (firstCoordinateCount == 0U ||
        firstCoordinateCount > plan.centered_refreshes) {
        throw GlrError(
            "GLRProductionAdapter: resumable ordinary-refresh pack Begin "
            "requires a nonempty prefix within the native coordinate range");
    }

    auto chunk = glscheme::rns::glr_ship_refresh_only_pack_chunk_prime(
        *m_context, sparseCoefficientInput, parameters, config,
        glscheme::rns::GlrShipRefreshOnlyPackCoordinateRange{
            0U, firstCoordinateCount});
    NativeRefreshPackAccumulator accumulator;
    glscheme::rns::glr_ship_refresh_only_pack_merge_prime(
        *m_context, sparseCoefficientInput, parameters, config, accumulator,
        std::move(chunk));
    return OrdinaryRefreshPackSession(std::move(accumulator));
}

void GLRProductionAdapter::OrdinaryRefreshPackFacade::Advance(
    OrdinaryRefreshPackSession& session,
    const Ciphertext& sparseCoefficientInput,
    const NativeRefreshPackParameters& parameters,
    const NativeRefreshPackConfig& config,
    std::uint64_t coordinateCount) const {
    NativeRefreshPackAccumulator& accumulator = session.m_accumulator;
    if (!accumulator.initialized || accumulator.total_coordinates == 0U ||
        accumulator.next_coordinate > accumulator.total_coordinates) {
        throw GlrError(
            "GLRProductionAdapter: resumable ordinary-refresh pack session "
            "is uninitialized or malformed");
    }
    const std::uint64_t remaining =
        accumulator.total_coordinates - accumulator.next_coordinate;
    if (coordinateCount == 0U || coordinateCount > remaining) {
        throw GlrError(
            "GLRProductionAdapter: resumable ordinary-refresh pack Advance "
            "requires a nonempty count within the remaining coordinate range");
    }

    const std::uint64_t begin = accumulator.next_coordinate;
    auto chunk = glscheme::rns::glr_ship_refresh_only_pack_chunk_prime(
        *m_context, sparseCoefficientInput, parameters, config,
        glscheme::rns::GlrShipRefreshOnlyPackCoordinateRange{
            begin, begin + coordinateCount});
    glscheme::rns::glr_ship_refresh_only_pack_merge_prime(
        *m_context, sparseCoefficientInput, parameters, config, accumulator,
        std::move(chunk));
}

GLRProductionAdapter::NativeRefreshPackCheckpointReceipt
GLRProductionAdapter::OrdinaryRefreshPackFacade::SerializeCheckpoint(
    const OrdinaryRefreshPackSession& session,
    const NativeRefreshPackCheckpointSink& sink) const {
    const NativeRefreshPackAccumulator& accumulator = session.m_accumulator;
    const NativeRefreshTracePreflight plan =
        glscheme::rns::glr_ship_refresh_only_pack_preflight(
            m_context->n(), m_context->p_());
    if (!accumulator.initialized ||
        accumulator.total_coordinates != plan.centered_refreshes ||
        accumulator.parameter_fingerprint !=
            glscheme::rns::glr_parameter_fingerprint(m_context->params)) {
        throw GlrError(
            "GLRProductionAdapter: resumable ordinary-refresh checkpoint "
            "is not bound to this native context");
    }
    return glscheme::rns::
        glr_serialize_ship_refresh_only_pack_accumulator(
            *m_context, accumulator, sink);
}

GLRProductionAdapter::OrdinaryRefreshPackSession
GLRProductionAdapter::OrdinaryRefreshPackFacade::Resume(
    const NativeRefreshPackCheckpointReceipt& authenticatedReceipt,
    const NativeRefreshPackCheckpointSource& source) const {
    NativeRefreshPackAccumulator accumulator =
        glscheme::rns::glr_deserialize_ship_refresh_only_pack_accumulator(
            *m_context, authenticatedReceipt, source);
    const NativeRefreshTracePreflight plan =
        glscheme::rns::glr_ship_refresh_only_pack_preflight(
            m_context->n(), m_context->p_());
    if (!accumulator.initialized ||
        accumulator.total_coordinates != plan.centered_refreshes ||
        accumulator.parameter_fingerprint !=
            glscheme::rns::glr_parameter_fingerprint(m_context->params)) {
        throw GlrError(
            "GLRProductionAdapter: resumed ordinary-refresh checkpoint is "
            "not bound to this native context");
    }
    return OrdinaryRefreshPackSession(std::move(accumulator));
}

GLRProductionAdapter::OrdinaryRefreshPackFinalizedResult
GLRProductionAdapter::OrdinaryRefreshPackFacade::Finalize(
    OrdinaryRefreshPackSession&& session,
    const Ciphertext& sparseCoefficientInput,
    const NativeRefreshPackParameters& parameters,
    const NativeRefreshPackConfig& config) const {
    if (!session.CoordinateCoverComplete()) {
        throw GlrError(
            "GLRProductionAdapter: resumable ordinary-refresh pack Finalize "
            "requires a complete gap-free coordinate cover");
    }
    NativeRefreshPackEvidence evidence;
    NativeRefreshPackResult result =
        glscheme::rns::glr_ship_refresh_only_pack_finalize_prime(
            *m_context, sparseCoefficientInput, parameters, config,
            std::move(session.m_accumulator), &evidence);
    return OrdinaryRefreshPackFinalizedResult{
        std::move(result), std::move(evidence)};
}

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

GLRProductionAdapter::CompactEvaluationKeys::CompactEvaluationKeys(
    NativeCompactKskSetGenerationResult generation,
    std::unique_ptr<NativeKeyProvider> provider)
    : m_generation(std::move(generation)),
      m_provider(std::move(provider)) {
    if (!m_provider) {
        throw GlrError(
            "GLRProductionAdapter: null compact evaluation-key provider");
    }
}

const GLRProductionAdapter::NativeCompactKskSetGenerationResult&
GLRProductionAdapter::CompactEvaluationKeys::GetGenerationResult()
    const noexcept {
    return m_generation;
}

const GLRProductionAdapter::NativeKeyProvider&
GLRProductionAdapter::CompactEvaluationKeys::GetNativeProvider() const {
    if (!m_provider) {
        throw GlrError(
            "GLRProductionAdapter: moved-from compact evaluation-key "
            "provider");
    }
    return *m_provider;
}

bool GLRProductionAdapter::CompactEvaluationKeys::HasKey(
    const KeyId& id) const noexcept {
    return m_provider != nullptr && m_provider->has_key(id);
}

GLRProductionAdapter::CompactDirectBootstrapKeys::
    CompactDirectBootstrapKeys(
        NativeGL128DirectBootstrapKeyGenerationResult generation,
        std::unique_ptr<NativeKeyProvider> provider)
    : m_generation(std::move(generation)),
      m_provider(std::move(provider)) {
    if (!m_provider) {
        throw GlrError(
            "GLRProductionAdapter: null compact direct-bootstrap provider");
    }
}

const GLRProductionAdapter::
    NativeGL128DirectBootstrapKeyGenerationResult&
GLRProductionAdapter::CompactDirectBootstrapKeys::GetGenerationResult()
    const noexcept {
    return m_generation;
}

const GLRProductionAdapter::NativeGL128DirectBootstrapKeyLineageBinding&
GLRProductionAdapter::CompactDirectBootstrapKeys::GetLineage()
    const noexcept {
    return m_generation.lineage;
}

const GLRProductionAdapter::NativeKeyProvider&
GLRProductionAdapter::CompactDirectBootstrapKeys::GetNativeProvider() const {
    if (!m_provider) {
        throw GlrError(
            "GLRProductionAdapter: moved-from compact direct-bootstrap "
            "provider");
    }
    return *m_provider;
}

bool GLRProductionAdapter::CompactDirectBootstrapKeys::HasKey(
    const KeyId& id) const noexcept {
    return m_provider != nullptr && m_provider->has_key(id);
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
    Context context = glscheme::rns::glr_gl128_make_context();
    const auto receipt = glscheme::rns::glr_gl128_validate_context(context);
    if (context.params.name != profile.parameter_source ||
        receipt.profile_name != profile.parameter_source ||
        receipt.matrix_order != profile.n ||
        context.params.p != profile.p ||
        receipt.matrix_count != profile.phi ||
        receipt.parameter_fingerprint !=
            profile.binding_fingerprint) {
        throw GlrError(
            "GLRProductionAdapter: canonical profile/context binding mismatch");
    }
    return GLRProductionAdapter(std::move(context));
}

GLRProductionAdapter::GLRProductionAdapter(Context context)
    : m_context(std::move(context)) {}

const GLRProductionAdapter::Context& GLRProductionAdapter::GetContext() const noexcept {
    return m_context;
}

GLRProductionAdapter::NativeGL128ProfileReceipt
GLRProductionAdapter::GetCanonicalProfileReceipt() const {
    return glscheme::rns::glr_gl128_validate_context(m_context);
}

GLRProductionAdapter::NativeGL128SchemeKeyPlan
GLRProductionAdapter::PlanCanonicalSchemeKeys(
    const NativeGL128SchemeWorkload& workload) const {
    auto plan = glscheme::rns::glr_gl128_scheme_key_plan(m_context, workload);
    RequireCanonicalSchemeKeyPlan(m_context, plan);
    return plan;
}

GLRProductionAdapter::NativeGL128DirectBootstrapKeyPlan
GLRProductionAdapter::PlanCanonicalDirectBootstrapKeys() const {
    return glscheme::rns::glr_gl128_direct_bootstrap_key_plan(m_context);
}

GLRProductionAdapter::NativeValidatedDftPlaintextProviderSession
GLRProductionAdapter::OpenDftPlaintextSession(
    const NativeRefreshDftPlaintextProvider& provider,
    const NativeRefreshDftPlaintextBinding& binding) const {
    return glscheme::rns::glr_open_dft_plaintext_provider_session(
        m_context, provider, binding);
}

GLRProductionAdapter::NativeDftPlaintextGenerationConfig
GLRProductionAdapter::GetCanonicalDirectDftGenerationConfig() const {
    return glscheme::rns::glr_gl128_dft_generation_config(m_context);
}

GLRProductionAdapter::NativeDftPlaintextGenerationResult
GLRProductionAdapter::GenerateForwardDftPlaintextEntries(
    double forwardScale, std::uint32_t forwardLevel,
    const NativeDftPlaintextEntrySink& sink) const {
    return glscheme::rns::glr_generate_forward_dft_plaintext_entries(
        m_context, forwardScale, forwardLevel, sink);
}

GLRProductionAdapter::NativeValidatedDftPlaintextProviderSession
GLRProductionAdapter::OpenForwardDftPlaintextSession(
    const NativeRefreshDftPlaintextProvider& provider,
    const NativeRefreshDftPlaintextBinding& binding) const {
    const auto& manifest = provider.manifest();
    if (manifest.schema !=
            glscheme::rns::kGlrDftPlaintextForwardManifestSchema ||
        manifest.entries.size() !=
            glscheme::rns::kGlrDftPlaintextForwardEntryCount ||
        binding.expected_manifest_schema !=
            glscheme::rns::kGlrDftPlaintextForwardManifestSchema ||
        binding.expected_entry_count !=
            glscheme::rns::kGlrDftPlaintextForwardEntryCount) {
        throw GlrError(
            "GLRProductionAdapter: direct bootstrap requires the "
            "forward-only two-record DFT schema");
    }
    return glscheme::rns::glr_open_dft_plaintext_provider_session(
        m_context, provider, binding);
}

GLRProductionAdapter::NativeDftPlaintextByteCensus
GLRProductionAdapter::ModelForwardDftPlaintextStreamingBytes(
    std::uint32_t forwardLevel) const {
    return glscheme::rns::glr_model_forward_dft_plaintext_streaming_bytes(
        m_context.params, forwardLevel);
}

GLRProductionAdapter::NativeCompactKskSetGenerationResult
GLRProductionAdapter::GenerateCompactSchemeKeys(
    const SecretKey& primaryKey, const NativeGL128SchemeKeyPlan& plan,
    std::string ownerKeySeedCommitment,
    const NativeCompactKskSetSink& sink, std::uint64_t seed) const {
    RequireCanonicalSchemeKeyPlan(m_context, plan);
    RequireProductionSecretKey(m_context, primaryKey);
    GlrRngOwner rng = MakeRng(seed);
    auto generation = glscheme::rns::glr_gl128_generate_compact_scheme_keys(
        m_context, plan, primaryKey, ownerKeySeedCommitment, *rng, sink);
    std::vector<std::pair<GlrKskId, std::uint32_t>> expected;
    expected.reserve(plan.ids.size());
    for (const auto& id : plan.ids) {
        expected.emplace_back(id, plan.key_level);
    }
    RequireCompactGeneration(m_context, generation, expected);
    const std::string primaryLineage =
        glscheme::rns::glr_ship_direct_primary_secret_lineage_commitment(
            m_context, primaryKey);
    if (generation.manifest.schema !=
            "glscheme.rns_hybrid_ksk_manifest.v2" ||
        generation.manifest.primary_secret_lineage_commitment !=
            primaryLineage ||
        !generation.manifest.sparse_secret_lineage_commitment.empty()) {
        throw GlrError(
            "GLRProductionAdapter: compact scheme keys lost their concrete "
            "primary-secret lineage");
    }
    return generation;
}

GLRProductionAdapter::NativeGL128DirectBootstrapKeyGenerationResult
GLRProductionAdapter::GenerateCompactDirectBootstrapKeys(
    const SecretKey& primaryKey,
    const glscheme::rns::GlrSparseSecretKey& sparseKey,
    const NativeGL128DirectBootstrapKeyPlan& plan,
    std::string ownerKeySeedCommitment,
    const NativeCompactKskSetSink& sink, std::uint64_t seed) const {
    const auto expectedPlan =
        glscheme::rns::glr_gl128_direct_bootstrap_key_plan(m_context);
    if (!DirectBootstrapKeyPlanEquals(plan, expectedPlan)) {
        throw GlrError(
            "GLRProductionAdapter: direct-bootstrap key plan is not the "
            "canonical five-key h40 L0/L2/L14/L24 plan");
    }
    RequireProductionSecretKey(m_context, primaryKey);
    GlrRngOwner rng = MakeRng(seed);
    auto generation =
        glscheme::rns::glr_gl128_generate_compact_direct_bootstrap_keys(
            m_context, plan, primaryKey, sparseKey,
            ownerKeySeedCommitment, *rng, sink);
    RequireDirectBootstrapKeyGeneration(m_context, plan, generation);
    return generation;
}

GLRProductionAdapter::CompactEvaluationKeys
GLRProductionAdapter::OpenCompactSchemeKeys(
    const NativeGL128SchemeKeyPlan& plan,
    NativeCompactKskSetGenerationResult generation,
    NativeCompactKskBlobLeaseCallbacks callbacks) const {
    RequireCanonicalSchemeKeyPlan(m_context, plan);
    std::vector<std::pair<GlrKskId, std::uint32_t>> expected;
    expected.reserve(plan.ids.size());
    for (const auto& id : plan.ids) {
        expected.emplace_back(id, plan.key_level);
    }
    RequireCompactGeneration(m_context, generation, expected);
    if (generation.manifest.schema !=
            "glscheme.rns_hybrid_ksk_manifest.v2" ||
        !IsCanonicalSha256Root(
            generation.manifest.primary_secret_lineage_commitment) ||
        !generation.manifest.sparse_secret_lineage_commitment.empty()) {
        throw GlrError(
            "GLRProductionAdapter: compact scheme-key opening requires one "
            "concrete primary-secret lineage");
    }
    auto provider =
        glscheme::rns::glr_make_authenticated_leased_compact_ksk_provider(
            m_context, generation.manifest, generation.binding,
            std::move(callbacks));
    if (!provider || provider->secret_material_accessed()) {
        throw GlrError(
            "GLRProductionAdapter: compact scheme-key provider failed its "
            "secret-free opening");
    }
    return CompactEvaluationKeys(std::move(generation),
                                 std::move(provider));
}

GLRProductionAdapter::CompactDirectBootstrapKeys
GLRProductionAdapter::OpenCompactDirectBootstrapKeys(
    const NativeGL128DirectBootstrapKeyPlan& plan,
    NativeGL128DirectBootstrapKeyGenerationResult generation,
    NativeCompactKskBlobLeaseCallbacks callbacks) const {
    const auto expectedPlan =
        glscheme::rns::glr_gl128_direct_bootstrap_key_plan(m_context);
    if (!DirectBootstrapKeyPlanEquals(plan, expectedPlan)) {
        throw GlrError(
            "GLRProductionAdapter: direct-bootstrap key plan is not the "
            "canonical five-key h40 L0/L2/L14/L24 plan");
    }
    RequireDirectBootstrapKeyGeneration(m_context, plan, generation);
    auto provider =
        glscheme::rns::glr_make_authenticated_leased_compact_ksk_provider(
            m_context, generation.key_generation.manifest,
            generation.key_generation.binding,
            std::move(callbacks));
    if (!provider || provider->secret_material_accessed()) {
        throw GlrError(
            "GLRProductionAdapter: compact direct-bootstrap provider failed "
            "its secret-free opening");
    }
    return CompactDirectBootstrapKeys(std::move(generation),
                                      std::move(provider));
}

GLRProductionAdapter::NativeGL128DirectBootstrapAuthorizationBundle
GLRProductionAdapter::AuthorizeDirectBootstrap(
    const SecretKey& primaryKey,
    const glscheme::rns::GlrSparseSecretKey& sparseKey,
    std::string ownerKeySeedCommitment,
    const SecurityReport& sparseH40SecurityReport,
    const NativeDirectVectorDensePrimarySecurityEvidence&
        densePrimarySecurity) const {
    RequireProductionSecretKey(m_context, primaryKey);
    return glscheme::rns::glr_gl128_authorize_direct_bootstrap(
        m_context, primaryKey, sparseKey, ownerKeySeedCommitment,
        sparseH40SecurityReport, densePrimarySecurity);
}

GLRProductionAdapter::NativeGL128PersistedSelectorBankResult
GLRProductionAdapter::GeneratePersistedDirectSelectorBank(
    const SecretKey& primaryKey,
    const glscheme::rns::GlrSparseSecretKey& sparseKey,
    const NativeGL128DirectBootstrapAuthorizationBundle& authorization,
    const NativeDirectVectorProductionSelectorGenerationSeed& generationSeed,
    const NativeGL128SelectorPersistenceSink& sink,
    const NativeDirectVectorProductionSelectorManifestCheckpoint*
        resumeCheckpoint) const {
    RequireProductionSecretKey(m_context, primaryKey);
    return glscheme::rns::glr_gl128_generate_persisted_selector_bank(
        m_context, primaryKey, sparseKey, authorization, generationSeed, sink,
        resumeCheckpoint);
}

GLRProductionAdapter::
    NativeDirectVectorProductionSelectorProviderOpeningResult
GLRProductionAdapter::OpenPersistedDirectSelectorBank(
    const NativeGL128DirectBootstrapAuthorizationBundle& authorization,
    const NativeGL128PersistedSelectorBankResult& persisted,
    const CompactDirectBootstrapKeys& evaluationKeys,
    NativeDirectVectorProductionSelectorBlobLeaseCallbacks callbacks) const {
    const auto& provider = RequireDirectBootstrapKeys(
        m_context, evaluationKeys, authorization.authorization);
    return glscheme::rns::glr_gl128_open_persisted_selector_provider(
        m_context, authorization, persisted, evaluationKeys.GetLineage(),
        provider,
        std::move(callbacks));
}

GLRProductionAdapter::NativeGL128DirectInputPreparationResult
GLRProductionAdapter::PrepareDirectShipInput(
    const Ciphertext& canonicalCiphertext,
    const NativeGL128DirectBootstrapAuthorizationBundle& authorization,
    const CompactDirectBootstrapKeys& evaluationKeys,
    double normalizationRelativeTolerance) const {
    const auto& provider = RequireDirectBootstrapKeys(
        m_context, evaluationKeys, authorization.authorization);
    return glscheme::rns::glr_gl128_prepare_direct_ship_input(
        m_context, canonicalCiphertext, authorization,
        evaluationKeys.GetLineage(), provider,
        normalizationRelativeTolerance);
}

GLRProductionAdapter::NativeGL128DirectInputPreparationResult
GLRProductionAdapter::PrepareDirectShipInput(
    const Ciphertext& canonicalCiphertext,
    const NativeGL128DirectBootstrapAuthorizationBundle& authorization,
    const NativeValidatedDftPlaintextProviderSession& dftSession,
    const CompactDirectBootstrapKeys& evaluationKeys,
    const NativeCtsStcConfig& config,
    double normalizationRelativeTolerance) const {
    const auto& provider = RequireDirectBootstrapKeys(
        m_context, evaluationKeys, authorization.authorization);
    return glscheme::rns::glr_gl128_prepare_direct_ship_input(
        m_context, canonicalCiphertext, authorization,
        evaluationKeys.GetLineage(), dftSession, provider, config,
        normalizationRelativeTolerance);
}

GLRProductionAdapter::NativeGL128BootstrapResult
GLRProductionAdapter::BootstrapDirect(
    const Ciphertext& canonicalCiphertext,
    const NativeGL128DirectBootstrapAuthorizationBundle& authorization,
    const NativeDirectVectorProductionSelectorProviderOpeningResult&
        selectorOpening,
    const NativeValidatedDftPlaintextProviderSession& dftSession,
    const CompactDirectBootstrapKeys& evaluationKeys,
    const NativeCtsStcConfig& config,
    double normalizationRelativeTolerance) const {
    const auto& provider = RequireDirectBootstrapKeys(
        m_context, evaluationKeys, authorization.authorization);
    return glscheme::rns::glr_gl128_bootstrap(
        m_context, canonicalCiphertext, authorization, selectorOpening,
        dftSession, provider, evaluationKeys.GetLineage(), config,
        normalizationRelativeTolerance);
}

GLRProductionAdapter::NativeGL128H40FreeSupportProxyResearchReceipt
GLRProductionAdapter::RecordH40FreeSupportProxyForResearch(
    const SecurityReport& researchProxyReport) const {
    const auto profile =
        glscheme::rns::glr_gl128_validate_context(m_context);
    return glscheme::rns::
        glr_record_gl128_h40_free_support_proxy_for_research(
            m_context.params, profile.support_commitment,
            researchProxyReport);
}

GLRProductionAdapter::NativeGL128ResearchOnlySession
GLRProductionAdapter::BeginResearchOnlyBootstrapSession(
    const SecretKey& primaryKey, const SparseSecretKey& sparseKey,
    std::string ownerKeySeedCommitment,
    const NativeGL128H40FreeSupportProxyResearchReceipt& proxyEvidence)
    const {
    RequireProductionSecretKey(m_context, primaryKey);
    return glscheme::rns::glr_gl128_begin_research_only_session(
        m_context, primaryKey, sparseKey, ownerKeySeedCommitment,
        proxyEvidence);
}

GLRProductionAdapter::NativeGL128ResearchPersistedSelectorBank
GLRProductionAdapter::GeneratePersistedResearchSelectorBank(
    const SecretKey& primaryKey, const SparseSecretKey& sparseKey,
    const NativeGL128ResearchOnlySession& session,
    const NativeGL128ResearchSelectorGenerationSeed& generationSeed,
    const NativeGL128ResearchSelectorPersistenceSink& sink) const {
    RequireProductionSecretKey(m_context, primaryKey);
    return glscheme::rns::
        glr_gl128_research_generate_persisted_selector_bank(
            m_context, primaryKey, sparseKey, session, generationSeed, sink);
}

GLRProductionAdapter::NativeGL128ResearchSelectorProviderOpeningResult
GLRProductionAdapter::OpenPersistedResearchSelectorProvider(
    const NativeGL128ResearchOnlySession& session,
    const NativeGL128ResearchPersistedSelectorBank& persisted,
    const CompactDirectBootstrapKeys& evaluationKeys,
    NativeGL128ResearchSelectorBlobLeaseCallbacks callbacks) const {
    const auto& provider = RequireResearchDirectBootstrapKeys(
        m_context, evaluationKeys, session);
    return glscheme::rns::
        glr_gl128_research_open_persisted_selector_provider(
            m_context, session, persisted, evaluationKeys.GetLineage(),
            provider, std::move(callbacks));
}

GLRProductionAdapter::NativeGL128ResearchInputPreparationResult
GLRProductionAdapter::PrepareResearchDirectShipInput(
    const Ciphertext& canonicalCiphertext,
    const NativeGL128ResearchOnlySession& session,
    const CompactDirectBootstrapKeys& evaluationKeys,
    double normalizationRelativeTolerance) const {
    const auto& provider = RequireResearchDirectBootstrapKeys(
        m_context, evaluationKeys, session);
    return glscheme::rns::glr_gl128_research_prepare_direct_ship_input(
        m_context, canonicalCiphertext, session,
        evaluationKeys.GetLineage(), provider,
        normalizationRelativeTolerance);
}

GLRProductionAdapter::NativeGL128ResearchBootstrapResult
GLRProductionAdapter::BootstrapResearchDirect(
    const Ciphertext& canonicalCiphertext,
    const NativeGL128ResearchOnlySession& session,
    const NativeGL128ResearchSelectorProviderOpeningResult& selectorOpening,
    const NativeValidatedDftPlaintextProviderSession& dftSession,
    const CompactDirectBootstrapKeys& evaluationKeys,
    const NativeCtsStcConfig& config,
    double normalizationRelativeTolerance) const {
    const auto& provider = RequireResearchDirectBootstrapKeys(
        m_context, evaluationKeys, session);
    return glscheme::rns::glr_gl128_research_bootstrap(
        m_context, canonicalCiphertext, session, selectorOpening, dftSession,
        provider, evaluationKeys.GetLineage(), config,
        normalizationRelativeTolerance);
}

GLRProductionAdapter::NativeGL128H64ResearchProfileReceipt
GLRProductionAdapter::GetH64ResearchProfile() const {
    return glscheme::rns::glr_gl128_h64_research_profile(m_context);
}

GLRProductionAdapter::NativeGL128H64HiddenSelectorPlan
GLRProductionAdapter::PlanH64HiddenSelector() const {
    return glscheme::rns::glr_gl128_h64_hidden_selector_plan(m_context);
}

GLRProductionAdapter::NativeGL128H64WActionPlan
GLRProductionAdapter::PlanH64WActionResearch() const {
    return glscheme::rns::glr_gl128_h64_w_action_plan(m_context);
}

GLRProductionAdapter::NativeGL128H64WActionResearchCapabilities
GLRProductionAdapter::GetH64WActionResearchCapabilities() const {
    const auto plan = PlanH64WActionResearch();
    if (plan.schema != glscheme::rns::kGlrH64WActionPlanSchema ||
        !plan.evidence.allocation_free_cryptographic_plan ||
        plan.evidence.encrypted_logarithmic_circuit_executed ||
        plan.evidence.exact_estimator_evidence_present ||
        plan.evidence.exact_noise_evidence_present ||
        plan.evidence.production_security_authorized ||
        plan.evidence.bootstrap_direct_admitted ||
        plan.production_security_authorized ||
        plan.bootstrap_direct_admitted ||
        plan.material.production_sized_material_allocated) {
        throw GlrError(
            "GLRProductionAdapter: H64 W-action metadata is malformed or "
            "overstates executable/security admission");
    }
    NativeGL128H64WActionResearchCapabilities capabilities;
    capabilities.currentOracleExternalProducts =
        plan.operations.current_oracle_cmux_external_products;
    capabilities.logarithmicExternalProducts =
        plan.operations.total_external_products;
    capabilities.logarithmicCompactMaterialBytes =
        plan.material.logarithmic_compact_material_bytes;
    capabilities.compactBytesIncludingSparseFold =
        plan.material.logarithmic_compact_bytes_including_sparse_fold;
    capabilities.controlSpecialPrimeCount =
        plan.material.control_special_prime_count;
    capabilities.prefixMaskSpecialPrimeCount =
        plan.material.prefix_mask_special_prime_count;
    capabilities.actionKeySpecialPrimeCount =
        plan.material.action_key_special_prime_count;
    capabilities.sparseFoldSpecialPrimeCount =
        plan.material.sparse_fold_special_prime_count;
    capabilities.allocationFreeCryptographicPlan = true;
    return capabilities;
}

GLRProductionAdapter::NativeGL128H64P257OneBitCapabilities
GLRProductionAdapter::GetH64P257OneBitCapabilities() const {
    (void)glscheme::rns::glr_gl128_validate_context(m_context);
    NativeGL128H64P257OneBitCapabilities capabilities;
    if (!capabilities.cpuValueExecutionExposed ||
        !capabilities.gpuValueExecutionExposed ||
        !capabilities.actualCiphertextProductExecuted ||
        !capabilities.exactPairedRescaleExecuted ||
        capabilities.outputReanchoredToDelta ||
        capabilities.encryptedPrefixSpliceExecuted ||
        capabilities.keyedWRotationsExecuted ||
        capabilities.completeEightBitWActionExecuted ||
        capabilities.hiddenFineXSelectionExecuted ||
        capabilities.hiddenSignSelectionExecuted ||
        capabilities.exactNoiseEvidencePresent ||
        capabilities.productionSecurityAuthorized ||
        capabilities.bootstrapDirectAdmitted) {
        throw GlrError(
            "GLRProductionAdapter: canonical one-bit H64 capability "
            "overstates execution or security admission");
    }
    capabilities.gpuDeviceAvailable =
        glscheme::rns::glr_device_ks_available();
    return capabilities;
}

GLRProductionAdapter::NativeGL128H64P257OneBitMaterial
GLRProductionAdapter::GenerateH64P257OneBitMaterial(
    const SparseSecretKey& sparseKey,
    const NativeGL128H64HiddenSelectorOwnerSeed& ownerSeed,
    std::uint64_t seed) const {
    (void)glscheme::rns::glr_gl128_validate_context(m_context);
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_generate_h64_p257_one_bit_material(
        m_context, sparseKey, ownerSeed, *rng);
}

GLRProductionAdapter::NativeGL128H64P257OneBitResult
GLRProductionAdapter::EvaluateH64P257OneBitCpu(
    const NativeGL128H64P257OneBitMaterial& material,
    std::span<const NativeGL128H64P257OneBitRequest> requests) const {
    (void)glscheme::rns::glr_gl128_validate_context(m_context);
    return glscheme::rns::glr_h64_p257_one_bit_root_action_cpu(
        m_context, material, requests);
}

GLRProductionAdapter::NativeGL128H64P257OneBitGpuResult
GLRProductionAdapter::EvaluateH64P257OneBitGpu(
    const NativeGL128H64P257OneBitMaterial& material,
    const NativeGL128H64P257OneBitRequest& request) const {
    (void)glscheme::rns::glr_gl128_validate_context(m_context);
    return glscheme::rns::glr_h64_p257_one_bit_root_action_gpu(
        m_context, material, request);
}

GLRProductionAdapter::NativeGL128H64P257PrefixSpliceCapabilities
GLRProductionAdapter::GetH64P257PrefixSpliceCapabilities() const {
    (void)glscheme::rns::glr_gl128_validate_context(m_context);
    NativeGL128H64P257PrefixSpliceCapabilities capabilities;
    if (!capabilities.cpuValueExecutionExposed ||
        !capabilities.encryptedBinaryMaskReturned ||
        !capabilities.encryptedPrefixSpliceExecuted ||
        capabilities.fixedWholeFormulaArmsSelected ||
        capabilities.keyedWRotationsExecuted ||
        capabilities.encryptedDenominatorExecuted ||
        capabilities.completeEightBitWActionExecuted ||
        capabilities.exactNoiseEvidencePresent ||
        capabilities.productionSecurityAuthorized ||
        capabilities.bootstrapDirectAdmitted) {
        throw GlrError(
            "GLRProductionAdapter: canonical prefix-splice capability "
            "overstates execution or security admission");
    }
    return capabilities;
}

GLRProductionAdapter::NativeGL128H64P257PrefixSpliceMaterial
GLRProductionAdapter::GenerateH64P257PrefixSpliceMaterial(
    const SparseSecretKey& sparseKey,
    const NativeGL128H64HiddenSelectorOwnerSeed& ownerSeed,
    std::uint64_t seed) const {
    (void)glscheme::rns::glr_gl128_validate_context(m_context);
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_generate_h64_p257_prefix_splice_material(
        m_context, sparseKey, ownerSeed, *rng);
}

GLRProductionAdapter::NativeGL128H64P257PrefixSpliceResult
GLRProductionAdapter::EvaluateH64P257PrefixSpliceCpu(
    const NativeGL128H64P257PrefixSpliceMaterial& material,
    std::span<const NativeGL128H64P257OneBitRequest> requests) const {
    (void)glscheme::rns::glr_gl128_validate_context(m_context);
    return glscheme::rns::glr_h64_p257_prefix_splice_cpu(
        m_context, material, requests);
}

GLRProductionAdapter::NativeGL128H64P257RightMuxRotCapabilities
GLRProductionAdapter::GetH64P257RightMuxRotCapabilities() const {
    (void)glscheme::rns::glr_gl128_validate_context(m_context);
    NativeGL128H64P257RightMuxRotCapabilities capabilities;
    if (!capabilities.cpuValueExecutionExposed ||
        !capabilities.encryptedPrefixSpliceExecuted ||
        !capabilities.keyedWRotationsExecuted ||
        capabilities.encryptedDenominatorExecuted ||
        capabilities.completeEightBitWActionExecuted ||
        capabilities.exactNoiseEvidencePresent ||
        capabilities.productionSecurityAuthorized ||
        capabilities.bootstrapDirectAdmitted) {
        throw GlrError(
            "GLRProductionAdapter: canonical right-MuxRot capability "
            "overstates execution or security admission");
    }
    return capabilities;
}

GLRProductionAdapter::NativeGL128H64P257RightMuxRotMaterial
GLRProductionAdapter::GenerateH64P257RightMuxRotMaterial(
    const SparseSecretKey& sparseKey,
    const NativeGL128H64HiddenSelectorOwnerSeed& ownerSeed,
    std::uint64_t seed) const {
    (void)glscheme::rns::glr_gl128_validate_context(m_context);
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_generate_h64_p257_right_muxrot_material(
        m_context, sparseKey, ownerSeed, *rng);
}

GLRProductionAdapter::NativeGL128H64P257RightMuxRotResult
GLRProductionAdapter::EvaluateH64P257RightMuxRotCpu(
    const NativeGL128H64P257RightMuxRotMaterial& material,
    std::span<const NativeGL128H64P257OneBitRequest> requests) const {
    (void)glscheme::rns::glr_gl128_validate_context(m_context);
    return glscheme::rns::glr_h64_p257_right_muxrot_cpu(
        m_context, material, requests);
}

GLRProductionAdapter::NativeGL128H64StructuredSecurityAudit
GLRProductionAdapter::AuditH64StructuredSecurity() const {
    const auto transcript =
        glscheme::rns::glr_gl128_h64_checked_free_support_transcript();
    auto audit =
        glscheme::rns::glr_gl128_h64_structured_security_audit(
            m_context, transcript);
    glscheme::rns::glr_validate_gl128_h64_structured_security_audit(
        m_context, audit);
    return audit;
}

GLRProductionAdapter::NativeGL128H64StructuredSecurityCapabilities
GLRProductionAdapter::GetH64StructuredSecurityCapabilities() const {
    const auto audit = AuditH64StructuredSecurity();
    if (!audit.cryptographic_material_allocation_free ||
        audit.cryptographic_material_generated ||
        !audit.checked_free_support_transcript.free_support_proxy_only ||
        audit.checked_free_support_transcript.structured_distribution_modeled ||
        audit.free_support_proxy_promoted ||
        audit.rlwe_lattice.checked_proxy_covers_structured_distribution ||
        audit.rlwe_lattice.exact_structured_lattice_estimate_present ||
        audit.composed_key_leakage.same_secret_multi_sample_theorem_bound ||
        audit.composed_key_leakage.circular_security_theorem_bound ||
        audit.composed_key_leakage.related_key_security_theorem_bound ||
        audit.composed_key_leakage.joint_public_window_and_rlwe_attack_analyzed ||
        audit.exact_structured_security_certificate_present ||
        audit.production_security_authorized ||
        audit.bootstrap_direct_admitted) {
        throw GlrError(
            "GLRProductionAdapter: structured H64 security audit is "
            "malformed or overstates security admission");
    }
    NativeGL128H64StructuredSecurityCapabilities capabilities;
    capabilities.auditCommitment = audit.audit_commitment;
    capabilities.freeSupportProxyClassicalBits =
        audit.checked_free_support_transcript.reported_classical_bits;
    capabilities.rawPublicWindowChoiceBits =
        audit.choice_entropy.raw_choice_bits;
    capabilities.genericSplitTimeBits =
        audit.public_window_attacks.generic_split_time_bits;
    capabilities.genericSplitMemoryBits =
        audit.public_window_attacks.generic_split_memory_bits;
    capabilities.cryptographicMaterialAllocationFree = true;
    return capabilities;
}

GLRProductionAdapter::NativeGL128H64OwnerRootProductResult
GLRProductionAdapter::EvaluateH64OwnerRootProductOracle(
    std::uint32_t yRow,
    std::span<const glscheme::rns::GlrShipDirectGaussian> publicB,
    std::span<const glscheme::rns::GlrShipDirectGaussian> publicA,
    const SparseSecretKey& sparseKey) const {
    return glscheme::rns::glr_gl128_h64_owner_root_product_oracle(
        m_context, yRow, publicB, publicA, sparseKey.support);
}

GLRProductionAdapter::NativeGL128H64HiddenSelectorBinding
GLRProductionAdapter::BindH64HiddenSelectorManifest(
    const NativeGL128H64HiddenSelectorManifest& manifest) const {
    (void)glscheme::rns::glr_gl128_validate_context(m_context);
    return glscheme::rns::glr_gl128_h64_hidden_selector_binding(manifest);
}

GLRProductionAdapter::NativeGL128H64HiddenSelectorGenerationResult
GLRProductionAdapter::GenerateH64HiddenSelectorMaterial(
    const SparseSecretKey& sparseKey,
    const NativeGL128H64HiddenSelectorOwnerSeed& ownerSeed,
    const NativeGL128H64HiddenSelectorRecordSink& sink,
    const NativeGL128H64HiddenSelectorCheckpoint* resumeCheckpoint,
    std::size_t maxRecordsThisCall) const {
    return glscheme::rns::glr_generate_gl128_h64_hidden_selector_material(
        m_context, sparseKey, ownerSeed, sink, resumeCheckpoint,
        maxRecordsThisCall);
}

std::unique_ptr<
    GLRProductionAdapter::NativeGL128H64HiddenSelectorProvider>
GLRProductionAdapter::OpenH64HiddenSelectorProvider(
    NativeGL128H64HiddenSelectorManifest manifest,
    NativeGL128H64HiddenSelectorBinding binding,
    NativeGL128H64HiddenSelectorLeaseCallbacks callbacks) const {
    return glscheme::rns::
        glr_make_authenticated_gl128_h64_hidden_selector_provider(
            m_context, std::move(manifest), std::move(binding),
            std::move(callbacks));
}

GLRProductionAdapter::NativeGL128ValidatedH64HiddenSelectorSession
GLRProductionAdapter::OpenH64HiddenSelectorSession(
    const NativeGL128H64HiddenSelectorProvider& provider,
    const NativeGL128H64HiddenSelectorBinding& binding) const {
    return glscheme::rns::glr_open_gl128_h64_hidden_selector_session(
        m_context, provider, binding);
}

GLRProductionAdapter::NativeGL128H64PublicRootProviderBinding
GLRProductionAdapter::BindH64PublicRootManifest(
    const NativeGL128H64PublicRootProviderManifest& manifest) const {
    (void)glscheme::rns::glr_gl128_validate_context(m_context);
    return glscheme::rns::glr_gl128_h64_public_root_provider_binding(
        manifest);
}

GLRProductionAdapter::NativeGL128H64PublicRootSource
GLRProductionAdapter::ExtractH64PublicRootSource(
    const Ciphertext& normalizedSparseQ0, std::uint32_t yRow,
    std::uint32_t branch) const {
    return glscheme::rns::glr_gl128_h64_public_root_source(
        m_context, normalizedSparseQ0, yRow, branch);
}

GLRProductionAdapter::NativeGL128H64PublicRootProviderManifest
GLRProductionAdapter::BuildH64PublicRootManifest(
    const NativeGL128H64PublicRootSource& source) const {
    return glscheme::rns::glr_gl128_h64_public_root_provider_manifest(
        m_context, source);
}

std::unique_ptr<
    GLRProductionAdapter::NativeGL128H64PublicRootCandidateProvider>
GLRProductionAdapter::OpenH64PublicRootProvider(
    NativeGL128H64PublicRootProviderManifest manifest,
    NativeGL128H64PublicRootProviderBinding binding,
    NativeGL128H64PublicRootProviderCallbacks callbacks) const {
    return glscheme::rns::
        glr_make_authenticated_gl128_h64_public_root_candidate_provider(
            m_context, std::move(manifest), std::move(binding),
            std::move(callbacks));
}

GLRProductionAdapter::NativeGL128H64ConcretePublicRootProviderOpening
GLRProductionAdapter::OpenConcreteH64PublicRootProvider(
    NativeGL128H64PublicRootSource source) const {
    return glscheme::rns::
        glr_make_gl128_h64_concrete_public_root_provider(
            m_context, std::move(source));
}

GLRProductionAdapter::NativeGL128H64SparseFoldKskBinding
GLRProductionAdapter::BindH64SparseFoldKeys(
    const NativeKeyProvider& evaluationKeys,
    const std::string& expectedPrimarySecretLineageCommitment,
    const std::string& expectedSparseSecretLineageCommitment) const {
    return glscheme::rns::glr_bind_gl128_h64_sparse_fold_ksk_provider(
        m_context, evaluationKeys,
        expectedPrimarySecretLineageCommitment,
        expectedSparseSecretLineageCommitment);
}

GLRProductionAdapter::NativeGL128H64SparseFoldResult
GLRProductionAdapter::EvaluateH64OneBranchSparseFold(
    const NativeGL128ValidatedH64HiddenSelectorSession& hiddenSelector,
    const NativeGL128H64PublicRootCandidateProvider& publicRoots,
    const NativeGL128H64PublicRootProviderBinding& publicRootBinding,
    const NativeKeyProvider& evaluationKeys,
    const NativeGL128H64SparseFoldKskBinding& sparseFoldKeys) const {
    return glscheme::rns::glr_gl128_h64_blind_select_and_sparse_fold_cpu(
        m_context, hiddenSelector, publicRoots, publicRootBinding,
        evaluationKeys, sparseFoldKeys);
}

GLRProductionAdapter::NativeGL128H64AllYPublicSourceSchedule
GLRProductionAdapter::PlanH64AllYPublicSources(
    const Ciphertext& normalizedSparseQ0) const {
    return glscheme::rns::glr_gl128_h64_make_all_y_public_source_schedule(
        m_context, normalizedSparseQ0);
}

std::string
GLRProductionAdapter::GetH64AllYPublicSourceScheduleCommitment(
    const NativeGL128H64AllYPublicSourceSchedule& schedule) const {
    (void)glscheme::rns::glr_gl128_validate_context(m_context);
    return glscheme::rns::
        glr_gl128_h64_all_y_public_source_schedule_commitment(schedule);
}

GLRProductionAdapter::NativeGL128H64AllYPublicRootProviderResolver
GLRProductionAdapter::MakeH64AllYPublicRootProviderResolver() const {
    return glscheme::rns::
        glr_make_gl128_h64_concrete_public_root_provider_resolver(m_context);
}

GLRProductionAdapter::NativeGL128H64ResearchAllYStcResult
GLRProductionAdapter::EvaluateH64AllYStCResearch(
    const Ciphertext& normalizedSparseQ0,
    const NativeGL128H64AllYPublicSourceSchedule& sourceSchedule,
    const NativeGL128ValidatedH64HiddenSelectorSession& hiddenSelector,
    const NativeGL128H64AllYPublicRootProviderResolver&
        rootProviderResolver,
    const NativeKeyProvider& evaluationKeys,
    const NativeGL128H64SparseFoldKskBinding& sparseFoldKeys,
    const NativeValidatedDftPlaintextProviderSession& dftSession,
    const NativeCtsStcConfig& config) const {
    return glscheme::rns::glr_gl128_h64_all_y_stc_research(
        m_context, normalizedSparseQ0, sourceSchedule, hiddenSelector,
        rootProviderResolver, evaluationKeys, sparseFoldKeys, dftSession,
        config);
}

GLRProductionAdapter::NativeGL128BootstrapAcceptanceReceipt
GLRProductionAdapter::AcceptBootstrapDirect(
    const SecretKey& primaryKey,
    const MatrixBatch& expected,
    const NativeGL128BootstrapResult& bootstrap,
    const NativeGL128BootstrapAcceptanceLimits& limits) const {
    RequireProductionSecretKey(m_context, primaryKey);
    return glscheme::rns::glr_gl128_accept_bootstrap_output(
        m_context, primaryKey, expected, bootstrap, limits);
}

GLRProductionAdapter::NativeGL128ResearchBootstrapAcceptanceReceipt
GLRProductionAdapter::AcceptResearchBootstrapDirect(
    const SecretKey& primaryKey, const MatrixBatch& expected,
    const NativeGL128ResearchOnlySession& session,
    const NativeGL128ResearchBootstrapResult& bootstrap,
    const NativeGL128BootstrapAcceptanceLimits& limits) const {
    RequireProductionSecretKey(m_context, primaryKey);
    return glscheme::rns::glr_gl128_accept_research_bootstrap_output(
        m_context, primaryKey, expected, session, bootstrap, limits);
}

GLRProductionAdapter::ResidentQ0GpuBootstrapEvidenceProjection
GLRProductionAdapter::ProjectResidentQ0GpuBootstrapEvidence(
    const NativeDirectGpuBootstrapRequest& request,
    const NativeDirectGpuBootstrapEvidence& evidence) const {
    const auto& preparation = evidence.preparation;
    const auto& allY = evidence.all_y;
    const auto& cache = allY.cache_plan;
    const std::string fingerprint =
        glscheme::rns::glr_parameter_fingerprint(m_context.params);
    if (request.schema !=
            "glscheme.ship_direct_gpu_bootstrap_request.v1" ||
        request.canonical_primary_input == nullptr ||
        request.authorization == nullptr ||
        request.selector_opening == nullptr ||
        request.evaluation_keys == nullptr ||
        request.resident_dft_bank == nullptr ||
        request.stc_config == nullptr ||
        evidence.schema !=
            "glscheme.ship_direct_gpu_bootstrap_evidence.v1" ||
        preparation.schema !=
            "glscheme.ship_direct_gpu_preparation_evidence.v1" ||
        allY.schema != "glscheme.ship_direct_gpu_all_y_evidence.v1" ||
        cache.schema !=
            "glscheme.ship_direct_gpu_all_y_cache_plan.v1" ||
        evidence.parameter_fingerprint != fingerprint ||
        allY.parameter_fingerprint != fingerprint ||
        !evidence.completed || !preparation.completed || !allY.completed ||
        !allY.exact_256x128x128_profile || !cache.exact_gl128_profile ||
        !evidence.evaluator_secret_free || !allY.evaluator_secret_free ||
        !preparation.output_sparse_q0_device_resident ||
        !preparation.public_q0_raw_residue_metadata_rebased ||
        !std::isfinite(preparation.public_q0_pre_rebase_scale) ||
        preparation.public_q0_pre_rebase_scale <= 0.0 ||
        preparation.public_q0_pre_rebase_scale !=
            preparation.normalized_scale ||
        preparation.public_q0_post_rebase_scale != 1.0 ||
        cache.modeled_resident_public_table_builds == 0U ||
        cache.modeled_host_fallback_table_uploads !=
            cache.modeled_resident_public_table_builds ||
        cache.modeled_public_table_uploads !=
            cache.modeled_host_fallback_table_uploads ||
        allY.public_table_prewarm_d2h_bytes != 0U ||
        evidence.public_q0_boundary_d2h_bytes !=
            allY.public_slice_boundary_d2h_bytes ||
        evidence.public_q0_table_boundary_declared !=
            allY.public_slice_boundary_d2h_declared) {
        throw GlrError(
            "GLRProductionAdapter: resident-q0 GPU evidence is incomplete "
            "or inconsistent with the canonical native ledger");
    }

    if (request.use_public_q0_host_boundary_fallback) {
        if (allY.public_table_prewarm_h2d_bytes != 0U ||
            evidence.public_q0_boundary_d2h_bytes == 0U ||
            !evidence.public_q0_table_boundary_declared ||
            allY.public_q0_table_encoder_resident ||
            evidence.public_q0_table_encoder_resident ||
            evidence.fully_device_resident) {
            throw GlrError(
                "GLRProductionAdapter: explicit public-q0 host fallback "
                "evidence was mislabeled as resident");
        }
    } else if (evidence.public_q0_boundary_d2h_bytes != 0U ||
               evidence.public_q0_table_boundary_declared ||
               !allY.public_q0_table_encoder_resident ||
               !evidence.public_q0_table_encoder_resident ||
               !evidence.fully_device_resident) {
        throw GlrError(
            "GLRProductionAdapter: resident public-q0 table evidence did "
            "not close without the explicit host fallback");
    }

    ResidentQ0GpuBootstrapEvidenceProjection out;
    out.native = evidence;
    out.modeledResidentPublicTableBuilds =
        cache.modeled_resident_public_table_builds;
    out.modeledHostFallbackTableUploads =
        cache.modeled_host_fallback_table_uploads;
    out.publicTablePrewarmH2DBytes =
        allY.public_table_prewarm_h2d_bytes;
    out.publicTablePrewarmD2HBytes =
        allY.public_table_prewarm_d2h_bytes;
    out.publicQ0BoundaryD2HBytes = evidence.public_q0_boundary_d2h_bytes;
    out.publicQ0PreRebaseScale = preparation.public_q0_pre_rebase_scale;
    out.publicQ0PostRebaseScale = preparation.public_q0_post_rebase_scale;
    out.explicitHostBoundaryFallbackRequested =
        request.use_public_q0_host_boundary_fallback;
    out.residentQ0PathRequested =
        !request.use_public_q0_host_boundary_fallback;
    out.publicQ0RawResidueMetadataRebased =
        preparation.public_q0_raw_residue_metadata_rebased;
    out.allYPublicQ0TableEncoderResident =
        allY.public_q0_table_encoder_resident;
    out.publicQ0TableBoundaryDeclared =
        evidence.public_q0_table_boundary_declared;
    out.publicQ0TableEncoderResident =
        evidence.public_q0_table_encoder_resident;
    out.fullyDeviceResident = evidence.fully_device_resident;
    out.nativeEvidenceComplete = evidence.completed;
    out.productionSecurityClaimed = false;
    return out;
}

GLRProductionAdapter::NativeGL128CiphertextArtifactReceipt
GLRProductionAdapter::WriteCiphertextArtifact(
    const Ciphertext& ciphertext,
    const NativeGL128CiphertextArtifactSink& sink) const {
    return glscheme::rns::glr_gl128_write_ciphertext_artifact(
        m_context, ciphertext, sink);
}

GLRProductionAdapter::NativeGL128CiphertextArtifactReadResult
GLRProductionAdapter::ReadCiphertextArtifact(
    const NativeGL128CiphertextArtifactSource& source) const {
    return glscheme::rns::glr_gl128_read_ciphertext_artifact(
        m_context, source);
}

GLRProductionAdapter::OrdinaryRefreshPackFacade
GLRProductionAdapter::ResumableOrdinaryRefreshPack() const noexcept {
    return OrdinaryRefreshPackFacade(m_context);
}

GLRProductionAdapter::DirectVectorAllYReturnPreflight
GLRProductionAdapter::PreflightDirectVectorPrimaryAllYReturn() const {
    return MakeDirectVectorPrimaryAllYReturnPreflight(m_context);
}

void GLRProductionAdapter::ValidateDirectVectorPrimaryAllYReturnPreflight(
    const DirectVectorAllYReturnPreflight& preflight) const {
    if (!DirectVectorAllYReturnPreflightEquals(
            preflight, MakeDirectVectorPrimaryAllYReturnPreflight(m_context))) {
        throw GlrError(
            "GLRProductionAdapter: direct-vector all-Y return preflight is "
            "forged or overstates canonical h40 execution/value acceptance");
    }
}

GLRProductionAdapter::DirectVectorPrimaryAuthorization
GLRProductionAdapter::AuthorizeDirectVectorPrimaryCandidate(
    const std::string& supportCommitment,
    const SecurityReport& sparseH40SecurityReport,
    const NativeDirectVectorDensePrimarySecurityEvidence&
        densePrimarySecurity,
    const DirectVectorOwnerKeyLineage& ownerKeyLineage) const {
    return MakeDirectVectorPrimaryAuthorization(
        m_context, supportCommitment, sparseH40SecurityReport,
        densePrimarySecurity, ownerKeyLineage);
}

void GLRProductionAdapter::ValidateDirectVectorPrimaryAuthorization(
    const DirectVectorPrimaryAuthorization& authorization,
    const std::string& supportCommitment,
    const SecurityReport& sparseH40SecurityReport,
    const NativeDirectVectorDensePrimarySecurityEvidence&
        densePrimarySecurity,
    const DirectVectorOwnerKeyLineage& ownerKeyLineage) const {
    RequireDirectVectorPrimaryAuthorization(
        authorization,
        MakeDirectVectorPrimaryAuthorization(
            m_context, supportCommitment, sparseH40SecurityReport,
            densePrimarySecurity, ownerKeyLineage));
}

GLRProductionAdapter::DirectVectorPrimarySelectorStorageAuthorization
GLRProductionAdapter::AuthorizeDirectVectorPrimarySelectorStorage(
    const DirectVectorPrimaryAuthorization& authorization) const {
    return MakeDirectVectorPrimarySelectorStorageAuthorization(
        m_context, authorization);
}

void GLRProductionAdapter::
    ValidateDirectVectorPrimarySelectorStorageAuthorization(
        const DirectVectorPrimarySelectorStorageAuthorization& storage,
        const DirectVectorPrimaryAuthorization& authorization) const {
    RequireDirectVectorPrimarySelectorStorageAuthorization(
        storage,
        MakeDirectVectorPrimarySelectorStorageAuthorization(
            m_context, authorization));
}

GLRProductionAdapter::DirectVectorSelectorRecordPreflight
GLRProductionAdapter::PreflightDirectVectorPrimarySelectorRecord(
    const DirectVectorPrimarySelectorStorageAuthorization& storage,
    const DirectVectorPrimaryAuthorization& authorization) const {
    return MakeDirectVectorPrimarySelectorRecordPreflight(
        m_context, storage, authorization);
}

void GLRProductionAdapter::ValidateDirectVectorPrimarySelectorRecordPreflight(
    const DirectVectorSelectorRecordPreflight& preflight,
    const DirectVectorPrimarySelectorStorageAuthorization& storage,
    const DirectVectorPrimaryAuthorization& authorization) const {
    if (!DirectVectorSelectorRecordPreflightEquals(
            preflight,
            MakeDirectVectorPrimarySelectorRecordPreflight(
                m_context, storage, authorization))) {
        throw GlrError(
            "GLRProductionAdapter: random-access selector record preflight "
            "is forged or overstates record/material/value generation");
    }
}

std::unique_ptr<
    GLRProductionAdapter::NativeDirectVectorProductionSelectorGenerator>
GLRProductionAdapter::CreateDirectVectorPrimarySelectorGenerator(
    const SecretKey& primaryKey,
    const glscheme::rns::GlrSparseSecretKey& sparseKey,
    const DirectVectorPrimaryAuthorization& authorization,
    const DirectVectorPrimarySelectorStorageAuthorization& storage,
    const NativeDirectVectorProductionSelectorGenerationSeed& generationSeed)
    const {
    ValidateDirectVectorPrimarySelectorStorageAuthorization(storage,
                                                             authorization);
    RequireProductionSecretKey(m_context, primaryKey);
    return glscheme::rns::
        glr_make_ship_direct_vector_gl128_selector_generator(
            m_context, primaryKey, sparseKey, authorization.native,
            storage.native, generationSeed);
}

GLRProductionAdapter::
    NativeDirectVectorProductionSelectorManifestCheckpoint
GLRProductionAdapter::BeginDirectVectorPrimarySelectorManifest(
    const DirectVectorPrimaryAuthorization& authorization,
    const DirectVectorPrimarySelectorStorageAuthorization& storage) const {
    ValidateDirectVectorPrimarySelectorStorageAuthorization(storage,
                                                             authorization);
    return glscheme::rns::
        glr_begin_ship_direct_vector_gl128_selector_manifest_checkpoint(
            authorization.native, storage.native);
}

GLRProductionAdapter::
    NativeDirectVectorProductionSelectorManifestCheckpoint
GLRProductionAdapter::AppendDirectVectorPrimarySelectorRecord(
    const DirectVectorPrimaryAuthorization& authorization,
    const DirectVectorPrimarySelectorStorageAuthorization& storage,
    const NativeDirectVectorProductionSelectorManifestCheckpoint& checkpoint,
    const NativeDirectVectorSelectorRecordGenerationResult& record) const {
    ValidateDirectVectorPrimarySelectorStorageAuthorization(storage,
                                                             authorization);
    return glscheme::rns::
        glr_append_ship_direct_vector_gl128_selector_manifest_record(
            m_context, authorization.native, storage.native, checkpoint,
            record);
}

GLRProductionAdapter::
    NativeDirectVectorProductionSelectorManifestFinalizationResult
GLRProductionAdapter::FinalizeDirectVectorPrimarySelectorManifests(
    const DirectVectorPrimaryAuthorization& authorization,
    const DirectVectorPrimarySelectorStorageAuthorization& storage,
    const NativeDirectVectorProductionSelectorManifestCheckpoint& checkpoint)
    const {
    ValidateDirectVectorPrimarySelectorStorageAuthorization(storage,
                                                             authorization);
    return glscheme::rns::
        glr_finalize_ship_direct_vector_gl128_selector_manifests(
            m_context, authorization.native, storage.native, checkpoint);
}

GLRProductionAdapter::
    NativeDirectVectorProductionSelectorProviderOpeningResult
GLRProductionAdapter::OpenPersistedDirectVectorPrimarySelectorProvider(
    const DirectVectorPrimaryAuthorization& authorization,
    const DirectVectorPrimarySelectorStorageAuthorization& storage,
    const NativeDirectVectorProductionSelectorManifestCheckpoint& checkpoint,
    NativeDirectVectorProductionSelectorManifestFinalizationResult finalized,
    const CompactDirectBootstrapKeys& evaluationKeys,
    const NativeDirectVectorProductionSelectorBlobPersistenceEvidence&
        persistence,
    NativeDirectVectorProductionSelectorBlobLeaseCallbacks callbacks) const {
    ValidateDirectVectorPrimarySelectorStorageAuthorization(storage,
                                                             authorization);
    const auto& provider = RequireDirectBootstrapKeys(
        m_context, evaluationKeys, authorization.native);
    return glscheme::rns::
        glr_open_ship_direct_vector_gl128_persisted_selector_provider(
            m_context, authorization.native, storage.native, checkpoint,
            std::move(finalized), provider, persistence,
            std::move(callbacks));
}

GLRProductionAdapter::DirectVectorProductionRowResult
GLRProductionAdapter::ExecuteDirectVectorPrimaryRowProduction(
    const NativeDirectVectorPublicSlice& input,
    const DirectVectorPrimaryAuthorization& authorization,
    const NativeDirectVectorProductionSelectorProviderOpeningResult&
        selectorOpening,
    const CompactDirectBootstrapKeys& evaluationKeys) const {
    const auto& provider = RequireDirectBootstrapKeys(
        m_context, evaluationKeys, authorization.native);
    DirectVectorProductionRowResult out;
    out.ciphertext = glscheme::rns::
        glr_ship_direct_vector_half_bootstrap_gl128_production(
            m_context, input, authorization.native, selectorOpening,
            provider, &out.evidence);
    if (!out.evidence.production_authorization_bound ||
        !out.evidence.production_selector_provider_admitted ||
        !out.evidence.selector_payload_persistence_attested ||
        !out.evidence.ksk_owner_seed_lineage_bound ||
        !out.evidence.value_execution || out.evidence.insecure_toy_only ||
        !out.evidence.evaluator_secret_free) {
        throw GlrError(
            "GLRProductionAdapter: direct production row returned incomplete "
            "authorization/provider/value evidence");
    }
    return out;
}

GLRProductionAdapter::DirectVectorProductionAllYResult
GLRProductionAdapter::ExecuteDirectVectorAllYProduction(
    const Ciphertext& q0SparseCoefficients,
    const DirectVectorPrimaryAuthorization& authorization,
    const NativeDirectVectorProductionSelectorProviderOpeningResult&
        selectorOpening,
    const CompactDirectBootstrapKeys& evaluationKeys,
    const NativeValidatedDftPlaintextProviderSession& dftSession,
    const NativeCtsStcConfig& config) const {
    const auto& provider = RequireDirectBootstrapKeys(
        m_context, evaluationKeys, authorization.native);
    DirectVectorProductionAllYResult out;
    out.native =
        glscheme::rns::glr_ship_direct_all_y_stc_gl128_production(
            m_context, q0SparseCoefficients, authorization.native,
            selectorOpening, provider, dftSession, config,
            &out.evidence);
    if (out.native.representation !=
            glscheme::rns::GlrShipDirectFullReturnRepresentation::
                refreshed_xy_slot_ciphertext ||
        out.evidence.y_rows != glscheme::rns::kGl128MatrixOrder ||
        !out.evidence.q0_only_sparse_rp_input ||
        !out.evidence.strict_y_order ||
        !out.evidence.every_y_row_direct_vector_executed ||
        !out.evidence.every_xw_coefficient_simultaneous ||
        !out.evidence.randomized_primary_rows ||
        !out.evidence.selector_provider_secret_free ||
        !out.evidence.evaluation_key_provider_secret_free ||
        out.evidence.insecure_toy_only ||
        !out.evidence.production_authorization_bound ||
        !out.evidence.production_selector_opening_bound ||
        !out.evidence.every_y_row_non_toy_production_evidence ||
        !out.evidence.authenticated_dft_session_bound ||
        !out.evidence.four_key_provider_bound ||
        !out.evidence.exact_gl128_all_y_slot_ledger ||
        !out.evidence.exact_l18_to_l22_return_ledger ||
        !out.evidence.evaluator_api_has_no_decrypt_callback ||
        !out.evidence.ciphertext_value_execution_performed ||
        out.evidence.decrypted_value_noise_acceptance_recorded) {
        throw GlrError(
            "GLRProductionAdapter: all-Y direct production returned "
            "incomplete persisted-selector/StC execution evidence");
    }
    return out;
}

GLRProductionAdapter::DirectVectorH2Stride2SmokeReceipt
GLRProductionAdapter::BindInsecureDirectVectorH2Stride2Smoke(
    const NativeDirectVectorEvidence& evidence,
    std::uint64_t ownerCheckedSlots, double worstOwnerSlotError,
    double runtimeSeconds, std::uint64_t peakRssBytes,
    std::uint32_t compactSelectorMaxLive,
    std::uint32_t evaluationKeyMaxLive) const {
    return MakeDirectVectorH2Stride2SmokeReceipt(
        m_context, evidence, ownerCheckedSlots, worstOwnerSlotError,
        runtimeSeconds, peakRssBytes, compactSelectorMaxLive,
        evaluationKeyMaxLive);
}

void GLRProductionAdapter::ValidateInsecureDirectVectorH2Stride2SmokeReceipt(
    const DirectVectorH2Stride2SmokeReceipt& receipt) const {
    RequireDirectVectorH2Stride2SmokeReceipt(
        receipt,
        MakeDirectVectorH2Stride2SmokeReceipt(
            m_context, receipt.native, receipt.ownerCheckedSlots,
            receipt.worstOwnerSlotError, receipt.runtimeSeconds,
            receipt.peakRssBytes, receipt.compactSelectorMaxLive,
            receipt.evaluationKeyMaxLive));
}

GLRProductionAdapter::OrdinaryRefreshPreflight
GLRProductionAdapter::PreflightOrdinaryRefresh() const {
    return MakeCanonicalOrdinaryRefreshPreflight(m_context);
}

void GLRProductionAdapter::ValidateOrdinaryRefreshPreflight(
    const OrdinaryRefreshPreflight& preflight) const {
    RequireCanonicalOrdinaryRefreshPreflight(
        preflight, MakeCanonicalOrdinaryRefreshPreflight(m_context));
}

GLRProductionAdapter::OrdinaryRefreshAuthorization
GLRProductionAdapter::AuthorizeOrdinaryRefreshProduction(
    const std::string& supportCommitment,
    const SecurityReport& securityReport,
    std::uint32_t sparseHammingWeight,
    bool reducedExposureCorridor) const {
    return MakeOrdinaryRefreshAuthorization(
        m_context, supportCommitment, securityReport, sparseHammingWeight,
        reducedExposureCorridor);
}

void GLRProductionAdapter::ValidateOrdinaryRefreshAuthorization(
    const OrdinaryRefreshAuthorization& authorization,
    const std::string& supportCommitment,
    const SecurityReport& securityReport,
    std::uint32_t sparseHammingWeight,
    bool reducedExposureCorridor) const {
    RequireOrdinaryRefreshAuthorization(
        authorization,
        MakeOrdinaryRefreshAuthorization(
            m_context, supportCommitment, securityReport,
            sparseHammingWeight, reducedExposureCorridor));
}

void GLRProductionAdapter::ValidateOrdinaryRefreshExecutionEvidence(
    const NativeRefreshEndpointResult& result,
    const NativeRefreshEndpointEvidence& evidence) const {
    RequireCanonicalOrdinaryRefreshExecutionEvidence(
        m_context, result, evidence);
}

GLRProductionAdapter::OrdinaryRefreshExecutionResult
GLRProductionAdapter::ExecuteOrdinaryRefresh(
    const Ciphertext& canonicalCiphertext,
    const OrdinaryRefreshExecutionMaterialView& material) const {
    constexpr std::uint32_t kSparseHammingWeight = 40;
    constexpr std::uint32_t kFoldKeyLevel = 18;
    constexpr std::uint32_t kTransformMaterialLevel = 17;
    constexpr double kRefreshGamma = 64.0;
    constexpr double kDftScale = 70368744177664.0;  // 2^46
    constexpr double kNormalizationTolerance = 1.0e-12;

    if (material.keyProvider == nullptr || material.keyBinding == nullptr ||
        material.dftProvider == nullptr ||
        material.dftBinding == nullptr ||
        material.gadgetProvider == nullptr ||
        material.gadgetBinding == nullptr ||
        material.compactSelector == nullptr ||
        material.compactSelectorBinding == nullptr ||
        material.securityReport == nullptr) {
        throw GlrError(
            "GLRProductionAdapter: ordinary-refresh execution requires "
            "non-null authenticated leased KSK provider/binding, streamed-DFT provider/binding, streamed-gadget/"
            "binding, compact-selector/binding, and SecurityReport material");
    }

    const NativeKeyProvider& keys = *material.keyProvider;
    const std::string parameterFingerprint =
        glscheme::rns::glr_parameter_fingerprint(m_context.params);
    if (keys.secret_material_accessed() ||
        keys.parameter_fingerprint() != parameterFingerprint ||
        keys.sparse_support_commitment().empty()) {
        throw GlrError(
            "GLRProductionAdapter: ordinary-refresh KSK provider is "
            "secret-bearing, cross-parameter, or lacks sparse support");
    }
    // These opaque sessions bind the caller's external envelopes to the
    // provider/manifest bytes before the input ciphertext is inspected or any
    // CtS arithmetic begins.  The endpoint receives the same sessions so it
    // does not reinterpret or re-author the bindings.
    auto dftSession =
        glscheme::rns::glr_open_dft_plaintext_provider_session(
            m_context, *material.dftProvider, *material.dftBinding);
    auto gadgetSession =
        glscheme::rns::glr_open_ship_gadget_provider_session(
            m_context, *material.gadgetProvider, *material.gadgetBinding);
    auto selectorSession =
        glscheme::rns::glr_open_ship_compact_selector_session(
            m_context, *material.compactSelector,
            *material.compactSelectorBinding);
    glscheme::rns::glr_validate_ship_compact_selector_join(
        m_context, selectorSession, gadgetSession.manifest(),
        keys.sparse_support_commitment(), keys.parameter_fingerprint());

    const NativeLeasedKeyBinding& keyBinding = *material.keyBinding;
    const std::string keyManifestCommitment =
        glscheme::rns::glr_ksk_manifest_commitment(keys.manifest());
    if (keys.policy() != "authenticated-leased-rns-hybrid" ||
        keys.residency() != "synchronous-callback-lease" ||
        keyManifestCommitment.rfind("sha256:", 0) != 0 ||
        keyBinding.expected_manifest_commitment != keyManifestCommitment ||
        keyBinding.expected_public_material_commitment !=
            keys.public_material_commitment() ||
        keyBinding.expected_parameter_fingerprint != parameterFingerprint ||
        keyBinding.expected_parameter_fingerprint !=
            keys.parameter_fingerprint() ||
        keyBinding.expected_sparse_support_commitment !=
            keys.sparse_support_commitment() ||
        keyBinding.expected_record_count != keys.manifest().records.size()) {
        throw GlrError(
            "GLRProductionAdapter: ordinary-refresh execution requires an "
            "externally pinned authenticated leased KSK opening");
    }

    const auto& dftManifest = dftSession.manifest();
    const auto& selectorManifest = selectorSession.manifest();
    const auto& gadgetManifest = gadgetSession.manifest();
    static constexpr std::array<
        glscheme::rns::GlrDftPlaintextKind, 4> kDftKinds{
        glscheme::rns::GlrDftPlaintextKind::x_forward,
        glscheme::rns::GlrDftPlaintextKind::x_inverse,
        glscheme::rns::GlrDftPlaintextKind::w_forward,
        glscheme::rns::GlrDftPlaintextKind::w_inverse};
    static constexpr std::array<glscheme::rns::GlrRing, 4> kDftRings{
        glscheme::rns::GlrRing::Rp,
        glscheme::rns::GlrRing::Rp,
        glscheme::rns::GlrRing::Raux,
        glscheme::rns::GlrRing::Raux};
    bool canonicalDft =
        dftManifest.entries.size() == kDftKinds.size() &&
        dftManifest.policy ==
            glscheme::rns::GlrDftPlaintextMaterialPolicy::
                owner_authored_immutable &&
        !dftManifest.stc_weight_composed &&
        !dftSession.binding().expected_stc_weight_composed;
    for (std::size_t i = 0; canonicalDft && i < kDftKinds.size(); ++i) {
        const auto& entry = dftManifest.entries[i];
        canonicalDft =
            entry.kind == kDftKinds[i] && entry.ring == kDftRings[i] &&
            entry.domain == glscheme::rns::GlrDomain::Slot &&
            entry.plaintext_level == kTransformMaterialLevel &&
            entry.poly_level == kTransformMaterialLevel && !entry.extended &&
            entry.scale_bits == std::bit_cast<std::uint64_t>(kDftScale);
    }
    if (!canonicalDft) {
        throw GlrError(
            "GLRProductionAdapter: ordinary-refresh execution requires an "
            "authenticated unweighted four-entry level-17 DFT provider at "
            "exact scale 2^46");
    }
    if (selectorManifest.sparse_hamming_weight != kSparseHammingWeight ||
        selectorManifest.windows.size() != kSparseHammingWeight ||
        selectorManifest.key_level != kFoldKeyLevel ||
        gadgetManifest.windows.size() != kSparseHammingWeight ||
        gadgetManifest.key_level != kFoldKeyLevel ||
        selectorManifest.support_commitment !=
            gadgetManifest.support_commitment) {
        throw GlrError(
            "GLRProductionAdapter: ordinary-refresh execution material is "
            "not the exact h40/level-18 streamed opening");
    }

    // Policy-only authorization is recomputed from the support that survived
    // both external bindings and the selector/gadget/KSK join.  It is not
    // accepted as a caller parameter and is not copied into endpoint admission;
    // the native endpoint independently recomputes the same authorization.
    const auto authorization = MakeOrdinaryRefreshAuthorization(
        m_context, selectorManifest.support_commitment,
        *material.securityReport, kSparseHammingWeight,
        /*reducedExposureCorridor=*/true);

    glscheme::rns::GlrShipRefreshOnlyParameters parameters;
    parameters.gamma = kRefreshGamma;
    parameters.max_abs_coefficient = 1.0;

    glscheme::rns::GlrShipRefreshOnlyEndpointConfig config;
    config.ship.keys = material.keyProvider;
    config.ship.compact_selector = material.compactSelector;
    config.ship.compact_selector_binding = material.compactSelectorBinding;
    config.ship.validated_compact_selector_session = &selectorSession;
    config.ship.gadget_provider = material.gadgetProvider;
    config.ship.gadget_binding = material.gadgetBinding;
    config.ship.validated_gadget_session = &gadgetSession;
    config.ship.production_mode = true;
    config.dft_bank = nullptr;
    config.dft_provider = material.dftProvider;
    config.dft_binding = material.dftBinding;
    config.validated_dft_session = &dftSession;
    config.normalization_relative_tolerance = kNormalizationTolerance;
    config.fold_level = kFoldKeyLevel;
    config.transform_material_level = kTransformMaterialLevel;
    config.sparse_hamming_weight = kSparseHammingWeight;
    config.corridor_exposure_reduced_keys = true;
    config.security_report = material.securityReport;

    OrdinaryRefreshExecutionResult out;
    out.nativeAllYProductionPreflight =
        authorization.nativeAllYProductionPreflight;
    out.nativeResult =
        glscheme::rns::glr_ship_refresh_only_endpoint_prime(
            m_context, canonicalCiphertext, parameters, config,
            &out.nativeEvidence);
    ValidateOrdinaryRefreshExecutionEvidence(
        out.nativeResult, out.nativeEvidence);
    RequireOrdinaryRefreshEvidenceMatchesAllYReceipt(
        out.nativeEvidence, out.nativeAllYProductionPreflight);
    if (out.nativeResult.representation !=
            glscheme::rns::GlrShipRefreshOnlyEndpointRepresentation::
                refreshed_xy ||
        out.nativeResult.input_level != 18U ||
        out.nativeResult.output_level != 22U ||
        !out.nativeEvidence.canonical_production_authorized ||
        !out.nativeEvidence.streamed_gadget_provider_used ||
        !out.nativeEvidence.compact_selector_binding_used ||
        !out.nativeEvidence.streamed_dft_provider_used ||
        !out.nativeEvidence.bounded_ksk_provider_used ||
        !out.nativeEvidence.authenticated_ksk_payloads_used ||
        !out.nativeEvidence.provider_secret_free ||
        !out.nativeEvidence.ksk_provider_secret_free ||
        !out.nativeEvidence.dft_owner_authored_immutable ||
        !out.nativeEvidence.dft_provider_secret_free ||
        out.nativeEvidence.dft_plaintext_visits != 4U ||
        out.nativeEvidence.dft_peak_live_plaintexts != 1U ||
        out.nativeEvidence.ksk_manifest_commitment_sha256 !=
            keyManifestCommitment ||
        out.nativeEvidence.fold_level != kFoldKeyLevel ||
        out.nativeEvidence.transform_material_level !=
            kTransformMaterialLevel ||
        out.nativeEvidence.gadget_manifest_commitment !=
            gadgetManifest.manifest_commitment ||
        out.nativeEvidence.selector_binding_commitment !=
            selectorManifest.manifest_commitment ||
        out.nativeEvidence.dft_manifest_commitment !=
            dftManifest.manifest_commitment) {
        throw GlrError(
            "GLRProductionAdapter: native ordinary-refresh execution returned "
            "incomplete canonical streamed-material evidence");
    }
    out.productionExecutionExposed = true;
    return out;
}

GLRProductionAdapter::SecretKey GLRProductionAdapter::KeyGen(
    std::uint64_t seed) const {
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_keygen_primary(m_context, *rng);
}

GLRProductionAdapter::PublicKey GLRProductionAdapter::PublicKeyGen(
    const SecretKey& secretKey, std::uint64_t seed) const {
    RequireProductionSecretKey(m_context, secretKey);
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_gl128_keygen_public(
        m_context, secretKey, *rng);
}

GLRProductionAdapter::CompactPublicKey
GLRProductionAdapter::CompactPublicKeyGen(
    const SecretKey& secretKey, std::uint64_t seed) const {
    RequireProductionSecretKey(m_context, secretKey);
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_gl128_keygen_compact_public(
        m_context, secretKey, *rng);
}

GLRProductionAdapter::PublicKey
GLRProductionAdapter::ExpandCompactPublicKey(
    const CompactPublicKey& compactPublicKey) const {
    return glscheme::rns::glr_gl128_expand_compact_public_key(
        m_context, compactPublicKey);
}

std::uint64_t GLRProductionAdapter::PublicKeyResidentBytes() const {
    return glscheme::rns::glr_public_key_resident_bytes(m_context);
}

std::uint64_t GLRProductionAdapter::CompactPublicKeyMaterialBytes() const {
    return glscheme::rns::glr_compact_public_key_material_bytes(m_context);
}

GLRProductionAdapter::Plaintext GLRProductionAdapter::Encode(
    const MatrixBatch& matrices, double scale, std::uint32_t level,
    bool slotDomain) const {
    Plaintext plaintext = glscheme::rns::glr_gl128_encode(
        m_context, matrices, scale, level);
    if (slotDomain) {
        glscheme::rns::glr_to_slots(m_context, plaintext.poly);
    }
    return plaintext;
}

GLRProductionAdapter::MatrixBatch GLRProductionAdapter::Decode(
    const Plaintext& plaintext) const {
    return glscheme::rns::glr_gl128_decode(m_context, plaintext);
}

GLRProductionAdapter::NativeGL128TransposedPlaintext
GLRProductionAdapter::EncodeTransposed(
    const MatrixBatch& matrices, double scale, std::uint32_t level) const {
    return glscheme::rns::glr_gl128_encode_transposed(
        m_context, matrices, scale, level);
}

GLRProductionAdapter::NativeGL128TransposedDecodeResult
GLRProductionAdapter::DecodeTransposed(
    const NativeGL128TransposedPlaintext& plaintext) const {
    return glscheme::rns::glr_gl128_decode_transposed(m_context, plaintext);
}

GLRProductionAdapter::NativeGL128TransposedCiphertext
GLRProductionAdapter::EncryptTransposed(
    const SecretKey& secretKey,
    const NativeGL128TransposedPlaintext& plaintext,
    std::uint64_t seed) const {
    RequireProductionSecretKey(m_context, secretKey);
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_gl128_encrypt_secret_transposed(
        m_context, secretKey, plaintext, *rng);
}

GLRProductionAdapter::NativeGL128TransposedCiphertext
GLRProductionAdapter::EncryptTransposed(
    const PublicKey& publicKey,
    const NativeGL128TransposedPlaintext& plaintext,
    std::uint64_t seed) const {
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_gl128_encrypt_public_transposed(
        m_context, publicKey, plaintext, *rng);
}

GLRProductionAdapter::NativeGL128TransposedCiphertext
GLRProductionAdapter::EncryptTransposed(
    const CompactPublicKey& publicKey,
    const NativeGL128TransposedPlaintext& plaintext,
    std::uint64_t seed) const {
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_gl128_encrypt_public_transposed(
        m_context, publicKey, plaintext, *rng);
}

GLRProductionAdapter::NativeGL128TransposedPlaintext
GLRProductionAdapter::DecryptTransposed(
    const SecretKey& secretKey,
    const NativeGL128TransposedCiphertext& ciphertext) const {
    RequireProductionSecretKey(m_context, secretKey);
    return glscheme::rns::glr_gl128_decrypt_transposed(
        m_context, secretKey, ciphertext);
}

GLRProductionAdapter::NativeGL128TransposedDecodeResult
GLRProductionAdapter::DecryptDecodeTransposed(
    const SecretKey& secretKey,
    const NativeGL128TransposedCiphertext& ciphertext) const {
    RequireProductionSecretKey(m_context, secretKey);
    return glscheme::rns::glr_gl128_decrypt_decode_transposed(
        m_context, secretKey, ciphertext);
}

GLRProductionAdapter::NativeGL128LeftPlainMatrixMultiplyResult
GLRProductionAdapter::MatrixMultiplyPlainLeft(
    const NativeGL128TransposedPlaintext& plaintextLeft,
    const NativeGL128TransposedCiphertext& encryptedRight,
    const NativeGL128PlainProductOptions& options) const {
    return glscheme::rns::glr_gl128_matrix_multiply_plain_left(
        m_context, plaintextLeft, encryptedRight, options);
}

GLRProductionAdapter::NativeGL128ModulusMaintenanceResult
GLRProductionAdapter::LogicalRescale(const Ciphertext& ciphertext) const {
    return glscheme::rns::glr_gl128_logical_rescale(
        m_context, ciphertext);
}

GLRProductionAdapter::NativeGL128ModulusMaintenanceResult
GLRProductionAdapter::DropToLevel(
    const Ciphertext& ciphertext, std::uint32_t targetLevel) const {
    return glscheme::rns::glr_gl128_drop_to_level(
        m_context, ciphertext, targetLevel);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Encrypt(
    const SecretKey& secretKey, const Plaintext& plaintext, std::uint64_t seed,
    bool slotDomain) const {
    RequireProductionSecretKey(m_context, secretKey);
    RequireProductionPlaintext(m_context, plaintext);
    GlrRngOwner rng = MakeRng(seed);
    if (slotDomain) {
        return glscheme::rns::glr_gl128_encrypt_secret(
            m_context, secretKey, plaintext, *rng);
    }
    Ciphertext result = glscheme::rns::glr_encrypt(
        m_context, secretKey, plaintext, *rng, slotDomain);
    result.key_lineage_commitment =
        glscheme::rns::glr_ship_direct_primary_secret_lineage_commitment(
            m_context, secretKey);
    return result;
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Encrypt(
    const PublicKey& publicKey, const Plaintext& plaintext, std::uint64_t seed,
    bool slotDomain) const {
    RequireProductionPlaintext(m_context, plaintext);
    if (publicKey.parameter_fingerprint !=
            glscheme::rns::glr_parameter_fingerprint(m_context.params) ||
        publicKey.key_id != "primary" ||
        !IsCanonicalSha256Root(publicKey.key_lineage_commitment)) {
        throw GlrError(
            "GLRProductionAdapter: public encryption requires a "
            "profile-generated concrete primary-lineage public key");
    }
    GlrRngOwner rng = MakeRng(seed);
    if (slotDomain) {
        return glscheme::rns::glr_gl128_encrypt_public(
            m_context, publicKey, plaintext, *rng);
    }
    return glscheme::rns::glr_encrypt_public(
        m_context, publicKey, plaintext, *rng, slotDomain);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Encrypt(
    const CompactPublicKey& publicKey, const Plaintext& plaintext,
    std::uint64_t seed, bool slotDomain) const {
    RequireProductionPlaintext(m_context, plaintext);
    if (publicKey.parameter_fingerprint !=
            glscheme::rns::glr_parameter_fingerprint(m_context.params) ||
        publicKey.key_id != "primary" ||
        !IsCanonicalSha256Root(publicKey.key_lineage_commitment)) {
        throw GlrError(
            "GLRProductionAdapter: compact public encryption requires a "
            "profile-generated concrete primary-lineage key");
    }
    GlrRngOwner rng = MakeRng(seed);
    if (slotDomain) {
        return glscheme::rns::glr_gl128_encrypt_public(
            m_context, publicKey, plaintext, *rng);
    }
    return glscheme::rns::glr_encrypt_public(
        m_context, publicKey, plaintext, *rng, slotDomain);
}

GLRProductionAdapter::Plaintext GLRProductionAdapter::Decrypt(
    const SecretKey& secretKey, const Ciphertext& ciphertext) const {
    return glscheme::rns::glr_gl128_decrypt(
        m_context, secretKey, ciphertext);
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Add(
    const Ciphertext& lhs, const Ciphertext& rhs) const {
    return glscheme::rns::glr_gl128_add(m_context, lhs, rhs).ciphertext;
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Sub(
    const Ciphertext& lhs, const Ciphertext& rhs) const {
    return glscheme::rns::glr_gl128_subtract(m_context, lhs, rhs).ciphertext;
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
    NativeGL128PlainProductOptions options;
    options.rescale = false;
    return glscheme::rns::glr_gl128_matrix_multiply_plain(
               m_context, ciphertext, plaintext, options)
        .ciphertext;
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Hadamard(
    const Ciphertext& ciphertext, const Plaintext& plaintext) const {
    NativeGL128PlainProductOptions options;
    options.rescale = false;
    return glscheme::rns::glr_gl128_hadamard_plain(
               m_context, ciphertext, plaintext, options)
        .ciphertext;
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
    manifest.schema = "glscheme.rns_hybrid_ksk_manifest.v2";
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
    manifest.primary_secret_lineage_commitment =
        glscheme::rns::glr_ship_direct_primary_secret_lineage_commitment(
            m_context, primaryKey);
    manifest.sparse_secret_lineage_commitment.clear();
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
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_gl128_rotate_rows(
               m_context, ciphertext, amount, provider)
        .ciphertext;
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::RotateColumns(
    const Ciphertext& ciphertext, std::int32_t amount) const {
    return glscheme::rns::glr_gl128_rotate_columns(
               m_context, ciphertext, amount)
        .ciphertext;
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::RotateMatrices(
    const Ciphertext& ciphertext, std::int32_t amount,
    const EvaluationKeys& keys) const {
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_gl128_rotate_matrices(
               m_context, ciphertext, amount, provider)
        .ciphertext;
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Transpose(
    const Ciphertext& ciphertext, const EvaluationKeys& keys) const {
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_gl128_transpose(
               m_context, ciphertext, provider)
        .ciphertext;
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Conjugate(
    const Ciphertext& ciphertext, const EvaluationKeys& keys) const {
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_gl128_conjugate(
               m_context, ciphertext, provider)
        .ciphertext;
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::HermitianTranspose(
    const Ciphertext& ciphertext, const EvaluationKeys& keys) const {
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_gl128_hermitian_transpose(
               m_context, ciphertext, provider)
        .ciphertext;
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::MatMul(
    const Ciphertext& lhs, const Ciphertext& rhs,
    const EvaluationKeys& keys) const {
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_gl128_matrix_multiply_cipher(
               m_context, lhs, rhs, provider)
        .ciphertext;
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::MatMulAdjoint(
    const Ciphertext& lhs, const Ciphertext& rhs,
    const EvaluationKeys& keys) const {
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_gl128_matrix_multiply_cipher_adjoint(
               m_context, lhs, rhs, provider)
        .ciphertext;
}

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Hadamard(
    const Ciphertext& lhs, const Ciphertext& rhs,
    const EvaluationKeys& keys) const {
    const auto& provider = RequireEvaluationKeys(m_context, keys);
    return glscheme::rns::glr_gl128_hadamard_cipher(
               m_context, lhs, rhs, provider)
        .ciphertext;
}

GLRProductionAdapter::NativeGL128EvaluationResult
GLRProductionAdapter::EvaluateAdd(const Ciphertext& lhs,
                                  const Ciphertext& rhs) const {
    return glscheme::rns::glr_gl128_add(m_context, lhs, rhs);
}

GLRProductionAdapter::NativeGL128EvaluationResult
GLRProductionAdapter::EvaluateSub(const Ciphertext& lhs,
                                  const Ciphertext& rhs) const {
    return glscheme::rns::glr_gl128_subtract(m_context, lhs, rhs);
}

GLRProductionAdapter::NativeGL128EvaluationResult
GLRProductionAdapter::EvaluateMatMul(
    const Ciphertext& lhs, const Plaintext& rhs,
    const NativeGL128PlainProductOptions& options) const {
    return glscheme::rns::glr_gl128_matrix_multiply_plain(
        m_context, lhs, rhs, options);
}

GLRProductionAdapter::NativeGL128EvaluationResult
GLRProductionAdapter::EvaluateMatMul(
    const Ciphertext& lhs, const Ciphertext& rhs,
    const NativeKeyProvider& keys) const {
    if (keys.secret_material_accessed()) {
        throw GlrError(
            "GLRProductionAdapter: ct-ct matrix multiplication provider "
            "reports secret-material access");
    }
    return glscheme::rns::glr_gl128_matrix_multiply_cipher(
        m_context, lhs, rhs, keys);
}

GLRProductionAdapter::NativeGL128EvaluationResult
GLRProductionAdapter::EvaluateMatMulAdjoint(
    const Ciphertext& lhs, const Ciphertext& rhs,
    const NativeKeyProvider& keys) const {
    if (keys.secret_material_accessed()) {
        throw GlrError(
            "GLRProductionAdapter: ct-ct adjoint matrix multiplication "
            "provider reports secret-material access");
    }
    return glscheme::rns::glr_gl128_matrix_multiply_cipher_adjoint(
        m_context, lhs, rhs, keys);
}

GLRProductionAdapter::NativeGL128EvaluationResult
GLRProductionAdapter::EvaluateHadamard(
    const Ciphertext& lhs, const Plaintext& rhs,
    const NativeGL128PlainProductOptions& options) const {
    return glscheme::rns::glr_gl128_hadamard_plain(
        m_context, lhs, rhs, options);
}

GLRProductionAdapter::NativeGL128EvaluationResult
GLRProductionAdapter::EvaluateHadamard(
    const Ciphertext& lhs, const Ciphertext& rhs,
    const NativeKeyProvider& keys) const {
    if (keys.secret_material_accessed()) {
        throw GlrError(
            "GLRProductionAdapter: ct-ct Hadamard provider reports "
            "secret-material access");
    }
    return glscheme::rns::glr_gl128_hadamard_cipher(
        m_context, lhs, rhs, keys);
}

GLRProductionAdapter::NativeGL128EvaluationResult
GLRProductionAdapter::EvaluateRotateRows(
    const Ciphertext& ciphertext, std::int32_t amount,
    const NativeKeyProvider& keys) const {
    return glscheme::rns::glr_gl128_rotate_rows(
        m_context, ciphertext, amount, keys);
}

GLRProductionAdapter::NativeGL128EvaluationResult
GLRProductionAdapter::EvaluateRotateColumns(
    const Ciphertext& ciphertext, std::int32_t amount) const {
    return glscheme::rns::glr_gl128_rotate_columns(
        m_context, ciphertext, amount);
}

GLRProductionAdapter::NativeGL128EvaluationResult
GLRProductionAdapter::EvaluateRotateMatrices(
    const Ciphertext& ciphertext, std::int32_t amount,
    const NativeKeyProvider& keys) const {
    return glscheme::rns::glr_gl128_rotate_matrices(
        m_context, ciphertext, amount, keys);
}

GLRProductionAdapter::NativeGL128EvaluationResult
GLRProductionAdapter::EvaluateTranspose(
    const Ciphertext& ciphertext, const NativeKeyProvider& keys) const {
    return glscheme::rns::glr_gl128_transpose(m_context, ciphertext, keys);
}

GLRProductionAdapter::NativeGL128EvaluationResult
GLRProductionAdapter::EvaluateConjugate(
    const Ciphertext& ciphertext, const NativeKeyProvider& keys) const {
    return glscheme::rns::glr_gl128_conjugate(m_context, ciphertext, keys);
}

GLRProductionAdapter::NativeGL128EvaluationResult
GLRProductionAdapter::EvaluateHermitianTranspose(
    const Ciphertext& ciphertext, const NativeKeyProvider& keys) const {
    return glscheme::rns::glr_gl128_hermitian_transpose(
        m_context, ciphertext, keys);
}

}  // namespace lbcrypto
