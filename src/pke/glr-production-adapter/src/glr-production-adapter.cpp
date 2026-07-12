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
    const auto native =
        glscheme::rns::glr_ship_refresh_only_endpoint_authorize_gl128(
            context.params, kFoldKeyLevel, kTransformMaterialLevel,
            sparseHammingWeight, reducedExposureCorridor, supportCommitment,
            securityReport);
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
    if (!BindingTextEquals(actual.profileBindingFingerprint,
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
    (void)MakeOrdinaryRefreshAuthorization(
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
    out.nativeResult =
        glscheme::rns::glr_ship_refresh_only_endpoint_prime(
            m_context, canonicalCiphertext, parameters, config,
            &out.nativeEvidence);
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
    return glscheme::rns::glr_keygen_public(m_context, secretKey, *rng);
}

std::uint64_t GLRProductionAdapter::PublicKeyResidentBytes() const {
    return glscheme::rns::glr_public_key_resident_bytes(m_context);
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

GLRProductionAdapter::Ciphertext GLRProductionAdapter::Encrypt(
    const PublicKey& publicKey, const Plaintext& plaintext, std::uint64_t seed,
    bool slotDomain) const {
    RequireProductionPlaintext(m_context, plaintext);
    GlrRngOwner rng = MakeRng(seed);
    return glscheme::rns::glr_encrypt_public(
        m_context, publicKey, plaintext, *rng, slotDomain);
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
