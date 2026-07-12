#include "openfhe/pke/glr-production-adapter.h"

#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

void Require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

}  // namespace

int main() {
    using Adapter = lbcrypto::GLRProductionAdapter;
    using Direction = glscheme::rns::GlrKsDirection;

    Adapter adapter = Adapter::Create();
    const auto profile = adapter.GetH64ResearchProfile();
    Require(profile.schema == "glscheme.gl128_h64_research_profile.v1" &&
                profile.profile_name ==
                    glscheme::rns::kGl128H64ResearchProfileName &&
                profile.matrix_order == 128 &&
                profile.matrix_count == 256 &&
                profile.sparse_hamming_weight == 64 &&
                profile.unsigned_choices_per_support == 512 &&
                profile.signed_choices_per_support == 1024 &&
                profile.window_count == 64 &&
                profile.raw_choice_entropy_bits == 640 &&
                profile.design_structured_floor_bits == 160 &&
                profile.exact_gl128_geometry &&
                profile.distinct_from_canonical_h40 &&
                profile.canonical_h40_unchanged &&
                profile.research_full_qp_estimator_proxy_present &&
                !profile.exact_estimator_evidence_present &&
                !profile.exact_noise_evidence_present &&
                !profile.production_security_authorized,
            "H64 research profile overstates production evidence");

    const auto plan = adapter.PlanH64HiddenSelector();
    Require(plan.schema == "glscheme.gl128_h64_hidden_selector_plan.v2" &&
                plan.profile.parameter_fingerprint ==
                    profile.parameter_fingerprint &&
                plan.profile.support_commitment ==
                    profile.support_commitment &&
                plan.storage.key_level == 0 &&
                plan.storage.active_q_primes == 25 &&
                plan.storage.active_special_primes == 13 &&
                plan.storage.control_record_count == 640 &&
                plan.storage.compact_bytes_per_control_pair == 39845952ULL &&
                plan.storage.full_bytes_per_control_pair == 159383552ULL &&
                plan.storage.compact_control_material_bytes ==
                    25501409280ULL &&
                plan.storage.full_control_material_bytes ==
                    102005473280ULL &&
                plan.storage.exact_cryptographic_material_census &&
                !plan.storage.restricted_p1_research_plan &&
                !plan.storage.restricted_p1_noise_certified &&
                plan.direct_cmux_output_level == 0 &&
                plan.direct_leaf_rescale_level == 2 &&
                plan.direct_h64_root_level == 14 &&
                plan.sparse_tree_depth == 6 &&
                plan.sparse_tree_product_nodes == 63 &&
                plan.sparse_tree_frontier_input_levels ==
                    std::vector<std::uint32_t>{2, 4, 6, 8, 10, 12} &&
                plan.sparse_domain_key_requirements.size() == 3 &&
                plan.sparse_domain_key_requirements[0].id.direction ==
                    Direction::sparse_sq_to_sparse &&
                plan.sparse_domain_key_requirements[0].key_level == 2 &&
                plan.sparse_domain_key_requirements[0].special_prime_count ==
                    1 &&
                plan.sparse_domain_key_requirements[1].id.direction ==
                    Direction::conjugation_to_sparse &&
                plan.sparse_domain_key_requirements[1].key_level == 14 &&
                plan.sparse_domain_key_requirements[1]
                        .special_prime_count == 1 &&
                plan.sparse_domain_key_requirements[2].id.direction ==
                    Direction::sparse_to_primary &&
                plan.sparse_domain_key_requirements[2].key_level == 14 &&
                plan.sparse_domain_key_requirements[2]
                        .special_prime_count == 1 &&
                plan.authenticated_sparse_ksk_schedule &&
                plan.full_64_support_fold_composed &&
                !plan.primary_domain_direct_tree_compatible &&
                plan.sparse_to_primary_before_forward_stc_required &&
                !plan.production_security_authorized &&
                !plan.bootstrap_direct_admitted,
            "H64 hidden-selector plan lost its research L0/L2/L14 schedule");

    const auto dft = adapter.GetCanonicalDirectDftGenerationConfig();
    Require(dft.profile ==
                    Adapter::NativeDftPlaintextGenerationConfig::Profile::
                        forward_only_two_record_v2 &&
                dft.forward_level == 13 && dft.inverse_level == 17 &&
                Adapter::kForwardDftPlaintextEntryCount == 2,
            "H64 forward StC is not pinned to directional DFT schema v2");

    Adapter::NativeGL128H64ResearchAllYStcEvidence evidence;
    Require(evidence.schema ==
                    "glscheme.gl128_h64_research_all_y_stc_evidence.v1" &&
                evidence.source_schedule_entries == 0 &&
                evidence.provider_resolver_calls == 0 &&
                evidence.branch_folds == 0 &&
                evidence.y_rows_composed == 0 &&
                !evidence.ciphertext_arithmetic_executed &&
                !evidence.full_all_y_stc_composed &&
                !evidence.exact_estimator_evidence_present &&
                !evidence.exact_noise_evidence_present &&
                !evidence.value_noise_acceptance_recorded &&
                !evidence.production_security_authorized &&
                !evidence.bootstrap_direct_admitted,
            "default H64 all-Y evidence overstates research execution");

    auto resolver = adapter.MakeH64AllYPublicRootProviderResolver();
    Require(static_cast<bool>(resolver),
            "H64 synchronous public-root provider resolver is absent");
    Require(Adapter::kH64AllYRows == 128 &&
                Adapter::kH64AllYBranchesPerRow == 2 &&
                Adapter::kH64AllYBranchFoldCount == 256 &&
                Adapter::NativeGL128H64ResearchPosture::research_only &&
                Adapter::NativeGL128H64ResearchPosture::
                    full_all_y_stc_composed &&
                !Adapter::NativeGL128H64ResearchPosture::
                    exact_estimator_evidence_present &&
                !Adapter::NativeGL128H64ResearchPosture::
                    exact_noise_evidence_present &&
                !Adapter::NativeGL128H64ResearchPosture::
                    production_security_claim &&
                !Adapter::NativeGL128H64ResearchPosture::
                    production_authorization_admitted,
            "OpenFHE H64 research posture is malformed");
    return 0;
}
