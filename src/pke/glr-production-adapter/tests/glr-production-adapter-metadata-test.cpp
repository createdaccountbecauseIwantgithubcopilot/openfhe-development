#include "openfhe/pke/glr-production-adapter.h"

#include <cstdint>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace {

void Require(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

}  // namespace

int main() {
    using Adapter = lbcrypto::GLRProductionAdapter;
    using glscheme::production::LayoutKind;

    static_assert(std::is_same_v<Adapter::Context, glscheme::rns::GlrContext>);
    static_assert(
        std::is_same_v<Adapter::Ciphertext, glscheme::rns::GlrCiphertext>);
    static_assert(!std::is_copy_constructible_v<Adapter>);
    static_assert(!std::is_copy_constructible_v<Adapter::EvaluationKeys>);
    using AdapterRef = const Adapter&;
    using CiphertextRef = const Adapter::Ciphertext&;
    using PlaintextRef = const Adapter::Plaintext&;
    using KeysRef = const Adapter::EvaluationKeys&;
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Sub(
                      std::declval<CiphertextRef>(),
                      std::declval<CiphertextRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Negate(
                      std::declval<CiphertextRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Rescale(
                      std::declval<CiphertextRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().MatMul(
                      std::declval<CiphertextRef>(),
                      std::declval<PlaintextRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Hadamard(
                      std::declval<CiphertextRef>(),
                      std::declval<PlaintextRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().RotateRows(
                      std::declval<CiphertextRef>(), 1,
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().RotateColumns(
                      std::declval<CiphertextRef>(), 1)),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().RotateMatrices(
                      std::declval<CiphertextRef>(), 1,
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Transpose(
                      std::declval<CiphertextRef>(),
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Conjugate(
                      std::declval<CiphertextRef>(),
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().HermitianTranspose(
                      std::declval<CiphertextRef>(),
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().MatMul(
                      std::declval<CiphertextRef>(),
                      std::declval<CiphertextRef>(),
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);
    static_assert(std::is_same_v<
                  decltype(std::declval<AdapterRef>().Hadamard(
                      std::declval<CiphertextRef>(),
                      std::declval<CiphertextRef>(),
                      std::declval<KeysRef>())),
                  Adapter::Ciphertext>);

    const Adapter::Profile profile = Adapter::CanonicalProfile();
    Require(profile.layout == LayoutKind::gl128_257_n32_tensor,
            "wrong typed layout");
    Require(profile.canonical_name ==
                "GL-128-257-N32/physical-256x128x128",
            "wrong canonical name");
    Require(profile.n == 128 && profile.p == 257 && profile.phi == 256,
            "wrong GL algebra shape");
    Require(profile.has_w_axis && profile.matrix_count == 256,
            "production profile lost its W axis");
    Require(profile.physical.planes == 256 && profile.physical.rows == 128 &&
                profile.physical.columns == 128,
            "wrong physical tensor shape");
    Require(profile.payload_complex_values == 4194304ULL,
            "wrong production payload size");
    Require(profile.rlwe_ring_dimension == 65536ULL,
            "wrong RLWE dimension");

    // Context construction and primary key generation are small enough for a
    // fast smoke test.  A full R' plaintext/ciphertext allocates gigabytes at
    // this canonical geometry, so encode/encrypt/decrypt/add are compile/link
    // provider checks here and belong in the resource-qualified acceptance run.
    Adapter adapter = Adapter::Create();
    const auto& context = adapter.GetContext();
    Require(context.params.name == "GL-128-257-N32", "wrong context profile");
    Require(context.n() == 128 && context.p_() == 257 && context.phi() == 256,
            "wrong context geometry");
    Require(context.params.coeffs_Rp() == 4194304ULL,
            "context is not the production R' tensor");

    // Planning is exact and allocation-free even for the production geometry.
    // It must deduplicate the Hermitian key shared by the explicit transform
    // and ciphertext MatMul, while retaining the two new §3.5/§3.6 families.
    Adapter::EvaluationKeyRequest allRequest;
    allRequest.rowRotations = {1, 1};
    allRequest.matrixRotations = {1};
    allRequest.transpose = true;
    allRequest.conjugation = true;
    allRequest.hermitianTranspose = true;
    allRequest.ciphertextMatMul = true;
    allRequest.ciphertextHadamard = true;
    const Adapter::EvaluationKeyPlan allPlan =
        adapter.PlanEvaluationKeys(allRequest);
    Require(allPlan.canonicalProfile == profile.canonical_name,
            "evaluation plan lost its canonical profile binding");
    Require(allPlan.parameterFingerprint == profile.binding_fingerprint,
            "evaluation plan lost its parameter fingerprint binding");
    Require(allPlan.keyLevel == 0 && allPlan.entries.size() == 7,
            "wrong deduplicated ordinary GL evaluation-key plan");
    const std::uint64_t plannedSum = std::accumulate(
        allPlan.entries.begin(), allPlan.entries.end(), std::uint64_t{0},
        [](std::uint64_t sum,
           const Adapter::EvaluationKeyPlanEntry& entry) {
            return sum + entry.residentBytes;
        });
    Require(allPlan.residentBytes == plannedSum && plannedSum > 0,
            "evaluation-key resident-byte total is not exact");
    for (const auto& entry : allPlan.entries) {
        Require(
            entry.residentBytes == glscheme::rns::glr_model_switch_key_bytes(
                                       context.params, entry.ring,
                                       static_cast<std::uint32_t>(
                                           glscheme::rns::glr_digit_groups(
                                               context.params, 0)
                                               .size())),
            "level-0 plan disagrees with the native switch-key size model");
    }
    using Direction = glscheme::rns::GlrKsDirection;
    const auto hasDirection = [&allPlan](Direction direction) {
        for (const auto& entry : allPlan.entries) {
            if (entry.id.direction == direction) {
                return true;
            }
        }
        return false;
    };
    Require(hasDirection(Direction::primary_conjtranspose_to_primary) &&
                hasDirection(
                    Direction::primary_product_conjtranspose_to_primary) &&
                hasDirection(Direction::primary_sq_to_primary),
            "ct-ct MatMul/Hadamard key debts are absent from the plan");

    Adapter::EvaluationKeyRequest lateRequest = allRequest;
    lateRequest.keyLevel =
        context.params.levels() - context.params.rescale_stride - 1;
    const auto latePlan = adapter.PlanEvaluationKeys(lateRequest);
    Require(latePlan.residentBytes < allPlan.residentBytes,
            "late-level key planning did not reduce resident bytes");

    bool rejectedNoRescaleHeadroom = false;
    try {
        Adapter::EvaluationKeyRequest invalid;
        invalid.ciphertextHadamard = true;
        invalid.keyLevel = context.params.levels() - 1;
        (void)adapter.PlanEvaluationKeys(invalid);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedNoRescaleHeadroom = true;
    }
    Require(rejectedNoRescaleHeadroom,
            "ct-ct plan without logical-rescale headroom did not fail closed");

    bool rejectedBadRotation = false;
    try {
        Adapter::EvaluationKeyRequest invalid;
        invalid.rowRotations = {128};
        (void)adapter.PlanEvaluationKeys(invalid);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedBadRotation = true;
    }
    Require(rejectedBadRotation,
            "out-of-range row-rotation key did not fail closed");

    Adapter::MatrixBatch wFreeRows;
    wFreeRows.n = 4096;
    wFreeRows.count = 1;
    bool rejectedWFreeRows = false;
    try {
        (void)adapter.Encode(wFreeRows, context.params.delta);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedWFreeRows = true;
    }
    Require(rejectedWFreeRows, "W-free dense rows aliased the GLR tensor");

    Adapter::SecretKey secretKey = adapter.KeyGen(0x474c523132383235ULL);
    Require(secretKey.key_id == "primary", "wrong key domain");
    Require(secretKey.s.ring == glscheme::rns::GlrRing::R,
            "primary key is not native ring R");
    Require(secretKey.s.extended, "primary key is missing the QP basis");
    const std::uint64_t expectedKeyResidues =
        std::uint64_t{context.active_qp_primes(0)} * 2 *
        context.params.coeffs_R();
    Require(secretKey.s.data.size() == expectedKeyResidues,
            "primary key storage does not match native GLR QP geometry");

    // A nonempty production plan must be rejected before generation when the
    // caller's explicit byte budget is one byte short.  Do not materialize
    // these multi-GiB keys in this metadata test.
    bool rejectedBudget = false;
    try {
        (void)adapter.MaterializeEvaluationKeys(
            secretKey, allPlan, "metadata-test-primary-commitment",
            allPlan.residentBytes - 1, 0x4556414c4b455953ULL);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedBudget = true;
    }
    Require(rejectedBudget,
            "evaluation-key materialization ignored its byte budget");

    // Empty materialization still crosses the real provider factory and
    // proves that the exported evaluator object is parameter-bound,
    // secret-free, move-only, and contains no hidden default keys.
    const Adapter::EvaluationKeyPlan emptyPlan =
        adapter.PlanEvaluationKeys(Adapter::EvaluationKeyRequest{});
    Require(emptyPlan.entries.empty() && emptyPlan.residentBytes == 0,
            "empty evaluation plan is not allocation-free");
    bool rejectedEmptyCommitment = false;
    try {
        (void)adapter.MaterializeEvaluationKeys(secretKey, emptyPlan, "", 0);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedEmptyCommitment = true;
    }
    Require(rejectedEmptyCommitment,
            "empty primary-key commitment did not fail closed");

    Adapter::EvaluationKeyPlan forgedPlan = emptyPlan;
    forgedPlan.residentBytes = 1;
    bool rejectedForgedPlan = false;
    try {
        (void)adapter.MaterializeEvaluationKeys(
            secretKey, forgedPlan, "metadata-test-primary-commitment", 1);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedForgedPlan = true;
    }
    Require(rejectedForgedPlan,
            "forged evaluation-key plan total did not fail closed");

    auto emptyKeys = adapter.MaterializeEvaluationKeys(
        secretKey, emptyPlan, "metadata-test-primary-commitment", 0,
        0x454d5054594b4559ULL);
    Require(emptyKeys.ResidentBytes() == 0 &&
                emptyKeys.GetManifest().records.empty() &&
                !emptyKeys.GetNativeProvider().secret_material_accessed(),
            "empty evaluator provider violated its public-material contract");
    Require(!emptyKeys.HasKey({Direction::row_rotation, 1}),
            "empty evaluator provider invented a default rotation key");

    Adapter::Ciphertext malformed;
    bool rejectedMalformedCiphertext = false;
    try {
        (void)adapter.Negate(malformed);
    }
    catch (const glscheme::rns::GlrError&) {
        rejectedMalformedCiphertext = true;
    }
    Require(rejectedMalformedCiphertext,
            "undersized native ciphertext did not fail closed");
    secretKey.secure_clear();

    std::cout << "glr_production_adapter_metadata_test: ALL PASS\n";
    return 0;
}
