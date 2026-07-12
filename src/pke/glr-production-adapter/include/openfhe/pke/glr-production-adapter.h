#ifndef LBCRYPTO_PKE_GLR_PRODUCTION_ADAPTER_H
#define LBCRYPTO_PKE_GLR_PRODUCTION_ADAPTER_H

// Optional provider for the native W-batched GL RNS engine in GLScheme.
//
// This is intentionally separate from GLSchemelet.  The canonical production
// layout is phi=256 matrices of shape 128x128 in R'[X,Y,W]; none of these types
// are OpenFHE DCRT rows, and the adapter exposes no DCRT conversion seam.

#include "glscheme/production_profiles.hpp"
#include "glscheme/rns_dft_plaintext_provider.hpp"
#include "glscheme/rns_encode.hpp"
#include "glscheme/rns_hybrid_ks.hpp"
#include "glscheme/rns_keygen.hpp"
#include "glscheme/rns_public_key.hpp"
#include "glscheme/rns_ship.hpp"
#include "glscheme/rns_ship_compact_selector.hpp"
#include "glscheme/rns_ship_gadget_provider.hpp"
#include "glscheme/rns_w_algebra.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace lbcrypto {

class GLRProductionAdapter final {
public:
    using Profile = glscheme::production::Profile;
    using Context = glscheme::rns::GlrContext;
    using SecretKey = glscheme::rns::GlrSecretKey;
    using PublicKey = glscheme::rns::GlrPublicKey;
    using MatrixBatch = glscheme::rns::GlrMatrixBatch;
    using Plaintext = glscheme::rns::GlrPlaintext;
    using Ciphertext = glscheme::rns::GlrCiphertext;
    using KeyId = glscheme::rns::GlrKskId;
    using KeyRing = glscheme::rns::GlrRing;
    using KeyManifest = glscheme::rns::GlrKskManifest;
    using NativeKeyProvider = glscheme::rns::GlrKskProvider;
    using NativeLeasedKeyBinding = glscheme::rns::GlrLeasedKskBinding;
    using SecurityReport = ::glscheme::SecurityReport;
    using NativeRefreshTracePreflight =
        glscheme::rns::GlrShipRefreshOnlyPackPreflight;
    using NativeRefreshEndpointPreflight =
        glscheme::rns::GlrShipRefreshOnlyEndpointPreflight;
    using NativeRefreshEndpointResult =
        glscheme::rns::GlrShipRefreshOnlyEndpointResult;
    using NativeRefreshEndpointEvidence =
        glscheme::rns::GlrShipRefreshOnlyEndpointEvidence;
    using NativeRefreshDftPlaintextProvider =
        glscheme::rns::GlrDftPlaintextProvider;
    using NativeRefreshDftPlaintextBinding =
        glscheme::rns::GlrDftPlaintextBinding;
    using NativeRefreshGadgetProvider =
        glscheme::rns::GlrShipGadgetProvider;
    using NativeRefreshGadgetBinding =
        glscheme::rns::GlrShipGadgetBinding;
    using NativeRefreshCompactSelectorManifest =
        glscheme::rns::GlrShipCompactSelectorManifest;
    using NativeRefreshCompactSelectorBinding =
        glscheme::rns::GlrShipCompactSelectorBinding;
    using NativeRefreshPackParameters =
        glscheme::rns::GlrShipRefreshOnlyParameters;
    using NativeRefreshPackConfig = glscheme::rns::GlrShipConfig;
    using NativeRefreshPackAccumulator =
        glscheme::rns::GlrShipRefreshOnlyPackAccumulator;
    using NativeRefreshPackResult =
        glscheme::rns::GlrShipRefreshOnlyPackedResult;
    using NativeRefreshPackEvidence =
        glscheme::rns::GlrShipRefreshOnlyPackEvidence;
    using NativeRefreshPackCheckpointSink =
        glscheme::rns::GlrShipRefreshOnlyPackCheckpointSink;
    using NativeRefreshPackCheckpointSource =
        glscheme::rns::GlrShipRefreshOnlyPackCheckpointSource;
    using NativeRefreshPackCheckpointReceipt =
        glscheme::rns::GlrShipRefreshOnlyPackCheckpointReceipt;

    // Fixed-capacity binding text keeps the refresh preflight itself free of
    // heap-owning strings while still carrying the exact canonical name and
    // native parameter fingerprint.  View() remains valid for the lifetime
    // of the containing preflight value.
    struct FixedProfileBindingText {
        std::array<char, 96> bytes{};
        std::uint32_t size = 0;

        std::string_view View() const noexcept {
            return size <= bytes.size()
                       ? std::string_view(bytes.data(), size)
                       : std::string_view{};
        }
    };

    // Fixed-layout projection of the native all-Y production preflight.  The
    // native object owns schema/authorization strings; those bindings are
    // carried separately below so authorization remains trivially copyable.
    struct NativeRefreshAllYProductionReceipt {
        NativeRefreshTracePreflight pack;
        NativeRefreshEndpointPreflight endpoint;
        std::uint32_t schemaVersion = 0;
        std::uint32_t y_rows = 0;
        std::uint32_t branches_per_y_row = 0;
        std::uint32_t pair_major_row_tile_width = 0;
        std::uint32_t pair_major_row_tiles_per_centered_refresh = 0;
        std::uint64_t logical_all_y_branch_items = 0;
        std::uint64_t scalar_equivalent_branch_invocations = 0;
        std::uint64_t scalar_equivalent_exponent_ladder_nodes = 0;
        std::uint64_t scalar_equivalent_gadget_key_applications = 0;
        std::uint64_t pair_major_branch_tiles_per_centered_refresh = 0;
        std::uint64_t total_pair_major_branch_tile_invocations = 0;
        std::uint32_t streamed_unsigned_candidate_count = 0;
        std::uint32_t streamed_signed_pair_count = 0;
        std::uint32_t streamed_signed_pairs_per_window = 0;
        std::uint64_t streamed_exponent_leaf_batch_invocations = 0;
        std::uint64_t streamed_exponent_leaf_tables_batched = 0;
        std::uint64_t streamed_exponent_leaf_pair_visits = 0;
        std::uint64_t
            streamed_exponent_leaf_scalar_equivalent_pair_visits = 0;
        std::uint32_t streamed_exponent_leaf_max_batch_size = 0;
        std::uint32_t streamed_exponent_leaf_peak_accumulators = 0;
        std::uint32_t streamed_exponent_leaf_peak_scratch_polys = 0;
        bool exact_all_y_coverage = false;
        bool full_streamed_physical_schedule_pinned = false;
        bool context_ciphertext_or_key_allocation_required = true;
        bool material_schedule_metadata_admitted = false;
        bool ciphertext_value_execution_performed = false;
        bool value_noise_acceptance_recorded = false;
    };

    enum class OrdinaryRefreshAvailability : std::uint8_t {
        // This fixed census never owns or attests execution material.  The
        // separately typed ExecuteOrdinaryRefresh seam remains contingent on
        // caller-supplied material and a successful native endpoint call.
        preflight_only = 1,
    };

    struct RefreshTraceKeyEntry {
        KeyId id;
        // Logarithmic doubling applies each exact key once per centered
        // readout.  This is 32,768 for canonical GL-128-257-N32.
        std::uint64_t applications = 0;
    };

    // Exact native digit payload for one switch key of each ring at a numeric
    // key level.  This uses GLScheme's active-level digit census (not the
    // provisional full-chain dnum), so Q7/Q8 each correctly carry one digit.
    struct RefreshKeyLevelByteModel {
        std::uint32_t keyLevel = 0;
        std::uint64_t ringRPerKeyBytes = 0;
        std::uint64_t ringRpPerKeyBytes = 0;
        std::uint64_t ringRauxPerKeyBytes = 0;
    };

    static constexpr std::size_t kCanonicalRefreshTraceKeyCount = 15;
    static constexpr std::size_t kCanonicalRefreshEndpointKeyDebtCount = 5;
    static constexpr std::size_t kCanonicalRefreshKeyLevelModelCount = 2;

    // Fixed-size, key/ciphertext-free ordinary-refresh census.  traceKeys are
    // exactly row_rotation:{1,2,4,8,16,32,64} followed by
    // w_rotation:{1,2,4,8,16,32,64,128}.  They are the coefficient-projector
    // keys only, not a claim that production SHIP is executable.
    // endpointKeyDebts separately names primary_to_sparse,
    // sparse_to_primary, conjugation_to_sparse, the primary transform key,
    // and the auxiliary transform key required by a full endpoint.  endpoint
    // binds the canonical gamma=64, input-delta, DFT=2^46 strict arithmetic
    // ledger.  The explicit Q7+P14/h40 corridor fields are requirements for
    // separately supplied execution material, never readiness claims.
    struct OrdinaryRefreshPreflight {
        FixedProfileBindingText canonicalProfile;
        FixedProfileBindingText parameterFingerprint;
        glscheme::production::LayoutKind layout =
            glscheme::production::LayoutKind::gl128_257_n32_tensor;
        NativeRefreshTracePreflight native;
        NativeRefreshEndpointPreflight endpoint;
        std::array<RefreshTraceKeyEntry,
                   kCanonicalRefreshTraceKeyCount> traceKeys{};
        std::uint32_t traceKeyCount = 0;
        std::array<KeyId,
                   kCanonicalRefreshEndpointKeyDebtCount> endpointKeyDebts{};
        std::uint32_t endpointKeyDebtCount = 0;
        // Entries are level 18 (Q7) then level 17 (Q8).  The byte totals below
        // cover only the 15 listed trace rotations and five listed non-trace
        // debts; selector/gadget material is neither owned nor attested by the
        // preflight and is deliberately not implied by these planning numbers.
        std::array<RefreshKeyLevelByteModel,
                   kCanonicalRefreshKeyLevelModelCount> keyLevelModels{};
        std::uint32_t keyLevelModelCount = 0;
        std::uint64_t traceRotationKeyResidentBytes = 0;
        std::uint64_t listedNonTraceKeyDebtResidentBytes = 0;
        double refreshGamma = 1.0;
        double normalizationRelativeTolerance = 0.0;
        // Numeric levels count dropped Q primes.  Every trace and non-trace
        // endpoint KSK is generated on the refreshed level-18 Q7 basis; DFT
        // material is authored at level 17 and aligned only by exact drop.
        std::uint32_t traceKeyLevel = 0;
        std::uint32_t nonTraceKeyLevel = 0;
        std::uint32_t corridorQPrimeCount = 0;
        std::uint32_t corridorSpecialPrimeCount = 0;
        std::uint32_t requiredSparseHammingWeight = 0;
        OrdinaryRefreshAvailability availability =
            OrdinaryRefreshAvailability::preflight_only;
        bool canonicalProfileBound = false;
        bool reducedExposureCorridorRequired = false;
        bool securityAuthorizationRequired = false;
        bool sparseKeyRequired = false;
        // Legacy resident-bank requirements.  The OpenFHE execution seam does
        // not accept either material form; they remain false for its canonical
        // compact/streamed opening.
        bool encryptedSelectorBankRequired = false;
        bool encryptedGadgetBankRequired = false;
        bool dftBankRequired = false;
        bool productionExecutionExposed = false;
        // Append-only truth for the separately typed execution material view.
        bool compactSelectorBindingRequired = false;
        bool authenticatedLeasedKskRequired = false;
        bool streamedGadgetProviderRequired = false;
        bool streamedDftProviderRequired = false;
    };

    // Fixed, copyable result of validating one ACTUAL support commitment and
    // authenticated SecurityReport against GLScheme's canonical GL-128
    // endpoint authorization gate.  `productionAuthorizationAdmitted` means
    // that metadata passed the Q7+P14/h40 policy; it cannot be promoted or
    // copied into execution admission.  ExecuteOrdinaryRefresh instead
    // recomputes authorization from its actual material/report and calls the
    // native endpoint, so this policy-only result always remains false.
    struct OrdinaryRefreshAuthorization {
        NativeRefreshAllYProductionReceipt nativeAllYProductionPreflight;
        FixedProfileBindingText profileBindingFingerprint;
        FixedProfileBindingText supportCommitment;
        FixedProfileBindingText bootstrapProfileFingerprint;
        FixedProfileBindingText estimatorTranscriptSha256;
        std::uint32_t sparseHammingWeight = 0;
        std::uint32_t foldKeyLevel = 0;
        std::uint32_t transformMaterialLevel = 0;
        std::uint32_t exposedQPrimeCount = 0;
        std::uint32_t exposedSpecialPrimeCount = 0;
        bool reducedExposureCorridor = false;
        bool profileFingerprintBound = false;
        bool supportCommitmentBound = false;
        bool securityPolicyValidated = false;
        bool productionAuthorizationAdmitted = false;
        bool productionExecutionExposed = false;
    };

    // Non-owning view of one complete native ordinary-refresh opening.  Every
    // pointer is mandatory and must outlive ExecuteOrdinaryRefresh.  KSKs and
    // DFT plaintexts are supplied only through authenticated bounded
    // providers plus independently pinned external bindings.  DFT plaintexts
    // additionally require the owner-authored immutable policy.  This seam
    // accepts no resident DFT bank.  The view carries no secret, admission bit,
    // shared ownership, or copied OrdinaryRefreshAuthorization.  The adapter
    // pins h=40, the reduced Q7+P14 corridor, fold/key level 18, transform level
    // 17, gamma=64, DFT scale 2^46, and tolerance 1e-12 internally.
    struct OrdinaryRefreshExecutionMaterialView {
        const NativeKeyProvider* keyProvider = nullptr;
        const NativeLeasedKeyBinding* keyBinding = nullptr;
        const NativeRefreshDftPlaintextProvider* dftProvider = nullptr;
        const NativeRefreshDftPlaintextBinding* dftBinding = nullptr;
        const NativeRefreshGadgetProvider* gadgetProvider = nullptr;
        const NativeRefreshGadgetBinding* gadgetBinding = nullptr;
        const NativeRefreshCompactSelectorManifest* compactSelector = nullptr;
        const NativeRefreshCompactSelectorBinding* compactSelectorBinding =
            nullptr;
        const SecurityReport* securityReport = nullptr;
    };

    // Returned only after the native endpoint completes and its canonical
    // streamed-material evidence is checked.  A thrown call returns no result;
    // the flag therefore cannot become true on validation or execution failure.
    struct OrdinaryRefreshExecutionResult {
        NativeRefreshEndpointResult nativeResult;
        NativeRefreshEndpointEvidence nativeEvidence;
        NativeRefreshAllYProductionReceipt nativeAllYProductionPreflight;
        bool productionExecutionExposed = false;
    };

    class OrdinaryRefreshPackFacade;

    // Move-only rolling state for the native ordinary-refresh coefficient
    // packer.  This type is intentionally not convertible to either a packed
    // tensor or a refreshed-xy endpoint result.  A session becomes a packed
    // tensor only through OrdinaryRefreshPackFacade::Finalize after the native
    // core validates a complete, gap-free coordinate cover.
    class OrdinaryRefreshPackSession final {
    public:
        OrdinaryRefreshPackSession(const OrdinaryRefreshPackSession&) = delete;
        OrdinaryRefreshPackSession& operator=(
            const OrdinaryRefreshPackSession&) = delete;
        OrdinaryRefreshPackSession(OrdinaryRefreshPackSession&&) noexcept =
            default;
        OrdinaryRefreshPackSession& operator=(
            OrdinaryRefreshPackSession&&) noexcept = default;
        ~OrdinaryRefreshPackSession() = default;

        std::uint64_t NextCoordinate() const noexcept;
        std::uint64_t TotalCoordinates() const noexcept;
        bool CoordinateCoverComplete() const noexcept;

    private:
        friend class OrdinaryRefreshPackFacade;
        explicit OrdinaryRefreshPackSession(
            NativeRefreshPackAccumulator accumulator);

        NativeRefreshPackAccumulator m_accumulator;
    };

    // The pack finalizer returns only the native full coefficient tensor and
    // its measured pack evidence.  It deliberately has no endpoint-complete,
    // production-exposed, ciphertext-value, or value/noise acceptance flag:
    // CtS/normalization and StC/output validation remain the responsibility of
    // the unchanged ExecuteOrdinaryRefresh endpoint, and owner decryption is a
    // separate acceptance lane.
    struct OrdinaryRefreshPackFinalizedResult {
        NativeRefreshPackResult nativeResult;
        NativeRefreshPackEvidence nativeEvidence;
    };

    // Narrow OpenFHE-facing facade over GLScheme's resumable native packer.
    // Begin executes and merges the first nonempty prefix. Advance consumes
    // the next contiguous coordinate count. SerializeCheckpoint and Resume
    // use the bounded core codec and its externally authenticated receipt.
    // Finalize consumes a complete session and cannot expose a refreshed-xy
    // result. The referenced context and every provider/config pointer must
    // outlive each synchronous call. The explicit context constructor keeps
    // small staged/toy conformance possible; canonical callers obtain the
    // facade from GLRProductionAdapter::ResumableOrdinaryRefreshPack().
    class OrdinaryRefreshPackFacade final {
    public:
        explicit OrdinaryRefreshPackFacade(const Context& context) noexcept;

        OrdinaryRefreshPackSession Begin(
            const Ciphertext& sparseCoefficientInput,
            const NativeRefreshPackParameters& parameters,
            const NativeRefreshPackConfig& config,
            std::uint64_t firstCoordinateCount) const;

        void Advance(
            OrdinaryRefreshPackSession& session,
            const Ciphertext& sparseCoefficientInput,
            const NativeRefreshPackParameters& parameters,
            const NativeRefreshPackConfig& config,
            std::uint64_t coordinateCount) const;

        NativeRefreshPackCheckpointReceipt SerializeCheckpoint(
            const OrdinaryRefreshPackSession& session,
            const NativeRefreshPackCheckpointSink& sink) const;

        OrdinaryRefreshPackSession Resume(
            const NativeRefreshPackCheckpointReceipt& authenticatedReceipt,
            const NativeRefreshPackCheckpointSource& source) const;

        OrdinaryRefreshPackFinalizedResult Finalize(
            OrdinaryRefreshPackSession&& session,
            const Ciphertext& sparseCoefficientInput,
            const NativeRefreshPackParameters& parameters,
            const NativeRefreshPackConfig& config) const;

    private:
        const Context* m_context = nullptr;
    };

    // Ordinary GL evaluation-key request.  Rotation amounts name the exact
    // native Galois keys to materialize; there is no implicit all-rotations
    // closure.  keyLevel counts dropped Q primes, just like GlrCiphertext.
    // A higher key level reduces resident bytes but can only evaluate
    // ciphertexts at that numeric level or later/deeper in the chain.
    struct EvaluationKeyRequest {
        std::vector<std::int32_t> rowRotations;
        std::vector<std::int32_t> matrixRotations;
        bool transpose = false;
        bool conjugation = false;
        bool hermitianTranspose = false;
        bool ciphertextMatMul = false;
        bool ciphertextHadamard = false;
        std::uint32_t keyLevel = 0;
    };

    struct EvaluationKeyPlanEntry {
        KeyId id;
        KeyRing ring = KeyRing::R;
        std::uint64_t residentBytes = 0;
    };

    // A public, allocation-free preflight result.  residentBytes is the exact
    // native in-memory digit payload (both key components and i-split lanes),
    // not a disk-cache estimate.  The adapter has no key serialization seam.
    struct EvaluationKeyPlan {
        std::string canonicalProfile;
        std::string parameterFingerprint;
        std::uint32_t keyLevel = 0;
        std::vector<EvaluationKeyPlanEntry> entries;
        std::uint64_t residentBytes = 0;
    };

    // Secret-free evaluator material.  Construction is only through
    // MaterializeEvaluationKeys, which validates the exact production
    // fingerprint and an explicit caller byte budget before key generation.
    class EvaluationKeys final {
    public:
        EvaluationKeys(const EvaluationKeys&) = delete;
        EvaluationKeys& operator=(const EvaluationKeys&) = delete;
        EvaluationKeys(EvaluationKeys&&) noexcept = default;
        EvaluationKeys& operator=(EvaluationKeys&&) noexcept = default;
        ~EvaluationKeys() = default;

        const EvaluationKeyPlan& GetPlan() const noexcept;
        const KeyManifest& GetManifest() const noexcept;
        const NativeKeyProvider& GetNativeProvider() const;
        bool HasKey(const KeyId& id) const noexcept;
        std::uint64_t ResidentBytes() const noexcept;

    private:
        friend class GLRProductionAdapter;
        EvaluationKeys(EvaluationKeyPlan plan, KeyManifest manifest,
                       std::unique_ptr<NativeKeyProvider> provider);

        EvaluationKeyPlan m_plan;
        KeyManifest m_manifest;
        std::unique_ptr<NativeKeyProvider> m_provider;
    };

    // Returns and validates the one profile this provider accepts:
    // GL-128-257-N32, physical layout 256x128x128.
    static Profile CanonicalProfile();

    // Builds native GLScheme transform tables for the canonical profile.
    static GLRProductionAdapter Create();

    GLRProductionAdapter(const GLRProductionAdapter&) = delete;
    GLRProductionAdapter& operator=(const GLRProductionAdapter&) = delete;
    GLRProductionAdapter(GLRProductionAdapter&&) noexcept = default;
    GLRProductionAdapter& operator=(GLRProductionAdapter&&) noexcept = default;
    ~GLRProductionAdapter() = default;

    const Context& GetContext() const noexcept;

    OrdinaryRefreshPackFacade ResumableOrdinaryRefreshPack() const noexcept;

    // Calls GLScheme's allocation-free prime-p refresh census and binds it to
    // this adapter's exact GL-128-257-N32 context.  No key, ciphertext,
    // selector/gadget bank, DFT bank, or sparse secret is allocated.  The
    // validator is suitable for a copied/persisted preflight and rejects any
    // profile, fingerprint, geometry, count, key-list, or availability
    // tampering before it could be interpreted as evaluator readiness.
    OrdinaryRefreshPreflight PreflightOrdinaryRefresh() const;
    void ValidateOrdinaryRefreshPreflight(
        const OrdinaryRefreshPreflight& preflight) const;

    // Calls glr_ship_refresh_only_endpoint_authorize_gl128 with the actual
    // commitment/report.  Fold/key level 18 and transform-material level 17
    // are pinned internally; no bare authorization boolean is accepted.
    OrdinaryRefreshAuthorization AuthorizeOrdinaryRefreshProduction(
        const std::string& supportCommitment,
        const SecurityReport& securityReport,
        std::uint32_t sparseHammingWeight = 40,
        bool reducedExposureCorridor = true) const;
    void ValidateOrdinaryRefreshAuthorization(
        const OrdinaryRefreshAuthorization& authorization,
        const std::string& supportCommitment,
        const SecurityReport& securityReport,
        std::uint32_t sparseHammingWeight = 40,
        bool reducedExposureCorridor = true) const;

    // Allocation-free validation of the native endpoint's canonical stage
    // ledger and full all-Y pack census.  Material-specific provider roots are
    // checked separately by ExecuteOrdinaryRefresh; this validator never
    // promotes policy/evidence metadata into an execution claim.
    void ValidateOrdinaryRefreshExecutionEvidence(
        const NativeRefreshEndpointResult& result,
        const NativeRefreshEndpointEvidence& evidence) const;

    // Executes the genuine native canonical endpoint on caller-owned native
    // material.  It validates both external bindings, joins the compact
    // selector to the streamed gadget/KSK support, opens the externally bound
    // streamed DFT provider, and recomputes the h40 authorization from the
    // actual selector support and SecurityReport before calling
    // glr_ship_refresh_only_endpoint_prime.  This API is an execution seam, not
    // evidence that a full GL-128 material/value run has occurred.
    OrdinaryRefreshExecutionResult ExecuteOrdinaryRefresh(
        const Ciphertext& canonicalCiphertext,
        const OrdinaryRefreshExecutionMaterialView& material) const;

    // GLScheme's current owner-side encryption API is symmetric.  A zero seed
    // requests operating-system entropy; nonzero seeds are deterministic and
    // intended for tests/reproducible experiments.
    SecretKey KeyGen(std::uint64_t seed = 0) const;
    PublicKey PublicKeyGen(const SecretKey& secretKey,
                           std::uint64_t seed = 0) const;
    std::uint64_t PublicKeyResidentBytes() const;

    Plaintext Encode(const MatrixBatch& matrices, double scale,
                     std::uint32_t level = 0,
                     bool slotDomain = false) const;
    MatrixBatch Decode(const Plaintext& plaintext) const;

    Ciphertext Encrypt(const SecretKey& secretKey, const Plaintext& plaintext,
                       std::uint64_t seed = 0, bool slotDomain = true) const;
    Ciphertext Encrypt(const PublicKey& publicKey, const Plaintext& plaintext,
                       std::uint64_t seed = 0,
                       bool slotDomain = true) const;
    Plaintext Decrypt(const SecretKey& secretKey,
                      const Ciphertext& ciphertext) const;

    // Native GLR ciphertext addition.  This delegates directly to glr_ct_add;
    // it does not unpack matrices into OpenFHE rows.
    Ciphertext Add(const Ciphertext& lhs, const Ciphertext& rhs) const;
    Ciphertext Sub(const Ciphertext& lhs, const Ciphertext& rhs) const;
    Ciphertext Negate(const Ciphertext& ciphertext) const;

    // One native logical GL rescale.  The N32 profile represents one logical
    // scale level with two physical Q primes, so this drops exactly
    // max(1,rescale_stride) tail primes and fails closed without headroom.
    Ciphertext Rescale(const Ciphertext& ciphertext) const;

    // Native plaintext-ciphertext GL operations.  A coefficient-domain
    // plaintext is transformed to Slot domain on a private copy; inputs are
    // never reinterpreted as OpenFHE DCRT rows.
    Ciphertext MatMul(const Ciphertext& ciphertext,
                      const Plaintext& plaintext) const;
    Ciphertext Hadamard(const Ciphertext& ciphertext,
                       const Plaintext& plaintext) const;

    // Allocation-free evaluation-key planning, followed by explicitly
    // budgeted owner-side materialization.  primaryKeyCommitment is an opaque
    // nonempty public commitment supplied by the key owner; the adapter will
    // not invent one from, serialize, or expose the secret key.  A zero RNG
    // seed requests operating-system entropy.
    EvaluationKeyPlan PlanEvaluationKeys(
        const EvaluationKeyRequest& request) const;
    EvaluationKeys MaterializeEvaluationKeys(
        const SecretKey& primaryKey, const EvaluationKeyPlan& plan,
        std::string primaryKeyCommitment, std::uint64_t maxResidentBytes,
        std::uint64_t seed = 0) const;

    Ciphertext RotateRows(const Ciphertext& ciphertext, std::int32_t amount,
                          const EvaluationKeys& keys) const;
    Ciphertext RotateColumns(const Ciphertext& ciphertext,
                             std::int32_t amount) const;
    Ciphertext RotateMatrices(const Ciphertext& ciphertext,
                              std::int32_t amount,
                              const EvaluationKeys& keys) const;
    Ciphertext Transpose(const Ciphertext& ciphertext,
                         const EvaluationKeys& keys) const;
    Ciphertext Conjugate(const Ciphertext& ciphertext,
                         const EvaluationKeys& keys) const;
    Ciphertext HermitianTranspose(const Ciphertext& ciphertext,
                                  const EvaluationKeys& keys) const;

    // Ordinary §3.5/§3.6 ciphertext-ciphertext operations.  MatMul consumes
    // the Hermitian-right and product-basis keys; Hadamard consumes the
    // primary-square relinearization key.  Both perform the native logical
    // rescale (two physical Q-prime drops on the N32 profile).
    Ciphertext MatMul(const Ciphertext& lhs, const Ciphertext& rhs,
                      const EvaluationKeys& keys) const;
    Ciphertext Hadamard(const Ciphertext& lhs, const Ciphertext& rhs,
                       const EvaluationKeys& keys) const;

private:
    explicit GLRProductionAdapter(Context context);

    Context m_context;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_GLR_PRODUCTION_ADAPTER_H
