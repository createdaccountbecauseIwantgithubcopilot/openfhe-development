#ifndef LBCRYPTO_PKE_GLR_PRODUCTION_ADAPTER_H
#define LBCRYPTO_PKE_GLR_PRODUCTION_ADAPTER_H

// Optional provider for the native W-batched GL RNS engine in GLScheme.
//
// This is intentionally separate from GLSchemelet.  The canonical production
// layout is phi=256 matrices of shape 128x128 in R'[X,Y,W]; none of these types
// are OpenFHE DCRT rows, and the adapter exposes no DCRT conversion seam.

#include "glscheme/production_profiles.hpp"
#include "glscheme/rns_encode.hpp"
#include "glscheme/rns_hybrid_ks.hpp"
#include "glscheme/rns_keygen.hpp"
#include "glscheme/rns_public_key.hpp"
#include "glscheme/rns_ship.hpp"
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
    using NativeRefreshTracePreflight =
        glscheme::rns::GlrShipRefreshOnlyPackPreflight;

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

    enum class OrdinaryRefreshAvailability : std::uint8_t {
        // The adapter exposes no sparse-key, encrypted selector/gadget-bank,
        // or DFT-bank owner/provider seam and no production value execution.
        preflight_only = 1,
    };

    struct RefreshTraceKeyEntry {
        KeyId id;
        // Logarithmic doubling applies each exact key once per centered
        // readout.  This is 32,768 for canonical GL-128-257-N32.
        std::uint64_t applications = 0;
    };

    static constexpr std::size_t kCanonicalRefreshTraceKeyCount = 15;
    static constexpr std::size_t kCanonicalRefreshEndpointKeyDebtCount = 5;

    // Fixed-size, key/ciphertext-free ordinary-refresh census.  traceKeys are
    // exactly row_rotation:{1,2,4,8,16,32,64} followed by
    // w_rotation:{1,2,4,8,16,32,64,128}.  They are the coefficient-projector
    // keys only, not a claim that production SHIP is executable.
    // endpointKeyDebts separately names primary_to_sparse,
    // sparse_to_primary, conjugation_to_sparse, the primary transform key,
    // and the auxiliary transform key required by a full endpoint.
    struct OrdinaryRefreshPreflight {
        FixedProfileBindingText canonicalProfile;
        FixedProfileBindingText parameterFingerprint;
        glscheme::production::LayoutKind layout =
            glscheme::production::LayoutKind::gl128_257_n32_tensor;
        NativeRefreshTracePreflight native;
        std::array<RefreshTraceKeyEntry,
                   kCanonicalRefreshTraceKeyCount> traceKeys{};
        std::uint32_t traceKeyCount = 0;
        std::array<KeyId,
                   kCanonicalRefreshEndpointKeyDebtCount> endpointKeyDebts{};
        std::uint32_t endpointKeyDebtCount = 0;
        OrdinaryRefreshAvailability availability =
            OrdinaryRefreshAvailability::preflight_only;
        bool canonicalProfileBound = false;
        bool sparseKeyRequired = false;
        bool encryptedSelectorBankRequired = false;
        bool encryptedGadgetBankRequired = false;
        bool dftBankRequired = false;
        bool productionExecutionExposed = false;
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

    // Calls GLScheme's allocation-free prime-p refresh census and binds it to
    // this adapter's exact GL-128-257-N32 context.  No key, ciphertext,
    // selector/gadget bank, DFT bank, or sparse secret is allocated.  The
    // validator is suitable for a copied/persisted preflight and rejects any
    // profile, fingerprint, geometry, count, key-list, or availability
    // tampering before it could be interpreted as evaluator readiness.
    OrdinaryRefreshPreflight PreflightOrdinaryRefresh() const;
    void ValidateOrdinaryRefreshPreflight(
        const OrdinaryRefreshPreflight& preflight) const;

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
