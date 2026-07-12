//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#ifndef LBCRYPTO_PKE_GL_INT_PRODUCTION_GLR_BRIDGE_H
#define LBCRYPTO_PKE_GL_INT_PRODUCTION_GLR_BRIDGE_H

#include "openfhe/pke/glr-production-adapter.h"
#include "scheme/gl/gl-int-production-matmul.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

/** Exact integer GLR bridge; legacy Q2 imports remain quarantined. */
class GLIntProductionGLRBridge final {
public:
    using NativePlaintext = GLRProductionAdapter::Plaintext;
    using NativeCiphertext = GLRProductionAdapter::Ciphertext;
    using NativeSecretKey = GLRProductionAdapter::SecretKey;

    struct Capabilities {
        bool exactQ2CoefficientBridge{true};
        bool exactQ2SlotBridge{true};
        bool ownerDerivedNativeLineage{true};
        bool canonicalGL128ProfileBound{true};
        bool integerTErrHybridKeySwitch{true};
        bool keyedRowRotation{true};
        bool keyedInterMatrixRotation{true};
        bool keyedTranspose{true};
        bool keyedConjugationFamilySwap{true};
        bool denseEq5IntegerBatch{true};
        bool fullChainSymmetricTErrEncryption{true};
        bool fullChainBGVModSwitch{true};
        bool fullChainPublicTErrEncryption{true};
        bool compactSeededPublicA{true};
        bool fullChainDenseTernaryOwnerKeygen{true};
        bool fullChainSwitchIntSmall{true};
        bool fullChainSwitchIntBig{true};
        bool compactSeededSwitchKeys{true};
        bool fullChainDenseHadamard{true};
        bool fullChainDenseTraceProduct{true};
        bool fullChainKeyedAutomorphisms{true};
        bool selectableGPUTraceGemm{true};
        bool productionSecurityAuthorized{false};
        bool bootstrapDirectAdmitted{false};
    };

    struct Receipt {
        std::string schema{"openfhe.gl_int.glr_q2_bridge.v1"};
        std::string parameterFingerprint;
        std::string integerKeyTag;
        std::string nativeKeyLineageCommitment;
        std::string representation;
        std::string admissionRejection;
        std::string requiredEvaluationKey;
        std::uint64_t plaintextModulus{0};
        std::uint64_t plaintextScale{0};
        std::uint32_t nativeLevel{0};
        std::uint32_t activeQPrimes{0};
        bool exactModuloT{false};
        bool denseEq5Layout{false};
        bool tErrorInvariant{false};
        bool denseTernaryOwner{false};
        bool ownerSecretLineageBound{false};
        bool productionSecurityAuthorized{false};
        bool bootstrapDirectAdmitted{false};
    };

    class OwnerBinding final {
    public:
        OwnerBinding(const OwnerBinding&) = delete;
        OwnerBinding& operator=(const OwnerBinding&) = delete;
        OwnerBinding(OwnerBinding&&) noexcept = default;
        OwnerBinding& operator=(OwnerBinding&&) = delete;
        ~OwnerBinding();

        const NativeSecretKey& GetNativeSecretKey() const noexcept;
        const Receipt& GetReceipt() const noexcept;

    private:
        friend class GLIntProductionGLRBridge;
        OwnerBinding(NativeSecretKey secret, Receipt receipt,
                     std::string primaryLineageCommitment);

        NativeSecretKey m_secret;
        Receipt m_receipt;
        std::string m_primaryLineageCommitment;
    };

    struct PlaintextImport {
        NativePlaintext native;
        Receipt receipt;
    };

    struct CiphertextImport {
        NativeCiphertext native;
        Receipt receipt;
    };

    static constexpr std::size_t kDenseIntegerSlotCount =
        static_cast<std::size_t>(2) * 256 * 128 * 128;

    struct DenseIntegerBatch {
        // [family +/-][matrix 0..255][row][column], every value canonical mod t.
        std::vector<std::uint64_t> values;
        void Validate() const;
        std::uint64_t At(GLIntBranch family, std::uint32_t matrix,
                         std::uint32_t row, std::uint32_t column) const;
    };

    enum class IntegerAutomorphism : std::uint8_t {
        RowRotation,
        InterMatrixRotation,
        Transpose,
        ConjugationFamilySwap,
    };

    enum class FullChainSwitchKind : std::uint8_t {
        Square,
        ConjugationFamilySwap,
        RowRotation,
        InterMatrixRotation,
        Transpose,
        ConjugateTranspose,
        ProductConjugateTranspose,
    };

    /**
     * Restricted Q2P1 native hybrid key.  Its single Q2 gadget digit obeys
     * b+a*s_dst=P1*s_source+t*e; evaluation uses exact Q2->Q2P1 ModUp and
     * BGV t-corrected ModDown, never the CKKS divide-and-round path.
     */
    class IntegerAutomorphismKey final {
    public:
        IntegerAutomorphismKey(const IntegerAutomorphismKey&) = delete;
        IntegerAutomorphismKey& operator=(const IntegerAutomorphismKey&) = delete;
        IntegerAutomorphismKey(IntegerAutomorphismKey&&) noexcept = default;
        IntegerAutomorphismKey& operator=(IntegerAutomorphismKey&&) noexcept = default;
        ~IntegerAutomorphismKey() = default;

        IntegerAutomorphism GetOperation() const noexcept;
        std::int32_t GetAmount() const noexcept;
        std::uint32_t GetKeyLevel() const noexcept;
        std::uint32_t GetSpecialPrimeCount() const noexcept;
        const std::string& GetNativeKeyLineageCommitment() const noexcept;
        bool UsesTErrors() const noexcept;
        bool IsSecurityAuthorized() const noexcept;

    private:
        friend class GLIntProductionGLRBridge;
        IntegerAutomorphismKey(IntegerAutomorphism operation,
                               std::int32_t amount,
                               glscheme::rns::GlrRing ring,
                               glscheme::rns::GlrPoly b,
                               glscheme::rns::GlrPoly a,
                               std::string parameterFingerprint,
                               std::string nativeKeyLineageCommitment);

        IntegerAutomorphism m_operation{IntegerAutomorphism::RowRotation};
        std::int32_t m_amount{0};
        glscheme::rns::GlrRing m_ring{glscheme::rns::GlrRing::R};
        glscheme::rns::GlrPoly m_b;
        glscheme::rns::GlrPoly m_a;
        std::string m_parameterFingerprint;
        std::string m_nativeKeyLineageCommitment;
    };

    /** Compact full-Q ring-R public key: b is stored and uniform a is seeded. */
    class IntegerPublicKey final {
    public:
        IntegerPublicKey(const IntegerPublicKey&) = delete;
        IntegerPublicKey& operator=(const IntegerPublicKey&) = delete;
        IntegerPublicKey(IntegerPublicKey&&) noexcept = default;
        IntegerPublicKey& operator=(IntegerPublicKey&&) noexcept = default;
        ~IntegerPublicKey() = default;

        std::uint32_t GetKeyLevel() const noexcept;
        std::size_t GetStoredBytes() const noexcept;
        const std::string& GetParameterFingerprint() const noexcept;
        const std::string& GetIntegerKeyTag() const noexcept;
        const std::string& GetNativeKeyLineageCommitment() const noexcept;
        bool UsesSeededPublicA() const noexcept;
        bool UsesTErrors() const noexcept;
        bool HasDenseTernaryOwnerLineage() const noexcept;
        bool IsSecurityAuthorized() const noexcept;

    private:
        friend class GLIntProductionGLRBridge;
        IntegerPublicKey(
            glscheme::rns::GlrPoly b,
            glscheme::rns::GlrPublicASeed publicASeed,
            std::string parameterFingerprint, std::string integerKeyTag,
            std::string nativeKeyLineageCommitment,
            bool denseTernaryOwner);

        glscheme::rns::GlrPoly m_b;
        glscheme::rns::GlrPublicASeed m_publicASeed{};
        std::string m_parameterFingerprint;
        std::string m_integerKeyTag;
        std::string m_nativeKeyLineageCommitment;
        bool m_denseTernaryOwner{false};
    };

    struct IntegerSwitchResult {
        glscheme::rns::GlrPoly b;
        glscheme::rns::GlrPoly a;
    };

    /** Generic seeded-a full-chain SwitchInt_small/SwitchInt_big key. */
    class FullChainIntegerSwitchKey final {
    public:
        FullChainIntegerSwitchKey(const FullChainIntegerSwitchKey&) = delete;
        FullChainIntegerSwitchKey& operator=(
            const FullChainIntegerSwitchKey&) = delete;
        FullChainIntegerSwitchKey(
            FullChainIntegerSwitchKey&&) noexcept = default;
        FullChainIntegerSwitchKey& operator=(
            FullChainIntegerSwitchKey&&) noexcept = default;
        ~FullChainIntegerSwitchKey() = default;

        FullChainSwitchKind GetKind() const noexcept;
        std::int32_t GetAmount() const noexcept;
        std::uint32_t GetKeyLevel() const noexcept;
        std::uint32_t GetDigitCount() const noexcept;
        std::uint32_t GetSpecialPrimeCount() const noexcept;
        glscheme::rns::GlrRing GetRequiredInputRing() const noexcept;
        std::size_t GetMaterializedBytes() const noexcept;
        std::size_t GetCompactStoredBytes() const noexcept;
        const std::string& GetParameterFingerprint() const noexcept;
        const std::string& GetNativeKeyLineageCommitment() const noexcept;
        bool IsBigSwitch() const noexcept;
        bool UsesSeededPublicA() const noexcept;
        bool UsesTErrors() const noexcept;
        bool HasDenseTernaryOwnerLineage() const noexcept;
        bool IsSecurityAuthorized() const noexcept;

    private:
        friend class GLIntProductionGLRBridge;
        FullChainIntegerSwitchKey(
            FullChainSwitchKind kind, std::int32_t amount,
            glscheme::rns::GlrSwitchKey native,
            std::uint32_t activeSpecialPrimeCount,
            std::string nativeKeyLineageCommitment,
            bool denseTernaryOwner);

        FullChainSwitchKind m_kind{FullChainSwitchKind::Square};
        std::int32_t m_amount{0};
        glscheme::rns::GlrSwitchKey m_native;
        std::uint32_t m_activeSpecialPrimeCount{0};
        std::string m_nativeKeyLineageCommitment;
        bool m_denseTernaryOwner{false};
    };

    explicit GLIntProductionGLRBridge(
        const GLRProductionAdapter& adapter);

    Capabilities GetCapabilities() const noexcept;
    std::uint32_t GetNativeQ2Level() const noexcept;

    /** Legacy bounded h<=4 owner import retained only for Q2 compatibility. */
    OwnerBinding ImportOwnerSecret(
        const GLIntProductionSecretKey& secretKey) const;
    OwnerBinding GenerateFullChainOwnerBinding(
        std::uint64_t seed = 0) const;
    PlaintextImport ImportEncodedPlaintext(
        const GLIntProductionEncodedPlaintext& plaintext) const;
    GLIntProductionEncodedPlaintext ExportEncodedPlaintextModT(
        const NativePlaintext& plaintext) const;
    CiphertextImport ImportCoefficientCiphertext(
        const GLIntProductionCiphertext& ciphertext,
        const OwnerBinding& owner) const;
    GLIntProductionCiphertext ExportCoefficientCiphertext(
        const NativeCiphertext& ciphertext,
        const OwnerBinding& owner) const;
    CiphertextImport ImportSlotCiphertext(
        const GLIntProductionSlotCiphertext& ciphertext,
        const OwnerBinding& owner) const;
    GLIntProductionSlotCiphertext ExportSlotCiphertext(
        const NativeCiphertext& ciphertext,
        const OwnerBinding& owner) const;

    IntegerAutomorphismKey GenerateIntegerAutomorphismKey(
        const OwnerBinding& owner, IntegerAutomorphism operation,
        std::int32_t amount = 0, std::uint64_t seed = 0) const;
    NativeCiphertext EvaluateIntegerAutomorphism(
        const NativeCiphertext& ciphertext,
        const IntegerAutomorphismKey& evaluationKey) const;

    NativePlaintext EncodeDenseIntegerBatch(
        const DenseIntegerBatch& batch) const;
    DenseIntegerBatch DecryptDecodeFullChain(
        const NativeCiphertext& ciphertext,
        const OwnerBinding& owner) const;
    CiphertextImport EncryptFullChainSymmetric(
        const DenseIntegerBatch& batch, const OwnerBinding& owner,
        std::uint64_t seed = 0) const;
    IntegerPublicKey GenerateFullChainPublicKey(
        const OwnerBinding& owner, std::uint64_t seed = 0) const;
    CiphertextImport EncryptFullChainPublic(
        const DenseIntegerBatch& batch, const IntegerPublicKey& publicKey,
        std::uint64_t seed = 0) const;
    /** keyLevel=0 covers Q25; keyLevel=18 is the compact Q7/L18 corridor. */
    FullChainIntegerSwitchKey GenerateFullChainIntegerSwitchKey(
        const OwnerBinding& owner, FullChainSwitchKind kind,
        std::int32_t amount = 0, std::uint32_t keyLevel = 0,
        std::uint64_t seed = 0) const;
    IntegerSwitchResult ApplyFullChainIntegerSwitch(
        const glscheme::rns::GlrPoly& input,
        const FullChainIntegerSwitchKey& evaluationKey) const;
    glscheme::rns::GlrCompactSwitchKey CompactFullChainIntegerSwitchKey(
        const FullChainIntegerSwitchKey& evaluationKey) const;
    FullChainIntegerSwitchKey RestoreFullChainIntegerSwitchKey(
        FullChainSwitchKind kind, std::int32_t amount,
        const glscheme::rns::GlrCompactSwitchKey& compact,
        const Receipt& ownerReceipt) const;
    NativeCiphertext EvaluateFullChainIntegerAutomorphism(
        const NativeCiphertext& ciphertext,
        const FullChainIntegerSwitchKey& evaluationKey) const;
    NativeCiphertext RotateFullChainIntegerColumns(
        const NativeCiphertext& ciphertext, std::int32_t amount) const;
    NativeCiphertext EvaluateFullChainIntegerHadamard(
        const NativeCiphertext& lhs, const NativeCiphertext& rhs,
        const FullChainIntegerSwitchKey& squareKey) const;
    NativeCiphertext EvaluateFullChainIntegerTrace(
        const NativeCiphertext& lhs, const NativeCiphertext& rhs,
        const FullChainIntegerSwitchKey& conjugatedRightKey,
        const FullChainIntegerSwitchKey& productKey,
        glscheme::rns::GlrGemmKind gemmKind =
            glscheme::rns::GlrGemmKind::auto_dispatch) const;
    Receipt InspectFullChainCiphertext(
        const NativeCiphertext& ciphertext) const;
    NativeCiphertext ModSwitchFullChain(
        const NativeCiphertext& ciphertext) const;

    /** Always throws until an exact randomized Q7/L18 integer lift exists. */
    void RequireBootstrapDirectAdmission(const Receipt& receipt) const;
    /** Always throws for the sparse h<=4/Q2/support-revealing source path. */
    void RequireProductionSecurityAuthorization(const Receipt& receipt) const;

private:
    Receipt MakeReceipt(std::string representation) const;
    void ValidateOwner(const std::string& keyTag,
                       const OwnerBinding& owner,
                       const char* operation) const;
    glscheme::rns::GlrPoly RestrictToQ2P1(
        const glscheme::rns::GlrPoly& full) const;
    glscheme::rns::GlrPoly ModUpQ2P1(
        const glscheme::rns::GlrPoly& input) const;
    glscheme::rns::GlrPoly BGVModDownP1(
        const glscheme::rns::GlrPoly& input) const;
    std::pair<glscheme::rns::GlrPoly, glscheme::rns::GlrPoly>
    ApplyIntegerSwitch(
        const glscheme::rns::GlrPoly& input,
        const IntegerAutomorphismKey& evaluationKey) const;
    glscheme::rns::GlrPoly RestrictSecretToQ(
        const glscheme::rns::GlrPoly& full,
        std::uint32_t level) const;
    glscheme::rns::GlrPoly RingMultiply(
        const glscheme::rns::GlrPoly& lhs,
        const glscheme::rns::GlrPoly& rhs) const;
    glscheme::rns::GlrPoly SampleTErr(
        glscheme::rns::GlrRing ring, std::uint32_t level,
        glscheme::rns::GlrRng& rng) const;
    glscheme::rns::GlrPoly SampleTernaryRp(
        std::uint32_t level, glscheme::rns::GlrRng& rng) const;
    void AddTErrInPlace(glscheme::rns::GlrPoly* target,
                        glscheme::rns::GlrRng& rng) const;
    void MultiplyRpByRInSlots(
        glscheme::rns::GlrPoly* rp,
        const glscheme::rns::GlrPoly& r) const;
    std::pair<glscheme::rns::GlrKskId, std::int32_t>
    NormalizeFullChainSwitchKind(FullChainSwitchKind kind,
                                 std::int32_t amount) const;
    glscheme::rns::GlrPoly BuildFullChainSwitchSource(
        const OwnerBinding& owner, FullChainSwitchKind kind,
        std::int32_t amount, std::uint32_t keyLevel) const;
    void ConvertSwitchKeyErrorsToTErr(
        glscheme::rns::GlrSwitchKey* key,
        const glscheme::rns::GlrPoly& source,
        const OwnerBinding& owner) const;
    void AccumulateIntegerSwitchDigit(
        glscheme::rns::GlrPoly* b, glscheme::rns::GlrPoly* a,
        const glscheme::rns::GlrPoly& lifted,
        const glscheme::rns::GlrSwitchKey& key,
        std::size_t digit) const;
    glscheme::rns::GlrPoly BGVModDownSpecialPoly(
        const glscheme::rns::GlrPoly& input) const;
    std::uint64_t ValidateFullChainCiphertext(
        const NativeCiphertext& ciphertext, const char* operation) const;
    IntegerSwitchResult ApplyFullChainIntegerSwitchToRp(
        const glscheme::rns::GlrPoly& input,
        const FullChainIntegerSwitchKey& evaluationKey) const;
    glscheme::rns::GlrPoly BGVModSwitchPoly(
        const glscheme::rns::GlrPoly& input) const;

    const GLRProductionAdapter* m_adapter{nullptr};
    std::uint32_t m_q2Level{0};
    std::uint32_t m_q0{0};
    std::uint32_t m_q1{0};
    glscheme::rns::GlrContext m_plaintextContext;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_GL_INT_PRODUCTION_GLR_BRIDGE_H
