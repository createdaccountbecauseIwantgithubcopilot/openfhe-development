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

namespace lbcrypto {

/** Exact, deliberately non-authorizing Q2 bridge into the canonical GLR ABI. */
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
        std::uint64_t plaintextModulus{0};
        std::uint32_t nativeLevel{0};
        std::uint32_t activeQPrimes{0};
        bool exactModuloT{false};
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

    explicit GLIntProductionGLRBridge(
        const GLRProductionAdapter& adapter);

    Capabilities GetCapabilities() const noexcept;
    std::uint32_t GetNativeQ2Level() const noexcept;

    OwnerBinding ImportOwnerSecret(
        const GLIntProductionSecretKey& secretKey) const;
    PlaintextImport ImportEncodedPlaintext(
        const GLIntProductionEncodedPlaintext& plaintext) const;
    GLIntProductionEncodedPlaintext ExportEncodedPlaintextModT(
        const NativePlaintext& plaintext) const;
    CiphertextImport ImportCoefficientCiphertext(
        const GLIntProductionCiphertext& ciphertext,
        const OwnerBinding& owner) const;
    CiphertextImport ImportSlotCiphertext(
        const GLIntProductionSlotCiphertext& ciphertext,
        const OwnerBinding& owner) const;

    /** Always throws until an exact randomized Q7/L18 integer lift exists. */
    void RequireBootstrapDirectAdmission(const Receipt& receipt) const;
    /** Always throws for the sparse h<=4/Q2/support-revealing source path. */
    void RequireProductionSecurityAuthorization(const Receipt& receipt) const;

private:
    Receipt MakeReceipt(std::string representation) const;
    void ValidateOwner(const std::string& keyTag,
                       const OwnerBinding& owner,
                       const char* operation) const;

    const GLRProductionAdapter* m_adapter{nullptr};
    std::uint32_t m_q2Level{0};
    std::uint32_t m_q0{0};
    std::uint32_t m_q1{0};
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_GL_INT_PRODUCTION_GLR_BRIDGE_H
