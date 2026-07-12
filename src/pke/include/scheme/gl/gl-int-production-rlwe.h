//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#ifndef LBCRYPTO_PKE_SCHEME_GL_INT_PRODUCTION_RLWE_H
#define LBCRYPTO_PKE_SCHEME_GL_INT_PRODUCTION_RLWE_H

#include "scheme/gl/gl-int-production.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lbcrypto {

class GLIntProductionSwitchCore;

inline constexpr std::size_t kGLIntProductionRLWEPlaneCount = 2;
inline constexpr std::size_t kGLIntProductionMaxSecretTerms = 4;

/** One canonical Gaussian residue modulo one N32 ciphertext prime. */
struct GLIntProductionModResidue {
    uint32_t real{0};
    uint32_t imaginary{0};

    bool operator==(const GLIntProductionModResidue& other) const noexcept {
        return real == other.real && imaginary == other.imaginary;
    }
};

/** Secret-free view of one RNS ciphertext plane. */
struct GLIntProductionCiphertextPlane {
    uint32_t modulus{0};
    std::vector<GLIntProductionModResidue> b;
    std::vector<GLIntProductionModResidue> a;
};

/**
 * Bounded sparse ternary secret in
 * R_q = Z_q[I,X,W]/(I^2+1,X^128-I,Phi_257(W)).
 *
 * It is constant in Y exactly as GL_scheme.md §§3.2/4.2 require.  Terms are
 * private to the production RLWE core; callers receive only the key tag and
 * declared Hamming weight.
 */
class GLIntProductionSecretKey final {
public:
    const GLIntWBatchedParameters& GetParameters() const noexcept;
    const std::string& GetKeyTag() const noexcept;
    std::size_t GetHammingWeight() const noexcept;
    void Validate() const;

private:
    friend class GLIntProductionRLWECore;
    friend class GLIntProductionSwitchCore;

    struct Term {
        uint32_t x{0};
        uint32_t w{0};
        int8_t real{0};
        int8_t imaginary{0};
    };

    GLIntProductionSecretKey(GLIntWBatchedParameters parameters,
                             std::string keyTag, std::vector<Term> terms);

    GLIntWBatchedParameters m_parameters;
    std::string m_keyTag;
    std::vector<Term> m_terms;
};

/**
 * Genuine two-component R'_q ciphertext over a bounded two-prime prefix of
 * the production N32 basis.  Each plane contains the complete physical
 * 4,194,304-coefficient tensor for b and a; no plaintext shadow is stored.
 */
class GLIntProductionCiphertext final {
public:
    const GLIntWBatchedParameters& GetParameters() const noexcept;
    const GLIntWBatchedCodecRoots& GetRoots() const noexcept;
    const std::string& GetKeyTag() const noexcept;
    uint32_t GetLevel() const noexcept;
    const std::vector<GLIntProductionCiphertextPlane>& GetPlanes() const noexcept;
    void Validate() const;

private:
    friend class GLIntProductionRLWECore;

    GLIntProductionCiphertext(
        GLIntWBatchedParameters parameters, GLIntWBatchedCodecRoots roots,
        std::string keyTag, uint32_t level,
        std::vector<GLIntProductionCiphertextPlane> planes);

    GLIntWBatchedParameters m_parameters;
    GLIntWBatchedCodecRoots m_roots;
    std::string m_keyTag;
    uint32_t m_level{0};
    std::vector<GLIntProductionCiphertextPlane> m_planes;
};

struct GLIntProductionRLWECapabilities {
    bool exactProductionRPrimeCiphertext{true};
    bool symmetricTErrEncryption{true};
    bool exactDecryptionModT{true};
    bool boundedRnsModulusDrop{true};
    bool noiseScalingModSwitch{false};
    bool publicKeyEncryption{false};
    bool switchIntSmall{false};
    bool switchIntBig{false};
    bool securityAuthorized{false};
    bool ciphertextMatMul{false};
    bool bootstrap{false};
};

/**
 * Production-shaped Section-4 symmetric RLWE tranche.
 *
 * Encrypt samples uniform a in every active RNS plane and ternary e over the
 * complete R'_q tensor, then forms b=-a*s+m+t*e.  Decrypt evaluates b+a*s,
 * center-lifts modulo q, reduces modulo t, and cross-checks every active
 * plane.  The secret is a real W-dependent sparse element of R and never a
 * cleartext shadow.
 *
 * ModSwitchDrop removes the tail RNS plane without decryption.  It is an
 * exact basis/level drop because every plane independently satisfies the BGV
 * equation; it deliberately does not claim the noise-scaling ModSwitch of a
 * complete 25-prime production chain.  The two-prime prefix and sparse secret
 * are bounded implementation geometry, not a security authorization.
 */
class GLIntProductionRLWECore final {
public:
    explicit GLIntProductionRLWECore(
        GLIntWBatchedParameters parameters =
            GLIntWBatchedParameters::GL128257N32());

    const GLIntWBatchedParameters& GetParameters() const noexcept;
    const GLIntWBatchedCodecRoots& GetRoots() const noexcept;
    const std::vector<uint32_t>& GetModuli() const noexcept;
    GLIntProductionRLWECapabilities GetCapabilities() const noexcept;

    GLIntProductionSecretKey KeyGen(std::size_t hammingWeight = 2,
                                    uint64_t seed = 0) const;
    GLIntProductionCiphertext Encrypt(
        const GLIntProductionSecretKey& secretKey,
        const GLIntProductionEncodedPlaintext& plaintext,
        uint64_t seed = 0) const;
    GLIntProductionEncodedPlaintext Decrypt(
        const GLIntProductionSecretKey& secretKey,
        const GLIntProductionCiphertext& ciphertext) const;

    GLIntProductionCiphertext Add(
        const GLIntProductionCiphertext& lhs,
        const GLIntProductionCiphertext& rhs) const;
    GLIntProductionCiphertext Subtract(
        const GLIntProductionCiphertext& lhs,
        const GLIntProductionCiphertext& rhs) const;
    GLIntProductionCiphertext Negate(
        const GLIntProductionCiphertext& ciphertext) const;

    /** Exact evaluator-only RNS tail-plane drop; consumes one bounded level. */
    GLIntProductionCiphertext ModSwitchDrop(
        GLIntProductionCiphertext ciphertext) const;

private:
    void ValidateKey(const GLIntProductionSecretKey& key,
                     const char* operation) const;
    void ValidatePlaintext(const GLIntProductionEncodedPlaintext& plaintext,
                           const char* objectName) const;
    void ValidateCiphertext(const GLIntProductionCiphertext& ciphertext,
                            const char* objectName) const;
    void ValidateOperands(const GLIntProductionCiphertext& lhs,
                          const GLIntProductionCiphertext& rhs,
                          const char* operation) const;
    std::vector<GLIntProductionModResidue> MultiplyBySecret(
        const std::vector<GLIntProductionModResidue>& polynomial,
        const GLIntProductionSecretKey& secretKey, uint32_t modulus) const;

    GLIntWBatchedParameters m_parameters;
    GLIntWBatchedCodecRoots m_roots;
    std::vector<uint32_t> m_moduli;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_SCHEME_GL_INT_PRODUCTION_RLWE_H
