//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#ifndef LBCRYPTO_PKE_SCHEME_GL_INT_PRODUCTION_SWITCH_H
#define LBCRYPTO_PKE_SCHEME_GL_INT_PRODUCTION_SWITCH_H

#include "scheme/gl/gl-int-production-rlwe.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lbcrypto {

inline constexpr std::size_t kGLIntProductionMaxSwitchKeyTerms = 4096;
inline constexpr std::size_t kGLIntProductionMaxAuxSwitchInputTerms = 8;

enum class GLIntProductionSwitchDirection : uint8_t {
    SmallSquareToPrimary,
    BigTransposeToPrimary,
};

struct GLIntProductionRNSPolynomialPlane {
    uint32_t modulus{0};
    std::vector<GLIntProductionModResidue> coefficients;
};

/** Complete production R'_q polynomial over an active bounded RNS prefix. */
class GLIntProductionRNSPolynomial final {
public:
    const GLIntWBatchedParameters& GetParameters() const noexcept;
    const GLIntWBatchedCodecRoots& GetRoots() const noexcept;
    uint32_t GetLevel() const noexcept;
    const std::vector<GLIntProductionRNSPolynomialPlane>& GetPlanes() const noexcept;
    void Validate() const;

private:
    friend class GLIntProductionSwitchCore;

    GLIntProductionRNSPolynomial(
        GLIntWBatchedParameters parameters, GLIntWBatchedCodecRoots roots,
        uint32_t level, std::vector<GLIntProductionRNSPolynomialPlane> planes);

    GLIntWBatchedParameters m_parameters;
    GLIntWBatchedCodecRoots m_roots;
    uint32_t m_level{0};
    std::vector<GLIntProductionRNSPolynomialPlane> m_planes;
};

/**
 * Secret-free bounded evaluation key satisfying k0+k1*s_destination=s_source.
 * Components use a sparse coefficient representation but apply to complete
 * dense R'_q inputs.  The current key is deliberately noise-free and therefore
 * algebraically exact but not RLWE-secure.
 */
class GLIntProductionSwitchKey final {
public:
    GLIntProductionSwitchDirection GetDirection() const noexcept;
    const std::string& GetDestinationKeyTag() const noexcept;
    std::size_t GetK0TermCount() const noexcept;
    std::size_t GetK1TermCount() const noexcept;
    bool IsNoiseFree() const noexcept;
    bool IsSecurityAuthorized() const noexcept;
    void Validate() const;

private:
    friend class GLIntProductionSwitchCore;

    struct Term {
        uint32_t x{0};
        uint32_t y{0};
        uint32_t w{0};
        int64_t real{0};
        int64_t imaginary{0};
    };

    GLIntProductionSwitchKey(GLIntWBatchedParameters parameters,
                             GLIntProductionSwitchDirection direction,
                             std::string destinationKeyTag,
                             std::vector<Term> k0,
                             std::vector<Term> k1);

    GLIntWBatchedParameters m_parameters;
    GLIntProductionSwitchDirection m_direction{
        GLIntProductionSwitchDirection::SmallSquareToPrimary};
    std::string m_destinationKeyTag;
    std::vector<Term> m_k0;
    std::vector<Term> m_k1;
};

/**
 * Two-plane RLWE evaluation key for the paper's auxiliary-modulus SwitchInt.
 * Each plane satisfies b+a*s_dst=q_o*s_source+t*e; q_o is the tail prime.
 */
class GLIntProductionAuxSwitchKey final {
public:
    GLIntProductionSwitchDirection GetDirection() const noexcept;
    const std::string& GetDestinationKeyTag() const noexcept;
    uint32_t GetAuxiliaryModulus() const noexcept;
    const std::vector<GLIntProductionCiphertextPlane>& GetPlanes() const noexcept;
    bool UsesTErrors() const noexcept;
    bool UsesNoiseScalingModSwitch() const noexcept;
    bool IsSecurityAuthorized() const noexcept;
    void Validate() const;

private:
    friend class GLIntProductionSwitchCore;

    GLIntProductionAuxSwitchKey(
        GLIntWBatchedParameters parameters, GLIntWBatchedCodecRoots roots,
        GLIntProductionSwitchDirection direction,
        std::string destinationKeyTag, uint32_t auxiliaryModulus,
        std::vector<GLIntProductionCiphertextPlane> planes);

    GLIntWBatchedParameters m_parameters;
    GLIntWBatchedCodecRoots m_roots;
    GLIntProductionSwitchDirection m_direction{
        GLIntProductionSwitchDirection::SmallSquareToPrimary};
    std::string m_destinationKeyTag;
    uint32_t m_auxiliaryModulus{0};
    std::vector<GLIntProductionCiphertextPlane> m_planes;
};

class GLIntProductionSwitchResult final {
public:
    GLIntProductionSwitchDirection GetDirection() const noexcept;
    const std::string& GetDestinationKeyTag() const noexcept;
    const GLIntProductionRNSPolynomial& GetB() const noexcept;
    const GLIntProductionRNSPolynomial& GetA() const noexcept;
    void Validate() const;

private:
    friend class GLIntProductionSwitchCore;

    GLIntProductionSwitchResult(GLIntProductionSwitchDirection direction,
                                std::string destinationKeyTag,
                                GLIntProductionRNSPolynomial b,
                                GLIntProductionRNSPolynomial a);

    GLIntProductionSwitchDirection m_direction;
    std::string m_destinationKeyTag;
    GLIntProductionRNSPolynomial m_b;
    GLIntProductionRNSPolynomial m_a;
};

struct GLIntProductionSwitchCapabilities {
    bool denseRPrimeInput{true};
    bool boundedSparseEvaluationKey{true};
    bool denseAuxiliaryEvaluationKey{true};
    bool boundedSparseAuxiliaryInput{true};
    bool switchIntSmall{true};
    bool switchIntBig{true};
    bool gadgetDecomposition{true};
    bool noisyEvaluationKey{true};
    bool auxiliaryModulusKeySwitch{true};
    bool noiseScalingModSwitch{true};
    bool securityAuthorized{false};
    bool ciphertextMatMul{false};
};

/**
 * Exact bounded SwitchInt algebra for the production quotient ring.
 *
 * SmallSquare keys switch s(X,W)^2 to s(X,W).  BigTranspose keys switch the
 * integer cross-lane source s(-I,Y^-1,W^-1) to s(I,X,W), including inverse
 * Y/W exponents, Gaussian-sign changes, both I-wraps, and exact Phi_257(W)
 * fan-out.  Owner verification recomputes the source relation from the
 * supplied primary secret without exposing that secret.
 *
 * The original sparse-key methods remain fast, noise-free algebra anchors.
 * The Aux methods implement the paper's real one-digit q_o gadget path:
 * dense two-plane RLWE keys satisfy b+a*s=q_o*s_source+t*e, a bounded sparse
 * base-q input is centered and lifted to qq_o, and coefficientwise BGV
 * ModReduce returns to q.  The two-prime basis, sparse owner secret, and
 * bounded input are not a security authorization or a full ciphertext-matmul
 * integration.
 */
class GLIntProductionSwitchCore final {
public:
    explicit GLIntProductionSwitchCore(
        GLIntWBatchedParameters parameters =
            GLIntWBatchedParameters::GL128257N32());

    const GLIntWBatchedParameters& GetParameters() const noexcept;
    GLIntProductionSwitchCapabilities GetCapabilities() const noexcept;

    GLIntProductionSwitchKey EvalKeyGenSmallSquare(
        const GLIntProductionSecretKey& primaryKey,
        uint64_t seed = 0) const;
    GLIntProductionSwitchKey EvalKeyGenBigTranspose(
        const GLIntProductionSecretKey& primaryKey,
        uint64_t seed = 0) const;

    GLIntProductionAuxSwitchKey EvalKeyGenAuxSmallSquare(
        const GLIntProductionSecretKey& primaryKey,
        uint64_t seed = 0) const;
    GLIntProductionAuxSwitchKey EvalKeyGenAuxBigTranspose(
        const GLIntProductionSecretKey& primaryKey,
        uint64_t seed = 0) const;

    GLIntProductionRNSPolynomial ExtractA(
        const GLIntProductionCiphertext& ciphertext) const;
    GLIntProductionRNSPolynomial MakeMonomial(
        uint32_t level, uint32_t x, uint32_t y, uint32_t w,
        int64_t real, int64_t imaginary = 0) const;

    GLIntProductionSwitchResult SwitchIntSmall(
        const GLIntProductionRNSPolynomial& input,
        const GLIntProductionSwitchKey& evaluationKey) const;
    GLIntProductionSwitchResult SwitchIntBig(
        const GLIntProductionRNSPolynomial& input,
        const GLIntProductionSwitchKey& evaluationKey) const;
    GLIntProductionSwitchResult SwitchIntAuxSmall(
        const GLIntProductionRNSPolynomial& input,
        const GLIntProductionAuxSwitchKey& evaluationKey) const;
    GLIntProductionSwitchResult SwitchIntAuxBig(
        const GLIntProductionRNSPolynomial& input,
        const GLIntProductionAuxSwitchKey& evaluationKey) const;

    bool VerifyEvaluationKeyOwner(
        const GLIntProductionSwitchKey& evaluationKey,
        const GLIntProductionSecretKey& primaryKey) const;
    bool VerifySwitchResultOwner(
        const GLIntProductionRNSPolynomial& input,
        const GLIntProductionSwitchResult& result,
        const GLIntProductionSwitchKey& evaluationKey,
        const GLIntProductionSecretKey& primaryKey) const;
    bool VerifyAuxEvaluationKeyOwner(
        const GLIntProductionAuxSwitchKey& evaluationKey,
        const GLIntProductionSecretKey& primaryKey) const;
    bool VerifyAuxSwitchResultOwner(
        const GLIntProductionRNSPolynomial& input,
        const GLIntProductionSwitchResult& result,
        const GLIntProductionAuxSwitchKey& evaluationKey,
        const GLIntProductionSecretKey& primaryKey) const;

private:
    using Term = GLIntProductionSwitchKey::Term;

    void ValidatePrimaryKey(const GLIntProductionSecretKey& key,
                            const char* operation) const;
    void ValidatePolynomial(const GLIntProductionRNSPolynomial& polynomial,
                            const char* objectName) const;
    void ValidateEvaluationKey(
        const GLIntProductionSwitchKey& evaluationKey,
        GLIntProductionSwitchDirection direction,
        const char* operation) const;
    void ValidateAuxEvaluationKey(
        const GLIntProductionAuxSwitchKey& evaluationKey,
        GLIntProductionSwitchDirection direction,
        const char* operation) const;
    std::vector<Term> PrimaryTerms(
        const GLIntProductionSecretKey& key) const;
    std::vector<Term> SourceTerms(
        const GLIntProductionSecretKey& key,
        GLIntProductionSwitchDirection direction) const;
    std::vector<Term> MultiplySparse(const std::vector<Term>& lhs,
                                     const std::vector<Term>& rhs) const;
    std::vector<Term> SubtractSparse(const std::vector<Term>& lhs,
                                     const std::vector<Term>& rhs) const;
    std::vector<GLIntProductionModResidue> MultiplyDenseBySparse(
        const std::vector<GLIntProductionModResidue>& dense,
        const std::vector<Term>& sparse, uint32_t modulus) const;
    GLIntProductionSwitchResult Apply(
        const GLIntProductionRNSPolynomial& input,
        const GLIntProductionSwitchKey& evaluationKey) const;
    GLIntProductionAuxSwitchKey AuxEvalKeyGen(
        const GLIntProductionSecretKey& primaryKey,
        GLIntProductionSwitchDirection direction, uint64_t seed) const;
    GLIntProductionSwitchResult ApplyAux(
        const GLIntProductionRNSPolynomial& input,
        const GLIntProductionAuxSwitchKey& evaluationKey) const;
    std::vector<Term> SparseInputTerms(
        const GLIntProductionRNSPolynomial& input) const;

    GLIntWBatchedParameters m_parameters;
    GLIntWBatchedCodecRoots m_roots;
    std::vector<uint32_t> m_moduli;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_SCHEME_GL_INT_PRODUCTION_SWITCH_H
