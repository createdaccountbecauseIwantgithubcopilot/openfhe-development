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
    bool switchIntSmall{true};
    bool switchIntBig{true};
    bool gadgetDecomposition{false};
    bool noisyEvaluationKey{false};
    bool securityAuthorized{false};
    bool ciphertextMatMul{false};
};

/**
 * Exact bounded SwitchInt algebra for the production quotient ring.
 *
 * SmallSquare keys switch s(X,W)^2 to s(X,W).  BigTranspose keys switch
 * s(Y,W) to s(X,W).  Apply multiplies a complete dense R'_q input by the two
 * sparse evaluation-key components, including both X/Y I-wraps and exact
 * Phi_257(W) fan-out.  Owner verification recomputes the source relation from
 * the supplied primary secret without exposing that secret.
 *
 * This is the real key-switch equation but not yet the production gadget/RNS
 * construction: keys contain no t*e noise or gadget digits, so security and
 * ciphertext-matmul capabilities remain false.
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

    bool VerifyEvaluationKeyOwner(
        const GLIntProductionSwitchKey& evaluationKey,
        const GLIntProductionSecretKey& primaryKey) const;
    bool VerifySwitchResultOwner(
        const GLIntProductionRNSPolynomial& input,
        const GLIntProductionSwitchResult& result,
        const GLIntProductionSwitchKey& evaluationKey,
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

    GLIntWBatchedParameters m_parameters;
    GLIntWBatchedCodecRoots m_roots;
    std::vector<uint32_t> m_moduli;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_SCHEME_GL_INT_PRODUCTION_SWITCH_H
