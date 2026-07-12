//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#ifndef LBCRYPTO_PKE_SCHEME_GL_SHIP_H
#define LBCRYPTO_PKE_SCHEME_GL_SHIP_H

#include "scheme/gl/gl-schemelet.h"

#include <complex>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

class GLShipError : public GLException {
public:
    using GLException::GLException;
};

class GLShipParameterError : public GLShipError {
public:
    using GLShipError::GLShipError;
};

class GLShipStateError : public GLShipError {
public:
    using GLShipError::GLShipError;
};

class GLShipEvaluationKeyError : public GLShipError {
public:
    using GLShipError::GLShipError;
};

class GLShipUnsupportedError : public GLShipError {
public:
    using GLShipError::GLShipError;
};

enum class GLShipSelection {
    DIRECT_COLUMN,
    HYBRID_MASKED_COLUMN,
};

enum class GLShipRepresentation {
    POST_XINV_COEFFICIENT,
    X_COEFFICIENT_SLOTS,
};

/**
 * Public, non-wrapping coarse candidate window in block units for the hybrid
 * masked-column selection.  A window restricts the encrypted coarse bank of
 * one support ordinal to blockCount candidate blocks starting at blockBegin.
 * Windows are a correctness surface only; no spacing-assumption security
 * claim is made.
 */
struct GLShipCoarseWindow {
    uint32_t blockBegin{0};
    uint32_t blockCount{0};
};

struct GLShipParameters {
    std::size_t dimension{4};
    double gamma{64.0};
    std::size_t hammingWeight{2};
    uint32_t reservedLevels{1};
    GLShipSelection selection{GLShipSelection::DIRECT_COLUMN};
    // Hybrid masked-column selection only: theta, a power of two in [2, n]
    // dividing n.  Must stay zero for direct-column selection.
    std::size_t coarseBlockSize{0};
    // Hybrid only: optional public per-ordinal coarse windows (empty = the
    // full [0, n/theta) candidate range for every support ordinal).
    std::vector<GLShipCoarseWindow> coarseWindows{};

    uint32_t RequiredMultiplicativeDepth() const;
    void Validate(const GLGeometry& geometry, const GLParameters& glParameters) const;
};

struct GLShipMonomial {
    uint32_t alpha{0};
    int8_t sign{1};
};

using GLShipGaussianInteger = std::complex<int64_t>;

/** Exact, clear algebra helpers used by both key generation/evaluation and pinned oracles. */
class GLShipAlgebra final {
public:
    static std::vector<GLShipGaussianInteger> MultiplyMonomial(
        const std::vector<GLShipGaussianInteger>& input, uint32_t alpha, int8_t sign);

    /**
     * Exact coefficientwise multiplication by +i: (re, im) -> (-im, re).
     * The evaluator derives the hybrid v-lane tables omega^{Re (i G)[k]} from
     * it, and the clear hybrid conformance tests pin the per-digit lane
     * invariant with it.
     */
    static std::vector<GLShipGaussianInteger> MultiplyGaussianI(
        const std::vector<GLShipGaussianInteger>& input);

    static std::vector<GLShipGaussianInteger> DecryptionRelation(
        const std::vector<GLShipGaussianInteger>& b,
        const std::vector<GLShipGaussianInteger>& a,
        const std::vector<GLShipMonomial>& support);

    static std::vector<std::complex<double>> RootVector(
        uint64_t q0, const std::vector<int64_t>& exponents);

    /**
     * Load-bearing SHIP base-node constant.  After multiplying by
     * exp(2*pi*i*Z/q0), conjugation-add yields
     * gamma/(2*pi)*sin(2*pi*Z/q0).  Keeping this as a tested algebra helper
     * prevents broad refresh tolerances from hiding a systematic output-leg
     * scale or sign drift.
     */
    static std::complex<double> BaseNodeScale(double gamma);
};

class GLShipSchemelet;
class GLShipTestAccess;

/**
 * Evaluator-visible material for the direct-column and hybrid masked-column
 * toy half-bootstraps.
 *
 * The flat selector bank contains fresh primary-key encryptions of joint
 * support/sign indicator bits.  For direct-column keys it is the 2*h*n joint
 * bank; for hybrid keys it is the coarse (block, sign) bank over the public
 * per-ordinal windows, and the fine bank additionally holds the three
 * mask-fused encrypted digit pieces PH/PL/NG per binary digit of each
 * alpha0_t.  It stores no private key, clear support, clear sign, clear digit
 * bit, logical input, or decrypted shadow; bank shapes depend only on the
 * public (n, theta, h, windows).
 */
class GLShipEvaluationKey final {
public:
    const GLShipParameters& GetParameters() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;
    const std::string& GetSparseKeyTag() const noexcept;
    const std::string& GetPrimaryKeyTag() const noexcept;
    uint64_t GetBottomModulus() const noexcept;
    std::size_t GetSelectorCount() const noexcept;
    std::size_t GetFineSelectorCount() const noexcept;

private:
    friend class GLShipSchemelet;
    friend class GLShipTestAccess;

    GLShipEvaluationKey(GLShipParameters parameters, CryptoContext<DCRTPoly> context,
                        std::string sparseKeyTag, std::string primaryKeyTag, uint64_t q0,
                        EvalKey<DCRTPoly> bottomPrimaryToSparseKey,
                        std::vector<Ciphertext<DCRTPoly>> selectors,
                        std::vector<Ciphertext<DCRTPoly>> fineSelectors,
                        std::vector<EvalKey<DCRTPoly>> relinearizationKeys,
                        std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> conjugationKeys,
                        std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> xForwardKeys);

    GLShipParameters m_parameters;
    CryptoContext<DCRTPoly> m_context;
    std::string m_sparseKeyTag;
    std::string m_primaryKeyTag;
    uint64_t m_q0;
    EvalKey<DCRTPoly> m_bottomPrimaryToSparseKey;
    std::vector<Ciphertext<DCRTPoly>> m_selectors;
    std::vector<Ciphertext<DCRTPoly>> m_fineSelectors;
    std::vector<EvalKey<DCRTPoly>> m_relinearizationKeys;
    std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> m_conjugationKeys;
    std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> m_xForwardKeys;
};

/** Client-only material.  The sparse secret never crosses into evaluator APIs. */
class GLShipClientMaterial final {
public:
    GLShipClientMaterial(const GLShipClientMaterial&) = delete;
    GLShipClientMaterial& operator=(const GLShipClientMaterial&) = delete;
    GLShipClientMaterial(GLShipClientMaterial&&) noexcept = default;
    GLShipClientMaterial& operator=(GLShipClientMaterial&&) noexcept = default;

    const GLShipEvaluationKey& GetEvaluationKey() const noexcept;

private:
    friend class GLShipSchemelet;
    friend class GLShipTestAccess;

    GLShipClientMaterial(PrivateKey<DCRTPoly> sparseSecretKey,
                         GLShipEvaluationKey evaluationKey);

    PrivateKey<DCRTPoly> m_sparseSecretKey;
    GLShipEvaluationKey m_evaluationKey;
};

/** One randomized, one-tower, post-XInv ciphertext under the sparse key. */
class GLShipLowSliceCiphertext final {
public:
    GLShipRepresentation GetRepresentation() const noexcept;
    std::size_t GetDimension() const noexcept;
    uint64_t GetBottomModulus() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;
    const Ciphertext<DCRTPoly>& GetNativeCiphertext() const noexcept;
    const std::string& GetKeyTag() const;

private:
    friend class GLShipSchemelet;
    friend class GLShipTestAccess;

    GLShipLowSliceCiphertext(std::size_t dimension, uint64_t q0,
                             CryptoContext<DCRTPoly> context,
                             Ciphertext<DCRTPoly> ciphertext);

    std::size_t m_dimension;
    uint64_t m_q0;
    CryptoContext<DCRTPoly> m_context;
    Ciphertext<DCRTPoly> m_ciphertext;
    GLShipRepresentation m_representation;
};

/** High-modulus primary-key result whose slots contain refreshed X coefficients. */
class GLShipHalfBootstrapResult final {
public:
    GLShipRepresentation GetRepresentation() const noexcept;
    std::size_t GetDimension() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;
    const Ciphertext<DCRTPoly>& GetNativeCiphertext() const noexcept;
    const std::string& GetKeyTag() const;

private:
    friend class GLShipSchemelet;

    GLShipHalfBootstrapResult(std::size_t dimension, CryptoContext<DCRTPoly> context,
                              Ciphertext<DCRTPoly> ciphertext);

    std::size_t m_dimension;
    CryptoContext<DCRTPoly> m_context;
    Ciphertext<DCRTPoly> m_ciphertext;
    GLShipRepresentation m_representation;
};

/**
 * Bounded, exact-ring direct-column SHIP implementation for n=4/8/16/32/64/128
 * conformance only. Hybrid masked-column material remains n=4/8 because its
 * distinct depth and selector-material contract has not been extended.
 *
 * The evaluator derives all root tables from the actual public A/B components
 * of the randomized low-level ciphertext.  It never decrypts and never creates
 * a transparent a=0 output.  RefreshOnly additionally normalizes every native
 * GL row to q0/gamma, uses OpenFHE's q0*P-only sparse encapsulation switch,
 * evaluates the half-bootstrap on all Y rows, and applies an explicit encrypted
 * X-forward transform before constructing a canonical GLCiphertext.
 */
class GLShipSchemelet final {
public:
    GLShipSchemelet(const GLSchemelet& glSchemelet, GLShipParameters parameters);

    const GLShipParameters& GetParameters() const noexcept;
    const GLGeometry& GetGeometry() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;

    GLShipClientMaterial KeyGen(const KeyPair<DCRTPoly>& primaryKeyPair,
                                const std::vector<GLShipMonomial>& support) const;

    GLShipLowSliceCiphertext EncryptLowSlice(
        const GLShipClientMaterial& clientMaterial,
        const std::vector<std::complex<double>>& coefficients) const;

    GLShipHalfBootstrapResult EvalHalfBootstrap(
        const GLShipLowSliceCiphertext& input,
        const GLShipEvaluationKey& evaluationKey) const;

    /**
     * Exact-ring direct-column n=4/8/16/32/64/128 ordinary refresh. Hybrid remains n=4/8.
     *
     * Every independently computed Gaussian X-coefficient lane must have real
     * and imaginary magnitude at most one.  This is an encrypted-message
     * contract and cannot be observed or enforced by the evaluator; all public
     * dimensions, levels, scales, key tags, and evaluation-key shapes are
     * validated fail-closed.
     */
    GLCiphertext RefreshOnly(const GLCiphertext& input,
                             const GLShipEvaluationKey& evaluationKey) const;

private:
    friend class GLShipTestAccess;

    std::size_t SelectorIndex(std::size_t supportOrdinal, std::size_t alpha,
                              int8_t sign) const;
    std::size_t CoarseSelectorIndex(std::size_t supportOrdinal, std::size_t blockOffset,
                                    int8_t sign) const;
    std::size_t FineSelectorIndex(std::size_t supportOrdinal, uint32_t digit,
                                  std::size_t piece) const;
    Ciphertext<DCRTPoly> EvalHybridLeaf(const std::vector<GLShipGaussianInteger>& branchA,
                                        std::size_t supportOrdinal,
                                        const GLShipEvaluationKey& evaluationKey) const;
    void ValidatePrimaryKeyPair(const KeyPair<DCRTPoly>& primaryKeyPair) const;
    void ValidateEvaluationKey(const GLShipEvaluationKey& evaluationKey) const;
    void ValidateLowSlice(const GLShipLowSliceCiphertext& input,
                          const GLShipEvaluationKey& evaluationKey) const;
    GLShipHalfBootstrapResult EvalHalfBootstrapValidated(
        const GLShipLowSliceCiphertext& input,
        const GLShipEvaluationKey& evaluationKey) const;
    GLShipLowSliceCiphertext NormalizeAndSwitchRow(
        const Ciphertext<DCRTPoly>& input, const GLShipEvaluationKey& evaluationKey,
        std::size_t row) const;
    std::vector<Plaintext> MakeXForwardDiagonals(uint32_t level) const;
    Ciphertext<DCRTPoly> EvalXForward(
        const GLShipHalfBootstrapResult& input,
        const GLShipEvaluationKey& evaluationKey,
        const std::vector<Plaintext>& diagonals) const;

    GLShipParameters m_parameters;
    GLGeometry m_geometry;
    GLParameters m_glParameters;
    CryptoContext<DCRTPoly> m_context;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_SCHEME_GL_SHIP_H
