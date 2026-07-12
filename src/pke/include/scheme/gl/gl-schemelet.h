//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.
//==================================================================================

#ifndef LBCRYPTO_PKE_SCHEME_GL_SCHEMELET_H
#define LBCRYPTO_PKE_SCHEME_GL_SCHEMELET_H

#include "openfhe.h"

#include <complex>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace lbcrypto {

/** Base class for validation errors raised at the GL aggregate boundary. */
class GLException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class GLDimensionError : public GLException {
public:
    using GLException::GLException;
};

class GLContextMismatchError : public GLException {
public:
    using GLException::GLException;
};

class GLKeyContextMismatchError : public GLContextMismatchError {
public:
    using GLContextMismatchError::GLContextMismatchError;
};

class GLKeyMismatchError : public GLException {
public:
    using GLException::GLException;
};

class GLMissingRowError : public GLException {
public:
    using GLException::GLException;
};

class GLCiphertextError : public GLException {
public:
    using GLException::GLException;
};

class GLNativeModeError : public GLException {
public:
    using GLException::GLException;
};

class GLDepthError : public GLException {
public:
    using GLException::GLException;
};

class GLMissingEvaluationKeyError : public GLException {
public:
    using GLException::GLException;
};

class GLReferenceCircuitError : public GLException {
public:
    using GLException::GLException;
};

/**
 * Geometry of the first W-free GL conformance slice.
 *
 * R  = Z[i][X]/(X^n-i)
 * R' = R[Y]/(Y^n-i)
 *
 * A logical plaintext is one row-major n x n complex matrix.  Only n=4 and
 * n=8 are deliberately accepted in this vertical slice.
 */
class GLGeometry final {
public:
    explicit GLGeometry(std::size_t dimension);

    std::size_t GetDimension() const noexcept;
    std::size_t GetRowCount() const noexcept;
    std::size_t GetColumnsPerRow() const noexcept;
    std::size_t GetCellCount() const noexcept;
    std::size_t GetNativeRingDimension() const noexcept;
    std::size_t GetNativeCyclotomicOrder() const noexcept;

    bool operator==(const GLGeometry& other) const noexcept;
    bool operator!=(const GLGeometry& other) const noexcept;

private:
    std::size_t m_dimension;
};

/** CKKS transport parameters used to construct the row context. */
struct GLParameters {
    std::size_t dimension{4};
    uint32_t multiplicativeDepth{1};
    uint32_t scalingModSize{40};
    uint32_t firstModSize{50};
    uint32_t ringDimension{0};
    SecurityLevel securityLevel{HEStd_128_classic};
    ScalingTechnique scalingTechnique{FLEXIBLEAUTO};

    GLGeometry GetGeometry() const;
    bool RequestsExactNativeRing() const noexcept;
    void Validate() const;
};

/** Exact-size row-major complex matrix container. */
class GLPlaintext final {
public:
    GLPlaintext(GLGeometry geometry, std::vector<std::complex<double>> values);
    GLPlaintext(std::size_t dimension, std::vector<std::complex<double>> values);

    const GLGeometry& GetGeometry() const noexcept;
    const std::vector<std::complex<double>>& GetValues() const noexcept;
    std::complex<double>& At(std::size_t row, std::size_t column);
    const std::complex<double>& At(std::size_t row, std::size_t column) const;

private:
    GLGeometry m_geometry;
    std::vector<std::complex<double>> m_values;
};

/**
 * n CKKS plaintext rows produced by the W-free GL codec.
 *
 * For zeta = exp(2*pi*i/(4n)) and zeta_k = zeta^(5^k), row y stores
 *
 *   c_y(zeta_j) = (1/n) sum_k M[j,k] zeta_k^(-y)
 *
 * across CKKS slots j.  Thus the explicit Y-axis of sigma^{-1} is implemented.
 * OpenFHE's CKKS encoder remains responsible for the X-axis interpolation,
 * scaling/rounding, and RNS representation of each row.
 */
class GLEncodedPlaintext final {
public:
    const GLGeometry& GetGeometry() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;
    const std::vector<Plaintext>& GetRows() const noexcept;
    void Validate() const;

private:
    friend class GLSchemelet;

    GLEncodedPlaintext(GLGeometry geometry, CryptoContext<DCRTPoly> context, std::vector<Plaintext> rows);

    GLGeometry m_geometry;
    CryptoContext<DCRTPoly> m_context;
    std::vector<Plaintext> m_rows;
};

/**
 * W-free GL ciphertext aggregate.
 *
 * The aggregate owns exactly n real OpenFHE ciphertexts.  Row y represents
 * the coefficient of Y^y, so the two components across all row ciphertexts
 * represent the two GL components in R'.  There is intentionally no cleartext
 * shadow in this type.
 */
class GLCiphertext final {
public:
    GLCiphertext(GLGeometry geometry, CryptoContext<DCRTPoly> context,
                 std::vector<Ciphertext<DCRTPoly>> rows);

    const GLGeometry& GetGeometry() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;
    const std::vector<Ciphertext<DCRTPoly>>& GetRows() const noexcept;
    const std::string& GetKeyTag() const;
    void Validate() const;

private:
    GLGeometry m_geometry;
    CryptoContext<DCRTPoly> m_context;
    std::vector<Ciphertext<DCRTPoly>> m_rows;
};

/**
 * The two sliced big key-switching keys required by native GL multiplication.
 *
 * The first row-key family switches the Y coefficients of conjugate(s)(Y^-1)
 * to s(X).  The second switches the Y coefficients of
 * s(X)*conjugate(s)(Y^-1) to s(X).  This object contains OpenFHE EvalKeys only;
 * it never retains a private-key element.
 *
 * This first correctness representation stores n ordinary OpenFHE switching
 * keys per family.  One big switch performs n^2 KeySwitchCore calls.  A
 * production construction needs a fused R' decomposition/key layout and must
 * assess security against OpenFHE HYBRID's full QP modulus and all 2n
 * correlated sliced keys.  The n=4/8/16 exact-ring mode is HEStd_NotSet test code,
 * not a security or performance claim.
 */
class GLNativeEvalKey final {
public:
    const GLGeometry& GetGeometry() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;
    const std::string& GetKeyTag() const noexcept;
    void Validate() const;

private:
    friend class GLSchemelet;

    GLNativeEvalKey(GLGeometry geometry, CryptoContext<DCRTPoly> context, std::string keyTag,
                    std::vector<EvalKey<DCRTPoly>> conjugateRows,
                    std::vector<EvalKey<DCRTPoly>> productRows);

    GLGeometry m_geometry;
    CryptoContext<DCRTPoly> m_context;
    std::string m_keyTag;
    std::vector<EvalKey<DCRTPoly>> m_conjugateRows;
    std::vector<EvalKey<DCRTPoly>> m_productRows;
};

/**
 * Owned per-index GL row-rotation key material.
 *
 * Maps every requested GL row-rotation amount nu (1 <= nu < n) to the
 * framework automorphism key for X -> X^{5^nu}, generated through the
 * framework's own EvalAtIndexKeyGen path but kept in this owned object rather
 * than the ambient global registry (the SHIP port's owned xForwardKeys map is
 * the precedent).  It contains destination-bound OpenFHE EvalKeys only; no
 * private-key element is retained.
 */
class GLRotationEvalKey final {
public:
    const GLGeometry& GetGeometry() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;
    const std::string& GetKeyTag() const noexcept;
    const std::set<uint32_t>& GetRotationAmounts() const noexcept;
    void Validate() const;

private:
    friend class GLSchemelet;

    GLRotationEvalKey(GLGeometry geometry, CryptoContext<DCRTPoly> context, std::string keyTag,
                      std::set<uint32_t> rotationAmounts,
                      std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> automorphismKeys);

    GLGeometry m_geometry;
    CryptoContext<DCRTPoly> m_context;
    std::string m_keyTag;
    std::set<uint32_t> m_rotationAmounts;
    std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> m_automorphismKeys;
};

/**
 * Owned GL conjugation key material.
 *
 * Holds the framework conjugation automorphism key (automorphism index
 * cyclotomicOrder-1, a Switch_small-class key switch), generated through the
 * framework keygen path but owned here instead of the ambient registry.  It
 * contains a destination-bound OpenFHE EvalKey only; no private-key element
 * is retained.
 */
class GLConjugationEvalKey final {
public:
    const GLGeometry& GetGeometry() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;
    const std::string& GetKeyTag() const noexcept;
    void Validate() const;

private:
    friend class GLSchemelet;

    GLConjugationEvalKey(GLGeometry geometry, CryptoContext<DCRTPoly> context, std::string keyTag,
                         std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> conjugationKeys);

    GLGeometry m_geometry;
    CryptoContext<DCRTPoly> m_context;
    std::string m_keyTag;
    std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> m_conjugationKeys;
};

/**
 * The third GL sliced big key-switching family, K_transpose = ksk_{s(Y)->s(X)}.
 *
 * Row y encrypts the switch of the CONSTANT source polynomial s_y (the y-th
 * Gaussian coefficient of the primary secret) to s(X), mirroring the two
 * matmul families stored in GLNativeEvalKey.  One native transpose performs
 * one BigSwitch (n^2 KeySwitchCore calls in this correctness representation).
 * This object contains OpenFHE EvalKeys only; it never retains a private-key
 * element.  Exact-ring (ringDimension=2n) HEStd_NotSet test material, not a
 * security or performance claim.
 */
class GLTransposeEvalKey final {
public:
    const GLGeometry& GetGeometry() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;
    const std::string& GetKeyTag() const noexcept;
    void Validate() const;

private:
    friend class GLSchemelet;

    GLTransposeEvalKey(GLGeometry geometry, CryptoContext<DCRTPoly> context, std::string keyTag,
                       std::vector<EvalKey<DCRTPoly>> transposeRows);

    GLGeometry m_geometry;
    CryptoContext<DCRTPoly> m_context;
    std::string m_keyTag;
    std::vector<EvalKey<DCRTPoly>> m_transposeRows;
};

/**
 * First honest OpenFHE vertical slice for W-free GL encoding and transport.
 *
 * The GL Y-axis sigma/sigma^{-1} pair is explicit.  CKKS packing is used
 * independently for each Y-coefficient row and delegates the X-axis canonical
 * embedding (including slot-generator ordering), scale rounding, and RNS/NTT
 * storage to OpenFHE; this slice does not assert bit-level polynomial-
 * coefficient parity with an independent GL X-axis codec.  With
 * ringDimension=2n the OpenFHE cyclotomic order is exactly 4n, matching
 * R ~= Z[X]/Phi_{4n}; for n=4/8/16 this mode is intentionally restricted to
 * HEStd_NotSet and is not a security claim. The n=16 conformance point is
 * exact-ring only; n=4/8 may also use a larger transport ring, which is not a
 * native-R equivalence.
 *
 * The distinctly named Native operations implement the W-free GL trace on
 * DCRT coefficient pairs and use genuine OpenFHE key switching; they are
 * restricted to exact ringDimension=2n.  EvalMatMulPlain and
 * EvalMatMulReference remain transport/reference oracles that reconstruct
 * logical columns with packed operations.  No method in this slice implements
 * or claims SHIP bootstrapping.
 */
class GLSchemelet final {
public:
    explicit GLSchemelet(GLParameters parameters);

    const GLParameters& GetParameters() const noexcept;
    const GLGeometry& GetGeometry() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;
    bool UsesExactNativeRing() const noexcept;

    KeyPair<DCRTPoly> KeyGen() const;

    GLEncodedPlaintext Encode(const GLPlaintext& plaintext) const;
    GLPlaintext Decode(const GLEncodedPlaintext& plaintext) const;

    GLCiphertext Encrypt(const PublicKey<DCRTPoly>& publicKey, const GLEncodedPlaintext& plaintext) const;
    GLCiphertext Encrypt(const PrivateKey<DCRTPoly>& privateKey, const GLEncodedPlaintext& plaintext) const;
    GLPlaintext Decrypt(const PrivateKey<DCRTPoly>& privateKey, const GLCiphertext& ciphertext) const;

    GLCiphertext Add(const GLCiphertext& lhs, const GLCiphertext& rhs) const;

    /** Rowwise framework negation; decodes to -U.  Transport and exact modes. */
    GLCiphertext Negate(const GLCiphertext& ciphertext) const;

    /** Rowwise framework subtraction; decodes to U-V.  Transport and exact modes. */
    GLCiphertext Sub(const GLCiphertext& lhs, const GLCiphertext& rhs) const;

    /**
     * Sigma-transpose (Remark 3.13) encode: Encode_T(M) = Encode(M^T).
     *
     * Under this encoding convention the plaintext-right circledast computes
     * the LEFT product V^* U instead of U V^*; decode with DecodeTransposed.
     * Valid in transport and exact modes (a pure encoding convention).
     */
    GLEncodedPlaintext EncodeTransposed(const GLPlaintext& plaintext) const;

    /** Sigma-transpose (Remark 3.13) decode: the transpose of Decode. */
    GLPlaintext DecodeTransposed(const GLEncodedPlaintext& plaintext) const;

    /**
     * Generate the GL Hadamard relinearization key (the framework's ordinary
     * s^2 EvalMult key = the paper's Switch_small for the Hadamard product).
     *
     * This deliberately calls the framework's own EvalMultKeyGen: OpenFHE
     * relinearization keys are registry-based via the key tag, and the GL
     * Hadamard product uses exactly that framework Switch_small, so the
     * ambient registry is the honest home for it (unlike the owned GL-specific
     * sliced families).  EvalHadamard revalidates the registry entry and fails
     * closed with GLMissingEvaluationKeyError when it is absent.
     */
    void EvalHadamardKeyGen(const PrivateKey<DCRTPoly>& privateKey) const;

    /**
     * GL Hadamard (entrywise) product; decodes to U o V and consumes 1 level.
     *
     * Y-convolution row form: out_r = sum_{y1+y2=r} row_{y1}*row_{y2}
     * + i * sum_{y1+y2=r+n} row_{y1}*row_{y2}.  Every row-pair product is one
     * framework ct x ct multiplication relinearized with the framework s^2
     * key; the Y^n=i wrap group is folded in with the exact unit-i monomial
     * X^{ringDim/2}; the degree-2 sums receive exactly one rescale.
     *
     * Despite operating on GL row content, this construction is
     * representation-valid in transport rings too (hence no Native suffix):
     * rows interact only through same-slot framework products and exact
     * unit-i monomial multiplies, and X^{ringDim/2} scales every canonical
     * CKKS slot by exactly +i in any power-of-two CKKS ring because each slot
     * root is zeta^{5^j} with 5^j = 1 (mod 4).  Only FIXEDAUTO and
     * FLEXIBLEAUTO are supported; operands must be rescaled (scale degree 1)
     * aggregates at one shared level/scale.
     */
    GLCiphertext EvalHadamard(const GLCiphertext& lhs, const GLCiphertext& rhs) const;

    /**
     * Generate owned framework rotation keys for the requested GL row
     * rotations (each amount in [1, n-1]).  No ambient registry is touched.
     */
    GLRotationEvalKey EvalRowRotateKeyGen(const PrivateKey<DCRTPoly>& privateKey,
                                          const std::vector<uint32_t>& rotationAmounts) const;

    /**
     * GL row rotation by nu (X -> X^{5^nu}): per-row framework slot rotation
     * by +nu with the owned key material.  0 levels; scale unchanged; decodes
     * to (j,k) -> U[(j+nu) mod n, k].  Transport and exact modes.  A missing
     * per-index key fails closed with GLMissingEvaluationKeyError; nu=0
     * returns a validated copy without key material.
     */
    GLCiphertext EvalRowRotate(const GLCiphertext& ciphertext, uint32_t nu,
                               const GLRotationEvalKey& evaluationKey) const;

    /**
     * GL column rotation by nu (Y -> Y^{5^nu}): keyless row permutation plus
     * exact unit factors.  For every input row y with 5^nu * y = q*n + r the
     * output row r is i^{q mod 4} times row y (unit-i monomial per factor of
     * i, an exact negation where i^2 appears).  No key material, no key
     * switch, 0 levels; decodes to (j,k) -> U[j, (k+nu) mod n].  Transport
     * and exact modes.
     */
    GLCiphertext EvalColumnRotate(const GLCiphertext& ciphertext, uint32_t nu) const;

    /**
     * Generate the owned framework conjugation key (automorphism index
     * cyclotomicOrder-1, Switch_small class).  No ambient registry is touched.
     */
    GLConjugationEvalKey EvalConjugateKeyGen(const PrivateKey<DCRTPoly>& privateKey) const;

    /**
     * GL conjugation; decodes to entrywise conj(U).  Per-row framework
     * conjugation followed by the Y^{-1} row relabeling: output row 0 is
     * conj(row 0) and output row n-y is (-i) * conj(row y) for y=1..n-1
     * (one exact unit-i monomial multiply then an exact negation).  0 levels;
     * scale unchanged.  Transport and exact modes (the conjugation
     * automorphism exists in any power-of-two CKKS ring).
     */
    GLCiphertext EvalConjugate(const GLCiphertext& ciphertext,
                               const GLConjugationEvalKey& evaluationKey) const;

    /**
     * Generate the third GL sliced big key family K_transpose =
     * ksk_{s(Y)->s(X)} whose per-Y-coefficient source secrets are the
     * constant polynomials s_y (the y-th Gaussian coefficient of the primary
     * secret).  Exact-ring only.
     */
    GLTransposeEvalKey EvalTransposeNativeKeyGen(const PrivateKey<DCRTPoly>& privateKey) const;

    /**
     * Native GL transpose; decodes to U^T.  Step 1 is the pure public
     * coefficient relabeling b'(X,Y)=b(Y,X), a'(X,Y)=a(Y,X) (Gaussian
     * coefficient x of new row y' = Gaussian coefficient y' of old row x;
     * both T-lanes move together and no wrap units appear).  Step 2 is one
     * BigSwitch with K_transpose, switching the relation from s(Y) back to
     * s(X).  0 rescales; level and scale unchanged.  Exact-ring only
     * (GLNativeModeError otherwise).
     */
    GLCiphertext EvalTransposeNative(const GLCiphertext& ciphertext,
                                     const GLTransposeEvalKey& evaluationKey) const;

    /**
     * Genuine W-free GL plaintext-right circledast in the native coefficient
     * representation.
     *
     * For logical matrices A and B this returns an encryption of the product
     * of A with the conjugate transpose of B, divided by n.
     * The implementation performs the GL trace directly on DCRT coefficient
     * pairs (degrees x and x+n are one Gaussian coefficient), then performs
     * one CKKS rescale.  It is available only when ringDimension=2n; it does
     * not reconstruct slots or invoke a generic packed matrix circuit.
     */
    GLCiphertext EvalCircledastPlainNative(const GLCiphertext& lhs, const GLPlaintext& rhs) const;

    /**
     * Genuine W-free GL encrypted-left/clear-right ordinary matrix product.
     *
     * This evaluates n * (A circledast B^*) so the decoded result is A*B.
     * The exact public factor n changes the represented value, not its CKKS
     * scale metadata, and the result consumes one level.
     */
    GLCiphertext EvalMatMulPlainNative(const GLCiphertext& lhs, const GLPlaintext& rhs) const;

    /** Generate the two genuine GL big relinearization key families. */
    GLNativeEvalKey EvalMatMulNativeKeyGen(const PrivateKey<DCRTPoly>& privateKey) const;

    /** Native encrypted conjugate transpose, using the first GL big key. */
    GLCiphertext EvalAdjointNative(const GLCiphertext& ciphertext,
                                   const GLNativeEvalKey& evaluationKey) const;

    /** Genuine native encrypted circledast; decodes to A times B-adjoint over n. */
    GLCiphertext EvalCircledastNative(const GLCiphertext& lhs, const GLCiphertext& rhs,
                                     const GLNativeEvalKey& evaluationKey) const;

    /** Genuine native encrypted ordinary matrix product A*B. */
    GLCiphertext EvalMatMulNative(const GLCiphertext& lhs, const GLCiphertext& rhs,
                                 const GLNativeEvalKey& evaluationKey) const;

    /**
     * Ordinary encrypted-left/clear-right matrix-product oracle.
     *
     * This evaluates every encrypted Y-coefficient row at every canonical Y
     * root, applies a clear right-matrix linear combination, then applies the
     * explicit Y-axis sigma^{-1}.  It needs no evaluation key, requires
     * multiplicativeDepth >= 3, and finishes at CKKS level 2 with the final
     * scalar product intentionally left at scale degree two (hence the extra
     * configured modulus).  Only FIXEDAUTO and FLEXIBLEAUTO are supported by
     * this bounded reference circuit.
     */
    GLCiphertext EvalMatMulPlain(const GLCiphertext& lhs, const GLPlaintext& rhs) const;

    /** Generate the relinearization and slot-sum keys for EvalMatMulReference. */
    void EvalMatMulReferenceKeyGen(const PrivateKey<DCRTPoly>& privateKey) const;

    /**
     * Ordinary encrypted/encrypted matrix-product reference circuit.
     *
     * The circuit reconstructs encrypted columns, extracts each right-hand
     * entry with a one-hot CKKS mask, broadcasts it with native EvalSum,
     * multiplies/relinearizes, and applies the explicit Y-axis sigma^{-1}.
     * It requires multiplicativeDepth >= 4, finishes at CKKS level 3 with the
     * final scalar product at scale degree two (hence the extra configured
     * modulus), and requires keys generated by EvalMatMulReferenceKeyGen.  Only
     * FIXEDAUTO and FLEXIBLEAUTO are supported.
     */
    GLCiphertext EvalMatMulReference(const GLCiphertext& lhs, const GLCiphertext& rhs) const;

private:
    void ValidateOwnedContext(const CryptoContext<DCRTPoly>& context, const char* objectName) const;
    void ValidateKeyContext(const PublicKey<DCRTPoly>& key, const char* operation) const;
    void ValidateKeyContext(const PrivateKey<DCRTPoly>& key, const char* operation) const;
    void ValidateMatMulCiphertext(const GLCiphertext& ciphertext, const char* objectName) const;
    void ValidateReferenceCircuit(uint32_t minimumDepth, const char* operation) const;
    void ValidateReferenceEvaluationKeys(const std::string& keyTag) const;
    void ValidateNativeTrace(const GLCiphertext& ciphertext, const char* operation) const;
    void ValidateNativeEvaluationKey(const GLNativeEvalKey& evaluationKey,
                                     const std::string& keyTag, const char* operation) const;
    void ValidateHadamardCircuit(const GLCiphertext& lhs, const GLCiphertext& rhs,
                                 const char* operation) const;
    void ValidateHadamardEvaluationKey(const std::string& keyTag, const char* operation) const;
    void ValidateRotationEvaluationKey(const GLRotationEvalKey& evaluationKey,
                                       const std::string& keyTag, const char* operation) const;
    void ValidateConjugationEvaluationKey(const GLConjugationEvalKey& evaluationKey,
                                          const std::string& keyTag, const char* operation) const;
    void ValidateTransposeEvaluationKey(const GLTransposeEvalKey& evaluationKey,
                                        const std::string& keyTag, const char* operation) const;

    GLParameters m_parameters;
    GLGeometry m_geometry;
    CryptoContext<DCRTPoly> m_context;
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_SCHEME_GL_SCHEMELET_H
