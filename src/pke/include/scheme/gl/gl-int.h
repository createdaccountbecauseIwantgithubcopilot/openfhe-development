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

#ifndef LBCRYPTO_PKE_SCHEME_GL_INT_H
#define LBCRYPTO_PKE_SCHEME_GL_INT_H

#include "scheme/gl/gl-schemelet.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace lbcrypto {

/** Validation errors specific to the integer (BGV-like) GL mode parameters/codec. */
class GLIntParameterError : public GLException {
public:
    using GLException::GLException;
};

/**
 * Parameters of the W-free integer (BGV-like) GL mode.
 *
 * The row framework is OpenFHE BGV at a prime plaintext modulus t with
 * t = 1 (mod 4n).  The ring dimension is always the exact native 2n
 * (cyclotomic order 4n) and the security level is always HEStd_NotSet:
 * the integer mode is exact-ring-only in this slice, there is no transport
 * ring construction path, and the n=4/8 toy dimensions are conformance
 * geometry, not a security claim.  The scaling technique is pinned to
 * FIXEDMANUAL so every BGV modulus satisfies q_i = 1 (mod t) and ModReduce
 * is plaintext-invariant; neither is exposed as a knob.
 */
struct GLIntParameters {
    std::size_t dimension{4};          // 4 or 8 only (GLGeometry gate; 4096 throws)
    uint64_t plaintextModulus{257};    // prime, = 1 (mod 4n); conformance pins 257
    uint32_t multiplicativeDepth{2};

    GLGeometry GetGeometry() const;
    void Validate() const;
};

/**
 * One integer GL plaintext: the pair (M+, M-) of n x n matrices over Z_t
 * (GL_scheme.md Eq. 5 with phi(1) = 1).  Values are canonicalized into
 * [0, t) at construction; every equality on this type is exact mod t.
 */
class GLIntPlaintext final {
public:
    GLIntPlaintext(GLGeometry geometry, uint64_t plaintextModulus, std::vector<int64_t> plusValues,
                   std::vector<int64_t> minusValues);

    const GLGeometry& GetGeometry() const noexcept;
    uint64_t GetModulus() const noexcept;
    int64_t AtPlus(std::size_t row, std::size_t column) const;
    int64_t AtMinus(std::size_t row, std::size_t column) const;
    const std::vector<int64_t>& GetPlusValues() const noexcept;
    const std::vector<int64_t>& GetMinusValues() const noexcept;

private:
    GLGeometry m_geometry;
    uint64_t m_modulus;
    std::vector<int64_t> m_plusValues;
    std::vector<int64_t> m_minusValues;
};

/**
 * n BGV packed plaintext rows produced by the integer GL codec sigma_int.
 *
 * With zeta the minimum primitive 4n-th root of unity mod t (the OpenFHE
 * RootOfUnity/PackedEncoding rule) and zeta_k = zeta^(5^k), row y stores
 *
 *   slot j     = n^{-1} sum_k M+[j,k] zeta_k^{-y}   (mod t)
 *   slot n + j = n^{-1} sum_k M-[j,k] zeta_k^{+y}   (mod t)
 *
 * so the + branch rides the first slot half and the - branch the second.
 * OpenFHE's PackedEncoding remains responsible for the X-axis (negacyclic
 * FTT) packing of each row at the same pinned root.
 */
class GLIntEncodedPlaintext final {
public:
    const GLGeometry& GetGeometry() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;
    const std::vector<Plaintext>& GetRows() const noexcept;
    void Validate() const;

private:
    friend class GLIntSchemelet;

    GLIntEncodedPlaintext(GLGeometry geometry, CryptoContext<DCRTPoly> context, std::vector<Plaintext> rows);

    GLGeometry m_geometry;
    CryptoContext<DCRTPoly> m_context;
    std::vector<Plaintext> m_rows;
};

/**
 * Integer-mode W-free GL ciphertext aggregate: exactly n real OpenFHE BGV
 * ciphertexts, row y = coefficient of Y^y.  There is intentionally no
 * cleartext shadow in this type.
 */
class GLIntCiphertext final {
public:
    GLIntCiphertext(GLGeometry geometry, CryptoContext<DCRTPoly> context,
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
 * The owned integer-mode GL evaluation-key bundle.
 *
 * Three sliced big key-switching families, n ordinary OpenFHE switch keys
 * each (one big switch performs n^2 KeySwitchCore calls; the fused
 * production layout is out of scope exactly as in the complex port):
 *
 *   K1 conjugateRows: ksk_{s(-I,Y^{-1}) -> s}, per-Y-coefficient sources are
 *      the Gaussian coefficients of the T -> T^{-1} image of the secret;
 *   K2 productRows:   ksk_{s * s(-I,Y^{-1}) -> s};
 *   K3 transposeRows: ksk_{s(Y) -> s(X)}, per-Y-coefficient sources are the
 *      constant Gaussian coefficients s_y of the primary secret itself;
 *
 * plus the owned automorphism-key map for {5^nu mod 4n : nu = 1..n-1} and
 * the T -> T^{-1} index 4n-1 (row rotations and the conjugation swap).
 * The Hadamard s^2 relinearization key deliberately lives in the framework's
 * ambient EvalMultKeyGen registry instead (see EvalIntKeyGen).  This object
 * contains destination-bound OpenFHE EvalKeys only; it never retains a
 * private-key element.  HEStd_NotSet toy material, not a security claim.
 */
class GLIntEvalKey final {
public:
    const GLGeometry& GetGeometry() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;
    const std::string& GetKeyTag() const noexcept;
    void Validate() const;

private:
    friend class GLIntSchemelet;

    GLIntEvalKey(GLGeometry geometry, CryptoContext<DCRTPoly> context, std::string keyTag,
                 std::vector<EvalKey<DCRTPoly>> conjugateRows,
                 std::vector<EvalKey<DCRTPoly>> productRows,
                 std::vector<EvalKey<DCRTPoly>> transposeRows,
                 std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> automorphismKeys);

    GLGeometry m_geometry;
    CryptoContext<DCRTPoly> m_context;
    std::string m_keyTag;
    std::vector<EvalKey<DCRTPoly>> m_conjugateRows;   // K1
    std::vector<EvalKey<DCRTPoly>> m_productRows;     // K2
    std::vector<EvalKey<DCRTPoly>> m_transposeRows;   // K3
    std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> m_automorphismKeys;
};

/**
 * Integer (BGV-like) GL mode of GL_scheme.md section 4, W-free profile,
 * as an OpenFHE-only sibling of the CKKS GLSchemelet.
 *
 * A logical plaintext is the matrix pair (M+, M-) over Z_t; every operation
 * and every conformance gate is exact mod t (no scale, no Delta, no
 * tolerance anywhere).  The Y-transform root is pinned equal to OpenFHE's
 * deterministic packing root (the minimum primitive 4n-th root of unity
 * mod t) because the native transpose/adjoint substitute X and Y and hence
 * force one shared root family; the constructor re-verifies the packing
 * against this pinned codec and fails closed on any mismatch.
 *
 * The trace primitive EvalCircledastInt decodes to
 * n^{-1} (U+ V-^T, U- V+^T) with n^{-1} taken mod t (the factor lives in
 * the represented value, exactly as in Theorem 4.1); EvalMatMulInt feeds
 * the adjoint-analog of the right operand and multiplies by the exact
 * public integer n, decoding to the pair of ordinary per-branch products
 * (U+ V+, U- V-).  BGV ModReduce is the spec's ModSwitch; every
 * multiplication-class operation consumes exactly one level.  No method in
 * this slice implements or claims SHIP bootstrapping.
 */
class GLIntSchemelet final {
public:
    explicit GLIntSchemelet(GLIntParameters parameters);

    const GLIntParameters& GetParameters() const noexcept;
    const GLGeometry& GetGeometry() const noexcept;
    const CryptoContext<DCRTPoly>& GetCryptoContext() const noexcept;
    uint64_t GetPlaintextModulus() const noexcept;
    /** Pinned packing/Y-transform root (2 at n=4, 15 at n=8 for t=257). */
    uint64_t GetZeta() const noexcept;
    /** Gaussian unit I = zeta^n (16 for t=257 at both toy dims). */
    uint64_t GetGaussianUnit() const noexcept;
    bool UsesExactNativeRing() const noexcept;

    KeyPair<DCRTPoly> KeyGen() const;

    /**
     * Generate the complete owned integer-mode key bundle (K1 + K2 + K3 +
     * the automorphism map) and, through the framework's own registry path,
     * the ambient s^2 EvalMult relinearization key used by EvalHadamardInt
     * (the ambient registry is the honest home for the framework Switch_small,
     * exactly as in the complex port; EvalHadamardInt revalidates the entry
     * and fails closed when it is absent).
     */
    GLIntEvalKey EvalIntKeyGen(const PrivateKey<DCRTPoly>& privateKey) const;

    GLIntEncodedPlaintext EncodeInt(const GLIntPlaintext& plaintext) const;
    GLIntPlaintext DecodeInt(const GLIntEncodedPlaintext& plaintext) const;

    /**
     * Remark 3.13 analog: the transposed encoding satisfies
     * EncodeIntTransposed(M) = EncodeInt(M^T per branch); under it the SAME
     * EvalMatMulInt computes the LEFT products (V+ U+, V- U-) after
     * DecodeIntTransposed.
     */
    GLIntEncodedPlaintext EncodeIntTransposed(const GLIntPlaintext& plaintext) const;
    GLIntPlaintext DecodeIntTransposed(const GLIntEncodedPlaintext& plaintext) const;

    GLIntCiphertext EncryptInt(const PublicKey<DCRTPoly>& publicKey,
                               const GLIntEncodedPlaintext& plaintext) const;
    GLIntCiphertext EncryptInt(const PrivateKey<DCRTPoly>& privateKey,
                               const GLIntEncodedPlaintext& plaintext) const;
    GLIntPlaintext DecryptInt(const PrivateKey<DCRTPoly>& privateKey,
                              const GLIntCiphertext& ciphertext) const;

    /** Rowwise framework add/sub/negate; decode to U+V, U-V, -U per branch.  0 levels. */
    GLIntCiphertext AddInt(const GLIntCiphertext& lhs, const GLIntCiphertext& rhs) const;
    GLIntCiphertext SubInt(const GLIntCiphertext& lhs, const GLIntCiphertext& rhs) const;
    GLIntCiphertext NegateInt(const GLIntCiphertext& ciphertext) const;

    /**
     * Integer GL Hadamard product; decodes to (U+ o V+, U- o V-) and
     * consumes exactly 1 level.  Y-convolution row form with every row-pair
     * product one framework BGV multiplication relinearized by the ambient
     * s^2 key; the Y^n = I wrap group is folded in with the exact monomial
     * T^n, whose slot action is (+I on the + half, -I on the - half) —
     * the correct action of the ring element I on sigma_int; each output
     * row then receives exactly one ModReduce.
     */
    GLIntCiphertext EvalHadamardInt(const GLIntCiphertext& lhs, const GLIntCiphertext& rhs) const;

    /**
     * GL row rotation by nu in [1, n-1] (X -> X^{5^nu}): per-row framework
     * automorphism 5^nu mod 4n with the owned key map.  0 levels; decodes to
     * (j,k) -> U[(j+nu) mod n, k] on both branches.
     */
    GLIntCiphertext EvalRowRotateInt(const GLIntCiphertext& ciphertext, std::size_t nu,
                                     const GLIntEvalKey& evaluationKey) const;

    /**
     * GL column rotation by nu in [1, n-1] (Y -> Y^{5^nu}): keyless row
     * permutation plus exact monomial unit factors I^q.  No key material,
     * no key switch, 0 levels; decodes to (j,k) -> U[j, (k+nu) mod n] on
     * both branches.
     */
    GLIntCiphertext EvalColumnRotateInt(const GLIntCiphertext& ciphertext, std::size_t nu) const;

    /**
     * Section 4.4 "conjugation" (I,X,Y) -> (I^{-1},X^{-1},Y^{-1}): per-row
     * framework automorphism 4n-1 followed by the Y^{-1} row relabeling with
     * the exact (-I) monomial T^{3n}.  0 levels; decodes to the pure branch
     * swap (M-, M+) — no entrywise change (entries are plain Z_t scalars).
     */
    GLIntCiphertext EvalConjSwapInt(const GLIntCiphertext& ciphertext,
                                    const GLIntEvalKey& evaluationKey) const;

    /**
     * Native integer GL transpose; decodes to (U+^T, U-^T).  Step 1 is the
     * pure public coefficient relabeling b'(X,Y) = b(Y,X) on both components;
     * step 2 is one big switch with the K3 family ksk_{s(Y) -> s(X)}.
     * 0 rescales; level and metadata unchanged.  The exact identity
     * EvalTransposeInt == EvalConjSwapInt(EvalAdjointInt(ct)) holds mod t.
     */
    GLIntCiphertext EvalTransposeInt(const GLIntCiphertext& ciphertext,
                                     const GLIntEvalKey& evaluationKey) const;

    /**
     * Integer adjoint analog (I,X,Y) -> (I^{-1},Y^{-1},X^{-1}); decodes to
     * the branch-swapped transposes (U-^T, U+^T).  One big switch with K1,
     * 0 rescales.
     */
    GLIntCiphertext EvalAdjointInt(const GLIntCiphertext& ciphertext,
                                   const GLIntEvalKey& evaluationKey) const;

    /**
     * Plaintext-right integer circledast (GL trace on DCRT coefficient
     * pairs); decodes to n^{-1} (U+ V-^T, U- V+^T) with n^{-1} mod t folded
     * into the represented value (no explicit factor is applied).  Consumes
     * 1 level (one internal ModReduce at the primitive boundary).
     */
    GLIntCiphertext EvalCircledastPlainInt(const GLIntCiphertext& lhs,
                                           const GLIntPlaintext& rhs) const;

    /**
     * Plaintext-right ordinary per-branch products; decodes to
     * (U+ V+, U- V-).  Feeds the clear adjoint-analog (V-^T, V+^T) of the
     * right operand into the trace and multiplies both output components by
     * the exact public integer n, which exactly cancels n^{-1} mod t.
     * Consumes 1 level.
     */
    GLIntCiphertext EvalMatMulPlainInt(const GLIntCiphertext& lhs, const GLIntPlaintext& rhs) const;

    /** Encrypted circledast; decodes to n^{-1} (U+ V-^T, U- V+^T).  1 level. */
    GLIntCiphertext EvalCircledastInt(const GLIntCiphertext& lhs, const GLIntCiphertext& rhs,
                                      const GLIntEvalKey& evaluationKey) const;

    /**
     * Encrypted ordinary per-branch products; decodes to (U+ V+, U- V-).
     * Adjoint of the right operand via K1, then the cipher trace with the
     * exact factor n applied to all four component combinations before
     * either big switch.  1 level.
     */
    GLIntCiphertext EvalMatMulInt(const GLIntCiphertext& lhs, const GLIntCiphertext& rhs,
                                  const GLIntEvalKey& evaluationKey) const;

private:
    void ValidateOwnedContext(const CryptoContext<DCRTPoly>& context, const char* objectName) const;
    void ValidateKeyContext(const PublicKey<DCRTPoly>& key, const char* operation) const;
    void ValidateKeyContext(const PrivateKey<DCRTPoly>& key, const char* operation) const;
    void ValidatePlaintextCompatible(const GLIntPlaintext& plaintext, const char* objectName) const;
    void ValidateAggregate(const GLIntCiphertext& ciphertext, const char* objectName) const;
    void ValidateOperandPair(const GLIntCiphertext& lhs, const GLIntCiphertext& rhs,
                             const char* operation) const;
    void ValidateEvaluationKey(const GLIntEvalKey& evaluationKey, const std::string& keyTag,
                               const char* operation) const;
    void ValidateHadamardEvaluationKey(const std::string& keyTag, const char* operation) const;
    void RequireMultiplicationBudget(const GLIntCiphertext& ciphertext, const char* operation) const;
    void RequireRotationAmount(std::size_t nu, const char* operation) const;
    void VerifyPackingAgainstPinnedCodec() const;

    std::vector<std::vector<int64_t>> EncodeSlotRows(const GLIntPlaintext& plaintext) const;
    std::vector<Plaintext> PackSlotRows(const std::vector<std::vector<int64_t>>& slotRows,
                                        uint32_t level) const;
    GLIntPlaintext DecodeSlotRows(const std::vector<std::vector<int64_t>>& slotRows) const;

    GLIntCiphertext EvaluateIntPlainTrace(const GLIntCiphertext& lhs, const GLIntPlaintext& rhs,
                                          int64_t exactValueFactor) const;
    GLIntCiphertext EvaluateIntAdjoint(const GLIntCiphertext& ciphertext,
                                       const std::vector<EvalKey<DCRTPoly>>& conjugateKeyRows) const;
    GLIntCiphertext EvaluateIntCipherTrace(const GLIntCiphertext& lhs, const GLIntCiphertext& rhs,
                                           const std::vector<EvalKey<DCRTPoly>>& conjugateKeyRows,
                                           const std::vector<EvalKey<DCRTPoly>>& productKeyRows,
                                           int64_t exactValueFactor) const;

    GLIntParameters m_parameters;
    GLGeometry m_geometry;
    CryptoContext<DCRTPoly> m_context;
    uint64_t m_zeta{0};                 // pinned minimum primitive 4n-th root mod t
    uint64_t m_gaussianUnit{0};         // I = zeta^n mod t
    uint64_t m_inverseDimension{0};     // n^{-1} mod t
    std::vector<uint64_t> m_yRoots;         // zeta_k = zeta^{5^k}
    std::vector<uint64_t> m_yRootInverses;  // zeta_k^{-1}
};

}  // namespace lbcrypto

#endif  // LBCRYPTO_PKE_SCHEME_GL_INT_H
