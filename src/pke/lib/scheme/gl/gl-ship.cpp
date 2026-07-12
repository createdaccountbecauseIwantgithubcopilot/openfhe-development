//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "scheme/gl/gl-ship.h"

#include "key/privatekey.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "schemebase/rlwe-cryptoparameters.h"

#include <algorithm>
#include <cmath>
#include <exception>
#include <limits>
#include <set>
#include <sstream>
#include <utility>

namespace lbcrypto {

namespace {

std::size_t TowerCount(const Ciphertext<DCRTPoly>& ciphertext);

uint32_t CeilLog2(std::size_t value) {
    uint32_t result = 0;
    std::size_t power = 1;
    while (power < value) {
        power <<= 1;
        ++result;
    }
    return result;
}

std::vector<int32_t> RequiredXForwardRotations(
    const GLShipParameters& parameters, std::size_t dimension) {
    // Match OpenFHE's square BSGS split for a one-level dense linear
    // transform: baby rotations 1..b-1 and giant rotations b,2b,... .
    const auto babyStep = static_cast<std::size_t>(
        std::ceil(std::sqrt(static_cast<double>(dimension))));
    const auto giantStep = (dimension + babyStep - 1) / babyStep;
    std::set<int32_t> rotations;
    for (std::size_t baby = 1; baby < babyStep; ++baby) {
        rotations.insert(static_cast<int32_t>(baby));
    }
    for (std::size_t giant = 1; giant < giantStep; ++giant) {
        rotations.insert(static_cast<int32_t>(babyStep * giant));
    }
    if (parameters.selection == GLShipSelection::HYBRID_MASKED_COLUMN) {
        for (uint32_t digit = 0; digit < CeilLog2(parameters.coarseBlockSize); ++digit) {
            rotations.insert(static_cast<int32_t>(
                dimension - (std::size_t{1} << digit)));
        }
    }
    return {rotations.begin(), rotations.end()};
}

// The hybrid coarse block size theta must be a power of two in [2, n] that
// divides n.  For a power of two, CeilLog2 is the exact binary digit count
// of the fine chain.
bool IsHybridBlockSizeValid(std::size_t coarseBlockSize, std::size_t dimension) {
    return coarseBlockSize >= 2 && coarseBlockSize <= dimension && dimension != 0 &&
           dimension % coarseBlockSize == 0 &&
           (coarseBlockSize & (coarseBlockSize - 1)) == 0;
}

// Selection-dependent evaluation depth before the reserved budget:
//   direct: 1 (selection) + ceil(log2(h)) (tree) + 1 (XFwd)
//   hybrid: 1 (coarse)   + log2(theta) (fine digits)
//           + ceil(log2(h+1)) (tree over h leaves + the base plaintext node)
//           + 1 (XFwd)
uint32_t SelectionEvaluationDepth(const GLShipParameters& parameters) {
    if (parameters.selection == GLShipSelection::HYBRID_MASKED_COLUMN) {
        return 2 + CeilLog2(parameters.coarseBlockSize) +
               CeilLog2(parameters.hammingWeight + 1);
    }
    return 2 + CeilLog2(parameters.hammingWeight);
}

// Per-ordinal coarse candidate window in block units (full range when the
// public window list is empty).
std::pair<uint32_t, uint32_t> CoarseWindowOf(const GLShipParameters& parameters,
                                             std::size_t dimension,
                                             std::size_t supportOrdinal) {
    const auto blocks = static_cast<uint32_t>(dimension / parameters.coarseBlockSize);
    if (parameters.coarseWindows.empty()) {
        return {0, blocks};
    }
    const auto& window = parameters.coarseWindows[supportOrdinal];
    return {window.blockBegin, window.blockCount};
}

std::size_t ExpectedCoarseSelectorCount(const GLShipParameters& parameters,
                                        std::size_t dimension) {
    if (parameters.selection != GLShipSelection::HYBRID_MASKED_COLUMN) {
        return 2 * parameters.hammingWeight * dimension;
    }
    std::size_t total = 0;
    for (std::size_t ordinal = 0; ordinal < parameters.hammingWeight; ++ordinal) {
        total += 2 * CoarseWindowOf(parameters, dimension, ordinal).second;
    }
    return total;
}

std::size_t ExpectedFineSelectorCount(const GLShipParameters& parameters) {
    if (parameters.selection != GLShipSelection::HYBRID_MASKED_COLUMN) {
        return 0;
    }
    return 3 * parameters.hammingWeight *
           static_cast<std::size_t>(CeilLog2(parameters.coarseBlockSize));
}

bool SameCoarseWindows(const std::vector<GLShipCoarseWindow>& lhs,
                       const std::vector<GLShipCoarseWindow>& rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (std::size_t index = 0; index < lhs.size(); ++index) {
        if (lhs[index].blockBegin != rhs[index].blockBegin ||
            lhs[index].blockCount != rhs[index].blockCount) {
            return false;
        }
    }
    return true;
}

uint64_t ToUint64(const NativeInteger& value) {
    return static_cast<uint64_t>(value.ConvertToInt());
}

std::shared_ptr<CryptoParametersCKKSRNS> GetCKKSParameters(
    const CryptoContext<DCRTPoly>& context) {
    if (!context) {
        throw GLContextMismatchError("GL SHIP has no CryptoContext");
    }
    auto parameters = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
        context->GetCryptoParameters());
    if (!parameters || !parameters->GetElementParams() ||
        parameters->GetElementParams()->GetParams().empty()) {
        throw GLShipParameterError("GL SHIP requires CKKS-RNS element parameters");
    }
    return parameters;
}

uint64_t BottomModulus(const CryptoContext<DCRTPoly>& context) {
    const auto parameters = GetCKKSParameters(context);
    const auto q0 = ToUint64(parameters->GetElementParams()->GetParams().front()->GetModulus());
    if (q0 == 0 || q0 > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        throw GLShipParameterError("GL SHIP q0 must fit in a positive signed 64-bit integer");
    }
    return q0;
}

int64_t Centered(const NativeInteger& value, uint64_t modulus) {
    const uint64_t raw = ToUint64(value);
    if (raw > modulus / 2) {
        return -static_cast<int64_t>(modulus - raw);
    }
    return static_cast<int64_t>(raw);
}

std::vector<int64_t> CenteredCoefficients(const DCRTPoly& input, uint64_t expectedQ0,
                                          std::size_t expectedRingDimension) {
    if (input.GetNumOfElements() != 1 || input.GetRingDimension() != expectedRingDimension) {
        throw GLShipStateError("GL SHIP coefficient extraction requires one exact-ring tower");
    }
    auto coefficient = input;
    coefficient.SetFormat(Format::COEFFICIENT);
    const auto& tower = coefficient.GetElementAtIndex(0);
    const uint64_t modulus = ToUint64(tower.GetModulus());
    if (modulus != expectedQ0) {
        throw GLShipStateError("GL SHIP input tower modulus does not match q0");
    }
    std::vector<int64_t> result(expectedRingDimension);
    for (std::size_t index = 0; index < expectedRingDimension; ++index) {
        result[index] = Centered(tower[index], modulus);
    }
    return result;
}

std::vector<GLShipGaussianInteger> ToGaussian(const std::vector<int64_t>& coefficients,
                                              std::size_t n) {
    if (coefficients.size() != 2 * n) {
        throw GLShipStateError("GL SHIP real coefficient vector must have length 2n");
    }
    std::vector<GLShipGaussianInteger> result(n);
    for (std::size_t index = 0; index < n; ++index) {
        result[index] = GLShipGaussianInteger(coefficients[index], coefficients[index + n]);
    }
    return result;
}

std::vector<GLShipGaussianInteger> MultiplyByNegativeGaussianI(
    const std::vector<GLShipGaussianInteger>& input) {
    std::vector<GLShipGaussianInteger> result;
    result.reserve(input.size());
    for (const auto& value : input) {
        result.emplace_back(value.imag(), -value.real());
    }
    return result;
}

DCRTPoly GaussianI(const std::shared_ptr<DCRTPoly::Params>& parameters, std::size_t n) {
    if (!parameters || parameters->GetRingDimension() != 2 * n) {
        throw GLNativeModeError("exact multiplication by i requires ring dimension 2n");
    }
    DCRTPoly result(parameters, Format::COEFFICIENT, true);
    for (std::size_t towerIndex = 0; towerIndex < result.GetNumOfElements(); ++towerIndex) {
        auto tower = result.GetElementAtIndex(towerIndex);
        tower[n] = NativeInteger(1);
        result.SetElementAtIndex(towerIndex, std::move(tower));
    }
    result.SetFormat(Format::EVALUATION);
    return result;
}

void MultiplyCiphertextByGaussianI(Ciphertext<DCRTPoly>& ciphertext, std::size_t n) {
    if (!ciphertext || ciphertext->NumberCiphertextElements() != 2) {
        throw GLShipStateError("exact multiplication by i requires a two-component ciphertext");
    }
    auto& elements = ciphertext->GetElements();
    const auto gaussianI = GaussianI(elements.front().GetParams(), n);
    for (auto& element : elements) {
        element *= gaussianI;
    }
}

void ModReduceOneLevel(const CryptoContext<DCRTPoly>& context,
                       Ciphertext<DCRTPoly>& ciphertext, const char* operation) {
    if (!ciphertext) {
        throw GLShipStateError(std::string(operation) + " received a null ciphertext");
    }
    const auto parameters = GetCKKSParameters(context);
    const auto compositeDegree = parameters->GetCompositeDegree();
    if (compositeDegree != 1) {
        throw GLShipUnsupportedError(
            "bounded GL SHIP requires a one-prime CKKS composite degree");
    }
    const auto beforeTowers = TowerCount(ciphertext);
    const auto beforeLevel = ciphertext->GetLevel();
    const auto beforeNoiseScaleDegree = ciphertext->GetNoiseScaleDeg();
    if (beforeTowers <= compositeDegree || beforeNoiseScaleDegree < 2) {
        throw GLShipStateError(std::string(operation) +
                               " has no scale/tower budget for an exact modulus drop");
    }
    context->GetScheme()->ModReduceInternalInPlace(ciphertext, compositeDegree);
    if (TowerCount(ciphertext) != beforeTowers - compositeDegree ||
        ciphertext->GetLevel() != beforeLevel + compositeDegree ||
        ciphertext->GetNoiseScaleDeg() != beforeNoiseScaleDegree - 1) {
        throw GLShipStateError(std::string(operation) +
                               " did not consume exactly one CKKS level");
    }
}

void DropCiphertextToLevel(Ciphertext<DCRTPoly>& ciphertext, uint32_t targetLevel) {
    if (!ciphertext || ciphertext->GetLevel() > targetLevel) {
        throw GLShipStateError("GL SHIP cannot raise a ciphertext by dropping towers");
    }
    const auto levelsToDrop = static_cast<std::size_t>(targetLevel - ciphertext->GetLevel());
    if (levelsToDrop == 0) {
        return;
    }
    for (auto& element : ciphertext->GetElements()) {
        if (element.GetNumOfElements() <= levelsToDrop) {
            throw GLShipStateError("GL SHIP level alignment would remove every RNS tower");
        }
        element.DropLastElements(levelsToDrop);
    }
    ciphertext->SetLevel(targetLevel);
}

PrivateKey<DCRTPoly> MakeSparseSecret(const CryptoContext<DCRTPoly>& context,
                                      const std::vector<GLShipMonomial>& support,
                                      std::size_t n) {
    const auto cryptoParameters = std::dynamic_pointer_cast<CryptoParametersRLWE<DCRTPoly>>(
        context->GetCryptoParameters());
    if (!cryptoParameters || !cryptoParameters->GetElementParams()) {
        throw GLShipParameterError("GL SHIP could not obtain RLWE element parameters");
    }

    DCRTPoly secret(cryptoParameters->GetElementParams(), Format::COEFFICIENT, true);
    for (std::size_t towerIndex = 0; towerIndex < secret.GetNumOfElements(); ++towerIndex) {
        auto tower = secret.GetElementAtIndex(towerIndex);
        const auto modulus = tower.GetModulus();
        for (const auto& monomial : support) {
            if (monomial.alpha >= n || (monomial.sign != -1 && monomial.sign != 1)) {
                throw GLShipParameterError("GL SHIP sparse monomial is invalid");
            }
            tower[monomial.alpha] = monomial.sign == 1 ? NativeInteger(1) : modulus - NativeInteger(1);
        }
        secret.SetElementAtIndex(towerIndex, std::move(tower));
    }
    secret.SetFormat(Format::EVALUATION);

    auto privateKey = std::make_shared<PrivateKeyImpl<DCRTPoly>>(context);
    privateKey->SetPrivateElement(std::move(secret));
    return privateKey;
}

std::vector<int64_t> PhysicalGaussianCoefficients(
    std::size_t n, double gamma,
    const std::vector<std::complex<double>>& coefficients, uint64_t q0) {
    if (coefficients.size() != n) {
        throw GLDimensionError("GL SHIP low slice requires exactly n Gaussian coefficients");
    }
    std::vector<int64_t> physical(2 * n, 0);
    const long double multiplier = static_cast<long double>(q0) / static_cast<long double>(gamma);
    for (std::size_t index = 0; index < n; ++index) {
        if (!std::isfinite(coefficients[index].real()) ||
            !std::isfinite(coefficients[index].imag()) ||
            std::abs(coefficients[index].real()) > 1.0 ||
            std::abs(coefficients[index].imag()) > 1.0) {
            throw GLShipParameterError("GL SHIP toy coefficients must have finite lanes in [-1,1]");
        }
        physical[index] = static_cast<int64_t>(
            std::llround(multiplier * static_cast<long double>(coefficients[index].real())));
        physical[index + n] = static_cast<int64_t>(
            std::llround(multiplier * static_cast<long double>(coefficients[index].imag())));
    }
    return physical;
}

NativeInteger Residue(int64_t value, const NativeInteger& modulus) {
    const uint64_t magnitude = value >= 0 ? static_cast<uint64_t>(value)
                                          : static_cast<uint64_t>(-value);
    NativeInteger residue(magnitude);
    residue.ModEq(modulus);
    if (value >= 0 || residue == NativeInteger(0)) {
        return residue;
    }
    return modulus - residue;
}

DCRTPoly MakePhysicalGaussianPlaintext(
    const CryptoContext<DCRTPoly>& context, const std::vector<int64_t>& coefficients) {
    const auto parameters = GetCKKSParameters(context)->GetElementParams();
    if (coefficients.size() != parameters->GetRingDimension()) {
        throw GLDimensionError("GL SHIP physical plaintext must have 2n coefficients");
    }
    DCRTPoly plaintext(parameters, Format::COEFFICIENT, true);
    for (std::size_t towerIndex = 0; towerIndex < plaintext.GetNumOfElements(); ++towerIndex) {
        auto tower = plaintext.GetElementAtIndex(towerIndex);
        const auto modulus = tower.GetModulus();
        for (std::size_t coefficient = 0; coefficient < coefficients.size(); ++coefficient) {
            tower[coefficient] = Residue(coefficients[coefficient], modulus);
        }
        plaintext.SetElementAtIndex(towerIndex, std::move(tower));
    }
    plaintext.SetFormat(Format::EVALUATION);
    return plaintext;
}

std::complex<double> RootOfUnity(uint64_t q0, int64_t exponent) {
    const long double pi = std::acos(-1.0L);
    const long double angle = 2.0L * pi * static_cast<long double>(exponent) /
                              static_cast<long double>(q0);
    const auto value = std::polar(1.0L, angle);
    return {static_cast<double>(value.real()), static_cast<double>(value.imag())};
}

std::size_t TowerCount(const Ciphertext<DCRTPoly>& ciphertext) {
    if (!ciphertext || ciphertext->GetElements().empty()) {
        return 0;
    }
    return ciphertext->GetElements().front().GetNumOfElements();
}

}  // namespace

uint32_t GLShipParameters::RequiredMultiplicativeDepth() const {
    if (hammingWeight == 0) {
        return std::numeric_limits<uint32_t>::max();
    }
    // Direct column: one level selects the leaves, ceil(log2(h)) levels
    // reduce their balanced product, and one final level realizes XFwd.
    // Hybrid masked column: one level accumulates the coarse lanes, each of
    // the log2(theta) fine digits consumes one relinearized ct*ct level, the
    // tree reduces h leaves plus the base plaintext node in ceil(log2(h+1))
    // levels, and one final level realizes XFwd.  Reserved levels are live
    // after the ordinary refresh returns.  A structurally invalid hybrid
    // block size fails closed as unsatisfiable depth (Validate names it).
    if (selection == GLShipSelection::HYBRID_MASKED_COLUMN &&
        !IsHybridBlockSizeValid(coarseBlockSize, dimension)) {
        return std::numeric_limits<uint32_t>::max();
    }
    const uint32_t evaluationDepth = SelectionEvaluationDepth(*this);
    if (reservedLevels > std::numeric_limits<uint32_t>::max() - evaluationDepth) {
        return std::numeric_limits<uint32_t>::max();
    }
    return evaluationDepth + reservedLevels;
}

void GLShipParameters::Validate(const GLGeometry& geometry,
                                const GLParameters& glParameters) const {
    // The dimension gate fires before any selection logic, so every selection
    // mode keeps failing closed at n=4096 pending production parameters.
    if (dimension != geometry.GetDimension() ||
        (dimension != 4 && dimension != 8 && dimension != 16 && dimension != 32 &&
         dimension != 64 && dimension != 128)) {
        throw GLShipParameterError(
            "GL SHIP conformance supports matching n=4/8, plus direct-column n=16/32/64/128");
    }
    if (!std::isfinite(gamma) || gamma <= 2.0) {
        throw GLShipParameterError("GL SHIP gamma must be finite and greater than two");
    }
    if (hammingWeight == 0 || hammingWeight > dimension) {
        throw GLShipParameterError("GL SHIP Hamming weight must lie in [1,n]");
    }
    if (reservedLevels == 0) {
        throw GLShipParameterError("GL SHIP requires at least one reserved post-bootstrap level");
    }
    if (selection != GLShipSelection::DIRECT_COLUMN &&
        selection != GLShipSelection::HYBRID_MASKED_COLUMN) {
        throw GLShipUnsupportedError(
            "GL SHIP currently supports direct-column and hybrid masked-column selection only");
    }
    if (selection == GLShipSelection::HYBRID_MASKED_COLUMN && dimension >= 16) {
        throw GLShipUnsupportedError(
            "GL SHIP hybrid conformance remains restricted to n=4 or n=8");
    }
    if (selection == GLShipSelection::DIRECT_COLUMN) {
        if (coarseBlockSize != 0 || !coarseWindows.empty()) {
            throw GLShipParameterError(
                "GL SHIP direct-column selection takes no hybrid coarse parameters");
        }
    }
    else {
        if (!IsHybridBlockSizeValid(coarseBlockSize, dimension)) {
            throw GLShipParameterError(
                "GL SHIP hybrid coarse block size must be a power of two in [2, n] that divides n");
        }
        if (!coarseWindows.empty() && coarseWindows.size() != hammingWeight) {
            throw GLShipParameterError(
                "GL SHIP hybrid coarse windows must provide one window per support ordinal");
        }
        const auto blocks = dimension / coarseBlockSize;
        for (const auto& window : coarseWindows) {
            if (window.blockCount == 0 || window.blockBegin >= blocks ||
                static_cast<std::size_t>(window.blockBegin) + window.blockCount > blocks) {
                throw GLShipParameterError(
                    "GL SHIP hybrid coarse window exceeds the candidate block range");
            }
        }
    }
    const uint32_t evaluationDepth = SelectionEvaluationDepth(*this);
    if (reservedLevels > std::numeric_limits<uint32_t>::max() - evaluationDepth) {
        throw GLShipParameterError("GL SHIP multiplicative-depth requirement overflows uint32_t");
    }
    if (!glParameters.RequestsExactNativeRing() ||
        glParameters.ringDimension != geometry.GetNativeRingDimension()) {
        throw GLNativeModeError("GL SHIP requires exact ringDimension=2n; transport rings are rejected");
    }
    if (glParameters.securityLevel != HEStd_NotSet) {
        throw GLNativeModeError("GL SHIP n=4/8/16/32/64/128 is an HEStd_NotSet conformance mode only");
    }
    if (glParameters.scalingTechnique != FLEXIBLEAUTO) {
        throw GLShipUnsupportedError(
            "bounded GL SHIP supports only FLEXIBLEAUTO CKKS scaling");
    }
    const auto requiredDepth = RequiredMultiplicativeDepth();
    if (glParameters.multiplicativeDepth < requiredDepth) {
        std::ostringstream os;
        os << "GL SHIP full refresh requires multiplicativeDepth >= " << requiredDepth;
        throw GLDepthError(os.str());
    }
}

std::vector<GLShipGaussianInteger> GLShipAlgebra::MultiplyMonomial(
    const std::vector<GLShipGaussianInteger>& input, uint32_t alpha, int8_t sign) {
    const auto n = input.size();
    if (n == 0 || alpha >= n || (sign != -1 && sign != 1)) {
        throw GLShipParameterError("invalid GL SHIP Gaussian monomial multiplication");
    }
    std::vector<GLShipGaussianInteger> result(n, GLShipGaussianInteger(0, 0));
    for (std::size_t source = 0; source < n; ++source) {
        std::size_t destination = source + alpha;
        auto value = input[source];
        if (destination >= n) {
            destination -= n;
            value = GLShipGaussianInteger(-value.imag(), value.real());
        }
        result[destination] += static_cast<int64_t>(sign) * value;
    }
    return result;
}

std::vector<GLShipGaussianInteger> GLShipAlgebra::MultiplyGaussianI(
    const std::vector<GLShipGaussianInteger>& input) {
    std::vector<GLShipGaussianInteger> result;
    result.reserve(input.size());
    for (const auto& value : input) {
        result.emplace_back(-value.imag(), value.real());
    }
    return result;
}

std::vector<GLShipGaussianInteger> GLShipAlgebra::DecryptionRelation(
    const std::vector<GLShipGaussianInteger>& b,
    const std::vector<GLShipGaussianInteger>& a,
    const std::vector<GLShipMonomial>& support) {
    if (b.empty() || b.size() != a.size()) {
        throw GLDimensionError("GL SHIP decryption oracle requires equal nonempty vectors");
    }
    auto result = b;
    for (const auto& monomial : support) {
        const auto term = MultiplyMonomial(a, monomial.alpha, monomial.sign);
        for (std::size_t index = 0; index < result.size(); ++index) {
            result[index] += term[index];
        }
    }
    return result;
}

std::vector<std::complex<double>> GLShipAlgebra::RootVector(
    uint64_t q0, const std::vector<int64_t>& exponents) {
    if (q0 == 0) {
        throw GLShipParameterError("GL SHIP root modulus must be nonzero");
    }
    std::vector<std::complex<double>> result;
    result.reserve(exponents.size());
    for (const auto exponent : exponents) {
        result.push_back(RootOfUnity(q0, exponent));
    }
    return result;
}

GLShipEvaluationKey::GLShipEvaluationKey(
    GLShipParameters parameters, CryptoContext<DCRTPoly> context,
    std::string sparseKeyTag, std::string primaryKeyTag, uint64_t q0,
    EvalKey<DCRTPoly> bottomPrimaryToSparseKey,
    std::vector<Ciphertext<DCRTPoly>> selectors,
    std::vector<Ciphertext<DCRTPoly>> fineSelectors,
    std::vector<EvalKey<DCRTPoly>> relinearizationKeys,
    std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> conjugationKeys,
    std::shared_ptr<std::map<uint32_t, EvalKey<DCRTPoly>>> xForwardKeys)
    : m_parameters(std::move(parameters)),
      m_context(std::move(context)),
      m_sparseKeyTag(std::move(sparseKeyTag)),
      m_primaryKeyTag(std::move(primaryKeyTag)),
      m_q0(q0),
      m_bottomPrimaryToSparseKey(std::move(bottomPrimaryToSparseKey)),
      m_selectors(std::move(selectors)),
      m_fineSelectors(std::move(fineSelectors)),
      m_relinearizationKeys(std::move(relinearizationKeys)),
      m_conjugationKeys(std::move(conjugationKeys)),
      m_xForwardKeys(std::move(xForwardKeys)) {}

const GLShipParameters& GLShipEvaluationKey::GetParameters() const noexcept {
    return m_parameters;
}

const CryptoContext<DCRTPoly>& GLShipEvaluationKey::GetCryptoContext() const noexcept {
    return m_context;
}

const std::string& GLShipEvaluationKey::GetSparseKeyTag() const noexcept {
    return m_sparseKeyTag;
}

const std::string& GLShipEvaluationKey::GetPrimaryKeyTag() const noexcept {
    return m_primaryKeyTag;
}

uint64_t GLShipEvaluationKey::GetBottomModulus() const noexcept {
    return m_q0;
}

std::size_t GLShipEvaluationKey::GetSelectorCount() const noexcept {
    return m_selectors.size();
}

std::size_t GLShipEvaluationKey::GetFineSelectorCount() const noexcept {
    return m_fineSelectors.size();
}

GLShipClientMaterial::GLShipClientMaterial(PrivateKey<DCRTPoly> sparseSecretKey,
                                           GLShipEvaluationKey evaluationKey)
    : m_sparseSecretKey(std::move(sparseSecretKey)),
      m_evaluationKey(std::move(evaluationKey)) {}

const GLShipEvaluationKey& GLShipClientMaterial::GetEvaluationKey() const noexcept {
    return m_evaluationKey;
}

GLShipLowSliceCiphertext::GLShipLowSliceCiphertext(
    std::size_t dimension, uint64_t q0, CryptoContext<DCRTPoly> context,
    Ciphertext<DCRTPoly> ciphertext)
    : m_dimension(dimension),
      m_q0(q0),
      m_context(std::move(context)),
      m_ciphertext(std::move(ciphertext)),
      m_representation(GLShipRepresentation::POST_XINV_COEFFICIENT) {}

GLShipRepresentation GLShipLowSliceCiphertext::GetRepresentation() const noexcept {
    return m_representation;
}

std::size_t GLShipLowSliceCiphertext::GetDimension() const noexcept {
    return m_dimension;
}

uint64_t GLShipLowSliceCiphertext::GetBottomModulus() const noexcept {
    return m_q0;
}

const CryptoContext<DCRTPoly>& GLShipLowSliceCiphertext::GetCryptoContext() const noexcept {
    return m_context;
}

const Ciphertext<DCRTPoly>& GLShipLowSliceCiphertext::GetNativeCiphertext() const noexcept {
    return m_ciphertext;
}

const std::string& GLShipLowSliceCiphertext::GetKeyTag() const {
    if (!m_ciphertext) {
        throw GLShipStateError("GL SHIP low slice has no native ciphertext");
    }
    return m_ciphertext->GetKeyTag();
}

GLShipHalfBootstrapResult::GLShipHalfBootstrapResult(
    std::size_t dimension, CryptoContext<DCRTPoly> context,
    Ciphertext<DCRTPoly> ciphertext)
    : m_dimension(dimension),
      m_context(std::move(context)),
      m_ciphertext(std::move(ciphertext)),
      m_representation(GLShipRepresentation::X_COEFFICIENT_SLOTS) {}

GLShipRepresentation GLShipHalfBootstrapResult::GetRepresentation() const noexcept {
    return m_representation;
}

std::size_t GLShipHalfBootstrapResult::GetDimension() const noexcept {
    return m_dimension;
}

const CryptoContext<DCRTPoly>& GLShipHalfBootstrapResult::GetCryptoContext() const noexcept {
    return m_context;
}

const Ciphertext<DCRTPoly>& GLShipHalfBootstrapResult::GetNativeCiphertext() const noexcept {
    return m_ciphertext;
}

const std::string& GLShipHalfBootstrapResult::GetKeyTag() const {
    if (!m_ciphertext) {
        throw GLShipStateError("GL SHIP half-bootstrap result has no native ciphertext");
    }
    return m_ciphertext->GetKeyTag();
}

GLShipSchemelet::GLShipSchemelet(const GLSchemelet& glSchemelet,
                                 GLShipParameters parameters)
    : m_parameters(std::move(parameters)),
      m_geometry(glSchemelet.GetGeometry()),
      m_glParameters(glSchemelet.GetParameters()),
      m_context(glSchemelet.GetCryptoContext()) {
    m_parameters.Validate(m_geometry, m_glParameters);
    if (!glSchemelet.UsesExactNativeRing() ||
        m_context->GetRingDimension() != m_geometry.GetNativeRingDimension() ||
        m_context->GetCyclotomicOrder() != m_geometry.GetNativeCyclotomicOrder()) {
        throw GLNativeModeError("GL SHIP requires the exact W-free native ring");
    }
    const auto ckksParameters = GetCKKSParameters(m_context);
    if (ckksParameters->GetCompositeDegree() != 1) {
        throw GLShipUnsupportedError(
            "bounded GL SHIP requires one RNS prime per CKKS level");
    }
    if (ckksParameters->GetKeySwitchTechnique() != HYBRID ||
        !ckksParameters->GetParamsP() ||
        ckksParameters->GetParamsP()->GetParams().empty()) {
        throw GLShipUnsupportedError(
            "bounded GL SHIP requires HYBRID key switching with an auxiliary P basis");
    }
    (void)BottomModulus(m_context);
}

const GLShipParameters& GLShipSchemelet::GetParameters() const noexcept {
    return m_parameters;
}

const GLGeometry& GLShipSchemelet::GetGeometry() const noexcept {
    return m_geometry;
}

const CryptoContext<DCRTPoly>& GLShipSchemelet::GetCryptoContext() const noexcept {
    return m_context;
}

std::size_t GLShipSchemelet::SelectorIndex(std::size_t supportOrdinal,
                                           std::size_t alpha, int8_t sign) const {
    if (supportOrdinal >= m_parameters.hammingWeight || alpha >= m_geometry.GetDimension() ||
        (sign != -1 && sign != 1)) {
        throw GLShipParameterError("GL SHIP selector index is outside the direct-column bank");
    }
    const std::size_t signIndex = sign == -1 ? 0 : 1;
    return (supportOrdinal * m_geometry.GetDimension() + alpha) * 2 + signIndex;
}

std::size_t GLShipSchemelet::CoarseSelectorIndex(std::size_t supportOrdinal,
                                                 std::size_t blockOffset, int8_t sign) const {
    if (m_parameters.selection != GLShipSelection::HYBRID_MASKED_COLUMN ||
        supportOrdinal >= m_parameters.hammingWeight || (sign != -1 && sign != 1)) {
        throw GLShipParameterError("GL SHIP hybrid selection index is outside the coarse bank");
    }
    const auto n = m_geometry.GetDimension();
    std::size_t base = 0;
    for (std::size_t ordinal = 0; ordinal < supportOrdinal; ++ordinal) {
        base += 2 * CoarseWindowOf(m_parameters, n, ordinal).second;
    }
    if (blockOffset >= CoarseWindowOf(m_parameters, n, supportOrdinal).second) {
        throw GLShipParameterError("GL SHIP hybrid selection index is outside the coarse bank");
    }
    const std::size_t signIndex = sign == -1 ? 0 : 1;
    return base + 2 * blockOffset + signIndex;
}

std::size_t GLShipSchemelet::FineSelectorIndex(std::size_t supportOrdinal, uint32_t digit,
                                               std::size_t piece) const {
    const auto digits = CeilLog2(m_parameters.coarseBlockSize);
    if (m_parameters.selection != GLShipSelection::HYBRID_MASKED_COLUMN ||
        supportOrdinal >= m_parameters.hammingWeight || digit >= digits || piece >= 3) {
        throw GLShipParameterError("GL SHIP hybrid selection index is outside the coarse bank");
    }
    return (supportOrdinal * digits + digit) * 3 + piece;
}

void GLShipSchemelet::ValidatePrimaryKeyPair(
    const KeyPair<DCRTPoly>& primaryKeyPair) const {
    if (!primaryKeyPair.good() || !primaryKeyPair.publicKey || !primaryKeyPair.secretKey) {
        throw GLShipEvaluationKeyError("GL SHIP primary key pair is incomplete");
    }
    if (primaryKeyPair.publicKey->GetCryptoContext().get() != m_context.get() ||
        primaryKeyPair.secretKey->GetCryptoContext().get() != m_context.get()) {
        throw GLKeyContextMismatchError("GL SHIP primary key pair belongs to another context");
    }
    if (primaryKeyPair.publicKey->GetKeyTag().empty() ||
        primaryKeyPair.publicKey->GetKeyTag() != primaryKeyPair.secretKey->GetKeyTag()) {
        throw GLKeyMismatchError("GL SHIP primary public/private key tags do not match");
    }
}

GLShipClientMaterial GLShipSchemelet::KeyGen(
    const KeyPair<DCRTPoly>& primaryKeyPair,
    const std::vector<GLShipMonomial>& support) const {
    ValidatePrimaryKeyPair(primaryKeyPair);
    if (support.size() != m_parameters.hammingWeight) {
        throw GLShipParameterError("GL SHIP support size does not match Hamming weight");
    }
    std::set<uint32_t> seen;
    for (const auto& monomial : support) {
        if (monomial.alpha >= m_geometry.GetDimension() ||
            (monomial.sign != -1 && monomial.sign != 1) ||
            !seen.insert(monomial.alpha).second) {
            throw GLShipParameterError("GL SHIP support contains an invalid or duplicate monomial");
        }
    }
    if (m_parameters.selection == GLShipSelection::HYBRID_MASKED_COLUMN &&
        !m_parameters.coarseWindows.empty()) {
        // Client-side (key-generation) rule: the evaluator never learns the
        // live block, so window containment can only be checked here.
        for (std::size_t ordinal = 0; ordinal < support.size(); ++ordinal) {
            const auto liveBlock = support[ordinal].alpha /
                                   static_cast<uint32_t>(m_parameters.coarseBlockSize);
            const auto& window = m_parameters.coarseWindows[ordinal];
            if (liveBlock < window.blockBegin ||
                liveBlock >= window.blockBegin + window.blockCount) {
                throw GLShipParameterError(
                    "GL SHIP hybrid coarse window cannot contain its support ordinal");
            }
        }
    }

    auto sparseSecret = MakeSparseSecret(m_context, support, m_geometry.GetDimension());
    if (!sparseSecret || sparseSecret->GetKeyTag().empty()) {
        throw GLShipEvaluationKeyError("GL SHIP failed to construct the sparse client key");
    }

    // OpenFHE's sparse-encapsulation switch is deliberately generated only
    // over q0*p0.  Unlike an ordinary HYBRID KeySwitchGen result, this object
    // contains no sparse-key RLWE samples at the full computational Q chain.
    auto bottomPrimaryToSparseKey =
        FHECKKSRNS::KeySwitchGenSparse(primaryKeyPair.secretKey, sparseSecret);
    if (!bottomPrimaryToSparseKey ||
        bottomPrimaryToSparseKey->GetKeyTag() != sparseSecret->GetKeyTag()) {
        throw GLShipEvaluationKeyError(
            "GL SHIP failed to generate its q0*P primary-to-sparse switch");
    }

    auto generatedRelinearizationKey =
        m_context->GetScheme()->EvalMultKeyGen(primaryKeyPair.secretKey);
    if (!generatedRelinearizationKey) {
        throw GLShipEvaluationKeyError("GL SHIP failed to generate the relinearization key");
    }
    std::vector<EvalKey<DCRTPoly>> relinearizationKeys{
        std::move(generatedRelinearizationKey)};
    const uint32_t conjugationIndex = static_cast<uint32_t>(m_context->GetCyclotomicOrder() - 1);
    const auto generatedConjugationKeys =
        m_context->GetScheme()->EvalAutomorphismKeyGen(
            primaryKeyPair.secretKey, {conjugationIndex});
    if (!generatedConjugationKeys ||
        generatedConjugationKeys->find(conjugationIndex) == generatedConjugationKeys->end()) {
        throw GLShipEvaluationKeyError("GL SHIP failed to generate the conjugation key");
    }
    auto conjugationKeys = std::make_shared<std::map<uint32_t, EvalKey<DCRTPoly>>>();
    conjugationKeys->emplace(conjugationIndex,
                             generatedConjugationKeys->at(conjugationIndex));

    const auto xForwardRotations =
        RequiredXForwardRotations(m_parameters, m_geometry.GetDimension());
    auto xForwardKeys = m_context->GetScheme()->EvalAtIndexKeyGen(
        primaryKeyPair.secretKey, xForwardRotations);
    if (!xForwardKeys || xForwardKeys->empty()) {
        throw GLShipEvaluationKeyError("GL SHIP failed to generate X-forward rotation keys");
    }

    const auto n = m_geometry.GetDimension();
    // Every selector-class object (direct joint bits, hybrid coarse bits, and
    // hybrid fine mask-fused digit pieces) is a fresh primary-key encryption
    // in one uniform metadata class: level 0, noise-scale degree 1, n slots,
    // full towers.
    const auto encryptSelectorValues =
        [&](const std::vector<std::complex<double>>& values) {
            auto plaintext = m_context->MakeCKKSPackedPlaintext(
                values, 1, 0, nullptr, static_cast<uint32_t>(n));
            if (!plaintext) {
                throw GLShipEvaluationKeyError("GL SHIP failed to encode a selector");
            }
            auto selector = m_context->Encrypt(primaryKeyPair.publicKey, plaintext);
            if (!selector || selector->NumberCiphertextElements() != 2 ||
                selector->GetKeyTag() != primaryKeyPair.publicKey->GetKeyTag()) {
                throw GLShipEvaluationKeyError("GL SHIP failed to encrypt a selector");
            }
            return selector;
        };

    std::vector<Ciphertext<DCRTPoly>> selectors;
    std::vector<Ciphertext<DCRTPoly>> fineSelectors;
    if (m_parameters.selection == GLShipSelection::DIRECT_COLUMN) {
        selectors.reserve(2 * m_parameters.hammingWeight * n);
        for (std::size_t ordinal = 0; ordinal < support.size(); ++ordinal) {
            for (std::size_t alpha = 0; alpha < n; ++alpha) {
                for (const int8_t sign : {int8_t(-1), int8_t(1)}) {
                    const double bit = support[ordinal].alpha == alpha &&
                                               support[ordinal].sign == sign
                                           ? 1.0
                                           : 0.0;
                    std::vector<std::complex<double>> values(n, {bit, 0.0});
                    selectors.push_back(encryptSelectorValues(values));
                }
            }
        }
    }
    else {
        const auto theta = m_parameters.coarseBlockSize;
        const auto digits = CeilLog2(theta);
        // Coarse (block, sign) one-hot bank over the public per-ordinal
        // windows: ordinal ascending, block ascending, sign -1 then +1.
        // Exactly one live candidate per ordinal at (alpha_t/theta, sigma_t);
        // dead candidates are fresh encryptions of zero.
        selectors.reserve(ExpectedCoarseSelectorCount(m_parameters, n));
        for (std::size_t ordinal = 0; ordinal < support.size(); ++ordinal) {
            const auto window = CoarseWindowOf(m_parameters, n, ordinal);
            const auto liveBlock =
                support[ordinal].alpha / static_cast<uint32_t>(theta);
            for (uint32_t offset = 0; offset < window.second; ++offset) {
                const uint32_t block = window.first + offset;
                for (const int8_t sign : {int8_t(-1), int8_t(1)}) {
                    const double bit =
                        block == liveBlock && support[ordinal].sign == sign ? 1.0 : 0.0;
                    std::vector<std::complex<double>> values(n, {bit, 0.0});
                    selectors.push_back(encryptSelectorValues(values));
                }
            }
        }
        // Fine mask-fused digit bank: ordinal ascending, digit ascending
        // (LSB first), pieces PH = Enc(a*mHigh), PL = Enc(a*mLow),
        // NG = Enc(1-a).  Per digit the three pieces sum to the all-ones
        // vector; both digit polarities are therefore present.
        fineSelectors.reserve(ExpectedFineSelectorCount(m_parameters));
        for (std::size_t ordinal = 0; ordinal < support.size(); ++ordinal) {
            const auto alpha0 = support[ordinal].alpha % static_cast<uint32_t>(theta);
            for (uint32_t digit = 0; digit < digits; ++digit) {
                const double bit = static_cast<double>((alpha0 >> digit) & 1u);
                const std::size_t delta = std::size_t{1} << digit;
                std::vector<std::complex<double>> rotateHigh(n);
                std::vector<std::complex<double>> rotateLow(n);
                std::vector<std::complex<double>> identity(n, {1.0 - bit, 0.0});
                for (std::size_t slot = 0; slot < n; ++slot) {
                    rotateHigh[slot] = {slot >= delta ? bit : 0.0, 0.0};
                    rotateLow[slot] = {slot < delta ? bit : 0.0, 0.0};
                }
                fineSelectors.push_back(encryptSelectorValues(rotateHigh));
                fineSelectors.push_back(encryptSelectorValues(rotateLow));
                fineSelectors.push_back(encryptSelectorValues(identity));
            }
        }
    }

    GLShipEvaluationKey evaluationKey(
        m_parameters, m_context, sparseSecret->GetKeyTag(),
        primaryKeyPair.publicKey->GetKeyTag(), BottomModulus(m_context),
        std::move(bottomPrimaryToSparseKey), std::move(selectors),
        std::move(fineSelectors), std::move(relinearizationKeys),
        std::move(conjugationKeys), std::move(xForwardKeys));
    ValidateEvaluationKey(evaluationKey);
    return GLShipClientMaterial(std::move(sparseSecret), std::move(evaluationKey));
}

GLShipLowSliceCiphertext GLShipSchemelet::EncryptLowSlice(
    const GLShipClientMaterial& clientMaterial,
    const std::vector<std::complex<double>>& coefficients) const {
    if (!clientMaterial.m_sparseSecretKey ||
        clientMaterial.m_sparseSecretKey->GetCryptoContext().get() != m_context.get() ||
        clientMaterial.m_sparseSecretKey->GetKeyTag() !=
            clientMaterial.m_evaluationKey.GetSparseKeyTag()) {
        throw GLKeyMismatchError("GL SHIP client sparse key does not match its evaluation key");
    }
    ValidateEvaluationKey(clientMaterial.m_evaluationKey);

    const auto physicalCoefficients = PhysicalGaussianCoefficients(
        m_geometry.GetDimension(), m_parameters.gamma, coefficients,
        clientMaterial.m_evaluationKey.GetBottomModulus());
    const auto physicalPlaintext = MakePhysicalGaussianPlaintext(m_context, physicalCoefficients);
    auto ciphertext = m_context->GetScheme()->Encrypt(
        physicalPlaintext, clientMaterial.m_sparseSecretKey);
    if (!ciphertext || ciphertext->NumberCiphertextElements() != 2) {
        throw GLShipStateError("GL SHIP symmetric encryption did not return two components");
    }
    ciphertext->SetEncodingType(INVALID_ENCODING);
    ciphertext->SetScalingFactor(1.0);
    ciphertext->SetScalingFactorInt(NativeInteger(1));
    ciphertext->SetNoiseScaleDeg(1);
    ciphertext->SetSlots(0);
    const auto towerCount = TowerCount(ciphertext);
    if (towerCount == 0) {
        throw GLShipStateError("GL SHIP symmetric encryption returned no RNS towers");
    }
    const auto levelsToDrop = towerCount - 1;
    m_context->GetScheme()->LevelReduceInternalInPlace(ciphertext, levelsToDrop);
    if (TowerCount(ciphertext) != 1) {
        throw GLShipStateError("GL SHIP failed to reduce the input to one q0 tower");
    }

    GLShipLowSliceCiphertext result(
        m_geometry.GetDimension(), clientMaterial.m_evaluationKey.GetBottomModulus(),
        m_context, std::move(ciphertext));
    ValidateLowSlice(result, clientMaterial.m_evaluationKey);
    return result;
}

void GLShipSchemelet::ValidateEvaluationKey(
    const GLShipEvaluationKey& evaluationKey) const {
    if (!evaluationKey.m_context || evaluationKey.m_context.get() != m_context.get()) {
        throw GLContextMismatchError("GL SHIP evaluation key belongs to another context");
    }
    if (evaluationKey.m_parameters.dimension != m_parameters.dimension ||
        evaluationKey.m_parameters.hammingWeight != m_parameters.hammingWeight ||
        evaluationKey.m_parameters.gamma != m_parameters.gamma ||
        evaluationKey.m_parameters.reservedLevels != m_parameters.reservedLevels ||
        evaluationKey.m_parameters.selection != m_parameters.selection ||
        evaluationKey.m_parameters.coarseBlockSize != m_parameters.coarseBlockSize ||
        !SameCoarseWindows(evaluationKey.m_parameters.coarseWindows,
                           m_parameters.coarseWindows)) {
        throw GLShipEvaluationKeyError("GL SHIP evaluation-key parameters do not match");
    }
    if (evaluationKey.m_q0 != BottomModulus(m_context) ||
        evaluationKey.m_sparseKeyTag.empty() || evaluationKey.m_primaryKeyTag.empty()) {
        throw GLShipEvaluationKeyError("GL SHIP evaluation-key modulus or key tags are invalid");
    }
    const auto ckksParameters = GetCKKSParameters(m_context);
    const auto auxiliaryParameters = ckksParameters->GetParamsP();
    if (!auxiliaryParameters || auxiliaryParameters->GetParams().empty()) {
        throw GLShipEvaluationKeyError("GL SHIP auxiliary P parameters are missing");
    }
    const auto& q0Parameters =
        ckksParameters->GetElementParams()->GetParams().front();
    const auto& p0Parameters = auxiliaryParameters->GetParams().front();
    const auto hasExactBottomSwitchBasis =
        [&](const DCRTPoly& element) {
            if (element.GetFormat() != Format::EVALUATION ||
                element.GetNumOfElements() != 2 ||
                element.GetRingDimension() != q0Parameters->GetRingDimension() ||
                element.GetCyclotomicOrder() != q0Parameters->GetCyclotomicOrder()) {
                return false;
            }
            const auto towerMatches = [](const auto& tower, const auto& expected) {
                return tower.GetFormat() == Format::EVALUATION &&
                       tower.GetRingDimension() == expected->GetRingDimension() &&
                       tower.GetCyclotomicOrder() == expected->GetCyclotomicOrder() &&
                       tower.GetModulus() == expected->GetModulus() &&
                       tower.GetRootOfUnity() == expected->GetRootOfUnity();
            };
            return towerMatches(element.GetElementAtIndex(0), q0Parameters) &&
                   towerMatches(element.GetElementAtIndex(1), p0Parameters);
        };
    if (!evaluationKey.m_bottomPrimaryToSparseKey ||
        evaluationKey.m_bottomPrimaryToSparseKey->GetCryptoContext().get() != m_context.get() ||
        evaluationKey.m_bottomPrimaryToSparseKey->GetKeyTag() !=
            evaluationKey.m_sparseKeyTag ||
        evaluationKey.m_bottomPrimaryToSparseKey->GetAVector().size() != 1 ||
        evaluationKey.m_bottomPrimaryToSparseKey->GetBVector().size() != 1 ||
        !hasExactBottomSwitchBasis(
            evaluationKey.m_bottomPrimaryToSparseKey->GetAVector().front()) ||
        !hasExactBottomSwitchBasis(
            evaluationKey.m_bottomPrimaryToSparseKey->GetBVector().front()) ||
        ToUint64(q0Parameters->GetModulus()) != evaluationKey.m_q0) {
        throw GLShipEvaluationKeyError(
            "GL SHIP primary-to-sparse switch is not restricted to exactly q0*p0");
    }
    const bool hybrid =
        m_parameters.selection == GLShipSelection::HYBRID_MASKED_COLUMN;
    const auto expectedSelectors =
        ExpectedCoarseSelectorCount(m_parameters, m_geometry.GetDimension());
    if (evaluationKey.m_selectors.size() != expectedSelectors) {
        // A 2*h*n direct bank presented to a hybrid schemelet (or any
        // window/theta mismatch that survives the fingerprint) fails here.
        throw GLShipEvaluationKeyError(
            hybrid ? "GL SHIP hybrid coarse selector bank has the wrong size"
                   : "GL SHIP direct-column selector bank has the wrong size");
    }
    const auto fullTowerCount =
        ckksParameters->GetElementParams()->GetParams().size();
    const auto selectorScalingFactor = ckksParameters->GetScalingFactorReal(0);
    const auto selectorMetadataIsValid = [&](const Ciphertext<DCRTPoly>& selector) {
        return selector && selector->GetCryptoContext().get() == m_context.get() &&
               selector->GetKeyTag() == evaluationKey.m_primaryKeyTag &&
               selector->NumberCiphertextElements() == 2 && selector->GetLevel() == 0 &&
               selector->GetEncodingType() == CKKS_PACKED_ENCODING &&
               selector->GetSlots() == m_geometry.GetDimension() &&
               selector->GetNoiseScaleDeg() == 1 &&
               selector->GetScalingFactor() == selectorScalingFactor &&
               selector->GetScalingFactorInt() == NativeInteger(1) &&
               TowerCount(selector) == fullTowerCount &&
               selector->GetElements()[1].GetNumOfElements() == fullTowerCount;
    };
    for (const auto& selector : evaluationKey.m_selectors) {
        if (!selectorMetadataIsValid(selector)) {
            throw GLShipEvaluationKeyError("GL SHIP selector metadata is invalid");
        }
    }
    if (!hybrid) {
        if (!evaluationKey.m_fineSelectors.empty()) {
            throw GLShipEvaluationKeyError(
                "GL SHIP direct-column key must not carry hybrid fine mux material");
        }
    }
    else {
        if (evaluationKey.m_fineSelectors.size() !=
            ExpectedFineSelectorCount(m_parameters)) {
            throw GLShipEvaluationKeyError(
                "GL SHIP hybrid fine mux-key bank is missing a digit or polarity");
        }
        for (const auto& fineSelector : evaluationKey.m_fineSelectors) {
            if (!selectorMetadataIsValid(fineSelector)) {
                throw GLShipEvaluationKeyError(
                    "GL SHIP hybrid fine mux-key metadata is invalid");
            }
        }
    }
    if (evaluationKey.m_relinearizationKeys.empty()) {
        throw GLShipEvaluationKeyError("GL SHIP primary relinearization key is missing");
    }
    for (const auto& relinearizationKey : evaluationKey.m_relinearizationKeys) {
        if (!relinearizationKey ||
            relinearizationKey->GetCryptoContext().get() != m_context.get() ||
            relinearizationKey->GetKeyTag() != evaluationKey.m_primaryKeyTag) {
            throw GLShipEvaluationKeyError("GL SHIP primary relinearization key is invalid");
        }
    }
    const uint32_t conjugationIndex = static_cast<uint32_t>(m_context->GetCyclotomicOrder() - 1);
    if (!evaluationKey.m_conjugationKeys ||
        evaluationKey.m_conjugationKeys->find(conjugationIndex) ==
            evaluationKey.m_conjugationKeys->end() ||
        !evaluationKey.m_conjugationKeys->at(conjugationIndex) ||
        evaluationKey.m_conjugationKeys->at(conjugationIndex)->GetCryptoContext().get() !=
            m_context.get() ||
        evaluationKey.m_conjugationKeys->at(conjugationIndex)->GetKeyTag() !=
            evaluationKey.m_primaryKeyTag) {
        throw GLShipEvaluationKeyError("GL SHIP conjugation key is missing or invalid");
    }
    if (!evaluationKey.m_xForwardKeys) {
        throw GLShipEvaluationKeyError("GL SHIP X-forward rotation-key map is missing");
    }
    const auto cyclotomicOrder = static_cast<uint32_t>(m_context->GetCyclotomicOrder());
    for (const auto rotation :
         RequiredXForwardRotations(m_parameters, m_geometry.GetDimension())) {
        const auto automorphismIndex = m_context->GetScheme()->FindAutomorphismIndex(
            static_cast<uint32_t>(rotation), cyclotomicOrder);
        const auto found = evaluationKey.m_xForwardKeys->find(automorphismIndex);
        if (found == evaluationKey.m_xForwardKeys->end() || !found->second ||
            found->second->GetCryptoContext().get() != m_context.get() ||
            found->second->GetKeyTag() != evaluationKey.m_primaryKeyTag) {
            throw GLShipEvaluationKeyError(
                "GL SHIP X-forward rotation key is missing or invalid");
        }
    }
}

void GLShipSchemelet::ValidateLowSlice(
    const GLShipLowSliceCiphertext& input,
    const GLShipEvaluationKey& evaluationKey) const {
    if (input.m_representation != GLShipRepresentation::POST_XINV_COEFFICIENT) {
        throw GLShipStateError("GL SHIP input is not in post-XInv coefficient state");
    }
    if (input.m_dimension != m_geometry.GetDimension() || !input.m_context ||
        input.m_context.get() != m_context.get() || !input.m_ciphertext ||
        input.m_ciphertext->GetCryptoContext().get() != m_context.get()) {
        throw GLContextMismatchError("GL SHIP low slice geometry or context does not match");
    }
    if (input.m_ciphertext->NumberCiphertextElements() != 2) {
        throw GLShipStateError("GL SHIP low slice must have exactly two components");
    }
    const auto ckksParameters = GetCKKSParameters(m_context);
    const auto& q0Parameters =
        ckksParameters->GetElementParams()->GetParams().front();
    const auto componentIsExactQ0 = [&](const DCRTPoly& component) {
        if (component.GetFormat() != Format::EVALUATION ||
            component.GetNumOfElements() != 1 ||
            component.GetRingDimension() != q0Parameters->GetRingDimension() ||
            component.GetCyclotomicOrder() != q0Parameters->GetCyclotomicOrder()) {
            return false;
        }
        const auto& tower = component.GetElementAtIndex(0);
        return tower.GetFormat() == Format::EVALUATION &&
               tower.GetRingDimension() == q0Parameters->GetRingDimension() &&
               tower.GetCyclotomicOrder() == q0Parameters->GetCyclotomicOrder() &&
               tower.GetModulus() == q0Parameters->GetModulus() &&
               tower.GetRootOfUnity() == q0Parameters->GetRootOfUnity();
    };
    const auto fullTowerCount =
        ckksParameters->GetElementParams()->GetParams().size();
    if (TowerCount(input.m_ciphertext) != 1 ||
        !std::all_of(input.m_ciphertext->GetElements().begin(),
                     input.m_ciphertext->GetElements().end(), componentIsExactQ0) ||
        input.m_ciphertext->GetLevel() != fullTowerCount - 1) {
        throw GLShipStateError(
            "GL SHIP low slice must contain two exact evaluation-format q0 components");
    }
    if (input.m_ciphertext->GetEncodingType() != INVALID_ENCODING ||
        input.m_ciphertext->GetNoiseScaleDeg() != 1 ||
        input.m_ciphertext->GetScalingFactor() != 1.0 ||
        input.m_ciphertext->GetScalingFactorInt() != NativeInteger(1) ||
        input.m_ciphertext->GetSlots() != 0) {
        throw GLShipStateError("GL SHIP low slice raw-coefficient metadata is invalid");
    }
    if (input.m_q0 != evaluationKey.m_q0 || input.m_q0 != BottomModulus(m_context)) {
        throw GLShipStateError("GL SHIP low slice q0 does not match the evaluation key");
    }
    if (ToUint64(q0Parameters->GetModulus()) != input.m_q0) {
        throw GLShipStateError("GL SHIP low slice retained the wrong RNS tower");
    }
    if (input.m_ciphertext->GetKeyTag().empty() ||
        input.m_ciphertext->GetKeyTag() != evaluationKey.m_sparseKeyTag) {
        throw GLKeyMismatchError("GL SHIP low slice is not under the expected sparse key");
    }
}

// Everything until GL_SHIP_EVALUATOR_END is evaluator-side code.  Static
// trust-boundary audits forbid private-key access and decryption in this span.
// GL_SHIP_EVALUATOR_BEGIN

/**
 * One hybrid masked-column leaf (GL_bootstrap Alg. 3 lines 10-11).
 *
 * Coarse stage: the (block, sign) one-hot bank of this support ordinal is
 * accumulated against the two input-specific public lane tables
 * u = omega^{Re G} and v = omega^{Re iG}, G = sigma A^{(b)} X^{theta j1},
 * in one level.  Fine stage: for each binary digit of alpha0 (LSB first) the
 * three mask-fused encrypted pieces PH/PL/NG drive a full mux over the
 * slot-rotated frontiers with the exact X^n = i wrap law
 *   U' = PH*Rot(U) + PL*Rot(V) + NG*U
 *   V' = PH*Rot(V) + PL*conj(Rot(U)) + NG*V
 * at one relinearized ct*ct level per digit; the final digit updates only U.
 * The op sequence never branches on secret data: identical circuits for all
 * key contents.  Frontiers and the returned leaf are derived intermediates
 * (JIT premux) -- they are consumed by the caller's product tree and never
 * serialized or cached.
 */
Ciphertext<DCRTPoly> GLShipSchemelet::EvalHybridLeaf(
    const std::vector<GLShipGaussianInteger>& branchA, std::size_t supportOrdinal,
    const GLShipEvaluationKey& evaluationKey) const {
    const auto n = m_geometry.GetDimension();
    const auto theta = m_parameters.coarseBlockSize;
    const auto digits = CeilLog2(theta);
    const auto window = CoarseWindowOf(m_parameters, n, supportOrdinal);

    // Coarse masked-column accumulation over both factor lanes.  The lane
    // tables are produced just in time from the public branch component and
    // discarded with this scope.
    Ciphertext<DCRTPoly> laneU;
    Ciphertext<DCRTPoly> laneV;
    for (uint32_t offset = 0; offset < window.second; ++offset) {
        const uint32_t block = window.first + offset;
        for (const int8_t sign : {int8_t(-1), int8_t(1)}) {
            const auto shifted = GLShipAlgebra::MultiplyMonomial(
                branchA, static_cast<uint32_t>(theta) * block, sign);
            const auto shiftedTimesI = GLShipAlgebra::MultiplyGaussianI(shifted);
            std::vector<std::complex<double>> uTable(n);
            std::vector<std::complex<double>> vTable(n);
            for (std::size_t coefficient = 0; coefficient < n; ++coefficient) {
                uTable[coefficient] =
                    RootOfUnity(evaluationKey.m_q0, shifted[coefficient].real());
                vTable[coefficient] =
                    RootOfUnity(evaluationKey.m_q0, shiftedTimesI[coefficient].real());
            }
            auto uPlaintext = m_context->MakeCKKSPackedPlaintext(
                uTable, 1, 0, nullptr, static_cast<uint32_t>(n));
            auto vPlaintext = m_context->MakeCKKSPackedPlaintext(
                vTable, 1, 0, nullptr, static_cast<uint32_t>(n));
            if (!uPlaintext || !vPlaintext) {
                throw GLShipStateError("GL SHIP failed to encode a hybrid coarse lane table");
            }
            const auto selectorIndex = CoarseSelectorIndex(supportOrdinal, offset, sign);
            auto uTerm = m_context->EvalMult(
                evaluationKey.m_selectors[selectorIndex], uPlaintext);
            auto vTerm = m_context->EvalMult(
                evaluationKey.m_selectors[selectorIndex], vPlaintext);
            if (!uTerm || !vTerm) {
                throw GLShipStateError("GL SHIP hybrid coarse selector product failed");
            }
            if (laneU) {
                m_context->EvalAddInPlace(laneU, uTerm);
                m_context->EvalAddInPlace(laneV, vTerm);
            }
            else {
                laneU = std::move(uTerm);
                laneV = std::move(vTerm);
            }
        }
    }
    if (!laneU || !laneV) {
        throw GLShipStateError(
            "GL SHIP hybrid coarse accumulation did not finish at level one");
    }
    ModReduceOneLevel(m_context, laneU, "GL SHIP hybrid coarse lane");
    ModReduceOneLevel(m_context, laneV, "GL SHIP hybrid coarse lane");
    if (laneU->GetLevel() != 1 || laneV->GetLevel() != 1) {
        throw GLShipStateError(
            "GL SHIP hybrid coarse accumulation did not finish at level one");
    }

    // Fine binary digit chain, LSB first, one level per digit.
    const uint32_t conjugationIndex =
        static_cast<uint32_t>(m_context->GetCyclotomicOrder() - 1);
    for (uint32_t digit = 0; digit < digits; ++digit) {
        const std::size_t delta = std::size_t{1} << digit;
        const uint32_t frontierLevel = 1 + digit;
        const bool finalDigit = digit + 1 == digits;

        // Rot_{-delta} = Rot_{n-delta} through the owned X-forward family
        // (5^n == 1 mod 4n, so left rotation by n-delta is the inverse).
        auto rotatedU = m_context->GetScheme()->EvalAtIndex(
            laneU, static_cast<uint32_t>(n - delta), *evaluationKey.m_xForwardKeys);
        auto rotatedV = m_context->GetScheme()->EvalAtIndex(
            laneV, static_cast<uint32_t>(n - delta), *evaluationKey.m_xForwardKeys);
        if (!rotatedU || !rotatedV) {
            throw GLShipStateError("GL SHIP hybrid fine rotation failed");
        }
        Ciphertext<DCRTPoly> conjugatedRotatedU;
        if (!finalDigit) {
            conjugatedRotatedU = m_context->EvalAutomorphism(
                rotatedU, conjugationIndex, *evaluationKey.m_conjugationKeys);
            if (!conjugatedRotatedU) {
                throw GLShipStateError("GL SHIP hybrid fine conjugation failed");
            }
        }

        // Fresh level-0 digit keys ride the same tower-drop alignment the
        // tree odd-carry already relies on.
        auto rotateHigh =
            evaluationKey.m_fineSelectors[FineSelectorIndex(supportOrdinal, digit, 0)]->Clone();
        auto rotateLow =
            evaluationKey.m_fineSelectors[FineSelectorIndex(supportOrdinal, digit, 1)]->Clone();
        auto identityPiece =
            evaluationKey.m_fineSelectors[FineSelectorIndex(supportOrdinal, digit, 2)]->Clone();
        DropCiphertextToLevel(rotateHigh, frontierLevel);
        DropCiphertextToLevel(rotateLow, frontierLevel);
        DropCiphertextToLevel(identityPiece, frontierLevel);

        const auto muxTerm = [&](const Ciphertext<DCRTPoly>& piece,
                                 const Ciphertext<DCRTPoly>& operand) {
            auto product = m_context->GetScheme()->EvalMultAndRelinearize(
                piece, operand, evaluationKey.m_relinearizationKeys);
            if (!product || product->NumberCiphertextElements() != 2) {
                throw GLShipStateError("GL SHIP hybrid fine mux product failed");
            }
            return product;
        };

        auto nextU = muxTerm(rotateHigh, rotatedU);
        m_context->EvalAddInPlace(nextU, muxTerm(rotateLow, rotatedV));
        m_context->EvalAddInPlace(nextU, muxTerm(identityPiece, laneU));
        ModReduceOneLevel(m_context, nextU, "GL SHIP hybrid fine digit");
        if (!finalDigit) {
            auto nextV = muxTerm(rotateHigh, rotatedV);
            m_context->EvalAddInPlace(nextV, muxTerm(rotateLow, conjugatedRotatedU));
            m_context->EvalAddInPlace(nextV, muxTerm(identityPiece, laneV));
            ModReduceOneLevel(m_context, nextV, "GL SHIP hybrid fine digit");
            laneV = std::move(nextV);
        }
        laneU = std::move(nextU);
    }
    if (!laneU || laneU->NumberCiphertextElements() != 2 ||
        laneU->GetLevel() != 1 + digits) {
        throw GLShipStateError("GL SHIP hybrid leaf did not finish at its digit-chain level");
    }
    return laneU;
}

GLShipHalfBootstrapResult GLShipSchemelet::EvalHalfBootstrap(
    const GLShipLowSliceCiphertext& input,
    const GLShipEvaluationKey& evaluationKey) const {
    ValidateEvaluationKey(evaluationKey);
    return EvalHalfBootstrapValidated(input, evaluationKey);
}

GLShipHalfBootstrapResult GLShipSchemelet::EvalHalfBootstrapValidated(
    const GLShipLowSliceCiphertext& input,
    const GLShipEvaluationKey& evaluationKey) const {
    ValidateLowSlice(input, evaluationKey);

    const auto n = m_geometry.GetDimension();
    const auto& elements = input.m_ciphertext->GetElements();
    const auto b = ToGaussian(CenteredCoefficients(elements[0], evaluationKey.m_q0, 2 * n), n);
    const auto a = ToGaussian(CenteredCoefficients(elements[1], evaluationKey.m_q0, 2 * n), n);
    const std::vector<std::vector<GLShipGaussianInteger>> branchB = {
        b, MultiplyByNegativeGaussianI(b)};
    const std::vector<std::vector<GLShipGaussianInteger>> branchA = {
        a, MultiplyByNegativeGaussianI(a)};
    const auto pi = std::acos(-1.0);
    const std::complex<double> shipScale(0.0, -m_parameters.gamma / (4.0 * pi));

    const bool hybrid =
        m_parameters.selection == GLShipSelection::HYBRID_MASKED_COLUMN;
    std::vector<Ciphertext<DCRTPoly>> branchReturns;
    branchReturns.reserve(2);
    for (std::size_t branch = 0; branch < 2; ++branch) {
        std::vector<Ciphertext<DCRTPoly>> leaves;
        leaves.reserve(m_parameters.hammingWeight);
        if (!hybrid) {
            for (std::size_t ordinal = 0; ordinal < m_parameters.hammingWeight; ++ordinal) {
                Ciphertext<DCRTPoly> accumulated;
                for (std::size_t alpha = 0; alpha < n; ++alpha) {
                    for (const int8_t sign : {int8_t(-1), int8_t(1)}) {
                        const auto shifted = GLShipAlgebra::MultiplyMonomial(
                            branchA[branch], static_cast<uint32_t>(alpha), sign);
                        std::vector<std::complex<double>> factors(n);
                        for (std::size_t coefficient = 0; coefficient < n; ++coefficient) {
                            const int64_t exponent = shifted[coefficient].real();
                            factors[coefficient] = RootOfUnity(evaluationKey.m_q0, exponent);
                            if (ordinal == 0) {
                                const int64_t baseExponent = branchB[branch][coefficient].real();
                                factors[coefficient] *=
                                    shipScale * RootOfUnity(evaluationKey.m_q0, baseExponent);
                            }
                        }
                        auto plaintext = m_context->MakeCKKSPackedPlaintext(
                            factors, 1, 0, nullptr, static_cast<uint32_t>(n));
                        if (!plaintext) {
                            throw GLShipStateError("GL SHIP failed to encode a root-factor table");
                        }
                        const auto selectorIndex = SelectorIndex(ordinal, alpha, sign);
                        auto term = m_context->EvalMult(
                            evaluationKey.m_selectors[selectorIndex], plaintext);
                        if (!term) {
                            throw GLShipStateError("GL SHIP selector/plaintext product failed");
                        }
                        if (accumulated) {
                            m_context->EvalAddInPlace(accumulated, term);
                        }
                        else {
                            accumulated = std::move(term);
                        }
                    }
                }
                if (!accumulated) {
                    throw GLShipStateError("GL SHIP produced an empty direct-column leaf");
                }
                auto leaf = accumulated;
                ModReduceOneLevel(m_context, leaf, "GL SHIP direct-column leaf");
                if (!leaf || leaf->NumberCiphertextElements() != 2) {
                    throw GLShipStateError("GL SHIP direct-column leaf rescale failed");
                }
                if (leaf->GetLevel() != 1) {
                    throw GLShipStateError("GL SHIP direct-column leaf did not finish at level one");
                }
                leaves.push_back(std::move(leaf));
            }
        }
        else {
            // Hybrid leaves cannot fuse the base: a slot-indexed base factor
            // baked into the coarse tables would migrate under the secret
            // fine rotation with no public correction.  The base therefore
            // enters the balanced tree as its own plaintext node 0 (SHIP
            // Algorithm 1's pt_0), and the tree reduces h+1 nodes.
            for (std::size_t ordinal = 0; ordinal < m_parameters.hammingWeight; ++ordinal) {
                leaves.push_back(EvalHybridLeaf(branchA[branch], ordinal, evaluationKey));
            }
            const uint32_t leafLevel = 1 + CeilLog2(m_parameters.coarseBlockSize);
            std::vector<std::complex<double>> baseFactors(n);
            for (std::size_t coefficient = 0; coefficient < n; ++coefficient) {
                const int64_t baseExponent = branchB[branch][coefficient].real();
                baseFactors[coefficient] =
                    shipScale * RootOfUnity(evaluationKey.m_q0, baseExponent);
            }
            auto basePlaintext = m_context->MakeCKKSPackedPlaintext(
                baseFactors, 1, leafLevel, nullptr, static_cast<uint32_t>(n));
            if (!basePlaintext) {
                throw GLShipStateError("GL SHIP failed to encode the hybrid base table");
            }
            // First tree round with the base as node 0: pair (0,1) is the
            // plaintext-ciphertext product, the remaining pairs are ordinary
            // relinearized products, and an odd tail node is carried.
            auto baseProduct = m_context->EvalMult(leaves.front(), basePlaintext);
            if (!baseProduct) {
                throw GLShipStateError("GL SHIP hybrid base product failed");
            }
            ModReduceOneLevel(m_context, baseProduct, "GL SHIP hybrid base product");
            if (!baseProduct || baseProduct->NumberCiphertextElements() != 2) {
                throw GLShipStateError("GL SHIP hybrid base product rescale failed");
            }
            const uint32_t roundLevel = baseProduct->GetLevel();
            std::vector<Ciphertext<DCRTPoly>> nodes;
            nodes.reserve(leaves.size() / 2 + 1);
            nodes.push_back(std::move(baseProduct));
            std::size_t index = 1;
            for (; index + 1 < leaves.size(); index += 2) {
                auto product = m_context->GetScheme()->EvalMultAndRelinearize(
                    leaves[index], leaves[index + 1],
                    evaluationKey.m_relinearizationKeys);
                if (!product || product->NumberCiphertextElements() != 2) {
                    throw GLShipStateError("GL SHIP balanced product/relinearization failed");
                }
                ModReduceOneLevel(m_context, product, "GL SHIP balanced product");
                if (!product || product->NumberCiphertextElements() != 2) {
                    throw GLShipStateError("GL SHIP balanced product rescale failed");
                }
                nodes.push_back(std::move(product));
            }
            if (index < leaves.size()) {
                auto carry = leaves[index]->Clone();
                DropCiphertextToLevel(carry, roundLevel);
                nodes.push_back(std::move(carry));
            }
            leaves = std::move(nodes);
        }

        while (leaves.size() > 1) {
            std::vector<Ciphertext<DCRTPoly>> next;
            next.reserve((leaves.size() + 1) / 2);
            uint32_t nextLevel = 0;
            bool hasProduct = false;
            std::size_t index = 0;
            for (; index + 1 < leaves.size(); index += 2) {
                auto product = m_context->GetScheme()->EvalMultAndRelinearize(
                    leaves[index], leaves[index + 1],
                    evaluationKey.m_relinearizationKeys);
                if (!product || product->NumberCiphertextElements() != 2) {
                    throw GLShipStateError("GL SHIP balanced product/relinearization failed");
                }
                ModReduceOneLevel(m_context, product, "GL SHIP balanced product");
                if (!product || product->NumberCiphertextElements() != 2) {
                    throw GLShipStateError("GL SHIP balanced product rescale failed");
                }
                nextLevel = product->GetLevel();
                hasProduct = true;
                next.push_back(std::move(product));
            }
            if (index < leaves.size()) {
                auto carry = leaves[index]->Clone();
                if (hasProduct) {
                    DropCiphertextToLevel(carry, nextLevel);
                }
                next.push_back(std::move(carry));
            }
            leaves = std::move(next);
        }

        auto phase = leaves.front();
        const uint32_t expectedPhaseLevel =
            hybrid ? 1 + CeilLog2(m_parameters.coarseBlockSize) +
                         CeilLog2(m_parameters.hammingWeight + 1)
                   : 1 + CeilLog2(m_parameters.hammingWeight);
        const auto fullTowerCount =
            GetCKKSParameters(m_context)->GetElementParams()->GetParams().size();
        if (phase->GetLevel() != expectedPhaseLevel ||
            TowerCount(phase) != fullTowerCount - expectedPhaseLevel) {
            throw GLShipStateError("GL SHIP product tree consumed an unexpected level budget");
        }
        const uint32_t conjugationIndex =
            static_cast<uint32_t>(m_context->GetCyclotomicOrder() - 1);
        auto conjugate = m_context->EvalAutomorphism(
            phase, conjugationIndex, *evaluationKey.m_conjugationKeys);
        auto realReturn = m_context->EvalAdd(phase, conjugate);
        if (!realReturn || realReturn->NumberCiphertextElements() != 2) {
            throw GLShipStateError("GL SHIP conjugation-add branch return failed");
        }
        branchReturns.push_back(std::move(realReturn));
    }

    auto imaginaryReturn = branchReturns[1]->Clone();
    MultiplyCiphertextByGaussianI(imaginaryReturn, n);
    auto output = m_context->EvalAdd(branchReturns[0], imaginaryReturn);
    if (!output || output->NumberCiphertextElements() != 2 ||
        output->GetKeyTag() != evaluationKey.m_primaryKeyTag ||
        output->GetEncodingType() != CKKS_PACKED_ENCODING) {
        throw GLShipStateError("GL SHIP recombination did not produce a primary-key ciphertext");
    }
    if (TowerCount(output) <= TowerCount(input.m_ciphertext)) {
        throw GLShipStateError("GL SHIP half-bootstrap did not renew the input modulus");
    }
    if (TowerCount(output) <= static_cast<std::size_t>(m_parameters.reservedLevels) + 1) {
        throw GLShipStateError(
            "GL SHIP result did not preserve XFwd plus the reserved post-operation budget");
    }
    DCRTPoly zero(output->GetElements()[1].GetParams(), Format::EVALUATION, true);
    if (output->GetElements()[1] == zero) {
        throw GLShipStateError("GL SHIP rejected a transparent a=0 output");
    }
    return GLShipHalfBootstrapResult(n, m_context, std::move(output));
}

GLShipLowSliceCiphertext GLShipSchemelet::NormalizeAndSwitchRow(
    const Ciphertext<DCRTPoly>& input, const GLShipEvaluationKey& evaluationKey,
    std::size_t row) const {
    if (!input) {
        throw GLMissingRowError("GL RefreshOnly received a null row");
    }
    if (input->GetCryptoContext().get() != m_context.get()) {
        throw GLContextMismatchError("GL RefreshOnly row belongs to another context");
    }
    if (input->GetKeyTag() != evaluationKey.m_primaryKeyTag) {
        throw GLKeyMismatchError("GL RefreshOnly row is not under the primary key");
    }
    if (input->NumberCiphertextElements() != 2 ||
        input->GetEncodingType() != CKKS_PACKED_ENCODING ||
        input->GetSlots() != m_geometry.GetDimension()) {
        throw GLShipStateError("GL RefreshOnly row is not a canonical two-component GL row");
    }
    if (input->GetNoiseScaleDeg() != 1 || !std::isfinite(input->GetScalingFactor()) ||
        input->GetScalingFactor() <= 0.0 ||
        input->GetScalingFactorInt() != NativeInteger(1)) {
        throw GLShipStateError(
            "GL RefreshOnly requires a finite degree-one CKKS input scale");
    }
    const auto fullTowerCount =
        GetCKKSParameters(m_context)->GetElementParams()->GetParams().size();
    const auto inputTowerCount = TowerCount(input);
    const auto componentsAreCanonical = std::all_of(
        input->GetElements().begin(), input->GetElements().end(),
        [inputTowerCount](const DCRTPoly& component) {
            return component.GetFormat() == Format::EVALUATION &&
                   component.GetNumOfElements() == inputTowerCount;
        });
    if (inputTowerCount < 2 || inputTowerCount > fullTowerCount ||
        input->GetLevel() != fullTowerCount - inputTowerCount ||
        !componentsAreCanonical) {
        throw GLShipStateError(
            "GL RefreshOnly requires canonical level metadata and at least two aligned evaluation-format towers");
    }

    auto normalized = input->Clone();
    const auto levelsToDrop = TowerCount(normalized) - 2;
    if (levelsToDrop != 0) {
        m_context->GetScheme()->LevelReduceInternalInPlace(normalized, levelsToDrop);
    }
    if (TowerCount(normalized) != 2 || normalized->GetNoiseScaleDeg() != 1) {
        throw GLShipStateError("GL RefreshOnly failed to isolate the q0*q1 normalization basis");
    }

    const auto q0 = ToUint64(
        normalized->GetElements().front().GetElementAtIndex(0).GetModulus());
    const auto q1 = ToUint64(
        normalized->GetElements().front().GetElementAtIndex(1).GetModulus());
    if (q0 != evaluationKey.m_q0 || q1 == 0) {
        throw GLShipStateError("GL RefreshOnly normalization retained the wrong RNS basis");
    }

    // In this exact-ring codec, the backing polynomial of a canonical row is
    // already psi(XInv(row slots)).  If its current physical scale is S, an
    // integer plaintext multiplier K followed by division by q1 must satisfy
    //
    //     S*K/q1 ~= q0/gamma.
    //
    // EvalMult(double) materializes round(operand*SF_level), so choose operand
    // such that the materialized integer is exactly K and verify that property.
    const long double sourceScale = normalized->GetScalingFactor();
    const long double idealMultiplier =
        static_cast<long double>(q0) * static_cast<long double>(q1) /
        (static_cast<long double>(m_parameters.gamma) * sourceScale);
    constexpr uint64_t kMaxExactlyRepresentableDoubleInteger = uint64_t{1} << 52;
    if (!std::isfinite(static_cast<double>(idealMultiplier)) || idealMultiplier < 1.0L ||
        idealMultiplier > static_cast<long double>(kMaxExactlyRepresentableDoubleInteger)) {
        std::ostringstream os;
        os << "GL RefreshOnly row " << row
           << " cannot realize q0/gamma with an exact scalar multiplier";
        throw GLShipStateError(os.str());
    }
    const auto integerMultiplier = static_cast<uint64_t>(std::llround(idealMultiplier));
    const auto ckksParameters = GetCKKSParameters(m_context);
    const double plaintextScale =
        ckksParameters->GetScalingFactorReal(normalized->GetLevel());
    if (!std::isfinite(plaintextScale) || plaintextScale <= 0.0) {
        throw GLShipStateError("GL RefreshOnly could not obtain its normalization plaintext scale");
    }
    const double scalar = static_cast<double>(integerMultiplier) / plaintextScale;
    if (!std::isfinite(scalar) || scalar <= 0.0 ||
        static_cast<uint64_t>(std::llround(scalar * plaintextScale)) != integerMultiplier) {
        throw GLShipStateError("GL RefreshOnly scalar cannot materialize the required exact integer");
    }

    m_context->EvalMultInPlace(normalized, scalar);
    if (normalized->GetNoiseScaleDeg() != 2 || TowerCount(normalized) != 2) {
        throw GLShipStateError("GL RefreshOnly normalization multiplication changed an unexpected state");
    }
    ModReduceOneLevel(m_context, normalized, "GL RefreshOnly q0/gamma normalization");
    if (TowerCount(normalized) != 1) {
        throw GLShipStateError("GL RefreshOnly normalization did not finish at q0");
    }

    const long double realizedPhysicalScale =
        sourceScale * static_cast<long double>(integerMultiplier) /
        static_cast<long double>(q1);
    const long double targetPhysicalScale =
        static_cast<long double>(q0) / static_cast<long double>(m_parameters.gamma);
    const long double relativeScaleError =
        std::abs(realizedPhysicalScale - targetPhysicalScale) / targetPhysicalScale;
    if (relativeScaleError > 1.0e-10L) {
        throw GLShipStateError("GL RefreshOnly q0/gamma normalization is outside tolerance");
    }

    normalized->SetEncodingType(INVALID_ENCODING);
    normalized->SetScalingFactor(1.0);
    normalized->SetScalingFactorInt(NativeInteger(1));
    normalized->SetNoiseScaleDeg(1);
    normalized->SetSlots(0);

    auto switched = FHECKKSRNS::KeySwitchSparse(
        normalized, evaluationKey.m_bottomPrimaryToSparseKey);
    if (!switched || switched->NumberCiphertextElements() != 2) {
        throw GLShipStateError("GL RefreshOnly q0*P primary-to-sparse switch failed");
    }
    switched->SetKeyTag(evaluationKey.m_sparseKeyTag);
    switched->SetEncodingType(INVALID_ENCODING);
    switched->SetScalingFactor(1.0);
    switched->SetScalingFactorInt(NativeInteger(1));
    switched->SetNoiseScaleDeg(1);
    switched->SetSlots(0);

    GLShipLowSliceCiphertext result(m_geometry.GetDimension(), evaluationKey.m_q0,
                                    m_context, std::move(switched));
    ValidateLowSlice(result, evaluationKey);
    return result;
}

std::vector<Plaintext> GLShipSchemelet::MakeXForwardDiagonals(
    uint32_t level) const {
    const auto n = m_geometry.GetDimension();
    const auto order = m_geometry.GetNativeCyclotomicOrder();
    const auto babyStep = static_cast<std::size_t>(
        std::ceil(std::sqrt(static_cast<double>(n))));
    const long double pi = std::acos(-1.0L);
    std::vector<std::complex<long double>> roots(n);
    std::size_t exponent = 1;
    for (std::size_t slot = 0; slot < n; ++slot) {
        const long double angle = 2.0L * pi * static_cast<long double>(exponent) /
                                  static_cast<long double>(order);
        roots[slot] = std::polar(1.0L, angle);
        exponent = (exponent * 5) % order;
    }

    std::vector<Plaintext> diagonals;
    diagonals.reserve(n);
    for (std::size_t rotation = 0; rotation < n; ++rotation) {
        std::vector<std::complex<double>> diagonal(n);
        for (std::size_t slot = 0; slot < n; ++slot) {
            const auto coefficient = (slot + rotation) % n;
            const auto value = std::pow(roots[slot], static_cast<int>(coefficient));
            diagonal[slot] = {static_cast<double>(value.real()),
                              static_cast<double>(value.imag())};
        }
        // Halevi-Shoup BSGS: the outer Rot_{bj} is applied after the inner
        // sum, so pre-rotate D_{bj+i} by -bj.  OpenFHE's linear-transform
        // precomputation uses this same shifted-diagonal convention.
        const auto giantRotation = babyStep * (rotation / babyStep);
        diagonal = Rotate(diagonal, -static_cast<int32_t>(giantRotation));
        auto plaintext = m_context->MakeCKKSPackedPlaintext(
            diagonal, 1, level, nullptr, static_cast<uint32_t>(n));
        if (!plaintext) {
            throw GLShipStateError("GL XFwd BSGS diagonal encoding failed");
        }
        diagonals.push_back(std::move(plaintext));
    }
    return diagonals;
}

Ciphertext<DCRTPoly> GLShipSchemelet::EvalXForward(
    const GLShipHalfBootstrapResult& input,
    const GLShipEvaluationKey& evaluationKey,
    const std::vector<Plaintext>& diagonals) const {
    if (input.m_representation != GLShipRepresentation::X_COEFFICIENT_SLOTS ||
        input.m_dimension != m_geometry.GetDimension() || !input.m_context ||
        input.m_context.get() != m_context.get() || !input.m_ciphertext ||
        input.m_ciphertext->GetCryptoContext().get() != m_context.get()) {
        throw GLShipStateError("GL XFwd requires a matching X-coefficient-slot result");
    }
    if (input.m_ciphertext->GetKeyTag() != evaluationKey.m_primaryKeyTag ||
        input.m_ciphertext->NumberCiphertextElements() != 2 ||
        input.m_ciphertext->GetEncodingType() != CKKS_PACKED_ENCODING ||
        input.m_ciphertext->GetSlots() != m_geometry.GetDimension()) {
        throw GLShipStateError("GL XFwd input metadata or primary key is invalid");
    }
    if (TowerCount(input.m_ciphertext) <=
        static_cast<std::size_t>(m_parameters.reservedLevels) + 1) {
        throw GLDepthError("GL XFwd has no level beyond the reserved post-refresh budget");
    }

    const auto n = m_geometry.GetDimension();
    if (diagonals.size() != n ||
        std::any_of(diagonals.begin(), diagonals.end(),
                    [&](const Plaintext& diagonal) {
                        return !diagonal ||
                               diagonal->GetLevel() != input.m_ciphertext->GetLevel();
                    })) {
        throw GLShipStateError("GL XFwd BSGS diagonal bank does not match the input level");
    }

    const auto babyStep = static_cast<std::size_t>(
        std::ceil(std::sqrt(static_cast<double>(n))));
    const auto giantStep = (n + babyStep - 1) / babyStep;
    std::vector<Ciphertext<DCRTPoly>> babies;
    babies.reserve(babyStep);
    babies.push_back(input.m_ciphertext->Clone());
    for (std::size_t baby = 1; baby < babyStep; ++baby) {
        auto rotated = m_context->GetScheme()->EvalAtIndex(
            input.m_ciphertext, static_cast<uint32_t>(baby),
            *evaluationKey.m_xForwardKeys);
        if (!rotated || rotated->NumberCiphertextElements() != 2) {
            throw GLShipStateError("GL XFwd BSGS baby rotation failed");
        }
        babies.push_back(std::move(rotated));
    }

    Ciphertext<DCRTPoly> accumulated;
    for (std::size_t giant = 0; giant < giantStep; ++giant) {
        Ciphertext<DCRTPoly> inner;
        for (std::size_t baby = 0; baby < babyStep; ++baby) {
            const auto rotation = giant * babyStep + baby;
            if (rotation >= n) {
                break;
            }
            auto term = m_context->EvalMult(babies[baby], diagonals[rotation]);
            if (!term) {
                throw GLShipStateError("GL XFwd BSGS diagonal multiplication failed");
            }
            if (inner) {
                m_context->EvalAddInPlace(inner, term);
            }
            else {
                inner = std::move(term);
            }
        }
        if (!inner) {
            throw GLShipStateError("GL XFwd BSGS produced an empty giant step");
        }
        if (giant != 0) {
            inner = m_context->GetScheme()->EvalAtIndex(
                inner, static_cast<uint32_t>(giant * babyStep),
                *evaluationKey.m_xForwardKeys);
            if (!inner || inner->NumberCiphertextElements() != 2) {
                throw GLShipStateError("GL XFwd BSGS giant rotation failed");
            }
        }
        if (accumulated) {
            m_context->EvalAddInPlace(accumulated, inner);
        }
        else {
            accumulated = std::move(inner);
        }
    }
    if (!accumulated || accumulated->GetNoiseScaleDeg() != 2) {
        throw GLShipStateError("GL XFwd produced an invalid diagonal sum");
    }
    ModReduceOneLevel(m_context, accumulated, "GL XFwd diagonal transform");
    if (accumulated->NumberCiphertextElements() != 2 ||
        accumulated->GetKeyTag() != evaluationKey.m_primaryKeyTag ||
        accumulated->GetEncodingType() != CKKS_PACKED_ENCODING ||
        accumulated->GetSlots() != n ||
        TowerCount(accumulated) <= m_parameters.reservedLevels) {
        throw GLShipStateError("GL XFwd did not return a canonical row with reserved depth");
    }
    return accumulated;
}

GLCiphertext GLShipSchemelet::RefreshOnly(
    const GLCiphertext& input, const GLShipEvaluationKey& evaluationKey) const {
    ValidateEvaluationKey(evaluationKey);
    input.Validate();
    if (input.GetGeometry() != m_geometry || !input.GetCryptoContext() ||
        input.GetCryptoContext().get() != m_context.get()) {
        throw GLContextMismatchError("GL RefreshOnly input geometry or context does not match");
    }
    if (input.GetKeyTag() != evaluationKey.m_primaryKeyTag) {
        throw GLKeyMismatchError("GL RefreshOnly input is not under the evaluation key's primary key");
    }

    const auto& first = input.GetRows().front();
    const auto firstTowerCount = TowerCount(first);
    const auto firstLevel = first->GetLevel();
    const auto firstNoiseScaleDegree = first->GetNoiseScaleDeg();
    const auto firstScalingFactor = first->GetScalingFactor();
    for (std::size_t row = 0; row < input.GetRows().size(); ++row) {
        const auto& current = input.GetRows()[row];
        if (TowerCount(current) != firstTowerCount || current->GetLevel() != firstLevel ||
            current->GetNoiseScaleDeg() != firstNoiseScaleDegree ||
            current->GetScalingFactor() != firstScalingFactor ||
            current->GetElements()[1].GetNumOfElements() != firstTowerCount) {
            throw GLShipStateError("GL RefreshOnly requires aligned row levels and scales");
        }
    }

    const auto rowCount = m_geometry.GetRowCount();
    std::vector<Ciphertext<DCRTPoly>> refreshedRows(rowCount);
    const auto xForwardDiagonals = MakeXForwardDiagonals(
        SelectionEvaluationDepth(m_parameters) - 1);
    std::exception_ptr rowFailure;
#if !defined(__MINGW32__) && !defined(__MINGW64__)
    #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(rowCount))
#endif
    for (int64_t signedRow = 0; signedRow < static_cast<int64_t>(rowCount); ++signedRow) {
        const auto row = static_cast<std::size_t>(signedRow);
        try {
            const auto low = NormalizeAndSwitchRow(
                input.GetRows()[row], evaluationKey, row);
            const auto coefficientSlots =
                EvalHalfBootstrapValidated(low, evaluationKey);
            refreshedRows[row] =
                EvalXForward(coefficientSlots, evaluationKey, xForwardDiagonals);
        }
        catch (...) {
#if !defined(__MINGW32__) && !defined(__MINGW64__)
            #pragma omp critical(gl_ship_refresh_row_failure)
#endif
            {
                if (!rowFailure) {
                    rowFailure = std::current_exception();
                }
            }
        }
    }
    if (rowFailure) {
        std::rethrow_exception(rowFailure);
    }

    return GLCiphertext(m_geometry, m_context, std::move(refreshedRows));
}
// GL_SHIP_EVALUATOR_END

}  // namespace lbcrypto
