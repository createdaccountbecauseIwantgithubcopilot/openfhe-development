//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//==================================================================================

#include "scheme/gl/gl-int-production-matmul.h"

#include <algorithm>
#include <limits>
#include <map>
#include <random>
#include <set>
#include <string>
#include <tuple>
#include <utility>

namespace lbcrypto {
namespace {

using SlotKey = std::tuple<uint8_t, uint32_t, uint32_t, uint32_t>;
using EntryKey = std::tuple<uint8_t, uint8_t, uint32_t, uint32_t, uint32_t>;

bool SameParameters(const GLIntWBatchedParameters& lhs,
                    const GLIntWBatchedParameters& rhs) noexcept {
    return lhs.dimension == rhs.dimension &&
           lhs.cyclotomicPrime == rhs.cyclotomicPrime &&
           lhs.wGenerator == rhs.wGenerator &&
           lhs.plaintextModulus == rhs.plaintextModulus &&
           lhs.multiplicativeDepth == rhs.multiplicativeDepth &&
           lhs.nativeRnsWordBits == rhs.nativeRnsWordBits;
}

void RequireProductionParameters(const GLIntWBatchedParameters& parameters) {
    parameters.Validate();
    if (!parameters.IsGL128257N32Geometry() ||
        parameters.plaintextModulus != 1579009) {
        throw GLIntParameterError(
            "production encrypted matrix core requires canonical "
            "GL-128-257-N32 with t=1579009");
    }
}

bool IsValidBranch(GLIntBranch branch) noexcept {
    return branch == GLIntBranch::Plus || branch == GLIntBranch::Minus;
}

uint64_t AddMod(uint64_t lhs, uint64_t rhs, uint64_t modulus) noexcept {
    return static_cast<uint64_t>(
        (static_cast<unsigned __int128>(lhs) + rhs) % modulus);
}

uint64_t SubMod(uint64_t lhs, uint64_t rhs, uint64_t modulus) noexcept {
    return lhs >= rhs ? lhs - rhs : modulus - (rhs - lhs);
}

uint64_t MulMod(uint64_t lhs, uint64_t rhs, uint64_t modulus) noexcept {
    return static_cast<uint64_t>(
        (static_cast<unsigned __int128>(lhs) * rhs) % modulus);
}

uint64_t PowMod(uint64_t base, uint64_t exponent, uint64_t modulus) noexcept {
    uint64_t result = 1;
    while (exponent != 0) {
        if ((exponent & 1) != 0) {
            result = MulMod(result, base, modulus);
        }
        base = MulMod(base, base, modulus);
        exponent >>= 1;
    }
    return result;
}

uint64_t Canonical(int64_t value, uint64_t modulus) noexcept {
    const auto signedModulus = static_cast<int64_t>(modulus);
    const auto remainder     = value % signedModulus;
    return static_cast<uint64_t>(
        remainder < 0 ? remainder + signedModulus : remainder);
}

bool HasExactOrder(uint64_t value, uint64_t order, uint64_t modulus) {
    if (value < 2 || PowMod(value, order, modulus) != 1) {
        return false;
    }
    auto remaining = order;
    for (uint64_t factor = 2; factor * factor <= remaining; ++factor) {
        if (remaining % factor != 0) {
            continue;
        }
        if (PowMod(value, order / factor, modulus) == 1) {
            return false;
        }
        do {
            remaining /= factor;
        } while (remaining % factor == 0);
    }
    return remaining == 1 ||
           PowMod(value, order / remaining, modulus) != 1;
}

uint32_t RootFromSmallestGeneratorBase(uint64_t order, uint32_t modulus) {
    const auto cofactor = (modulus - 1) / order;
    for (uint32_t base = 2; base < modulus; ++base) {
        const auto candidate = PowMod(base, cofactor, modulus);
        if (HasExactOrder(candidate, order, modulus)) {
            return static_cast<uint32_t>(candidate);
        }
    }
    throw GLIntParameterError(
        "production encrypted matrix core could not find an RNS root");
}

uint64_t NextRandom(uint64_t* state) noexcept {
    auto z = (*state += 0x9e3779b97f4a7c15ULL);
    z      = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z      = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

uint64_t ResolveSeed(uint64_t seed) {
    if (seed != 0) {
        return seed;
    }
    std::random_device random;
    return (static_cast<uint64_t>(random()) << 32) ^ random();
}

SlotKey KeyOf(const GLIntProductionSlotCiphertextValue& value) {
    return {static_cast<uint8_t>(value.branch), value.matrix, value.row,
            value.column};
}

template <typename GadgetEntry>
EntryKey EntryKeyOf(const GadgetEntry& entry) {
    return {static_cast<uint8_t>(entry.direction),
            static_cast<uint8_t>(entry.branch), entry.matrix,
            entry.destinationRow, entry.sourceRow};
}

}  // namespace

GLIntProductionSlotCiphertext::GLIntProductionSlotCiphertext(
    GLIntWBatchedParameters parameters, std::string keyTag,
    uint64_t compositeModulus, uint64_t plaintextScale,
    std::vector<GLIntProductionSlotCiphertextValue> values)
    : m_parameters(std::move(parameters)),
      m_keyTag(std::move(keyTag)),
      m_compositeModulus(compositeModulus),
      m_plaintextScale(plaintextScale),
      m_values(std::move(values)) {
    Validate();
}

const GLIntWBatchedParameters&
GLIntProductionSlotCiphertext::GetParameters() const noexcept {
    return m_parameters;
}

const std::string&
GLIntProductionSlotCiphertext::GetKeyTag() const noexcept {
    return m_keyTag;
}

uint64_t GLIntProductionSlotCiphertext::GetCompositeModulus() const noexcept {
    return m_compositeModulus;
}

uint64_t GLIntProductionSlotCiphertext::GetPlaintextScale() const noexcept {
    return m_plaintextScale;
}

const std::vector<GLIntProductionSlotCiphertextValue>&
GLIntProductionSlotCiphertext::GetValues() const noexcept {
    return m_values;
}

void GLIntProductionSlotCiphertext::Validate() const {
    RequireProductionParameters(m_parameters);
    if (m_keyTag.empty() || m_plaintextScale == 0 ||
        m_plaintextScale >= m_parameters.plaintextModulus ||
        m_compositeModulus <= m_parameters.plaintextModulus ||
        m_compositeModulus >
            static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
        m_values.size() > kGLIntProductionMaxLogicalValues) {
        throw GLCiphertextError(
            "production Slot ciphertext has invalid key/modulus/support metadata");
    }
    SlotKey previous{};
    bool havePrevious = false;
    for (const auto& value : m_values) {
        if (!IsValidBranch(value.branch) ||
            value.matrix >= m_parameters.cyclotomicPrime - 1 ||
            value.row >= m_parameters.dimension ||
            value.column >= m_parameters.dimension ||
            value.b >= m_compositeModulus || value.a >= m_compositeModulus) {
            throw GLCiphertextError(
                "production Slot ciphertext record is invalid");
        }
        const auto key = KeyOf(value);
        if (havePrevious && !(previous < key)) {
            throw GLCiphertextError(
                "production Slot ciphertext support is not strictly ordered");
        }
        previous     = key;
        havePrevious = true;
    }
}

GLIntProductionGadgetEvalKeys::GLIntProductionGadgetEvalKeys(
    GLIntWBatchedParameters parameters, std::string destinationKeyTag,
    uint64_t compositeModulus, uint32_t digitCount,
    std::vector<Entry> entries)
    : m_parameters(std::move(parameters)),
      m_destinationKeyTag(std::move(destinationKeyTag)),
      m_compositeModulus(compositeModulus),
      m_digitCount(digitCount),
      m_entries(std::move(entries)) {
    Validate();
}

const std::string&
GLIntProductionGadgetEvalKeys::GetDestinationKeyTag() const noexcept {
    return m_destinationKeyTag;
}

uint32_t GLIntProductionGadgetEvalKeys::GetDigitCount() const noexcept {
    return m_digitCount;
}

std::size_t GLIntProductionGadgetEvalKeys::GetEntryCount() const noexcept {
    return m_entries.size();
}

bool GLIntProductionGadgetEvalKeys::UsesTErrors() const noexcept {
    return true;
}

bool GLIntProductionGadgetEvalKeys::IsSecurityAuthorized() const noexcept {
    return false;
}

void GLIntProductionGadgetEvalKeys::Validate() const {
    RequireProductionParameters(m_parameters);
    if (m_destinationKeyTag.empty() ||
        m_compositeModulus <= m_parameters.plaintextModulus ||
        m_digitCount == 0 || m_digitCount >= 64 ||
        m_entries.size() > kGLIntProductionMaxGadgetEntries) {
        throw GLMissingEvaluationKeyError(
            "production gadget key bundle has invalid bounded metadata");
    }
    EntryKey previous{};
    bool havePrevious = false;
    for (const auto& entry : m_entries) {
        if ((entry.direction !=
                 GLIntProductionGadgetDirection::RightToPrimary &&
             entry.direction !=
                 GLIntProductionGadgetDirection::ProductToPrimary &&
             entry.direction !=
                 GLIntProductionGadgetDirection::SquareToPrimary) ||
            !IsValidBranch(entry.branch) ||
            entry.matrix >= m_parameters.cyclotomicPrime - 1 ||
            entry.destinationRow >= m_parameters.dimension ||
            entry.sourceRow >= m_parameters.dimension ||
            entry.digits.size() != m_digitCount) {
            throw GLMissingEvaluationKeyError(
                "production gadget evaluation-key entry is invalid");
        }
        const auto key = EntryKeyOf(entry);
        if (havePrevious && !(previous < key)) {
            throw GLMissingEvaluationKeyError(
                "production gadget evaluation-key entries are not ordered");
        }
        for (const auto& digit : entry.digits) {
            if (digit.b >= m_compositeModulus ||
                digit.a >= m_compositeModulus) {
                throw GLMissingEvaluationKeyError(
                    "production gadget evaluation-key digit is not canonical");
            }
        }
        previous     = key;
        havePrevious = true;
    }
}

GLIntProductionMatMulCore::GLIntProductionMatMulCore(
    GLIntWBatchedParameters parameters)
    : m_parameters(std::move(parameters)) {
    RequireProductionParameters(m_parameters);
    const GLIntProductionRLWECore rlwe(m_parameters);
    m_moduli = rlwe.GetModuli();
    m_compositeModulus =
        static_cast<uint64_t>(m_moduli[0]) * m_moduli[1];
    for (const auto modulus : m_moduli) {
        // Match the native GLR root table exactly: find the smallest element
        // of order 4*n*p, then derive zeta=root^p and eta=root^(4*n).
        const auto root4np = RootFromSmallestGeneratorBase(
            4 * m_parameters.dimension * m_parameters.cyclotomicPrime,
            modulus);
        m_zeta.push_back(PowMod(root4np, m_parameters.cyclotomicPrime,
                                modulus));
        m_eta.push_back(PowMod(root4np, 4 * m_parameters.dimension,
                               modulus));
    }
    auto remaining = m_compositeModulus - 1;
    while (remaining != 0) {
        ++m_digitCount;
        remaining >>= 1;
    }
}

const GLIntWBatchedParameters&
GLIntProductionMatMulCore::GetParameters() const noexcept {
    return m_parameters;
}

uint64_t GLIntProductionMatMulCore::GetCompositeModulus() const noexcept {
    return m_compositeModulus;
}

GLIntProductionMatMulCapabilities
GLIntProductionMatMulCore::GetCapabilities() const noexcept {
    return {};
}

void GLIntProductionMatMulCore::ValidatePrimaryKey(
    const GLIntProductionSecretKey& key, const char* operation) const {
    key.Validate();
    if (!SameParameters(m_parameters, key.GetParameters())) {
        throw GLKeyContextMismatchError(std::string(operation) +
                                        " primary key parameters mismatch");
    }
}

void GLIntProductionMatMulCore::ValidateCiphertext(
    const GLIntProductionSlotCiphertext& ciphertext,
    const char* objectName) const {
    ciphertext.Validate();
    if (!SameParameters(m_parameters, ciphertext.GetParameters()) ||
        ciphertext.GetCompositeModulus() != m_compositeModulus) {
        throw GLContextMismatchError(std::string(objectName) +
                                     " production Slot context mismatch");
    }
}

void GLIntProductionMatMulCore::ValidateOperands(
    const GLIntProductionSlotCiphertext& lhs,
    const GLIntProductionSlotCiphertext& rhs, const char* operation) const {
    ValidateCiphertext(lhs, "left production Slot ciphertext");
    ValidateCiphertext(rhs, "right production Slot ciphertext");
    if (lhs.GetKeyTag() != rhs.GetKeyTag()) {
        throw GLKeyMismatchError(std::string(operation) +
                                 " requires one destination key");
    }
}

void GLIntProductionMatMulCore::ValidateEvaluationKeys(
    const GLIntProductionGadgetEvalKeys& evaluationKeys,
    const std::string& destinationKeyTag, const char* operation) const {
    evaluationKeys.Validate();
    if (!SameParameters(m_parameters, evaluationKeys.m_parameters) ||
        evaluationKeys.m_compositeModulus != m_compositeModulus) {
        throw GLKeyContextMismatchError(std::string(operation) +
                                        " gadget-key context mismatch");
    }
    if (evaluationKeys.GetDestinationKeyTag() != destinationKeyTag) {
        throw GLKeyMismatchError(std::string(operation) +
                                 " gadget-key destination mismatch");
    }
}

uint64_t GLIntProductionMatMulCore::EvaluateSecret(
    const GLIntProductionSecretKey& key, GLIntBranch branch, uint32_t matrix,
    uint32_t row) const {
    std::vector<uint64_t> residues;
    residues.reserve(m_moduli.size());
    for (std::size_t plane = 0; plane < m_moduli.size(); ++plane) {
        const auto modulus = static_cast<uint64_t>(m_moduli[plane]);
        const auto xExponent = PowMod(5, row, 4 * m_parameters.dimension);
        const auto wExponent = PowMod(m_parameters.wGenerator, matrix,
                                      m_parameters.cyclotomicPrime);
        auto xPoint = PowMod(m_zeta[plane], xExponent, modulus);
        auto wPoint = PowMod(m_eta[plane], wExponent, modulus);
        auto iUnit = PowMod(m_zeta[plane], m_parameters.dimension, modulus);
        if (branch == GLIntBranch::Minus) {
            xPoint = PowMod(xPoint, modulus - 2, modulus);
            wPoint = PowMod(wPoint, modulus - 2, modulus);
            iUnit  = modulus - iUnit;
        }
        uint64_t result = 0;
        for (const auto& term : key.m_terms) {
            const auto coefficient = AddMod(
                Canonical(term.real, modulus),
                MulMod(iUnit, Canonical(term.imaginary, modulus), modulus),
                modulus);
            const auto value = MulMod(
                coefficient,
                MulMod(PowMod(xPoint, term.x, modulus),
                       PowMod(wPoint, term.w, modulus), modulus),
                modulus);
            result = AddMod(result, value, modulus);
        }
        residues.push_back(result);
    }

    const auto q0 = static_cast<uint64_t>(m_moduli[0]);
    const auto q1 = static_cast<uint64_t>(m_moduli[1]);
    const auto r0ModQ1 = residues[0] % q1;
    const auto difference =
        residues[1] >= r0ModQ1 ? residues[1] - r0ModQ1
                               : q1 - (r0ModQ1 - residues[1]);
    const auto correction =
        MulMod(difference, PowMod(q0 % q1, q1 - 2, q1), q1);
    return residues[0] + q0 * correction;
}

GLIntProductionSlotCiphertext GLIntProductionMatMulCore::Encrypt(
    const GLIntProductionSecretKey& secretKey,
    const GLIntProductionSparsePlaintext& plaintext, uint64_t seed) const {
    ValidatePrimaryKey(secretKey, "production Slot Encrypt");
    plaintext.Validate();
    if (!SameParameters(m_parameters, plaintext.GetParameters())) {
        throw GLContextMismatchError(
            "production Slot Encrypt plaintext parameters mismatch");
    }
    uint64_t rngState = ResolveSeed(seed);
    std::vector<GLIntProductionSlotCiphertextValue> values;
    values.reserve(plaintext.GetValues().size());
    for (const auto& message : plaintext.GetValues()) {
        const auto secret = EvaluateSecret(secretKey, message.branch,
                                           message.matrix, message.row);
        const auto a = NextRandom(&rngState) % m_compositeModulus;
        const auto error = (NextRandom(&rngState) & 1) != 0 ? int64_t{1}
                                                            : int64_t{-1};
        const auto noisyMessage = AddMod(
            static_cast<uint64_t>(message.value),
            Canonical(static_cast<int64_t>(m_parameters.plaintextModulus) *
                          error,
                      m_compositeModulus),
            m_compositeModulus);
        values.push_back({message.branch, message.matrix, message.row,
                          message.column,
                          SubMod(noisyMessage,
                                 MulMod(a, secret, m_compositeModulus),
                                 m_compositeModulus),
                          a});
    }
    return GLIntProductionSlotCiphertext(
        m_parameters, secretKey.GetKeyTag(), m_compositeModulus, 1,
        std::move(values));
}

GLIntProductionSparsePlaintext GLIntProductionMatMulCore::Decrypt(
    const GLIntProductionSecretKey& secretKey,
    const GLIntProductionSlotCiphertext& ciphertext) const {
    ValidatePrimaryKey(secretKey, "production Slot Decrypt");
    ValidateCiphertext(ciphertext, "production Slot ciphertext");
    if (ciphertext.GetKeyTag() != secretKey.GetKeyTag()) {
        throw GLKeyMismatchError(
            "production Slot Decrypt key tag mismatch");
    }
    std::vector<GLIntProductionSlotValue> output;
    output.reserve(ciphertext.GetValues().size());
    const auto plaintextModulus = m_parameters.plaintextModulus;
    const auto inverseScale = PowMod(ciphertext.GetPlaintextScale(),
                                     plaintextModulus - 2,
                                     plaintextModulus);
    for (const auto& value : ciphertext.GetValues()) {
        const auto secret = EvaluateSecret(secretKey, value.branch,
                                           value.matrix, value.row);
        const auto residue = AddMod(
            value.b, MulMod(value.a, secret, m_compositeModulus),
            m_compositeModulus);
        const auto centered =
            residue <= m_compositeModulus / 2
                ? static_cast<int64_t>(residue)
                : -static_cast<int64_t>(m_compositeModulus - residue);
        output.push_back(
            {value.branch, value.matrix, value.row, value.column,
             static_cast<int64_t>(MulMod(Canonical(centered, plaintextModulus),
                                         inverseScale, plaintextModulus))});
    }
    return GLIntProductionSparsePlaintext(m_parameters, std::move(output));
}

GLIntProductionSlotCiphertext GLIntProductionMatMulCore::Add(
    const GLIntProductionSlotCiphertext& lhs,
    const GLIntProductionSlotCiphertext& rhs) const {
    ValidateOperands(lhs, rhs, "production Slot Add");
    if (lhs.GetPlaintextScale() != rhs.GetPlaintextScale()) {
        throw GLCiphertextError(
            "production Slot Add requires equal plaintext scales");
    }
    std::map<SlotKey, GLIntProductionSlotCiphertextValue> values;
    for (const auto& value : lhs.GetValues()) {
        values.emplace(KeyOf(value), value);
    }
    for (const auto& value : rhs.GetValues()) {
        const auto [it, inserted] = values.emplace(KeyOf(value), value);
        if (!inserted) {
            it->second.b = AddMod(it->second.b, value.b, m_compositeModulus);
            it->second.a = AddMod(it->second.a, value.a, m_compositeModulus);
        }
        if (values.size() > kGLIntProductionMaxLogicalValues) {
            throw GLDimensionError(
                "production Slot Add exceeds its sparse support bound");
        }
    }
    std::vector<GLIntProductionSlotCiphertextValue> output;
    output.reserve(values.size());
    for (const auto& [key, value] : values) {
        static_cast<void>(key);
        if (value.b != 0 || value.a != 0) {
            output.push_back(value);
        }
    }
    return GLIntProductionSlotCiphertext(
        m_parameters, lhs.GetKeyTag(), m_compositeModulus,
        lhs.GetPlaintextScale(), std::move(output));
}

GLIntProductionSlotCiphertext GLIntProductionMatMulCore::Subtract(
    const GLIntProductionSlotCiphertext& lhs,
    const GLIntProductionSlotCiphertext& rhs) const {
    return Add(lhs, Negate(rhs));
}

GLIntProductionSlotCiphertext GLIntProductionMatMulCore::Negate(
    const GLIntProductionSlotCiphertext& ciphertext) const {
    ValidateCiphertext(ciphertext, "production Slot ciphertext");
    auto output = ciphertext.GetValues();
    for (auto& value : output) {
        value.b = value.b == 0 ? 0 : m_compositeModulus - value.b;
        value.a = value.a == 0 ? 0 : m_compositeModulus - value.a;
    }
    return GLIntProductionSlotCiphertext(
        m_parameters, ciphertext.GetKeyTag(), m_compositeModulus,
        ciphertext.GetPlaintextScale(),
        std::move(output));
}

GLIntProductionMatMulCore::Entry GLIntProductionMatMulCore::MakeEntry(
    const GLIntProductionSecretKey& key,
    GLIntProductionGadgetDirection direction, GLIntBranch branch,
    uint32_t matrix, uint32_t destinationRow, uint32_t sourceRow,
    uint64_t* rngState) const {
    const auto destination =
        EvaluateSecret(key, branch, matrix, destinationRow);
    const auto rightBranch = branch == GLIntBranch::Plus
                                 ? GLIntBranch::Minus
                                 : GLIntBranch::Plus;
    const auto right = EvaluateSecret(key, rightBranch, matrix, sourceRow);
    uint64_t source = 0;
    if (direction == GLIntProductionGadgetDirection::RightToPrimary) {
        source = right;
    }
    else if (direction ==
             GLIntProductionGadgetDirection::ProductToPrimary) {
        source = MulMod(destination, right, m_compositeModulus);
    }
    else {
        source = MulMod(destination, destination, m_compositeModulus);
    }

    Entry entry;
    entry.direction      = direction;
    entry.branch         = branch;
    entry.matrix         = matrix;
    entry.destinationRow = destinationRow;
    entry.sourceRow      = sourceRow;
    entry.digits.reserve(m_digitCount);
    uint64_t gadget = 1;
    for (uint32_t digitIndex = 0; digitIndex < m_digitCount; ++digitIndex) {
        const auto a = NextRandom(rngState) % m_compositeModulus;
        const auto error = (NextRandom(rngState) & 1) != 0 ? int64_t{1}
                                                            : int64_t{-1};
        const auto target = AddMod(
            MulMod(gadget, source, m_compositeModulus),
            Canonical(static_cast<int64_t>(m_parameters.plaintextModulus) *
                          error,
                      m_compositeModulus),
            m_compositeModulus);
        entry.digits.push_back(
            {SubMod(target,
                    MulMod(a, destination, m_compositeModulus),
                    m_compositeModulus),
             a});
        gadget = AddMod(gadget, gadget, m_compositeModulus);
    }
    return entry;
}

GLIntProductionGadgetEvalKeys GLIntProductionMatMulCore::EvalKeyGen(
    const GLIntProductionSecretKey& primaryKey,
    const GLIntProductionSlotCiphertext& lhs,
    const GLIntProductionSlotCiphertext& rhs, uint64_t seed) const {
    ValidatePrimaryKey(primaryKey, "production gadget EvalKeyGen");
    ValidateOperands(lhs, rhs, "production gadget EvalKeyGen");
    if (lhs.GetKeyTag() != primaryKey.GetKeyTag()) {
        throw GLKeyMismatchError(
            "production gadget EvalKeyGen ciphertext/key tag mismatch");
    }
    std::set<EntryKey> requests;
    for (const auto& left : lhs.GetValues()) {
        const auto opposite = left.branch == GLIntBranch::Plus
                                  ? GLIntBranch::Minus
                                  : GLIntBranch::Plus;
        for (const auto& right : rhs.GetValues()) {
            if (right.branch == opposite && right.matrix == left.matrix &&
                right.column == left.column) {
                for (const auto direction : {
                         GLIntProductionGadgetDirection::RightToPrimary,
                         GLIntProductionGadgetDirection::ProductToPrimary}) {
                    requests.emplace(static_cast<uint8_t>(direction),
                                     static_cast<uint8_t>(left.branch),
                                     left.matrix, left.row, right.row);
                }
            }
            if (KeyOf(left) == KeyOf(right)) {
                requests.emplace(
                    static_cast<uint8_t>(
                        GLIntProductionGadgetDirection::SquareToPrimary),
                    static_cast<uint8_t>(left.branch), left.matrix, left.row,
                    left.row);
            }
        }
    }
    if (requests.size() > kGLIntProductionMaxGadgetEntries) {
        throw GLDimensionError(
            "production gadget EvalKeyGen exceeds its entry bound");
    }
    uint64_t rngState = ResolveSeed(seed);
    std::vector<Entry> entries;
    entries.reserve(requests.size());
    for (const auto& request : requests) {
        entries.push_back(MakeEntry(
            primaryKey,
            static_cast<GLIntProductionGadgetDirection>(std::get<0>(request)),
            static_cast<GLIntBranch>(std::get<1>(request)),
            std::get<2>(request), std::get<3>(request),
            std::get<4>(request), &rngState));
    }
    return GLIntProductionGadgetEvalKeys(
        m_parameters, primaryKey.GetKeyTag(), m_compositeModulus,
        m_digitCount, std::move(entries));
}

const GLIntProductionMatMulCore::Entry&
GLIntProductionMatMulCore::RequireEntry(
    const GLIntProductionGadgetEvalKeys& keys,
    GLIntProductionGadgetDirection direction, GLIntBranch branch,
    uint32_t matrix, uint32_t destinationRow, uint32_t sourceRow,
    const char* operation) const {
    const EntryKey key{static_cast<uint8_t>(direction),
                       static_cast<uint8_t>(branch), matrix, destinationRow,
                       sourceRow};
    const auto it = std::lower_bound(
        keys.m_entries.begin(), keys.m_entries.end(), key,
        [](const Entry& lhs, const EntryKey& rhs) {
            return EntryKeyOf(lhs) < rhs;
        });
    if (it == keys.m_entries.end() || EntryKeyOf(*it) != key) {
        throw GLMissingEvaluationKeyError(std::string(operation) +
                                          " is missing a gadget direction");
    }
    return *it;
}

std::pair<uint64_t, uint64_t> GLIntProductionMatMulCore::ApplyGadget(
    uint64_t value, const Entry& entry) const {
    uint64_t b = 0;
    uint64_t a = 0;
    for (uint32_t digit = 0; digit < m_digitCount; ++digit) {
        if (((value >> digit) & 1) != 0) {
            b = AddMod(b, entry.digits[digit].b, m_compositeModulus);
            a = AddMod(a, entry.digits[digit].a, m_compositeModulus);
        }
    }
    return {b, a};
}

GLIntProductionSlotCiphertext GLIntProductionMatMulCore::MatrixMultiply(
    const GLIntProductionSlotCiphertext& lhs,
    const GLIntProductionSlotCiphertext& rhs,
    const GLIntProductionGadgetEvalKeys& evaluationKeys) const {
    ValidateOperands(lhs, rhs, "production encrypted MatrixMultiply");
    ValidateEvaluationKeys(evaluationKeys, lhs.GetKeyTag(),
                           "production encrypted MatrixMultiply");
    struct Tensor {
        uint64_t d0{0};
        uint64_t d1{0};
        uint64_t d2{0};
        uint64_t d3{0};
    };
    std::map<SlotKey, Tensor> tensors;
    for (const auto& left : lhs.GetValues()) {
        const auto opposite = left.branch == GLIntBranch::Plus
                                  ? GLIntBranch::Minus
                                  : GLIntBranch::Plus;
        for (const auto& right : rhs.GetValues()) {
            if (right.branch != opposite || right.matrix != left.matrix ||
                right.column != left.column) {
                continue;
            }
            const SlotKey outputKey{static_cast<uint8_t>(left.branch),
                                    left.matrix, left.row, right.row};
            auto& tensor = tensors[outputKey];
            tensor.d0 = AddMod(tensor.d0,
                               MulMod(left.b, right.b, m_compositeModulus),
                               m_compositeModulus);
            tensor.d1 = AddMod(tensor.d1,
                               MulMod(left.b, right.a, m_compositeModulus),
                               m_compositeModulus);
            tensor.d2 = AddMod(tensor.d2,
                               MulMod(left.a, right.b, m_compositeModulus),
                               m_compositeModulus);
            tensor.d3 = AddMod(tensor.d3,
                               MulMod(left.a, right.a, m_compositeModulus),
                               m_compositeModulus);
            if (tensors.size() > kGLIntProductionMaxLogicalValues) {
                throw GLDimensionError(
                    "production encrypted MatrixMultiply exceeds output bound");
            }
        }
    }

    std::vector<GLIntProductionSlotCiphertextValue> output;
    output.reserve(tensors.size());
    for (const auto& [key, tensor] : tensors) {
        const auto branch = static_cast<GLIntBranch>(std::get<0>(key));
        const auto matrix = std::get<1>(key);
        const auto destinationRow = std::get<2>(key);
        const auto sourceRow = std::get<3>(key);
        const auto& rightKey = RequireEntry(
            evaluationKeys,
            GLIntProductionGadgetDirection::RightToPrimary, branch, matrix,
            destinationRow, sourceRow, "production encrypted MatrixMultiply");
        const auto& productKey = RequireEntry(
            evaluationKeys,
            GLIntProductionGadgetDirection::ProductToPrimary, branch, matrix,
            destinationRow, sourceRow, "production encrypted MatrixMultiply");
        const auto switchedRight = ApplyGadget(tensor.d1, rightKey);
        const auto switchedProduct = ApplyGadget(tensor.d3, productKey);
        output.push_back({branch, matrix, destinationRow, sourceRow,
                          AddMod(tensor.d0,
                                 AddMod(switchedRight.first,
                                        switchedProduct.first,
                                        m_compositeModulus),
                                 m_compositeModulus),
                          AddMod(tensor.d2,
                                 AddMod(switchedRight.second,
                                        switchedProduct.second,
                                        m_compositeModulus),
                                 m_compositeModulus)});
    }
    return GLIntProductionSlotCiphertext(
        m_parameters, lhs.GetKeyTag(), m_compositeModulus,
        MulMod(m_parameters.dimension,
               MulMod(lhs.GetPlaintextScale(), rhs.GetPlaintextScale(),
                      m_parameters.plaintextModulus),
               m_parameters.plaintextModulus),
        std::move(output));
}

GLIntProductionSlotCiphertext GLIntProductionMatMulCore::Hadamard(
    const GLIntProductionSlotCiphertext& lhs,
    const GLIntProductionSlotCiphertext& rhs,
    const GLIntProductionGadgetEvalKeys& evaluationKeys) const {
    ValidateOperands(lhs, rhs, "production encrypted Hadamard");
    ValidateEvaluationKeys(evaluationKeys, lhs.GetKeyTag(),
                           "production encrypted Hadamard");
    std::map<SlotKey, GLIntProductionSlotCiphertextValue> right;
    for (const auto& value : rhs.GetValues()) {
        right.emplace(KeyOf(value), value);
    }
    std::vector<GLIntProductionSlotCiphertextValue> output;
    for (const auto& left : lhs.GetValues()) {
        const auto it = right.find(KeyOf(left));
        if (it == right.end()) {
            continue;
        }
        const auto& other = it->second;
        const auto d0 = MulMod(left.b, other.b, m_compositeModulus);
        const auto d1 = AddMod(
            MulMod(left.b, other.a, m_compositeModulus),
            MulMod(left.a, other.b, m_compositeModulus),
            m_compositeModulus);
        const auto d2 = MulMod(left.a, other.a, m_compositeModulus);
        const auto& squareKey = RequireEntry(
            evaluationKeys,
            GLIntProductionGadgetDirection::SquareToPrimary, left.branch,
            left.matrix, left.row, left.row,
            "production encrypted Hadamard");
        const auto switched = ApplyGadget(d2, squareKey);
        output.push_back({left.branch, left.matrix, left.row, left.column,
                          AddMod(d0, switched.first, m_compositeModulus),
                          AddMod(d1, switched.second, m_compositeModulus)});
    }
    return GLIntProductionSlotCiphertext(
        m_parameters, lhs.GetKeyTag(), m_compositeModulus,
        MulMod(lhs.GetPlaintextScale(), rhs.GetPlaintextScale(),
               m_parameters.plaintextModulus),
        std::move(output));
}

}  // namespace lbcrypto
