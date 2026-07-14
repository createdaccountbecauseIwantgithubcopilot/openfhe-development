//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#include "openfhe.h"
#include "key/evalkeyrelin.h"
#include "scheme/ckksrns/ckksrns-paco-serialization.h"

#include "gtest/gtest.h"

#include <algorithm>
#include <complex>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace lbcrypto {
namespace {

PaCoParameters SerializationTestParameters() {
    return PaCoParameters{2, 2, 1, 1};
}

CryptoContext<DCRTPoly> SerializationTestContext(uint32_t ringDimension = 32, uint32_t scalingModSize = 35) {
    const auto pacoParameters = SerializationTestParameters();
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetRingDim(ringDimension);
    parameters.SetBatchSize(ringDimension / 2);
    parameters.SetMultiplicativeDepth(pacoParameters.MultiplicativeDepth() + 2);
    parameters.SetFirstModSize(45);
    parameters.SetScalingModSize(scalingModSize);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetNumLargeDigits(2);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    parameters.SetCKKSDataType(COMPLEX);

    auto context = GenCryptoContext(parameters);
    context->Enable(PKE);
    context->Enable(KEYSWITCH);
    context->Enable(LEVELEDSHE);
    context->Enable(ADVANCEDSHE);
    context->Enable(FHE);
    return context;
}

std::vector<uint8_t> TestAuthenticationKey(uint8_t offset = 0) {
    std::vector<uint8_t> result(32);
    for (size_t i = 0; i < result.size(); ++i)
        result[i] = static_cast<uint8_t>(i + 1 + offset);
    return result;
}

PaCoBootstrapKeyExportOptions AuthenticatedExportOptions() {
    PaCoBootstrapKeyExportOptions options;
    options.lifecycle.bundleId             = "unit-test/paco/evaluator-A";
    options.lifecycle.issuer               = "unit-test-owner";
    options.lifecycle.generation           = 7;
    options.lifecycle.createdAtUnixSeconds = 100;
    options.lifecycle.expiresAtUnixSeconds = 200;
    options.authenticationKey              = TestAuthenticationKey();
    return options;
}

PaCoBootstrapKeyImportOptions AuthenticatedImportOptions(const std::string& keyTag) {
    PaCoBootstrapKeyImportOptions options;
    options.expectedBundleId       = "unit-test/paco/evaluator-A";
    options.expectedIssuer         = "unit-test-owner";
    options.expectedKeyTag         = keyTag;
    options.minimumGeneration      = 7;
    options.currentTimeUnixSeconds = 150;
    options.authenticationKey      = TestAuthenticationKey();
    return options;
}

Ciphertext<DCRTPoly> EncryptAtBaseModulus(const CryptoContext<DCRTPoly>& context, const PublicKey<DCRTPoly>& publicKey,
                                          const std::vector<std::complex<double>>& slots) {
    auto plaintext  = context->MakeCKKSPackedPlaintext(slots, 1, 0, nullptr, slots.size());
    auto ciphertext = context->Encrypt(publicKey, plaintext);
    return context->Compress(ciphertext, 1);
}

std::vector<std::complex<double>> DecryptSlots(const CryptoContext<DCRTPoly>& context,
                                               const PrivateKey<DCRTPoly>& secretKey,
                                               ConstCiphertext<DCRTPoly> ciphertext) {
    Plaintext plaintext;
    context->Decrypt(secretKey, ciphertext, &plaintext);
    plaintext->SetLength(context->GetRingDimension() / 2);
    return plaintext->GetCKKSPackedValue();
}

DCRTPoly RemoveEvaluationKeyTower(const DCRTPoly& source, uint32_t removedTower) {
    if (removedTower >= source.GetNumOfElements() || source.GetNumOfElements() < 2)
        throw std::invalid_argument("test tower removal is out of range");
    std::vector<NativeInteger> moduli;
    std::vector<NativeInteger> roots;
    moduli.reserve(source.GetNumOfElements() - 1);
    roots.reserve(source.GetNumOfElements() - 1);
    for (uint32_t i = 0; i < source.GetNumOfElements(); ++i) {
        if (i == removedTower)
            continue;
        moduli.push_back(source.GetElementAtIndex(i).GetModulus());
        roots.push_back(source.GetElementAtIndex(i).GetRootOfUnity());
    }
    auto parameters =
        std::make_shared<DCRTPoly::Params>(source.GetCyclotomicOrder(), std::move(moduli), std::move(roots));
    DCRTPoly result(parameters, Format::EVALUATION, true);
    uint32_t target = 0;
    for (uint32_t i = 0; i < source.GetNumOfElements(); ++i) {
        if (i != removedTower)
            result.SetElementAtIndex(target++, source.GetElementAtIndex(i));
    }
    return result;
}

EvalKey<DCRTPoly> CloneKeyRemovingTower(const EvalKey<DCRTPoly>& source, uint32_t removedTower) {
    auto result = std::make_shared<EvalKeyRelinImpl<DCRTPoly>>(source->GetCryptoContext());
    std::vector<DCRTPoly> a;
    std::vector<DCRTPoly> b;
    for (const auto& component : source->GetAVector())
        a.push_back(RemoveEvaluationKeyTower(component, removedTower));
    for (const auto& component : source->GetBVector())
        b.push_back(RemoveEvaluationKeyTower(component, removedTower));
    result->SetAVector(std::move(a));
    result->SetBVector(std::move(b));
    result->SetKeyTag(source->GetKeyTag());
    return result;
}

PaCoBootstrapKeys ReplaceFirstAutomorphismKey(const PaCoBootstrapKeys& source, const EvalKey<DCRTPoly>& replacement) {
    PaCoBootstrapKeys result = source;
    result.automorphismKeys  = std::make_shared<std::map<uint32_t, EvalKey<DCRTPoly>>>(*source.automorphismKeys);
    result.automorphismKeys->at(source.automorphismIndices.front()) = replacement;
    return result;
}

TEST(UTCKKSRNS_PACO_KEY_SERIALIZATION, AuthenticatedRoundTripAndFailClosedPolicy) {
    const auto parameters = SerializationTestParameters();
    const auto context    = SerializationTestContext();
    PaCoCKKSRNS owner(context, parameters);
    const auto ownerMaterial = PaCoCKKSRNS::KeyGen(context, parameters.h, UINT64_C(0x5061436f));
    owner.GenerateBootstrapKeys(ownerMaterial);
    const auto original = owner.GetBootstrapKeys();

    const auto exportOptions = AuthenticatedExportOptions();
    const auto artifact      = PaCoBootstrapKeySerializer::Serialize(context, original, exportOptions);
    EXPECT_EQ(artifact, PaCoBootstrapKeySerializer::Serialize(context, original, exportOptions));
    ASSERT_GT(artifact.size(), 8U + 3U * sizeof(uint32_t));
    constexpr std::string_view magic = "PACKBK02";
    EXPECT_TRUE(std::equal(artifact.begin(), artifact.begin() + magic.size(), magic.begin()));
    EXPECT_EQ(artifact[8], PaCoBootstrapKeySerializer::FORMAT_VERSION);
    EXPECT_EQ(PaCoBootstrapKeySerializer::ContextFingerprint(context),
              PaCoBootstrapKeySerializer::ContextFingerprint(context));

    const auto importOptions = AuthenticatedImportOptions(original.keyTag);
    const auto restored      = PaCoBootstrapKeySerializer::Deserialize(context, parameters, artifact, importOptions);
    EXPECT_TRUE(restored.manifest.authenticityVerified);
    EXPECT_EQ(restored.manifest.lifecycle.bundleId, exportOptions.lifecycle.bundleId);
    EXPECT_EQ(restored.manifest.lifecycle.generation, exportOptions.lifecycle.generation);
    EXPECT_EQ(restored.manifest.keyTag, original.keyTag);
    EXPECT_EQ(restored.manifest.automorphismIndices, original.automorphismIndices);
    EXPECT_EQ(restored.manifest.automorphismKeyLevels, original.automorphismKeyLevels);
    EXPECT_EQ(restored.manifest.multiplicationKeyLevel, original.multiplicationKeyLevel);
    ASSERT_EQ(restored.manifest.automorphismKeyEntries.size(), original.automorphismIndices.size());
    for (const auto& entry : restored.manifest.automorphismKeyEntries) {
        EXPECT_EQ(entry.minimumLevel, original.automorphismKeyLevels.at(entry.automorphismIndex));
        EXPECT_EQ(entry.activeQTowers, original.totalTowers - entry.minimumLevel);
        EXPECT_GT(entry.pTowers, 0U);
        EXPECT_GT(entry.digitCount, 0U);
        EXPECT_GT(entry.serializedBytes, 0U);
    }
    EXPECT_EQ(PaCoBootstrapKeySerializer::DigestHex(restored.manifest.contextFingerprint).size(), 64U);

    PaCoCKKSRNS evaluator(context, parameters);
    EXPECT_NO_THROW(evaluator.LoadBootstrapKeys(restored.keys));
    EXPECT_TRUE(evaluator.IsSetup());
    const std::complex<double> expected{2.5e-4, -1.75e-4};
    const std::vector<std::complex<double>> slots(context->GetRingDimension() / 2, expected);
    const auto input   = EncryptAtBaseModulus(context, ownerMaterial.keyPair.publicKey, slots);
    const auto output  = evaluator.EvalSequential(input);
    const auto decoded = DecryptSlots(context, ownerMaterial.keyPair.secretKey, output);
    ASSERT_FALSE(decoded.empty());
    EXPECT_LE(std::abs(decoded.front() - expected), 2e-4);

    auto corrupted = artifact;
    corrupted[corrupted.size() / 2] ^= 0x01;
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, corrupted, importOptions));

    auto wrongAuthentication              = importOptions;
    wrongAuthentication.authenticationKey = TestAuthenticationKey(1);
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, artifact, wrongAuthentication));

    auto wrongKeyTag = importOptions;
    wrongKeyTag.expectedKeyTag += "-wrong";
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, artifact, wrongKeyTag));

    auto wrongBundle             = importOptions;
    wrongBundle.expectedBundleId = "unit-test/paco/evaluator-B";
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, artifact, wrongBundle));

    auto rollback              = importOptions;
    rollback.minimumGeneration = exportOptions.lifecycle.generation + 1;
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, artifact, rollback));

    auto noClock                   = importOptions;
    noClock.currentTimeUnixSeconds = 0;
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, artifact, noClock));

    auto expired                   = importOptions;
    expired.currentTimeUnixSeconds = exportOptions.lifecycle.expiresAtUnixSeconds;
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, artifact, expired));

    const PaCoParameters wrongParameters{parameters.h, parameters.C * 2, parameters.g0, parameters.g1};
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, wrongParameters, artifact, importOptions));

    auto wrongNumericalPolicy                          = parameters;
    wrongNumericalPolicy.numerics.minimumPrecisionBits = 1;
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, wrongNumericalPolicy, artifact, importOptions));

    auto tinyEntryLimit          = importOptions;
    tinyEntryLimit.maxEntryBytes = 1;
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, artifact, tinyEntryLimit));

    auto tinyKeyCount                    = importOptions;
    tinyKeyCount.maxEvaluationKeyEntries = 1;
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, artifact, tinyKeyCount));

    const auto wrongContext = SerializationTestContext(64);
    EXPECT_NE(PaCoBootstrapKeySerializer::ContextFingerprint(context),
              PaCoBootstrapKeySerializer::ContextFingerprint(wrongContext));
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(wrongContext, parameters, artifact, importOptions));
}

TEST(UTCKKSRNS_PACO_KEY_SERIALIZATION, AuthenticationAndUnsupportedFormatsFailClosed) {
    const auto parameters = SerializationTestParameters();
    const auto context    = SerializationTestContext();
    PaCoCKKSRNS owner(context, parameters);
    const auto ownerMaterial = PaCoCKKSRNS::KeyGen(context, parameters.h, UINT64_C(0x494e544547524954));
    owner.GenerateBootstrapKeys(ownerMaterial);
    const auto keys = owner.GetBootstrapKeys();

    PaCoBootstrapKeyExportOptions exportOptions;
    exportOptions.lifecycle.bundleId   = "unit-test/paco/authentication-required";
    exportOptions.lifecycle.generation = 1;
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Serialize(context, keys, exportOptions));

    exportOptions.authenticationKey = TestAuthenticationKey();
    const auto artifact             = PaCoBootstrapKeySerializer::Serialize(context, keys, exportOptions);

    PaCoBootstrapKeyImportOptions importOptions;
    importOptions.expectedBundleId  = exportOptions.lifecycle.bundleId;
    importOptions.expectedKeyTag    = keys.keyTag;
    importOptions.authenticationKey = exportOptions.authenticationKey;
    EXPECT_NO_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, artifact, importOptions));

    auto noAuthentication = importOptions;
    noAuthentication.authenticationKey.clear();
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, artifact, noAuthentication));

    auto unsignedV2 = artifact;
    std::fill(unsignedV2.begin() + 16, unsignedV2.begin() + 20, 0);
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, unsignedV2, importOptions));

    auto unsupportedVersion = artifact;
    unsupportedVersion[7]   = '1';
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, unsupportedVersion, importOptions));

    auto invalidMagic = artifact;
    invalidMagic[0] ^= 0xff;
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, invalidMagic, importOptions));

    const std::vector<uint8_t> truncatedMagic{'P', 'A', 'C', 'K'};
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Deserialize(context, parameters, truncatedMagic, importOptions));
}

TEST(UTCKKSRNS_PACO_KEY_SERIALIZATION, RejectsWrongLevelsAndStrippedHybridBasesBeforeExport) {
    const auto parameters = SerializationTestParameters();
    const auto context    = SerializationTestContext();
    PaCoCKKSRNS owner(context, parameters);
    const auto ownerMaterial = PaCoCKKSRNS::KeyGen(context, parameters.h, UINT64_C(0x424153454c455645));
    owner.GenerateBootstrapKeys(ownerMaterial);
    const auto keys          = owner.GetBootstrapKeys();
    const auto exportOptions = AuthenticatedExportOptions();

    auto wrongLevel = keys;
    auto level      = wrongLevel.automorphismKeyLevels.begin();
    ASSERT_NE(level, wrongLevel.automorphismKeyLevels.end());
    ++level->second;
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Serialize(context, wrongLevel, exportOptions));

    auto tamperedMap = keys;
    tamperedMap.automorphismKeyLevels.erase(tamperedMap.automorphismKeyLevels.begin());
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Serialize(context, tamperedMap, exportOptions));

    const uint32_t index         = keys.automorphismIndices.front();
    const uint32_t levelValue    = keys.automorphismKeyLevels.at(index);
    const uint32_t activeQTowers = keys.totalTowers - levelValue;
    const auto& key              = keys.automorphismKeys->at(index);
    ASSERT_GT(activeQTowers, 0U);
    ASSERT_GT(key->GetAVector().front().GetNumOfElements(), activeQTowers);

    const auto strippedQ = ReplaceFirstAutomorphismKey(keys, CloneKeyRemovingTower(key, activeQTowers - 1));
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Serialize(context, strippedQ, exportOptions));

    const auto strippedP = ReplaceFirstAutomorphismKey(keys, CloneKeyRemovingTower(key, activeQTowers));
    EXPECT_ANY_THROW(PaCoBootstrapKeySerializer::Serialize(context, strippedP, exportOptions));
}

}  // namespace
}  // namespace lbcrypto
