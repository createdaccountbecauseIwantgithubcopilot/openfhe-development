#include "openfhe/pke/gl-int-production-glr-bridge.h"

#include <exception>
#include <string>

namespace {

template <typename Fn>
bool ThrowsContaining(Fn&& fn, const char* needle) {
    try {
        fn();
    }
    catch (const std::exception& error) {
        return std::string(error.what()).find(needle) != std::string::npos;
    }
    return false;
}

lbcrypto::GLIntProductionGLRBridge::NativeCiphertext
MakeFinalLevelCiphertext(
    const lbcrypto::GLRProductionAdapter& adapter) {
    const auto& context = adapter.GetContext();
    const std::uint32_t level = context.params.levels() - 1;
    lbcrypto::GLIntProductionGLRBridge::NativeCiphertext ciphertext;
    ciphertext.b = glscheme::rns::GlrPoly::zero(
        context, glscheme::rns::GlrRing::Rp, level, false,
        glscheme::rns::GlrDomain::Slot);
    ciphertext.a = glscheme::rns::GlrPoly::zero(
        context, glscheme::rns::GlrRing::Rp, level, false,
        glscheme::rns::GlrDomain::Slot);
    const auto q = context.params.q_chain.front().q;
    ciphertext.b.data.front() = 17;
    ciphertext.b.data[ciphertext.b.data.size() / 2] = q - 1;
    ciphertext.a.data[ciphertext.a.data.size() / 3] = 29;
    ciphertext.a.data.back() = q - 7;
    ciphertext.scale = 17.0;
    ciphertext.level = level;
    ciphertext.key_id = "integer-q2-untrusted";
    ciphertext.key_lineage_commitment =
        "sha256:" + std::string(64, 'd');
    return ciphertext;
}

bool ExactNegation(
    const lbcrypto::GLRProductionAdapter& adapter,
    const lbcrypto::GLIntProductionGLRBridge::NativeCiphertext& input,
    const lbcrypto::GLIntProductionGLRBridge::NativeCiphertext& output) {
    const auto q = adapter.GetContext().params.q_chain.front().q;
    if (output.level != input.level || output.scale != input.scale ||
        output.key_id != input.key_id ||
        output.key_lineage_commitment != input.key_lineage_commitment ||
        output.b.data.size() != input.b.data.size() ||
        output.a.data.size() != input.a.data.size()) {
        return false;
    }
    for (std::size_t index = 0; index < input.b.data.size(); ++index) {
        const auto expected =
            input.b.data[index] == 0 ? 0 : q - input.b.data[index];
        if (output.b.data[index] != expected) {
            return false;
        }
    }
    for (std::size_t index = 0; index < input.a.data.size(); ++index) {
        const auto expected =
            input.a.data[index] == 0 ? 0 : q - input.a.data[index];
        if (output.a.data[index] != expected) {
            return false;
        }
    }
    return true;
}

}  // namespace

int main() {
    auto adapter = lbcrypto::GLRProductionAdapter::Create();
    const lbcrypto::GLIntProductionGLRBridge bridge(adapter);
    const auto capabilities = bridge.GetCapabilities();
    const auto& native = adapter.GetContext();
    lbcrypto::GLIntProductionGLRBridge::Receipt receipt;
    receipt.schema = "openfhe.gl_int.glr_full_chain.v1";
    receipt.parameterFingerprint =
        glscheme::rns::glr_parameter_fingerprint(native.params);
    receipt.integerKeyTag = "gl-int-full-" + std::string(64, 'a');
    receipt.nativeKeyLineageCommitment =
        "sha256:" + std::string(64, 'b');
    receipt.representation = "Q25-L0-dense-Eq5-m-plus-tE";
    receipt.admissionRejection =
        "BootstrapDirect rejected: the dense integer lineage has no "
        "certified Q7/L18 m+t*e to SHIP input lift or mod-t refresh theorem";
    receipt.plaintextModulus = 1579009;
    receipt.nativeLevel = 0;
    receipt.activeQPrimes = native.active_q_primes(0);
    receipt.exactModuloT = true;
    receipt.denseEq5Layout = true;
    receipt.tErrorInvariant = true;
    receipt.denseTernaryOwner = true;
    receipt.ownerSecretLineageBound = true;

    const bool validReceiptRejected =
        ThrowsContaining(
            [&] { bridge.RequireBootstrapDirectAdmission(receipt); },
            "BootstrapDirect rejected") &&
        ThrowsContaining(
            [&] { bridge.RequireProductionSecurityAuthorization(receipt); },
            "production security rejected");
    auto malformed = receipt;
    malformed.plaintextModulus += 1;
    const bool malformedReceiptRejected =
        ThrowsContaining(
            [&] { bridge.RequireBootstrapDirectAdmission(malformed); },
            "malformed GL integer bridge receipt") &&
        ThrowsContaining(
            [&] {
                bridge.RequireProductionSecurityAuthorization(malformed);
            },
            "malformed GL integer bridge receipt");
    const auto integerCiphertext = MakeFinalLevelCiphertext(adapter);
    const auto negated = bridge.NegateFullChain(integerCiphertext);
    const bool exactNegation =
        ExactNegation(adapter, integerCiphertext, negated);
    const bool malformedNegationRejected = ThrowsContaining(
        [&] {
            (void)bridge.NegateFullChain(
                lbcrypto::GLIntProductionGLRBridge::NativeCiphertext{});
        },
        "authentic full-chain integer Slot ciphertext");

    return capabilities.exactQ2CoefficientBridge &&
                   capabilities.exactQ2SlotBridge &&
                   capabilities.ownerDerivedNativeLineage &&
                   capabilities.denseEq5IntegerBatch &&
                   capabilities.fullChainSymmetricTErrEncryption &&
                   capabilities.fullChainBGVModSwitch &&
                   capabilities.fullChainBGVModSwitchExactIntegerSemantics &&
                   capabilities.fullChainPublicTErrEncryption &&
                   capabilities.compactSeededPublicA &&
                   capabilities.fullChainDenseTernaryOwnerKeygen &&
                   capabilities.fullChainSwitchIntSmall &&
                   capabilities.fullChainSwitchIntBig &&
                   capabilities.compactSeededSwitchKeys &&
                   capabilities.fullChainDenseHadamard &&
                   capabilities.fullChainDenseTraceProduct &&
                   capabilities.fullChainKeyedAutomorphisms &&
                   capabilities.fullChainNegate &&
                   capabilities.selectableGPUTraceGemm &&
                   capabilities.strictFullChainReceiptValidation &&
                   !capabilities.productionSecurityAuthorized &&
                   !capabilities.bootstrapDirectAdmitted &&
                   validReceiptRejected && malformedReceiptRejected &&
                   exactNegation && malformedNegationRejected
               ? 0
               : 1;
}
