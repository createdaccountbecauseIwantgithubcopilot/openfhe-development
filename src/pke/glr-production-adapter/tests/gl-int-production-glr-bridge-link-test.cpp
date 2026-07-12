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

    return capabilities.exactQ2CoefficientBridge &&
                   capabilities.exactQ2SlotBridge &&
                   capabilities.ownerDerivedNativeLineage &&
                   capabilities.denseEq5IntegerBatch &&
                   capabilities.fullChainSymmetricTErrEncryption &&
                   capabilities.fullChainBGVModSwitch &&
                   capabilities.fullChainPublicTErrEncryption &&
                   capabilities.compactSeededPublicA &&
                   capabilities.fullChainDenseTernaryOwnerKeygen &&
                   capabilities.fullChainSwitchIntSmall &&
                   capabilities.fullChainSwitchIntBig &&
                   capabilities.compactSeededSwitchKeys &&
                   capabilities.fullChainDenseHadamard &&
                   capabilities.fullChainDenseTraceProduct &&
                   capabilities.fullChainKeyedAutomorphisms &&
                   capabilities.selectableGPUTraceGemm &&
                   capabilities.strictFullChainReceiptValidation &&
                   !capabilities.productionSecurityAuthorized &&
                   !capabilities.bootstrapDirectAdmitted &&
                   validReceiptRejected && malformedReceiptRejected
               ? 0
               : 1;
}
