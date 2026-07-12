#include "openfhe/pke/gl-int-production-glr-bridge.h"

int main() {
    auto adapter = lbcrypto::GLRProductionAdapter::Create();
    const lbcrypto::GLIntProductionGLRBridge bridge(adapter);
    const auto capabilities = bridge.GetCapabilities();
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
                   !capabilities.productionSecurityAuthorized &&
                   !capabilities.bootstrapDirectAdmitted
               ? 0
               : 1;
}
