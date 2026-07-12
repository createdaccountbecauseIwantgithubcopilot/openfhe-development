#include "openfhe/pke/gl-int-production-glr-bridge.h"

int main() {
    auto adapter = lbcrypto::GLRProductionAdapter::Create();
    const lbcrypto::GLIntProductionGLRBridge bridge(adapter);
    const auto capabilities = bridge.GetCapabilities();
    return capabilities.exactQ2CoefficientBridge &&
                   capabilities.exactQ2SlotBridge &&
                   capabilities.ownerDerivedNativeLineage &&
                   !capabilities.productionSecurityAuthorized &&
                   !capabilities.bootstrapDirectAdmitted
               ? 0
               : 1;
}
