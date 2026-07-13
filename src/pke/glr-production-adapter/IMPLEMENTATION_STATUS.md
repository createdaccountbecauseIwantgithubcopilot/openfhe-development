# GLR production-adapter implementation status

## H64 selected-leaf P14 fold

The adapter exposes `GetH64SelectedLeafFoldCapabilities()` and
`EvaluateH64SelectedLeafFoldCpu()` for the selected-leaf fold committed in
GLScheme core revision `3f2675b1514f6535e63164074bf079bc8ecc7f36`.
The receipt binds the exact `GL-128-257-N32` parameter fingerprint and H64
support commitment. The evaluator accepts 64 provider-selected, randomized
nontransparent sparse-key leaves at L2, delegates the 63-product six-frontier
tree, and returns the primary-key result at L14 after conjugation-add and the
sparse-to-primary switch.

The fold uses the complete P14 basis: API sentinel `0`, effective special-prime
count 14, and 32,505,952 compact bytes (31.00 MiB) across the L2
relinearization key and two L14 return keys. The core owner acceptance executes
63 products, 63 relinearizations, 63 logical paired rescales, and 126 physical
Q-prime drops across all 32,768 X/W coordinates. The OpenFHE focused test pins
the typed delegation surface and metadata; it deliberately does not duplicate
the 184-second core owner run or claim a framework-native ciphertext value pass.

This seam starts after selection. Hidden encrypted controls, the complete
hidden 64-support fold, all-Y/StC value composition, a formal composed-noise
certificate, structured-security certification, GPU execution, production
authorization, and `BootstrapDirect` admission remain false.
