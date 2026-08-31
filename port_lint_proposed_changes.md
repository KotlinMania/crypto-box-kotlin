# port-lint Proposed Changes

**Generated:** 2026-08-31
**Source:** tmp
**Target:** src/commonMain/kotlin/io/github/kotlinmania/cryptobox

These are review proposals only. They are emitted when a Rust -> Kotlin pair matches only after fallback normalization, so the existing `port-lint` header is not an exact provenance match.

| Target file | Current header | Proposed header | Source path | Reason |
|-------------|----------------|-----------------|-------------|--------|
| `src/commonMain/kotlin/io/github/kotlinmania/cryptobox/internal/Blake2b.kt` | `// port-lint: source crypto_box/src/lib.rs` | `// port-lint: source crypto_box/tests/lib.rs` | `crypto_box/tests/lib.rs` | `port-lint provenance header matched only by basename: 'crypto_box/src/lib.rs' vs expected 'crypto_box/tests/lib.rs'` |
