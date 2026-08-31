# Immediate Actions - High-Value Files

Based on AST analysis, here are the concrete next steps.

## Summary

- **Files Present:** 4/4 (100.0%)
- **Function parity:** 11/39 matched (target 78) — 28.2%
- **Class/type parity:** 4/11 matched (target 11) — 36.4%
- **Combined symbol parity:** 15/50 matched (target 89) — 30.0%
- **Average inline-code cosine:** 0.20 (function body across 2 matched files)
- **Average documentation cosine:** 0.37 (doc text across 2 matched files)
- **Cheat-zeroed Files:** 2
- **Critical Issues:** 4 files with <0.60 function similarity

## Priority 1: Fix Incomplete High-Dependency Files

No incomplete high-dependency files detected.

## Priority 2: Port Missing High-Value Files

Critical missing files (>10 dependencies):

No missing high-value files detected.

## Detailed Work Items

Every matched file is listed below with function and type symbol parity.

### 1. crypto_box.lib

- **Target:** `cryptobox.CryptoBox [STUB]`
- **Similarity:** 0.00
- **Dependents:** 0
- **Priority Score:** 131610.0
- **Functions:** 1/9 matched (target 54)
- **Missing functions:** `new`, `encrypt_in_place`, `encrypt_in_place_detached`, `decrypt_in_place`, `decrypt_in_place_detached`, `get_seal_nonce`, `test_public_key_serialization`, `test_secret_key_serialization`
- **Types:** 2/7 matched (target 8)
- **Missing types:** `Tag`, `CryptoBox`, `NonceSize`, `TagSize`, `CiphertextOverhead`
- **Tests:** 1/3 matched

### 2. crypto_box.secret_key

- **Target:** `cryptobox.SecretKey`
- **Similarity:** 0.23
- **Dependents:** 0
- **Priority Score:** 91607.7
- **Functions:** 6/14 matched (target 11)
- **Missing functions:** `to_scalar`, `fmt`, `drop`, `from`, `eq`, `try_from`, `serialize`, `deserialize`
- **Types:** 1/2 matched (target 1)
- **Missing types:** `Error`

### 3. crypto_box.public_key

- **Target:** `cryptobox.PublicKey`
- **Similarity:** 0.17
- **Dependents:** 0
- **Priority Score:** 91408.3
- **Functions:** 4/12 matched (target 9)
- **Missing functions:** `to_bytes`, `as_ref`, `from`, `try_from`, `partial_cmp`, `cmp`, `serialize`, `deserialize`
- **Types:** 1/2 matched (target 1)
- **Missing types:** `Error`

### 4. tests.lib

- **Target:** `internal.Blake2b [STUB] [PROVENANCE-FALLBACK]`
- **Similarity:** 0.00
- **Dependents:** 0
- **Priority Score:** 40410.0
- **Functions:** 0/4 matched
- **Missing functions:** `generate_secret_key`, `secret_and_public_keys`, `edwards_to_montgomery`, `seal`
- **Types:** 0/0 matched (target 1)
- **Missing types:** _none_
- **Tests:** 0/4 matched
- **Provenance warning:** port-lint provenance header matched only by basename: `crypto_box/src/lib.rs` vs expected `crypto_box/tests/lib.rs`
- **Proposed provenance header:** `// port-lint: source crypto_box/tests/lib.rs` (current: `// port-lint: source crypto_box/src/lib.rs`)
- **Lint issues:** 1

## Success Criteria

For each file to be considered "complete":
- **Similarity ≥ 0.85** (Excellent threshold)
- All public APIs ported
- All tests ported
- Documentation ported
- port-lint header present

