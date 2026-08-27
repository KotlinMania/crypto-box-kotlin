# Immediate Actions - High-Value Files

Based on AST analysis, here are the concrete next steps.

## Summary

- **Files Present:** 3/3 (100.0%)
- **Function parity:** 11/35 matched (target 78) — 31.4%
- **Class/type parity:** 4/11 matched (target 11) — 36.4%
- **Combined symbol parity:** 15/46 matched (target 89) — 32.6%
- **Average inline-code cosine:** 0.16 (function body across 3 matched files)
- **Average documentation cosine:** 0.37 (doc text across 3 matched files)
- **Cheat-zeroed Files:** 0
- **Critical Issues:** 3 files with <0.60 function similarity

## Priority 1: Fix Incomplete High-Dependency Files

No incomplete high-dependency files detected.

## Priority 2: Port Missing High-Value Files

Critical missing files (>10 dependencies):

No missing high-value files detected.

## Detailed Work Items

Every matched file is listed below with function and type symbol parity.

### 1. lib

- **Target:** `cryptobox.CryptoBox`
- **Similarity:** 0.08
- **Dependents:** 0
- **Priority Score:** 131609.2
- **Functions:** 1/9 matched (target 58)
- **Missing functions:** `new`, `encrypt_in_place`, `encrypt_in_place_detached`, `decrypt_in_place`, `decrypt_in_place_detached`, `get_seal_nonce`, `test_public_key_serialization`, `test_secret_key_serialization`
- **Types:** 2/7 matched (target 9)
- **Missing types:** `Tag`, `CryptoBox`, `NonceSize`, `TagSize`, `CiphertextOverhead`
- **Tests:** 1/3 matched

### 2. secret_key

- **Target:** `cryptobox.SecretKey`
- **Similarity:** 0.23
- **Dependents:** 0
- **Priority Score:** 91607.7
- **Functions:** 6/14 matched (target 11)
- **Missing functions:** `to_scalar`, `fmt`, `drop`, `from`, `eq`, `try_from`, `serialize`, `deserialize`
- **Types:** 1/2 matched (target 1)
- **Missing types:** `Error`

### 3. public_key

- **Target:** `cryptobox.PublicKey`
- **Similarity:** 0.17
- **Dependents:** 0
- **Priority Score:** 91408.3
- **Functions:** 4/12 matched (target 9)
- **Missing functions:** `to_bytes`, `as_ref`, `from`, `try_from`, `partial_cmp`, `cmp`, `serialize`, `deserialize`
- **Types:** 1/2 matched (target 1)
- **Missing types:** `Error`

## Success Criteria

For each file to be considered "complete":
- **Similarity ≥ 0.85** (Excellent threshold)
- All public APIs ported
- All tests ported
- Documentation ported
- port-lint header present

