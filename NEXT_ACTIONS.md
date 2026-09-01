# Immediate Actions - High-Value Files

Based on AST analysis, here are the concrete next steps.

## Summary

- **Files Present:** 4/4 (100.0%)
- **Function parity:** 10/26 matched (target 20) — 38.5%
- **Class/type parity:** 2/4 matched (target 2) — 50.0%
- **Combined symbol parity:** 12/30 matched (target 22) — 40.0%
- **Average inline-code cosine:** 0.20 (function body across 2 matched files)
- **Average documentation cosine:** 0.37 (doc text across 2 matched files)
- **Cheat-zeroed Files:** 0
- **Critical Issues:** 4 files with <0.60 function similarity

## Priority 1: Fix Incomplete High-Dependency Files

No incomplete high-dependency files detected.

## Priority 2: Port Missing High-Value Files

Critical missing files (>10 dependencies):

No missing high-value files detected.

## Detailed Work Items

Every matched file is listed below with function and type symbol parity.

### 1. crypto_box.secret_key

- **Target:** `cryptobox.SecretKey`
- **Similarity:** 0.23
- **Dependents:** 0
- **Priority Score:** 91607.7
- **Functions:** 6/14 matched (target 11)
- **Missing functions:** `to_scalar`, `fmt`, `drop`, `from`, `eq`, `try_from`, `serialize`, `deserialize`
- **Types:** 1/2 matched (target 1)
- **Missing types:** `Error`

### 2. crypto_box.public_key

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

## Reexport / Wiring Modules

These files match `reexport_modules` patterns in `.ast_distance_config.json`. They are filtered out of
normal priority and missing-file ladders because they are wiring
modules, not direct logic ports. Consult them for call-site routing;
do not treat them as the next implementation target by default.

### Matched

| Source | Target | Path |
|--------|--------|------|
| `crypto_box.lib` | `cryptobox.CryptoBox` | `crypto_box/src/lib` |
| `tests.lib` | `internal.Blake2b` | `crypto_box/tests/lib` |

