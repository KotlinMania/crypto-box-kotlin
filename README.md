# crypto-box-kotlin in Kotlin

[![GitHub link](https://img.shields.io/badge/GitHub-KotlinMania%2Fcrypto--box--kotlin-blue.svg)](https://github.com/KotlinMania/crypto-box-kotlin)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.kotlinmania/crypto-box-kotlin)](https://central.sonatype.com/artifact/io.github.kotlinmania/crypto-box-kotlin)
[![Build status](https://img.shields.io/github/actions/workflow/status/KotlinMania/crypto-box-kotlin/ci.yml?branch=main)](https://github.com/KotlinMania/crypto-box-kotlin/actions)

This is a Kotlin Multiplatform line-by-line transliteration port of [`RustCrypto/nacl-compa`](https://github.com/RustCrypto/nacl-compat).

**Original Project:** This port is based on [`RustCrypto/nacl-compa`](https://github.com/RustCrypto/nacl-compat). All design credit and project intent belong to the upstream authors; this repository is a faithful port to Kotlin Multiplatform with no behavioural changes intended.

### Porting status

This is an **in-progress port**. The goal is feature parity with the upstream Rust crate while providing a native Kotlin Multiplatform API. Every Kotlin file carries a `// port-lint: source <path>` header naming its upstream Rust counterpart so the AST-distance tool can track provenance.

---

## About this Kotlin port

### Installation

```kotlin
dependencies {
    implementation("io.github.kotlinmania:crypto-box-kotlin:0.1.1")
}
```

### Building

```bash
./gradlew build
./gradlew test
```

### Targets

- macOS arm64
- Linux x64
- Windows mingw-x64
- iOS arm64 / simulator-arm64 (Swift export + XCFramework)
- JS (browser + Node.js)
- Wasm-JS (browser + Node.js)
- Android (API 24+)

### Porting guidelines

See [AGENTS.md](AGENTS.md) and [CLAUDE.md](CLAUDE.md) for translator discipline, port-lint header convention, and Rust → Kotlin idiom mapping.

### License

This Kotlin port is distributed under the same Apache-2.0 license as the upstream [`RustCrypto/nacl-compa`](https://github.com/RustCrypto/nacl-compat). See [LICENSE](LICENSE) (and any sibling `LICENSE-*` / `NOTICE` files mirrored from upstream) for the full text.

Original work copyrighted by the nacl-compa authors.  
Kotlin port: Copyright (c) 2026 Sydney Renee and The Solace Project.

### Acknowledgments

Thanks to the [`RustCrypto/nacl-compa`](https://github.com/RustCrypto/nacl-compat) maintainers and contributors for the original Rust implementation. This port reproduces their work in Kotlin Multiplatform; bug reports about upstream design or behavior should go to the upstream repository.
