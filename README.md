# crypto-box-kotlin

[![GitHub](https://img.shields.io/badge/GitHub-KotlinMania%2Fcrypto--box--kotlin-blue.svg)](https://github.com/KotlinMania/crypto-box-kotlin)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.kotlinmania/crypto-box-kotlin)](https://central.sonatype.com/artifact/io.github.kotlinmania/crypto-box-kotlin)
[![Build Status](https://img.shields.io/github/actions/workflow/status/KotlinMania/crypto-box-kotlin/ci.yml?branch=main)](https://github.com/KotlinMania/crypto-box-kotlin/actions)
[![Kotlin](https://img.shields.io/badge/kotlin-2.4.20-blue.svg?logo=kotlin)](https://kotlinlang.org)
[![License](https://img.shields.io/badge/license-Apache%202.0%20%2F%20MIT-blue.svg)](LICENSE)

Pure Kotlin Multiplatform implementation of [NaCl](https://nacl.cr.yp.to/)'s [`crypto_box`](https://nacl.cr.yp.to/box.html) public-key authenticated encryption primitive, combining [X25519](https://cr.yp.to/ecdh.html) Elliptic Curve Diffie-Hellman key agreement with [XSalsa20Poly1305](https://nacl.cr.yp.to/secretbox.html) (`SalsaBox` / `CryptoBox`) and XChaCha20Poly1305 (`ChaChaBox`) authenticated encryption into an Elliptic Curve Integrated Encryption Scheme ([ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme)), including libsodium-compatible [sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes).

## Installation

Add `crypto-box-kotlin` to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("io.github.kotlinmania:crypto-box-kotlin:0.2.1")
}
```

## Quick Start

### 1. Public-Key Authenticated Encryption (`SalsaBox` & `ChaChaBox`)

Either party can encrypt or decrypt messages under the shared key derived via X25519 Diffie-Hellman key agreement. Use `SalsaBox` for classic NaCl `crypto_box` (XSalsa20Poly1305) or `ChaChaBox` for XChaCha20Poly1305:

```kotlin
import io.github.kotlinmania.cryptobox.ChaChaBox
import io.github.kotlinmania.cryptobox.PublicKey
import io.github.kotlinmania.cryptobox.SalsaBox
import io.github.kotlinmania.cryptobox.SecretKey

// Alice and Bob each generate a keypair
val aliceSecretKey = SecretKey.generate()
val alicePublicKey = aliceSecretKey.publicKey()

val bobSecretKey = SecretKey.generate()
val bobPublicKey = bobSecretKey.publicKey()

// Alice derives a box with Bob's public key and her secret key
val aliceBox = SalsaBox.new(bobPublicKey, aliceSecretKey)
val nonce = SalsaBox.generateNonce()
val plaintext = "Top secret message we're encrypting".encodeToByteArray()

// Encrypt (returns 16-byte Poly1305 tag + ciphertext)
val ciphertext = aliceBox.encrypt(nonce, plaintext)

// Bob derives the same box using Alice's public key and his secret key
val bobBox = SalsaBox.new(alicePublicKey, bobSecretKey)
val decrypted = bobBox.decrypt(nonce, ciphertext)
check(plaintext.contentEquals(decrypted))

// ChaChaBox provides the same API using XChaCha20Poly1305:
val chachaBox = ChaChaBox.new(bobPublicKey, aliceSecretKey)
val chachaNonce = ChaChaBox.generateNonce()
val chachaCiphertext = chachaBox.encrypt(chachaNonce, plaintext)
val chachaDecrypted = ChaChaBox.new(alicePublicKey, bobSecretKey).decrypt(chachaNonce, chachaCiphertext)
check(plaintext.contentEquals(chachaDecrypted))
```

### 2. Anonymous Sealed Boxes (`seal` & `unseal`)

Sealed boxes anonymously encrypt a message to a recipient's `PublicKey` using an ephemeral X25519 keypair and a BLAKE2b-derived nonce:

```kotlin
import io.github.kotlinmania.cryptobox.SecretKey

val recipientSecretKey = SecretKey.generate()
val recipientPublicKey = recipientSecretKey.publicKey()

val message = "Anonymous sealed box payload".encodeToByteArray()

// Sender only needs the recipient's PublicKey
val sealedCiphertext = recipientPublicKey.seal(message)

// Recipient opens the sealed box using their SecretKey
val unsealedPlaintext = recipientSecretKey.unseal(sealedCiphertext)
check(message.contentEquals(unsealedPlaintext))
```

### 3. In-Place & Detached Tag Operations

For zero-overhead buffer management or detached Poly1305 authentication tags:

```kotlin
import io.github.kotlinmania.cryptobox.ChaChaBox
import io.github.kotlinmania.cryptobox.SecretKey

val aliceSk = SecretKey.generate()
val bobSk = SecretKey.generate()
val box = ChaChaBox.new(bobSk.publicKey(), aliceSk)
val nonce = ChaChaBox.generateNonce()

val buffer = "Detached in-place encryption".encodeToByteArray()

// Encrypts `buffer` in place and returns the 16-byte authentication tag
val tag = box.encryptInPlaceDetached(nonce, ByteArray(0), buffer)

// Verifies `tag` in constant time and decrypts `buffer` in place
ChaChaBox.new(aliceSk.publicKey(), bobSk).decryptInPlaceDetached(nonce, ByteArray(0), buffer, tag)
```

### 4. Key Serialization & Memory Zeroization

`SecretKey` implements `Zeroize`, `ZeroizeOnDrop`, and `AutoCloseable` (via `zeroize-kotlin`) so secret key material and clamped scalars can be scrubbed when no longer needed:

```kotlin
import io.github.kotlinmania.cryptobox.PublicKey
import io.github.kotlinmania.cryptobox.SecretKey

SecretKey.generate().use { secretKey ->
    val publicKey = PublicKey.from(secretKey)

    // ByteArray and hexadecimal serialization round-trips
    val pubHex = publicKey.serializeHex()
    val restoredPub = PublicKey.deserializeHex(pubHex)
    check(restoredPub == publicKey)
} // secretKey.close() automatically zeroizes raw key bytes and scalar material
```

## API Overview

| Symbol | Description |
| :--- | :--- |
| `SecretKey` | X25519 secret key (`generate()`, `fromBytes()`, `fromSlice()`, `fromScalar()`, `publicKey()`, `toBytes()`, `toScalar()`, `unseal()`, `sealOpen()`, `serialize()`, `deserialize()`, `zeroize()`). |
| `PublicKey` | X25519 Montgomery public key (`from(SecretKey)`, `fromBytes()`, `fromSlice()`, `asBytes()`, `toBytes()`, `seal()`, `serialize()`, `deserialize()`, lexicographical `Comparable<PublicKey>`). |
| `SalsaBox` / `CryptoBox` | Authenticated encryption box using X25519 + XSalsa20Poly1305 (`new()`, `generateNonce()`, `encrypt()`, `decrypt()`, `encryptInPlace()`, `encryptInPlaceDetached()`, `decryptInPlace()`, `decryptInPlaceDetached()`). |
| `ChaChaBox` | Authenticated encryption box using X25519 + XChaCha20Poly1305 (`new()`, `generateNonce()`, `encrypt()`, `decrypt()`, `encryptInPlace()`, `encryptInPlaceDetached()`, `decryptInPlace()`, `decryptInPlaceDetached()`). |
| `KEY_SIZE` | `32` — Size of a public or secret key in bytes. |
| `NONCE_SIZE` / `NonceSize` | `24` — Size of a `SalsaBox` or `ChaChaBox` nonce in bytes. |
| `TAG_SIZE` / `TagSize` | `16` — Size of a Poly1305 authentication tag in bytes. |
| `SEALBYTES` | `48` (`KEY_SIZE + TAG_SIZE`) — Overhead bytes of a sealed box ciphertext. |

## Supported Targets

- **JVM** (JDK 21+)
- **Android** (API 24+)
- **Apple (Swift Export + XCFramework)**: `macosArm64`, `iosArm64`, `iosSimulatorArm64`, `tvosArm64`, `tvosSimulatorArm64`, `watchosDeviceArm64`, `watchosSimulatorArm64`
- **Linux**: `linuxX64`, `linuxArm64`
- **Windows**: `mingwX64`
- **Android Native**: `androidNativeArm64`, `androidNativeX64`
- **JavaScript & WebAssembly**: `js` (Browser & Node.js), `wasmJs` (Browser & Node.js), `wasmWasi` (Node.js)

## Building & Testing

```bash
./gradlew test
./gradlew build
```

---

## Upstream Attribution, Security Notes & License

### Acknowledgments

This library is a Kotlin Multiplatform port of [`crypto_box`](https://github.com/RustCrypto/nacl-compat/tree/master/crypto_box) from [`RustCrypto/nacl-compat`](https://github.com/RustCrypto/nacl-compat). Thanks to the `RustCrypto/nacl-compat` maintainers and contributors for the original design and implementation.

The upstream `crypto_box` crate received a [security audit by Cure53](https://cure53.de/pentest-report_rust-libs_2022.pdf) (version 0.7.1) with no significant findings, funded by [Threema](https://threema.ch/).

### License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option. See [LICENSE](LICENSE) for details.

Original work Copyright (c) RustCrypto Developers.  
Kotlin port Copyright (c) 2026 Sydney Renee and The Solace Project.
