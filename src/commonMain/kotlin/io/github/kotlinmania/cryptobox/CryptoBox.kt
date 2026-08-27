// port-lint: source lib.rs
package io.github.kotlinmania.cryptobox

import io.github.kotlinmania.cryptobox.internal.ChaCha20
import io.github.kotlinmania.cryptobox.internal.Curve25519
import io.github.kotlinmania.cryptobox.internal.Salsa20
import kotlin.random.Random

public const val KEY_SIZE: Int = 32
public const val NONCE_SIZE: Int = 24
public const val TAG_SIZE: Int = 16
public const val SEALBYTES: Int = KEY_SIZE + TAG_SIZE

/**
 * Public-key encryption scheme based on X25519 and XSalsa20Poly1305.
 */
public class SalsaBox(
    private val key: ByteArray,
) {
    public constructor(publicKey: PublicKey, secretKey: SecretKey) : this(
        deriveKey(publicKey, secretKey),
    )

    public fun encrypt(nonce: ByteArray, plaintext: ByteArray): ByteArray =
        Salsa20.xsalsa20poly1305Encrypt(key, nonce, plaintext)

    public fun decrypt(nonce: ByteArray, ciphertext: ByteArray): ByteArray =
        Salsa20.xsalsa20poly1305Decrypt(key, nonce, ciphertext)

    public companion object {
        public fun generateNonce(random: Random = Random.Default): ByteArray {
            val nonce = ByteArray(NONCE_SIZE)
            random.nextBytes(nonce)
            return nonce
        }

        private fun deriveKey(publicKey: PublicKey, secretKey: SecretKey): ByteArray {
            val sharedSecret = Curve25519.scalarmult(secretKey.toBytes(), publicKey.asBytes())
            return Salsa20.hsalsa20(sharedSecret, ByteArray(16))
        }
    }
}

/**
 * Public-key encryption scheme based on X25519 and XChaCha20Poly1305.
 */
public class ChaChaBox(
    private val key: ByteArray,
) {
    public constructor(publicKey: PublicKey, secretKey: SecretKey) : this(
        deriveKey(publicKey, secretKey),
    )

    public fun encrypt(nonce: ByteArray, plaintext: ByteArray): ByteArray =
        ChaCha20.xchacha20poly1305Encrypt(key, nonce, plaintext)

    public fun decrypt(nonce: ByteArray, ciphertext: ByteArray): ByteArray =
        ChaCha20.xchacha20poly1305Decrypt(key, nonce, ciphertext)

    public companion object {
        public fun generateNonce(random: Random = Random.Default): ByteArray {
            val nonce = ByteArray(NONCE_SIZE)
            random.nextBytes(nonce)
            return nonce
        }

        private fun deriveKey(publicKey: PublicKey, secretKey: SecretKey): ByteArray {
            val sharedSecret = Curve25519.scalarmult(secretKey.toBytes(), publicKey.asBytes())
            return ChaCha20.hchacha20(sharedSecret, ByteArray(16))
        }
    }
}
