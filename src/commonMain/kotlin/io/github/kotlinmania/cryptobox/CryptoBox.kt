// port-lint: source lib.rs
package io.github.kotlinmania.cryptobox

import io.github.kotlinmania.cryptobox.internal.Blake2b
import io.github.kotlinmania.cryptobox.internal.ChaCha20
import io.github.kotlinmania.cryptobox.internal.Curve25519
import io.github.kotlinmania.cryptobox.internal.Salsa20
import io.github.kotlinmania.getrandom.GetrandomResult
import io.github.kotlinmania.getrandom.getrandom
import io.github.kotlinmania.zeroize.zeroize
import kotlin.random.Random

/**
 * Size of a CryptoBox public or secret key in bytes.
 */
public const val KEY_SIZE: Int = 32

/**
 * Size of a CryptoBox nonce in bytes.
 */
public const val NONCE_SIZE: Int = 24

/**
 * Size of a Poly1305 tag in bytes.
 */
public const val TAG_SIZE: Int = 16

/**
 * Extra bytes for the ciphertext of a sealed box compared to the plaintext.
 */
public const val SEALBYTES: Int = KEY_SIZE + TAG_SIZE

/**
 * Size of a nonce in bytes for AEAD operations.
 */
public const val NonceSize: Int = NONCE_SIZE

/**
 * Size of an authentication tag in bytes for AEAD operations.
 */
public const val TagSize: Int = TAG_SIZE

/**
 * Extra overhead bytes beyond the authentication tag for AEAD ciphertexts.
 */
public const val CiphertextOverhead: Int = 0

/**
 * Poly1305 authentication tag (16 bytes).
 */
public typealias Tag = ByteArray

/**
 * CryptoBox nonce (24 bytes).
 */
public typealias Nonce = ByteArray

/**
 * Error type thrown when key slice conversion or authenticated decryption fails.
 */
public typealias Error = IllegalArgumentException

internal fun getSealNonce(ephemeralPk: PublicKey, recipientPk: PublicKey): ByteArray {
    val hasher = Blake2b.new24()
    hasher.update(ephemeralPk.asBytes())
    hasher.update(recipientPk.asBytes())
    return hasher.finalize()
}

/**
 * Public-key encryption scheme based on the X25519 Elliptic Curve
 * Diffie-Hellman function and the authenticated encryption cipher.
 *
 * Note that additional associated data (AAD) is not supported and encryption
 * operations will throw [IllegalArgumentException] if non-empty associated data is provided.
 */
public class CryptoBox(
    private val key: ByteArray,
) {
    public constructor(publicKey: PublicKey, secretKey: SecretKey) : this(
        deriveKey(publicKey, secretKey),
    )

    public fun encrypt(nonce: ByteArray, plaintext: ByteArray): ByteArray =
        Salsa20.xsalsa20poly1305Encrypt(key, nonce, plaintext)

    public fun decrypt(nonce: ByteArray, ciphertext: ByteArray): ByteArray =
        Salsa20.xsalsa20poly1305Decrypt(key, nonce, ciphertext)

    public fun encryptInPlace(
        nonce: ByteArray,
        associatedData: ByteArray,
        buffer: ByteArray,
    ): ByteArray {
        val tag = Salsa20.xsalsa20poly1305EncryptInPlaceDetached(key, nonce, associatedData, buffer)
        val out = ByteArray(TAG_SIZE + buffer.size)
        tag.copyInto(out, 0, 0, TAG_SIZE)
        buffer.copyInto(out, TAG_SIZE, 0, buffer.size)
        return out
    }

    public fun encryptInPlaceDetached(
        nonce: ByteArray,
        associatedData: ByteArray,
        buffer: ByteArray,
    ): ByteArray = Salsa20.xsalsa20poly1305EncryptInPlaceDetached(key, nonce, associatedData, buffer)

    public fun decryptInPlace(
        nonce: ByteArray,
        associatedData: ByteArray,
        buffer: ByteArray,
    ): ByteArray {
        require(buffer.size >= TAG_SIZE) { "Ciphertext too short" }
        val tag = buffer.copyOfRange(0, TAG_SIZE)
        val body = buffer.copyOfRange(TAG_SIZE, buffer.size)
        Salsa20.xsalsa20poly1305DecryptInPlaceDetached(key, nonce, associatedData, body, tag)
        return body
    }

    public fun decryptInPlaceDetached(
        nonce: ByteArray,
        associatedData: ByteArray,
        buffer: ByteArray,
        tag: ByteArray,
    ) {
        Salsa20.xsalsa20poly1305DecryptInPlaceDetached(key, nonce, associatedData, buffer, tag)
    }

    public companion object {
        public fun new(publicKey: PublicKey, secretKey: SecretKey): CryptoBox =
            CryptoBox(publicKey, secretKey)

        public fun generateNonce(): ByteArray {
            val nonce = ByteArray(NONCE_SIZE)
            when (val res = getrandom(nonce)) {
                is GetrandomResult.Ok -> {
                    return nonce
                }

                is GetrandomResult.Failure -> {
                    error("Failed to obtain OS randomness for nonce: ${res.errorMessage ?: "unknown error"}")
                }
            }
        }

        public fun generateNonce(random: Random): ByteArray {
            val nonce = ByteArray(NONCE_SIZE)
            random.nextBytes(nonce)
            return nonce
        }

        private fun deriveKey(publicKey: PublicKey, secretKey: SecretKey): ByteArray {
            val sharedSecret = Curve25519.scalarmult(secretKey.toScalar(), publicKey.asBytes())
            val derived = Salsa20.hsalsa20(sharedSecret, ByteArray(16))
            sharedSecret.zeroize()
            return derived
        }
    }
}

/**
 * [CryptoBox] instantiated with the Salsa20 stream cipher (XSalsa20Poly1305).
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

    public fun encryptInPlace(
        nonce: ByteArray,
        associatedData: ByteArray,
        buffer: ByteArray,
    ): ByteArray {
        val tag = Salsa20.xsalsa20poly1305EncryptInPlaceDetached(key, nonce, associatedData, buffer)
        val out = ByteArray(TAG_SIZE + buffer.size)
        tag.copyInto(out, 0, 0, TAG_SIZE)
        buffer.copyInto(out, TAG_SIZE, 0, buffer.size)
        return out
    }

    public fun encryptInPlaceDetached(
        nonce: ByteArray,
        associatedData: ByteArray,
        buffer: ByteArray,
    ): ByteArray = Salsa20.xsalsa20poly1305EncryptInPlaceDetached(key, nonce, associatedData, buffer)

    public fun decryptInPlace(
        nonce: ByteArray,
        associatedData: ByteArray,
        buffer: ByteArray,
    ): ByteArray {
        require(buffer.size >= TAG_SIZE) { "Ciphertext too short" }
        val tag = buffer.copyOfRange(0, TAG_SIZE)
        val body = buffer.copyOfRange(TAG_SIZE, buffer.size)
        Salsa20.xsalsa20poly1305DecryptInPlaceDetached(key, nonce, associatedData, body, tag)
        return body
    }

    public fun decryptInPlaceDetached(
        nonce: ByteArray,
        associatedData: ByteArray,
        buffer: ByteArray,
        tag: ByteArray,
    ) {
        Salsa20.xsalsa20poly1305DecryptInPlaceDetached(key, nonce, associatedData, buffer, tag)
    }

    public companion object {
        public fun new(publicKey: PublicKey, secretKey: SecretKey): SalsaBox =
            SalsaBox(publicKey, secretKey)

        public fun generateNonce(): ByteArray = CryptoBox.generateNonce()

        public fun generateNonce(random: Random): ByteArray = CryptoBox.generateNonce(random)

        private fun deriveKey(publicKey: PublicKey, secretKey: SecretKey): ByteArray {
            val sharedSecret = Curve25519.scalarmult(secretKey.toScalar(), publicKey.asBytes())
            val derived = Salsa20.hsalsa20(sharedSecret, ByteArray(16))
            sharedSecret.zeroize()
            return derived
        }
    }
}

/**
 * [CryptoBox] instantiated with the ChaCha20 stream cipher (XChaCha20Poly1305).
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

    public fun encryptInPlace(
        nonce: ByteArray,
        associatedData: ByteArray,
        buffer: ByteArray,
    ): ByteArray {
        val tag = ChaCha20.xchacha20poly1305EncryptInPlaceDetached(key, nonce, associatedData, buffer)
        val out = ByteArray(TAG_SIZE + buffer.size)
        tag.copyInto(out, 0, 0, TAG_SIZE)
        buffer.copyInto(out, TAG_SIZE, 0, buffer.size)
        return out
    }

    public fun encryptInPlaceDetached(
        nonce: ByteArray,
        associatedData: ByteArray,
        buffer: ByteArray,
    ): ByteArray = ChaCha20.xchacha20poly1305EncryptInPlaceDetached(key, nonce, associatedData, buffer)

    public fun decryptInPlace(
        nonce: ByteArray,
        associatedData: ByteArray,
        buffer: ByteArray,
    ): ByteArray {
        require(buffer.size >= TAG_SIZE) { "Ciphertext too short" }
        val tag = buffer.copyOfRange(0, TAG_SIZE)
        val body = buffer.copyOfRange(TAG_SIZE, buffer.size)
        ChaCha20.xchacha20poly1305DecryptInPlaceDetached(key, nonce, associatedData, body, tag)
        return body
    }

    public fun decryptInPlaceDetached(
        nonce: ByteArray,
        associatedData: ByteArray,
        buffer: ByteArray,
        tag: ByteArray,
    ) {
        ChaCha20.xchacha20poly1305DecryptInPlaceDetached(key, nonce, associatedData, buffer, tag)
    }

    public companion object {
        public fun new(publicKey: PublicKey, secretKey: SecretKey): ChaChaBox =
            ChaChaBox(publicKey, secretKey)

        public fun generateNonce(): ByteArray = CryptoBox.generateNonce()

        public fun generateNonce(random: Random): ByteArray = CryptoBox.generateNonce(random)

        private fun deriveKey(publicKey: PublicKey, secretKey: SecretKey): ByteArray {
            val sharedSecret = Curve25519.scalarmult(secretKey.toScalar(), publicKey.asBytes())
            val derived = ChaCha20.hchacha20(sharedSecret, ByteArray(16))
            sharedSecret.zeroize()
            return derived
        }
    }
}
