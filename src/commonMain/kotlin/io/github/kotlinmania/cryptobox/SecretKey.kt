// port-lint: source secret_key.rs
package io.github.kotlinmania.cryptobox

import io.github.kotlinmania.constanttimeeq.constantTimeEq32
import io.github.kotlinmania.cryptobox.internal.Curve25519
import io.github.kotlinmania.getrandom.GetrandomResult
import io.github.kotlinmania.getrandom.getrandom
import io.github.kotlinmania.zeroize.Zeroize
import io.github.kotlinmania.zeroize.ZeroizeOnDrop
import io.github.kotlinmania.zeroize.zeroize
import kotlin.random.Random

/**
 * A CryptoBox secret key.
 */
public class SecretKey(
    private val bytes: ByteArray,
) : Zeroize,
    ZeroizeOnDrop,
    AutoCloseable {
    private val scalar: ByteArray

    init {
        require(bytes.size == KEY_SIZE) {
            "Invalid secret key length: expected $KEY_SIZE bytes, got ${bytes.size}"
        }
        scalar = Curve25519.clampScalar(bytes)
    }

    override fun zeroize() {
        bytes.zeroize()
        scalar.zeroize()
    }

    override fun close() {
        zeroize()
    }

    /**
     * Zeroize the secret key material when no longer needed.
     */
    public fun drop() {
        zeroize()
    }

    /**
     * Get the [PublicKey] which corresponds to this [SecretKey].
     */
    public fun publicKey(): PublicKey {
        val pubBytes = Curve25519.scalarmultBase(scalar)
        return PublicKey(pubBytes)
    }

    /**
     * Serialize [SecretKey] to bytes.
     *
     * Warning: The serialized bytes are secret key material. Please treat them with
     * the care they deserve!
     */
    public fun toBytes(): ByteArray = bytes.copyOf()

    /**
     * Return a copy of this secret key's bytes.
     */
    public fun toByteArray(): ByteArray = bytes.copyOf()

    /**
     * Obtain the inner clamped scalar bytes of this [SecretKey].
     *
     * Warning: This value is key material. Please treat it with the care it deserves!
     */
    public fun toScalar(): ByteArray = scalar.copyOf()

    /**
     * Implementation of the sealed box decryption function from libsodium "sealed boxes".
     *
     * Sealed boxes are designed to anonymously send messages to a recipient given their public key.
     */
    public fun unseal(ciphertext: ByteArray): ByteArray {
        require(ciphertext.size > KEY_SIZE) { "Ciphertext too short for sealed box" }

        val ephemeralPkBytes = ciphertext.copyOfRange(0, KEY_SIZE)
        val ephemeralPk = PublicKey.fromBytes(ephemeralPkBytes)
        val nonce = getSealNonce(ephemeralPk, publicKey())
        val salsaBox = SalsaBox(ephemeralPk, this)
        val encrypted = ciphertext.copyOfRange(KEY_SIZE, ciphertext.size)
        return salsaBox.decrypt(nonce, encrypted)
    }

    /**
     * Alias for [unseal] matching libsodium's sealed box open.
     */
    public fun sealOpen(ciphertext: ByteArray): ByteArray = unseal(ciphertext)

    /**
     * Serialize this secret key to a byte array.
     */
    public fun serialize(): ByteArray = bytes.copyOf()

    /**
     * Serialize this secret key to an uppercase hexadecimal string.
     */
    public fun serializeHex(): String =
        bytes.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0').uppercase() }

    /**
     * Format this secret key with redacted contents.
     */
    public fun fmt(): String = toString()

    /**
     * Constant-time equality comparison on the secret key's scalar.
     */
    public fun eq(other: SecretKey): Boolean = equals(other)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SecretKey) return false
        return constantTimeEq32(scalar, other.scalar)
    }

    override fun hashCode(): Int = scalar.contentHashCode()

    override fun toString(): String = "SecretKey([REDACTED])"

    public companion object {
        public const val KEY_SIZE: Int = 32

        /**
         * Initialize [SecretKey] from a byte array.
         */
        public fun fromBytes(bytes: ByteArray): SecretKey = SecretKey(bytes.copyOf())

        /**
         * Initialize [SecretKey] from a byte slice.
         *
         * Throws [IllegalArgumentException] if the slice length is not exactly equal to [KEY_SIZE].
         */
        public fun fromSlice(slice: ByteArray): SecretKey {
            require(slice.size == KEY_SIZE) {
                "Invalid secret key length: expected $KEY_SIZE bytes, got ${slice.size}"
            }
            return SecretKey(slice.copyOf())
        }

        /**
         * Initialize [SecretKey] from a 32-byte array.
         */
        public fun from(bytes: ByteArray): SecretKey = fromBytes(bytes)

        /**
         * Initialize [SecretKey] from a 32-byte clamped scalar.
         */
        public fun fromScalar(scalar: ByteArray): SecretKey = fromBytes(scalar)

        /**
         * Attempt to initialize [SecretKey] from a byte slice.
         */
        public fun tryFrom(slice: ByteArray): SecretKey = fromSlice(slice)

        /**
         * Generate a random [SecretKey] using the operating system CSPRNG (`getrandom`).
         */
        public fun generate(): SecretKey {
            val bytes = ByteArray(KEY_SIZE)
            when (val res = getrandom(bytes)) {
                is GetrandomResult.Ok -> {
                    return SecretKey(bytes)
                }

                is GetrandomResult.Failure -> {
                    error("Failed to obtain OS randomness for SecretKey: ${res.errorMessage ?: "unknown error"}")
                }
            }
        }

        /**
         * Generate a random [SecretKey] using the provided random number generator.
         */
        public fun generate(random: Random): SecretKey {
            val bytes = ByteArray(KEY_SIZE)
            random.nextBytes(bytes)
            return SecretKey(bytes)
        }

        /**
         * Deserialize a [SecretKey] from a 32-byte array.
         */
        public fun deserialize(bytes: ByteArray): SecretKey = fromSlice(bytes)

        /**
         * Deserialize a [SecretKey] from a hexadecimal string.
         */
        public fun deserializeHex(hex: String): SecretKey {
            require(hex.length == KEY_SIZE * 2) {
                "Invalid secret key hex length: expected ${KEY_SIZE * 2} characters, got ${hex.length}"
            }
            val decoded = ByteArray(KEY_SIZE)
            for (i in 0 until KEY_SIZE) {
                val index = i * 2
                decoded[i] = hex.substring(index, index + 2).toInt(16).toByte()
            }
            return fromBytes(decoded)
        }
    }
}
