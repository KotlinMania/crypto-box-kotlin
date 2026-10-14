// port-lint: source public_key.rs
package io.github.kotlinmania.cryptobox

import kotlin.random.Random

/**
 * A CryptoBox public key.
 */
public class PublicKey(
    private val bytes: ByteArray,
) : Comparable<PublicKey> {
    init {
        require(bytes.size == KEY_SIZE) {
            "Invalid public key length: expected $KEY_SIZE bytes, got ${bytes.size}"
        }
    }

    /**
     * Borrow the public key as bytes.
     */
    public fun asBytes(): ByteArray = bytes.copyOf()

    /**
     * Serialize this public key as bytes.
     */
    public fun toBytes(): ByteArray = bytes.copyOf()

    /**
     * Return a copy of this public key's bytes.
     */
    public fun toByteArray(): ByteArray = bytes.copyOf()

    /**
     * Borrow the public key as a byte array reference.
     */
    public fun asRef(): ByteArray = bytes.copyOf()

    /**
     * Implementation of the sealed box encryption function from libsodium "sealed boxes".
     *
     * Sealed boxes are designed to anonymously send messages to a recipient given their public key.
     */
    public fun seal(plaintext: ByteArray): ByteArray = seal(plaintext, Random.Default)

    /**
     * Implementation of the sealed box encryption function from libsodium "sealed boxes"
     * using the provided random number generator.
     */
    public fun seal(plaintext: ByteArray, random: Random): ByteArray {
        val ephemeralSk = SecretKey.generate(random)
        val ephemeralPk = ephemeralSk.publicKey()

        val nonce = getSealNonce(ephemeralPk, this)
        val salsaBox = SalsaBox(this, ephemeralSk)
        val encrypted = salsaBox.encrypt(nonce, plaintext)
        ephemeralSk.zeroize()

        val out = ByteArray(KEY_SIZE + encrypted.size)
        ephemeralPk.asBytes().copyInto(out, 0, 0, KEY_SIZE)
        encrypted.copyInto(out, KEY_SIZE, 0, encrypted.size)
        return out
    }

    /**
     * Serialize this public key to a byte array.
     */
    public fun serialize(): ByteArray = bytes.copyOf()

    /**
     * Serialize this public key to an uppercase hexadecimal string.
     */
    public fun serializeHex(): String =
        bytes.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0').uppercase() }

    /**
     * Compare this public key with [other] lexicographically.
     */
    public fun cmp(other: PublicKey): Int = compareTo(other)

    /**
     * Partially compare this public key with [other] lexicographically.
     */
    public fun partialCmp(other: PublicKey): Int = compareTo(other)

    override fun compareTo(other: PublicKey): Int {
        for (i in 0 until KEY_SIZE) {
            val a = bytes[i].toInt() and 0xFF
            val b = other.bytes[i].toInt() and 0xFF
            if (a != b) return a.compareTo(b)
        }
        return 0
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PublicKey) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String =
        "PublicKey(" + bytes.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') } + ")"

    public companion object {
        public const val KEY_SIZE: Int = 32

        /**
         * Initialize [PublicKey] from a byte array.
         */
        public fun fromBytes(bytes: ByteArray): PublicKey = PublicKey(bytes.copyOf())

        /**
         * Initialize [PublicKey] from a byte slice.
         *
         * Throws [IllegalArgumentException] if the slice length is not exactly equal to [KEY_SIZE].
         */
        public fun fromSlice(slice: ByteArray): PublicKey {
            require(slice.size == KEY_SIZE) {
                "Invalid public key length: expected $KEY_SIZE bytes, got ${slice.size}"
            }
            return PublicKey(slice.copyOf())
        }

        /**
         * Derive the [PublicKey] corresponding to the given [secretKey].
         */
        public fun from(secretKey: SecretKey): PublicKey = secretKey.publicKey()

        /**
         * Initialize [PublicKey] from a 32-byte array.
         */
        public fun from(bytes: ByteArray): PublicKey = fromBytes(bytes)

        /**
         * Attempt to initialize [PublicKey] from a byte slice.
         */
        public fun tryFrom(slice: ByteArray): PublicKey = fromSlice(slice)

        /**
         * Deserialize a [PublicKey] from a 32-byte array.
         */
        public fun deserialize(bytes: ByteArray): PublicKey = fromSlice(bytes)

        /**
         * Deserialize a [PublicKey] from a hexadecimal string.
         */
        public fun deserializeHex(hex: String): PublicKey {
            require(hex.length == KEY_SIZE * 2) {
                "Invalid public key hex length: expected ${KEY_SIZE * 2} characters, got ${hex.length}"
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
