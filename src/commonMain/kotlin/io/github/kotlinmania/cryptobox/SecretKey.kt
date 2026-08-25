// port-lint: source secret_key.rs
package io.github.kotlinmania.cryptobox

import io.github.kotlinmania.cryptobox.internal.Blake2b
import io.github.kotlinmania.cryptobox.internal.Curve25519
import kotlin.random.Random

/**
 * A CryptoBox secret key.
 */
public class SecretKey(
    private val bytes: ByteArray,
) {
    init {
        require(bytes.size == KEY_SIZE) {
            "Invalid secret key length: expected $KEY_SIZE bytes, got ${bytes.size}"
        }
    }

    public fun publicKey(): PublicKey {
        val pubBytes = Curve25519.scalarmultBase(bytes)
        return PublicKey(pubBytes)
    }

    public fun toBytes(): ByteArray = bytes.copyOf()

    public fun toByteArray(): ByteArray = bytes.copyOf()

    public fun sealOpen(ciphertext: ByteArray): ByteArray {
        require(ciphertext.size >= KEY_SIZE + 16) { "Ciphertext too short for sealed box" }

        val ephemeralPkBytes = ciphertext.copyOfRange(0, KEY_SIZE)
        val ephemeralPk = PublicKey.fromBytes(ephemeralPkBytes)
        val pk = publicKey()

        val nonceInput = ByteArray(KEY_SIZE * 2)
        ephemeralPkBytes.copyInto(nonceInput, 0, 0, KEY_SIZE)
        pk.asBytes().copyInto(nonceInput, KEY_SIZE, 0, KEY_SIZE)
        val nonce = Blake2b.hash24(nonceInput)

        val salsaBox = SalsaBox(ephemeralPk, this)
        val encrypted = ciphertext.copyOfRange(KEY_SIZE, ciphertext.size)
        return salsaBox.decrypt(nonce, encrypted)
    }

    public fun unseal(ciphertext: ByteArray): ByteArray = sealOpen(ciphertext)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SecretKey) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = "SecretKey([REDACTED])"

    public companion object {
        public const val KEY_SIZE: Int = 32

        public fun fromBytes(bytes: ByteArray): SecretKey = SecretKey(bytes.copyOf())

        public fun fromSlice(slice: ByteArray): SecretKey {
            require(slice.size == KEY_SIZE) {
                "Invalid secret key length: expected $KEY_SIZE bytes, got ${slice.size}"
            }
            return SecretKey(slice.copyOf())
        }

        public fun generate(random: Random = Random.Default): SecretKey {
            val bytes = ByteArray(KEY_SIZE)
            random.nextBytes(bytes)
            return SecretKey(bytes)
        }
    }
}
