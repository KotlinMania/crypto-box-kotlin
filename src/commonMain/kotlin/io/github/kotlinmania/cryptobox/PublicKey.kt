// port-lint: source public_key.rs
package io.github.kotlinmania.cryptobox

import io.github.kotlinmania.cryptobox.internal.Blake2b

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

    public fun asBytes(): ByteArray = bytes.copyOf()

    public fun toByteArray(): ByteArray = bytes.copyOf()

    public fun seal(plaintext: ByteArray): ByteArray {
        val ephemeralSk = SecretKey.generate()
        val ephemeralPk = ephemeralSk.publicKey()

        val nonceInput = ByteArray(KEY_SIZE * 2)
        ephemeralPk.asBytes().copyInto(nonceInput, 0, 0, KEY_SIZE)
        bytes.copyInto(nonceInput, KEY_SIZE, 0, KEY_SIZE)
        val nonce = Blake2b.hash24(nonceInput)

        val salsaBox = SalsaBox(this, ephemeralSk)
        val encrypted = salsaBox.encrypt(nonce, plaintext)

        val out = ByteArray(KEY_SIZE + encrypted.size)
        ephemeralPk.asBytes().copyInto(out, 0, 0, KEY_SIZE)
        encrypted.copyInto(out, KEY_SIZE, 0, encrypted.size)
        return out
    }

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

        public fun fromBytes(bytes: ByteArray): PublicKey = PublicKey(bytes.copyOf())

        public fun fromSlice(slice: ByteArray): PublicKey {
            require(slice.size == KEY_SIZE) {
                "Invalid public key length: expected $KEY_SIZE bytes, got ${slice.size}"
            }
            return PublicKey(slice.copyOf())
        }
    }
}
