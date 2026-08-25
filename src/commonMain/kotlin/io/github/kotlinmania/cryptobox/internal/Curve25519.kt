// port-lint: source lib.rs
package io.github.kotlinmania.cryptobox.internal

/**
 * X25519 (RFC 7748) Montgomery curve scalar multiplication over Field 2^255 - 19.
 */
internal object Curve25519 {
    private val A24 = FieldElement(121665L, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    fun clampScalar(scalar: ByteArray): ByteArray {
        val clamped = scalar.copyOf(32)
        clamped[0] = (clamped[0].toInt() and 248).toByte()
        clamped[31] = (clamped[31].toInt() and 127).toByte()
        clamped[31] = (clamped[31].toInt() or 64).toByte()
        return clamped
    }

    fun scalarmult(scalar: ByteArray, point: ByteArray): ByteArray {
        val clamped = clampScalar(scalar)
        val x1 = FieldElement.fromBytes(point)
        var x2 = FieldElement.ONE
        var z2 = FieldElement.ZERO
        var x3 = x1
        var z3 = FieldElement.ONE

        var swap = 0
        for (pos in 254 downTo 0) {
            val byteIndex = pos / 8
            val bitIndex = pos % 8
            val bit = (clamped[byteIndex].toInt() ushr bitIndex) and 1
            swap = swap xor bit
            if (swap == 1) {
                val tx = x2; x2 = x3; x3 = tx
                val tz = z2; z2 = z3; z3 = tz
            }
            swap = bit

            val a = x2.add(z2)
            val aa = a.square()
            val b = x2.sub(z2)
            val bb = b.square()
            val e = aa.sub(bb)
            val c = x3.add(z3)
            val d = x3.sub(z3)
            val da = d.mul(a)
            val cb = c.mul(b)
            x3 = da.add(cb).square()
            z3 = x1.mul(da.sub(cb).square())
            x2 = aa.mul(bb)
            z2 = e.mul(aa.add(A24.mul(e)))
        }
        if (swap == 1) {
            val tx = x2; x2 = x3; x3 = tx
            val tz = z2; z2 = z3; z3 = tz
        }
        return x2.mul(z2.invert()).toByteArray()
    }

    fun scalarmultBase(scalar: ByteArray): ByteArray {
        val basePoint = ByteArray(32)
        basePoint[0] = 9
        return scalarmult(scalar, basePoint)
    }
}
