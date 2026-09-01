// port-lint: source lib.rs
package io.github.kotlinmania.cryptobox.internal

/**
 * An element of the field GF(2^255 - 19).
 *
 * Implemented using radix 2^25.5 (10 limbs of alternating 26 and 25 bits)
 * for constant-time, platform-independent field arithmetic.
 */
internal class FieldElement internal constructor(
    internal val l0: Long,
    internal val l1: Long,
    internal val l2: Long,
    internal val l3: Long,
    internal val l4: Long,
    internal val l5: Long,
    internal val l6: Long,
    internal val l7: Long,
    internal val l8: Long,
    internal val l9: Long,
) {
    companion object {
        val ZERO = FieldElement(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        val ONE = FieldElement(1, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        // d = -121665 / 121666 mod (2^255 - 19)
        // d = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
        val D =
            fromBytes(
                byteArrayOf(
                    0xa3.toByte(),
                    0x78.toByte(),
                    0x59.toByte(),
                    0x13.toByte(),
                    0xca.toByte(),
                    0x4d.toByte(),
                    0xeb.toByte(),
                    0x75.toByte(),
                    0xab.toByte(),
                    0xd8.toByte(),
                    0x41.toByte(),
                    0x41.toByte(),
                    0x4d.toByte(),
                    0x0a.toByte(),
                    0x70.toByte(),
                    0x00.toByte(),
                    0x98.toByte(),
                    0xe8.toByte(),
                    0x79.toByte(),
                    0x77.toByte(),
                    0x79.toByte(),
                    0x40.toByte(),
                    0xc7.toByte(),
                    0x8c.toByte(),
                    0x73.toByte(),
                    0xfe.toByte(),
                    0x6f.toByte(),
                    0x2b.toByte(),
                    0xee.toByte(),
                    0x6c.toByte(),
                    0x03.toByte(),
                    0x52.toByte(),
                ),
            )

        // 2d mod (2^255 - 19)
        val TWO_D = D.add(D)

        // sqrt(-1) mod (2^255 - 19)
        // = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
        val SQRT_M1 =
            fromBytes(
                byteArrayOf(
                    0xb0.toByte(),
                    0xa0.toByte(),
                    0x0e.toByte(),
                    0x4a.toByte(),
                    0x27.toByte(),
                    0x1b.toByte(),
                    0xee.toByte(),
                    0xc4.toByte(),
                    0x78.toByte(),
                    0xe4.toByte(),
                    0x2f.toByte(),
                    0xad.toByte(),
                    0x06.toByte(),
                    0x18.toByte(),
                    0x43.toByte(),
                    0x2f.toByte(),
                    0xa7.toByte(),
                    0xd7.toByte(),
                    0xfb.toByte(),
                    0x3d.toByte(),
                    0x99.toByte(),
                    0x00.toByte(),
                    0x4d.toByte(),
                    0x2b.toByte(),
                    0x0b.toByte(),
                    0xdf.toByte(),
                    0xc1.toByte(),
                    0x4f.toByte(),
                    0x80.toByte(),
                    0x24.toByte(),
                    0x83.toByte(),
                    0x2b.toByte(),
                ),
            )

        private fun load32(bytes: ByteArray, offset: Int): Long {
            val b0 = bytes[offset].toLong() and 0xFFL
            val b1 = bytes[offset + 1].toLong() and 0xFFL
            val b2 = bytes[offset + 2].toLong() and 0xFFL
            val b3 = bytes[offset + 3].toLong() and 0xFFL
            return b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
        }

        fun fromBytes(bytes: ByteArray): FieldElement {
            require(bytes.size >= 32) { "FieldElement requires 32 bytes" }
            val l0 = load32(bytes, 0) and 0x3FFFFFFL
            val l1 = (load32(bytes, 3) ushr 2) and 0x1FFFFFFL
            val l2 = (load32(bytes, 6) ushr 3) and 0x3FFFFFFL
            val l3 = (load32(bytes, 9) ushr 5) and 0x1FFFFFFL
            val l4 = (load32(bytes, 12) ushr 6) and 0x3FFFFFFL
            val l5 = load32(bytes, 16) and 0x1FFFFFFL
            val l6 = (load32(bytes, 19) ushr 1) and 0x3FFFFFFL
            val l7 = (load32(bytes, 22) ushr 3) and 0x1FFFFFFL
            val l8 = (load32(bytes, 25) ushr 4) and 0x3FFFFFFL
            val l9 = ((load32(bytes, 28) and 0x7FFFFFFFL) ushr 6) and 0x1FFFFFFL
            return FieldElement(l0, l1, l2, l3, l4, l5, l6, l7, l8, l9)
        }

        fun sqrtRatioM1(u: FieldElement, v: FieldElement): Pair<Boolean, FieldElement> {
            val v2 = v.square()
            val v3 = v2.mul(v)
            val v4 = v2.square()
            val v7 = v4.mul(v3)
            val uv3 = u.mul(v3)
            val uv7 = u.mul(v7)
            val pow = uv7.pow22523()
            var r = uv3.mul(pow)
            val check = v.mul(r.square())
            val negU = u.negate()

            val correctSign = check == u
            val flippedSign = check == negU

            if (flippedSign) {
                r = r.mul(SQRT_M1)
            }

            val isSquare = correctSign || flippedSign
            return Pair(isSquare, r)
        }
    }

    fun add(other: FieldElement): FieldElement =
        FieldElement(
            l0 + other.l0,
            l1 + other.l1,
            l2 + other.l2,
            l3 + other.l3,
            l4 + other.l4,
            l5 + other.l5,
            l6 + other.l6,
            l7 + other.l7,
            l8 + other.l8,
            l9 + other.l9,
        ).carry()

    fun sub(other: FieldElement): FieldElement {
        val p0 = 0x3FFFFEDL * 2
        val p1 = 0x1FFFFFFL * 2
        val p2 = 0x3FFFFFFL * 2
        val p3 = 0x1FFFFFFL * 2
        val p4 = 0x3FFFFFFL * 2
        val p5 = 0x1FFFFFFL * 2
        val p6 = 0x3FFFFFFL * 2
        val p7 = 0x1FFFFFFL * 2
        val p8 = 0x3FFFFFFL * 2
        val p9 = 0x1FFFFFFL * 2

        return FieldElement(
            (l0 + p0) - other.l0,
            (l1 + p1) - other.l1,
            (l2 + p2) - other.l2,
            (l3 + p3) - other.l3,
            (l4 + p4) - other.l4,
            (l5 + p5) - other.l5,
            (l6 + p6) - other.l6,
            (l7 + p7) - other.l7,
            (l8 + p8) - other.l8,
            (l9 + p9) - other.l9,
        ).carry()
    }

    fun negate(): FieldElement = ZERO.sub(this)

    fun mul(b: FieldElement): FieldElement {
        val a = this
        val a0 = a.l0
        val a1 = a.l1
        val a2 = a.l2
        val a3 = a.l3
        val a4 = a.l4
        val a5 = a.l5
        val a6 = a.l6
        val a7 = a.l7
        val a8 = a.l8
        val a9 = a.l9

        val b0 = b.l0
        val b1 = b.l1
        val b2 = b.l2
        val b3 = b.l3
        val b4 = b.l4
        val b5 = b.l5
        val b6 = b.l6
        val b7 = b.l7
        val b8 = b.l8
        val b9 = b.l9

        val a1x19 = a1 * 19L
        val a2x19 = a2 * 19L
        val a3x19 = a3 * 19L
        val a4x19 = a4 * 19L
        val a5x19 = a5 * 19L
        val a6x19 = a6 * 19L
        val a7x19 = a7 * 19L
        val a8x19 = a8 * 19L
        val a9x19 = a9 * 19L

        val a1x38 = a1x19 * 2L
        val a3x38 = a3x19 * 2L
        val a5x38 = a5x19 * 2L
        val a7x38 = a7x19 * 2L
        val a9x38 = a9x19 * 2L

        val b1x2 = b1 * 2L
        val b3x2 = b3 * 2L
        val b5x2 = b5 * 2L
        val b7x2 = b7 * 2L
        val b9x2 = b9 * 2L

        val r0 =
            a0 * b0 + a1x38 * b9 + a2x19 * b8 + a3x38 * b7 + a4x19 * b6 +
                a5x38 * b5 + a6x19 * b4 + a7x38 * b3 + a8x19 * b2 + a9x38 * b1

        val r1 =
            a0 * b1 + a1 * b0 + a2x19 * b9 + a3x19 * b8 + a4x19 * b7 +
                a5x19 * b6 + a6x19 * b5 + a7x19 * b4 + a8x19 * b3 + a9x19 * b2

        val r2 =
            a0 * b2 + a1 * b1x2 + a2 * b0 + a3x38 * b9 + a4x19 * b8 +
                a5x38 * b7 + a6x19 * b6 + a7x38 * b5 + a8x19 * b4 + a9x38 * b3

        val r3 =
            a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4x19 * b9 +
                a5x19 * b8 + a6x19 * b7 + a7x19 * b6 + a8x19 * b5 + a9x19 * b4

        val r4 =
            a0 * b4 + a1 * b3x2 + a2 * b2 + a3 * b1x2 + a4 * b0 +
                a5x38 * b9 + a6x19 * b8 + a7x38 * b7 + a8x19 * b6 + a9x38 * b5

        val r5 =
            a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0 +
                a6x19 * b9 + a7x19 * b8 + a8x19 * b7 + a9x19 * b6

        val r6 =
            a0 * b6 + a1 * b5x2 + a2 * b4 + a3 * b3x2 + a4 * b2 + a5 * b1x2 + a6 * b0 +
                a7x38 * b9 + a8x19 * b8 + a9x38 * b7

        val r7 =
            a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 +
                a6 * b1 + a7 * b0 + a8x19 * b9 + a9x19 * b8

        val r8 =
            a0 * b8 + a1 * b7x2 + a2 * b6 + a3 * b5x2 + a4 * b4 + a5 * b3x2 +
                a6 * b2 + a7 * b1x2 + a8 * b0 + a9x38 * b9

        val r9 =
            a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 +
                a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0

        return FieldElement(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9).carry()
    }

    fun square(): FieldElement = mul(this)

    fun pow22523(): FieldElement {
        var t0 = square()
        var t1 = t0.square()
        t1 = t1.square()
        t1 = mul(t1)
        t0 = t0.mul(t1)
        var t2 = t0.square()
        t1 = t1.mul(t2)

        t2 = t1.square()
        for (i in 1 until 5) t2 = t2.square()
        t1 = t2.mul(t1)

        t2 = t1.square()
        for (i in 1 until 10) t2 = t2.square()
        t2 = t2.mul(t1)

        var t3 = t2.square()
        for (i in 1 until 20) t3 = t3.square()
        t2 = t3.mul(t2)

        t2 = t2.square()
        for (i in 1 until 10) t2 = t2.square()
        t1 = t2.mul(t1)

        t2 = t1.square()
        for (i in 1 until 50) t2 = t2.square()
        t2 = t2.mul(t1)

        t3 = t2.square()
        for (i in 1 until 100) t3 = t3.square()
        t2 = t3.mul(t2)

        t2 = t2.square()
        for (i in 1 until 50) t2 = t2.square()
        t1 = t2.mul(t1)

        t1 = t1.square()
        t1 = t1.square()
        return t1.mul(this)
    }

    fun invert(): FieldElement {
        val t1 = pow22523()
        var t2 = t1.square()
        t2 = t2.square()
        t2 = t2.square()
        val z3 = square().mul(this)
        return t2.mul(z3)
    }

    private fun carry(): FieldElement {
        var c0 = l0
        var c1 = l1
        var c2 = l2
        var c3 = l3
        var c4 = l4
        var c5 = l5
        var c6 = l6
        var c7 = l7
        var c8 = l8
        var c9 = l9

        for (pass in 0 until 2) {
            var carry = c0 shr 26
            c0 = c0 and 0x3FFFFFFL
            c1 += carry
            carry = c1 shr 25
            c1 = c1 and 0x1FFFFFFL
            c2 += carry
            carry = c2 shr 26
            c2 = c2 and 0x3FFFFFFL
            c3 += carry
            carry = c3 shr 25
            c3 = c3 and 0x1FFFFFFL
            c4 += carry
            carry = c4 shr 26
            c4 = c4 and 0x3FFFFFFL
            c5 += carry
            carry = c5 shr 25
            c5 = c5 and 0x1FFFFFFL
            c6 += carry
            carry = c6 shr 26
            c6 = c6 and 0x3FFFFFFL
            c7 += carry
            carry = c7 shr 25
            c7 = c7 and 0x1FFFFFFL
            c8 += carry
            carry = c8 shr 26
            c8 = c8 and 0x3FFFFFFL
            c9 += carry
            carry = c9 shr 25
            c9 = c9 and 0x1FFFFFFL
            c0 += carry * 19L
        }

        return FieldElement(c0, c1, c2, c3, c4, c5, c6, c7, c8, c9)
    }

    fun toByteArray(): ByteArray {
        val c = this.carry()
        var c0 = c.l0
        var c1 = c.l1
        var c2 = c.l2
        var c3 = c.l3
        var c4 = c.l4
        var c5 = c.l5
        var c6 = c.l6
        var c7 = c.l7
        var c8 = c.l8
        var c9 = c.l9

        var q0 = c0 + 19L
        var carry = q0 shr 26
        q0 = q0 and 0x3FFFFFFL
        var q1 = c1 + carry
        carry = q1 shr 25
        q1 = q1 and 0x1FFFFFFL
        var q2 = c2 + carry
        carry = q2 shr 26
        q2 = q2 and 0x3FFFFFFL
        var q3 = c3 + carry
        carry = q3 shr 25
        q3 = q3 and 0x1FFFFFFL
        var q4 = c4 + carry
        carry = q4 shr 26
        q4 = q4 and 0x3FFFFFFL
        var q5 = c5 + carry
        carry = q5 shr 25
        q5 = q5 and 0x1FFFFFFL
        var q6 = c6 + carry
        carry = q6 shr 26
        q6 = q6 and 0x3FFFFFFL
        var q7 = c7 + carry
        carry = q7 shr 25
        q7 = q7 and 0x1FFFFFFL
        var q8 = c8 + carry
        carry = q8 shr 26
        q8 = q8 and 0x3FFFFFFL
        var q9 = c9 + carry
        carry = q9 shr 25
        q9 = q9 and 0x1FFFFFFL

        val mask = -carry
        val r0 = (c0 and mask.inv()) or (q0 and mask)
        val r1 = (c1 and mask.inv()) or (q1 and mask)
        val r2 = (c2 and mask.inv()) or (q2 and mask)
        val r3 = (c3 and mask.inv()) or (q3 and mask)
        val r4 = (c4 and mask.inv()) or (q4 and mask)
        val r5 = (c5 and mask.inv()) or (q5 and mask)
        val r6 = (c6 and mask.inv()) or (q6 and mask)
        val r7 = (c7 and mask.inv()) or (q7 and mask)
        val r8 = (c8 and mask.inv()) or (q8 and mask)
        val r9 = (c9 and mask.inv()) or (q9 and mask)

        val out = ByteArray(32)
        out[0] = r0.toByte()
        out[1] = (r0 shr 8).toByte()
        out[2] = (r0 shr 16).toByte()
        out[3] = ((r0 shr 24) or (r1 shl 2)).toByte()
        out[4] = (r1 shr 6).toByte()
        out[5] = (r1 shr 14).toByte()
        out[6] = ((r1 shr 22) or (r2 shl 3)).toByte()
        out[7] = (r2 shr 5).toByte()
        out[8] = (r2 shr 13).toByte()
        out[9] = ((r2 shr 21) or (r3 shl 5)).toByte()
        out[10] = (r3 shr 3).toByte()
        out[11] = (r3 shr 11).toByte()
        out[12] = ((r3 shr 19) or (r4 shl 6)).toByte()
        out[13] = (r4 shr 2).toByte()
        out[14] = (r4 shr 10).toByte()
        out[15] = (r4 shr 18).toByte()
        out[16] = r5.toByte()
        out[17] = (r5 shr 8).toByte()
        out[18] = (r5 shr 16).toByte()
        out[19] = ((r5 shr 24) or (r6 shl 1)).toByte()
        out[20] = (r6 shr 7).toByte()
        out[21] = (r6 shr 15).toByte()
        out[22] = ((r6 shr 23) or (r7 shl 3)).toByte()
        out[23] = (r7 shr 5).toByte()
        out[24] = (r7 shr 13).toByte()
        out[25] = ((r7 shr 21) or (r8 shl 4)).toByte()
        out[26] = (r8 shr 4).toByte()
        out[27] = (r8 shr 12).toByte()
        out[28] = ((r8 shr 20) or (r9 shl 6)).toByte()
        out[29] = (r9 shr 2).toByte()
        out[30] = (r9 shr 10).toByte()
        out[31] = (r9 shr 18).toByte()

        return out
    }

    fun isNegative(): Boolean = (toByteArray()[0].toInt() and 1) == 1

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is FieldElement) return false
        val a = this.toByteArray()
        val b = other.toByteArray()
        return a.contentEquals(b)
    }

    override fun hashCode(): Int = toByteArray().contentHashCode()

    override fun toString(): String =
        toByteArray().joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
}
