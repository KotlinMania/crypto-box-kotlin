// port-lint: source lib.rs
package io.github.kotlinmania.cryptobox.internal

/**
 * Poly1305 one-time authenticator (RFC 8439).
 */
internal object Poly1305 {
    fun authenticate(key: ByteArray, message: ByteArray): ByteArray {
        require(key.size == 32) { "Poly1305 key must be 32 bytes" }

        val rBytes = key.copyOfRange(0, 16)
        rBytes[3] = (rBytes[3].toInt() and 15).toByte()
        rBytes[7] = (rBytes[7].toInt() and 15).toByte()
        rBytes[11] = (rBytes[11].toInt() and 15).toByte()
        rBytes[15] = (rBytes[15].toInt() and 15).toByte()
        rBytes[4] = (rBytes[4].toInt() and 252).toByte()
        rBytes[8] = (rBytes[8].toInt() and 252).toByte()
        rBytes[12] = (rBytes[12].toInt() and 252).toByte()

        val r0 = ((rBytes[0].toLong() and 0xFF) or ((rBytes[1].toLong() and 0xFF) shl 8) or ((rBytes[2].toLong() and 0xFF) shl 16) or ((rBytes[3].toLong() and 0xFF) shl 24)) and 0x03FFFFFFL
        val r1 = (((rBytes[3].toLong() and 0xFF) ushr 2) or ((rBytes[4].toLong() and 0xFF) shl 6) or ((rBytes[5].toLong() and 0xFF) shl 14) or ((rBytes[6].toLong() and 0xFF) shl 22)) and 0x03FFFF03L
        val r2 = (((rBytes[6].toLong() and 0xFF) ushr 4) or ((rBytes[7].toLong() and 0xFF) shl 4) or ((rBytes[8].toLong() and 0xFF) shl 12) or ((rBytes[9].toLong() and 0xFF) shl 20)) and 0x03FFC0FFL
        val r3 = (((rBytes[9].toLong() and 0xFF) ushr 6) or ((rBytes[10].toLong() and 0xFF) shl 2) or ((rBytes[11].toLong() and 0xFF) shl 10) or ((rBytes[12].toLong() and 0xFF) shl 18)) and 0x03F03FFFL
        val r4 = (((rBytes[12].toLong() and 0xFF) ushr 8) or ((rBytes[13].toLong() and 0xFF) shl 0) or ((rBytes[14].toLong() and 0xFF) shl 8) or ((rBytes[15].toLong() and 0xFF) shl 16)) and 0x000FFFFFL

        val s1 = r1 * 5
        val s2 = r2 * 5
        val s3 = r3 * 5
        val s4 = r4 * 5

        var h0 = 0L
        var h1 = 0L
        var h2 = 0L
        var h3 = 0L
        var h4 = 0L

        var offset = 0
        while (offset < message.size) {
            val blockSize = minOf(16, message.size - offset)
            val buf = ByteArray(17)
            message.copyInto(buf, 0, offset, offset + blockSize)
            buf[blockSize] = 1

            val c0 = ((buf[0].toLong() and 0xFF) or ((buf[1].toLong() and 0xFF) shl 8) or ((buf[2].toLong() and 0xFF) shl 16) or ((buf[3].toLong() and 0xFF) shl 24)) and 0x03FFFFFFL
            val c1 = (((buf[3].toLong() and 0xFF) ushr 2) or ((buf[4].toLong() and 0xFF) shl 6) or ((buf[5].toLong() and 0xFF) shl 14) or ((buf[6].toLong() and 0xFF) shl 22)) and 0x03FFFFFFL
            val c2 = (((buf[6].toLong() and 0xFF) ushr 4) or ((buf[7].toLong() and 0xFF) shl 4) or ((buf[8].toLong() and 0xFF) shl 12) or ((buf[9].toLong() and 0xFF) shl 20)) and 0x03FFFFFFL
            val c3 = (((buf[9].toLong() and 0xFF) ushr 6) or ((buf[10].toLong() and 0xFF) shl 2) or ((buf[11].toLong() and 0xFF) shl 10) or ((buf[12].toLong() and 0xFF) shl 18)) and 0x03FFFFFFL
            val c4 = ((buf[12].toLong() and 0xFF) ushr 8) or ((buf[13].toLong() and 0xFF) shl 0) or ((buf[14].toLong() and 0xFF) shl 8) or ((buf[15].toLong() and 0xFF) shl 16) or ((buf[16].toLong() and 0xFF) shl 24)

            h0 += c0
            h1 += c1
            h2 += c2
            h3 += c3
            h4 += c4

            val d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
            var d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
            var d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
            var d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
            var d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

            var c = d0 ushr 26
            h0 = d0 and 0x03FFFFFFL
            d1 += c
            c = d1 ushr 26
            h1 = d1 and 0x03FFFFFFL
            d2 += c
            c = d2 ushr 26
            h2 = d2 and 0x03FFFFFFL
            d3 += c
            c = d3 ushr 26
            h3 = d3 and 0x03FFFFFFL
            d4 += c
            c = d4 ushr 26
            h4 = d4 and 0x03FFFFFFL
            h0 += c * 5
            c = h0 ushr 26
            h0 = h0 and 0x03FFFFFFL
            h1 += c

            offset += blockSize
        }

        var c = h1 ushr 26
        h1 = h1 and 0x03FFFFFFL
        h2 += c
        c = h2 ushr 26
        h2 = h2 and 0x03FFFFFFL
        h3 += c
        c = h3 ushr 26
        h3 = h3 and 0x03FFFFFFL
        h4 += c
        c = h4 ushr 26
        h4 = h4 and 0x03FFFFFFL
        h0 += c * 5
        c = h0 ushr 26
        h0 = h0 and 0x03FFFFFFL
        h1 += c

        val g0 = (h0 + 5) and 0x03FFFFFFL
        var gc = (h0 + 5) ushr 26
        val g1 = (h1 + gc) and 0x03FFFFFFL
        gc = (h1 + gc) ushr 26
        val g2 = (h2 + gc) and 0x03FFFFFFL
        gc = (h2 + gc) ushr 26
        val g3 = (h3 + gc) and 0x03FFFFFFL
        gc = (h3 + gc) ushr 26
        val g4 = h4 + gc - (1L shl 26)

        if (g4 >= 0) {
            h0 = g0
            h1 = g1
            h2 = g2
            h3 = g3
            h4 = g4
        }

        val f0 = (h0 or (h1 shl 26)) and 0xFFFFFFFFL
        val f1 = ((h1 ushr 6) or (h2 shl 20)) and 0xFFFFFFFFL
        val f2 = ((h2 ushr 12) or (h3 shl 14)) and 0xFFFFFFFFL
        val f3 = ((h3 ushr 18) or (h4 shl 8)) and 0xFFFFFFFFL

        val s0 = (key[16].toLong() and 0xFF) or ((key[17].toLong() and 0xFF) shl 8) or ((key[18].toLong() and 0xFF) shl 16) or ((key[19].toLong() and 0xFF) shl 24)
        val s1W = (key[20].toLong() and 0xFF) or ((key[21].toLong() and 0xFF) shl 8) or ((key[22].toLong() and 0xFF) shl 16) or ((key[23].toLong() and 0xFF) shl 24)
        val s2W = (key[24].toLong() and 0xFF) or ((key[25].toLong() and 0xFF) shl 8) or ((key[26].toLong() and 0xFF) shl 16) or ((key[27].toLong() and 0xFF) shl 24)
        val s3W = (key[28].toLong() and 0xFF) or ((key[29].toLong() and 0xFF) shl 8) or ((key[30].toLong() and 0xFF) shl 16) or ((key[31].toLong() and 0xFF) shl 24)

        var carry = 0L
        val t0 = (f0 + s0) and 0xFFFFFFFFL
        carry = (f0 + s0) ushr 32
        val t1 = (f1 + s1W + carry) and 0xFFFFFFFFL
        carry = (f1 + s1W + carry) ushr 32
        val t2 = (f2 + s2W + carry) and 0xFFFFFFFFL
        carry = (f2 + s2W + carry) ushr 32
        val t3 = (f3 + s3W + carry) and 0xFFFFFFFFL

        val tag = ByteArray(16)
        tag[0] = (t0 and 0xFF).toByte()
        tag[1] = ((t0 ushr 8) and 0xFF).toByte()
        tag[2] = ((t0 ushr 16) and 0xFF).toByte()
        tag[3] = ((t0 ushr 24) and 0xFF).toByte()

        tag[4] = (t1 and 0xFF).toByte()
        tag[5] = ((t1 ushr 8) and 0xFF).toByte()
        tag[6] = ((t1 ushr 16) and 0xFF).toByte()
        tag[7] = ((t1 ushr 24) and 0xFF).toByte()

        tag[8] = (t2 and 0xFF).toByte()
        tag[9] = ((t2 ushr 8) and 0xFF).toByte()
        tag[10] = ((t2 ushr 16) and 0xFF).toByte()
        tag[11] = ((t2 ushr 24) and 0xFF).toByte()

        tag[12] = (t3 and 0xFF).toByte()
        tag[13] = ((t3 ushr 8) and 0xFF).toByte()
        tag[14] = ((t3 ushr 16) and 0xFF).toByte()
        tag[15] = ((t3 ushr 24) and 0xFF).toByte()

        return tag
    }
}
