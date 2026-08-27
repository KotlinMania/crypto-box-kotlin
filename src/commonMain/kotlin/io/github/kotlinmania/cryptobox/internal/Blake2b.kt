// port-lint: source lib.rs
package io.github.kotlinmania.cryptobox.internal

/**
 * BLAKE2b cryptographic hash (RFC 7693) for 24-byte seal nonce derivation.
 */
internal object Blake2b {
    private val IV =
        longArrayOf(
            7640891576956012808L,
            -4942790177534073029L,
            4354685564936845355L,
            -6534734903238641935L,
            5840696475078001361L,
            -7276294671716946913L,
            2270897969802886507L,
            6620516959819538809L,
        )

    private val SIGMA =
        arrayOf(
            intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
            intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        )

    private fun rotr64(x: Long, n: Int): Long = (x ushr n) or (x shl (64 - n))

    private fun g(v: LongArray, a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
        v[a] = v[a] + v[b] + x
        v[d] = rotr64(v[d] xor v[a], 32)
        v[c] = v[c] + v[d]
        v[b] = rotr64(v[b] xor v[c], 24)
        v[a] = v[a] + v[b] + y
        v[d] = rotr64(v[d] xor v[a], 16)
        v[c] = v[c] + v[d]
        v[b] = rotr64(v[b] xor v[c], 63)
    }

    fun hash24(input: ByteArray): ByteArray {
        val outLen = 24
        val h = IV.copyOf()
        h[0] = h[0] xor 0x01010000L xor outLen.toLong()

        val buf = ByteArray(128)
        var bufLen = 0
        var totalBytes = 0L

        fun compress(last: Boolean) {
            val v = LongArray(16)
            for (i in 0 until 8) v[i] = h[i]
            for (i in 0 until 8) v[8 + i] = IV[i]

            v[12] = v[12] xor totalBytes
            if (last) {
                v[14] = v[14] xor -1L
            }

            val m = LongArray(16)
            for (i in 0 until 16) {
                var l = 0L
                for (j in 0 until 8) {
                    l = l or ((buf[i * 8 + j].toLong() and 0xFF) shl (j * 8))
                }
                m[i] = l
            }

            for (r in 0 until 12) {
                val s = SIGMA[r]
                g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
                g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
                g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
                g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
                g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
                g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
                g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
                g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
            }

            for (i in 0 until 8) {
                h[i] = h[i] xor v[i] xor v[i + 8]
            }
        }

        var offset = 0
        while (offset < input.size) {
            if (bufLen == 128) {
                totalBytes += 128
                compress(last = false)
                bufLen = 0
            }
            val toCopy = minOf(128 - bufLen, input.size - offset)
            input.copyInto(buf, bufLen, offset, offset + toCopy)
            bufLen += toCopy
            offset += toCopy
        }

        totalBytes += bufLen
        while (bufLen < 128) {
            buf[bufLen++] = 0
        }
        compress(last = true)

        val out = ByteArray(outLen)
        for (i in 0 until outLen) {
            val word = h[i / 8]
            val shift = (i % 8) * 8
            out[i] = ((word ushr shift) and 0xFF).toByte()
        }
        return out
    }
}
