// port-lint: source lib.rs
package io.github.kotlinmania.cryptobox.internal

internal object Salsa20 {
    private val SIGMA =
        intArrayOf(
            0x61707865,
            0x3320646e,
            0x79622d32,
            0x6b206574,
        )

    private fun rotl(v: Int, c: Int): Int = (v shl c) or (v ushr (32 - c))

    private fun loadLittleEndian32(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)

    private fun storeLittleEndian32(v: Int, bytes: ByteArray, offset: Int) {
        bytes[offset] = (v and 0xFF).toByte()
        bytes[offset + 1] = ((v ushr 8) and 0xFF).toByte()
        bytes[offset + 2] = ((v ushr 16) and 0xFF).toByte()
        bytes[offset + 3] = ((v ushr 24) and 0xFF).toByte()
    }

    fun hsalsa20(key: ByteArray, input: ByteArray): ByteArray {
        require(key.size == 32)
        require(input.size == 16)

        val x = IntArray(16)
        x[0] = SIGMA[0]
        x[1] = loadLittleEndian32(key, 0)
        x[2] = loadLittleEndian32(key, 4)
        x[3] = loadLittleEndian32(key, 8)
        x[4] = loadLittleEndian32(key, 12)
        x[5] = SIGMA[1]
        x[6] = loadLittleEndian32(input, 0)
        x[7] = loadLittleEndian32(input, 4)
        x[8] = loadLittleEndian32(input, 8)
        x[9] = loadLittleEndian32(input, 12)
        x[10] = SIGMA[2]
        x[11] = loadLittleEndian32(key, 16)
        x[12] = loadLittleEndian32(key, 20)
        x[13] = loadLittleEndian32(key, 24)
        x[14] = loadLittleEndian32(key, 28)
        x[15] = SIGMA[3]

        for (i in 0 until 10) {
            x[4] = x[4] xor rotl(x[0] + x[12], 7)
            x[8] = x[8] xor rotl(x[4] + x[0], 9)
            x[12] = x[12] xor rotl(x[8] + x[4], 13)
            x[0] = x[0] xor rotl(x[12] + x[8], 18)

            x[9] = x[9] xor rotl(x[5] + x[1], 7)
            x[13] = x[13] xor rotl(x[9] + x[5], 9)
            x[1] = x[1] xor rotl(x[13] + x[9], 13)
            x[5] = x[5] xor rotl(x[1] + x[13], 18)

            x[14] = x[14] xor rotl(x[10] + x[6], 7)
            x[2] = x[2] xor rotl(x[14] + x[10], 9)
            x[6] = x[6] xor rotl(x[2] + x[14], 13)
            x[10] = x[10] xor rotl(x[6] + x[2], 18)

            x[3] = x[3] xor rotl(x[15] + x[11], 7)
            x[7] = x[7] xor rotl(x[3] + x[15], 9)
            x[11] = x[11] xor rotl(x[7] + x[3], 13)
            x[15] = x[15] xor rotl(x[11] + x[7], 18)

            x[1] = x[1] xor rotl(x[0] + x[3], 7)
            x[2] = x[2] xor rotl(x[1] + x[0], 9)
            x[3] = x[3] xor rotl(x[2] + x[1], 13)
            x[0] = x[0] xor rotl(x[3] + x[2], 18)

            x[6] = x[6] xor rotl(x[5] + x[4], 7)
            x[7] = x[7] xor rotl(x[6] + x[5], 9)
            x[4] = x[4] xor rotl(x[7] + x[6], 13)
            x[5] = x[5] xor rotl(x[4] + x[7], 18)

            x[11] = x[11] xor rotl(x[10] + x[9], 7)
            x[8] = x[8] xor rotl(x[11] + x[10], 9)
            x[9] = x[9] xor rotl(x[8] + x[11], 13)
            x[10] = x[10] xor rotl(x[9] + x[8], 18)

            x[12] = x[12] xor rotl(x[15] + x[14], 7)
            x[13] = x[13] xor rotl(x[12] + x[15], 9)
            x[14] = x[14] xor rotl(x[13] + x[12], 13)
            x[15] = x[15] xor rotl(x[14] + x[13], 18)
        }

        val out = ByteArray(32)
        storeLittleEndian32(x[0], out, 0)
        storeLittleEndian32(x[5], out, 4)
        storeLittleEndian32(x[10], out, 8)
        storeLittleEndian32(x[15], out, 12)
        storeLittleEndian32(x[6], out, 16)
        storeLittleEndian32(x[7], out, 20)
        storeLittleEndian32(x[8], out, 24)
        storeLittleEndian32(x[9], out, 28)
        return out
    }

    private fun salsa20Block(key: ByteArray, nonce: ByteArray, counter: Long): ByteArray {
        val input = IntArray(16)
        input[0] = SIGMA[0]
        input[1] = loadLittleEndian32(key, 0)
        input[2] = loadLittleEndian32(key, 4)
        input[3] = loadLittleEndian32(key, 8)
        input[4] = loadLittleEndian32(key, 12)
        input[5] = SIGMA[1]
        input[6] = loadLittleEndian32(nonce, 0)
        input[7] = loadLittleEndian32(nonce, 4)
        input[8] = (counter and 0xFFFFFFFFL).toInt()
        input[9] = (counter ushr 32).toInt()
        input[10] = SIGMA[2]
        input[11] = loadLittleEndian32(key, 16)
        input[12] = loadLittleEndian32(key, 20)
        input[13] = loadLittleEndian32(key, 24)
        input[14] = loadLittleEndian32(key, 28)
        input[15] = SIGMA[3]

        val x = input.copyOf()
        for (i in 0 until 10) {
            x[4] = x[4] xor rotl(x[0] + x[12], 7)
            x[8] = x[8] xor rotl(x[4] + x[0], 9)
            x[12] = x[12] xor rotl(x[8] + x[4], 13)
            x[0] = x[0] xor rotl(x[12] + x[8], 18)

            x[9] = x[9] xor rotl(x[5] + x[1], 7)
            x[13] = x[13] xor rotl(x[9] + x[5], 9)
            x[1] = x[1] xor rotl(x[13] + x[9], 13)
            x[5] = x[5] xor rotl(x[1] + x[13], 18)

            x[14] = x[14] xor rotl(x[10] + x[6], 7)
            x[2] = x[2] xor rotl(x[14] + x[10], 9)
            x[6] = x[6] xor rotl(x[2] + x[14], 13)
            x[10] = x[10] xor rotl(x[6] + x[2], 18)

            x[3] = x[3] xor rotl(x[15] + x[11], 7)
            x[7] = x[7] xor rotl(x[3] + x[15], 9)
            x[11] = x[11] xor rotl(x[7] + x[3], 13)
            x[15] = x[15] xor rotl(x[11] + x[7], 18)

            x[1] = x[1] xor rotl(x[0] + x[3], 7)
            x[2] = x[2] xor rotl(x[1] + x[0], 9)
            x[3] = x[3] xor rotl(x[2] + x[1], 13)
            x[0] = x[0] xor rotl(x[3] + x[2], 18)

            x[6] = x[6] xor rotl(x[5] + x[4], 7)
            x[7] = x[7] xor rotl(x[6] + x[5], 9)
            x[4] = x[4] xor rotl(x[7] + x[6], 13)
            x[5] = x[5] xor rotl(x[4] + x[7], 18)

            x[11] = x[11] xor rotl(x[10] + x[9], 7)
            x[8] = x[8] xor rotl(x[11] + x[10], 9)
            x[9] = x[9] xor rotl(x[8] + x[11], 13)
            x[10] = x[10] xor rotl(x[9] + x[8], 18)

            x[12] = x[12] xor rotl(x[15] + x[14], 7)
            x[13] = x[13] xor rotl(x[12] + x[15], 9)
            x[14] = x[14] xor rotl(x[13] + x[12], 13)
            x[15] = x[15] xor rotl(x[14] + x[13], 18)
        }

        val out = ByteArray(64)
        for (i in 0 until 16) {
            storeLittleEndian32(x[i] + input[i], out, i * 4)
        }
        return out
    }

    fun xsalsa20poly1305Encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == 32)
        require(nonce.size == 24)

        val subkey = hsalsa20(key, nonce.copyOfRange(0, 16))
        val salsaNonce = nonce.copyOfRange(16, 24)

        val block0 = salsa20Block(subkey, salsaNonce, 0L)
        val polyKey = block0.copyOfRange(0, 32)

        val ciphertext = ByteArray(plaintext.size)
        // First 32 bytes of keystream come from block0[32..64]
        val firstChunk = minOf(32, plaintext.size)
        for (i in 0 until firstChunk) {
            ciphertext[i] = (plaintext[i].toInt() xor block0[32 + i].toInt()).toByte()
        }

        var offset = firstChunk
        var counter = 1L
        while (offset < plaintext.size) {
            val block = salsa20Block(subkey, salsaNonce, counter++)
            val toProcess = minOf(64, plaintext.size - offset)
            for (i in 0 until toProcess) {
                ciphertext[offset + i] = (plaintext[offset + i].toInt() xor block[i].toInt()).toByte()
            }
            offset += toProcess
        }

        val tag = Poly1305.authenticate(polyKey, ciphertext)
        val result = ByteArray(16 + ciphertext.size)
        tag.copyInto(result, 0, 0, 16)
        ciphertext.copyInto(result, 16, 0, ciphertext.size)
        return result
    }

    fun xsalsa20poly1305Decrypt(key: ByteArray, nonce: ByteArray, ciphertextWithTag: ByteArray): ByteArray {
        require(key.size == 32)
        require(nonce.size == 24)
        require(ciphertextWithTag.size >= 16) { "Ciphertext too short" }

        val tag = ciphertextWithTag.copyOfRange(0, 16)
        val ciphertext = ciphertextWithTag.copyOfRange(16, ciphertextWithTag.size)

        val subkey = hsalsa20(key, nonce.copyOfRange(0, 16))
        val salsaNonce = nonce.copyOfRange(16, 24)

        val block0 = salsa20Block(subkey, salsaNonce, 0L)
        val polyKey = block0.copyOfRange(0, 32)

        val computedTag = Poly1305.authenticate(polyKey, ciphertext)
        var diff = 0
        for (i in 0 until 16) {
            diff = diff or (tag[i].toInt() xor computedTag[i].toInt())
        }
        if (diff != 0) {
            throw IllegalArgumentException("Decryption failed: tag mismatch")
        }

        val plaintext = ByteArray(ciphertext.size)
        val firstChunk = minOf(32, ciphertext.size)
        for (i in 0 until firstChunk) {
            plaintext[i] = (ciphertext[i].toInt() xor block0[32 + i].toInt()).toByte()
        }

        var offset = firstChunk
        var counter = 1L
        while (offset < ciphertext.size) {
            val block = salsa20Block(subkey, salsaNonce, counter++)
            val toProcess = minOf(64, ciphertext.size - offset)
            for (i in 0 until toProcess) {
                plaintext[offset + i] = (ciphertext[offset + i].toInt() xor block[i].toInt()).toByte()
            }
            offset += toProcess
        }
        return plaintext
    }
}
