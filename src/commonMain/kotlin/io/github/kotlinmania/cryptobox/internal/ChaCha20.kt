// port-lint: source crypto_box/src/lib.rs
package io.github.kotlinmania.cryptobox.internal

internal object ChaCha20 {
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

    private fun rounds(x: IntArray) {
        for (i in 0 until 10) {
            // Column round
            qr(x, 0, 4, 8, 12)
            qr(x, 1, 5, 9, 13)
            qr(x, 2, 6, 10, 14)
            qr(x, 3, 7, 11, 15)
            // Diagonal round
            qr(x, 0, 5, 10, 15)
            qr(x, 1, 6, 11, 12)
            qr(x, 2, 7, 8, 13)
            qr(x, 3, 4, 9, 14)
        }
    }

    private fun qr(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]
        x[d] = rotl(x[d] xor x[a], 16)
        x[c] += x[d]
        x[b] = rotl(x[b] xor x[c], 12)
        x[a] += x[b]
        x[d] = rotl(x[d] xor x[a], 8)
        x[c] += x[d]
        x[b] = rotl(x[b] xor x[c], 7)
    }

    fun hchacha20(key: ByteArray, input: ByteArray): ByteArray {
        require(key.size == 32)
        require(input.size == 16)

        val x = IntArray(16)
        for (i in 0 until 4) x[i] = SIGMA[i]
        for (i in 0 until 8) x[4 + i] = loadLittleEndian32(key, i * 4)
        for (i in 0 until 4) x[12 + i] = loadLittleEndian32(input, i * 4)

        rounds(x)

        val out = ByteArray(32)
        for (i in 0 until 4) storeLittleEndian32(x[i], out, i * 4)
        for (i in 0 until 4) storeLittleEndian32(x[12 + i], out, 16 + i * 4)
        return out
    }

    private fun chacha20Block(key: ByteArray, nonce: ByteArray, counter: Long): ByteArray {
        val input = IntArray(16)
        for (i in 0 until 4) input[i] = SIGMA[i]
        for (i in 0 until 8) input[4 + i] = loadLittleEndian32(key, i * 4)
        input[12] = (counter and 0xFFFFFFFFL).toInt()
        input[13] = (counter ushr 32).toInt()
        input[14] = loadLittleEndian32(nonce, 0)
        input[15] = loadLittleEndian32(nonce, 4)

        val x = input.copyOf()
        rounds(x)

        val out = ByteArray(64)
        for (i in 0 until 16) {
            storeLittleEndian32(x[i] + input[i], out, i * 4)
        }
        return out
    }

    fun xchacha20poly1305Encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        require(key.size == 32)
        require(nonce.size == 24)

        val subkey = hchacha20(key, nonce.copyOfRange(0, 16))
        val chachaNonce = nonce.copyOfRange(16, 24)

        val block0 = chacha20Block(subkey, chachaNonce, 0L)
        val polyKey = block0.copyOfRange(0, 32)

        val ciphertext = ByteArray(plaintext.size)
        val firstChunk = minOf(32, plaintext.size)
        for (i in 0 until firstChunk) {
            ciphertext[i] = (plaintext[i].toInt() xor block0[32 + i].toInt()).toByte()
        }

        var offset = firstChunk
        var counter = 1L
        while (offset < plaintext.size) {
            val block = chacha20Block(subkey, chachaNonce, counter++)
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

    fun xchacha20poly1305Decrypt(key: ByteArray, nonce: ByteArray, ciphertextWithTag: ByteArray): ByteArray {
        require(key.size == 32)
        require(nonce.size == 24)
        require(ciphertextWithTag.size >= 16) { "Ciphertext too short" }

        val tag = ciphertextWithTag.copyOfRange(0, 16)
        val ciphertext = ciphertextWithTag.copyOfRange(16, ciphertextWithTag.size)

        val subkey = hchacha20(key, nonce.copyOfRange(0, 16))
        val chachaNonce = nonce.copyOfRange(16, 24)

        val block0 = chacha20Block(subkey, chachaNonce, 0L)
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
            val block = chacha20Block(subkey, chachaNonce, counter++)
            val toProcess = minOf(64, ciphertext.size - offset)
            for (i in 0 until toProcess) {
                plaintext[offset + i] = (ciphertext[offset + i].toInt() xor block[i].toInt()).toByte()
            }
            offset += toProcess
        }
        return plaintext
    }
}
