// port-lint: tests lib.rs
package io.github.kotlinmania.cryptobox

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CryptoBoxTest {
    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.filter { !it.isWhitespace() }
        val result = ByteArray(clean.length / 2)
        for (i in result.indices) {
            val index = i * 2
            val v = clean.substring(index, index + 2).toInt(16)
            result[i] = v.toByte()
        }
        return result
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private val aliceSecretKeyBytes =
        hexToBytes("68f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d4c")
    private val alicePublicKeyBytes =
        hexToBytes("ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d")

    private val bobSecretKeyBytes =
        hexToBytes("b581fb5ae182a16f603f39270d4e3b95bc008310b727a11dd4e784a0044d461b")
    private val bobPublicKeyBytes =
        hexToBytes("e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754")

    private val nonce = hexToBytes("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")

    private val plaintext =
        byteArrayOf(
            0xbe.toByte(),
            0x07.toByte(),
            0x5f.toByte(),
            0xc5.toByte(),
            0x3c.toByte(),
            0x81.toByte(),
            0xf2.toByte(),
            0xd5.toByte(),
            0xcf.toByte(),
            0x14.toByte(),
            0x13.toByte(),
            0x16.toByte(),
            0xeb.toByte(),
            0xeb.toByte(),
            0x0c.toByte(),
            0x7b.toByte(),
            0x52.toByte(),
            0x28.toByte(),
            0xc5.toByte(),
            0x2a.toByte(),
            0x4c.toByte(),
            0x62.toByte(),
            0xcb.toByte(),
            0xd4.toByte(),
            0x4b.toByte(),
            0x66.toByte(),
            0x84.toByte(),
            0x9b.toByte(),
            0x64.toByte(),
            0x24.toByte(),
            0x4f.toByte(),
            0xfc.toByte(),
            0xe5.toByte(),
            0xec.toByte(),
            0xba.toByte(),
            0xaf.toByte(),
            0x33.toByte(),
            0xbd.toByte(),
            0x75.toByte(),
            0x1a.toByte(),
            0x1a.toByte(),
            0xc7.toByte(),
            0x28.toByte(),
            0xd4.toByte(),
            0x5e.toByte(),
            0x6c.toByte(),
            0x61.toByte(),
            0x29.toByte(),
            0x6c.toByte(),
            0xdc.toByte(),
            0x3c.toByte(),
            0x01.toByte(),
            0x23.toByte(),
            0x35.toByte(),
            0x61.toByte(),
            0xf4.toByte(),
            0x1d.toByte(),
            0xb6.toByte(),
            0x6c.toByte(),
            0xce.toByte(),
            0x31.toByte(),
            0x4a.toByte(),
            0xdb.toByte(),
            0x31.toByte(),
            0x0e.toByte(),
            0x3b.toByte(),
            0xe8.toByte(),
            0x25.toByte(),
            0x0c.toByte(),
            0x46.toByte(),
            0xf0.toByte(),
            0x6d.toByte(),
            0xce.toByte(),
            0xea.toByte(),
            0x3a.toByte(),
            0x7f.toByte(),
            0xa1.toByte(),
            0x34.toByte(),
            0x80.toByte(),
            0x57.toByte(),
            0xe2.toByte(),
            0xf6.toByte(),
            0x55.toByte(),
            0x6a.toByte(),
            0xd6.toByte(),
            0xb1.toByte(),
            0x31.toByte(),
            0x8a.toByte(),
            0x02.toByte(),
            0x4a.toByte(),
            0x83.toByte(),
            0x8f.toByte(),
            0x21.toByte(),
            0xaf.toByte(),
            0x1f.toByte(),
            0xde.toByte(),
            0x04.toByte(),
            0x89.toByte(),
            0x77.toByte(),
            0xeb.toByte(),
            0x48.toByte(),
            0xf5.toByte(),
            0x9f.toByte(),
            0xfd.toByte(),
            0x49.toByte(),
            0x24.toByte(),
            0xca.toByte(),
            0x1c.toByte(),
            0x60.toByte(),
            0x90.toByte(),
            0x2e.toByte(),
            0x52.toByte(),
            0xf0.toByte(),
            0xa0.toByte(),
            0x89.toByte(),
            0xbc.toByte(),
            0x76.toByte(),
            0x89.toByte(),
            0x70.toByte(),
            0x40.toByte(),
            0xe0.toByte(),
            0x82.toByte(),
            0xf9.toByte(),
            0x37.toByte(),
            0x76.toByte(),
            0x38.toByte(),
            0x48.toByte(),
            0x64.toByte(),
            0x5e.toByte(),
            0x07.toByte(),
            0x05.toByte(),
        )

    private val salsaCiphertext =
        hexToBytes(
            "c03f27d188ef650cd12936913137bb17" +
                "ed4c98c2648939e2e1d2e855470a7b8c632cabfd5ab3b3c2d313dc8c9ecf5da173e1f9c318cdef1dced6d251" +
                "9e695085e6b5c401a2bd5331442986c7076d412625497c4cb2fd94c6f103961033b2c930d7e82e0341f29d38" +
                "79bd6ab9d881ea3a1f365d634e653c6e171aac7fc1e76934d23be6f04a54010808dbf0f9bd30f63b68d026",
        )

    private val chachaCiphertext =
        hexToBytes(
            "0cd5ed093de698c8e410d0d451df2f52" +
                "83057376b947b9b7392b956e5d675f309218acce8cf85f6cf6a9e2e09ef8c5b0f97c661ee21b1b3418be5666" +
                "92634056a92b4034d5d0cf14c52420a488b7f0da0c5740dfc6b85397d3a8f679e84303e8d3f8b048abdb2dd7" +
                "9183b0a62683a1bc2a527fc9b82c5ffac4a684bcfeadfdcd28930b2dbe597f4716a658ccfca5b44049e06c",
        )

    private val sealSecretKeyBytes = hexToBytes("15b36cb00213373fb3fb03958fb0cc0012ecaca112fd249d3cf0961e311caac9")
    private val sealPublicKeyBytes = hexToBytes("fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574")
    private val sealPlaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.".encodeToByteArray()
    private val sealCiphertext =
        hexToBytes(
            "95eb5bf05ada25ee51f4158201c261a00bfb1955a9176c8c7f1a62f299a32e54" +
                "f6ebccc8ab9d2ce1b1d3710ba37d8db17aeeec0b78fc3d32b39b79ed96f18948c5a574b8e3f8eccc2f1324" +
                "08c21646f3aedae4a67fde4f77153b5458b8a6bd712dd8365534c567ec",
        )

    @Test
    fun generateSecretKey() {
        val sk = SecretKey.generate()
        assertEquals(32, sk.toBytes().size)
        val pk = sk.publicKey()
        assertEquals(32, pk.asBytes().size)
    }

    @Test
    fun secretAndPublicKeys() {
        val aliceSk = SecretKey.fromBytes(aliceSecretKeyBytes)
        assertEquals(bytesToHex(aliceSecretKeyBytes), bytesToHex(aliceSk.toBytes()))
        assertEquals(bytesToHex(alicePublicKeyBytes), bytesToHex(aliceSk.publicKey().asBytes()))

        val bobSk = SecretKey.fromBytes(bobSecretKeyBytes)
        assertEquals(bytesToHex(bobSecretKeyBytes), bytesToHex(bobSk.toBytes()))
        assertEquals(bytesToHex(bobPublicKeyBytes), bytesToHex(bobSk.publicKey().asBytes()))
    }

    @Test
    fun salsaBoxEncrypt() {
        val aliceSk = SecretKey.fromBytes(aliceSecretKeyBytes)
        val bobPk = PublicKey.fromBytes(bobPublicKeyBytes)

        val aliceBox = SalsaBox(bobPk, aliceSk)
        val ciphertext = aliceBox.encrypt(nonce, plaintext)

        assertEquals(bytesToHex(salsaCiphertext), bytesToHex(ciphertext))
    }

    @Test
    fun salsaBoxDecrypt() {
        val bobSk = SecretKey.fromBytes(bobSecretKeyBytes)
        val alicePk = PublicKey.fromBytes(alicePublicKeyBytes)

        val bobBox = SalsaBox(alicePk, bobSk)
        val decrypted = bobBox.decrypt(nonce, salsaCiphertext)

        assertTrue(plaintext.contentEquals(decrypted))
    }

    @Test
    fun chachaBoxEncrypt() {
        val aliceSk = SecretKey.fromBytes(aliceSecretKeyBytes)
        val bobPk = PublicKey.fromBytes(bobPublicKeyBytes)

        val aliceBox = ChaChaBox(bobPk, aliceSk)
        val ciphertext = aliceBox.encrypt(nonce, plaintext)

        assertEquals(bytesToHex(chachaCiphertext), bytesToHex(ciphertext))
    }

    @Test
    fun chachaBoxDecrypt() {
        val bobSk = SecretKey.fromBytes(bobSecretKeyBytes)
        val alicePk = PublicKey.fromBytes(alicePublicKeyBytes)

        val bobBox = ChaChaBox(alicePk, bobSk)
        val decrypted = bobBox.decrypt(nonce, chachaCiphertext)

        assertTrue(plaintext.contentEquals(decrypted))
    }

    @Test
    fun sealedBoxSealAndOpen() {
        val pk = PublicKey.fromBytes(sealPublicKeyBytes)
        val sk = SecretKey.fromBytes(sealSecretKeyBytes)

        val unsealedFromVector = sk.unseal(sealCiphertext)
        assertTrue(sealPlaintext.contentEquals(unsealedFromVector))

        val encrypted = pk.seal(sealPlaintext)
        val decrypted = sk.sealOpen(encrypted)
        assertTrue(sealPlaintext.contentEquals(decrypted))
    }

    @Test
    fun testPublicKeyFromSlice() {
        val array = ByteArray(40)

        assertFailsWith<IllegalArgumentException> {
            PublicKey.fromSlice(ByteArray(0))
        }

        for (i in 1..31) {
            assertFailsWith<IllegalArgumentException> {
                PublicKey.fromSlice(array.copyOfRange(0, i))
            }
        }

        val pk = PublicKey.fromSlice(array.copyOfRange(0, 32))
        assertEquals(32, pk.asBytes().size)

        for (i in 33..40) {
            assertFailsWith<IllegalArgumentException> {
                PublicKey.fromSlice(array.copyOfRange(0, i))
            }
        }
    }
}
