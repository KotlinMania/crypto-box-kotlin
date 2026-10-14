import Testing
import CryptoBox

@Suite("CryptoBox Export Smoke Tests")
struct CryptoBoxExportTests {
    @Test("Key generation, derivation, and serialization")
    func testKeyGenerationAndSerialization() throws {
        let aliceSk = SecretKey.Companion.shared.generate()
        #expect(aliceSk.toBytes().size == KEY_SIZE)
        #expect(aliceSk.toScalar().size == KEY_SIZE)
        #expect(aliceSk.fmt() == "SecretKey([REDACTED])")

        let alicePk = aliceSk.publicKey()
        #expect(alicePk.asBytes().size == KEY_SIZE)
        #expect(PublicKey.Companion.shared.from(secretKey: aliceSk) == alicePk)

        let pkHex = alicePk.serializeHex()
        let pkRestored = PublicKey.Companion.shared.deserializeHex(hex: pkHex)
        #expect(pkRestored == alicePk)

        let skHex = aliceSk.serializeHex()
        let skRestored = SecretKey.Companion.shared.deserializeHex(hex: skHex)
        #expect(skRestored == aliceSk)

        aliceSk.zeroize()
        let zeroedBytes = aliceSk.toBytes()
        for i in 0..<zeroedBytes.size {
            #expect(zeroedBytes[i] == 0)
        }
    }

    @Test("SalsaBox, ChaChaBox, CryptoBox, and sealed box round-trips")
    func testEncryptionAndSealedBoxes() throws {
        let aliceSk = SecretKey.Companion.shared.generate()
        let alicePk = aliceSk.publicKey()
        let bobSk = SecretKey.Companion.shared.generate()
        let bobPk = bobSk.publicKey()

        let message = SecretKey.Companion.shared.generate().toBytes()
        let emptyAad = PublicKey.Companion.shared.deserializeHex(
            hex: "0000000000000000000000000000000000000000000000000000000000000000"
        )
        _ = emptyAad

        // SalsaBox encrypt / decrypt
        let salsaNonce = SalsaBox.Companion.shared.generateNonce()
        #expect(salsaNonce.size == NONCE_SIZE)
        let aliceSalsa = SalsaBox.Companion.shared.new(publicKey: bobPk, secretKey: aliceSk)
        let bobSalsa = SalsaBox.Companion.shared.new(publicKey: alicePk, secretKey: bobSk)
        let salsaCiphertext = aliceSalsa.encrypt(nonce: salsaNonce, plaintext: message)
        #expect(salsaCiphertext.size == message.size + TAG_SIZE)
        let salsaPlaintext = bobSalsa.decrypt(nonce: salsaNonce, ciphertext: salsaCiphertext)
        #expect(salsaPlaintext.size == message.size)
        for i in 0..<message.size {
            #expect(salsaPlaintext[i] == message[i])
        }

        // ChaChaBox encrypt / decrypt
        let chachaNonce = ChaChaBox.Companion.shared.generateNonce()
        #expect(chachaNonce.size == NONCE_SIZE)
        let aliceChaCha = ChaChaBox.Companion.shared.new(publicKey: bobPk, secretKey: aliceSk)
        let bobChaCha = ChaChaBox.Companion.shared.new(publicKey: alicePk, secretKey: bobSk)
        let chachaCiphertext = aliceChaCha.encrypt(nonce: chachaNonce, plaintext: message)
        #expect(chachaCiphertext.size == message.size + TAG_SIZE)
        let chachaPlaintext = bobChaCha.decrypt(nonce: chachaNonce, ciphertext: chachaCiphertext)
        for i in 0..<message.size {
            #expect(chachaPlaintext[i] == message[i])
        }

        // CryptoBox encrypt / decrypt
        let boxNonce = CryptoBox.Companion.shared.generateNonce()
        let aliceBox = CryptoBox.Companion.shared.new(publicKey: bobPk, secretKey: aliceSk)
        let bobBox = CryptoBox.Companion.shared.new(publicKey: alicePk, secretKey: bobSk)
        let boxCiphertext = aliceBox.encrypt(nonce: boxNonce, plaintext: message)
        let boxPlaintext = bobBox.decrypt(nonce: boxNonce, ciphertext: boxCiphertext)
        for i in 0..<message.size {
            #expect(boxPlaintext[i] == message[i])
        }

        // Sealed box seal / unseal
        let sealed = bobPk.seal(plaintext: message)
        #expect(sealed.size == message.size + SEALBYTES)
        let unsealed = bobSk.unseal(ciphertext: sealed)
        for i in 0..<message.size {
            #expect(unsealed[i] == message[i])
        }
    }
}
