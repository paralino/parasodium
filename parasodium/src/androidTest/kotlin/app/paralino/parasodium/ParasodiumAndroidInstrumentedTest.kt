/*
 * Copyright (c) 2026 Paralino
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL is not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions derived from Lazysodium (Terl Tech Ltd).
 */

package app.paralino.parasodium

import androidx.test.ext.junit.runners.AndroidJUnit4
import app.paralino.parasodium.models.Key
import app.paralino.parasodium.models.SodiumException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ParasodiumAndroidInstrumentedTest {

    private val p: Parasodium = ParasodiumAndroid()

    private val pwhashOps = 2L
    private val pwhashMem = 8_388_608L // 8 MiB — faster than 64M for CI

    // --- AEAD ---

    @Test
    fun aead_xchacha_roundTrip() {
        val key = ByteArray(AEAD.XCHACHA20POLY1305_IETF_KEYBYTES)
        p.cryptoAeadXChaCha20Poly1305IetfKeygen(key)
        val msg = p.bytes("hello parasodium")
        val nonce = p.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES)
        val cipher = ByteArray(AEAD.XCHACHA20POLY1305_IETF_ABYTES + msg.size)
        assertTrue(
            p.cryptoAeadXChaCha20Poly1305IetfEncrypt(
                cipher = cipher,
                cipherLen = null,
                message = msg,
                messageLen = msg.size.toLong(),
                additionalData = null,
                additionalDataLen = 0L,
                nSec = null,
                nPub = nonce,
                key = key
            )
        )
        val out = ByteArray(msg.size)
        assertTrue(
            p.cryptoAeadXChaCha20Poly1305IetfDecrypt(
                message = out,
                messageLen = null,
                nSec = null,
                cipher = cipher,
                cipherLen = cipher.size.toLong(),
                additionalData = null,
                additionalDataLen = 0L,
                nPub = nonce,
                key = key
            )
        )
        assertEquals("hello parasodium", p.str(out))
    }

    @Test
    fun aead_xchacha_withAdditionalData_roundTrip() {
        val key = ByteArray(AEAD.XCHACHA20POLY1305_IETF_KEYBYTES)
        p.cryptoAeadXChaCha20Poly1305IetfKeygen(key)
        val msg = p.bytes("with ad")
        val ad = p.bytes("meta")
        val nonce = p.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES)
        val cipher = ByteArray(AEAD.XCHACHA20POLY1305_IETF_ABYTES + msg.size)
        assertTrue(
            p.cryptoAeadXChaCha20Poly1305IetfEncrypt(
                cipher = cipher,
                cipherLen = null,
                message = msg,
                messageLen = msg.size.toLong(),
                additionalData = ad,
                additionalDataLen = ad.size.toLong(),
                nSec = null,
                nPub = nonce,
                key = key
            )
        )
        val out = ByteArray(msg.size)
        assertTrue(
            p.cryptoAeadXChaCha20Poly1305IetfDecrypt(
                message = out,
                messageLen = null,
                nSec = null,
                cipher = cipher,
                cipherLen = cipher.size.toLong(),
                additionalData = ad,
                additionalDataLen = ad.size.toLong(),
                nPub = nonce,
                key = key
            )
        )
        assertArrayEquals(msg, out)
    }

    @Test
    fun aead_xchacha_decryptFails_wrongKey() {
        val key = ByteArray(AEAD.XCHACHA20POLY1305_IETF_KEYBYTES)
        val wrongKey = ByteArray(AEAD.XCHACHA20POLY1305_IETF_KEYBYTES)
        p.cryptoAeadXChaCha20Poly1305IetfKeygen(key)
        p.cryptoAeadXChaCha20Poly1305IetfKeygen(wrongKey)
        val msg = p.bytes("secret")
        val nonce = p.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES)
        val cipher = ByteArray(AEAD.XCHACHA20POLY1305_IETF_ABYTES + msg.size)
        assertTrue(
            p.cryptoAeadXChaCha20Poly1305IetfEncrypt(
                cipher = cipher,
                cipherLen = null,
                message = msg,
                messageLen = msg.size.toLong(),
                additionalData = null,
                additionalDataLen = 0L,
                nSec = null,
                nPub = nonce,
                key = key
            )
        )
        val out = ByteArray(msg.size)
        assertFalse(
            p.cryptoAeadXChaCha20Poly1305IetfDecrypt(
                message = out,
                messageLen = null,
                nSec = null,
                cipher = cipher,
                cipherLen = cipher.size.toLong(),
                additionalData = null,
                additionalDataLen = 0L,
                nPub = nonce,
                key = wrongKey
            )
        )
    }

    @Test
    fun aead_xchacha_decryptFails_wrongNonce() {
        val key = ByteArray(AEAD.XCHACHA20POLY1305_IETF_KEYBYTES)
        p.cryptoAeadXChaCha20Poly1305IetfKeygen(key)
        val msg = p.bytes("n")
        val nonceEnc = p.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES)
        val nonceWrong = p.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES)
        val cipher = ByteArray(AEAD.XCHACHA20POLY1305_IETF_ABYTES + msg.size)
        assertTrue(
            p.cryptoAeadXChaCha20Poly1305IetfEncrypt(
                cipher = cipher,
                cipherLen = null,
                message = msg,
                messageLen = msg.size.toLong(),
                additionalData = null,
                additionalDataLen = 0L,
                nSec = null,
                nPub = nonceEnc,
                key = key
            )
        )
        val out = ByteArray(msg.size)
        assertFalse(
            p.cryptoAeadXChaCha20Poly1305IetfDecrypt(
                message = out,
                messageLen = null,
                nSec = null,
                cipher = cipher,
                cipherLen = cipher.size.toLong(),
                additionalData = null,
                additionalDataLen = 0L,
                nPub = nonceWrong,
                key = key
            )
        )
    }

    @Test
    fun aead_xchacha_decryptFails_tamperedCiphertext() {
        val key = ByteArray(AEAD.XCHACHA20POLY1305_IETF_KEYBYTES)
        p.cryptoAeadXChaCha20Poly1305IetfKeygen(key)
        val msg = p.bytes("tamper")
        val nonce = p.nonce(AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES)
        val cipher = ByteArray(AEAD.XCHACHA20POLY1305_IETF_ABYTES + msg.size)
        assertTrue(
            p.cryptoAeadXChaCha20Poly1305IetfEncrypt(
                cipher = cipher,
                cipherLen = null,
                message = msg,
                messageLen = msg.size.toLong(),
                additionalData = null,
                additionalDataLen = 0L,
                nSec = null,
                nPub = nonce,
                key = key
            )
        )
        cipher[cipher.lastIndex] = (cipher[cipher.lastIndex].toInt() xor 1).toByte()
        val out = ByteArray(msg.size)
        assertFalse(
            p.cryptoAeadXChaCha20Poly1305IetfDecrypt(
                message = out,
                messageLen = null,
                nSec = null,
                cipher = cipher,
                cipherLen = cipher.size.toLong(),
                additionalData = null,
                additionalDataLen = 0L,
                nPub = nonce,
                key = key
            )
        )
    }

    // --- Box ---

    @Test
    fun box_roundTrip() {
        val alice = p.cryptoBoxKeypair()
        val bob = p.cryptoBoxKeypair()
        val nonce = p.nonce(Box.NONCEBYTES)
        val plain = p.bytes("box test")
        val cipher = ByteArray(Box.MACBYTES + plain.size)
        assertTrue(
            p.cryptoBoxEasy(
                cipherText = cipher,
                message = plain,
                messageLen = plain.size.toLong(),
                nonce = nonce,
                publicKey = bob.publicKey.getAsBytes(),
                secretKey = alice.secretKey.getAsBytes()
            )
        )
        val out = ByteArray(plain.size)
        assertTrue(
            p.cryptoBoxOpenEasy(
                message = out,
                cipherText = cipher,
                cipherTextLen = cipher.size.toLong(),
                nonce = nonce,
                publicKey = alice.publicKey.getAsBytes(),
                secretKey = bob.secretKey.getAsBytes()
            )
        )
        assertEquals("box test", p.str(out))
    }

    @Test
    fun box_openFails_wrongRecipientSecret() {
        val alice = p.cryptoBoxKeypair()
        val bob = p.cryptoBoxKeypair()
        val eve = p.cryptoBoxKeypair()
        val nonce = p.nonce(Box.NONCEBYTES)
        val plain = p.bytes("x")
        val cipher = ByteArray(Box.MACBYTES + plain.size)
        assertTrue(
            p.cryptoBoxEasy(
                cipherText = cipher,
                message = plain,
                messageLen = plain.size.toLong(),
                nonce = nonce,
                publicKey = bob.publicKey.getAsBytes(),
                secretKey = alice.secretKey.getAsBytes()
            )
        )
        val out = ByteArray(plain.size)
        assertFalse(
            p.cryptoBoxOpenEasy(
                message = out,
                cipherText = cipher,
                cipherTextLen = cipher.size.toLong(),
                nonce = nonce,
                publicKey = alice.publicKey.getAsBytes(),
                secretKey = eve.secretKey.getAsBytes()
            )
        )
    }

    @Test
    fun box_openFails_wrongNonce() {
        val alice = p.cryptoBoxKeypair()
        val bob = p.cryptoBoxKeypair()
        val n1 = p.nonce(Box.NONCEBYTES)
        val n2 = p.nonce(Box.NONCEBYTES)
        val plain = p.bytes("y")
        val cipher = ByteArray(Box.MACBYTES + plain.size)
        assertTrue(
            p.cryptoBoxEasy(
                cipherText = cipher,
                message = plain,
                messageLen = plain.size.toLong(),
                nonce = n1,
                publicKey = bob.publicKey.getAsBytes(),
                secretKey = alice.secretKey.getAsBytes()
            )
        )
        val out = ByteArray(plain.size)
        assertFalse(
            p.cryptoBoxOpenEasy(
                message = out,
                cipherText = cipher,
                cipherTextLen = cipher.size.toLong(),
                nonce = n2,
                publicKey = alice.publicKey.getAsBytes(),
                secretKey = bob.secretKey.getAsBytes()
            )
        )
    }

    // --- Sign ---

    @Test
    fun sign_roundTrip() {
        val kp = p.cryptoSignKeypair()
        val msg = p.bytes("signed")
        val sm = ByteArray(Sign.BYTES + msg.size)
        assertTrue(
            p.cryptoSign(
                signedMessage = sm,
                message = msg,
                messageLen = msg.size.toLong(),
                secretKey = kp.secretKey.getAsBytes()
            )
        )
        val out = ByteArray(msg.size)
        assertTrue(
            p.cryptoSignOpen(
                message = out,
                signedMessage = sm,
                signedMessageLen = sm.size.toLong(),
                publicKey = kp.publicKey.getAsBytes()
            )
        )
        assertArrayEquals(msg, out)
    }

    @Test
    fun sign_roundTrip_emptyMessage() {
        val kp = p.cryptoSignKeypair()
        val msg = ByteArray(0)
        val sm = ByteArray(Sign.BYTES)
        assertTrue(
            p.cryptoSign(
                signedMessage = sm,
                message = msg,
                messageLen = 0L,
                secretKey = kp.secretKey.getAsBytes()
            )
        )
        val out = ByteArray(0)
        assertTrue(
            p.cryptoSignOpen(
                message = out,
                signedMessage = sm,
                signedMessageLen = sm.size.toLong(),
                publicKey = kp.publicKey.getAsBytes()
            )
        )
        assertEquals(0, out.size)
    }

    @Test
    fun sign_openFails_wrongPublicKey() {
        val kp = p.cryptoSignKeypair()
        val other = p.cryptoSignKeypair()
        val msg = p.bytes("verify key")
        val sm = ByteArray(Sign.BYTES + msg.size)
        assertTrue(
            p.cryptoSign(
                signedMessage = sm,
                message = msg,
                messageLen = msg.size.toLong(),
                secretKey = kp.secretKey.getAsBytes()
            )
        )
        val out = ByteArray(msg.size)
        assertFalse(
            p.cryptoSignOpen(
                message = out,
                signedMessage = sm,
                signedMessageLen = sm.size.toLong(),
                publicKey = other.publicKey.getAsBytes()
            )
        )
    }

    @Test
    fun sign_open_rejects_tamper() {
        val kp = p.cryptoSignKeypair()
        val msg = p.bytes("message to sign")
        val sm = ByteArray(Sign.BYTES + msg.size)
        assertTrue(
            p.cryptoSign(
                signedMessage = sm,
                message = msg,
                messageLen = msg.size.toLong(),
                secretKey = kp.secretKey.getAsBytes()
            )
        )
        sm[0] = (sm[0].toInt() xor 0xFF).toByte()
        val out = ByteArray(msg.size)
        assertFalse(
            p.cryptoSignOpen(
                message = out,
                signedMessage = sm,
                signedMessageLen = sm.size.toLong(),
                publicKey = kp.publicKey.getAsBytes()
            )
        )
    }

    // --- KDF ---

    @Test
    fun kdf_deterministic() {
        val master = ByteArray(KeyDerivation.MASTER_KEY_BYTES)
        p.cryptoAeadXChaCha20Poly1305IetfKeygen(master)
        val mk = Key.fromBytes(master)
        val a = p.cryptoKdfDeriveFromKey(
            lengthOfSubKey = 32,
            subKeyId = 1L,
            context = "_ctx1234",
            masterKey = mk
        )
        val b = p.cryptoKdfDeriveFromKey(
            lengthOfSubKey = 32,
            subKeyId = 1L,
            context = "_ctx1234",
            masterKey = mk
        )
        assertArrayEquals(a.getAsBytes(), b.getAsBytes())
    }

    @Test
    fun kdf_differentSubKeyId_producesDifferentKey() {
        val master = ByteArray(KeyDerivation.MASTER_KEY_BYTES)
        p.cryptoAeadXChaCha20Poly1305IetfKeygen(master)
        val mk = Key.fromBytes(master)
        val a = p.cryptoKdfDeriveFromKey(
            lengthOfSubKey = 32,
            subKeyId = 1L,
            context = "_ctx1234",
            masterKey = mk
        )
        val b = p.cryptoKdfDeriveFromKey(
            lengthOfSubKey = 32,
            subKeyId = 2L,
            context = "_ctx1234",
            masterKey = mk
        )
        assertFalse(a.getAsBytes().contentEquals(b.getAsBytes()))
    }

    @Test
    fun kdf_differentContext_producesDifferentKey() {
        val master = ByteArray(KeyDerivation.MASTER_KEY_BYTES)
        p.cryptoAeadXChaCha20Poly1305IetfKeygen(master)
        val mk = Key.fromBytes(master)
        val a = p.cryptoKdfDeriveFromKey(
            lengthOfSubKey = 32,
            subKeyId = 1L,
            context = "_one____",
            masterKey = mk
        )
        val b = p.cryptoKdfDeriveFromKey(
            lengthOfSubKey = 32,
            subKeyId = 1L,
            context = "_two____",
            masterKey = mk
        )
        assertFalse(a.getAsBytes().contentEquals(b.getAsBytes()))
    }

    @Test
    fun kdf_invalidContextLength_throws() {
        val master = ByteArray(KeyDerivation.MASTER_KEY_BYTES)
        p.cryptoAeadXChaCha20Poly1305IetfKeygen(master)
        val mk = Key.fromBytes(master)
        assertThrows(SodiumException::class.java) {
            p.cryptoKdfDeriveFromKey(
                lengthOfSubKey = 32,
                subKeyId = 1L,
                context = "short",
                masterKey = mk
            )
        }
    }

    // --- Generic hash ---

    @Test
    fun generichash_deterministic_withoutKey() {
        val data = p.bytes("same input")
        val h1 = ByteArray(GenericHash.BYTES)
        val h2 = ByteArray(GenericHash.BYTES)
        assertTrue(
            p.cryptoGenericHash(dataOut = h1, outLen = h1.size, dataIn = data, inLen = data.size.toLong())
        )
        assertTrue(
            p.cryptoGenericHash(dataOut = h2, outLen = h2.size, dataIn = data, inLen = data.size.toLong())
        )
        assertArrayEquals(h1, h2)
    }

    @Test
    fun generichash_keyed_differsFromUnkeyed() {
        val data = p.bytes("payload")
        val key = ByteArray(32)
        p.cryptoAeadXChaCha20Poly1305IetfKeygen(key)
        val noKey = ByteArray(GenericHash.BYTES)
        val withKey = ByteArray(GenericHash.BYTES)
        assertTrue(
            p.cryptoGenericHash(
                dataOut = noKey,
                outLen = noKey.size,
                dataIn = data,
                inLen = data.size.toLong()
            )
        )
        assertTrue(
            p.cryptoGenericHash(
                dataOut = withKey,
                outLen = withKey.size,
                dataIn = data,
                inLen = data.size.toLong(),
                key = key,
                keyLen = key.size
            )
        )
        assertFalse(noKey.contentEquals(withKey))
    }

    // --- PwHash ---

    @Test
    fun pwhash_deterministic_sameInputs() {
        val salt = p.randomBytesBuf(PwHash.ARGON2ID_SALTBYTES)
        val pwd = p.bytes("same-password")
        PwHash.checkAll(
            passwordBytesLen = pwd.size.toLong(),
            saltBytesLen = salt.size.toLong(),
            opsLimit = pwhashOps,
            memLimit = pwhashMem
        )
        val out1 = ByteArray(32)
        val out2 = ByteArray(32)
        assertTrue(
            p.cryptoPwHash(
                outputHash = out1,
                outputHashLen = out1.size,
                password = pwd,
                passwordLen = pwd.size,
                salt = salt,
                opsLimit = pwhashOps,
                memLimit = pwhashMem,
                alg = PwHash.Alg.PWHASH_ALG_ARGON2ID13
            )
        )
        assertTrue(
            p.cryptoPwHash(
                outputHash = out2,
                outputHashLen = out2.size,
                password = pwd,
                passwordLen = pwd.size,
                salt = salt,
                opsLimit = pwhashOps,
                memLimit = pwhashMem,
                alg = PwHash.Alg.PWHASH_ALG_ARGON2ID13
            )
        )
        assertArrayEquals(out1, out2)
    }

    @Test
    fun pwhash_differentSalt_differs() {
        val salt1 = p.randomBytesBuf(PwHash.ARGON2ID_SALTBYTES)
        val salt2 = p.randomBytesBuf(PwHash.ARGON2ID_SALTBYTES)
        val pwd = p.bytes("pw")
        PwHash.checkAll(
            passwordBytesLen = pwd.size.toLong(),
            saltBytesLen = salt1.size.toLong(),
            opsLimit = pwhashOps,
            memLimit = pwhashMem
        )
        val out1 = ByteArray(32)
        val out2 = ByteArray(32)
        assertTrue(
            p.cryptoPwHash(
                outputHash = out1,
                outputHashLen = out1.size,
                password = pwd,
                passwordLen = pwd.size,
                salt = salt1,
                opsLimit = pwhashOps,
                memLimit = pwhashMem,
                alg = PwHash.Alg.PWHASH_ALG_ARGON2ID13
            )
        )
        assertTrue(
            p.cryptoPwHash(
                outputHash = out2,
                outputHashLen = out2.size,
                password = pwd,
                passwordLen = pwd.size,
                salt = salt2,
                opsLimit = pwhashOps,
                memLimit = pwhashMem,
                alg = PwHash.Alg.PWHASH_ALG_ARGON2ID13
            )
        )
        assertFalse(out1.contentEquals(out2))
    }

    @Test
    fun pwhash_checker_throwsOnBadSaltLength() {
        assertThrows(SodiumException::class.java) {
            PwHash.checkAll(
                passwordBytesLen = 4L,
                saltBytesLen = 5L,
                opsLimit = pwhashOps,
                memLimit = pwhashMem
            )
        }
    }

    @Test
    fun generichash_and_pwhash_smoke() {
        val h = ByteArray(GenericHash.BYTES)
        val data = p.bytes("hash me")
        assertTrue(
            p.cryptoGenericHash(dataOut = h, outLen = h.size, dataIn = data, inLen = data.size.toLong())
        )
        val salt = p.randomBytesBuf(PwHash.ARGON2ID_SALTBYTES)
        val passwordBytes = p.bytes("secret")
        PwHash.checkAll(
            passwordBytesLen = passwordBytes.size.toLong(),
            saltBytesLen = salt.size.toLong(),
            opsLimit = pwhashOps,
            memLimit = pwhashMem
        )
        val outputKey = ByteArray(32)
        assertTrue(
            p.cryptoPwHash(
                outputHash = outputKey,
                outputHashLen = outputKey.size,
                password = passwordBytes,
                passwordLen = passwordBytes.size,
                salt = salt,
                opsLimit = pwhashOps,
                memLimit = pwhashMem,
                alg = PwHash.Alg.PWHASH_ALG_ARGON2ID13
            )
        )
    }

    // --- Random & string helpers ---

    @Test
    fun randomBytesBuf_lengthAndNonTrivial() {
        val a = p.randomBytesBuf(32)
        val b = p.randomBytesBuf(32)
        assertEquals(32, a.size)
        assertEquals(32, b.size)
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun randomBytesRandom_returnsValue() {
        val x = p.randomBytesRandom()
        val y = p.randomBytesRandom()
        assertTrue(x >= 0)
        assertTrue(y >= 0)
    }

    @Test
    fun bytes_str_roundTrip_utf8() {
        val s = "hello paralino"
        assertEquals(s, p.str(p.bytes(s)))
    }

    @Test
    fun hexMessageEncoder_roundTrip() {
        val enc = HexMessageEncoder()
        val raw = p.randomBytesBuf(17)
        assertArrayEquals(raw, enc.decode(enc.encode(raw)))
    }
}
