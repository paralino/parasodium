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

import app.paralino.parasodium.internal.Libsodium
import app.paralino.parasodium.models.Key
import app.paralino.parasodium.models.KeyPair
import app.paralino.parasodium.models.SodiumException
import com.sun.jna.NativeLong
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets

/** Android [Parasodium] using JNA + packaged libsodium. */
class ParasodiumAndroid @JvmOverloads constructor(
    override val charset: Charset = StandardCharsets.UTF_8
) : Parasodium {

    private val sodium: Libsodium = Libsodium.instance

    init {
        if (sodium.sodium_init() == -1) {
            throw IllegalStateException("Sodium library could not be initialised properly.")
        }
    }

    override fun randomBytesRandom(): Long = sodium.randombytes_random()

    override fun randomBytesBuf(size: Int): ByteArray {
        val bs = ByteArray(size)
        sodium.randombytes_buf(bs, size)
        return bs
    }

    override fun nonce(size: Int): ByteArray = randomBytesBuf(size)

    override fun bytes(string: String): ByteArray = string.toByteArray(charset)

    override fun str(bytes: ByteArray): String = String(bytes, charset)

    override fun cryptoAeadXChaCha20Poly1305IetfKeygen(key: ByteArray) {
        sodium.crypto_aead_xchacha20poly1305_ietf_keygen(key)
    }

    override fun cryptoAeadXChaCha20Poly1305IetfEncrypt(
        cipher: ByteArray,
        cipherLen: LongArray?,
        message: ByteArray,
        messageLen: Long,
        additionalData: ByteArray?,
        additionalDataLen: Long,
        nSec: ByteArray?,
        nPub: ByteArray,
        key: ByteArray
    ): Boolean = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        cipher = cipher,
        cipherLen = cipherLen,
        message = message,
        messageLen = messageLen,
        additionalData = additionalData,
        additionalDataLen = additionalDataLen,
        nSec = nSec,
        nPub = nPub,
        key = key
    ).isSuccess()

    override fun cryptoAeadXChaCha20Poly1305IetfDecrypt(
        message: ByteArray,
        messageLen: LongArray?,
        nSec: ByteArray?,
        cipher: ByteArray,
        cipherLen: Long,
        additionalData: ByteArray?,
        additionalDataLen: Long,
        nPub: ByteArray,
        key: ByteArray
    ): Boolean = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        message = message,
        messageLen = messageLen,
        nSec = nSec,
        cipher = cipher,
        cipherLen = cipherLen,
        additionalData = additionalData,
        additionalDataLen = additionalDataLen,
        nPub = nPub,
        key = key
    ).isSuccess()

    override fun cryptoBoxKeypair(): KeyPair {
        val publicKey = randomBytesBuf(Box.PUBLICKEYBYTES)
        val secretKey = randomBytesBuf(Box.SECRETKEYBYTES)
        check(sodium.crypto_box_keypair(publicKey = publicKey, secretKey = secretKey).isSuccess()) {
            "Unable to create a public and private key."
        }
        return KeyPair(publicKey = Key.fromBytes(publicKey), secretKey = Key.fromBytes(secretKey))
    }

    override fun cryptoSignKeypair(): KeyPair {
        val publicKey = randomBytesBuf(Sign.PUBLICKEYBYTES)
        val secretKey = randomBytesBuf(Sign.SECRETKEYBYTES)
        check(
            sodium.crypto_sign_keypair(publicKey = publicKey, secretKey = secretKey).isSuccess()
        ) {
            "Could not generate a signing keypair."
        }
        return KeyPair(publicKey = Key.fromBytes(publicKey), secretKey = Key.fromBytes(secretKey))
    }

    override fun cryptoBoxEasy(
        cipherText: ByteArray,
        message: ByteArray,
        messageLen: Long,
        nonce: ByteArray,
        publicKey: ByteArray,
        secretKey: ByteArray
    ): Boolean {
        require(messageLen >= 0 && messageLen <= message.size) {
            "messageLen out of bounds: $messageLen"
        }
        return sodium.crypto_box_easy(
            cipherText = cipherText,
            message = message,
            messageLen = messageLen,
            nonce = nonce,
            publicKey = publicKey,
            secretKey = secretKey
        ).isSuccess()
    }

    override fun cryptoBoxOpenEasy(
        message: ByteArray,
        cipherText: ByteArray,
        cipherTextLen: Long,
        nonce: ByteArray,
        publicKey: ByteArray,
        secretKey: ByteArray
    ): Boolean {
        require(cipherTextLen >= 0 && cipherTextLen <= cipherText.size) {
            "cipherTextLen out of bounds: $cipherTextLen"
        }
        return sodium.crypto_box_open_easy(
            message = message,
            cipherText = cipherText,
            cipherTextLen = cipherTextLen,
            nonce = nonce,
            publicKey = publicKey,
            secretKey = secretKey
        ).isSuccess()
    }

    override fun cryptoSign(
        signedMessage: ByteArray,
        message: ByteArray,
        messageLen: Long,
        secretKey: ByteArray
    ): Boolean {
        require(messageLen >= 0 && messageLen <= message.size) {
            "messageLen out of bounds: $messageLen"
        }
        return sodium.crypto_sign(
            signedMessage = signedMessage,
            sigLength = null,
            message = message,
            messageLen = messageLen,
            secretKey = secretKey
        ).isSuccess()
    }

    override fun cryptoSignOpen(
        message: ByteArray,
        signedMessage: ByteArray,
        signedMessageLen: Long,
        publicKey: ByteArray
    ): Boolean {
        require(signedMessageLen >= 0 && signedMessageLen <= signedMessage.size) {
            "signedMessageLen out of bounds: $signedMessageLen"
        }
        return sodium.crypto_sign_open(
            message = message,
            messageLen = null,
            signedMessage = signedMessage,
            signedMessageLen = signedMessageLen,
            publicKey = publicKey
        ).isSuccess()
    }

    override fun cryptoKdfDeriveFromKey(
        lengthOfSubKey: Int,
        subKeyId: Long,
        context: String,
        masterKey: Key
    ): Key {
        if (lengthOfSubKey < KeyDerivation.BYTES_MIN || lengthOfSubKey > KeyDerivation.BYTES_MAX) {
            throw SodiumException("Subkey is not between the correct lengths.")
        }
        val masterBytes = masterKey.getAsBytes()
        if (masterBytes.size != KeyDerivation.MASTER_KEY_BYTES) {
            throw SodiumException("Master key is not the correct length.")
        }
        val ctx = bytes(context)
        if (ctx.size != KeyDerivation.CONTEXT_BYTES) {
            throw SodiumException("Context is not the correct length.")
        }
        val subKey = ByteArray(lengthOfSubKey)
        val res = sodium.crypto_kdf_derive_from_key(
            subkey = subKey,
            subkeyLen = lengthOfSubKey,
            subkeyId = subKeyId,
            context = ctx,
            masterKey = masterBytes
        )
        if (!res.isSuccess()) {
            throw SodiumException("Failed kdfDeriveFromKey.")
        }
        return Key.fromBytes(subKey)
    }

    override fun cryptoGenericHash(
        dataOut: ByteArray,
        outLen: Int,
        dataIn: ByteArray,
        inLen: Long,
        key: ByteArray?,
        keyLen: Int
    ): Boolean {
        require(inLen >= 0 && inLen <= dataIn.size) { "inLen out of bounds: $inLen" }
        require(outLen >= 0 && outLen <= dataOut.size) { "outLen out of bounds: $outLen" }
        return sodium.crypto_generichash(
            out = dataOut,
            outLen = outLen,
            `in` = dataIn,
            inLen = inLen,
            key = key,
            keyLen = keyLen
        ).isSuccess()
    }

    override fun cryptoGenericHash(
        dataOut: ByteArray,
        outLen: Int,
        dataIn: ByteArray,
        inLen: Long
    ): Boolean = cryptoGenericHash(
        dataOut = dataOut,
        outLen = outLen,
        dataIn = dataIn,
        inLen = inLen,
        key = null,
        keyLen = 0
    )

    override fun cryptoPwHash(
        outputHash: ByteArray,
        outputHashLen: Int,
        password: ByteArray,
        passwordLen: Int,
        salt: ByteArray,
        opsLimit: Long,
        memLimit: Long,
        alg: PwHash.Alg
    ): Boolean {
        require(outputHashLen >= 0 && outputHashLen <= outputHash.size) {
            "outputHashLen out of bounds: $outputHashLen"
        }
        require(passwordLen >= 0 && passwordLen <= password.size) {
            "passwordLen out of bounds: $passwordLen"
        }
        return sodium.crypto_pwhash(
            outputHash = outputHash,
            outputHashLen = outputHashLen.toLong(),
            password = password,
            passwordLen = passwordLen.toLong(),
            salt = salt,
            opsLimit = opsLimit,
            memLimit = NativeLong(memLimit),
            alg = alg.value
        ).isSuccess()
    }

    private fun Int.isSuccess(): Boolean = this == 0
}
