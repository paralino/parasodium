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

import app.paralino.parasodium.models.Key
import app.paralino.parasodium.models.KeyPair
import app.paralino.parasodium.models.SodiumException
import java.nio.charset.Charset

/**
 * Minimal libsodium wrapper for Paralino (https://paralino.com)
 */
interface Parasodium {

    val charset: Charset

    fun randomBytesRandom(): Long

    fun randomBytesBuf(size: Int): ByteArray

    fun nonce(size: Int): ByteArray

    fun bytes(string: String): ByteArray

    fun str(bytes: ByteArray): String

    fun cryptoAeadXChaCha20Poly1305IetfKeygen(key: ByteArray)

    fun cryptoAeadXChaCha20Poly1305IetfEncrypt(
        cipher: ByteArray,
        cipherLen: LongArray?,
        message: ByteArray,
        messageLen: Long,
        additionalData: ByteArray?,
        additionalDataLen: Long,
        nSec: ByteArray?,
        nPub: ByteArray,
        key: ByteArray
    ): Boolean

    fun cryptoAeadXChaCha20Poly1305IetfDecrypt(
        message: ByteArray,
        messageLen: LongArray?,
        nSec: ByteArray?,
        cipher: ByteArray,
        cipherLen: Long,
        additionalData: ByteArray?,
        additionalDataLen: Long,
        nPub: ByteArray,
        key: ByteArray
    ): Boolean

    fun cryptoBoxKeypair(): KeyPair

    fun cryptoSignKeypair(): KeyPair

    fun cryptoBoxEasy(
        cipherText: ByteArray,
        message: ByteArray,
        messageLen: Long,
        nonce: ByteArray,
        publicKey: ByteArray,
        secretKey: ByteArray
    ): Boolean

    fun cryptoBoxOpenEasy(
        message: ByteArray,
        cipherText: ByteArray,
        cipherTextLen: Long,
        nonce: ByteArray,
        publicKey: ByteArray,
        secretKey: ByteArray
    ): Boolean

    fun cryptoSign(
        signedMessage: ByteArray,
        message: ByteArray,
        messageLen: Long,
        secretKey: ByteArray
    ): Boolean

    fun cryptoSignOpen(
        message: ByteArray,
        signedMessage: ByteArray,
        signedMessageLen: Long,
        publicKey: ByteArray
    ): Boolean

    @Throws(SodiumException::class)
    fun cryptoKdfDeriveFromKey(
        lengthOfSubKey: Int,
        subKeyId: Long,
        context: String,
        masterKey: Key
    ): Key

    fun cryptoGenericHash(
        dataOut: ByteArray,
        outLen: Int,
        dataIn: ByteArray,
        inLen: Long,
        key: ByteArray?,
        keyLen: Int
    ): Boolean

    fun cryptoGenericHash(
        dataOut: ByteArray,
        outLen: Int,
        dataIn: ByteArray,
        inLen: Long
    ): Boolean

    fun cryptoPwHash(
        outputHash: ByteArray,
        outputHashLen: Int,
        password: ByteArray,
        passwordLen: Int,
        salt: ByteArray,
        opsLimit: Long,
        memLimit: Long,
        alg: PwHash.Alg
    ): Boolean
}
