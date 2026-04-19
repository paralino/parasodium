/*
 * Copyright (c) 2026 Paralino
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL is not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions derived from Lazysodium (Terl Tech Ltd).
 *
 * JNA bindings to libsodium — subset used by Parasodium.
 */

package app.paralino.parasodium.internal

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Pointer

internal interface Libsodium : Library {

    fun sodium_init(): Int

    fun randombytes_random(): Long

    fun randombytes_buf(buffer: ByteArray, size: Int)

    fun crypto_kdf_derive_from_key(
        subkey: ByteArray,
        subkeyLen: Int,
        subkeyId: Long,
        context: ByteArray,
        masterKey: ByteArray
    ): Int

    fun crypto_generichash(
        out: ByteArray,
        outLen: Int,
        `in`: ByteArray,
        inLen: Long,
        key: ByteArray?,
        keyLen: Int
    ): Int

    fun crypto_pwhash(
        outputHash: ByteArray,
        outputHashLen: Long,
        password: ByteArray,
        passwordLen: Long,
        salt: ByteArray,
        opsLimit: Long,
        memLimit: NativeLong,
        alg: Int
    ): Int

    fun crypto_box_keypair(publicKey: ByteArray, secretKey: ByteArray): Int

    fun crypto_box_easy(
        cipherText: ByteArray,
        message: ByteArray,
        messageLen: Long,
        nonce: ByteArray,
        publicKey: ByteArray,
        secretKey: ByteArray
    ): Int

    fun crypto_box_open_easy(
        message: ByteArray,
        cipherText: ByteArray,
        cipherTextLen: Long,
        nonce: ByteArray,
        publicKey: ByteArray,
        secretKey: ByteArray
    ): Int

    fun crypto_sign_keypair(publicKey: ByteArray, secretKey: ByteArray): Int

    fun crypto_sign(
        signedMessage: ByteArray,
        sigLength: Pointer?,
        message: ByteArray,
        messageLen: Long,
        secretKey: ByteArray
    ): Int

    fun crypto_sign_open(
        message: ByteArray,
        messageLen: Pointer?,
        signedMessage: ByteArray,
        signedMessageLen: Long,
        publicKey: ByteArray
    ): Int

    fun crypto_aead_xchacha20poly1305_ietf_keygen(key: ByteArray)

    fun crypto_aead_xchacha20poly1305_ietf_encrypt(
        cipher: ByteArray,
        cipherLen: LongArray?,
        message: ByteArray,
        messageLen: Long,
        additionalData: ByteArray?,
        additionalDataLen: Long,
        nSec: ByteArray?,
        nPub: ByteArray,
        key: ByteArray
    ): Int

    fun crypto_aead_xchacha20poly1305_ietf_decrypt(
        message: ByteArray,
        messageLen: LongArray?,
        nSec: ByteArray?,
        cipher: ByteArray,
        cipherLen: Long,
        additionalData: ByteArray?,
        additionalDataLen: Long,
        nPub: ByteArray,
        key: ByteArray
    ): Int

    companion object {
        /** Single JNA instance (shared across [app.paralino.parasodium.ParasodiumAndroid] instances). */
        val instance: Libsodium by lazy {
            System.loadLibrary("sodium")
            Native.load("sodium", Libsodium::class.java)
        }
    }
}
