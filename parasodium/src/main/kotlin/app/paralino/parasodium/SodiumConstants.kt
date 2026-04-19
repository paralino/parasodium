/*
 * Copyright (c) 2026 Paralino
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL is not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions derived from Lazysodium (Terl Tech Ltd).
 *
 * Libsodium size constants (subset).
 */

package app.paralino.parasodium

import app.paralino.parasodium.models.SodiumException

/** AEAD (XChaCha20-Poly1305 IETF). */
object AEAD {
    const val XCHACHA20POLY1305_IETF_KEYBYTES: Int = 32
    const val XCHACHA20POLY1305_IETF_ABYTES: Int = 16
    const val XCHACHA20POLY1305_IETF_NPUBBYTES: Int = 24
}

/** Curve25519 + XSalsa20 + Poly1305 (crypto_box_*). */
object Box {
    const val CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES: Int = 32
    const val CURVE25519XSALSA20POLY1305_SECRETKEYBYTES: Int = 32
    const val CURVE25519XSALSA20POLY1305_MACBYTES: Int = 16
    const val CURVE25519XSALSA20POLY1305_NONCEBYTES: Int = 24

    const val PUBLICKEYBYTES: Int = CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES
    const val SECRETKEYBYTES: Int = CURVE25519XSALSA20POLY1305_SECRETKEYBYTES
    const val MACBYTES: Int = CURVE25519XSALSA20POLY1305_MACBYTES
    const val NONCEBYTES: Int = CURVE25519XSALSA20POLY1305_NONCEBYTES
}

/** Ed25519 (crypto_sign_*). */
object Sign {
    const val BYTES: Int = 64
    const val PUBLICKEYBYTES: Int = 32
    const val SECRETKEYBYTES: Int = 64
}

/** crypto_kdf (Blake2b-based). */
object KeyDerivation {
    const val MASTER_KEY_BYTES: Int = 32
    const val CONTEXT_BYTES: Int = 8
    const val BLAKE2B_BYTES_MIN: Int = 16
    const val BLAKE2B_BYTES_MAX: Int = 64
    const val BYTES_MIN: Int = BLAKE2B_BYTES_MIN
    const val BYTES_MAX: Int = BLAKE2B_BYTES_MAX
}

/** crypto_generichash (Blake2b). */
object GenericHash {
    const val BYTES: Int = 32
}

private const val UNSIGNED_INT: Long = 0xFFFFFFFFL

/** Argon2 password hashing parameters. */
object PwHash {
    const val ARGON2ID_SALTBYTES: Int = 16
    const val ARGON2ID_BYTES_MIN: Int = 16
    const val SALTBYTES: Int = ARGON2ID_SALTBYTES

    const val ARGON2ID_OPSLIMIT_MIN: Long = 1L
    const val ARGON2ID_OPSLIMIT_MAX: Long = UNSIGNED_INT

    const val ARGON2ID_MEMLIMIT_MIN: Int = 8192
    const val ARGON2ID_MEMLIMIT_MAX: Int = UNSIGNED_INT.toInt()

    const val PASSWD_MIN: Long = 0L
    const val PASSWD_MAX: Long = UNSIGNED_INT

    val MEMLIMIT_MIN: com.sun.jna.NativeLong =
        com.sun.jna.NativeLong(ARGON2ID_MEMLIMIT_MIN.toLong())

    val MEMLIMIT_MAX: com.sun.jna.NativeLong =
        com.sun.jna.NativeLong(UNSIGNED_INT)

    enum class Alg(val value: Int) {
        PWHASH_ALG_ARGON2I13(1),
        PWHASH_ALG_ARGON2ID13(2),
    }

    @Throws(SodiumException::class)
    fun checkAll(
        passwordBytesLen: Long,
        saltBytesLen: Long,
        opsLimit: Long,
        memLimit: Long
    ): Boolean {
        if (saltBytesLen != SALTBYTES.toLong()) {
            throw SodiumException("The salt provided is not the correct length.")
        }
        if (passwordBytesLen !in PASSWD_MIN..PASSWD_MAX) {
            throw SodiumException("The password provided is not the correct length.")
        }
        if (opsLimit !in ARGON2ID_OPSLIMIT_MIN..ARGON2ID_OPSLIMIT_MAX) {
            throw SodiumException("The opsLimit provided is not the correct value.")
        }
        val mem = memLimit
        if (mem !in ARGON2ID_MEMLIMIT_MIN..UNSIGNED_INT) {
            throw SodiumException("The memLimit provided is not the correct value.")
        }
        return true
    }
}
