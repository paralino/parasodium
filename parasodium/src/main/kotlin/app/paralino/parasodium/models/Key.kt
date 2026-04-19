/*
 * Copyright (c) 2026 Paralino
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL is not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions derived from Lazysodium (Terl Tech Ltd).
 */

package app.paralino.parasodium.models

import java.nio.charset.StandardCharsets

/** Raw key material (not encoded). */
class Key private constructor(private val key: ByteArray) {

    fun getAsBytes(): ByteArray = key

    fun getAsHexString(): String = key.toHexString()

    fun getAsPlainString(): String = String(key, StandardCharsets.UTF_8)

    override fun equals(other: Any?): Boolean {
        if (other !is Key) return false
        return key.contentEquals(other.key)
    }

    override fun hashCode(): Int = key.contentHashCode()

    companion object {
        @JvmStatic
        fun fromBytes(bytes: ByteArray): Key = Key(bytes.clone())
    }
}

private val HEX = "0123456789ABCDEF".toCharArray()

/** Uppercase hex encoding (no prefix). */
fun ByteArray.toHexString(): String {
    val out = CharArray(size * 2)
    for (i in indices) {
        val v = this[i].toInt() and 0xFF
        out[i * 2] = HEX[v ushr 4]
        out[i * 2 + 1] = HEX[v and 0x0F]
    }
    return String(out)
}
