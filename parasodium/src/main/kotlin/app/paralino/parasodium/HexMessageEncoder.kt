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

import app.paralino.parasodium.models.toHexString

/** Hexadecimal [MessageEncoder] (uppercase A–F). */
class HexMessageEncoder : MessageEncoder {
    override fun encode(cipher: ByteArray): String = cipher.toHexString()
    override fun decode(cipherText: String): ByteArray = cipherText.hexToByteArray()
}

internal fun String.hexToByteArray(): ByteArray {
    val len = length
    require(len % 2 == 0) { "Hex string length must be even." }
    val data = ByteArray(len / 2)
    var i = 0
    while (i < len) {
        data[i / 2] = (
            (Character.digit(this[i], 16) shl 4) +
                Character.digit(this[i + 1], 16)
            ).toByte()
        i += 2
    }
    return data
}
