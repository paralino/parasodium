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

/** Encodes binary ciphertext or key material as a string (e.g. hex, Base64). */
interface MessageEncoder {
    fun encode(cipher: ByteArray): String
    fun decode(cipherText: String): ByteArray
}
