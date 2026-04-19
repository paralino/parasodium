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

/** secret key pair (e.g. box or sign). */
class KeyPair(
    val publicKey: Key,
    val secretKey: Key
) {
    override fun equals(other: Any?): Boolean {
        if (other !is KeyPair) return false
        return publicKey == other.publicKey && secretKey == other.secretKey
    }

    override fun hashCode(): Int = 31 * publicKey.hashCode() + secretKey.hashCode()
}
