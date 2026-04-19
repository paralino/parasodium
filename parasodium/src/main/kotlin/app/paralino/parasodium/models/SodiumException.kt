package app.paralino.parasodium.models

/** Checked exception for recoverable libsodium / validation failures. */
class SodiumException @JvmOverloads constructor(
    message: String? = null,
    cause: Throwable? = null
) : Exception(message, cause)