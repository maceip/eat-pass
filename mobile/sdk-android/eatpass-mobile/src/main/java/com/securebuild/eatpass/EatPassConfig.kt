package com.securebuild.eatpass

/**
 * Endpoints and identifiers for the coupled mobile gate (attestation + eat-pass mint).
 */
data class EatPassConfig(
    val attesterUrl: String,
    val issuerUrl: String,
    val issuerName: String = "issuer.eat-pass.dev",
    val originInfo: String = "tool-gate.secure.build/v1/tools/email.send",
    /** Optional: reject issuer if KT log pubkey does not match. */
    val ktLogPubHex: String? = null,
    /** HTTP connect/read timeout in seconds. */
    val timeoutSeconds: Long = 30,
)

data class MintResult(
    /** Ready-to-send `Authorization` header value (PrivateToken). */
    val authorizationHeader: String,
    val bindingHex: String,
)

class EatPassException(message: String, cause: Throwable? = null) : Exception(message, cause)
