package com.securebuild.eatpass

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Builds the Android Key Attestation bundle (no Play Integrity).
 * Device: [KeyGenParameterSpec.setAttestationChallenge] = eat-pass binding.
 */
internal object AndroidKeyAttestation {
    private const val ALIAS_PREFIX = "eatpass-attest-"
    private val json = Json { encodeDefaults = true }

    @Serializable
    private data class Bundle(
        val version: Int = 1,
        val platform: String = "android-key-attestation",
        val attestation_chain: List<String>,
        val binding: String,
        val package_name: String,
        val signing_cert_digest: String,
    )

    fun createBundle(context: Context, bindingHex: String): String {
        val binding = hexToBytes(bindingHex)
        require(binding.size == 32) { "binding must be 32 bytes" }

        val alias = ALIAS_PREFIX + bindingHex.take(16)
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.deleteEntry(alias)

        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN,
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(binding)
            .build()

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            .apply { initialize(spec) }
            .generateKeyPair()

        @Suppress("DEPRECATION")
        val chain = ks.getCertificateChain(alias)
            ?: throw EatPassException("Key attestation returned no certificate chain")

        val packageName = context.packageName
        val certDigest = signingCertSha256(context)

        val bundle = Bundle(
            attestation_chain = chain.map { cert ->
                val der = (cert as X509Certificate).encoded
                der.toHex()
            },
            binding = bindingHex,
            package_name = packageName,
            signing_cert_digest = certDigest.toHex(),
        )
        return json.encodeToString(bundle)
    }

    private fun signingCertSha256(context: Context): ByteArray {
        val pm = context.packageManager
        @Suppress("DEPRECATION")
        val flags = if (Build.VERSION.SDK_INT >= 28) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            PackageManager.GET_SIGNATURES
        }
        val info = pm.getPackageInfo(context.packageName, flags)
        val certBytes = if (Build.VERSION.SDK_INT >= 28) {
            val signingInfo = info.signingInfo
                ?: throw EatPassException("No signing info")
            val cert = signingInfo.signingCertificateHistory?.firstOrNull()
                ?: throw EatPassException("No signing certificate")
            cert.toByteArray()
        } else {
            @Suppress("DEPRECATION")
            info.signatures.first().toByteArray()
        }
        return MessageDigest.getInstance("SHA-256").digest(certBytes)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        require(clean.length == 64) { "expected 64 hex chars" }
        return ByteArray(32) { i -> clean.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }
}
