package com.securebuild.eatpass

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import uniffi.eat_pass_mobile.EatPassClient
import java.util.concurrent.TimeUnit

/**
 * One-call coupled mint: Key Attestation + attester + issuer + eat-pass finalize.
 */
class EatPassMobileClient(
    private val context: android.content.Context,
    private val config: EatPassConfig,
) {
    private val http = OkHttpClient.Builder()
        .connectTimeout(config.timeoutSeconds, TimeUnit.SECONDS)
        .readTimeout(config.timeoutSeconds, TimeUnit.SECONDS)
        .build()

    suspend fun mintAuthorizationHeader(): MintResult = withContext(Dispatchers.IO) {
        val issuerBase = config.issuerUrl.trimEnd('/')
        val attesterBase = config.attesterUrl.trimEnd('/')

        val keysJson = get("$issuerBase/keys")
        config.ktLogPubHex?.let { pin ->
            val kt = get("$issuerBase/kt")
            val logPub = JSONObject(kt).optString("log_pub")
            if (!logPub.equals(pin, ignoreCase = true)) {
                throw EatPassException("issuer KT log pubkey does not match pinned key")
            }
        }

        val crypto = EatPassClient.new(
            issuerPkJson = keysJson,
            issuerName = config.issuerName,
            originInfo = config.originInfo,
        )
        val begin = crypto.begin(1u)
        val bundleJson = AndroidKeyAttestation.createBundle(context, begin.bindingHex)

        val authorizeBody = JSONObject()
            .put("eat_b64", Base64.encodeToString(bundleJson.toByteArray(), Base64.NO_WRAP))
            .put("binding", begin.bindingHex)
            .put("max_batch", 1)
            .toString()

        val authResp = post("$attesterBase/authorize", authorizeBody)
        val authorizationB64 = JSONObject(authResp).getString("authorization_b64")

        val signBody = JSONObject()
            .put("req", JSONObject(begin.requestJson))
            .put("authorization_b64", authorizationB64)
            .toString()

        val signResp = post("$issuerBase/sign", signBody)
        val headers = crypto.finalize(signResp)
        if (headers.isEmpty()) {
            throw EatPassException("issuer returned no token")
        }
        MintResult(
            authorizationHeader = headers.first(),
            bindingHex = begin.bindingHex,
        )
    }

    private fun get(url: String): String {
        val req = Request.Builder().url(url).get().build()
        http.newCall(req).execute().use { resp ->
            val body = resp.body?.string() ?: ""
            if (!resp.isSuccessful) {
                throw EatPassException("GET $url failed (${resp.code}): $body")
            }
            return body
        }
    }

    private fun post(url: String, jsonBody: String): String {
        val body = jsonBody.toRequestBody("application/json".toMediaType())
        val req = Request.Builder().url(url).post(body).build()
        http.newCall(req).execute().use { resp ->
            val text = resp.body?.string() ?: ""
            if (!resp.isSuccessful) {
                throw EatPassException("POST $url failed (${resp.code}): $text")
            }
            return text
        }
    }
}
