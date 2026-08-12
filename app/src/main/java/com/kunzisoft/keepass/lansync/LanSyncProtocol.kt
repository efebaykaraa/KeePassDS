/*
 * Copyright 2026 Jeremy Jamet / Kunzisoft and KeePassXC Team
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package com.kunzisoft.keepass.lansync

import android.util.Base64
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.json.JSONArray
import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal object LanSyncProtocol {
    const val DISCOVERY_PORT = 41439
    const val PROTOCOL_VERSION = 1
    const val DISCOVERY_MAGIC = "keepassxc-lan-sync-discovery"
    const val SETTINGS_KEY = "KPXC_LAN_SYNC_SETTINGS"
    const val MAX_FRAME_SIZE = 64 * 1024 * 1024

    private val secureRandom = SecureRandom()

    data class Device(
        val id: String,
        val name: String,
        val address: String,
        val port: Int,
    )

    data class Link(
        val peerId: String,
        val peerName: String,
        val databaseId: String,
        val address: String,
        val port: Int,
        val secret: ByteArray,
    ) {
        fun isValid() = peerId.isNotEmpty() && databaseId.isNotEmpty() &&
                address.isNotEmpty() && port in 1..65535 && secret.size == 32

        fun toJson() = JSONObject()
            .put("peerId", peerId)
            .put("peerName", peerName)
            .put("databaseId", databaseId)
            .put("address", address)
            .put("port", port)
            .put("secret", secret.base64())

        companion object {
            fun fromJson(value: JSONObject) = Link(
                value.optString("peerId"),
                value.optString("peerName"),
                value.optString("databaseId"),
                value.optString("address"),
                value.optInt("port"),
                value.optString("secret").decodeBase64(),
            )
        }
    }

    class KeyExchange {
        private val privateKey = X25519PrivateKeyParameters(secureRandom)
        val publicKey: ByteArray = privateKey.generatePublicKey().encoded

        fun derive(peerPublicKey: ByteArray, code: String): ByteArray {
            require(peerPublicKey.size == X25519PublicKeyParameters.KEY_SIZE)
            val agreement = X25519Agreement()
            agreement.init(privateKey)
            val shared = ByteArray(agreement.agreementSize)
            agreement.calculateAgreement(X25519PublicKeyParameters(peerPublicKey, 0), shared, 0)
            val generator = HKDFBytesGenerator(SHA256Digest())
            generator.init(
                HKDFParameters(
                    shared,
                    "keepassxc-lan-sync-v1:$code".toByteArray(Charsets.UTF_8),
                    ByteArray(0),
                )
            )
            return ByteArray(32).also { generator.generateBytes(it, 0, it.size) }
        }
    }

    fun linksFromJson(text: String?): MutableList<Link> {
        if (text.isNullOrBlank()) return mutableListOf()
        return try {
            val array = JSONArray(text)
            MutableList(array.length()) { Link.fromJson(array.getJSONObject(it)) }
                .filterTo(mutableListOf()) { it.isValid() }
        } catch (_: Exception) {
            mutableListOf()
        }
    }

    fun linksToJson(links: List<Link>): String = JSONArray().apply {
        links.forEach { put(it.toJson()) }
    }.toString()

    fun hash(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun proof(secret: ByteArray, role: String, databaseId: String): ByteArray =
        hmac(secret, role.toByteArray() + byteArrayOf(0) + databaseId.toByteArray())

    /** Sort object keys recursively so Android and Qt authenticate identical bytes. */
    fun authenticate(message: JSONObject, secret: ByteArray): JSONObject = message.apply {
        remove("mac")
        put("mac", hmac(secret, canonicalJson(this).toByteArray(Charsets.UTF_8)).base64())
    }

    fun verify(message: JSONObject, secret: ByteArray): Boolean {
        val supplied = message.optString("mac").decodeBase64()
        val expected = hmac(secret, canonicalJson(message).toByteArray(Charsets.UTF_8))
        return supplied.size == expected.size && MessageDigest.isEqual(supplied, expected)
    }

    fun authenticatedMessage(type: String, deviceId: String, databaseId: String, secret: ByteArray) =
        authenticate(
            JSONObject()
                .put("type", type)
                .put("version", PROTOCOL_VERSION)
                .put("senderId", deviceId)
                .put("databaseId", databaseId)
                .put("nonce", randomBytes(16).base64()),
            secret,
        )

    fun send(socket: Socket, message: JSONObject) {
        val bytes = message.toString().toByteArray(Charsets.UTF_8)
        require(bytes.size <= MAX_FRAME_SIZE) { "LAN sync message is too large" }
        DataOutputStream(socket.getOutputStream()).apply {
            writeInt(bytes.size)
            write(bytes)
            flush()
        }
    }

    fun receive(socket: Socket): JSONObject {
        val input = DataInputStream(socket.getInputStream())
        val size = try {
            input.readInt()
        } catch (e: EOFException) {
            throw EOFException("LAN sync peer disconnected")
        }
        require(size in 1..MAX_FRAME_SIZE) { "Invalid LAN sync frame size" }
        return JSONObject(String(ByteArray(size).also { input.readFully(it) }, Charsets.UTF_8))
    }

    fun randomCode(): String = secureRandom.nextInt(1_000_000).toString().padStart(6, '0')
    fun randomBytes(size: Int) = ByteArray(size).also(secureRandom::nextBytes)

    private fun hmac(secret: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(secret, "HmacSHA256"))
            doFinal(data)
        }

    private fun canonicalJson(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> value.keys().asSequence().filter { it != "mac" }.sorted().joinToString(",", "{", "}") {
            JSONObject.quote(it) + ":" + canonicalJson(value.get(it))
        }
        is JSONArray -> (0 until value.length()).joinToString(",", "[", "]") { canonicalJson(value.get(it)) }
        is String -> JSONObject.quote(value)
        is Boolean, is Number -> value.toString()
        else -> JSONObject.quote(value.toString())
    }

    fun ByteArray.base64(): String = Base64.encodeToString(this, Base64.NO_WRAP)
    fun String.decodeBase64(): ByteArray = try {
        Base64.decode(this, Base64.DEFAULT)
    } catch (_: IllegalArgumentException) {
        ByteArray(0)
    }

    fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
    fun String.decodeHex(): ByteArray = try {
        chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    } catch (_: Exception) {
        ByteArray(0)
    }
}
