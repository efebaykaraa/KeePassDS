/*
 * Copyright 2026 Jeremy Jamet / Kunzisoft and KeePassXC Team
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package com.kunzisoft.keepass.lansync

import android.content.Context
import android.os.Build
import android.text.InputType
import android.widget.EditText
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.kunzisoft.keepass.lansync.LanSyncProtocol.base64
import com.kunzisoft.keepass.lansync.LanSyncProtocol.decodeBase64
import com.kunzisoft.keepass.lansync.LanSyncProtocol.decodeHex
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

internal data class LanSyncDownload(
    val fileName: String,
    val data: ByteArray,
    val link: LanSyncProtocol.Link,
)

/** Keeps the new link in memory until the downloaded KDBX has been unlocked. */
internal object LanSyncBootstrapStore {
    private val linksByUri = ConcurrentHashMap<String, LanSyncProtocol.Link>()
    @Volatile private var pendingDownload: LanSyncDownload? = null

    fun hold(download: LanSyncDownload) {
        pendingDownload = download
    }

    fun takeDownload(): LanSyncDownload? = pendingDownload.also { pendingDownload = null }

    fun remember(uri: String, link: LanSyncProtocol.Link) {
        linksByUri[uri] = link
    }

    fun take(uri: String): LanSyncProtocol.Link? = linksByUri.remove(uri)
}

/** Initial LAN retrieval flow used before KeePassDS has a local database to open. */
internal class LanSyncBootstrapManager(
    private val activity: AppCompatActivity,
    private val onDownloaded: (LanSyncDownload) -> Unit,
) {
    private data class RemoteDatabase(val id: String, val name: String)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val preferences = activity.getSharedPreferences("lan_sync", Context.MODE_PRIVATE)
    private val deviceId = preferences.getString("device_id", null) ?: UUID.randomUUID().toString().also {
        preferences.edit().putString("device_id", it).apply()
    }
    private val deviceName = preferences.getString("device_name", null)
        ?: "${Build.MANUFACTURER} ${Build.MODEL}".trim()
    @Volatile private var receiving = false
    private var serverSocket: ServerSocket? = null
    private var discoverySocket: DatagramSocket? = null

    fun startReceiving() {
        if (receiving) return
        try {
            serverSocket = ServerSocket(0)
            discoverySocket = DatagramSocket(null).apply {
                reuseAddress = true
                broadcast = true
                bind(InetSocketAddress(LanSyncProtocol.DISCOVERY_PORT))
            }
            receiving = true
            scope.launch { discoveryLoop() }
            scope.launch { acceptLoop() }
        } catch (e: Exception) {
            stopReceiving()
        }
    }

    fun stopReceiving() {
        receiving = false
        try { discoverySocket?.close() } catch (_: Exception) {}
        try { serverSocket?.close() } catch (_: Exception) {}
        discoverySocket = null
        serverSocket = null
    }

    fun retrieve() {
        scope.launch {
            try {
                val device = chooseDeviceWithRefresh() ?: return@launch
                val databases = requestDatabases(device)
                if (databases.isEmpty()) {
                    throw IllegalStateException("The selected device has no open and unlocked password database.")
                }
                val database = choose(
                    "Select password database",
                    databases,
                    databases.map { it.name },
                ) ?: return@launch
                val download = pairAndDownload(device, database) ?: return@launch
                activity.runOnUiThread {
                    if (!activity.isFinishing) onDownloaded(download)
                }
            } catch (e: Exception) {
                showMessage("LAN retrieval failed", e.message ?: "Unknown error")
            }
        }
    }

    fun destroy() {
        stopReceiving()
        scope.cancel()
    }

    private fun discoveryLoop() {
        val socket = discoverySocket ?: return
        val buffer = ByteArray(8192)
        while (receiving) {
            try {
                val packet = DatagramPacket(buffer, buffer.size)
                socket.receive(packet)
                val request = JSONObject(String(packet.data, packet.offset, packet.length, Charsets.UTF_8))
                if (request.optString("magic") != LanSyncProtocol.DISCOVERY_MAGIC ||
                    request.optInt("version") != LanSyncProtocol.PROTOCOL_VERSION ||
                    request.optString("id") == deviceId
                ) continue
                val response = JSONObject()
                    .put("magic", LanSyncProtocol.DISCOVERY_MAGIC)
                    .put("version", LanSyncProtocol.PROTOCOL_VERSION)
                    .put("id", deviceId)
                    .put("name", deviceName)
                    .put("port", serverSocket?.localPort ?: 0)
                    .put("bootstrapReceive", true)
                    .toString().toByteArray()
                socket.send(DatagramPacket(response, response.size, packet.address, packet.port))
            } catch (_: SocketException) {
                break
            } catch (_: Exception) {
                // Ignore malformed discovery packets.
            }
        }
    }

    private fun acceptLoop() {
        val server = serverSocket ?: return
        while (receiving) {
            try {
                val socket = server.accept()
                scope.launch { socket.use(::handleIncomingPair) }
            } catch (_: SocketException) {
                break
            }
        }
    }

    private fun handleIncomingPair(socket: Socket) {
        try {
            socket.soTimeout = 120_000
            val begin = LanSyncProtocol.receive(socket)
            require(begin.optString("type") == "pair_begin") { "Unsupported incoming LAN request" }
            val peerId = begin.optString("senderId")
            val peerName = begin.optString("senderName", "KeePassXCS")
            val databaseId = begin.optString("databaseId")
            val databaseName = begin.optString("databaseName", "database.kdbx")
            val peerPort = begin.optInt("listenPort")
            require(peerId.isNotEmpty() && databaseId.isNotEmpty() && peerPort in 1..65535) {
                "Invalid pairing request"
            }
            if (!confirm(
                    "Incoming password database",
                    "$peerName wants to send “$databaseName” to this device.",
                )
            ) {
                sendError(socket, "Pairing request was declined")
                return
            }

            val code = LanSyncProtocol.randomCode()
            val exchange = LanSyncProtocol.KeyExchange()
            val secret = exchange.derive(begin.optString("publicKey").decodeBase64(), code)
            LanSyncProtocol.send(
                socket,
                JSONObject()
                    .put("type", "pair_challenge")
                    .put("deviceId", deviceId)
                    .put("deviceName", deviceName)
                    .put("publicKey", exchange.publicKey.base64())
                    .put("proof", LanSyncProtocol.proof(secret, "server", databaseId).base64()),
            )
            showVerificationCode(peerName, code)
            val verify = LanSyncProtocol.receive(socket)
            require(
                verify.optString("type") == "pair_verify" &&
                    LanSyncProtocol.proof(secret, "client", databaseId)
                        .contentEquals(verify.optString("proof").decodeBase64())
            ) { "Verification code was incorrect" }
            LanSyncProtocol.send(
                socket,
                LanSyncProtocol.authenticate(JSONObject().put("type", "paired"), secret),
            )

            val link = LanSyncProtocol.Link(
                peerId,
                peerName,
                databaseId,
                socket.inetAddress.hostAddress ?: return,
                peerPort,
                secret,
            )
            val download = downloadWithRetry(link, databaseName)
            activity.runOnUiThread {
                if (!activity.isFinishing) onDownloaded(download)
            }
        } catch (e: Exception) {
            try { sendError(socket, e.message ?: "Incoming transfer failed") } catch (_: Exception) {}
            showMessage("LAN retrieval failed", e.message ?: "Unknown error")
        }
    }

    private fun downloadWithRetry(link: LanSyncProtocol.Link, fileName: String): LanSyncDownload {
        var failure: Exception? = null
        repeat(20) {
            try {
                val response = authenticatedRequest(link, "get")
                val data = response.optString("data").decodeBase64()
                val expectedHash = response.optString("fileHash").decodeHex()
                require(response.optString("type") == "data" && data.isNotEmpty()) {
                    "The computer did not return a database"
                }
                require(expectedHash.size == 32 && LanSyncProtocol.hash(data).contentEquals(expectedHash)) {
                    "Downloaded database failed its integrity check"
                }
                return LanSyncDownload(safeFileName(fileName), data, link)
            } catch (e: Exception) {
                failure = e
                Thread.sleep(250)
            }
        }
        throw failure ?: IllegalStateException("The computer did not make the database available")
    }

    private fun sendError(socket: Socket, error: String) {
        LanSyncProtocol.send(socket, JSONObject().put("type", "error").put("error", error))
    }

    private fun requestDatabases(device: LanSyncProtocol.Device): List<RemoteDatabase> =
        Socket().use { socket ->
            socket.connect(InetSocketAddress(device.address, device.port), 5_000)
            socket.soTimeout = 15_000
            LanSyncProtocol.send(
                socket,
                JSONObject()
                    .put("type", "list_databases")
                    .put("version", LanSyncProtocol.PROTOCOL_VERSION)
                    .put("senderId", deviceId),
            )
            val response = LanSyncProtocol.receive(socket)
            if (response.optString("type") == "error") {
                throw IllegalStateException(response.optString("error"))
            }
            require(response.optString("type") == "databases") { "The selected device returned an invalid response" }
            val values = response.optJSONArray("databases") ?: return@use emptyList()
            buildList {
                for (index in 0 until values.length()) {
                    val value = values.optJSONObject(index) ?: continue
                    val id = value.optString("databaseId")
                    if (id.isNotEmpty()) add(RemoteDatabase(id, value.optString("databaseName", "database.kdbx")))
                }
            }
        }

    private fun pairAndDownload(
        device: LanSyncProtocol.Device,
        database: RemoteDatabase,
    ): LanSyncDownload? {
        val link = Socket().use { socket ->
            socket.connect(InetSocketAddress(device.address, device.port), 5_000)
            socket.soTimeout = 120_000
            val exchange = LanSyncProtocol.KeyExchange()
            LanSyncProtocol.send(
                socket,
                JSONObject()
                    .put("type", "pair_begin")
                    .put("version", LanSyncProtocol.PROTOCOL_VERSION)
                    .put("senderId", deviceId)
                    .put("senderName", deviceName)
                    // Bootstrap has no database listener yet. Discovery replaces this endpoint
                    // with the real ephemeral TCP port after the downloaded vault is opened.
                    .put("listenPort", LanSyncProtocol.DISCOVERY_PORT)
                    .put("databaseId", database.id)
                    .put("databaseName", database.name)
                    .put("fileHash", "")
                    .put("publicKey", exchange.publicKey.base64()),
            )
            val challenge = LanSyncProtocol.receive(socket)
            if (challenge.optString("type") == "error") {
                throw IllegalStateException(challenge.optString("error"))
            }
            require(challenge.optString("type") == "pair_challenge") {
                "The selected device returned an invalid pairing response"
            }
            val code = requestCode(challenge.optString("deviceName", device.name)) ?: return null
            require(code.matches(Regex("^[0-9]{6}$"))) { "A six-digit code is required" }
            val secret = exchange.derive(challenge.optString("publicKey").decodeBase64(), code)
            require(
                LanSyncProtocol.proof(secret, "server", database.id)
                    .contentEquals(challenge.optString("proof").decodeBase64())
            ) { "Verification code did not match the selected device" }
            LanSyncProtocol.send(
                socket,
                JSONObject()
                    .put("type", "pair_verify")
                    .put("proof", LanSyncProtocol.proof(secret, "client", database.id).base64()),
            )
            socket.soTimeout = 30_000
            val paired = LanSyncProtocol.receive(socket)
            require(paired.optString("type") == "paired" && LanSyncProtocol.verify(paired, secret)) {
                paired.optString("error", "Peer did not confirm pairing")
            }
            LanSyncProtocol.Link(
                challenge.optString("deviceId", device.id),
                challenge.optString("deviceName", device.name),
                database.id,
                device.address,
                device.port,
                secret,
            )
        }

        val response = authenticatedRequest(link, "get")
        val data = response.optString("data").decodeBase64()
        val expectedHash = response.optString("fileHash").decodeHex()
        require(response.optString("type") == "data" && data.isNotEmpty()) {
            "The selected device did not return a database"
        }
        require(expectedHash.size == 32 && LanSyncProtocol.hash(data).contentEquals(expectedHash)) {
            "Downloaded database failed its integrity check"
        }
        return LanSyncDownload(safeFileName(database.name), data, link)
    }

    private fun safeFileName(name: String): String =
        name.substringAfterLast('/').substringAfterLast('\\')
            .ifBlank { "database.kdbx" }
            .let { if (it.endsWith(".kdbx", true)) it else "$it.kdbx" }

    private fun authenticatedRequest(link: LanSyncProtocol.Link, type: String): JSONObject =
        Socket().use { socket ->
            socket.connect(InetSocketAddress(link.address, link.port), 5_000)
            socket.soTimeout = 30_000
            LanSyncProtocol.send(
                socket,
                LanSyncProtocol.authenticatedMessage(type, deviceId, link.databaseId, link.secret),
            )
            val response = LanSyncProtocol.receive(socket)
            require(LanSyncProtocol.verify(response, link.secret)) { "The database response could not be authenticated" }
            if (response.optString("type") == "error") throw IllegalStateException(response.optString("error"))
            response
        }

    private fun discover(): List<LanSyncProtocol.Device> {
        val results = linkedMapOf<String, LanSyncProtocol.Device>()
        DatagramSocket().use { socket ->
            socket.broadcast = true
            socket.soTimeout = 1_500
            val request = JSONObject()
                .put("magic", LanSyncProtocol.DISCOVERY_MAGIC)
                .put("version", LanSyncProtocol.PROTOCOL_VERSION)
                .put("id", deviceId)
                .toString().toByteArray()
            socket.send(
                DatagramPacket(
                    request,
                    request.size,
                    InetAddress.getByName("255.255.255.255"),
                    LanSyncProtocol.DISCOVERY_PORT,
                )
            )
            val deadline = System.currentTimeMillis() + 1_500
            while (System.currentTimeMillis() < deadline) {
                try {
                    val packet = DatagramPacket(ByteArray(8192), 8192)
                    socket.receive(packet)
                    val value = JSONObject(String(packet.data, packet.offset, packet.length))
                    val id = value.optString("id")
                    val port = value.optInt("port")
                    if (id.isNotEmpty() && id != deviceId && port in 1..65535 &&
                        value.optString("magic") == LanSyncProtocol.DISCOVERY_MAGIC &&
                        value.optInt("version") == LanSyncProtocol.PROTOCOL_VERSION
                    ) {
                        results[id] = LanSyncProtocol.Device(
                            id,
                            value.optString("name", "KeePassXCS"),
                            packet.address.hostAddress ?: continue,
                            port,
                        )
                    }
                } catch (_: SocketTimeoutException) {
                    break
                }
            }
        }
        return results.values.toList()
    }

    private fun chooseDeviceWithRefresh(): LanSyncProtocol.Device? {
        while (true) {
            val devices = discover()
            if (devices.isEmpty()) {
                if (!confirm(
                        "No devices found",
                        "No KeePassXCS device was found on this Wi-Fi network.",
                        "Search again",
                        "Cancel",
                    )
                ) return null
                continue
            }
            val choice = chooseIndex(
                "Select KeePassXCS device",
                devices.map { "${it.name} — ${it.address}" } + "Search again",
            ) ?: return null
            if (choice == devices.size) continue
            return devices[choice]
        }
    }

    private fun chooseIndex(title: String, labels: List<String>): Int? {
        var selected: Int? = null
        val latch = CountDownLatch(1)
        activity.runOnUiThread {
            if (activity.isFinishing) {
                latch.countDown()
                return@runOnUiThread
            }
            AlertDialog.Builder(activity)
                .setTitle(title)
                .setItems(labels.toTypedArray()) { _, which -> selected = which; latch.countDown() }
                .setNegativeButton(android.R.string.cancel) { _, _ -> latch.countDown() }
                .setOnCancelListener { latch.countDown() }
                .show()
        }
        latch.await(2, TimeUnit.MINUTES)
        return selected
    }

    private fun <T> choose(title: String, values: List<T>, labels: List<String>): T? {
        var selected: T? = null
        val latch = CountDownLatch(1)
        activity.runOnUiThread {
            if (activity.isFinishing) {
                latch.countDown()
                return@runOnUiThread
            }
            AlertDialog.Builder(activity)
                .setTitle(title)
                .setItems(labels.toTypedArray()) { _, which -> selected = values[which]; latch.countDown() }
                .setNegativeButton(android.R.string.cancel) { _, _ -> latch.countDown() }
                .setOnCancelListener { latch.countDown() }
                .show()
        }
        latch.await(2, TimeUnit.MINUTES)
        return selected
    }

    private fun requestCode(peer: String): String? {
        var result: String? = null
        val latch = CountDownLatch(1)
        activity.runOnUiThread {
            if (activity.isFinishing) {
                latch.countDown()
                return@runOnUiThread
            }
            val input = EditText(activity).apply {
                inputType = InputType.TYPE_CLASS_NUMBER
            }
            AlertDialog.Builder(activity)
                .setTitle("Verify LAN sync device")
                .setMessage("Enter the six-digit code shown on $peer:")
                .setView(input)
                .setPositiveButton(android.R.string.ok) { _, _ -> result = input.text.toString(); latch.countDown() }
                .setNegativeButton(android.R.string.cancel) { _, _ -> latch.countDown() }
                .setOnCancelListener { latch.countDown() }
                .show()
        }
        latch.await(2, TimeUnit.MINUTES)
        return result
    }

    private fun confirm(
        title: String,
        message: String,
        positive: String = "Accept",
        negative: String = "Decline",
    ): Boolean {
        var accepted = false
        val latch = CountDownLatch(1)
        activity.runOnUiThread {
            if (activity.isFinishing) {
                latch.countDown()
                return@runOnUiThread
            }
            AlertDialog.Builder(activity)
                .setTitle(title)
                .setMessage(message)
                .setPositiveButton(positive) { _, _ -> accepted = true; latch.countDown() }
                .setNegativeButton(negative) { _, _ -> latch.countDown() }
                .setOnCancelListener { latch.countDown() }
                .show()
        }
        latch.await(2, TimeUnit.MINUTES)
        return accepted
    }

    private fun showVerificationCode(peer: String, code: String) {
        val latch = CountDownLatch(1)
        activity.runOnUiThread {
            if (activity.isFinishing) {
                latch.countDown()
                return@runOnUiThread
            }
            AlertDialog.Builder(activity)
                .setTitle("LAN sync verification code")
                .setMessage("Enter this code on $peer:\n\n$code")
                .setPositiveButton(android.R.string.ok) { _, _ -> latch.countDown() }
                .setOnCancelListener { latch.countDown() }
                .show()
        }
        latch.await(2, TimeUnit.MINUTES)
    }

    private fun showMessage(title: String, message: String) {
        activity.runOnUiThread {
            if (!activity.isFinishing) {
                AlertDialog.Builder(activity)
                    .setTitle(title)
                    .setMessage(message)
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
            }
        }
    }
}
