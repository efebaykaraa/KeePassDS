/*
 * Copyright 2026 Jeremy Jamet / Kunzisoft and KeePassXC Team
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package com.kunzisoft.keepass.lansync

import android.content.Context
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.util.Log
import android.widget.EditText
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.kunzisoft.keepass.database.ContextualDatabase
import com.kunzisoft.keepass.database.element.CustomDataItem
import com.kunzisoft.keepass.database.element.binary.BinaryData
import com.kunzisoft.keepass.lansync.LanSyncProtocol.base64
import com.kunzisoft.keepass.lansync.LanSyncProtocol.decodeBase64
import com.kunzisoft.keepass.lansync.LanSyncProtocol.decodeHex
import com.kunzisoft.keepass.lansync.LanSyncProtocol.hex
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class LanSyncManager(
    private val activity: AppCompatActivity,
    private val databaseProvider: () -> ContextualDatabase?,
    private val requestSave: () -> Unit,
    private val requestReload: () -> Unit,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val preferences = activity.getSharedPreferences("lan_sync", Context.MODE_PRIVATE)
    private val deviceId = preferences.getString("device_id", null) ?: UUID.randomUUID().toString().also {
        preferences.edit().putString("device_id", it).apply()
    }
    private val deviceName = preferences.getString("device_name", null)
        ?: "${Build.MANUFACTURER} ${Build.MODEL}".trim()

    @Volatile private var running = false
    @Volatile private var syncing = false
    private var serverSocket: ServerSocket? = null
    private var discoverySocket: DatagramSocket? = null
    private var pendingUpload: PendingUpload? = null
    private var syncAfterSave: LanSyncProtocol.Link? = null
    @Volatile private var suppressNextAutomaticSync = false
    @Volatile private var pairingSaveLatch: CountDownLatch? = null
    @Volatile private var pairingSaveSucceeded = false

    private data class PendingUpload(
        val link: LanSyncProtocol.Link,
        val remoteHash: ByteArray,
        val manual: Boolean,
        val oldLocalData: ByteArray,
    )

    private data class ConnectionState(
        var peerId: String = "",
        var peerName: String = "",
        var databaseId: String = "",
        var peerPort: Int = 0,
        var pairSecret: ByteArray = ByteArray(0),
        var stagedData: ByteArray? = null,
        var expectedHash: ByteArray? = null,
        var oldData: ByteArray? = null,
    )

    fun start() {
        if (running || databaseProvider()?.loaded != true) return
        running = true
        try {
            serverSocket = ServerSocket(0)
            discoverySocket = DatagramSocket(null).apply {
                reuseAddress = true
                broadcast = true
                bind(InetSocketAddress(LanSyncProtocol.DISCOVERY_PORT))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Unable to start LAN sync listener", e)
            stop()
            return
        }
        scope.launch { discoveryLoop() }
        scope.launch { acceptLoop() }
    }

    fun stop() {
        running = false
        try { discoverySocket?.close() } catch (_: Exception) {}
        try { serverSocket?.close() } catch (_: Exception) {}
        discoverySocket = null
        serverSocket = null
    }

    fun destroy() {
        stop()
        scope.cancel()
    }

    /** Installs the phone-side link after a LAN-retrieved database is unlocked. */
    fun installBootstrapLink(database: ContextualDatabase): Boolean {
        val uri = database.fileUri ?: return false
        val customData = database.customData ?: return false
        val link = LanSyncBootstrapStore.take(uri.toString()) ?: return false
        customData.put(
            CustomDataItem(
                LanSyncProtocol.SETTINGS_KEY,
                LanSyncProtocol.linksToJson(listOf(link)),
            )
        )
        database.dataModifiedSinceLastLoading = true
        return true
    }

    fun showSetup() {
        if (databaseProvider()?.loaded != true) return
        scope.launch {
            val devices = discover()
            if (devices.isEmpty()) {
                showMessage("LAN sync", "No KeePassXCS or KeePassDS device was found on this Wi-Fi network.")
                return@launch
            }
            chooseDevice(devices)?.let { device ->
                val database = databaseProvider() ?: return@let
                val fileName = displayName(database.fileUri)
                if (!confirm("Select password database", "Synchronize “$fileName” with ${device.name}?")) return@let
                pair(device, database)
            }
        }
    }

    fun showPairedDevices() {
        val links = links(databaseProvider())
        if (links.isEmpty()) {
            showSetup()
            return
        }
        activity.runOnUiThread {
            val names = links.map { "${it.peerName} — ${it.address}" }.toTypedArray()
            AlertDialog.Builder(activity)
                .setTitle("LAN sync")
                .setItems(names) { _, index -> manualSync(links[index]) }
                .setNeutralButton("Pair new device") { _, _ -> showSetup() }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    private fun manualSync(link: LanSyncProtocol.Link? = links(databaseProvider()).firstOrNull()) {
        val database = databaseProvider() ?: return
        if (link == null) {
            showSetup()
        } else if (database.dataModifiedSinceLastLoading) {
            syncAfterSave = link
            requestSave()
        } else {
            startSync(link, true)
        }
    }

    /** Called by the activity whenever an action which may have saved the DB finishes. */
    fun onDatabaseActionFinished(success: Boolean) {
        pairingSaveLatch?.let {
            pairingSaveSucceeded = success
            it.countDown()
            return
        }
        if (!success) {
            pendingUpload?.let { pending -> scope.launch { rollbackLocal(pending.oldLocalData) } }
            pendingUpload = null
            syncAfterSave = null
            syncing = false
            return
        }
        val database = databaseProvider() ?: return
        if (database.dataModifiedSinceLastLoading) return
        if (suppressNextAutomaticSync) {
            suppressNextAutomaticSync = false
            return
        }

        val upload = pendingUpload
        if (upload != null) {
            pendingUpload = null
            scope.launch { finishUpload(upload) }
            return
        }
        val requested = syncAfterSave
        syncAfterSave = null
        if (requested != null) {
            startSync(requested, true)
            return
        }
        if (!syncing) links(database).forEach { startSync(it, false) }
    }

    private fun startSync(link: LanSyncProtocol.Link, manual: Boolean) {
        if (syncing || !link.isValid()) return
        syncing = true
        scope.launch {
            try {
                var active = link
                var head = request(active, "head")
                if (head == null) {
                    discover().firstOrNull { it.id == link.peerId }?.let {
                        active = link.copy(address = it.address, port = it.port)
                        head = request(active, "head")
                    }
                }
                val remoteHash = head?.optString("fileHash")?.decodeHex()
                    ?: throw IllegalStateException("Peer is unavailable")
                val response = request(active, "get", 30_000)
                    ?: throw IllegalStateException("Could not download peer database")
                val remoteData = response.optString("data").decodeBase64()
                if (remoteData.isEmpty() || !LanSyncProtocol.hash(remoteData).contentEquals(remoteHash)) {
                    throw IllegalStateException("Downloaded database failed its integrity check")
                }

                val database = databaseProvider() ?: throw IllegalStateException("Database was closed")
                if (database.dataModifiedSinceLastLoading) {
                    syncAfterSave = active
                    activity.runOnUiThread(requestSave)
                    syncing = false
                    return@launch
                }
                val ownSettings = database.customData?.get(LanSyncProtocol.SETTINGS_KEY)?.value
                val oldLocalData = readDatabase()
                    ?: throw IllegalStateException("Unable to preserve the pre-sync database")
                database.mergeData(
                    ByteArrayInputStream(remoteData),
                    null,
                    { _, _ -> ByteArray(0) },
                    { memoryWanted -> BinaryData.canMemoryBeAllocatedInRAM(activity, memoryWanted) },
                    null,
                )
                ownSettings?.let {
                    database.customData?.put(CustomDataItem(LanSyncProtocol.SETTINGS_KEY, it))
                }
                pendingUpload = PendingUpload(active, remoteHash, manual, oldLocalData)
                activity.runOnUiThread(requestSave)
            } catch (e: Exception) {
                syncing = false
                Log.e(TAG, "LAN sync failed", e)
                if (manual) showMessage("LAN sync failed", e.message ?: "Unknown error")
            }
        }
    }

    private fun finishUpload(pending: PendingUpload) {
        try {
            val data = readDatabase() ?: throw IllegalStateException("Unable to read the saved database")
            upload(pending.link, data, pending.remoteHash, mergeAtPeer = true)
                ?: throw IllegalStateException("Peer rejected the synchronized database")
            if (pending.manual) showMessage("LAN sync", "The database was synchronized successfully.")
        } catch (e: Exception) {
            Log.e(TAG, "LAN sync upload failed", e)
            rollbackLocal(pending.oldLocalData)
            if (pending.manual) showMessage("LAN sync failed", e.message ?: "Unknown error")
        } finally {
            syncing = false
        }
    }

    private fun pair(device: LanSyncProtocol.Device, database: ContextualDatabase) {
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(device.address, device.port), 5_000)
                socket.soTimeout = 120_000
                val exchange = LanSyncProtocol.KeyExchange()
                val dbId = databaseId(database)
                val localData = readDatabase() ?: throw IllegalStateException("Unable to read database")
                LanSyncProtocol.send(
                    socket,
                    JSONObject()
                        .put("type", "pair_begin")
                        .put("version", LanSyncProtocol.PROTOCOL_VERSION)
                        .put("senderId", deviceId)
                        .put("senderName", deviceName)
                        .put("listenPort", serverSocket?.localPort ?: 0)
                        .put("databaseId", dbId)
                        .put("databaseName", displayName(database.fileUri))
                        .put("fileHash", LanSyncProtocol.hash(localData).hex())
                        .put("publicKey", exchange.publicKey.base64()),
                )
                val challenge = LanSyncProtocol.receive(socket)
                if (challenge.optString("type") == "error") throw IllegalStateException(challenge.optString("error"))
                val code = requestCode(device.name) ?: return
                require(code.matches(Regex("^[0-9]{6}$"))) { "A six-digit code is required" }
                val secret = exchange.derive(challenge.optString("publicKey").decodeBase64(), code)
                require(
                    LanSyncProtocol.proof(secret, "server", dbId)
                        .contentEquals(challenge.optString("proof").decodeBase64())
                ) { "Verification code did not match the selected device" }
                LanSyncProtocol.send(
                    socket,
                    JSONObject().put("type", "pair_verify")
                        .put("proof", LanSyncProtocol.proof(secret, "client", dbId).base64()),
                )
                socket.soTimeout = 15_000
                val paired = LanSyncProtocol.receive(socket)
                require(paired.optString("type") == "paired" && LanSyncProtocol.verify(paired, secret)) {
                    paired.optString("error", "Peer did not confirm pairing")
                }
                saveLink(
                    database,
                    LanSyncProtocol.Link(device.id, device.name, dbId, device.address, device.port, secret),
                )
                syncAfterSave = links(database).firstOrNull { it.peerId == device.id }
                activity.runOnUiThread(requestSave)
                showMessage("LAN sync", "Pairing completed. Future synchronization will not ask again.")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Pairing failed", e)
            showMessage("LAN sync pairing failed", e.message ?: "Unknown error")
        }
    }

    private fun discoveryLoop() {
        val socket = discoverySocket ?: return
        val buffer = ByteArray(8192)
        while (running) {
            try {
                val packet = DatagramPacket(buffer, buffer.size)
                socket.receive(packet)
                val request = JSONObject(String(packet.data, packet.offset, packet.length, Charsets.UTF_8))
                if (request.optString("magic") != LanSyncProtocol.DISCOVERY_MAGIC ||
                    request.optInt("version") != LanSyncProtocol.PROTOCOL_VERSION ||
                    request.optString("id") == deviceId) continue
                val response = JSONObject()
                    .put("magic", LanSyncProtocol.DISCOVERY_MAGIC)
                    .put("version", LanSyncProtocol.PROTOCOL_VERSION)
                    .put("id", deviceId)
                    .put("name", deviceName)
                    .put("port", serverSocket?.localPort ?: 0)
                    .toString().toByteArray()
                socket.send(DatagramPacket(response, response.size, packet.address, packet.port))
            } catch (_: SocketException) {
                break
            } catch (e: Exception) {
                Log.w(TAG, "Invalid discovery packet", e)
            }
        }
    }

    private fun acceptLoop() {
        val server = serverSocket ?: return
        while (running) {
            try {
                val socket = server.accept()
                scope.launch { socket.use { handleConnection(it) } }
            } catch (_: SocketException) {
                break
            } catch (e: Exception) {
                Log.e(TAG, "LAN sync accept failed", e)
            }
        }
    }

    private fun handleConnection(socket: Socket) {
        val state = ConnectionState()
        socket.soTimeout = 120_000
        try {
            while (!socket.isClosed) {
                val message = LanSyncProtocol.receive(socket)
                when (message.optString("type")) {
                    "pair_begin" -> receivePairBegin(socket, message, state)
                    "pair_verify" -> receivePairVerify(socket, message, state)
                    else -> if (!handleAuthenticated(socket, message, state)) return
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "LAN sync connection ended: ${e.message}")
        }
    }

    private fun receivePairBegin(socket: Socket, message: JSONObject, state: ConnectionState) {
        val database = databaseProvider() ?: return sendError(socket, "Database is not open and unlocked")
        state.peerId = message.optString("senderId")
        state.peerName = message.optString("senderName")
        state.databaseId = message.optString("databaseId")
        state.peerPort = message.optInt("listenPort")
        if (state.databaseId != databaseId(database)) return sendError(socket, "Requested database is not open")
        if (!confirm("LAN sync pairing request", "${state.peerName} wants to synchronize “${displayName(database.fileUri)}”.")) {
            return sendError(socket, "Pairing request was declined")
        }
        val code = LanSyncProtocol.randomCode()
        val exchange = LanSyncProtocol.KeyExchange()
        state.pairSecret = exchange.derive(message.optString("publicKey").decodeBase64(), code)
        LanSyncProtocol.send(
            socket,
            JSONObject().put("type", "pair_challenge")
                .put("deviceId", deviceId)
                .put("deviceName", deviceName)
                .put("publicKey", exchange.publicKey.base64())
                .put("proof", LanSyncProtocol.proof(state.pairSecret, "server", state.databaseId).base64())
                .put("fileHash", (readDatabase()?.let(LanSyncProtocol::hash) ?: ByteArray(0)).hex()),
        )
        showMessage("LAN sync verification code", "Enter this code on ${state.peerName}:\n\n$code")
    }

    private fun receivePairVerify(socket: Socket, message: JSONObject, state: ConnectionState) {
        val expected = LanSyncProtocol.proof(state.pairSecret, "client", state.databaseId)
        if (!expected.contentEquals(message.optString("proof").decodeBase64())) {
            return sendError(socket, "Verification code was incorrect")
        }
        val database = databaseProvider() ?: return sendError(socket, "Database was closed")
        saveLink(
            database,
            LanSyncProtocol.Link(
                state.peerId,
                state.peerName,
                state.databaseId,
                socket.inetAddress.hostAddress ?: return,
                state.peerPort,
                state.pairSecret,
            ),
        )
        pairingSaveSucceeded = false
        val saveLatch = CountDownLatch(1)
        pairingSaveLatch = saveLatch
        activity.runOnUiThread(requestSave)
        saveLatch.await(30, TimeUnit.SECONDS)
        pairingSaveLatch = null
        if (!pairingSaveSucceeded) {
            return sendError(socket, "Unable to save pairing information")
        }
        send(socket, JSONObject().put("type", "paired"), state.pairSecret)
    }

    private fun handleAuthenticated(socket: Socket, message: JSONObject, state: ConnectionState): Boolean {
        val database = databaseProvider() ?: return false
        val sender = message.optString("senderId")
        val dbId = message.optString("databaseId")
        val link = links(database).firstOrNull { it.peerId == sender && it.databaseId == dbId }
        if (link == null || !LanSyncProtocol.verify(message, link.secret)) {
            sendError(socket, "Device or database is not authorized")
            return false
        }
        when (message.optString("type")) {
            "head" -> {
                val data = readDatabase() ?: return false
                send(socket, JSONObject().put("type", "head").put("fileHash", LanSyncProtocol.hash(data).hex()), link.secret)
            }
            "get" -> {
                val data = readDatabase() ?: return false
                send(socket, JSONObject().put("type", "data")
                    .put("fileHash", LanSyncProtocol.hash(data).hex()).put("data", data.base64()), link.secret)
            }
            "prepare" -> {
                if (database.dataModifiedSinceLastLoading || syncing) {
                    sendError(socket, "Destination database has unsaved changes", link.secret)
                    return true
                }
                val current = readDatabase() ?: return false
                val expected = message.optString("expectedHash").decodeHex()
                val staged = message.optString("data").decodeBase64()
                if (!LanSyncProtocol.hash(current).contentEquals(expected) ||
                    !LanSyncProtocol.hash(staged).contentEquals(message.optString("dataHash").decodeHex())) {
                    sendError(socket, "Database changed before transaction could be staged", link.secret)
                    return true
                }
                state.stagedData = staged
                state.expectedHash = expected
                state.oldData = current
                send(socket, JSONObject().put("type", "prepared"), link.secret)
            }
            "commit" -> {
                val current = readDatabase()
                val staged = state.stagedData
                if (current == null || staged == null ||
                    !LanSyncProtocol.hash(current).contentEquals(state.expectedHash)) {
                    sendError(socket, "Database changed during transaction; staged data was discarded", link.secret)
                    return true
                }
                if (!writeDatabase(staged, state.oldData)) {
                    sendError(socket, "Unable to replace database safely", link.secret)
                    return true
                }
                send(socket, JSONObject().put("type", "committed")
                    .put("fileHash", LanSyncProtocol.hash(staged).hex()), link.secret)
                state.stagedData = null
                suppressNextAutomaticSync = true
                activity.runOnUiThread(requestReload)
            }
            else -> sendError(socket, "Unsupported LAN sync request", link.secret)
        }
        return true
    }

    private fun request(link: LanSyncProtocol.Link, type: String, timeout: Int = 15_000): JSONObject? = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(link.address, link.port), 5_000)
            socket.soTimeout = timeout
            LanSyncProtocol.send(socket, LanSyncProtocol.authenticatedMessage(type, deviceId, link.databaseId, link.secret))
            LanSyncProtocol.receive(socket).takeIf { LanSyncProtocol.verify(it, link.secret) && it.optString("type") != "error" }
        }
    } catch (e: Exception) {
        Log.d(TAG, "$type request failed: ${e.message}")
        null
    }

    private fun upload(
        link: LanSyncProtocol.Link,
        data: ByteArray,
        expectedHash: ByteArray,
        mergeAtPeer: Boolean,
    ): JSONObject? = Socket().use { socket ->
        socket.connect(InetSocketAddress(link.address, link.port), 5_000)
        socket.soTimeout = 30_000
        val prepare = LanSyncProtocol.authenticatedMessage("prepare", deviceId, link.databaseId, link.secret)
            .put("expectedHash", expectedHash.hex())
            .put("dataHash", LanSyncProtocol.hash(data).hex())
            .put("data", data.base64())
            .put("merge", mergeAtPeer)
        // Recompute because fields were added after authenticatedMessage().
        LanSyncProtocol.authenticate(prepare, link.secret)
        LanSyncProtocol.send(socket, prepare)
        val prepared = LanSyncProtocol.receive(socket)
        if (!LanSyncProtocol.verify(prepared, link.secret) || prepared.optString("type") != "prepared") return null
        LanSyncProtocol.send(socket, LanSyncProtocol.authenticatedMessage("commit", deviceId, link.databaseId, link.secret))
        LanSyncProtocol.receive(socket).takeIf {
            LanSyncProtocol.verify(it, link.secret) && it.optString("type") == "committed"
        }
    }

    private fun discover(): List<LanSyncProtocol.Device> {
        val results = linkedMapOf<String, LanSyncProtocol.Device>()
        DatagramSocket().use { socket ->
            socket.broadcast = true
            socket.soTimeout = 1_500
            val request = JSONObject().put("magic", LanSyncProtocol.DISCOVERY_MAGIC)
                .put("version", LanSyncProtocol.PROTOCOL_VERSION).put("id", deviceId)
                .toString().toByteArray()
            socket.send(DatagramPacket(request, request.size, InetAddress.getByName("255.255.255.255"), LanSyncProtocol.DISCOVERY_PORT))
            val deadline = System.currentTimeMillis() + 1_500
            while (System.currentTimeMillis() < deadline) {
                try {
                    val packet = DatagramPacket(ByteArray(8192), 8192)
                    socket.receive(packet)
                    val value = JSONObject(String(packet.data, packet.offset, packet.length))
                    val id = value.optString("id")
                    if (id.isNotEmpty() && id != deviceId && value.optInt("version") == LanSyncProtocol.PROTOCOL_VERSION) {
                        results[id] = LanSyncProtocol.Device(
                            id, value.optString("name"), packet.address.hostAddress ?: continue, value.optInt("port"),
                        )
                    }
                } catch (_: java.net.SocketTimeoutException) {
                    break
                }
            }
        }
        return results.values.toList()
    }

    private fun databaseId(database: ContextualDatabase): String =
        database.rootGroup?.nodeId?.id?.toString() ?: ""

    private fun links(database: ContextualDatabase?): MutableList<LanSyncProtocol.Link> =
        LanSyncProtocol.linksFromJson(database?.customData?.get(LanSyncProtocol.SETTINGS_KEY)?.value)

    private fun saveLink(database: ContextualDatabase, link: LanSyncProtocol.Link) {
        val values = links(database).apply { removeAll { it.peerId == link.peerId }; add(link) }
        database.customData?.put(CustomDataItem(LanSyncProtocol.SETTINGS_KEY, LanSyncProtocol.linksToJson(values)))
        database.dataModifiedSinceLastLoading = true
    }

    private fun readDatabase(): ByteArray? = databaseProvider()?.fileUri?.let { uri ->
        activity.contentResolver.openInputStream(uri)?.use { it.readBytes() }
    }

    private fun writeDatabase(data: ByteArray, backup: ByteArray?): Boolean {
        val uri = databaseProvider()?.fileUri ?: return false
        return try {
            activity.contentResolver.openOutputStream(uri, "rwt")?.use { it.write(data); it.flush() }
                ?: return false
            true
        } catch (e: Exception) {
            Log.e(TAG, "Database replacement failed", e)
            if (backup != null) try {
                activity.contentResolver.openOutputStream(uri, "rwt")?.use { it.write(backup); it.flush() }
            } catch (restore: Exception) {
                Log.e(TAG, "Database rollback failed", restore)
            }
            false
        }
    }

    private fun rollbackLocal(oldData: ByteArray) {
        if (writeDatabase(oldData, null)) {
            suppressNextAutomaticSync = true
            activity.runOnUiThread(requestReload)
        }
    }

    private fun send(socket: Socket, message: JSONObject, secret: ByteArray) =
        LanSyncProtocol.send(socket, LanSyncProtocol.authenticate(message, secret))

    private fun sendError(socket: Socket, error: String, secret: ByteArray? = null) {
        val message = JSONObject().put("type", "error").put("error", error)
        LanSyncProtocol.send(socket, if (secret != null) LanSyncProtocol.authenticate(message, secret) else message)
    }

    private fun displayName(uri: Uri?): String {
        if (uri == null) return "database.kdbx"
        return try {
            activity.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
                if (it.moveToFirst()) it.getString(0) else null
            } ?: uri.lastPathSegment ?: "database.kdbx"
        } catch (_: Exception) {
            uri.lastPathSegment ?: "database.kdbx"
        }
    }

    private fun chooseDevice(devices: List<LanSyncProtocol.Device>): LanSyncProtocol.Device? {
        var selected: LanSyncProtocol.Device? = null
        val latch = CountDownLatch(1)
        activity.runOnUiThread {
            AlertDialog.Builder(activity).setTitle("Select LAN sync device")
                .setItems(devices.map { "${it.name} — ${it.address}" }.toTypedArray()) { _, which ->
                    selected = devices[which]; latch.countDown()
                }.setNegativeButton(android.R.string.cancel) { _, _ -> latch.countDown() }
                .setOnCancelListener { latch.countDown() }.show()
        }
        latch.await(2, TimeUnit.MINUTES)
        return selected
    }

    private fun requestCode(peer: String): String? {
        var result: String? = null
        val latch = CountDownLatch(1)
        activity.runOnUiThread {
            val input = EditText(activity).apply { inputType = android.text.InputType.TYPE_CLASS_NUMBER }
            AlertDialog.Builder(activity).setTitle("Verify LAN sync device")
                .setMessage("Enter the six-digit code shown on $peer:")
                .setView(input).setPositiveButton(android.R.string.ok) { _, _ -> result = input.text.toString(); latch.countDown() }
                .setNegativeButton(android.R.string.cancel) { _, _ -> latch.countDown() }
                .setOnCancelListener { latch.countDown() }.show()
        }
        latch.await(2, TimeUnit.MINUTES)
        return result
    }

    private fun confirm(title: String, message: String): Boolean {
        var accepted = false
        val latch = CountDownLatch(1)
        activity.runOnUiThread {
            AlertDialog.Builder(activity).setTitle(title).setMessage(message)
                .setPositiveButton("Accept") { _, _ -> accepted = true; latch.countDown() }
                .setNegativeButton("Decline") { _, _ -> latch.countDown() }
                .setOnCancelListener { latch.countDown() }.show()
        }
        latch.await(2, TimeUnit.MINUTES)
        return accepted
    }

    private fun showMessage(title: String, message: String) {
        activity.runOnUiThread {
            if (!activity.isFinishing) AlertDialog.Builder(activity).setTitle(title).setMessage(message)
                .setPositiveButton(android.R.string.ok, null).show()
        }
    }

    companion object {
        private const val TAG = "LanSyncManager"
    }
}
