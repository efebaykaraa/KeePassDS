package com.kunzisoft.keepass.lansync

import com.kunzisoft.keepass.lansync.LanSyncProtocol.decodeBase64
import com.kunzisoft.keepass.lansync.LanSyncProtocol.hex
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class LanSyncProtocolTest {
    @Test
    fun authenticationMatchesKeePassXCVector() {
        val message = JSONObject()
            .put("type", "get")
            .put("version", 1)
            .put("senderId", "android")
            .put("databaseId", "1234")
            .put("nonce", "AQID")
        val secret = ByteArray(32) { 's'.code.toByte() }

        LanSyncProtocol.authenticate(message, secret)

        assertEquals(
            "fde285064c4608f62768933a686301305f0ff25e1facb11262a3dd7f56e094e0",
            message.getString("mac").decodeBase64().hex(),
        )
        assertTrue(LanSyncProtocol.verify(message, secret))
    }

    @Test
    fun keyAgreementIsSymmetric() {
        val first = LanSyncProtocol.KeyExchange()
        val second = LanSyncProtocol.KeyExchange()
        assertArrayEquals(first.derive(second.publicKey, "123456"), second.derive(first.publicKey, "123456"))
    }
}
