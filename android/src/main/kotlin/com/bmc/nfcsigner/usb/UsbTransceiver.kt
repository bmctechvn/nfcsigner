package com.bmc.nfcsigner.usb

import android.hardware.usb.*
import com.bmc.nfcsigner.core.DebugLogger
import com.bmc.nfcsigner.core.Transceiver
import com.bmc.nfcsigner.core.ResponseHandler
import com.bmc.nfcsigner.models.ApduResponse
import java.io.IOException

class UsbTransceiver(
    private val usbManager: UsbManager,
    private val usbDevice: UsbDevice,
    private val usbConnection: UsbDeviceConnection,
    private val usbInterface: UsbInterface,
    private val endpointIn: UsbEndpoint,
    private val endpointOut: UsbEndpoint
) : Transceiver {

    private val logger = DebugLogger("UsbTransceiver")

    override fun connect() {
        // USB connection is established in constructor
    }

    override fun disconnect() {
        try {
            usbConnection.releaseInterface(usbInterface)
            usbConnection.close()
        } catch (e: Exception) {
            logger.debug("Error disconnecting USB: ${e.message}")
        }
    }

    override fun isConnected(): Boolean = usbConnection != null

    @Throws(IOException::class)
    override fun transceive(command: ByteArray): ApduResponse {
        logger.debug("USB → ${command.toHexString()}")

        val ccidMessage = createCcidMessage(command)

        // Send command
        val sent = usbConnection.bulkTransfer(endpointOut, ccidMessage, ccidMessage.size, 5000)
        if (sent != ccidMessage.size) {
            throw IOException("Failed to send CCID message: sent $sent of ${ccidMessage.size} bytes")
        }

        // Receive response
        val responseBuffer = ByteArray(1024)
        val received = usbConnection.bulkTransfer(endpointIn, responseBuffer, responseBuffer.size, 15000)
        if (received <= 0) {
            throw IOException("No response received from USB device")
        }

        val ccidResponse = responseBuffer.copyOf(received)
        logger.debug("USB ← ${ccidResponse.toHexString()}")

        return parseCcidResponse(ccidResponse)
    }

    private fun createCcidMessage(apdu: ByteArray): ByteArray {
        val message = ByteArray(10 + apdu.size)
        message[0] = 0x6F.toByte() // Message Type: PC_to_RDR_XfrBlock

        // Data length (little-endian)
        val dataLength = apdu.size
        message[1] = (dataLength and 0xFF).toByte()
        message[2] = ((dataLength shr 8) and 0xFF).toByte()
        message[3] = ((dataLength shr 16) and 0xFF).toByte()
        message[4] = ((dataLength shr 24) and 0xFF).toByte()

        // Reserved bytes
        for (i in 5..9) {
            message[i] = 0x00
        }

        System.arraycopy(apdu, 0, message, 10, apdu.size)
        return message
    }

    private fun parseCcidResponse(ccidResponse: ByteArray): ApduResponse {
        if (ccidResponse.size < 10) {
            throw IOException("CCID response too short: ${ccidResponse.size} bytes")
        }

        val messageType = ccidResponse[0].toInt() and 0xFF
        if (messageType != 0x80) { // RDR_to_PC_DataBlock
            throw IOException("Unexpected CCID message type: ${messageType.toString(16)}")
        }

        val dataLength = (ccidResponse[1].toInt() and 0xFF) or
                ((ccidResponse[2].toInt() and 0xFF) shl 8) or
                ((ccidResponse[3].toInt() and 0xFF) shl 16) or
                ((ccidResponse[4].toInt() and 0xFF) shl 24)

        return if (dataLength > 0 && 10 + dataLength <= ccidResponse.size) {
            val apduResponse = ccidResponse.copyOfRange(10, 10 + dataLength)
            ResponseHandler.parseResponse(apduResponse)
        } else {
            ApduResponse(byteArrayOf(), 0x90, 0x00) // Success status for empty response
        }
    }

    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02x".format(it) }
}