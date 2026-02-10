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
    private var sequenceNumber: Int = 0

    companion object {
        // CCID Message Types - PC to Reader
        private const val PC_TO_RDR_ICC_POWER_ON: Byte = 0x62
        private const val PC_TO_RDR_ICC_POWER_OFF: Byte = 0x63
        private const val PC_TO_RDR_XFR_BLOCK: Byte = 0x6F

        // CCID Message Types - Reader to PC
        private const val RDR_TO_PC_DATA_BLOCK: Int = 0x80
        private const val RDR_TO_PC_SLOT_STATUS: Int = 0x81

        // ICC Status values (bStatus bits 1:0)
        private const val ICC_STATUS_ACTIVE: Int = 0x00
        private const val ICC_STATUS_INACTIVE: Int = 0x01
        private const val ICC_STATUS_NOT_PRESENT: Int = 0x02

        // Response buffer size
        private const val RESPONSE_BUFFER_SIZE: Int = 4096

        // Timeout values
        private const val SEND_TIMEOUT_MS: Int = 5000
        private const val RECEIVE_TIMEOUT_MS: Int = 15000

        // Short timeout for pipe draining
        private const val DRAIN_TIMEOUT_MS: Int = 100
    }

    override fun connect() {
        // USB connection is established in constructor
    }

    override fun disconnect() {
        // QUAN TRỌNG: KHÔNG gọi releaseInterface() / close() ở đây!
        // UsbDeviceManager.disconnect() sẽ quản lý lifecycle của USB connection.
        // Double releaseInterface() trên composite device sẽ corrupt USB state.
        logger.debug("UsbTransceiver disconnected")
    }

    override fun isConnected(): Boolean = usbConnection != null

    /**
     * Drain (đọc hết) dữ liệu cũ còn sót trong USB IN pipe.
     * Gọi trước khi bắt đầu session mới để tránh đọc phải data cũ.
     */
    private fun drainPipe() {
        val drainBuffer = ByteArray(RESPONSE_BUFFER_SIZE)
        var drained: Int
        var totalDrained = 0
        do {
            drained = usbConnection.bulkTransfer(endpointIn, drainBuffer, drainBuffer.size, DRAIN_TIMEOUT_MS)
            if (drained > 0) {
                totalDrained += drained
                logger.debug("Drained $drained bytes of stale data from USB IN pipe")
            }
        } while (drained > 0)

        if (totalDrained > 0) {
            logger.debug("Total drained: $totalDrained bytes")
        }
    }

    /**
     * Reset USB pipe state: drain stale data + reset sequence number.
     * Gọi trước mỗi session USB mới.
     */
    fun resetPipeState() {
        logger.debug("Resetting USB pipe state...")
        drainPipe()
        sequenceNumber = 0
        logger.debug("USB pipe state reset complete")
    }

    /**
     * Gửi PC_to_RDR_IccPowerOn (0x62) để kích hoạt card slot.
     * Trả về ATR (Answer To Reset) từ card.
     * Bước này BẮT BUỘC trước khi gửi APDU command, đặc biệt với composite device.
     */
    @Throws(IOException::class)
    fun iccPowerOn(): ByteArray {
        // Reset pipe state trước khi Power On — critical cho composite device
        resetPipeState()

        logger.debug("Sending ICC Power On...")

        val message = ByteArray(10)
        message[0] = PC_TO_RDR_ICC_POWER_ON  // Message Type
        // Bytes 1-4: Data length = 0 (no data payload for power on)
        message[1] = 0x00
        message[2] = 0x00
        message[3] = 0x00
        message[4] = 0x00
        message[5] = 0x00  // Slot number
        message[6] = nextSequenceNumber().toByte()  // Sequence number
        message[7] = 0x00  // PowerSelect: auto voltage selection
        message[8] = 0x00  // RFU
        message[9] = 0x00  // RFU

        logger.debug("ICC Power On → ${message.toHexString()}")

        // Send power on command
        val sent = usbConnection.bulkTransfer(endpointOut, message, message.size, SEND_TIMEOUT_MS)
        if (sent != message.size) {
            throw IOException("Failed to send ICC Power On: sent $sent of ${message.size} bytes")
        }

        // Receive response (RDR_to_PC_DataBlock with ATR)
        val ccidResponse = readCcidResponse()

        logger.debug("ICC Power On ← ${ccidResponse.toHexString()}")

        if (ccidResponse.size < 10) {
            throw IOException("ICC Power On response too short: ${ccidResponse.size} bytes")
        }

        val messageType = ccidResponse[0].toInt() and 0xFF
        if (messageType != RDR_TO_PC_DATA_BLOCK) {
            throw IOException("Unexpected response type for ICC Power On: 0x${messageType.toString(16)}")
        }

        // Check ICC status
        checkCcidStatus(ccidResponse)

        // Extract ATR data
        val dataLength = extractDataLength(ccidResponse)
        val atr = if (dataLength > 0 && 10 + dataLength <= ccidResponse.size) {
            ccidResponse.copyOfRange(10, 10 + dataLength)
        } else {
            byteArrayOf()
        }

        logger.debug("ICC Power On success, ATR: ${atr.toHexString()}")
        return atr
    }

    /**
     * Gửi PC_to_RDR_IccPowerOff (0x63) để tắt card slot.
     */
    @Throws(IOException::class)
    fun iccPowerOff() {
        logger.debug("Sending ICC Power Off...")

        val message = ByteArray(10)
        message[0] = PC_TO_RDR_ICC_POWER_OFF  // Message Type
        message[5] = 0x00  // Slot number
        message[6] = nextSequenceNumber().toByte()

        val sent = usbConnection.bulkTransfer(endpointOut, message, message.size, SEND_TIMEOUT_MS)
        if (sent != message.size) {
            logger.debug("Failed to send ICC Power Off")
        }

        // Read response but don't fail if it fails
        try {
            val responseBuffer = ByteArray(RESPONSE_BUFFER_SIZE)
            usbConnection.bulkTransfer(endpointIn, responseBuffer, responseBuffer.size, RECEIVE_TIMEOUT_MS)
        } catch (e: Exception) {
            logger.debug("Error reading ICC Power Off response: ${e.message}")
        }

        // Drain any remaining data after power off
        drainPipe()

        logger.debug("ICC Power Off sent")
    }

    @Throws(IOException::class)
    override fun transceive(command: ByteArray): ApduResponse {
        logger.debug("USB → ${command.toHexString()}")

        val ccidMessage = createCcidMessage(command)

        // Send command
        val sent = usbConnection.bulkTransfer(endpointOut, ccidMessage, ccidMessage.size, SEND_TIMEOUT_MS)
        if (sent != ccidMessage.size) {
            throw IOException("Failed to send CCID message: sent $sent of ${ccidMessage.size} bytes")
        }

        // Receive response
        val ccidResponse = readCcidResponse()

        logger.debug("USB ← ${ccidResponse.toHexString()}")

        return parseCcidResponse(ccidResponse)
    }

    /**
     * Đọc CCID response từ USB IN pipe.
     * Đảm bảo đọc đủ data theo data length trong CCID header.
     */
    @Throws(IOException::class)
    private fun readCcidResponse(): ByteArray {
        val responseBuffer = ByteArray(RESPONSE_BUFFER_SIZE)
        val received = usbConnection.bulkTransfer(endpointIn, responseBuffer, responseBuffer.size, RECEIVE_TIMEOUT_MS)
        if (received <= 0) {
            throw IOException("No response received from USB device (received=$received)")
        }

        // Kiểm tra xem đã đọc đủ data chưa (theo CCID header)
        if (received >= 10) {
            val expectedDataLength = (responseBuffer[1].toInt() and 0xFF) or
                    ((responseBuffer[2].toInt() and 0xFF) shl 8) or
                    ((responseBuffer[3].toInt() and 0xFF) shl 16) or
                    ((responseBuffer[4].toInt() and 0xFF) shl 24)
            val expectedTotal = 10 + expectedDataLength

            if (received < expectedTotal) {
                // Chưa đủ data → đọc tiếp
                logger.debug("Partial CCID response: got $received of $expectedTotal bytes, reading more...")
                val fullBuffer = responseBuffer.copyOf(expectedTotal)
                var totalReceived = received

                while (totalReceived < expectedTotal) {
                    val remaining = expectedTotal - totalReceived
                    val extra = usbConnection.bulkTransfer(
                        endpointIn,
                        fullBuffer,
                        totalReceived,
                        remaining,
                        RECEIVE_TIMEOUT_MS
                    )
                    if (extra <= 0) {
                        logger.debug("Failed to read remaining CCID data: got $totalReceived of $expectedTotal")
                        break
                    }
                    totalReceived += extra
                }

                return fullBuffer.copyOf(totalReceived)
            }
        }

        return responseBuffer.copyOf(received)
    }

    private fun createCcidMessage(apdu: ByteArray): ByteArray {
        val message = ByteArray(10 + apdu.size)
        message[0] = PC_TO_RDR_XFR_BLOCK  // Message Type: PC_to_RDR_XfrBlock

        // Data length (little-endian)
        val dataLength = apdu.size
        message[1] = (dataLength and 0xFF).toByte()
        message[2] = ((dataLength shr 8) and 0xFF).toByte()
        message[3] = ((dataLength shr 16) and 0xFF).toByte()
        message[4] = ((dataLength shr 24) and 0xFF).toByte()

        message[5] = 0x00  // Slot number
        message[6] = nextSequenceNumber().toByte()  // Sequence number (incrementing)
        message[7] = 0x00  // BWI (Block Waiting Timeout)
        message[8] = 0x00  // levelParameter (for APDU level: 0x0000)
        message[9] = 0x00  // levelParameter

        System.arraycopy(apdu, 0, message, 10, apdu.size)
        return message
    }

    private fun parseCcidResponse(ccidResponse: ByteArray): ApduResponse {
        if (ccidResponse.size < 10) {
            throw IOException("CCID response too short: ${ccidResponse.size} bytes")
        }

        val messageType = ccidResponse[0].toInt() and 0xFF
        if (messageType != RDR_TO_PC_DATA_BLOCK) {
            throw IOException("Unexpected CCID message type: 0x${messageType.toString(16)}")
        }

        // Check ICC status and error
        checkCcidStatus(ccidResponse)

        val dataLength = extractDataLength(ccidResponse)

        return if (dataLength > 0 && 10 + dataLength <= ccidResponse.size) {
            val apduResponse = ccidResponse.copyOfRange(10, 10 + dataLength)
            ResponseHandler.parseResponse(apduResponse)
        } else {
            ApduResponse(byteArrayOf(), 0x90, 0x00)
        }
    }

    /**
     * Kiểm tra bStatus (byte 7) và bError (byte 8) trong CCID response.
     *
     * bStatus bits 1:0 (ICC Status):
     *   00 = ICC present and active
     *   01 = ICC present and inactive
     *   10 = No ICC present
     *
     * bStatus bit 6 (Command Status):
     *   0 = Processed without error
     *   1 = Failed
     */
    @Throws(IOException::class)
    private fun checkCcidStatus(ccidResponse: ByteArray) {
        val bStatus = ccidResponse[7].toInt() and 0xFF
        val bError = ccidResponse[8].toInt() and 0xFF
        val iccStatus = bStatus and 0x03
        val commandStatus = (bStatus shr 6) and 0x03

        logger.debug("CCID Status: bStatus=0x${bStatus.toString(16)}, bError=0x${bError.toString(16)}, iccStatus=$iccStatus, cmdStatus=$commandStatus")

        when (iccStatus) {
            ICC_STATUS_INACTIVE -> throw IOException("ICC present but inactive (not powered on). bError=0x${bError.toString(16)}")
            ICC_STATUS_NOT_PRESENT -> throw IOException("No ICC present in slot. bError=0x${bError.toString(16)}")
        }

        if (commandStatus != 0) {
            throw IOException("CCID command failed: bStatus=0x${bStatus.toString(16)}, bError=0x${bError.toString(16)}")
        }
    }

    /**
     * Extract data length (little-endian 4 bytes) từ CCID response.
     */
    private fun extractDataLength(ccidResponse: ByteArray): Int {
        return (ccidResponse[1].toInt() and 0xFF) or
                ((ccidResponse[2].toInt() and 0xFF) shl 8) or
                ((ccidResponse[3].toInt() and 0xFF) shl 16) or
                ((ccidResponse[4].toInt() and 0xFF) shl 24)
    }

    /**
     * Tạo sequence number tăng dần (0-255, wrap around).
     */
    private fun nextSequenceNumber(): Int {
        val seq = sequenceNumber
        sequenceNumber = (sequenceNumber + 1) and 0xFF
        return seq
    }

    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02x".format(it) }
}