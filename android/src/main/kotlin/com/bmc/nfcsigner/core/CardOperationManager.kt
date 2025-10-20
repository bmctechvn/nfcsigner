package com.bmc.nfcsigner.core

import com.bmc.nfcsigner.models.ApduResponse
import java.io.IOException

class CardOperationManager(private val transceiver: Transceiver) {

    private val logger = DebugLogger("CardOperationManager")

    @Throws(IOException::class)
    private fun executeCommandWithGetResponse(command: ByteArray): ApduResponse {
        val initialResponse = transceiver.transceive(command)
        return ResponseHandler.handleGetResponse(initialResponse) { getResponseCommand ->
            transceiver.transceive(getResponseCommand)
        }
    }

    fun selectApplet(aid: ByteArray): Boolean {
        logger.debug("Selecting applet: ${aid.toHexString()}")
        val command = ApduCommandBuilder.createSelectAppletCommand(aid)
        val response = transceiver.transceive(command)
        return response.isSuccess
    }

    fun verifyPin(pin: String): Pair<Boolean, Int> {
        logger.debug("Verifying PIN")
        val command = ApduCommandBuilder.createVerifyPinCommand(pin)
        val response = transceiver.transceive(command)

        if (!response.isSuccess) {
            val triesLeft = if (response.sw1 == 0x63 && response.sw2 >= 0xC0) {
                response.sw2 - 0xC0
            } else {
                0
            }
            return Pair(false, triesLeft)
        }

        return Pair(true, 0)
    }

    fun generateSignature(data: ByteArray, keyIndex: Int): ByteArray {
        logger.debug("Generating signature for ${data.size} bytes, keyIndex: $keyIndex")
        val command = ApduCommandBuilder.createComputeSignatureCommand(data, keyIndex)
        val response = executeCommandWithGetResponse(command)

        if (!response.isSuccess) {
            throw IOException("Signature generation failed: SW=${response.sw1.toString(16)}${response.sw2.toString(16)}")
        }

        return response.data
    }

    fun getRsaPublicKey(keyRole: String): ByteArray {
        logger.debug("Getting RSA public key for role: $keyRole")
        val command = ApduCommandBuilder.createGetRsaPublicKeyCommand(keyRole)
        val response = executeCommandWithGetResponse(command)

        if (!response.isSuccess) {
            throw IOException("Get public key failed: SW=${response.sw1.toString(16)}${response.sw2.toString(16)}")
        }

        return response.data
    }

    fun getCertificate(keyRole: String): ByteArray {
        logger.debug("Getting certificate for role: $keyRole")

        // Select certificate data first
        val selectCommand = ApduCommandBuilder.createSelectCertificateCommand(keyRole)
        val selectResponse = transceiver.transceive(selectCommand)

        if (!selectResponse.isSuccess) {
            throw IOException("Select certificate failed: SW=${selectResponse.sw1.toString(16)}${selectResponse.sw2.toString(16)}")
        }

        // Get certificate
        val getCertCommand = ApduCommandBuilder.createGetCertificateCommand()
        val certResponse = executeCommandWithGetResponse(getCertCommand)

        if (!certResponse.isSuccess) {
            throw IOException("Get certificate failed: SW=${certResponse.sw1.toString(16)}${certResponse.sw2.toString(16)}")
        }

        return certResponse.data
    }

    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02x".format(it) }
}