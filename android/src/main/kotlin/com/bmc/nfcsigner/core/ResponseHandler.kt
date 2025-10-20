package com.bmc.nfcsigner.core

import com.bmc.nfcsigner.models.ApduResponse

object ResponseHandler {

    fun parseResponse(response: ByteArray): ApduResponse {
        return if (response.size >= 2) {
            val data = response.copyOfRange(0, response.size - 2)
            val sw1 = response[response.size - 2].toInt() and 0xFF
            val sw2 = response[response.size - 1].toInt() and 0xFF
            ApduResponse(data, sw1, sw2)
        } else {
            ApduResponse(byteArrayOf(), 0, 0)
        }
    }

    fun handleGetResponse(
        initialResponse: ApduResponse,
        transceiver: (ByteArray) -> ApduResponse
    ): ApduResponse {
        var response = initialResponse
        var sw1 = response.sw1
        var sw2 = response.sw2

        if (sw1 != 0x61) {
            return response
        }

        val fullResponseData = response.data.toMutableList()

        while (sw1 == 0x61) {
            val getResponseCommand = ApduCommandBuilder.createGetResponseCommand(sw2)
            response = transceiver(getResponseCommand)
            sw1 = response.sw1
            sw2 = response.sw2

            fullResponseData.addAll(response.data.toList())
        }

        return ApduResponse(fullResponseData.toByteArray(), sw1, sw2)
    }
}