package com.bmc.nfcsigner.usb

import com.bmc.nfcsigner.core.CardOperationManager
import com.bmc.nfcsigner.core.Transceiver
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import java.io.IOException

class UsbCardManager(private val usbDeviceManager: UsbDeviceManager) {

    private var transceiver: Transceiver? = null
    private var cardOperationManager: CardOperationManager? = null

    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        if (!usbDeviceManager.connect()) {
            return@withContext false
        }

        transceiver = usbDeviceManager.createTransceiver()
        if (transceiver == null) {
            return@withContext false
        }

        cardOperationManager = CardOperationManager(transceiver!!)
        return@withContext true
    }

    fun getCardOperationManager(): CardOperationManager {
        return cardOperationManager ?: throw IllegalStateException("USB card manager not initialized")
    }

    fun disconnect() {
        transceiver?.disconnect()
        transceiver = null
        cardOperationManager = null
        usbDeviceManager.disconnect()
    }

    @Throws(IOException::class)
    suspend fun executeWithUsbCard(block: suspend (CardOperationManager) -> Unit): Boolean {
        if (!connect()) {
            return false
        }

        try {
            block(getCardOperationManager())
            return true
        } finally {
            disconnect()
        }
    }
}