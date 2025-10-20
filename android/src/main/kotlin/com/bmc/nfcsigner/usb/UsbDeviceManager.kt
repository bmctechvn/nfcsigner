package com.bmc.nfcsigner.usb

import android.content.*
import android.hardware.usb.*
import android.app.PendingIntent
import com.bmc.nfcsigner.models.CardStatus
import com.bmc.nfcsigner.core.DebugLogger
class UsbDeviceManager(private val context: Context) {

    private val usbManager: UsbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager
    private val logger = DebugLogger("UsbDeviceManager")

    private var usbDevice: UsbDevice? = null
    private var usbConnection: UsbDeviceConnection? = null
    private var usbInterface: UsbInterface? = null
    private var endpointIn: UsbEndpoint? = null
    private var endpointOut: UsbEndpoint? = null

    private val usbPermissionAction = "com.bmc.nfcsigner.USB_PERMISSION"
    private var permissionCallback: ((Boolean) -> Unit)? = null

    private val usbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (usbPermissionAction == intent.action) {
                val device: UsbDevice? = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                val granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)

                if (granted && device != null) {
                    usbDevice = device
                    logger.debug("USB permission granted for ${device.deviceName}")
                } else {
                    logger.debug("USB permission denied for $device")
                }

                permissionCallback?.invoke(granted)
                permissionCallback = null
            }
        }
    }

    init {
        val filter = IntentFilter(usbPermissionAction)
        context.registerReceiver(usbReceiver, filter)
    }

    fun cleanup() {
        context.unregisterReceiver(usbReceiver)
        disconnect()
    }

    fun isSmartCardReaderConnected(): Boolean {
        val deviceList = usbManager.deviceList
        logger.debug("Found ${deviceList.size} USB devices")

        for (device in deviceList.values) {
            if (isSmartCardReader(device)) {
                usbDevice = device
                logger.debug("Smart card reader detected: ${device.deviceName}")
                return true
            }
        }

        return false
    }

    private fun isSmartCardReader(device: UsbDevice): Boolean {
        for (i in 0 until device.interfaceCount) {
            val usbInterface = device.getInterface(i)
            if (usbInterface.interfaceClass == 0x0B || // Chip/Smart Card
                (usbInterface.interfaceClass == 0xFF && usbInterface.interfaceProtocol == 0)) {
                return true
            }
        }
        return false
    }

    fun requestPermission(callback: (Boolean) -> Unit) {
        val device = usbDevice ?: run {
            callback(false)
            return
        }

        if (usbManager.hasPermission(device)) {
            callback(true)
            return
        }

        permissionCallback = callback
        val permissionIntent = PendingIntent.getBroadcast(
            context, 0, Intent(usbPermissionAction), PendingIntent.FLAG_IMMUTABLE
        )
        usbManager.requestPermission(device, permissionIntent)
    }

    fun connect(): Boolean {
        val device = usbDevice ?: return false

        try {
            if (!usbManager.hasPermission(device)) {
                logger.debug("No USB permission")
                return false
            }

            usbConnection = usbManager.openDevice(device) ?: return false

            // Find CCID interface
            for (i in 0 until device.interfaceCount) {
                val usbIntf = device.getInterface(i)
                if (usbIntf.interfaceClass == 0x0B ||
                    (usbIntf.interfaceClass == 0xFF && usbIntf.interfaceProtocol == 0)) {
                    usbInterface = usbIntf
                    break
                }
            }

            usbInterface = usbInterface ?: device.getInterface(0) // Fallback

            if (!usbConnection!!.claimInterface(usbInterface, true)) {
                logger.debug("Failed to claim USB interface")
                return false
            }

            // Find endpoints
            for (i in 0 until usbInterface!!.endpointCount) {
                val endpoint = usbInterface!!.getEndpoint(i)
                when {
                    endpoint.direction == UsbConstants.USB_DIR_IN &&
                            endpoint.type == UsbConstants.USB_ENDPOINT_XFER_BULK -> {
                        endpointIn = endpoint
                    }
                    endpoint.direction == UsbConstants.USB_DIR_OUT &&
                            endpoint.type == UsbConstants.USB_ENDPOINT_XFER_BULK -> {
                        endpointOut = endpoint
                    }
                }
            }

            if (endpointIn == null || endpointOut == null) {
                logger.debug("Failed to find USB endpoints")
                return false
            }

            logger.debug("Successfully connected to USB reader")
            return true

        } catch (e: Exception) {
            logger.debug("USB connection error: ${e.message}")
            return false
        }
    }

    fun createTransceiver(): UsbTransceiver? {
        return try {
            UsbTransceiver(
                usbManager,
                usbDevice!!,
                usbConnection!!,
                usbInterface!!,
                endpointIn!!,
                endpointOut!!
            )
        } catch (e: Exception) {
            logger.debug("Failed to create USB transceiver: ${e.message}")
            null
        }
    }

    fun disconnect() {
        try {
            usbInterface?.let { usbConnection?.releaseInterface(it) }
            usbConnection?.close()
        } catch (e: Exception) {
            logger.debug("Error disconnecting USB: ${e.message}")
        }

        usbConnection = null
        usbInterface = null
        endpointIn = null
        endpointOut = null
    }
}