package com.bmc.nfcsigner

import android.content.Context
import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import com.bmc.nfcsigner.core.CardOperationManager
import com.bmc.nfcsigner.core.DebugLogger
import com.bmc.nfcsigner.models.SignatureConfig
import com.bmc.nfcsigner.nfc.NfcCardManager
import com.bmc.nfcsigner.pdf.PdfSigningHelper
import com.bmc.nfcsigner.usb.UsbCardManager
import com.bmc.nfcsigner.usb.UsbDeviceManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class NfcsignerPlugin : FlutterPlugin, MethodCallHandler, ActivityAware, NfcAdapter.ReaderCallback {

  private lateinit var channel: MethodChannel
  private var nfcAdapter: NfcAdapter? = null
  private var currentActivity: Activity? = null
  private var pendingCall: MethodCall? = null
  private var pendingResult: Result? = null

  // Managers
  private lateinit var nfcCardManager: NfcCardManager
  private lateinit var usbDeviceManager: UsbDeviceManager
  private lateinit var usbCardManager: UsbCardManager
  private lateinit var pdfSigningHelper: PdfSigningHelper  // Đổi tên

  private val logger = DebugLogger("NfcsignerPlugin")
  private lateinit var applicationContext: Context

  override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "nfcsigner")
    channel.setMethodCallHandler(this)
    applicationContext = flutterPluginBinding.applicationContext
    nfcAdapter = NfcAdapter.getDefaultAdapter(applicationContext)

    // Initialize managers
    nfcCardManager = NfcCardManager()
  }

  override fun onMethodCall(call: MethodCall, result: Result) {
    when {
      isUsbReaderConnected() -> {
        logger.debug("USB reader detected. Handling via USB.")
        handleUsbRequest(call, result)
      }
      else -> {
        logger.debug("No USB reader found. Falling back to NFC.")
        handleNfcRequest(call, result)
      }
    }
  }

  private fun handleNfcRequest(call: MethodCall, result: Result) {
    if (nfcAdapter == null) {
      result.error("NFC_UNAVAILABLE", "Thiết bị không hỗ trợ NFC.", null)
      return
    }

    if (currentActivity == null) {
      result.error("NO_ACTIVITY", "Plugin không thể truy cập Activity.", null)
      return
    }

    pendingCall = call
    pendingResult = result

    nfcAdapter?.enableReaderMode(
      currentActivity, this,
      NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
      null
    )
  }

  override fun onTagDiscovered(tag: Tag?) {
    val call = pendingCall
    val result = pendingResult

    if (tag == null || call == null || result == null) {
      cleanup()
      return
    }

    try {
      nfcCardManager.executeWithNfcCard(tag) { cardManager ->
        executeCommand(cardManager, call, result)
      }
    } catch (e: Exception) {
      result.error("COMMUNICATION_ERROR", "Lỗi giao tiếp với thẻ: ${e.message}", null)
    } finally {
      cleanup()
    }
  }

  private fun executeCommand(cardManager: CardOperationManager, call: MethodCall, result: Result) {
    when (call.method) {
      "generateSignature" -> handleGenerateSignature(cardManager, call, result)
      "getRsaPublicKey" -> handleGetRsaPublicKey(cardManager, call, result)
      "getCertificate" -> handleGetCertificate(cardManager, call, result)
      "signPdf" -> handleSignPdf(cardManager, call, result)
      "generateXMLSignature" -> handleGenerateXMLSignature(cardManager, call, result)
      else -> result.notImplemented()
    }
  }

  private fun handleGenerateSignature(cardManager: CardOperationManager, call: MethodCall, result: Result) {
    try {
      val appletID = call.argument<String>("appletID")!!
      val pin = call.argument<String>("pin")!!
      val dataToSign = call.argument<ByteArray>("dataToSign")!!
      val keyIndex = call.argument<Int>("keyIndex")!!

      if (!cardManager.selectApplet(hexStringToByteArray(appletID))) {
        result.error("APPLET_NOT_SELECTED", "Không thể chọn Applet.", null)
        return
      }

      val (pinVerified, triesLeft) = cardManager.verifyPin(pin)
      if (!pinVerified) {
        val message = if (triesLeft > 0) "Xác thực PIN thất bại. Còn $triesLeft lần thử."
        else "Xác thực PIN thất bại."
        result.error("AUTH_ERROR", message, null)
        return
      }

      val signature = cardManager.generateSignature(dataToSign, keyIndex)
      result.success(signature)

    } catch (e: Exception) {
      result.error("COMMUNICATION_ERROR", "Lỗi giao tiếp I/O: ${e.message}", null)
    }
  }

  private fun handleGetRsaPublicKey(cardManager: CardOperationManager, call: MethodCall, result: Result) {
    try {
      val appletID = call.argument<String>("appletID")!!
      val keyRole = call.argument<String>("keyRole")!!

      if (!cardManager.selectApplet(hexStringToByteArray(appletID))) {
        result.error("APPLET_NOT_SELECTED", "Không thể chọn Applet.", null)
        return
      }

      val publicKey = cardManager.getRsaPublicKey(keyRole)
      result.success(publicKey)

    } catch (e: IllegalArgumentException) {
      result.error("INVALID_PARAMETERS", e.message, null)
    } catch (e: Exception) {
      result.error("COMMUNICATION_ERROR", "Lỗi giao tiếp I/O: ${e.message}", null)
    }
  }

  private fun handleGetCertificate(cardManager: CardOperationManager, call: MethodCall, result: Result) {
    try {
      val appletID = call.argument<String>("appletID")!!
      val keyRole = call.argument<String>("keyRole")!!

      if (!cardManager.selectApplet(hexStringToByteArray(appletID))) {
        result.error("APPLET_NOT_SELECTED", "Không thể chọn Applet.", null)
        return
      }

      val certificate = cardManager.getCertificate(keyRole)
      result.success(certificate)

    } catch (e: Exception) {
      result.error("COMMUNICATION_ERROR", "Lỗi giao tiếp I/O: ${e.message}", null)
    }
  }

  private fun handleSignPdf(cardManager: CardOperationManager, call: MethodCall, result: Result) {
    try {
      val pdfBytes = call.argument<ByteArray>("pdfBytes")!!
      val appletID = call.argument<String>("appletID")!!
      val pin = call.argument<String>("pin")!!
      val keyIndex = call.argument<Int>("keyIndex")!!
      val reason = call.argument<String>("reason")!!
      val location = call.argument<String>("location")!!
      val pdfHashBytes = call.argument<ByteArray>("pdfHashBytes")!!
      val signatureConfig = SignatureConfig.fromMap(call.argument<Map<String, Any>>("signatureConfig"))

      // Khởi tạo PdfSigningHelper ở đây vì cần context
      pdfSigningHelper = PdfSigningHelper(applicationContext)

      val signedPdf = pdfSigningHelper.signPdf(
        pdfBytes, cardManager, appletID, pin, keyIndex, reason, location, pdfHashBytes, signatureConfig
      )

      result.success(signedPdf)

    } catch (e: Exception) {
      result.error("PDF_SIGN_ERROR", "Lỗi khi ký PDF: ${e.message}", null)
    }
  }

  private fun handleGenerateXMLSignature(cardManager: CardOperationManager, call: MethodCall, result: Result) {
    try {
      val appletID = call.argument<String>("appletID")!!
      val pin = call.argument<String>("pin")!!
      val dataToSign = call.argument<ByteArray>("dataToSign")!!
      val keyIndex = call.argument<Int>("keyIndex")!!

      if (!cardManager.selectApplet(hexStringToByteArray(appletID))) {
        result.error("APPLET_NOT_SELECTED", "Không thể chọn Applet.", null)
        return
      }

      val (pinVerified, triesLeft) = cardManager.verifyPin(pin)
      if (!pinVerified) {
        val message = if (triesLeft > 0) "Xác thực PIN thất bại. Còn $triesLeft lần thử."
        else "Xác thực PIN thất bại."
        result.error("AUTH_ERROR", message, null)
        return
      }

      val signature = cardManager.generateSignature(dataToSign, keyIndex)
      if (signature == null) {
        result.error("SIGNING_ERROR", "Không thể tạo chữ ký.", null)
        return
      }
      val keyRole = "sig" // Hoặc lấy từ call.arguments nếu có
      val certificate = cardManager.getCertificate(keyRole)
      if (certificate == null) {
        result.error("CERTIFICATE_ERROR", "Không thể lấy certificate từ thẻ.", null)
        return
      }

      // CHUYỂN SANG BASE64 - ĐỒNG BỘ VỚI iOS
      val certificateBase64 = android.util.Base64.encodeToString(certificate, android.util.Base64.NO_WRAP)
      val signatureBase64 = android.util.Base64.encodeToString(signature, android.util.Base64.NO_WRAP)

      // Tạo kết quả trả về
      val resultMap = mapOf(
        "certificate" to certificateBase64,
        "signature" to signatureBase64
      )
      result.success(resultMap)

    } catch (e: Exception) {
      result.error("COMMUNICATION_ERROR", "Lỗi giao tiếp I/O: ${e.message}", null)
    }
  }

  // USB Handling
  private fun isUsbReaderConnected(): Boolean {
    if (!this::usbDeviceManager.isInitialized) return false
    return usbDeviceManager.isSmartCardReaderConnected()
  }

  private fun handleUsbRequest(call: MethodCall, result: Result) {
    CoroutineScope(Dispatchers.IO).launch {
      try {
        val success = usbCardManager.executeWithUsbCard { cardManager ->
          // Chuyển về main thread để gọi result
          withContext(Dispatchers.Main) {
            executeCommand(cardManager, call, result)
          }
        }

        if (!success) {
          withContext(Dispatchers.Main) {
            result.error("USB_CONNECTION_FAILED", "Không thể kết nối đến USB reader", null)
          }
        }
      } catch (e: Exception) {
        withContext(Dispatchers.Main) {
          result.error("USB_COMM_ERROR", "Lỗi giao tiếp USB: ${e.message}", null)
        }
      }
    }
  }

  // Utility methods
  private fun hexStringToByteArray(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "Must have an even length" }
    return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
  }

  private fun cleanup() {
    currentActivity?.let { nfcAdapter?.disableReaderMode(it) }
    pendingCall = null
    pendingResult = null
  }

  // Activity Aware methods
  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    currentActivity = binding.activity
    usbDeviceManager = UsbDeviceManager(binding.activity)
    usbCardManager = UsbCardManager(usbDeviceManager)
  }

  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    onAttachedToActivity(binding)
  }

  override fun onDetachedFromActivityForConfigChanges() {
    onDetachedFromActivity()
  }

  override fun onDetachedFromActivity() {
    if (this::usbDeviceManager.isInitialized) {
      usbDeviceManager.cleanup()
    }
    currentActivity = null
  }

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }
}