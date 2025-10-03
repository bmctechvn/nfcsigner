package com.bmc.nfcsigner

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import androidx.annotation.NonNull
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.IOException
import java.io.ByteArrayOutputStream

class NfcsignerPlugin : FlutterPlugin, MethodCallHandler, ActivityAware, NfcAdapter.ReaderCallback {
  private lateinit var channel: MethodChannel
  private var nfcAdapter: NfcAdapter? = null
  private var currentActivity: Activity? = null
  private var pendingCall: MethodCall? = null
  private var pendingResult: Result? = null

  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "nfcsigner")
    channel.setMethodCallHandler(this)
    nfcAdapter = NfcAdapter.getDefaultAdapter(flutterPluginBinding.applicationContext)
  }

  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    if (nfcAdapter == null) {
      result.error("NFC_UNAVAILABLE", "Thiết bị không hỗ trợ NFC.", null)
      return
    }
    if (currentActivity == null) {
      result.error("NFC_UNAVAILABLE", "Plugin không thể truy cập Activity.", null)
      return
    }
    this.pendingCall = call
    this.pendingResult = result
    nfcAdapter?.enableReaderMode(
      currentActivity,
      this,
      NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
      null
    )
  }

  override fun onTagDiscovered(tag: Tag?) {
    val isoDep = IsoDep.get(tag)
    if (isoDep == null) {
      pendingResult?.error("TAG_NOT_SUPPORTED", "Thẻ không hỗ trợ giao thức IsoDep (APDU).", null)
      cleanup()
      return
    }
    val call = pendingCall
    val result = pendingResult
    if (call == null || result == null) {
      cleanup()
      return
    }
    try {
      isoDep.connect()
      isoDep.timeout = 5000
      when (call.method) {
        "generateSignature" -> handleGenerateSignature(isoDep, call, result)
        "getRsaPublicKey" -> handleGetRsaPublicKey(isoDep, call, result)
        "getCertificate" -> handleGetCertificate(isoDep, call, result)
        else -> result.notImplemented()
      }
    } catch (e: Exception) {
      result.error("COMMUNICATION_ERROR", "Lỗi giao tiếp với thẻ: ${e.message}", null)
    } finally {
      try {
        if (isoDep.isConnected) isoDep.close()
      } catch (_: IOException) {}
      cleanup()
    }
  }

  private fun handleGenerateSignature(isoDep: IsoDep, call: MethodCall, result: Result) {
    try {
      val appletID = call.argument<String>("appletID")!!
      val pin = call.argument<String>("pin")!!
      val dataToSign = call.argument<ByteArray>("dataToSign")!!
      val keyIndex = call.argument<Int>("keyIndex")!!

      // --- Select Applet ---
      val selectResponse = isoDep.transceive(createSelectAppletCommand(hexStringToByteArray(appletID)))
      if (!isSuccess(selectResponse)) {
        result.error("APPLET_NOT_SELECTED", "Không thể chọn Applet.", getStatusDetails(selectResponse))
        return
      }

      // --- Verify PIN ---
      val verifyResponse = isoDep.transceive(createVerifyPinCommand(pin))
      if (!isSuccess(verifyResponse)) {
        val (sw1, sw2) = getStatusWords(verifyResponse)
        val triesLeft = if (sw1 == 0x63 && sw2 >= 0xC0) sw2 - 0xC0 else 0
        val message = if (triesLeft > 0) "Xác thực PIN thất bại. Còn $triesLeft lần thử." else "Xác thực PIN thất bại."
        result.error("AUTH_ERROR", message, getStatusDetails(verifyResponse))
        return
      }

      // --- Compute Signature với logic GET RESPONSE chính xác ---
      val signatureApdu = createComputeSignatureCommand(dataToSign, keyIndex)

      // 1. Gửi lệnh ký ban đầu
      var response = isoDep.transceive(signatureApdu)
      var (sw1, sw2) = getStatusWords(response)

      val signatureDataStream = ByteArrayOutputStream()

      // 2. Lấy block dữ liệu đầu tiên (nếu có)
      if (response.size > 2) {
        signatureDataStream.write(response, 0, response.size - 2)
      }

      // 3. Bắt đầu vòng lặp GET RESPONSE nếu thẻ yêu cầu (sw1 = 0x61)
      while (sw1 == 0x61) {
        val getResponseCommand = byteArrayOf(0x00, 0xC0.toByte(), 0x00, 0x00, sw2.toByte())
        response = isoDep.transceive(getResponseCommand)

        val (newSw1, newSw2) = getStatusWords(response)
        sw1 = newSw1
        sw2 = newSw2

        if (response.size > 2) {
          signatureDataStream.write(response, 0, response.size - 2)
        }
      }

      // 4. Kiểm tra mã trạng thái CUỐI CÙNG
      if (sw1 == 0x90 && sw2 == 0x00) {
        result.success(signatureDataStream.toByteArray())
      } else {
        result.error(
          "OPERATION_NOT_SUPPORTED",
          "Thao tác ký số thất bại.",
          mapOf("sw1" to sw1, "sw2" to sw2)
        )
      }
    } catch (e: IOException) {
      result.error("COMMUNICATION_ERROR", "Lỗi giao tiếp I/O: ${e.message}", null)
    }
  }
  private fun handleGetRsaPublicKey(isoDep: IsoDep, call: MethodCall, result: Result) {
    try {
      val appletID = call.argument<String>("appletID")!!
      val keyRole = call.argument<String>("keyRole")!!

      // Bước 1: Chọn Applet
      val selectResponse = transceiveAndGetResponse(isoDep, createSelectAppletCommand(hexStringToByteArray(appletID)))
      if (!isSuccess(selectResponse)) {
        result.error("APPLET_NOT_SELECTED", "Không thể chọn Applet.", getStatusDetails(selectResponse))
        return
      }

      // Bước 2: Gửi lệnh lấy khóa công khai
      val getPubKeyApdu = createGetRsaPublicKeyCommand(keyRole)
      val pubKeyResponse = transceiveAndGetResponse(isoDep, getPubKeyApdu)

      if (!isSuccess(pubKeyResponse)) {
        result.error("OPERATION_NOT_SUPPORTED", "Không thể lấy khóa công khai.", getStatusDetails(pubKeyResponse))
        return
      }

      result.success(getData(pubKeyResponse))

    } catch (e: IllegalArgumentException) {
      result.error("INVALID_PARAMETERS", e.message, null)
    } catch (e: IOException) {
      result.error("COMMUNICATION_ERROR", "Lỗi giao tiếp I/O: ${e.message}", null)
    }
  }
  private fun handleGetCertificate(isoDep: IsoDep, call: MethodCall, result: Result) {
    try {
      val appletID = call.argument<String>("appletID")!!

      // Bước 1: Chọn Applet
      val selectResponse = transceiveAndGetResponse(isoDep, createSelectAppletCommand(hexStringToByteArray(appletID)))
      if (!isSuccess(selectResponse)) {
        result.error("APPLET_NOT_SELECTED", "Không thể chọn Applet.", getStatusDetails(selectResponse))
        return
      }
      // BƯỚC 2: CHỌN DỮ LIỆU CERTIFICATE (Select Data)
      val selectCertResponse = transceiveAndGetResponse(isoDep, createSelectCertificateCommand())
      if (!isSuccess(selectCertResponse)) {
        result.error("OPERATION_NOT_SUPPORTED", "Không thể chọn dữ liệu Certificate trên thẻ.", getStatusDetails(selectCertResponse))
        return
      }
      // Bước 3: Gửi lệnh lấy certificate
      val getCertApdu = createGetCertificateCommand()
      // Dùng transceiveAndGetResponse vì certificate có thể rất lớn
      val certResponse = transceiveAndGetResponse(isoDep, getCertApdu)

      if (!isSuccess(certResponse)) {
        result.error("OPERATION_NOT_SUPPORTED", "Không thể lấy certificate.", getStatusDetails(certResponse))
        return
      }

      result.success(getData(certResponse))

    } catch (e: IOException) {
      result.error("COMMUNICATION_ERROR", "Lỗi giao tiếp I/O: ${e.message}", null)
    }
  }
  private fun cleanup() {
    currentActivity?.let { nfcAdapter?.disableReaderMode(it) }
    pendingCall = null
    pendingResult = null
  }

  private fun transceive(isoDep: IsoDep, command: ByteArray): ByteArray = isoDep.transceive(command)
  private fun isSuccess(response: ByteArray): Boolean = response.size >= 2 && response[response.size - 2] == 0x90.toByte() && response[response.size - 1] == 0x00.toByte()
  private fun getData(response: ByteArray): ByteArray = response.copyOfRange(0, response.size - 2)
  private fun getStatusWords(response: ByteArray): Pair<Int, Int> = if (response.size >= 2) Pair(response[response.size - 2].toInt() and 0xFF, response[response.size - 1].toInt() and 0xFF) else Pair(0, 0)
  private fun getStatusDetails(response: ByteArray): Map<String, Int> {
    val (sw1, sw2) = getStatusWords(response)
    return mapOf("sw1" to sw1, "sw2" to sw2)
  }

  private fun createSelectAppletCommand(aid: ByteArray): ByteArray = byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, aid.size.toByte()) + aid + byteArrayOf(0x00)
  private fun createVerifyPinCommand(pin: String): ByteArray {
    val pinBytes = pin.toByteArray(Charsets.UTF_8)
    return byteArrayOf(0x00, 0x20, 0x00, 0x81.toByte(), pinBytes.size.toByte()) + pinBytes
  }

  /**
   * Hàm này tạo lệnh APDU Case 4 để ký số, khớp với log đã cung cấp.
   */
  private fun createComputeSignatureCommand(data: ByteArray, keyIndex: Int): ByteArray {
    val p1: Byte = 0x9E.toByte()
    val p2: Byte = when (keyIndex) {
      1 -> 0x9B.toByte()
      2 -> 0x9C.toByte()
      else -> 0x9A.toByte()
    }
    val lc = data.size.toByte()
    val le = 0x00.toByte()
    return byteArrayOf(0x00, 0x2A, p1, p2, lc) + data + byteArrayOf(le)
  }
  private fun createGetRsaPublicKeyCommand(keyRole: String): ByteArray {
    val data = when (keyRole) {
      "sig" -> byteArrayOf(0xB6.toByte(), 0x00)
      "dec" -> byteArrayOf(0xB8.toByte(), 0x00)
      "aut" -> byteArrayOf(0xA4.toByte(), 0x00)
      "sm" -> byteArrayOf(0xA6.toByte(), 0x00)
      else -> throw IllegalArgumentException("Vai trò khóa không hợp lệ: $keyRole")
    }

    val cla: Byte = 0x00
    val ins: Byte = 0x47
    val p1: Byte = 0x81.toByte()
    val p2: Byte = 0x00
    val lc = data.size.toByte()
    val le = 0x00.toByte()

    return byteArrayOf(cla, ins, p1, p2, lc) + data + byteArrayOf(le)
  }
  private fun createSelectCertificateCommand(): ByteArray {
    // Lệnh SELECT DATA theo đúng code C# bạn cung cấp.
    // Data: 60 04 5C 02 7F 21
    val data = byteArrayOf(0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21)
    val lc = data.size.toByte()
    return byteArrayOf(0x00, 0xA5.toByte(), 0x02, 0x04, lc) + data + byteArrayOf(0x00)
  }
  private fun createGetCertificateCommand(): ByteArray {
    // Lệnh GET DATA cho đối tượng Cardholder Certificate (Tag 7F21)
    return byteArrayOf(0x00, 0xCA.toByte(), 0x7F, 0x21, 0x00)
  }
  private fun hexStringToByteArray(hex: String): ByteArray {
    check(hex.length % 2 == 0) { "Must have an even length" }
    return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
  }
  /**
   * Hàm helper mới: Gửi một lệnh và tự động xử lý vòng lặp GET RESPONSE (61xx).
   * Trả về một phản hồi APDU hoàn chỉnh duy nhất.
   */
  @Throws(IOException::class)
  private fun transceiveAndGetResponse(isoDep: IsoDep, command: ByteArray): ByteArray {
    var response = isoDep.transceive(command)
    var (sw1, sw2) = getStatusWords(response)

    // Nếu thẻ trả về 61xx, bắt đầu vòng lặp để lấy hết dữ liệu
    if (sw1 == 0x61) {
      val fullResponseData = ByteArrayOutputStream()
      // Dữ liệu từ phản hồi đầu tiên (nếu có)
      if (response.size > 2) {
        fullResponseData.write(response, 0, response.size - 2)
      }

      while (sw1 == 0x61) {
        // Tạo lệnh GET RESPONSE
        val getResponseCommand = byteArrayOf(0x00, 0xC0.toByte(), 0x00, 0x00, sw2.toByte())
        response = isoDep.transceive(getResponseCommand)

        // Cập nhật sw1, sw2 cho lần lặp tiếp theo
        val (newSw1, newSw2) = getStatusWords(response)
        sw1 = newSw1
        sw2 = newSw2

        // Nối dữ liệu mới nhận được
        if (response.size > 2) {
          fullResponseData.write(response, 0, response.size - 2)
        }
      }

      // Tạo lại phản hồi cuối cùng hoàn chỉnh
      val finalData = fullResponseData.toByteArray()
      return finalData + byteArrayOf(sw1.toByte(), sw2.toByte())
    }

    // Nếu không phải 61xx, trả về phản hồi gốc
    return response
  }
  override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) { channel.setMethodCallHandler(null) }
  override fun onAttachedToActivity(binding: ActivityPluginBinding) { currentActivity = binding.activity }
  override fun onDetachedFromActivity() { currentActivity = null }
  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) { onAttachedToActivity(binding) }
  override fun onDetachedFromActivityForConfigChanges() { onDetachedFromActivity() }
}