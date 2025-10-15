package com.bmc.nfcsigner

import android.content.Context
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
// Import các lớp mới của iText 8
import com.itextpdf.kernel.pdf.PdfReader
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import com.itextpdf.kernel.pdf.StampingProperties
import com.itextpdf.signatures.*
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.cert.X509CertificateHolder
import java.security.cert.X509Certificate
import com.itextpdf.io.image.ImageDataFactory

//import org.simalliance.openmobileapi.Channel;
//import org.simalliance.openmobileapi.Reader;
//import org.simalliance.openmobileapi.SEService;
//import org.simalliance.openmobileapi.SEService.CallBack;
//import org.simalliance.openmobileapi.Session;

import fr.coppernic.sdk.pcsc2.ApduResponse;
import fr.coppernic.sdk.pcsc2.SCard;
import fr.coppernic.sdk.utils.core.CpcBytes;
import fr.coppernic.sdk.utils.core.CpcResult;
import fr.coppernic.sdk.utils.core.CpcResult.RESULT;
import fr.coppernic.sdk.power.PowerManager;
import fr.coppernic.sdk.power.api.PowerListener;
import fr.coppernic.sdk.power.api.peripheral.Peripheral;
import fr.coppernic.sdk.utils.ui.TextAppender;

// Cho Kotlin Coroutines
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import io.reactivex.Single // Import Single từ RxJava

class NfcsignerPlugin : FlutterPlugin, MethodCallHandler, ActivityAware, NfcAdapter.ReaderCallback {
  private lateinit var channel: MethodChannel
  private var nfcAdapter: NfcAdapter? = null
  private var currentActivity: Activity? = null
  private var pendingCall: MethodCall? = null
  private var pendingResult: Result? = null
  private lateinit var applicationContext: Context
  private fun ByteArray.toHexString(): String = joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }
  companion object {
    init {
      // Đảm bảo Bouncy Castle Provider được đăng ký một lần duy nhất
      // ngay khi lớp được nạp.
      if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
        Security.addProvider(BouncyCastleProvider())
      }
    }
  }
  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "nfcsigner")
    channel.setMethodCallHandler(this)
    nfcAdapter = NfcAdapter.getDefaultAdapter(flutterPluginBinding.applicationContext)
    applicationContext = flutterPluginBinding.applicationContext
  }
  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    // Tạm thời gọi debug
    //debugUsbConnection()
    // Logic tự động chuyển đổi: Ưu tiên USB trước
    if (isUsbReaderConnected()) {
      println("DEBUG: USB reader detected. Handling via USB.")
      handleUsbRequest(call, result)
    } else {
      println("DEBUG: No USB reader found. Falling back to NFC.")
      handleNfcRequest(call, result)
    }
    /*
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
    )*/
  }
  /**
   * Hàm kiểm tra kết nối USB, được viết lại để xử lý null safety.
   */
  private fun isUsbReaderConnected(): Boolean {
    return try {
      // Thử dùng Android OMAPI trước
      if (isOmapiAvailable()) {
        println("--- DEBUG: Using Android OMAPI ---")
        checkReadersViaOmapi()
      } else {
        println("--- DEBUG: OMAPI not available, trying Coppernic ---")
        checkReadersViaCoppernic()
      }
    } catch (e: Exception) {
      println("--- DEBUG: All USB reader checks failed: ${e.message} ---")
      false
    }
  }

  private fun isOmapiAvailable(): Boolean {
    return try {
      // Kiểm tra xem OMAPI có sẵn không
      Class.forName("android.se.omapi.Reader")
      true
    } catch (e: ClassNotFoundException) {
      false
    }
  }

  private fun checkReadersViaOmapi(): Boolean {
    // Chỉ chạy trên Android 8.0+ (API level 26+)
    if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.O) {
      println("--- DEBUG: OMAPI requires Android 8.0+ ---")
      return false
    }

    return try {
      val context = currentActivity?.applicationContext ?: return false

      // SỬA: Dùng tên service "se" thay vì Context.SESERVICE
      val seService = context.getSystemService("se") as? android.se.omapi.SEService
      if (seService == null) {
        println("--- DEBUG: SEService not available ---")
        return false
      }

      // SEService cần được kết nối trước khi sử dụng
      // Đây là một quá trình bất đồng bộ, cần implement SEService.OnConnectedListener
      // Vì đây chỉ là kiểm tra nhanh, chúng ta sẽ bỏ qua

      val readers = seService.readers
      println("--- DEBUG: OMAPI Readers found: ${readers.size} ---")
      readers.forEach { reader ->
        println("--- DEBUG: OMAPI Reader: ${reader.name} ---")
      }

      readers.isNotEmpty()
    } catch (e: Exception) {
      println("--- DEBUG: OMAPI check failed: ${e.message} ---")
      false
    }
  }

  private fun checkReadersViaCoppernic(): Boolean {
    val context = currentActivity?.applicationContext ?: return false
    var sCard: SCard? = null
    return try {
      sCard = SCard.Companion.createSCard(context).blockingGet()

      if (sCard.establishContext() != RESULT.OK) return false

      val readers = ArrayList<String>()
      sCard.listReaders(readers)
      readers.isNotEmpty()
    } catch (e: Exception) {
      when {
        e.message?.contains("SERVICE_NOT_FOUND") == true -> {
          println("--- INFO: Coppernic service not available on this device ---")
        }
        else -> {
          println("--- DEBUG: Coppernic error: ${e.message} ---")
        }
      }
      false
    } finally {
      sCard?.close()
    }
  }
  /**
   * Hàm xử lý cho luồng NFC (gần như không đổi).
   */
  private fun handleNfcRequest(call: MethodCall, result: Result) {
    if (nfcAdapter == null) {
      result.error("NFC_UNAVAILABLE", "Thiết bị không hỗ trợ NFC.", null)
      cleanup()
      return
    }
    if (currentActivity == null) {
      result.error("NO_ACTIVITY", "Plugin không thể truy cập Activity.", null)
      cleanup()
      return
    }
    this.pendingCall = call
    this.pendingResult = result
    nfcAdapter?.enableReaderMode(
      currentActivity, this,
      NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
      null
    )
  }
  /**
   * Hàm xử lý cho luồng USB, đã sửa lỗi null safety.
   */
  private fun handleUsbRequest(call: MethodCall, result: Result) {
    val context = currentActivity?.applicationContext
    if (context == null) {
      result.error("NO_CONTEXT", "Không thể lấy context.", null)
      cleanup()
      return
    }

    CoroutineScope(Dispatchers.IO).launch {
      var sCard: SCard? = null
      try {
        sCard = SCard.createSCard(context).blockingGet()
        sCard!! // Khẳng định không null

        if (sCard.establishContext() != RESULT.OK) throw IOException("Không thể thiết lập PCSC context.")
        val readers = ArrayList<String>()
        if (sCard.listReaders(readers) != RESULT.OK || readers.isEmpty()) throw IOException("Không tìm thấy đầu đọc thẻ USB.")
        val readerName = readers[0]
        if (sCard.connect(readerName) != RESULT.OK) throw IOException("Không thể kết nối đến đầu đọc '$readerName'.")

        // Tạo "hàm giao vận" (transceiver) cho USB, ĐÃ BAO GỒM logic GET RESPONSE
        val usbTransceiver: (ByteArray) -> ByteArray = { apdu ->
          val apduResponse = ApduResponse()
          var res = sCard.transmit(apdu, apduResponse)
          if (res != RESULT.OK) throw IOException("Lỗi transmit APDU. Mã lỗi: $res")

          // ======================== THÊM CÁC DÒNG DEBUG TẠI ĐÂY ========================
          println("--- DEBUG: Bắt đầu phân tích ApduResponse ---")

          // In toàn bộ đối tượng (thường sẽ gọi hàm toString() của nó)
          println("1. Toàn bộ đối tượng: $apduResponse")

          // In dữ liệu (payload) dưới dạng Hex
          val dataBytes = apduResponse.data
          if (dataBytes != null) {
            println("2. Dữ liệu (data): ${dataBytes.toHexString()}")
          } else {
            println("2. Dữ liệu (data): null")
          }
          var sw1 = 0x61 //apduResponse.sW1
          var sw2 = 0x00 //apduResponse.sW2

          if (sw1 == 0x61) {
            val fullResponseData = ByteArrayOutputStream()
            if (apduResponse.data != null) fullResponseData.write(apduResponse.data)

            while (sw1 == 0x61) {
              val getResponseCmd = byteArrayOf(0x00, 0xC0.toByte(), 0x00, 0x00, sw2.toByte())
              res = sCard.transmit(getResponseCmd, apduResponse)
              if (res != RESULT.OK) throw IOException("Lỗi GET RESPONSE. Mã lỗi: $res")

              sw1 = 0x90 //apduResponse.sW1
              sw2 = 0x00 //apduResponse.sW2
              if (apduResponse.data != null) fullResponseData.write(apduResponse.data)
            }
            fullResponseData.toByteArray() + byteArrayOf(sw1.toByte(), sw2.toByte())
          } else {
            (apduResponse.data ?: byteArrayOf()) + byteArrayOf(sw1.toByte(), sw2.toByte())
          }
        }

        withContext(Dispatchers.Main) {
          executeCommand(usbTransceiver, call, result)
        }

      } catch (e: Exception) {
        withContext(Dispatchers.Main) {
          result.error("USB_ERROR", "Lỗi giao tiếp USB: ${e.message}", null)
        }
      } finally {
        sCard?.disconnect()
        sCard?.close()
        withContext(Dispatchers.Main) {
          cleanup()
        }
      }
    }
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
      val nfcTransceiver: (ByteArray) -> ByteArray = { apdu ->
        println("DEBUG: NFC -> ${apdu.toHexString()}")
        val response = transceiveAndGetResponse(isoDep, apdu) // Dùng hàm helper cũ
        println("DEBUG: NFC <- ${response.toHexString()}")
        response
      }
      // Gọi hàm thực thi chung
      executeCommand(nfcTransceiver, call, result)
    } catch (e: Exception) {
      result.error("COMMUNICATION_ERROR", "Lỗi giao tiếp với thẻ: ${e.message}", null)
    } finally {
      try {
        if (isoDep.isConnected) isoDep.close()
      } catch (_: IOException) {}
      cleanup()
    }
  }
  /**
   * Hàm thực thi chung, nhận vào một hàm giao vận và xử lý logic.
   */
  private fun executeCommand(transceiver: (ByteArray) -> ByteArray, call: MethodCall, result: Result) {
    when (call.method) {
      "generateSignature" -> handleGenerateSignature(transceiver, call, result)
      "getRsaPublicKey" -> handleGetRsaPublicKey(transceiver, call, result)
      "getCertificate" -> handleGetCertificate(transceiver, call, result)
      "signPdf" -> handleSignPdf(transceiver, call, result)
      else -> result.notImplemented()
    }
  }

  private fun handleGenerateSignature(transceiver: (ByteArray) -> ByteArray, call: MethodCall, result: Result) {
    try {
      val appletID = call.argument<String>("appletID")!!
      val pin = call.argument<String>("pin")!!
      val dataToSign = call.argument<ByteArray>("dataToSign")!!
      val keyIndex = call.argument<Int>("keyIndex")!!

      // --- Select Applet ---
      val selectResponse = transceiver(createSelectAppletCommand(hexStringToByteArray(appletID)))
      if (!isSuccess(selectResponse)) {
        result.error("APPLET_NOT_SELECTED", "Không thể chọn Applet.", getStatusDetails(selectResponse))
        return
      }

      // --- Verify PIN ---
      val verifyResponse = transceiver(createVerifyPinCommand(pin))
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
      var response = transceiver(signatureApdu)
      var (sw1, sw2) = getStatusWords(response)

      val signatureDataStream = ByteArrayOutputStream()

      // 2. Lấy block dữ liệu đầu tiên (nếu có)
      if (response.size > 2) {
        signatureDataStream.write(response, 0, response.size - 2)
      }

      // 3. Bắt đầu vòng lặp GET RESPONSE nếu thẻ yêu cầu (sw1 = 0x61)
      while (sw1 == 0x61) {
        val getResponseCommand = byteArrayOf(0x00, 0xC0.toByte(), 0x00, 0x00, sw2.toByte())
        response = transceiver(getResponseCommand)

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
  private fun handleGetRsaPublicKey(transceiver: (ByteArray) -> ByteArray, call: MethodCall, result: Result) {
    try {
      val appletID = call.argument<String>("appletID")!!
      val keyRole = call.argument<String>("keyRole")!!

      // Bước 1: Chọn Applet
      val selectResponse = transceiver(createSelectAppletCommand(hexStringToByteArray(appletID)))
      if (!isSuccess(selectResponse)) {
        result.error("APPLET_NOT_SELECTED", "Không thể chọn Applet.", getStatusDetails(selectResponse))
        return
      }

      // Bước 2: Gửi lệnh lấy khóa công khai
      val getPubKeyApdu = createGetRsaPublicKeyCommand(keyRole)
      val pubKeyResponse = transceiver(getPubKeyApdu)

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
  private fun handleGetCertificate(transceiver: (ByteArray) -> ByteArray, call: MethodCall, result: Result) {
    try {
      val appletID = call.argument<String>("appletID")!!
      val keyRole = call.argument<String>("keyRole")!!
      // Bước 1: Chọn Applet
      val selectResponse = transceiver(createSelectAppletCommand(hexStringToByteArray(appletID)))
      if (!isSuccess(selectResponse)) {
        result.error("APPLET_NOT_SELECTED", "Không thể chọn Applet.", getStatusDetails(selectResponse))
        return
      }
      // BƯỚC 2: CHỌN DỮ LIỆU CERTIFICATE (Select Data)
      val selectCertResponse = transceiver(createSelectCertificateCommand(keyRole))
      if (!isSuccess(selectCertResponse)) {
        result.error("OPERATION_NOT_SUPPORTED", "Không thể chọn dữ liệu Certificate trên thẻ.", getStatusDetails(selectCertResponse))
        return
      }
      // Bước 3: Gửi lệnh lấy certificate
      val getCertApdu = createGetCertificateCommand()
      // Dùng transceiveAndGetResponse vì certificate có thể rất lớn
      val certResponse = transceiver(getCertApdu)

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
  private fun createSelectCertificateCommand(keyRole: String): ByteArray {
    // Lệnh SELECT DATA theo đúng code C# bạn cung cấp.
    // Data: 60 04 5C 02 7F 21
    //val data = byteArrayOf(0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21)
    val data = when (keyRole) {
      "sig" -> byteArrayOf(0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21)
      "dec" -> byteArrayOf(0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21)
      "aut" -> byteArrayOf(0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21)
      "sm" -> byteArrayOf(0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21)
      else -> throw IllegalArgumentException("Vai trò khóa không hợp lệ: $keyRole")
    }
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

  // --- HÀM XỬ LÝ KÝ PDF ĐÃ CẬP NHẬT CHO ITEXT 7 ---
  private fun handleSignPdf(transceiver: (ByteArray) -> ByteArray, call: MethodCall, result: Result) {
    val pdfBytes = call.argument<ByteArray>("pdfBytes")!!
    val appletID = call.argument<String>("appletID")!!
    val pin = call.argument<String>("pin")!!
    val keyIndex = call.argument<Int>("keyIndex")!!
    val reason = call.argument<String>("reason")!!
    val location = call.argument<String>("location")!!
    val pdfHashBytes = call.argument<ByteArray>("pdfHashBytes")!!

    // Nhận các tham số chữ ký
    val signatureConfig = call.argument<Map<String, Any>>("signatureConfig")
    val x = (signatureConfig?.get("x") as? Double)?.toFloat() ?: 36f
    val y = (signatureConfig?.get("y") as? Double)?.toFloat() ?: 700f
    val width = (signatureConfig?.get("width") as? Double)?.toFloat() ?: 200f
    val height = (signatureConfig?.get("height") as? Double)?.toFloat() ?: 50f
    val signatureImageWidth = (signatureConfig?.get("signatureImageWidth") as? Double)?.toFloat() ?: 50f
    val signatureImageHeight = (signatureConfig?.get("signatureImageHeight") as? Double)?.toFloat() ?: 50f
    val pageNumber = signatureConfig?.get("pageNumber") as? Int ?: 1
    val signatureImageBytes = signatureConfig?.get("signatureImage") as? ByteArray
    val contact = signatureConfig?.get("contact") as? String
    val signerName = signatureConfig?.get("signerName") as? String
    val signDateString = signatureConfig?.get("signDate") as? String
    var signDate = ""
    if (signDateString != null) {
      try {
        // Tạo một parser để đọc chuỗi ISO 8601 mà Dart gửi qua
        // Định dạng "yyyy-MM-dd'T'HH:mm:ss.SSS" khớp với đầu ra của toIso8601String()
        val isoParser = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS", java.util.Locale.getDefault())
        // Parse chuỗi thành một đối tượng Date
        val dateObject = isoParser.parse(signDateString)

        // Bây giờ, tạo một formatter để định dạng đối tượng Date đó theo ý bạn
        val displayFormatter = java.text.SimpleDateFormat("dd/MM/yyyy HH:mm:ss", java.util.Locale.getDefault())
        // Format và lấy ra chuỗi cuối cùng
        signDate = displayFormatter.format(dateObject)

      } catch (e: Exception) {
        // Nếu có lỗi, dùng lại chuỗi gốc hoặc một giá trị mặc định
        signDate = signDateString
        println("DEBUG: Lỗi khi phân tích ngày tháng: ${e.message}")
      }
    }
    try {
      Security.addProvider(BouncyCastleProvider())
      // --- Bước 1: Chọn Applet và Xác thực PIN ---
      val selectResponse = transceiver(createSelectAppletCommand(hexStringToByteArray(appletID)))
      if (!isSuccess(selectResponse)) {
        result.error("APPLET_NOT_SELECTED", "Không thể chọn Applet.", getStatusDetails(selectResponse))
        return
      }
      println("DEBUG: Verifying PIN before signing...")
      val verifyResponse = transceiver(createVerifyPinCommand(pin))
      if (!isSuccess(verifyResponse)) {
        result.error("AUTH_ERROR", "Xác thực PIN thất bại.", getStatusDetails(verifyResponse))
        return
      }
      println("DEBUG: PIN verification successful")

      // --- Bước 2: Lấy Certificate từ thẻ ---
      val keyRole = "sig" // Mặc định lấy certificate cho khóa ký
      val selectCertResponse = transceiver(createSelectCertificateCommand(keyRole))
      if (!isSuccess(selectCertResponse)) {
        result.error("OPERATION_NOT_SUPPORTED", "Không thể chọn dữ liệu Certificate trên thẻ.", getStatusDetails(selectCertResponse))
        return
      }

      // Bước lấy certificate
      val certResponse = transceiver(createGetCertificateCommand())
      if (!isSuccess(certResponse)) {
        result.error("OPERATION_NOT_SUPPORTED", "Không thể lấy certificate.", getStatusDetails(certResponse))
        return
      }
      val certificateBytes = getData(certResponse)

      // KIỂM TRA CERTIFICATE CÓ RỖNG KHÔNG
      if (certificateBytes.isEmpty()) {
        result.error("EMPTY_CERTIFICATE", "Certificate nhận được từ thẻ là rỗng.", null)
        return
      }

      val certFactory = CertificateFactory.getInstance("X.509")
      val certificate = parseCertificateSimple(certificateBytes)
      //certFactory.generateCertificate(ByteArrayInputStream(certificateBytes))
      if (certificate != null) {
        //println("DEBUG: Certificate parsed successfully!")
        println("DEBUG: Subject: ${certificate.subjectDN}")
        println("DEBUG: Issuer: ${certificate.issuerDN}")
        //return certificate
      }
      else {
        println("DEBUG: Certificate NULL!")
      }
      val certificateChain = arrayOf<Certificate>(certificate as Certificate)

      // --- Bước 3: Chuẩn bị ký với iText 7 ---
      val reader = PdfReader(ByteArrayInputStream(pdfBytes))
      val signedPdfStream = ByteArrayOutputStream()

      // Sử dụng StampingProperties cho iText 7
      val stampingProperties = StampingProperties()
      //.useAppendMode()
      val signer = PdfSigner(reader, signedPdfStream, stampingProperties)

      val pageRect = com.itextpdf.kernel.geom.Rectangle(x, y, width, height)
      val appearance = signer.signatureAppearance

      appearance
        .setReason(reason)
        .setLocation(location)
        .setPageRect(pageRect)
        .setPageNumber(pageNumber)
        .setReuseAppearance(false)

      // THÊM THÔNG TIN LIÊN HỆ VÀ TÊN NGƯỜI KÝ NẾU CÓ
      contact?.let { appearance.setContact(it) }
      // Lấy layer 2 (lớp văn bản) từ appearance
      val n2 = appearance.getLayer2()
      val canvas = com.itextpdf.kernel.pdf.canvas.PdfCanvas(n2, signer.document)

      // Load các file font .ttf từ thư mục assets
      val fontBytesRegular = loadFontFromAssets("fonts/Helvetica.ttf")
      val fontBytesBold = loadFontFromAssets("fonts/Helvetica-Bold.ttf")

      // Tạo đối tượng PdfFont từ dữ liệu byte và chỉ định encoding là IDENTITY_H (cho Unicode)
      // và chiến lược là PREFER_EMBEDDED (để nhúng font vào file)
      val font = com.itextpdf.kernel.font.PdfFontFactory.createFont(
        fontBytesRegular,
        com.itextpdf.io.font.PdfEncodings.IDENTITY_H,
        com.itextpdf.kernel.font.PdfFontFactory.EmbeddingStrategy.PREFER_EMBEDDED
      )
      val fontBold = com.itextpdf.kernel.font.PdfFontFactory.createFont(
        fontBytesBold,
        com.itextpdf.io.font.PdfEncodings.IDENTITY_H,
        com.itextpdf.kernel.font.PdfFontFactory.EmbeddingStrategy.PREFER_EMBEDDED
      )
      // =======================================================================

      val rect = appearance.pageRect
      val padding = 5f
      var textX = padding
      var textBlockWidth = rect.width - padding * 2

      // THÊM ẢNH CHỮ KÝ NẾU CÓ
      if (signatureImageBytes != null) {
        try {
          //println("DEBUG: Setting signature image, size: ${signatureImageBytes.size} bytes")
          val imageData = com.itextpdf.io.image.ImageDataFactory.create(signatureImageBytes)
          appearance.setSignatureGraphic(imageData)
          // Lấy layer 0 (lớp nền)
          val n0 = appearance.getLayer0()
          val canvas0 = com.itextpdf.kernel.pdf.canvas.PdfCanvas(n0, signer.document)

          // Thiết lập cách hiển thị: GRAPHIC (chỉ ảnh), GRAPHIC_AND_DESCRIPTION (ảnh + mô tả)
          appearance.renderingMode = com.itextpdf.signatures.PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION
          val imgHeight = signatureImageHeight
          val scale = imgHeight / imageData.height
          val imgWidth = signatureImageWidth // imageData.width * scale

          val imgX = padding
          val imgY = (rect.height - imgHeight) / 2f // Căn giữa theo chiều dọc
          canvas0.addImageWithTransformationMatrix(imageData, imgWidth, 0f, 0f, imgHeight, imgX, imgY)
          canvas0.release()
          // Dịch chuyển vị trí bắt đầu và thu hẹp chiều rộng của khối văn bản
          textX += imgWidth + padding
          textBlockWidth -= (imgWidth + padding)
        } catch (e: Exception) {
          println("DEBUG: Failed to set signature image: ${e.message}")
          appearance.renderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION
        }
      }
      else {
        appearance.renderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION
      }

      // Bắt đầu vẽ văn bản
      canvas.beginText()
        .setFontAndSize(fontBold, 9f) // Tên người ký in đậm, cỡ 9
        .moveText(textX.toDouble(), (rect.height - 12.0).toDouble())
        .showText(signerName)
        .endText() // Kết thúc vẽ tên

      canvas.beginText()
        .setFontAndSize(font, 7f) // Các thông tin khác cỡ 7
        .moveText(textX.toDouble(), (rect.height - 24).toDouble())
        .showText("Ngày: ${signDate}")
        .endText() // Kết thúc vẽ các thông tin còn lại
      canvas.beginText()
        .setFontAndSize(font, 7f) // Các thông tin khác cỡ 7
        .moveText(textX.toDouble(), (rect.height - 36).toDouble())
        .showText("Email: $contact")
        .endText()
      canvas.beginText()
        .setFontAndSize(font, 7f) // Các thông tin khác cỡ 7
        .moveText(textX.toDouble(), (rect.height - 48).toDouble())
        .showText("Location: $location")
        .endText()

      canvas.release() // Hoàn tất việc vẽ trên canvas
      // Implementation IExternalSignature cho iText 7
      val externalSignature = object : IExternalSignature {
        override fun getHashAlgorithm(): String = "SHA-256"

        override fun getEncryptionAlgorithm(): String = "RSA"

        override fun sign(message: ByteArray): ByteArray {
          val hash = pdfHashBytes
          //extractHashManually(message)
          println("DEBUG: Starting sign process, message length: ${hash.size}")

          // Tạo DigestInfo cho SHA-256
          //val digestInfo = createSha256DigestInfo(message)
          //println("DEBUG: DigestInfo created, length: ${hash.size}")

          // Ký dữ liệu trên thẻ
          val signResponse = transceiver(createComputeSignatureCommand(hash, keyIndex))
          if (!isSuccess(signResponse)) {
            val (sw1, sw2) = getStatusWords(signResponse)
            throw GeneralSecurityException("Ký trên thẻ thất bại. Mã SW: ${sw1.toString(16)}${sw2.toString(16)}")
          }

          val signatureBytes = getData(signResponse)
          println("DEBUG: Signature received, length: ${signatureBytes.size}")

          return signatureBytes
        }
      }

      // --- Bước 4: Thực hiện ký ---
      println("DEBUG: Starting PDF signing process...")
      try {
        signer.signDetached(
          BouncyCastleDigest(),
          externalSignature,
          certificateChain,
          null,
          null,
          null,
          0,
          PdfSigner.CryptoStandard.CMS
        )
        println("DEBUG: PDF signing completed successfully!")
      } catch (e: Exception) {
        println("DEBUG: Error during PDF signing: ${e.message}")
        e.printStackTrace()
        throw e
      }
      // --- Bước 5: Trả về file PDF đã ký ---
      result.success(signedPdfStream.toByteArray())

    } catch (e: Exception) {
      result.error("PDF_SIGN_ERROR", "Lỗi khi ký PDF: ${e.message}", null)
    }
  }

  private fun parseCertificateSimple(certificateBytes: ByteArray): X509Certificate? {
    return try {
      // Sử dụng Bouncy Castle implementation
      val certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider())
      certificateFactory.generateCertificate(ByteArrayInputStream(certificateBytes)) as X509Certificate
    } catch (e: Exception) {
      println("DEBUG: Bouncy Castle provider failed: ${e.message}")
      try {
        // Fallback to system provider
        val certificateFactory = CertificateFactory.getInstance("X.509")
        certificateFactory.generateCertificate(ByteArrayInputStream(certificateBytes)) as X509Certificate
      } catch (e2: Exception) {
        println("DEBUG: System provider also failed: ${e2.message}")
        null
      }
    }
  }

  // Fallback method nếu parse ASN.1 thất bại
  private fun extractHashManually(digestInfo: ByteArray): ByteArray {
    println("DEBUG: Trying manual hash extraction...")

    // Tìm vị trí của OCTET_STRING tag (0x04) và length
    for (i in 0 until digestInfo.size - 2) {
      if (digestInfo[i] == 0x04.toByte()) {
        val length = digestInfo[i + 1].toInt() and 0xFF

        // Kiểm tra xem length có hợp lý cho SHA-256 hash (32 bytes) không
        if (length == 32 && i + 2 + length <= digestInfo.size) {
          val hash = digestInfo.copyOfRange(i + 2, i + 2 + length)
          println("DEBUG: Manually extracted hash: ${hash.size} bytes")
          return createSha256DigestInfo(hash)
        }
      }
    }

    // Nếu không tìm thấy, trả về 32 bytes cuối (giả định là hash)
    //println("DEBUG: Using last 32 bytes as hash (fallback)")
    return createSha256DigestInfo(digestInfo.takeLast(32).toByteArray())
  }
  // Hàm helper tạo DigestInfo (chuyển từ Dart sang Kotlin)
  private fun createSha256DigestInfo(hash: ByteArray): ByteArray {
    // Kiểm tra kích thước hash
    if (hash.size != 32) {
      println("DEBUG: WARNING - Hash size is ${hash.size}, expected 32 for SHA-256")
    }

    // DigestInfo prefix cho SHA-256
    val sha256DigestInfoPrefix = byteArrayOf(
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86.toByte(),
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    )

    println("DEBUG: Creating DigestInfo - hash length: ${hash.size}")
    println("DEBUG: DigestInfo prefix length: ${sha256DigestInfoPrefix.size}")

    return sha256DigestInfoPrefix + hash
  }
  private fun debugUsbConnection() {
    val context = currentActivity?.applicationContext ?: return
    CoroutineScope(Dispatchers.IO).launch {
      var sCard: SCard? = null
      try {
        println("=== DEBUG USB CONNECTION ===")
        sCard = SCard.Companion.createSCard(context).blockingGet()
        println("1. SCard created: ${sCard != null}")

        val ctxResult = sCard.establishContext()
        println("2. establishContext: $ctxResult")

        val readers = ArrayList<String>()
        val listResult = sCard.listReaders(readers)
        println("3. listReaders: $listResult")
        println("4. Readers found: ${readers.size}")
        readers.forEachIndexed { i, reader -> println("   Reader $i: $reader") }

        if (readers.isNotEmpty()) {
          val connectResult = sCard.connect(readers[0])
          println("5. connect to ${readers[0]}: $connectResult")

          if (connectResult == RESULT.OK) {
            val atr = sCard.getAtr()
            println("6. ATR: ${atr?.toHexString()}")
            sCard.disconnect()
          }
        }
        println("=== END DEBUG ===")
      } catch (e: Exception) {
        println("=== DEBUG USB CONNECTION FAILED: ${e.message} ===")
        //e.printStackTrace()
      } finally {
        sCard?.close()
      }
    }
  }
  private fun loadFontFromAssets(path: String): ByteArray {
    val inputStream = applicationContext.assets.open(path)
    return inputStream.readBytes()
  }
}