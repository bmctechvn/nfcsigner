import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'models/card_status.dart';
import 'models/service_result.dart'; // Import ServiceResult
import 'models/pdf_signature_config.dart';
import 'models/xml_signature_config.dart';
import 'src/xml_signer.dart';

// Xuất các model để người dùng plugin có thể truy cập dễ dàng
export 'models/service_result.dart';
export 'models/card_status.dart';
export 'models/pdf_signature_config.dart';
export 'models/xml_signature_config.dart';
export 'src/crypto_utils.dart';
export 'src/xml_signer.dart';
/// Enum định nghĩa vai trò của khóa trên thẻ.
enum KeyRole {
  /// Khóa dùng để ký (Signature)
  sig,
  /// Khóa dùng để giải mã (Decryption)
  dec,
  /// Khóa dùng để xác thực (Authentication)
  aut,
  /// Khóa dùng cho Secure Messaging
  sm,
}
class Nfcsigner {
  static const MethodChannel _channel = MethodChannel('nfcsigner');

  /// Thực hiện chuỗi lệnh ký số hoàn chỉnh trên thẻ thông minh.
  ///
  /// Bao gồm các bước: Chọn Applet, Xác thực PIN, và Ký dữ liệu.
  /// Trả về một đối tượng [ServiceResult] chứa chữ ký hoặc thông tin lỗi chi tiết.
  static Future<ServiceResult<Uint8List>> generateSignature({
    required String appletID,
    required String pin,
    required Uint8List dataToSign,
    int keyIndex = 0,
  }) async {
    try {
      final Map<String, dynamic> arguments = {
        'appletID': appletID,
        'pin': pin,
        'dataToSign': dataToSign,
        'keyIndex': keyIndex,
      };

      // Gọi phương thức native
      final Uint8List? signature = await _channel.invokeMethod('generateSignature', arguments);

      // Nếu native trả về dữ liệu (không có exception), đó là thành công
      return ServiceResult.success(signature);

    } on PlatformException catch (e) {
      // Nếu native ném ra một exception, chuyển đổi nó thành một ServiceResult thất bại
      return ServiceResult.fromPlatformException(e);
    } catch (e) {
      // Bắt các lỗi không mong muốn khác
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: e.toString(),
      );
    }
  }
  /// Thực hiện chuỗi lệnh ký số XML hoàn chỉnh trên thẻ thông minh.
  ///
  /// Bao gồm các bước: Chọn Applet, Xác thực PIN, và Ký dữ liệu.
  /// Trả về một đối tượng [ServiceResult] chứa chữ ký hoặc thông tin lỗi chi tiết.
  ///
  static Future<ServiceResult<Map<String, Uint8List>>> generateXMLSignature({
    required String appletID,
    required String pin,
    required Uint8List dataToSign,
    int keyIndex = 0,
  }) async {
    try {
      if (kDebugMode) {
        print('🔍 [XML Single Session] Bắt đầu ký XML trong một session');
      }

      final Map<String, dynamic> arguments = {
        'appletID': appletID,
        'pin': pin,
        'dataToSign': dataToSign,
        'keyIndex': keyIndex,
      };

      final dynamic result = await _channel.invokeMethod('generateXMLSignature', arguments);

      if (kDebugMode) {
        print('🔍 [XML Single Session] Kiểu kết quả: ${result.runtimeType}');
      }

      Uint8List certificate;
      Uint8List signature;

      if (result is Uint8List) {
        if (kDebugMode) {
          print('🔍 [XML Single Session] Nhận Uint8List từ iOS');
        }
        // iOS trả về Uint8List chứa JSON
        final String jsonString = String.fromCharCodes(result);
        final Map<String, dynamic> resultMap = jsonDecode(jsonString);

        certificate = base64.decode(resultMap['certificate'] as String);
        signature = base64.decode(resultMap['signature'] as String);

      } else if (result is Map) {
        if (kDebugMode) {
          print('🔍 [XML Single Session] Nhận Map từ Android');
        }
        // Android trả về Map trực tiếp
        final Map<dynamic, dynamic> resultMap = result;

        // Xử lý cả hai trường hợp: String (base64) hoặc Uint8List
        if (resultMap['certificate'] is String) {
          certificate = base64.decode(resultMap['certificate'] as String);
        } else {
          throw Exception('Định dạng certificate không hợp lệ từ Android: ${resultMap['certificate']?.runtimeType}');
        }

        if (resultMap['signature'] is String) {
          signature = base64.decode(resultMap['signature'] as String);
        } else {
          throw Exception('Định dạng signature không hợp lệ từ Android: ${resultMap['signature']?.runtimeType}');
        }
      } else {
        throw Exception('Kiểu kết quả không được hỗ trợ: ${result.runtimeType}');
      }

      if (kDebugMode) {
        print('✅ [XML Single Session] Ký XML thành công');
        print(
            '✅ [XML Single Session] Certificate length: ${certificate.length}');
        print('✅ [XML Single Session] Signature length: ${signature.length}');
      }
      return ServiceResult.success({
        'certificate': certificate,
        'signature': signature,
      });

    } on PlatformException catch (e) {
      if (kDebugMode) {
        print('❌ [XML Single Session] PlatformException: ${e.message}');
      }
      return ServiceResult.fromPlatformException(e);
    } catch (e, stackTrace) {
      if (kDebugMode) {
        print('❌ [XML Single Session] Lỗi không mong muốn: $e');
        print('❌ [XML Single Session] Stack trace: $stackTrace');
      }
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: 'Lỗi ký XML: $e',
      );
    }
  }

  /// Lấy khóa công khai RSA từ thẻ dựa trên vai trò của khóa.

  static Future<ServiceResult<Uint8List>> getRsaPublicKey({
    required String appletID,
    required KeyRole keyRole,
  }) async {
    try {
      // Chuyển enum thành chuỗi mà lớp native mong đợi
      final String keyRoleString = keyRole.toString().split('.').last;

      final Map<String, dynamic> arguments = {
        'appletID': appletID,
        'keyRole': keyRoleString,
      };

      final Uint8List? publicKey = await _channel.invokeMethod('getRsaPublicKey', arguments);

      return ServiceResult.success(publicKey);

    } on PlatformException catch (e) {
      return ServiceResult.fromPlatformException(e);
    } catch (e) {
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: e.toString(),
      );
    }
  }
  /// Theo chuẩn BMC Card, đối tượng Certificate được lưu với tag `7F21`.
  static Future<ServiceResult<Uint8List>> getCertificate({
    required String appletID,
    required KeyRole keyRole,
  }) async {
    try {
      final String keyRoleString = keyRole.toString().split('.').last;

      final Map<String, dynamic> arguments = {
        'appletID': appletID,
        'keyRole': keyRoleString,
      };

      final Uint8List? certificate = await _channel.invokeMethod('getCertificate', arguments);

      return ServiceResult.success(certificate);

    } on PlatformException catch (e) {
      return ServiceResult.fromPlatformException(e);
    } catch (e) {
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: e.toString(),
      );
    }
  }

  /// Ký trực tiếp lên một file PDF bằng cách sử dụng logic native.
  ///
  /// [pdfBytes] là nội dung (dạng byte) của file PDF gốc.
  /// [pdfHashBytes] là DigestInfo SHA-256 của PDF (tùy chọn)
  /// Trả về một ServiceResult chứa nội dung (dạng byte) của file PDF đã được ký.
  static Future<ServiceResult<Uint8List>> signPdf({
    required Uint8List pdfBytes,
    required String appletID,
    required String pin,
    int keyIndex = 0,
    String reason = "Ký duyệt!",
    String location = "Hanoi",
    PdfSignatureConfig? signatureConfig,
    Uint8List? pdfHashBytes,
    int signatureLength = 512, // Hoặc 256 tùy vào khóa
  }) async {
    try {
      final Map<String, dynamic> arguments = {
        'pdfBytes': pdfBytes,
        'appletID': appletID,
        'pin': pin,
        'keyIndex': keyIndex,
        'reason': reason,
        'location': location,
        'signatureConfig': signatureConfig?.toMap(),
        'pdfHashBytes': pdfHashBytes,
        'signatureLength': 512, // Hoặc 256 tùy vào khóa
      };

      final dynamic result = await _channel.invokeMethod('signPdf', arguments);

      // Xử lý kết quả từ Windows (trả về Map) và Android/iOS (trả về Uint8List)
      if (result is Uint8List) {
        // Android/iOS: trả về PDF đã ký trực tiếp
        return ServiceResult.success(result);
      } else if (result is Map) {
        // Windows: trả về raw data, cần xử lý thêm
        // Hiện tại trên Windows chưa hỗ trợ ký PDF trực tiếp
        // Trả về PDF gốc như một fallback
        return ServiceResult.success(pdfBytes);
      } else {
        return ServiceResult.failure(
          status: CardStatus.unknownError,
          message: 'Định dạng kết quả không hợp lệ từ nền tảng',
        );
      }

    } on PlatformException catch (e) {
      return ServiceResult.fromPlatformException(e);
    } catch (e) {
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: e.toString(),
      );
    }
  }
  /// Ký số một tài liệu XML theo chuẩn XML-DSig (hoàn toàn trên Dart)
  ///
  /// [xmlContent] là nội dung XML cần ký
  /// [appletID] là ID của applet trên thẻ
  /// [pin] là mã PIN để xác thực
  /// [keyIndex] là chỉ số của khóa ký (mặc định 0)
  /// [signatureConfig] là cấu hình cho chữ ký XML
  /// Trả về một ServiceResult chứa nội dung XML đã được ký
  static Future<ServiceResult<String>> signXml({
    required String xmlContent,
    required String appletID,
    required String pin,
    int keyIndex = 0,
    XmlSignatureConfig? signatureConfig,
  }) async {
    try {

      // Tạo DigestInfo cho XML
      final digestInfo = XmlSigner.createDigestInfoForXml(
        xmlContent: xmlContent,
        config: signatureConfig ?? const XmlSignatureConfig(),
      );
      if (kDebugMode) {
        print("Digest: $digestInfo");
      }
      // Platform-specific implementation
      ServiceResult<Map<String, Uint8List>> resultData;
      if (Platform.isIOS || Platform.isAndroid) {
        // Ký DigestInfo bằng thẻ
        resultData = await generateXMLSignature(
          appletID: appletID,
          pin: pin,
          dataToSign: digestInfo,
          keyIndex: keyIndex,
        );

        if (!resultData.isSuccess) {
          return ServiceResult.failure(
            status: resultData.status,
            message: 'Lỗi ký số: ${resultData.message}',
          );
        }
      }
      else {
        if (kDebugMode) {
          print('🔍 [XML Signing] Sử dụng multiple sessions cho Android');
        }
        // Sử dụng multiple sessions approach cho Android
        final certificateResult = await getCertificate(
          appletID: appletID,
          keyRole: KeyRole.sig,
        );

        if (!certificateResult.isSuccess) {
          return ServiceResult.failure(
            status: certificateResult.status,
            message: 'Lỗi lấy certificate: ${certificateResult.message}',
          );
        }

        final signatureResult = await generateSignature(
          appletID: appletID,
          pin: pin,
          dataToSign: digestInfo,
          keyIndex: keyIndex,
        );

        if (!signatureResult.isSuccess) {
          return ServiceResult.failure(
            status: signatureResult.status,
            message: 'Lỗi ký số: ${signatureResult.message}',
          );
        }
        resultData = ServiceResult.success({
          'certificate': certificateResult.data!,
          'signature': signatureResult.data!,
        });
      }
      // Tạo XML đã ký
      final signedXml = XmlSigner.signXml(
        xmlContent: xmlContent,
        signatureBytes: resultData.data!['certificate']!,
        certificateBytes: resultData.data!['signature']!,
        config: signatureConfig ?? const XmlSignatureConfig(),
      );

      return ServiceResult.success(signedXml);

    } catch (e) {
      return ServiceResult.failure(
        status: CardStatus.unknownError,
        message: 'Lỗi ký XML: $e',
      );
    }
  }
}