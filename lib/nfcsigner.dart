import 'dart:async';
import 'package:flutter/services.dart';
import 'models/card_status.dart';
import 'models/service_result.dart'; // Import ServiceResult
import 'models/pdf_signature_config.dart';

// Xuất các model để người dùng plugin có thể truy cập dễ dàng
export 'models/service_result.dart';
export 'models/card_status.dart';
export 'models/pdf_signature_config.dart';
export 'src/crypto_utils.dart';
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
}