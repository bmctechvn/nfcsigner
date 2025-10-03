import 'dart:typed_data';
import 'package:crypto/crypto.dart';

/// Tiền tố ASN.1 cho cấu trúc DigestInfo của SHA-256.
/// Đây là một giá trị không đổi.
/// SEQUENCE (30) + Length (21) +
///   SEQUENCE (30) + Length (0D) +
///     OBJECT IDENTIFIER (06) + Length (09) + OID for sha256 (60 86 48 01 65 03 04 02 01) +
///     NULL (05) + Length (00) +
///   OCTET STRING (04) + Length (20)
const _sha256DigestInfoPrefix = [
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
];

/// Băm dữ liệu bằng SHA-256 và đóng gói vào cấu trúc ASN.1 DigestInfo.
///
/// [dataToHash] là dữ liệu gốc cần được băm.
/// Trả về một `Uint8List` chứa toàn bộ cấu trúc DigestInfo, sẵn sàng để gửi đến thẻ ký.
Uint8List createSha256DigestInfo(Uint8List dataToHash) {
  // 1. Băm dữ liệu gốc bằng SHA-256
  final hash = sha256.convert(dataToHash).bytes;

  // 2. Nối tiền tố ASN.1 với kết quả băm để tạo thành DigestInfo
  final builder = BytesBuilder();
  builder.add(_sha256DigestInfoPrefix);
  builder.add(hash);

  return builder.toBytes();
}