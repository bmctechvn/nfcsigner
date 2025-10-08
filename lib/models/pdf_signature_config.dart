
import 'dart:typed_data';

class PdfSignatureConfig {
  final double x;
  final double y;
  final double width;
  final double height;
  final int pageNumber;
  final Uint8List? signatureImage;
  final String? contact;
  final String? signerName;

  const PdfSignatureConfig({
    this.x = 36.0,
    this.y = 700.0,
    this.width = 200.0,
    this.height = 50.0,
    this.pageNumber = 1,
    this.signatureImage,
    this.contact,
    this.signerName,
  });

  Map<String, dynamic> toMap() {
    return {
      'x': x,
      'y': y,
      'width': width,
      'height': height,
      'pageNumber': pageNumber,
      'signatureImage': signatureImage,
      'contact': contact,
      'signerName': signerName,
    };
  }

  static PdfSignatureConfig fromMap(Map<String, dynamic> map) {
    return PdfSignatureConfig(
      x: map['x']?.toDouble() ?? 36.0,
      y: map['y']?.toDouble() ?? 700.0,
      width: map['width']?.toDouble() ?? 200.0,
      height: map['height']?.toDouble() ?? 50.0,
      pageNumber: map['pageNumber'] ?? 1,
      signatureImage: map['signatureImage'],
      contact: map['contact'],
      signerName: map['signerName'],
    );
  }
}