import 'package:flutter/material.dart';
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:nfcsigner/nfcsigner.dart';
import 'package:nfcsigner/src/crypto_utils.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      home: HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  bool _isSigning = false;
  bool _isLoading = false;
  String _statusMessage = 'Sẵn sàng để ký số';
  String _signatureHex = '';
  ServiceResult? _lastResult;
  String _publicKeyHex = '';
  String _certificateHex = '';

  String _bytesToHexString(Uint8List bytes) {
    return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join('');
  }
/*
 * Phần giao tiếp dữ liệu Thẻ
 */
  Future<void> _handleSignData() async {
    setState(() {
      _isSigning = true;
      _signatureHex = '';
      _lastResult = null;
      _statusMessage = 'Đang chuẩn bị dữ liệu...';
    });

    final dataToSign = Uint8List.fromList(utf8.encode('Hello, Flutter!'));
    setState(() {
      _statusMessage = 'Đang băm dữ liệu (SHA-256)...';
    });
    // BƯỚC 1: Băm và tạo DigestInfo từ dữ liệu gốc
    final digestInfoToSend = createSha256DigestInfo(dataToSign);

    setState(() {
      _statusMessage = 'Đang chờ thẻ...';
    });
    // Gọi plugin và nhận về đối tượng ServiceResult
    final result = await Nfcsigner.generateSignature(
      appletID: 'D27600012401',
      pin: '123456',
      dataToSign: digestInfoToSend,
      keyIndex: 0
    );

    if (mounted) {
      setState(() {
        _isSigning = false;
        _lastResult = result; // Lưu lại kết quả để hiển thị chi tiết

        if (result.isSuccess && result.data != null) {
          _statusMessage = result.message;
          _signatureHex = _bytesToHexString(result.data as Uint8List);
        } else {
          // Xây dựng thông báo lỗi chi tiết
          String errorMessage = 'Lỗi: ${result.message}';
          if (result.sw1 != null && result.sw2 != null) {
            final swHex = '${result.sw1!.toRadixString(16)}${result.sw2!.toRadixString(16)}'.toUpperCase();
            errorMessage += ' (Mã lỗi: $swHex)';
          }
          _statusMessage = errorMessage;
        }
      });
    }
  }
  Future<void> _handleGetPublicKey() async {
    setState(() {
      _isLoading = true;
      _signatureHex = '';
      _publicKeyHex = '';
      _lastResult = null;
      _statusMessage = 'Đang chờ thẻ...';
    });

    final result = await Nfcsigner.getRsaPublicKey(
      appletID: 'D27600012401', // Thay bằng AID của bạn
      keyRole: KeyRole.sig, // Lấy khóa dùng để ký
    );

    if (mounted) {
      setState(() {
        _isLoading = false;
        _lastResult = result;
        if (result.isSuccess && result.data != null) {
          _statusMessage = 'Lấy khóa công khai thành công!';
          _publicKeyHex = _bytesToHexString(result.data as Uint8List);
        } else {
          // Xây dựng thông báo lỗi chi tiết
          String errorMessage = 'Lỗi: ${result.message}';
          if (result.sw1 != null) {
            final swHex = '${result.sw1!.toRadixString(16)}${result.sw2!.toRadixString(16)}'.toUpperCase();
            errorMessage += ' (Mã thẻ: $swHex)';
          }
          _statusMessage = errorMessage;
        }
      });
    }
  }
  // HÀM ĐỂ LẤY CERTIFICATE
  Future<void> _handleGetCertificate() async {
    setState(() {
      _isLoading = true;
      _signatureHex = '';
      _publicKeyHex = '';
      _certificateHex = '';
      _lastResult = null;
      _statusMessage = 'Đang chờ thẻ...';
    });

    final result = await Nfcsigner.getCertificate(
      appletID: 'D27600012401', // Applet ID
      keyRole: KeyRole.sig, // Lấy Ceftificate của Signature
    );

    if (mounted) {
      setState(() {
        _isLoading = false;
        _lastResult = result;
        if (result.isSuccess && result.data != null) {
          _statusMessage = 'Lấy certificate thành công!';
          _certificateHex = _bytesToHexString(result.data as Uint8List);
        } else {
          // Xây dựng thông báo lỗi chi tiết
          String errorMessage = 'Lỗi: ${result.message}';
          if (result.sw1 != null) {
            final swHex = '${result.sw1!.toRadixString(16)}${result.sw2!.toRadixString(16)}'.toUpperCase();
            errorMessage += ' (Mã thẻ: $swHex)';
          }
          _statusMessage = errorMessage;
        }
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Ví dụ Plugin Ký số'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[

              Text(
                _statusMessage,
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    color: _lastResult == null ? null : (_lastResult!.isSuccess ? Colors.green.shade800 : Colors.red.shade800)
                ),
              ),
              const SizedBox(height: 32),
              if (_isSigning)
                const Center(child: CircularProgressIndicator())
              else
                ElevatedButton(
                  onPressed: _handleSignData,
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                  child: const Text('Bắt đầu Ký'),
                ),
              const SizedBox(height: 12),
              ElevatedButton(
                onPressed: _handleGetPublicKey,
                style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.blueGrey,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                ),
                child: const Text('Lấy Khóa Công Khai RSA'),
              ),
              const SizedBox(height: 12),
              // NÚT BẤM MỚI
              ElevatedButton(
                onPressed: _handleGetCertificate,
                style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.teal,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                ),
                child: const Text('Lấy Certificate'),
              ),
              if (_signatureHex.isNotEmpty)
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Chữ ký (Hex):',
                      style: TextStyle(fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 8),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.grey.shade200,
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: SelectableText(
                        _signatureHex,
                        style: const TextStyle(fontFamily: 'monospace'),
                      ),
                    ),
                  ],
                ),
              if (_publicKeyHex.isNotEmpty)
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Khóa công khai (Hex):', style: TextStyle(fontWeight: FontWeight.bold)),
                    const SizedBox(height: 8),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(color: Colors.grey.shade200, borderRadius: BorderRadius.circular(8)),
                      child: SelectableText(_publicKeyHex, style: const TextStyle(fontFamily: 'monospace')),
                    ),
                  ],
                ),
              if (_certificateHex.isNotEmpty)
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Certificate (Hex):', style: TextStyle(fontWeight: FontWeight.bold)),
                    const SizedBox(height: 8),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(color: Colors.grey.shade200, borderRadius: BorderRadius.circular(8)),
                      child: SelectableText(_certificateHex, style: const TextStyle(fontFamily: 'monospace')),
                    ),
                  ],
                ),
            ],
          ),
        ),
      ),
    );
  }
}