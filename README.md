# nfcsigner

[![pub version](https://img.shields.io/pub/v/nfcsigner.svg)](https://pub.dev/packages/nfcsigner)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Một plugin Flutter để giao tiếp với thẻ thông minh BCard, hỗ trợ ký số, lấy khóa công khai và certificate qua NFC trên Android, iOS và Windows.

## ✨ Tính năng

* Tạo chữ ký số từ dữ liệu đã được băm (`DigestInfo`).
* Lấy khóa công khai RSA.
* Đọc Certificate của chủ thẻ.
* Xử lý tự động các phản hồi APDU gồm nhiều phần (`GET RESPONSE`).
* API đơn giản, dễ sử dụng với các `enum` và lớp `ServiceResult` chi tiết.

## 🚀 Bắt đầu

Plugin này yêu cầu thiết bị phải có phần cứng NFC và được bật.

## ⚙️ Cài đặt

Thêm dependency này vào file `pubspec.yaml` của dự án Flutter của bạn:

```yaml
dependencies:
  nfcsigner: ^0.0.1 # Thay bằng phiên bản mới nhất trên pub.dev
```
Hoặc get package qua github:
```yaml
dependencies:  
  nfcsigner:
    git:
      url: https://github.com/your-username/nfcsigner.git
      ref: main # Hoặc một branch/tag cụ thể
```
Sau đó, chạy `flutter pub get`.

## 🛠 Cấu hình Bắt buộc

Bạn **bắt buộc** phải thực hiện các bước cấu hình native sau cho từng nền tảng.

### Android

Thêm quyền sử dụng NFC vào file `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.NFC" />
```

### iOS

1.  **Mở dự án iOS bằng Xcode:** Mở file `ios/Runner.xcworkspace`.
2.  **Thêm Capability:**
    * Đi đến tab `Signing & Capabilities`.
    * Nhấn `+ Capability`.
    * Tìm và thêm `Near Field Communication Tag Reading`.
3.  **Thêm mô tả quyền:** Mở file `ios/Runner/Info.plist` và thêm cặp key-value sau:
    ```xml
    <key>NFCReaderUsageDescription</key>
    <string>Sử dụng NFC để giao tiếp với thẻ thông minh của bạn.</string>
    ```

## 👨‍💻 Hướng dẫn sử dụng

Dưới đây là một ví dụ đầy đủ về cách sử dụng plugin.

```dart
import 'package:flutter/material.dart';
import 'package:nfcsigner/nfcsigner.dart';
import 'dart:convert';
import 'dart:typed_data';

// Hàm helper để băm dữ liệu và tạo DigestInfo (bạn nên có hàm này)
Uint8List createSha256DigestInfo(Uint8List dataToHash) {
  // ... (logic băm và tạo DigestInfo)
  return ...;
}


class MyCardScreen extends StatefulWidget {
  // ...
}

class _MyCardScreenState extends State<MyCardScreen> {
  String _status = "Sẵn sàng";
  
  Future<void> signData() async {
    setState(() { _status = "Đang chuẩn bị dữ liệu..."; });
    
    // 1. Chuẩn bị dữ liệu cần ký
    final originalMessage = Uint8List.fromList(utf8.encode('Dữ liệu cần ký'));
    final digestInfo = createSha256DigestInfo(originalMessage);

    setState(() { _status = "Vui lòng chạm thẻ..."; });

    // 2. Gọi hàm ký
    final result = await Nfcsigner.generateSignature(
      appletID: 'D27600012401', // AID của applet OpenPGP
      pin: '123456',
      dataToSign: digestInfo,
      keyIndex: 0,
    );
    
    // 3. Xử lý kết quả
    setState(() {
      if (result.isSuccess) {
        _status = "Ký thành công! Chữ ký: ${result.data}";
      } else {
        _status = "Lỗi: ${result.message} (Mã thẻ: ${result.sw1?.toRadixString(16)}${result.sw2?.toRadixString(16)})";
      }
    });
  }

  Future<void> getPublicKey() async {
    setState(() { _status = "Vui lòng chạm thẻ..."; });
    
    final result = await Nfcsigner.getRsaPublicKey(
      appletID: 'D27600012401',
      keyRole: KeyRole.signature,
    );

    setState(() {
      if (result.isSuccess) {
        _status = "Lấy khóa công khai thành công!";
        // Xử lý result.data (là một Uint8List)
      } else {
        _status = "Lỗi: ${result.message}";
      }
    });
  }

  // ... (Build method với các nút bấm gọi các hàm trên)
}
```

## 📚 API Chi tiết

### Lớp chính
* `Nfcsigner`: Lớp tĩnh chứa tất cả các phương thức.

### Các phương thức
* `Future<ServiceResult<Uint8List>> generateSignature(...)`
* `Future<ServiceResult<Uint8List>> getRsaPublicKey(...)`
* `Future<ServiceResult<Uint8List>> getCertificate(...)`

### Các `enum` và `Model`
* `KeyRole`: `signature`, `decryption`, `authentication`, `secureMessaging`.
* `CardStatus`: `ok`, `communicationError`, `authError`, và nhiều trạng thái lỗi chi tiết khác.
* `ServiceResult<T>`: Lớp chứa kết quả trả về, bao gồm `data`, `status`, `message`, `sw1`, `sw2`.

## 🐛 Báo lỗi và Đóng góp

Vui lòng tạo một issue trên kho [GitHub repository](https://github.com/bmctech.vn/nfcsigner/issues) để báo lỗi hoặc đề xuất tính năng mới.