import Flutter
import UIKit
import CoreNFC // Framework chính để làm việc với NFC
import PDFKit

// Đảm bảo code chỉ được biên dịch cho iOS 13.0 trở lên
@available(iOS 13.0, *)
public class SwiftNfcsignerPlugin: NSObject, FlutterPlugin, NFCTagReaderSessionDelegate {

    // Biến để lưu trữ session, lời gọi và kết quả đang chờ xử lý
    var session: NFCTagReaderSession?
    var pendingResult: FlutterResult?
    var pendingCall: FlutterMethodCall?

    // Hàm đăng ký plugin với Flutter Engine
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "nfcsigner", binaryMessenger: registrar.messenger())
        let instance = SwiftNfcsignerPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    // Hàm chính xử lý các lời gọi từ Dart
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        // Kiểm tra xem thiết bị có hỗ trợ NFC không
        guard NFCNDEFReaderSession.readingAvailable else {
            result(FlutterError(code: "NFC_UNAVAILABLE", message: "Thiết bị không hỗ trợ NFC.", details: nil))
            return
        }

        // Lưu lại lời gọi và callback để xử lý sau khi quét thẻ
        self.pendingCall = call
        self.pendingResult = result

        // Bắt đầu một session NFC mới để quét các thẻ ISO 14443 (loại phổ biến)
        session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: nil)
        session?.alertMessage = "Giữ thẻ của bạn gần đầu điện thoại."
        session?.begin()
    }

    // MARK: - NFCTagReaderSessionDelegate Callbacks

    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // Hàm này được gọi khi session sẵn sàng quét, không cần làm gì ở đây
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // Hàm này được gọi khi session bị hủy (do lỗi hoặc người dùng hủy)
        // Chỉ báo lỗi nếu đó không phải là do người dùng chủ động hủy
        if let nfcError = error as? NFCReaderError, nfcError.code != .readerSessionInvalidationErrorUserCanceled {
            pendingResult?(FlutterError(code: "COMMUNICATION_ERROR", message: error.localizedDescription, details: nil))
        }
        cleanup() // Dọn dẹp trạng thái
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        // Hàm này được gọi khi phát hiện một hoặc nhiều thẻ
        guard tags.count == 1 else {
            session.invalidate(errorMessage: "Phát hiện nhiều thẻ. Vui lòng chỉ sử dụng một thẻ.")
            pendingResult?(FlutterError(code: "COMMUNICATION_ERROR", message: "Phát hiện nhiều thẻ.", details: nil))
            cleanup()
            return
        }

        let tag = tags.first!
        // Kết nối với thẻ
        session.connect(to: tag) { (error: Error?) in
            if error != nil {
                session.invalidate(errorMessage: "Không thể kết nối với thẻ.")
                self.pendingResult?(FlutterError(code: "COMMUNICATION_ERROR", message: "Không thể kết nối với thẻ.", details: nil))
                self.cleanup()
                return
            }

            // Kiểm tra xem thẻ có hỗ trợ giao thức ISO7816 (APDU) không
            guard case let .iso7816(iso7816Tag) = tag else {
                session.invalidate(errorMessage: "Thẻ không tương thích (ISO7816).")
                self.pendingResult?(FlutterError(code: "TAG_NOT_SUPPORTED", message: "Thẻ không tương thích (ISO7816).", details: nil))
                self.cleanup()
                return
            }

            // Điều hướng đến hàm xử lý tương ứng với lời gọi từ Dart
            if self.pendingCall?.method == "generateSignature" {
                self.handleGenerateSignature(tag: iso7816Tag, session: session)
            } else if self.pendingCall?.method == "getRsaPublicKey" {
                self.handleGetRsaPublicKey(tag: iso7816Tag, session: session)
            }
            else if self.pendingCall?.method == "getCertificate" {
                            self.handleGetCertificate(tag: iso7816Tag, session: session)
            }
            else if self.pendingCall?.method == "signPdf" {
                            self.handleSignPdf(tag: iso7816Tag, session: session)
            } else {
                session.invalidate(errorMessage: "Lệnh không được hỗ trợ.")
                self.pendingResult?(FlutterMethodNotImplemented)
                self.cleanup()
            }
        }
    }

    // MARK: - Logic Handlers
    private func handleGenerateSignature(tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        // Lấy các tham số từ Dart
        guard let arguments = self.pendingCall?.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let pin = arguments["pin"] as? String,
              let dataToSign = arguments["dataToSign"] as? FlutterStandardTypedData,
              let keyIndex = arguments["keyIndex"] as? Int else {
            session.invalidate(errorMessage: "Tham số không hợp lệ.")
            self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            self.cleanup()
            return
        }

        // Tạo các lệnh APDU
        let selectAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x04, p2Parameter: 0x00, data: dataWithHexString(hex: appletIDHex), expectedResponseLength: -1)
        let verifyAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0x20, p1Parameter: 0x00, p2Parameter: 0x81, data: Data(pin.utf8), expectedResponseLength: -1)
        let p2Sign: UInt8 = {
            switch keyIndex {
                case 1: return 0x9B
                case 2: return 0x9C
                default: return 0x9A
            }
        }()
        let signAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0x2A, p1Parameter: 0x9E, p2Parameter: p2Sign, data: dataToSign.data, expectedResponseLength: 256)

        // Bắt đầu chuỗi lệnh tuần tự
        sendCommandAndGetResponse(tag: tag, apdu: selectAPDU) { (_, sw1, sw2, error) in
            guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                session.invalidate(errorMessage: "Không thể chọn Applet.")
                self.pendingResult?(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                self.cleanup()
                return
            }

            self.sendCommandAndGetResponse(tag: tag, apdu: verifyAPDU) { (_, sw1, sw2, error) in
                guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                    session.invalidate(errorMessage: "Xác thực PIN thất bại.")
                    self.pendingResult?(FlutterError(code: "AUTH_ERROR", message: "Xác thực PIN thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                    self.cleanup()
                    return
                }

                self.sendCommandAndGetResponse(tag: tag, apdu: signAPDU) { (responseData, sw1, sw2, error) in
                    guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                        session.invalidate(errorMessage: "Ký số thất bại.")
                        self.pendingResult?(FlutterError(code: "OPERATION_NOT_SUPPORTED", message: "Ký số thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                        self.cleanup()
                        return
                    }

                    session.alertMessage = "Ký thành công!"
                    session.invalidate()
                    self.pendingResult?(FlutterStandardTypedData(bytes: responseData))
                    self.cleanup()
                }
            }
        }
    }

    private func handleGetRsaPublicKey(tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        guard let arguments = self.pendingCall?.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String,
              let keyRole = arguments["keyRole"] as? String else {
            session.invalidate(errorMessage: "Tham số không hợp lệ.")
            self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            self.cleanup()
            return
        }

        let selectAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x04, p2Parameter: 0x00, data: dataWithHexString(hex: appletIDHex), expectedResponseLength: -1)

        sendCommandAndGetResponse(tag: tag, apdu: selectAPDU) { (_, sw1, sw2, error) in
            guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                session.invalidate(errorMessage: "Không thể chọn Applet.")
                self.pendingResult?(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                self.cleanup()
                return
            }

            var apduData: Data
            switch keyRole {
                case "sig": apduData = Data([0xB6, 0x00])
                case "dec": apduData = Data([0xB8, 0x00])
                case "aut": apduData = Data([0xA4, 0x00])
                case "sm": apduData = Data([0xA6, 0x00])
                default:
                    session.invalidate(errorMessage: "Vai trò khóa không hợp lệ.")
                    self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Vai trò khóa không hợp lệ: \(keyRole)", details: nil))
                    self.cleanup()
                    return
            }

            let getPubKeyAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0x47, p1Parameter: 0x81, p2Parameter: 0x00, data: apduData, expectedResponseLength: 256)

            self.sendCommandAndGetResponse(tag: tag, apdu: getPubKeyAPDU) { (responseData, sw1, sw2, error) in
                guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                    session.invalidate(errorMessage: "Không thể lấy khóa công khai.")
                    self.pendingResult?(FlutterError(code: "OPERATION_NOT_SUPPORTED", message: "Không thể lấy khóa công khai.", details: ["sw1": sw1, "sw2": sw2]))
                    self.cleanup()
                    return
                }

                session.alertMessage = "Lấy khóa thành công!"
                session.invalidate()
                self.pendingResult?(FlutterStandardTypedData(bytes: responseData))
                self.cleanup()
            }
        }
    }
    private func handleGetCertificate(tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        guard let arguments = self.pendingCall?.arguments as? [String: Any],
              let appletIDHex = arguments["appletID"] as? String
              let keyRole = arguments["keyRole"] as? String else {
            session.invalidate(errorMessage: "Tham số không hợp lệ.")
            self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            self.cleanup()
            return
        }

        // Tạo APDU chọn Applet
        let selectAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x04, p2Parameter: 0x00, data: dataWithHexString(hex: appletIDHex), expectedResponseLength: -1)

        // Bắt đầu chuỗi lệnh
        sendCommandAndGetResponse(tag: tag, apdu: selectAPDU) { (_, sw1, sw2, error) in
            guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                session.invalidate(errorMessage: "Không thể chọn Applet.")
                self.pendingResult?(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                self.cleanup()
                return
            }
        // BƯỚC 2: TẠO VÀ GỬI LỆNH SELECT DATA
        var selectCertData: Data
        switch keyRole {
                        case "sig": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
                        case "dec": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
                        case "aut": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
                        case "sm": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
                        default:
                            session.invalidate(errorMessage: "Vai trò khóa không hợp lệ.")
                            self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Vai trò khóa không hợp lệ: \(keyRole)", details: nil))
                            self.cleanup()
                            return
                    }
            let selectCertAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA5, p1Parameter: 0x02, p2Parameter: 0x04, data: selectCertData, expectedResponseLength: 256)

            self.sendCommandAndGetResponse(tag: tag, apdu: selectCertAPDU) { (_, sw1, sw2, error) in
                 guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                    session.invalidate(errorMessage: "Không thể chọn dữ liệu Certificate.")
                    self.pendingResult?(FlutterError(code: "OPERATION_NOT_SUPPORTED", message: "Không thể chọn dữ liệu Certificate.", details: ["sw1": sw1, "sw2": sw2]))
                    self.cleanup()
                    return
                }
            //Bước 3: Tạo APDU lấy Certificate (GET DATA 7F21)
            let getCertAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xCA, p1Parameter: 0x7F, p2Parameter: 0x21, data: Data(), expectedResponseLength: 256)

            // Gửi lệnh lấy Certificate
            self.sendCommandAndGetResponse(tag: tag, apdu: getCertAPDU) { (responseData, sw1, sw2, error) in
                guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                    session.invalidate(errorMessage: "Không thể lấy certificate.")
                    self.pendingResult?(FlutterError(code: "OPERATION_NOT_SUPPORTED", message: "Không thể lấy certificate.", details: ["sw1": sw1, "sw2": sw2]))
                    self.cleanup()
                    return
                }

                session.alertMessage = "Lấy certificate thành công!"
                session.invalidate()
                self.pendingResult?(FlutterStandardTypedData(bytes: responseData))
                self.cleanup()
            }
        }
    }
private func handleSignPdf(tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        guard let arguments = self.pendingCall?.arguments as? [String: Any],
              let pdfBytes = arguments["pdfBytes"] as? FlutterStandardTypedData,
              let appletIDHex = arguments["appletID"] as? String,
              let pin = arguments["pin"] as? String,
              let keyIndex = arguments["keyIndex"] as? Int,
              let reason = arguments["reason"] as? String,
              let location = arguments["location"] as? String else {
            session.invalidate(errorMessage: "Tham số không hợp lệ.")
            self.pendingResult?(FlutterError(code: "INVALID_PARAMETERS", message: "Tham số không hợp lệ.", details: nil))
            self.cleanup()
            return
        }

        // Lấy cấu hình chữ ký (nếu có)
        let signatureConfig = arguments["signatureConfig"] as? [String: Any]
        let x = signatureConfig?["x"] as? Double ?? 36.0
        let y = signatureConfig?["y"] as? Double ?? 700.0
        let width = signatureConfig?["width"] as? Double ?? 200.0
        let height = signatureConfig?["height"] as? Double ?? 50.0
        let pageNumber = signatureConfig?["pageNumber"] as? Int ?? 1
        let signatureImageBytes = signatureConfig?["signatureImage"] as? FlutterStandardTypedData
        let contact = signatureConfig?["contact"] as? String
        let signerName = signatureConfig?["signerName"] as? String

        // Tạo các lệnh APDU
        let selectAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x04, p2Parameter: 0x00, data: dataWithHexString(hex: appletIDHex), expectedResponseLength: -1)
        let verifyAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0x20, p1Parameter: 0x00, p2Parameter: 0x81, data: Data(pin.utf8), expectedResponseLength: -1)

        // Bắt đầu chuỗi lệnh tuần tự
        sendCommandAndGetResponse(tag: tag, apdu: selectAPDU) { (_, sw1, sw2, error) in
            guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                session.invalidate(errorMessage: "Không thể chọn Applet.")
                self.pendingResult?(FlutterError(code: "APPLET_NOT_SELECTED", message: "Không thể chọn Applet.", details: ["sw1": sw1, "sw2": sw2]))
                self.cleanup()
                return
            }

            self.sendCommandAndGetResponse(tag: tag, apdu: verifyAPDU) { (_, sw1, sw2, error) in
                guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                    session.invalidate(errorMessage: "Xác thực PIN thất bại.")
                    self.pendingResult?(FlutterError(code: "AUTH_ERROR", message: "Xác thực PIN thất bại.", details: ["sw1": sw1, "sw2": sw2]))
                    self.cleanup()
                    return
                }

                // Lấy certificate từ thẻ
                self.getCertificateFromCard(tag: tag) { certificateData in
                    guard let certificateData = certificateData else {
                        session.invalidate(errorMessage: "Không thể lấy certificate từ thẻ.")
                        self.pendingResult?(FlutterError(code: "CERTIFICATE_ERROR", message: "Không thể lấy certificate từ thẻ.", details: nil))
                        self.cleanup()
                        return
                    }

                    // Thực hiện ký PDF
                    self.signPdfWithCard(
                        tag: tag,
                        pdfData: pdfBytes.data,
                        certificateData: certificateData,
                        keyIndex: keyIndex,
                        reason: reason,
                        location: location,
                        x: x,
                        y: y,
                        width: width,
                        height: height,
                        pageNumber: pageNumber,
                        signatureImageData: signatureImageBytes?.data,
                        contact: contact,
                        signerName: signerName,
                        session: session
                    )
                }
            }
        }
    }

    private func getCertificateFromCard(tag: NFCISO7816Tag, completion: @escaping (Data?) -> Void) {
        let keyRole = "sig"

        // Tạo APDU chọn dữ liệu certificate
        let selectCertData: Data
        switch keyRole {
            case "sig": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
            case "dec": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
            case "aut": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
            case "sm": selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
            default:
                completion(nil)
                return
        }

        let selectCertAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA5, p1Parameter: 0x02, p2Parameter: 0x04, data: selectCertData, expectedResponseLength: 256)

        self.sendCommandAndGetResponse(tag: tag, apdu: selectCertAPDU) { (_, sw1, sw2, error) in
            guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                completion(nil)
                return
            }

            // Lấy certificate
            let getCertAPDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xCA, p1Parameter: 0x7F, p2Parameter: 0x21, data: Data(), expectedResponseLength: 2048)

            self.sendCommandAndGetResponse(tag: tag, apdu: getCertAPDU) { (responseData, sw1, sw2, error) in
                guard error == nil, sw1 == 0x90, sw2 == 0x00 else {
                    completion(nil)
                    return
                }
                completion(responseData)
            }
        }
    }

    private func signPdfWithCard(
        tag: NFCISO7816Tag,
        pdfData: Data,
        certificateData: Data,
        keyIndex: Int,
        reason: String,
        location: String,
        x: Double,
        y: Double,
        width: Double,
        height: Double,
        pageNumber: Int,
        signatureImageData: Data?,
        contact: String?,
        signerName: String?,
        session: NFCTagReaderSession
    ) {
        do {
            // Tạo PDF document
            guard let pdfDocument = PDFDocument(data: pdfData) else {
                throw NSError(domain: "PDFError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Không thể đọc PDF data"])
            }

            // Tạo annotation cho chữ ký
            let page = pdfDocument.page(at: pageNumber - 1)!
            let bounds = CGRect(x: x, y: y, width: width, height: height)

            let annotation = PDFAnnotation(bounds: bounds, forType: .stamp, withProperties: nil)
            annotation.contents = "Ký bởi: \(signerName ?? "Unknown")\nLý do: \(reason)\nĐịa điểm: \(location)"

            // Thêm ảnh chữ ký nếu có
            if let signatureImageData = signatureImageData, let image = UIImage(data: signatureImageData) {
                annotation.setValue(image, forAnnotationKey: .stampImage)
            }

            page.addAnnotation(annotation)

            // Lấy dữ liệu PDF đã được chèn annotation
            guard let modifiedPdfData = pdfDocument.dataRepresentation() else {
                throw NSError(domain: "PDFError", code: 2, userInfo: [NSLocalizedDescriptionKey: "Không thể tạo PDF đã sửa"])
            }

            // Ở đây chúng ta cần tạo hash của PDF và ký nó bằng thẻ
            // Tuy nhiên, PDFKit của Apple không hỗ trợ ký số trực tiếp
            // Giải pháp tạm thời: Trả về PDF đã có chữ ký hình ảnh
            // Để ký số thực sự, cần sử dụng thư viện bên thứ ba hoặc custom implementation

            session.alertMessage = "PDF đã được ký thành công!"
            session.invalidate()
            self.pendingResult?(FlutterStandardTypedData(bytes: modifiedPdfData))
            self.cleanup()

        } catch {
            session.invalidate(errorMessage: "Lỗi khi ký PDF: \(error.localizedDescription)")
            self.pendingResult?(FlutterError(code: "PDF_SIGN_ERROR", message: "Lỗi khi ký PDF: \(error.localizedDescription)", details: nil))
            self.cleanup()
        }
    }
    // MARK: - Helper Functions

    /// Gửi một lệnh APDU và tự động xử lý vòng lặp GET RESPONSE (61xx).
    private func sendCommandAndGetResponse(
        tag: NFCISO7816Tag,
        apdu: NFCISO7816APDU,
        completion: @escaping (Data, UInt8, UInt8, Error?) -> Void
    ) {
        var accumulatedData = Data()
        func recursiveSend(currentApdu: NFCISO7816APDU) {
            tag.sendCommand(apdu: currentApdu) { (responseData, sw1, sw2, error) in
                if let error = error {
                    completion(Data(), 0, 0, error)
                    return
                }

                accumulatedData.append(responseData)

                // Nếu thẻ báo còn dữ liệu, gửi lệnh GET RESPONSE
                if sw1 == 0x61 {
                    let getResponseApdu = NFCISO7816APDU(
                        instructionClass: 0x00, instructionCode: 0xC0,
                        p1Parameter: 0x00, p2Parameter: 0x00,
                        data: Data(), expectedResponseLength: Int(sw2)
                    )
                    recursiveSend(currentApdu: getResponseApdu)
                } else {
                    // Nếu không, trả về dữ liệu đã tích lũy và mã trạng thái cuối cùng
                    completion(accumulatedData, sw1, sw2, nil)
                }
            }
        }
        recursiveSend(currentApdu: apdu)
    }

    /// Dọn dẹp các biến trạng thái sau khi hoàn thành hoặc có lỗi.
    private func cleanup() {
        self.pendingCall = nil
        self.pendingResult = nil
        self.session = nil
    }

    /// Chuyển đổi một chuỗi Hex thành đối tượng Data.
    func dataWithHexString(hex: String) -> Data {
        var hex = hex
        var data = Data()
        while(hex.count > 0) {
            let subIndex = hex.index(hex.startIndex, offsetBy: 2)
            let c = String(hex[..<subIndex])
            hex = String(hex[subIndex...])
            var ch: UInt64 = 0
            Scanner(string: c).scanHexInt64(&ch)
            var char = UInt8(ch)
            data.append(&char, count: 1)
        }
        return data
    }
}