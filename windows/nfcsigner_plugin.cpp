#define NOMINMAX  // Ngăn chặn định nghĩa min và max từ windows.h

#include "nfcsigner_plugin.h"

#include <windows.h>
// For getPlatformVersion; remove unless needed for your plugin implementation.
#include <VersionHelpers.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <winscard.h>
#include <memory>
#include <sstream>
#include <iostream>
#include <podofo/auxiliary/Version.h>

#ifdef HAVE_PODOFO
// Include PoDoFo và OpenSSL
#include <podofo/podofo.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
using namespace PoDoFo;
#endif

namespace nfcsigner {

    // Helper function to convert hex string to byte vector
    std::vector<uint8_t> HexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        if (hex.length() % 2 != 0) {
            throw std::runtime_error("Hex string must have even length");
        }

        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            char* end;
            uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), &end, 16));
            if (*end != '\0') {
                throw std::runtime_error("Invalid hex character");
            }
            bytes.push_back(byte);
        }
        return bytes;
    }
    std::vector<uint8_t> CreateSelectAppletCommand(const std::string& appletID) {
        auto appletID_bytes = HexToBytes(appletID);
        std::vector<uint8_t> cmd = { 0x00, 0xA4, 0x04, 0x00, (uint8_t)appletID_bytes.size() };
        cmd.insert(cmd.end(), appletID_bytes.begin(), appletID_bytes.end());
        cmd.push_back(0x00);
        return cmd;
    }

    std::vector<uint8_t> CreateVerifyPinCommand(const std::string& pin) {
        std::vector<uint8_t> pin_bytes(pin.begin(), pin.end());
        std::vector<uint8_t> cmd = { 0x00, 0x20, 0x00, 0x81, (uint8_t)pin_bytes.size() };
        cmd.insert(cmd.end(), pin_bytes.begin(), pin_bytes.end());
        return cmd;
    }

    std::vector<uint8_t> CreateComputeSignatureCommand(const std::vector<uint8_t>& data, int keyIndex) {
        uint8_t p1 = 0x9E;
        uint8_t p2;
        switch (keyIndex) {
            case 1: p2 = 0x9B; break;
            case 2: p2 = 0x9C; break;
            default: p2 = 0x9A; break;
        }
        std::vector<uint8_t> cmd = { 0x00, 0x2A, p1, p2, (uint8_t)data.size() };
        cmd.insert(cmd.end(), data.begin(), data.end());
        cmd.push_back(0x00);
        return cmd;
    }

    std::vector<uint8_t> CreateSelectCertificateCommand() {
        std::vector<uint8_t> data = { 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21 };
        std::vector<uint8_t> cmd = { 0x00, 0xA5, 0x02, 0x04, (uint8_t)data.size() };
        cmd.insert(cmd.end(), data.begin(), data.end());
        cmd.push_back(0x00);
        return cmd;
    }
    std::vector<uint8_t> CreateGetRsaPublicKeyCommand(const std::string& keyRole) {
        std::vector<uint8_t> data;
        if (keyRole == "sig") data = { 0xB6, 0x00 };
        else if (keyRole == "dec") data = { 0xB8, 0x00 };
        else if (keyRole == "aut") data = { 0xA4, 0x00 };
        else if (keyRole == "sm") data = { 0xA6, 0x00 };
        else throw std::runtime_error("Invalid key role.");

        std::vector<uint8_t> cmd = { 0x00, 0x47, 0x81, 0x00, (uint8_t)data.size() };
        cmd.insert(cmd.end(), data.begin(), data.end());
        cmd.push_back(0x00);
        return cmd;
    }
    std::vector<uint8_t> CreateGetCertificateCommand() {
        return { 0x00, 0xCA, 0x7F, 0x21, 0x00 };
    }
#ifdef HAVE_PODOFO
// Helper function to create a detached PKCS#7/CMS signature container
/*
std::vector<uint8_t> CreateCMSContainer(
    const std::vector<uint8_t>& dataToSign,
    const std::vector<uint8_t>& certificate_der,
    const std::vector<uint8_t>& signature_raw)
{
    // Load certificate
    const unsigned char* p_cert = certificate_der.data();
    X509* cert = d2i_X509(NULL, &p_cert, certificate_der.size());
    if (!cert) {
        throw std::runtime_error("Failed to parse X509 certificate from DER.");
    }

    // Create a BIO for the data to be signed (will be hashed)
    BIO* data_bio = BIO_new_mem_buf(dataToSign.data(), dataToSign.size());
    if (!data_bio) {
        X509_free(cert);
        throw std::runtime_error("Failed to create BIO for data.");
    }

    // Create CMS SignedData structure
    int flags = CMS_BINARY | CMS_NOSMIMECAP | CMS_DETACHED | CMS_PARTIAL;
    CMS_ContentInfo* cms = CMS_sign(NULL, NULL, NULL, data_bio, flags);
    if (!cms) {
        BIO_free(data_bio);
        X509_free(cert);
        throw std::runtime_error("Failed to create CMS_ContentInfo.");
    }

    // Add signer info
    CMS_SignerInfo* si = CMS_add1_signer(cms, cert, NULL, EVP_sha256(), flags);
    if (!si) {
        CMS_ContentInfo_free(cms);
        BIO_free(data_bio);
        X509_free(cert);
        throw std::runtime_error("Failed to add signer to CMS.");
    }

    // Finalize the structure to get the SignedAttributes digest
    if (CMS_final(cms, data_bio, NULL, flags) <= 0) {
        CMS_ContentInfo_free(cms);
        BIO_free(data_bio);
        X509_free(cert);
        throw std::runtime_error("Failed to finalize CMS structure.");
    }

    // SỬA: Thay thế CMS_SignerInfo_set1_signature bằng cách sử dụng CMS_SignerInfo_sign
    // Set the raw signature value bằng cách sử dụng hàm thay thế
    ASN1_OCTET_STRING* sig_octet = ASN1_OCTET_STRING_new();
    if (!sig_octet) {
        CMS_ContentInfo_free(cms);
        BIO_free(data_bio);
        X509_free(cert);
        throw std::runtime_error("Failed to create ASN1_OCTET_STRING for signature.");
    }

    if (!ASN1_OCTET_STRING_set(sig_octet, signature_raw.data(), signature_raw.size())) {
        ASN1_OCTET_STRING_free(sig_octet);
        CMS_ContentInfo_free(cms);
        BIO_free(data_bio);
        X509_free(cert);
        throw std::runtime_error("Failed to set signature value in ASN1_OCTET_STRING.");
    }

    // Sử dụng CMS_SignerInfo_set0_signature để thiết lập chữ ký
    CMS_SignerInfo_set0_signature(si, sig_octet);

    // Convert CMS to DER format
    BIO* out_bio = BIO_new(BIO_s_mem());
    if (!i2d_CMS_bio(out_bio, cms)) {
        BIO_free(out_bio);
        CMS_ContentInfo_free(cms);
        BIO_free(data_bio);
        X509_free(cert);
        throw std::runtime_error("Failed to serialize CMS to DER.");
    }

    // Extract DER data into vector
    char* der_ptr;
    long der_len = BIO_get_mem_data(out_bio, &der_ptr);
    std::vector<uint8_t> cms_der(der_ptr, der_ptr + der_len);

    // Cleanup
    BIO_free(out_bio);
    CMS_ContentInfo_free(cms);
    BIO_free(data_bio);
    X509_free(cert);

    return cms_der;
}*/
#endif
// static
void NfcsignerPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {
  auto channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(), "nfcsigner",
          &flutter::StandardMethodCodec::GetInstance());

  auto plugin = std::make_unique<NfcsignerPlugin>();

  channel->SetMethodCallHandler(
      [plugin_pointer = plugin.get()](const auto &call, auto result) {
        plugin_pointer->HandleMethodCall(call, std::move(result));
      });

  registrar->AddPlugin(std::move(plugin));
}

NfcsignerPlugin::NfcsignerPlugin() {}

NfcsignerPlugin::~NfcsignerPlugin() {}

void NfcsignerPlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue> &method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
    const auto* args = std::get_if<flutter::EncodableMap>(method_call.arguments());

    if (method_call.method_name().compare("generateSignature") == 0) {
        HandleSign(args, std::move(result));
    } else if (method_call.method_name().compare("getRsaPublicKey") == 0) {
        HandleGetPublicKey(args, std::move(result));
    } else if (method_call.method_name().compare("getCertificate") == 0) {
        HandleGetCertificate(args, std::move(result));
    } else if (method_call.method_name().compare("signPdf") == 0) {
        HandleSignPdf(args, std::move(result));
    } else {
    result->NotImplemented();
  }
}
// Wrapper for an entire card operation
    template<typename Func>
    void CardOperation(Func&& operation, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        SCARDCONTEXT hContext = 0;
        SCARDHANDLE hCard = 0;
        DWORD dwActiveProtocol = 0;

        try {
            LONG lReturn = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hContext);
            if (lReturn != SCARD_S_SUCCESS) throw std::runtime_error("SCardEstablishContext failed.");

            DWORD dwReaders = SCARD_AUTOALLOCATE;
            LPTSTR mszReaders = NULL;
            lReturn = SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &dwReaders);
            if (lReturn != SCARD_S_SUCCESS || mszReaders == NULL || mszReaders[0] == '\0') {
                if (mszReaders) SCardFreeMemory(hContext, mszReaders);
                throw std::runtime_error("No card reader found.");
            }

            lReturn = SCardConnect(hContext, mszReaders, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
            SCardFreeMemory(hContext, mszReaders);
            if (lReturn != SCARD_S_SUCCESS) throw std::runtime_error("SCardConnect failed. Is a card inserted?");

            operation(hCard);

        } catch (const std::runtime_error& e) {
            result->Error("PC/SC_ERROR", e.what());
        }

        if (hCard) SCardDisconnect(hCard, SCARD_LEAVE_CARD);
        if (hContext) SCardReleaseContext(hContext);
    }

// APDU Transmit function with GET RESPONSE handling
    std::vector<uint8_t> NfcsignerPlugin::TransmitAndGetResponse(SCARDHANDLE hCard, const std::vector<uint8_t>& command) {

        //const SCARD_IO_REQUEST* pci;

        std::vector<uint8_t> response_buffer(260, 0); // 256 data + 2 status words
        DWORD response_len = 260;

        // Sử dụng SCARD_PCI_T1 nếu protocol là T1, ngược lại là T0
        // Trong ví dụ này, ta giả định T0 hoặc để Windows tự chọn. Dùng SCARD_PCI_T0 là phổ biến.
        LONG lReturn = SCardTransmit(hCard, SCARD_PCI_T1, command.data(), (DWORD)command.size(), NULL, response_buffer.data(), &response_len);
        if (lReturn != SCARD_S_SUCCESS) {
            throw std::runtime_error("Lỗi SCardTransmit.");
        }
        response_buffer.resize(response_len);

        if (response_len >= 2 && response_buffer[response_len - 2] == 0x61) {
            std::vector<uint8_t> full_response_data;
            if (response_len > 2) {
                full_response_data.insert(full_response_data.end(), response_buffer.begin(), response_buffer.end() - 2);
            }

            while (response_buffer[response_len - 2] == 0x61) {
                uint8_t le = response_buffer[response_len - 1];
                std::vector<uint8_t> get_response_cmd = { 0x00, 0xC0, 0x00, 0x00, le };

                response_len = 260;
                response_buffer.assign(260, 0);

                lReturn = SCardTransmit(hCard, SCARD_PCI_T1, get_response_cmd.data(), (DWORD)get_response_cmd.size(), NULL, response_buffer.data(), &response_len);
                if (lReturn != SCARD_S_SUCCESS) {
                    throw std::runtime_error("Lỗi SCardTransmit khi GET RESPONSE.");
                }
                response_buffer.resize(response_len);

                if (response_len > 2) {
                    full_response_data.insert(full_response_data.end(), response_buffer.begin(), response_buffer.end() - 2);
                }
            }
            full_response_data.push_back(response_buffer[response_len - 2]);
            full_response_data.push_back(response_buffer[response_len - 1]);
            return full_response_data;
        }

        return response_buffer;
    }
    void NfcsignerPlugin::HandleSign(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        auto p_result = result.release();
        CardOperation([this, args, p_result](SCARDHANDLE hCard) {
            // Lấy tham số
            auto appletID = std::get<std::string>(args->at(flutter::EncodableValue("appletID")));
            auto pin = std::get<std::string>(args->at(flutter::EncodableValue("pin")));
            auto dataToSign = std::get<std::vector<uint8_t>>(args->at(flutter::EncodableValue("dataToSign")));
            auto keyIndex = std::get<int>(args->at(flutter::EncodableValue("keyIndex")));

            // Chuỗi lệnh APDU
            auto select_resp = TransmitAndGetResponse(hCard, CreateSelectAppletCommand(appletID));
            if (select_resp.back() != 0x00 || select_resp[select_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Chọn Applet thất bại.");
            }

            auto verify_resp = TransmitAndGetResponse(hCard, CreateVerifyPinCommand(pin));
            if (verify_resp.back() != 0x00 || verify_resp[verify_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Xác thực PIN thất bại.");
            }

            auto sign_resp = TransmitAndGetResponse(hCard, CreateComputeSignatureCommand(dataToSign, keyIndex));
            if (sign_resp.back() != 0x00 || sign_resp[sign_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Ký số thất bại.");
            }

            std::vector<uint8_t> signature_data(sign_resp.begin(), sign_resp.end() - 2);
            p_result->Success(flutter::EncodableValue(signature_data));

        }, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>(p_result));
    }
    // Handler for getRsaPublicKey
    void NfcsignerPlugin::HandleGetPublicKey(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        auto p_result = result.release();
        CardOperation([this, args, p_result](SCARDHANDLE hCard) {
            // Extract args
            auto appletID = std::get<std::string>(args->at(flutter::EncodableValue("appletID")));
            auto keyRole = std::get<std::string>(args->at(flutter::EncodableValue("keyRole")));

            // APDU command definitions
            auto select_cmd = CreateSelectAppletCommand(appletID);
            auto get_key_cmd = CreateGetRsaPublicKeyCommand(keyRole);

            // Transmit sequence
            auto select_resp = TransmitAndGetResponse(hCard, select_cmd);
            if (select_resp.size() < 2 || select_resp[select_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Select Applet failed.");
            }

            auto key_resp = TransmitAndGetResponse(hCard, get_key_cmd);
            if (key_resp.size() < 2 || key_resp[key_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Get Public Key failed.");
            }

            // Return success
            std::vector<uint8_t> key_data(key_resp.begin(), key_resp.end() - 2);
            p_result->Success(flutter::EncodableValue(key_data));

        }, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>(p_result));
    }
    void NfcsignerPlugin::HandleGetCertificate(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        auto p_result = result.release();
        CardOperation([this, args, p_result](SCARDHANDLE hCard) {
            // Lấy tham số
            auto appletID = std::get<std::string>(args->at(flutter::EncodableValue("appletID")));

            // Chuỗi lệnh APDU
            auto select_resp = TransmitAndGetResponse(hCard, CreateSelectAppletCommand(appletID));
            if (select_resp.back() != 0x00 || select_resp[select_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Chọn Applet thất bại.");
            }

            auto select_cert_resp = TransmitAndGetResponse(hCard, CreateSelectCertificateCommand());
            if (select_cert_resp.back() != 0x00 || select_cert_resp[select_cert_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Chọn dữ liệu Certificate thất bại.");
            }

            auto cert_resp = TransmitAndGetResponse(hCard, CreateGetCertificateCommand());
            if (cert_resp.back() != 0x00 || cert_resp[cert_resp.size() - 2] != 0x90) {
                throw std::runtime_error("Lấy Certificate thất bại.");
            }

            std::vector<uint8_t> cert_data(cert_resp.begin(), cert_resp.end() - 2);
            p_result->Success(flutter::EncodableValue(cert_data));

        }, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>(p_result));
    }
    void NfcsignerPlugin::HandleSignPdf(const flutter::EncodableMap* args, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {

        auto p_result = result.release();

        CardOperation([this, args, p_result](SCARDHANDLE hCard) {
            try {
                // 1. Lấy tất cả tham số từ Flutter
                std::cout << "=== Starting PDF Signing Process ===" << std::endl;
                std::cout << "PoDoFo version: " << PODOFO_VERSION_STRING << std::endl;
                // 1. Lấy và validate các tham số
                if (!args) {
                    throw std::runtime_error("Arguments are null");
                }

                auto pdfBytes = std::get<std::vector<uint8_t>>(args->at(flutter::EncodableValue("pdfBytes")));
                auto appletID = std::get<std::string>(args->at(flutter::EncodableValue("appletID")));
                auto pin = std::get<std::string>(args->at(flutter::EncodableValue("pin")));
                auto keyIndex = std::get<int>(args->at(flutter::EncodableValue("keyIndex")));
                auto reason = std::get<std::string>(args->at(flutter::EncodableValue("reason")));
                auto location = std::get<std::string>(args->at(flutter::EncodableValue("location")));

                // Lấy DigestInfo bạn đã cung cấp
                auto data_to_send_to_card = std::get<std::vector<uint8_t>>(args->at(flutter::EncodableValue("pdfHashBytes")));
                if (data_to_send_to_card.empty()) {
                    throw std::runtime_error("pdfHashBytes cannot be empty.");
                }
                double x = 50.0, y = 700.0, width = 200.0, height = 50.0;
                int pageNumber = 1;

                auto config_iter = args->find(flutter::EncodableValue("signatureConfig"));
                if (config_iter != args->end()) {
                    auto signatureConfig = std::get<flutter::EncodableMap>(config_iter->second);

                    auto x_iter = signatureConfig.find(flutter::EncodableValue("x"));
                    auto y_iter = signatureConfig.find(flutter::EncodableValue("y"));
                    auto width_iter = signatureConfig.find(flutter::EncodableValue("width"));
                    auto height_iter = signatureConfig.find(flutter::EncodableValue("height"));
                    auto page_iter = signatureConfig.find(flutter::EncodableValue("pageNumber"));

                    if (x_iter != signatureConfig.end()) x = std::get<double>(x_iter->second);
                    if (y_iter != signatureConfig.end()) y = std::get<double>(y_iter->second);
                    if (width_iter != signatureConfig.end()) width = std::get<double>(width_iter->second);
                    if (height_iter != signatureConfig.end()) height = std::get<double>(height_iter->second);
                    if (page_iter != signatureConfig.end()) pageNumber = std::get<int>(page_iter->second);
                }

                // 2. Giao tiếp với thẻ để lấy Certificate
                // Việc ký sẽ được thực hiện sau bên trong callback của PoDoFo
                std::cout << "Selecting applet..." << std::endl;
                auto select_resp = TransmitAndGetResponse(hCard, CreateSelectAppletCommand(appletID));
                if (select_resp.size() < 2 || select_resp[select_resp.size() - 2] != 0x90) throw std::runtime_error("Select Applet failed.");

                std::cout << "Verifying PIN..." << std::endl;
                auto verify_resp = TransmitAndGetResponse(hCard, CreateVerifyPinCommand(pin));
                if (verify_resp.size() < 2 || verify_resp[verify_resp.size() - 2] != 0x90) throw std::runtime_error("Verify PIN failed.");

                std::cout << "Selecting certificate..." << std::endl;
                auto select_cert_resp = TransmitAndGetResponse(hCard, CreateSelectCertificateCommand());
                if (select_cert_resp.size() < 2 || select_cert_resp[select_cert_resp.size() - 2] != 0x90) throw std::runtime_error("Select Certificate data object failed.");

                auto cert_resp = TransmitAndGetResponse(hCard, CreateGetCertificateCommand());
                if (cert_resp.size() < 2 || cert_resp[cert_resp.size() - 2] != 0x90) throw std::runtime_error("Get Certificate failed.");
                std::vector<uint8_t> certificate_data(cert_resp.begin(), cert_resp.end() - 2);
                if (certificate_data.empty()) throw std::runtime_error("Certificate from card is empty.");

                // 3. Chuẩn bị tài liệu PDF và trường chữ ký bằng PoDoFo API mới
                std::cout << "Loading PDF document..." << std::endl;
// Tạm thời thay thế phần load PDF bằng việc tạo PDF đơn giản
#ifdef TEST_SIMPLE_PDF
                PoDoFo::PdfMemDocument document;
                auto& page = document.GetPages().CreatePage(PoDoFo::PageSize::A4);
                auto& font = document.GetFonts().GetStandard14Font(PoDoFo::PdfStandard14FontType::Helvetica);

                // Thêm một dòng text đơn giản
                auto& canvas = page.GetCanvas();
                canvas.DrawText("Test Document for Signing", 100, 700, font);
#else
                // Code load PDF hiện tại
                PoDoFo::PdfMemDocument document;
                document.LoadFromBuffer(PoDoFo::bufferview(
                        reinterpret_cast<const char*>(pdfBytes.data()), pdfBytes.size()
                ));
#endif
                std::cout << "PDF loaded successfully. Page count: " << document.GetPages().GetCount() << std::endl;

                PoDoFo::PdfPage& page = document.GetPages().GetPageAt(pageNumber > 0 ? pageNumber - 1 : 0);

                // API mới để tạo field chữ ký
                std::cout << "=== API for Signature ===" << std::endl;
                auto& signatureField = page.CreateField<PoDoFo::PdfSignature>(
                        "Signature", PoDoFo::Rect(x, y, width, height)
                );
                std::cout << "=== Starting set some signature parameters===" << std::endl;
               // signatureField.SetSignatureReason(PoDoFo::PdfString(reason));
               // signatureField.SetSignatureLocation(PoDoFo::PdfString(location));

                // 4. Cấu hình PdfSignerCms với callback để ký bằng thẻ
                std::cout << "=== Cấu hình PdfSignerCms với callback để ký bằng thẻ ===" << std::endl;
                PoDoFo::PdfSignerCmsParams params;

                // Đây là phần quan trọng nhất: định nghĩa hàm callback để ký
                // Hàm này sẽ được PoDoFo gọi khi nó đã chuẩn bị xong dữ liệu cần ký
                std::cout << "=== callback SigningService Calling ===" << std::endl;
                params.SigningService = [&](PoDoFo::bufferview hashToSign, bool dryrun, PoDoFo::charbuff& signedHash) {
                    // **LƯU Ý QUAN TRỌNG VỀ TÍNH HỢP LỆ CỦA CHỮ KÝ**
                    // PoDoFo cung cấp `hashToSign` - đây là dữ liệu THẬT SỰ cần được ký để chữ ký hợp lệ.
                    // Tuy nhiên, theo yêu cầu của bạn, chúng ta sẽ BỎ QUA `hashToSign` và sử dụng `data_to_send_to_card` (tức `pdfHashBytes` của bạn).
                    // Điều này sẽ làm cho chữ ký cuối cùng bị báo lỗi "Invalid Signature" khi xác thực.
                    std::cout << "=== Send Sign command to the Card ===" << std::endl;
                    auto sign_resp = TransmitAndGetResponse(hCard, CreateComputeSignatureCommand(data_to_send_to_card, keyIndex));
                    if (sign_resp.size() < 2 || sign_resp[sign_resp.size() - 2] != 0x90) {
                        throw std::runtime_error("Compute signature failed on card inside callback.");
                    }
                    std::cout << "=== Card Return Successfully ===" << std::endl;
                    std::vector<uint8_t> signature_raw(sign_resp.begin(), sign_resp.end() - 2);

                    // Cung cấp chữ ký thô lại cho PoDoFo
                    signedHash.assign(signature_raw.begin(), signature_raw.end());
                };

                // Tạo đối tượng signer
                PoDoFo::PdfSignerCms signer(
                        PoDoFo::bufferview(reinterpret_cast<const char*>(certificate_data.data()), certificate_data.size()),
                        params
                );

                // 5. Thực hiện ký - SỬ DỤNG PoDoFo::VectorStreamDevice có sẵn
                std::vector<char> buffer;
                PoDoFo::VectorStreamDevice outputDevice(buffer);
                PoDoFo::SignDocument(document, outputDevice, signer, signatureField);

                // 6. Lấy kết quả và trả về cho Flutter
                std::vector<uint8_t> signed_pdf_bytes(buffer.data(), buffer.data() + buffer.size());
                p_result->Success(flutter::EncodableValue(signed_pdf_bytes));
                std::cout << "=== PDF Signing Completed Successfully ===" << std::endl;
            } catch (const PoDoFo::PdfError& e) {
                std::string error_msg = std::string("PoDoFo Error: ") + e.what();
                std::cerr << error_msg << std::endl;
                p_result->Error("PODOFO_ERROR", error_msg);
            } catch (const std::exception& e) {
                std::string error_msg = std::string("Standard Exception: ") + e.what();
                std::cerr << error_msg << std::endl;
                p_result->Error("STD_EXCEPTION", error_msg);
            } catch (...) {
                std::string error_msg = "Unknown error occurred during PDF signing";
                std::cerr << error_msg << std::endl;
                p_result->Error("UNKNOWN_ERROR", error_msg);
            }
        }, std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>(p_result));
    }
}  // namespace nfcsigner
