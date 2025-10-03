#include "nfcsigner_plugin.h"

// This must be included before many other Windows headers.
#include <windows.h>

// For getPlatformVersion; remove unless needed for your plugin implementation.
#include <VersionHelpers.h>

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <winscard.h>
#include <memory>
#include <sstream>

namespace nfcsigner {

// Helper function to convert hex string to byte vector
    std::vector<uint8_t> HexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (unsigned int i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
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

    std::vector<uint8_t> CreateGetCertificateCommand() {
        return { 0x00, 0xCA, 0x7F, 0x21, 0x00 };
    }
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
    }
    else {
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
            std::vector<uint8_t> data;
            if (keyRole == "sig") data = { 0xB6, 0x00 };
            else if (keyRole == "dec") data = { 0xB8, 0x00 };
            else if (keyRole == "aut") data = { 0xA4, 0x00 };
            else if (keyRole == "sm") data = { 0xA6, 0x00 };
            else throw std::runtime_error("Invalid key role.");

            std::vector<uint8_t> select_cmd = { 0x00, 0xA4, 0x04, 0x00, (uint8_t)HexToBytes(appletID).size() };
            // Gọi HexToBytes một lần, lưu vào biến `appletID_bytes`
            auto appletID_bytes = HexToBytes(appletID);
            // Dùng begin() và end() từ cùng một biến
            select_cmd.insert(select_cmd.end(), appletID_bytes.begin(), appletID_bytes.end());
            //select_cmd.insert(select_cmd.end(), HexToBytes(appletID).begin(), HexToBytes(appletID).end());
            select_cmd.push_back(0x00);

            std::vector<uint8_t> get_key_cmd = { 0x00, 0x47, 0x81, 0x00, (uint8_t)data.size() };
            get_key_cmd.insert(get_key_cmd.end(), data.begin(), data.end());
            get_key_cmd.push_back(0x00);

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
}  // namespace nfcsigner
