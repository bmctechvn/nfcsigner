import Foundation
import CryptoTokenKit

/// Manager class for USB smart card operations using CryptoTokenKit
/// Requires iOS 16.0+ for CCID smart card reader support
@available(iOS 16.0, *)
class UsbCardManager: NSObject {
    
    // MARK: - Properties
    
    private var slotManager: TKSmartCardSlotManager?
    private var currentSlot: TKSmartCardSlot?
    private var currentCard: TKSmartCard?
    
    private let logger = UsbLogger()
    
    // MARK: - Initialization
    
    override init() {
        super.init()
        self.slotManager = TKSmartCardSlotManager.default
    }
    
    // MARK: - Public Methods
    
    /// Check if any USB smart card reader is connected
    func isReaderConnected() -> Bool {
        guard let slotManager = slotManager else {
            logger.debug("SlotManager is nil")
            return false
        }
        
        let slotNames = slotManager.slotNames
        logger.debug("Available slots: \(slotNames)")
        return !slotNames.isEmpty
    }
    
    /// Get list of connected reader names
    func getReaderNames() -> [String] {
        return slotManager?.slotNames ?? []
    }
    
    /// Connect to the first available smart card
    func connect(completion: @escaping (Bool, String?) -> Void) {
        guard let slotManager = slotManager else {
            completion(false, "SlotManager không khả dụng")
            return
        }
        
        let slotNames = slotManager.slotNames
        guard let firstSlotName = slotNames.first else {
            completion(false, "Không tìm thấy đầu đọc USB")
            return
        }
        
        logger.debug("Connecting to slot: \(firstSlotName)")
        
        slotManager.getSlot(withName: firstSlotName) { [weak self] slot in
            guard let self = self, let slot = slot else {
                completion(false, "Không thể kết nối với slot: \(firstSlotName)")
                return
            }
            
            self.currentSlot = slot
            self.logger.debug("Slot state: \(slot.state.rawValue)")
            
            // Check if card is present
            guard slot.state == .validCard else {
                let stateMessage: String
                switch slot.state {
                case .missing:
                    stateMessage = "Không có thẻ trong đầu đọc"
                case .empty:
                    stateMessage = "Đầu đọc rỗng"
                case .probing:
                    stateMessage = "Đang kiểm tra thẻ..."
                case .muteCard:
                    stateMessage = "Thẻ không phản hồi"
                @unknown default:
                    stateMessage = "Trạng thái không xác định"
                }
                completion(false, stateMessage)
                return
            }
            
            // Get the smart card
            guard let card = slot.makeSmartCard() else {
                completion(false, "Không thể tạo kết nối với thẻ")
                return
            }
            
            self.currentCard = card
            
            // Begin session with the card
            card.beginSession { success, error in
                if let error = error {
                    self.logger.debug("Session error: \(error.localizedDescription)")
                    completion(false, "Lỗi phiên làm việc: \(error.localizedDescription)")
                    return
                }
                
                if success {
                    self.logger.debug("Card session started successfully")
                    completion(true, nil)
                } else {
                    completion(false, "Không thể bắt đầu phiên làm việc với thẻ")
                }
            }
        }
    }
    
    /// Disconnect from current smart card
    func disconnect() {
        currentCard?.endSession()
        currentCard = nil
        currentSlot = nil
        logger.debug("Disconnected from card")
    }
    
    /// Check if currently connected to a card
    func isConnected() -> Bool {
        return currentCard != nil
    }
    
    // MARK: - APDU Communication
    
    /// Send APDU command to smart card and get response
    /// - Parameters:
    ///   - apdu: APDU command data
    ///   - completion: Callback with (responseData, sw1, sw2, error)
    func transmitApdu(_ apdu: Data, completion: @escaping (Data, UInt8, UInt8, Error?) -> Void) {
        guard let card = currentCard else {
            completion(Data(), 0, 0, NSError(domain: "UsbCardManager", code: 1, 
                userInfo: [NSLocalizedDescriptionKey: "Chưa kết nối với thẻ"]))
            return
        }
        
        logger.debug("TX: \(apdu.hexString)")
        
        card.transmit(apdu) { [weak self] response, error in
            guard let self = self else { return }
            
            if let error = error {
                self.logger.debug("Transmit error: \(error.localizedDescription)")
                completion(Data(), 0, 0, error)
                return
            }
            
            guard let response = response, response.count >= 2 else {
                completion(Data(), 0, 0, NSError(domain: "UsbCardManager", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "Phản hồi quá ngắn hoặc nil"]))
                return
            }
            
            let sw1 = response[response.count - 2]
            let sw2 = response[response.count - 1]
            let data = response.dropLast(2)
            
            self.logger.debug("RX: \(response.hexString) (SW: \(String(format: "%02X%02X", sw1, sw2)))")
            
            completion(Data(data), sw1, sw2, nil)
        }
    }
    
    /// Send APDU command with automatic GET RESPONSE handling for chained responses
    func transmitApduWithGetResponse(_ apdu: Data, completion: @escaping (Data, UInt8, UInt8, Error?) -> Void) {
        var accumulatedData = Data()
        
        func recursiveTransmit(_ command: Data) {
            transmitApdu(command) { [weak self] responseData, sw1, sw2, error in
                guard let self = self else { return }
                
                if let error = error {
                    completion(Data(), sw1, sw2, error)
                    return
                }
                
                accumulatedData.append(responseData)
                
                // Check for "more data available" status (61xx)
                if sw1 == 0x61 {
                    // Build GET RESPONSE command
                    let getResponseApdu = Data([0x00, 0xC0, 0x00, 0x00, sw2])
                    recursiveTransmit(getResponseApdu)
                } else {
                    completion(accumulatedData, sw1, sw2, nil)
                }
            }
        }
        
        recursiveTransmit(apdu)
    }
    
    // MARK: - High-Level Card Operations
    
    /// Select applet by AID
    func selectApplet(aid: Data, completion: @escaping (Bool, UInt8, UInt8, Error?) -> Void) {
        // SELECT APDU: 00 A4 04 00 [Lc] [AID]
        var apdu = Data([0x00, 0xA4, 0x04, 0x00, UInt8(aid.count)])
        apdu.append(aid)
        
        transmitApduWithGetResponse(apdu) { _, sw1, sw2, error in
            let success = (error == nil && sw1 == 0x90 && sw2 == 0x00)
            completion(success, sw1, sw2, error)
        }
    }
    
    /// Verify PIN
    func verifyPin(pin: String, completion: @escaping (Bool, UInt8, UInt8, Error?) -> Void) {
        // VERIFY APDU: 00 20 00 81 [Lc] [PIN]
        let pinData = Data(pin.utf8)
        var apdu = Data([0x00, 0x20, 0x00, 0x81, UInt8(pinData.count)])
        apdu.append(pinData)
        
        transmitApduWithGetResponse(apdu) { _, sw1, sw2, error in
            let success = (error == nil && sw1 == 0x90 && sw2 == 0x00)
            completion(success, sw1, sw2, error)
        }
    }
    
    /// Generate signature with specified key
    func generateSignature(dataToSign: Data, keyIndex: Int, completion: @escaping (Data?, UInt8, UInt8, Error?) -> Void) {
        // COMPUTE DIGITAL SIGNATURE: 00 2A 9E [P2] [Lc] [Data] [Le]
        let p2: UInt8
        switch keyIndex {
        case 1: p2 = 0x9B
        case 2: p2 = 0x9C
        default: p2 = 0x9A
        }
        
        var apdu = Data([0x00, 0x2A, 0x9E, p2, UInt8(dataToSign.count)])
        apdu.append(dataToSign)
        apdu.append(0x00) // Le = 256
        
        transmitApduWithGetResponse(apdu) { responseData, sw1, sw2, error in
            if error == nil && sw1 == 0x90 && sw2 == 0x00 {
                completion(responseData, sw1, sw2, nil)
            } else {
                completion(nil, sw1, sw2, error)
            }
        }
    }
    
    /// Get RSA public key for specified role
    func getRsaPublicKey(keyRole: String, completion: @escaping (Data?, UInt8, UInt8, Error?) -> Void) {
        // GENERATE ASYMMETRIC KEY PAIR (read): 00 47 81 00 [Lc] [Data]
        let roleData: Data
        switch keyRole {
        case "sig": roleData = Data([0xB6, 0x00])
        case "dec": roleData = Data([0xB8, 0x00])
        case "aut": roleData = Data([0xA4, 0x00])
        case "sm":  roleData = Data([0xA6, 0x00])
        default:
            completion(nil, 0, 0, NSError(domain: "UsbCardManager", code: 3,
                userInfo: [NSLocalizedDescriptionKey: "Vai trò khóa không hợp lệ: \(keyRole)"]))
            return
        }
        
        var apdu = Data([0x00, 0x47, 0x81, 0x00, UInt8(roleData.count)])
        apdu.append(roleData)
        apdu.append(0x00) // Le = 256
        
        transmitApduWithGetResponse(apdu) { responseData, sw1, sw2, error in
            if error == nil && sw1 == 0x90 && sw2 == 0x00 {
                completion(responseData, sw1, sw2, nil)
            } else {
                completion(nil, sw1, sw2, error)
            }
        }
    }
    
    /// Get certificate for specified role
    func getCertificate(keyRole: String, completion: @escaping (Data?, UInt8, UInt8, Error?) -> Void) {
        // Step 1: Select certificate data object
        let selectCertData = Data([0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
        var selectApdu = Data([0x00, 0xA5, 0x02, 0x04, UInt8(selectCertData.count)])
        selectApdu.append(selectCertData)
        selectApdu.append(0x00) // Le = 256
        
        transmitApduWithGetResponse(selectApdu) { [weak self] _, sw1, sw2, error in
            guard let self = self else { return }
            
            if error != nil || sw1 != 0x90 || sw2 != 0x00 {
                completion(nil, sw1, sw2, error ?? NSError(domain: "UsbCardManager", code: 4,
                    userInfo: [NSLocalizedDescriptionKey: "Không thể chọn certificate"]))
                return
            }
            
            // Step 2: Get certificate data
            let getCertApdu = Data([0x00, 0xCA, 0x7F, 0x21, 0x00, 0x08, 0x00]) // Extended Le for large cert
            
            self.transmitApduWithGetResponse(getCertApdu) { responseData, sw1, sw2, error in
                if error == nil && sw1 == 0x90 && sw2 == 0x00 {
                    completion(responseData, sw1, sw2, nil)
                } else {
                    completion(nil, sw1, sw2, error)
                }
            }
        }
    }
}

// MARK: - Helper Extensions

extension Data {
    var hexString: String {
        return map { String(format: "%02X", $0) }.joined(separator: " ")
    }
}

// MARK: - Logger

private class UsbLogger {
    func debug(_ message: String) {
        #if DEBUG
        print("🔌 [USB] \(message)")
        #endif
    }
}
