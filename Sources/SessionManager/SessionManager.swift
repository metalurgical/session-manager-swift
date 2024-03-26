import BigInt
import Foundation
import OSLog
import curveSecp256k1

public class SessionManager {
    private var sessionServerBaseUrl = "https://broadcast-server.tor.us/"
    private var sessionID: curveSecp256k1.SecretKey? {
        didSet {
            do {
                if let sessionID = sessionID {
                    KeychainManager.shared.save(key: .sessionID, val: try sessionID.serialize())
                }
            } catch {
                print("Error: Unknown error")
            }
        }
    }

    private let sessionNamespace: String = ""
    private let sessionTime: Int

    public func getSessionID() ->curveSecp256k1.SecretKey? {
        return sessionID
    }

    public func setSessionID(_ val: curveSecp256k1.SecretKey) {
        sessionID = val
    }
    
    public init(sessionServerBaseUrl: String? = nil, sessionTime: Int = 86400, sessionID: String? = nil) throws {
        if let sessionID = sessionID {
            let key = try SecretKey.init(hex: sessionID)
            self.sessionID = key
        } else {
            if let sessionID = KeychainManager.shared.get(key: .sessionID) {
                self.sessionID = try SecretKey.init(hex: sessionID)
            }
        }
        if let sessionServerBaseUrl = sessionServerBaseUrl {
            self.sessionServerBaseUrl = sessionServerBaseUrl
        }
        self.sessionTime = min(sessionTime, 7 * 86400)
        Router.baseURL = self.sessionServerBaseUrl
    }

    private func generateRandomSessionID() -> curveSecp256k1.SecretKey {
        return generatePrivateKey()
    }

    public func createSession<T: Encodable>(data: T) async throws -> String {
        do {
            let sessionID = generateRandomSessionID()
            self.sessionID = sessionID
            let publicKey = try sessionID.toPublic()
            let encodedObj = try JSONEncoder().encode(data)
            let jsonString = String(data: encodedObj, encoding: .utf8) ?? ""
            let encData = try encryptData(privkey: sessionID, jsonString)
            let sig = try curveSecp256k1.ECDSA.signRecoverable(key: sessionID, hash: encData).serialize()
            let sigData = try JSONEncoder().encode(sig)
            let sigJsonStr = String(data: sigData, encoding: .utf8) ?? ""
            let sessionRequestModel = SessionRequestModel(key: try publicKey.serialize(compressed: false), data: encData, signature: sigJsonStr, timeout: sessionTime)
            let api = Router.set(T: sessionRequestModel)
            let result = await Service.request(router: api)
            switch result {
            case let .success(data):
                let msgDict = try JSONSerialization.jsonObject(with: data)
                os_log("authrorize session response is: %@", log: getTorusLogger(log: Web3AuthLogger.network, type: .info), type: .info, "\(msgDict)")
                return try sessionID.serialize()
            case let .failure(error):
                throw error
            }
        } catch {
            throw error
        }
    }

    public func authorizeSession() async throws -> [String: Any] {
        guard let sessionID = sessionID else {
            throw SessionManagerError.sessionIDAbsent
        }
        let publicKey = try sessionID.toPublic().serialize(compressed: false)
        let api = Router.get([.init(name: "key", value: "\(publicKey)"), .init(name: "namespace", value: sessionNamespace)])
        let result = await Service.request(router: api)
        switch result {
        case let .success(data):
            do {
                let msgDict = try JSONSerialization.jsonObject(with: data) as? [String: String]
                let msgData = msgDict?["message"]
                os_log("authrorize session response is: %@", log: getTorusLogger(log: Web3AuthLogger.network, type: .info), type: .info, "\(String(describing: msgDict))")
                let loginDetails = try decryptData(privKey: sessionID, d: msgData ?? "")
                KeychainManager.shared.save(key: .sessionID, val: try sessionID.serialize())
                return loginDetails
            } catch {
                throw error
            }
        case let .failure(error):
            throw error
        }
    }

    public func invalidateSession() async throws -> Bool {
        guard let sessionID = sessionID else {
            throw SessionManagerError.sessionIDAbsent
        }
        do {
            let publicKey = try sessionID.toPublic()
            let encData = try encryptData(privkey: sessionID, "")
            let sig = try curveSecp256k1.ECDSA.signRecoverable(key: sessionID, hash: encData).serialize()
            let sigData = try JSONEncoder().encode(sig)
            let sigJsonStr = String(data: sigData, encoding: .utf8) ?? ""
            let sessionLogoutDataModel = SessionRequestModel(key: try publicKey.serialize(compressed: false), data: encData, signature: sigJsonStr, timeout: 1)
            let api = Router.set(T: sessionLogoutDataModel)
            let result = await Service.request(router: api)
            switch result {
            case let .success(data):
                do {
                    let msgDict = try JSONSerialization.jsonObject(with: data)
                    os_log("logout response is: %@", log: getTorusLogger(log: Web3AuthLogger.network, type: .info), type: .info, "\(msgDict)")
                    KeychainManager.shared.delete(key: .sessionID)
                    return true
                } catch {
                    throw error
                }
            case let .failure(error):
                throw error
            }
        } catch let error {
            throw error
        }
    }
}
