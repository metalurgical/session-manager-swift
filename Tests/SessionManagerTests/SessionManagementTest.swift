//
//  SessionManagementTest.swift
//  
//
//  Created by Dhruv Jaiswal on 10/04/23.
//

import XCTest
@testable import SessionManager

final class SessionManagementTest: XCTestCase {

    var sessionID: String = "02666153283f10e9323e8e296032534d54314bc3296f2a3c47c9130346cc0dab"

    func generatePrivateandPublicKey() -> (privKey: String, pubKey: String) {
        let privKeyData = generatePrivateKeyData() ?? Data()
        let publicKey = SECP256K1.privateToPublic(privateKey: privKeyData)?.subdata(in: 1 ..< 65) ?? Data()
        return (privKey: privKeyData.toHexString(), pubKey: publicKey.toHexString())
    }

    func test_createSessionID() async {
        do {
            let session = SessionManager()
            let (privKey, pubKey) = generatePrivateandPublicKey()
            let sfa = SFAModel(publicKey: pubKey, privateKey: privKey)
            let result = try await session.createSession(data: sfa)
            print(result)
            self.sessionID = result
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func test_authoriseSessionID() async {
        let session = SessionManager(sessionID: sessionID)
        do {
            let sfa = try await session.authorizeSession()
            print(sfa)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

    func testSign() {
        let privKey = "bce6550a433b2e38067501222f9e75a2d4c5a433a6d27ec90cd81fbd4194cc2b"
        let encData = "test data"
        do {
            let sig = try SECP256K1().sign(privkey: privKey, messageData: encData)
            XCTAssertEqual(sig.r, "d7736799107d8e6308af995d827dc8772993cd8ccab5c230fe8277cecb02f31a")
            XCTAssertEqual(sig.s, "4df631a4059f45d8cb0e8889ff1b8096243796189ec00440883b1c0271a19e80")
        } catch let error {
            XCTFail(error.localizedDescription)
        }
    }

    func testEncryptAndSign() {
        let privKey = "dda863b615ac6de27fb680b5563db3c19176a6f42cc1dee1768e220983385e3e"
        let encdata = "{\"iv\":\"693407372626b11017d0ec30acd29e6a\",\"ciphertext\":\"cbe09442851a0463b3e34e2f912c6aee\",\"ephemPublicKey\":\"0477e20c5d9e3281a4eca7d07c1c4cc9765522ea7966cd7ea8f552da42049778d4fcf44b35b59e84eddb1fa3266350e4f2d69d62da82819d51f107550e03852661\",\"mac\":\"96d358f46ef371982af600829c101e78f6c5d5f960bd96fdd2ca52763ee50f65\"}"
        do {
            let sig = try SECP256K1().sign(privkey: privKey, messageData: encdata)
            XCTAssertEqual(sig.r, "b0161b8abbd66da28734d105e28455bf9a48a33ee1dfde71f96e2e9197175650")
            XCTAssertEqual(sig.s, "4d53303ec05596ca6784cff1d25eb0e764f70ff5e1ce16a896ec58255b25b5ff")
        } catch let error {
            XCTFail(error.localizedDescription)
        }

    }

    func test_invalidateSession() async {
        let session = SessionManager(sessionID: sessionID)
        do {
            let result = try await session.invalidateSession()
            print(result)
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
}

struct SFAModel: Codable {
    let publicKey: String
    let privateKey: String
}
