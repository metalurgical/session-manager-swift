import Foundation

public struct Signature: Codable {
    let r: String
    let s: String

    public init(r: String, s: String) {
        self.r = r
        self.s = s
    }
}

struct SessionRequestModel: Codable {
    var key: String
    var data: String
    var signature: String
    var timeout: Int

    public init(key: String, data: String, signature: String, timeout: Int) {
        self.key = key
        self.data = data
        self.signature = signature
        self.timeout = timeout
    }
}

public struct ECIES: Codable {
    public init(iv: String, ephemPublicKey: String, ciphertext: String, mac: String) {
        self.iv = iv
        self.ephemPublicKey = ephemPublicKey
        self.ciphertext = ciphertext
        self.mac = mac
    }

    var iv: String
    var ephemPublicKey: String
    var ciphertext: String
    var mac: String
}
