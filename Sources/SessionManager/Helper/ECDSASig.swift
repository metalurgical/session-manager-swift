import BigInt
import Foundation
import secp256k1

extension SECP256K1 {
    func sign(privkey: secp256k1.Signing.PrivateKey, messageData: String) throws -> Signature {
        let encData = messageData.data(using: .utf8) ?? Data()
        let sig = SECP256K1.signForRecovery(hash: encData.sha3(.keccak256), privateKey: privkey.dataRepresentation)
        guard let unmrashalsig = SECP256K1.unmarshalSignature(signatureData: sig.rawSignature?.data ?? Data())
        else { throw SessionManagerError.runtimeError("Invalid Signature") }
        let r = unmrashalsig.r.bytes.uint8Reverse().toHexString()
        let s = unmrashalsig.s.bytes.uint8Reverse().toHexString()
        return .init(r: r, s: s)
    }
}
