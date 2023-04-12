//
//  File.swift
//
//
//  Created by Dhruv Jaiswal on 18/07/22.
//

import KeychainSwift

enum KeychainConstantEnum {
    case sessionID
    case custom(String)

    var value: String {
        switch self {
        case .sessionID:
            return "sessionID"
        case let .custom(string):
            return string
        }
    }
}

protocol KeychainManagerProtocol {
    func get(key: KeychainConstantEnum) -> String?

    func delete(key: KeychainConstantEnum)

    func save(key: KeychainConstantEnum, val: String)
}

class KeychainManager: KeychainManagerProtocol {
    private let keychain = KeychainSwift()
    static let shared = KeychainManager()

    private init() {}

    func get(key: KeychainConstantEnum) -> String? {
        return keychain.get(key.value)
    }

    func delete(key: KeychainConstantEnum) {
        keychain.delete(key.value)
    }

    func save(key: KeychainConstantEnum, val: String) {
        keychain.set(val, forKey: key.value)
    }
}
