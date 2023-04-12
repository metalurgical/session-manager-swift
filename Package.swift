// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SessionManager",
    platforms: [.iOS(.v14)],
    products: [
        .library(
            name: "SessionManager",
            targets: ["SessionManager"])
    ],
    dependencies: [
         .package(name: "KeychainSwift", url: "https://github.com/evgenyneu/keychain-swift.git", from: "20.0.0"),
        .package(name: "web3.swift", url: "https://github.com/argentlabs/web3.swift", from: "0.9.3"),
        .package(name: "CryptoSwift", url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.5.1")
    ],
    targets: [
        .target(
            name: "SessionManager",
            dependencies: ["KeychainSwift", "web3.swift", "CryptoSwift"]),
        .testTarget(
            name: "SessionManagerTests",
            dependencies: ["SessionManager"])
    ],
    swiftLanguageVersions: [.v5]
)
