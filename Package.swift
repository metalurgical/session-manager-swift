// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SessionManager",
    platforms: [.iOS(.v14), .macOS(.v11)],
    products: [
        .library(
            name: "SessionManager",
            targets: ["SessionManager"])
    ],
    dependencies: [
        .package(name: "KeychainSwift", url: "https://github.com/evgenyneu/keychain-swift.git", from: "20.0.0"),
        .package(name: "curvelib.swift", url: "https://github.com/tkey/curvelib.swift", from: "0.1.2"),
        .package(name: "CryptoSwift", url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.0"),
        .package(name: "BigInt", url: "https://github.com/attaswift/BigInt.git", from: "5.3.0")
    ],
    targets: [
        .target(
            name: "SessionManager",
            dependencies: ["KeychainSwift", "CryptoSwift", "BigInt", .product(name: "curveSecp256k1", package: "curvelib.swift")]),
        .testTarget(
            name: "SessionManagerTests",
            dependencies: ["SessionManager"])
    ],
    swiftLanguageVersions: [.v5]
)
