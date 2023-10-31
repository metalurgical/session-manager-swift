Pod::Spec.new do |spec|
  spec.name         = "TorusSessionManager"
  spec.version      = "3.0.1"
  spec.platform      = :ios, "14.0"
  spec.summary      = "SessionManagement SDK"
  spec.homepage     = "https://github.com/Web3Auth"
  spec.license      = { :type => 'MIT', :file => 'License.md' }
  spec.swift_version   = "5.0"
  spec.author       = { "Torus Labs" => "gaurav@tor.us" }
  spec.module_name = "SessionManager"
  spec.source       = { :git => "https://github.com/Web3Auth/session-manager-swift.git", :tag => spec.version }
  spec.source_files = "Sources/SessionManager/*.{swift}","Sources/SessionManager/**/*.{swift}"
  spec.dependency 'KeychainSwift', '~> 20.0.0'
  spec.dependency 'web3.swift', '~> 1.6.0'
  spec.dependency 'CryptoSwift', '~> 1.8.0'
end
