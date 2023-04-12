Pod::Spec.new do |spec|
  spec.name         = "Session-Manager"
  spec.version      = "1.0.0"
  spec.ios.deployment_target  = "14.0"
  spec.summary      = "Manages session"
  spec.homepage     = "https://github.com/Web3Auth/session-manager-swift"
  spec.license      = { :type => 'BSD', :file => 'License.md' }
  spec.swift_version   = "5.0"
  spec.author       = { "Torus Labs" => "dhruv@tor.us" }
  spec.module_name = "SessionManager"
  spec.source       = { :git => "https://github.com/Web3Auth/session-manager-swift.git", :tag => spec.version }
  spec.source_files = "Sources/SessionManager/*.{swift}","Sources/SessionManager/**/*.{swift}"
  spec.dependency 'KeychainSwift', '~> 20.0.0'
  spec.dependency 'web3.swift', '~> 0.9.3'
  spec.dependency 'CryptoSwift', '~> 1.5.1'
end