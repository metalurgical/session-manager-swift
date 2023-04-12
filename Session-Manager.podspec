Pod::Spec.new do |spec|
  spec.name         = "Session-Manager"
  spec.version      = "1.0.0"
  spec.ios.deployment_target  = "13.0"
  spec.summary      = "Manages session"
  spec.homepage     = "https://github.com/Web3Auth"
  spec.license      = { :type => 'MIT', :file => 'License.md' }
  spec.swift_version   = "5.0"
  spec.author       = { "Torus Labs" => "dhruv@tor.us" }
  spec.module_name = "SessionManager"
  spec.source       = { :git => "https://github.com/Web3Auth/session-manager-swift.git", :tag => spec.version }
  spec.source_files = "Sources/SessionManager/*.{swift}","Sources/SessionManager/**/*.{swift}"
  spec.dependency 'KeychainSwift', '~> 20.0.0'
  spec.dependency 'web3.swift', '~> 0.9.3'
  spec.dependency 'CryptoSwift', '~> 1.5.1'
  spec.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
  spec.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
end
