// Copyright (c) 2020 by Adarsh Rai. All rights reserved.

import XCTest
import Security
@testable import SecureEnclaveTest

@inline(__always)
func given(_ scenario:String, steps:(() -> Void)? = nil) {
    let stepName = "Given " + scenario
    print(stepName)
    XCTContext.runActivity(named: stepName) {_ in
        steps?()
    }
}

@inline(__always)
func when(_ scenario:String, steps:(() -> Void)? = nil) {
    let stepName = "When " + scenario
    print(stepName)
    XCTContext.runActivity(named: stepName) {_ in
        steps?()
    }
}

@inline(__always)
func then(_ scenario:String, steps:(() -> Void)? = nil) {
    let stepName = "Then " + scenario
    print(stepName)
    XCTContext.runActivity(named: stepName) {_ in
        steps?()
    }
}

@inline(__always)
func and(_ scenario:String, steps:(() -> Void)? = nil) {
    let stepName = "And " + scenario
    print(stepName)
    XCTContext.runActivity(named: stepName) {_ in
        steps?()
    }
}

@inline(__always)
func but(_ scenario:String, steps:(() -> Void)? = nil) {
    let stepName = "But " + scenario
    print(stepName)
    XCTContext.runActivity(named: stepName) {_ in
        steps?()
    }
}

class SecureEncryptionHelperTests: XCTestCase {

    let tagData = "com.personal.SecureEnclaveTest1".data(using: .utf8)!
    
    override func setUp() {
        FakeSecureEncryptionHelper.generateSecureKeyError = nil
        FakeSecureEncryptionHelper.accessControlError = nil
        FakeSecureEncryptionHelper.accessControlProtection = nil
        FakeSecureEncryptionHelper.accessControlFlags = nil
        
        FakeSecureEncryptionHelper.retievePrivateKeyError = nil
        
        FakeSecureEncryptionHelper.copyItemError = nil
        FakeSecureEncryptionHelper.copyItemQuery = nil
        
        FakeSecureEncryptionHelper.createRandomKeyError = nil
        
        FakeSecureEncryptionHelper.shouldReturnPublicKey = true
        
        FakeSecureEncryptionHelper.removeSecureKeyFor(tagData)
        
        FakeSecureEncryptionHelper.shouldReturnPublicKey = true
        
        FakeSecureEncryptionHelper.createEncryptedDataError = nil
        
        FakeSecureEncryptionHelper.createDecryptedDataError = nil
    }

    func testGenerateSecureAccessKeyWhenAccessControlFlagCreationFailed() {
        var generatedKey: SecKey?
        var keyError: SecureEncryptionError?
        let cfError = CFErrorCreate(kCFAllocatorDefault, "" as CFErrorDomain, 1, nil)
        given("access control flag creation is failing") {
            FakeSecureEncryptionHelper.accessControlError = cfError
        }
        when("generate secure access key is requested") {
            do {
                generatedKey = try FakeSecureEncryptionHelper.generateSecureKeyFor(self.tagData)
            } catch let error as SecureEncryptionError {
                keyError = error
            } catch {
                XCTFail()
            }
        }
        then("generated key is nil") {
            XCTAssertNil(generatedKey)
        }
        and("correct error is received") {
            XCTAssertEqual(keyError, .failedToGenerateSecureKey(cfError))
        }
        and("flags are correct") {
            XCTAssertTrue(FakeSecureEncryptionHelper.accessControlFlags!.contains(.privateKeyUsage))
        }
        and("protection is correct") {
            XCTAssertEqual(FakeSecureEncryptionHelper.accessControlProtection as! CFString, kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
        }
    }
    
    func testGenerateSecureAccessKeyWhenKeyCreationFailed() {
        var generatedKey: SecKey?
        var keyError: SecureEncryptionError?
        let cfError = CFErrorCreate(kCFAllocatorDefault, "" as CFErrorDomain, 2, nil)
        given("secure random key creation is failing") {
            FakeSecureEncryptionHelper.createRandomKeyError = cfError
        }
        when("generate secure access key is requested") {
            do {
                generatedKey = try FakeSecureEncryptionHelper.generateSecureKeyFor(self.tagData)
            } catch let error as SecureEncryptionError {
                keyError = error
            } catch {
                XCTFail()
            }
        }
        then("generated key is nil") {
            XCTAssertNil(generatedKey)
        }
        and("correct error is received") {
            XCTAssertEqual(keyError, .failedToGenerateSecureKey(cfError))
        }
    }
    
    func testGenerateSecureAccessKeyWhenEverythingIsSuccessful() {
        var generatedKey: SecKey?
        var keyError: SecureEncryptionError?
        
        given("none of Security operation fail") {}
        when("generate secure access key is requested") {
            do {
                generatedKey = try FakeSecureEncryptionHelper.generateSecureKeyFor(self.tagData)
            } catch let error as SecureEncryptionError {
                keyError = error
            } catch {
                XCTFail()
            }
        }
        then("valid key is generated") {
            XCTAssertNotNil(generatedKey)
        }
        and("error is nil") {
            XCTAssertNil(keyError)
        }
    }
    
    func testRetrievePrivateKeyWhenKeyIsNotGenerated() {
        var retrievedPrivateKey: SecKey?
        var keyError: SecureEncryptionError?
        
        given("no secure access key has been generated")
        when("private key of secure access key is retrieved") {
            do {
                retrievedPrivateKey = try FakeSecureEncryptionHelper.retrievePrivateKeyFor(self.tagData)
            } catch let error as SecureEncryptionError {
                keyError = error
            } catch {
                XCTFail()
            }
        }
        then("no key is returned") {
            XCTAssertNil(retrievedPrivateKey)
        }
        and("corresponding error is returned") {
            XCTAssertNotNil(keyError)
            XCTAssertEqual(keyError, SecureEncryptionError.failedToReadPrivateKey)
        }
    }
    
    func testRetievePrivateKeyWhenValidKeyExists() {
        var retrievedPrivateKey: SecKey?
        var keyError: SecureEncryptionError?
        
        given("a secure access key has already been generated") {
            _ = try? FakeSecureEncryptionHelper.generateSecureKeyFor(self.tagData)
        }
        when("private key of secure access key is retrieved") {
            do {
                retrievedPrivateKey = try FakeSecureEncryptionHelper.retrievePrivateKeyFor(self.tagData)
            } catch let error as SecureEncryptionError {
                keyError = error
            } catch {
                XCTFail()
            }
        }
        then("valid key is returned") {
            XCTAssertNotNil(retrievedPrivateKey)
        }
        and("corresponding error is nil") {
            XCTAssertNil(keyError)
        }
    }
    
    func testRetrievePrivateKeyIsCalledWithCorrectQuery() {
        var retrievedPrivateKey: SecKey?
        var keyError: SecureEncryptionError?
        
        given("a secure access key has already been generated") {
            _ = try? FakeSecureEncryptionHelper.generateSecureKeyFor(self.tagData)
        }
        and("user has denied permission to read key") {
            FakeSecureEncryptionHelper.copyItemError = errSecAuthFailed
        }
        when("private key of secure access key is retrieved") {
            do {
                retrievedPrivateKey = try FakeSecureEncryptionHelper.retrievePrivateKeyFor(self.tagData)
            } catch let error as SecureEncryptionError {
                keyError = error
            } catch {
                XCTFail()
            }
        }
        then("no key is returned") {
            XCTAssertNil(retrievedPrivateKey)
        }
        and("corresponding error is returned") {
            XCTAssertNotNil(keyError)
            XCTAssertEqual(keyError, SecureEncryptionError.failedToReadPrivateKey)
        }
        and("correct flags were used to read private key") {
            let queryDictionary = FakeSecureEncryptionHelper.copyItemQuery as! [String: Any]
            XCTAssertEqual(queryDictionary[kSecClass as String] as! String, kSecClassKey as String)
            XCTAssertEqual(queryDictionary[kSecAttrApplicationTag as String] as! Data, self.tagData)
            XCTAssertEqual(queryDictionary[kSecAttrKeyType as String] as! String, kSecAttrKeyTypeEC as String)
            XCTAssertEqual(queryDictionary[kSecReturnRef as String] as! Bool, true)
        }
    }
    
    func testRemoveSecureAccessKeyWithCorrespondingTag() {
        given("a secure access key has already been generated") {
            _ = try? FakeSecureEncryptionHelper.generateSecureKeyFor(self.tagData)
        }
        when("secure access key is deleted with corresponding tag") {
            FakeSecureEncryptionHelper.removeSecureKeyFor(self.tagData)
        }
        then("private key retrieval fails") {
            let retrievedPrivateKey = try? FakeSecureEncryptionHelper.retrievePrivateKeyFor(self.tagData)
            XCTAssertNil(retrievedPrivateKey)
        }
    }
    
    func testRemoveSecureAccessKeyWithDifferentTag() {
        given("a secure access key has already been generated") {
            _ = try? FakeSecureEncryptionHelper.generateSecureKeyFor(self.tagData)
        }
        when("secure access key is deleted with corresponding tag") {
            FakeSecureEncryptionHelper.removeSecureKeyFor("some.random.tag".data(using: .utf8)!)
        }
        then("private key retrieval still successds") {
            let retrievedPrivateKey = try? FakeSecureEncryptionHelper.retrievePrivateKeyFor(self.tagData)
            XCTAssertNotNil(retrievedPrivateKey)
        }
    }
    
    func testRetrievePublicKeyWhenSecureAccessKeyIsAlreadyDeleted() {
        var privateKey: SecKey?
        var retrievedPublicKey: SecKey?
        var keyError: SecureEncryptionError?
        given("a secure access key has already been generated") {
           privateKey = try? FakeSecureEncryptionHelper.generateSecureKeyFor(self.tagData)
        }
        and("then secure access key is deleted") {
            FakeSecureEncryptionHelper.removeSecureKeyFor(self.tagData)
        }
        when("public key is retrieved for private key of deleted secure access key") {
            do {
                retrievedPublicKey = try FakeSecureEncryptionHelper.retrievePublicKeyFor(privateKey!)
            } catch let error as SecureEncryptionError {
                keyError = error
            } catch {
                XCTFail()
            }
        }
        then("corresponding public key is still retrieved") {
            //In current implementation, the privae key contains the transient public key.
            //Therefore, when secure key is deleted, it only deletes private key from keychain.
            //But if private key exists in memory, then it also hold the corresponding public key.
            XCTAssertNotNil(retrievedPublicKey)
        }
        and("no error is received") {
            XCTAssertNil(keyError)
        }
    }
    
    func testRetrievePublicKeyWhenSecureAccessKeyExists() {
        var privateKey: SecKey?
        var retrievedPublicKey: SecKey?
        var keyError: SecureEncryptionError?
        given("a secure access key has already been generated") {
           privateKey = try? FakeSecureEncryptionHelper.generateSecureKeyFor(self.tagData)
        }
        when("public key is retrieved for private key") {
            do {
                retrievedPublicKey = try FakeSecureEncryptionHelper.retrievePublicKeyFor(privateKey!)
            } catch let error as SecureEncryptionError {
                keyError = error
            } catch {
                XCTFail()
            }
        }
        then("corresponding public key is retrieved") {
            XCTAssertNotNil(retrievedPublicKey)
        }
        and("no error is received") {
            XCTAssertNil(keyError)
        }
    }
    
    func testRetrievePublicKeyWhenNoPublicKeyIsReturned() {
        var privateKey: SecKey?
        var retrievedPublicKey: SecKey?
        var keyError: SecureEncryptionError?
        given("a secure access key has already been generated") {
           privateKey = try? FakeSecureEncryptionHelper.generateSecureKeyFor(self.tagData)
        }
        and("public key retrieval is failing") {
            FakeSecureEncryptionHelper.shouldReturnPublicKey = false
        }
        when("public key is retrieved for private key") {
            do {
                retrievedPublicKey = try FakeSecureEncryptionHelper.retrievePublicKeyFor(privateKey!)
            } catch let error as SecureEncryptionError {
                keyError = error
            } catch {
                XCTFail()
            }
        }
        then("corresponding public key is retrieved") {
            XCTAssertNil(retrievedPublicKey)
        }
        and("no error is received") {
            XCTAssertEqual(keyError, SecureEncryptionError.failedToReadPublicKey)
        }
    }
    
    func testEncryptionFailsWhenAlgorithmIsNotSupported() {
        let algorithm = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512
        var dataToEncrypt: Data?
        var encryptedData: Data?
        var encrytpionError: SecureEncryptionError?
        given("data to encrypt using algorithm \(algorithm)") {
            dataToEncrypt = "some_dummy_text".data(using: .utf8)
        }
        when("data is encrypted using unsupported algorithm \(algorithm)") {
            do {
                encryptedData = try FakeSecureEncryptionHelper.encrypt(dataToEncrypt!, using: self.tagData, algorithm: algorithm)
            } catch let error as SecureEncryptionError {
                encrytpionError = error
            } catch {
                XCTFail()
            }
        }
        then("it throws unsupported algorith error") {
            XCTAssertEqual(encrytpionError, SecureEncryptionError.unsupportedAlgorithm(algorithm))
        }
        and("encrypted data is nil") {
            XCTAssertNil(encryptedData)
        }
    }
    
    func testEncryptionFailsWhenRetrievePrivateKeyAndGenerateSecureKeyFailed() {
        let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256
        var dataToEncrypt: Data?
        var encryptedData: Data?
        var encrytpionError: SecureEncryptionError?
        given("data to encrypt using algorithm \(algorithm)") {
            dataToEncrypt = "some_dummy_text".data(using: .utf8)
        }
        and("retrieve private key is failing") {
            FakeSecureEncryptionHelper.retievePrivateKeyError = SecureEncryptionError.failedToReadPrivateKey
        }
        and("generate secure access key is failing with unknown error") {
            FakeSecureEncryptionHelper.generateSecureKeyError = SecureEncryptionError.unknown
        }
        when("data is encrypted") {
            do {
                encryptedData = try FakeSecureEncryptionHelper.encrypt(dataToEncrypt!, using: self.tagData)
            } catch let error as SecureEncryptionError {
                encrytpionError = error
            } catch {
                XCTFail()
            }
        }
        then("it throws unknown error") {
            XCTAssertEqual(encrytpionError, SecureEncryptionError.unknown)
        }
        and("encrypted data is nil") {
            XCTAssertNil(encryptedData)
        }
    }
    
    func testEncryptionFailsWhenRetrievePublicKeyAndGenerateSecureKeyFailed() {
        let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256
        var dataToEncrypt: Data?
        var encryptedData: Data?
        var encrytpionError: SecureEncryptionError?
        given("data to encrypt using algorithm \(algorithm)") {
            dataToEncrypt = "some_dummy_text".data(using: .utf8)
        }
        and("a secure access key already exists") {
            _ = try? FakeSecureEncryptionHelper.generateSecureKeyFor(self.tagData)
        }
        and("retrieve public key is failing") {
            FakeSecureEncryptionHelper.shouldReturnPublicKey = false
        }
        and("generate secure access key is failing with unknown error") {
            FakeSecureEncryptionHelper.generateSecureKeyError = SecureEncryptionError.unknown
        }
        when("data is encrypted") {
            do {
                encryptedData = try FakeSecureEncryptionHelper.encrypt(dataToEncrypt!, using: self.tagData)
            } catch let error as SecureEncryptionError {
                encrytpionError = error
            } catch {
                XCTFail()
            }
        }
        then("it throws unknown error") {
            XCTAssertEqual(encrytpionError, SecureEncryptionError.unknown)
        }
        and("encrypted data is nil") {
            XCTAssertNil(encryptedData)
        }
    }
    
    func testEncryptionFailsWhenRetrievePrivateKeyFailsAndGenerateSecureKeyPassesButRetrievePublicKeyFails() {
        let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256
        var dataToEncrypt: Data?
        var encryptedData: Data?
        var encrytpionError: SecureEncryptionError?
        given("data to encrypt using algorithm \(algorithm)") {
            dataToEncrypt = "some_dummy_text".data(using: .utf8)
        }
        and("retrieve private key is failing") {
            FakeSecureEncryptionHelper.retievePrivateKeyError = SecureEncryptionError.failedToReadPrivateKey
        }
        and("generate secure access key is successful")
        but("retrieve public key is failing") {
            FakeSecureEncryptionHelper.shouldReturnPublicKey = false
        }
        when("data is encrypted") {
            do {
                encryptedData = try FakeSecureEncryptionHelper.encrypt(dataToEncrypt!, using: self.tagData)
            } catch let error as SecureEncryptionError {
                encrytpionError = error
            } catch {
                XCTFail()
            }
        }
        then("it throws unknown error") {
            XCTAssertEqual(encrytpionError, SecureEncryptionError.failedToReadPublicKey)
        }
        and("encrypted data is nil") {
            XCTAssertNil(encryptedData)
        }
    }
    
    func testEncryptionFailsWhenRetrievePrivateKeyPassesAndRetrievePublicKeyFailsAndGenerateSecureKeyPassesButRetrievePublicKeyStillFails() {
        let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256
        var dataToEncrypt: Data?
        var encryptedData: Data?
        var encrytpionError: SecureEncryptionError?
        given("data to encrypt using algorithm \(algorithm)") {
            dataToEncrypt = "some_dummy_text".data(using: .utf8)
        }
        and("a secure access key already exists") {
            _ = try? FakeSecureEncryptionHelper.generateSecureKeyFor(self.tagData)
        }
        and("retrieve private key passes")
        and("retrieve public key is failing") {
            FakeSecureEncryptionHelper.shouldReturnPublicKey = false
        }
        and("generate secure access key is passes")
        but("retrieve public key is still failing") {
            FakeSecureEncryptionHelper.shouldReturnPublicKey = false
        }
        when("data is encrypted") {
            do {
                encryptedData = try FakeSecureEncryptionHelper.encrypt(dataToEncrypt!, using: self.tagData)
            } catch let error as SecureEncryptionError {
                encrytpionError = error
            } catch {
                XCTFail()
            }
        }
        then("it throws failed to read public key error") {
            XCTAssertEqual(encrytpionError, SecureEncryptionError.failedToReadPublicKey)
        }
        and("encrypted data is nil") {
            XCTAssertNil(encryptedData)
        }
    }
    
    func testEncryptionFailsCreateEncryptedDataFails() {
        let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256
        var dataToEncrypt: Data?
        var encryptedData: Data?
        var encrytpionError: SecureEncryptionError?
        let cfError = CFErrorCreate(kCFAllocatorDefault, "" as CFErrorDomain, 1, nil)
        
        given("data to encrypt using algorithm \(algorithm)") {
            dataToEncrypt = "some_dummy_text".data(using: .utf8)
        }
        and("create encrypted data is failing") {
            FakeSecureEncryptionHelper.createEncryptedDataError = cfError
        }
        when("data is encrypted") {
            do {
                encryptedData = try FakeSecureEncryptionHelper.encrypt(dataToEncrypt!, using: self.tagData)
            } catch let error as SecureEncryptionError {
                encrytpionError = error
            } catch {
                XCTFail()
            }
        }
        then("it throws unknown error") {
            XCTAssertEqual(encrytpionError, SecureEncryptionError.failedToEncrypt(cfError))
        }
        and("encrypted data is nil") {
            XCTAssertNil(encryptedData)
        }
    }
    
    func testEncryptionSucceeds() {
        var dataToEncrypt: Data?
        var encryptedData: Data?
        var encrytpionError: SecureEncryptionError?
        
        given("data to encrypt") {
            dataToEncrypt = "some_dummy_text".data(using: .utf8)
        }
        when("data is encrypted") {
            do {
                encryptedData = try FakeSecureEncryptionHelper.encrypt(dataToEncrypt!, using: self.tagData)
            } catch let error as SecureEncryptionError {
                encrytpionError = error
            } catch {
                XCTFail()
            }
        }
        then("encryption succeeds") {
            XCTAssertNotNil(encryptedData)
        }
        and("no error is received") {
            XCTAssertNil(encrytpionError)
        }
    }
    
    func testDecryptionFailsWhenRetrievePrivateKeyFails() {
        var encryptedData: Data?
        var decryptedData: Data?
        var decrytpionError: SecureEncryptionError?
        given("encrypted data") {
            encryptedData = try! FakeSecureEncryptionHelper.encrypt("some_dummy_text".data(using: .utf8)!, using: self.tagData)
        }
        and("retrieve private key is failing") {
            FakeSecureEncryptionHelper.retievePrivateKeyError = SecureEncryptionError.failedToReadPrivateKey
        }
        when("data is decrypted") {
            do {
                decryptedData = try FakeSecureEncryptionHelper.decrypt(encryptedData!, using: self.tagData)
            } catch let error as SecureEncryptionError {
                decrytpionError = error
            } catch {
                XCTFail()
            }
        }
        then("it throws failed to read private key error") {
            XCTAssertEqual(decrytpionError, SecureEncryptionError.failedToReadPrivateKey)
        }
        and("decrypted data is nil") {
            XCTAssertNil(decryptedData)
        }
    }
    
    func testDecryptionFailsWhenAlgorithmIsUnsupported() {
        let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256
        var encryptedData: Data?
        var decryptedData: Data?
        var decrytpionError: SecureEncryptionError?
        given("encrypted data") {
            encryptedData = try! FakeSecureEncryptionHelper.encrypt("some_dummy_text".data(using: .utf8)!, using: self.tagData)
        }
        when("data is decrypted using algorithm \(algorithm)") {
            do {
                decryptedData = try FakeSecureEncryptionHelper.decrypt(encryptedData!, using: self.tagData, algorithm: algorithm)
            } catch let error as SecureEncryptionError {
                decrytpionError = error
            } catch {
                XCTFail()
            }
        }
        then("it throws unsupported algorithm error") {
            XCTAssertEqual(decrytpionError, SecureEncryptionError.unsupportedAlgorithm(algorithm))
        }
        and("decrypted data is nil") {
            XCTAssertNil(decryptedData)
        }
    }
    
    func testDecryptionFailsWhenCreateDecryptedDatFails() {
        var encryptedData: Data?
        var decryptedData: Data?
        var decrytpionError: SecureEncryptionError?
        let cfError = CFErrorCreate(kCFAllocatorDefault, "" as CFErrorDomain, 1, nil)
        
        given("encrypted data") {
            encryptedData = try! FakeSecureEncryptionHelper.encrypt("some_dummy_text".data(using: .utf8)!, using: self.tagData)
        }
        and("create decrypted data is failing") {
            FakeSecureEncryptionHelper.createDecryptedDataError = cfError
        }
        when("data is decrypted") {
            do {
                decryptedData = try FakeSecureEncryptionHelper.decrypt(encryptedData!, using: self.tagData)
            } catch let error as SecureEncryptionError {
                decrytpionError = error
            } catch {
                XCTFail()
            }
        }
        then("it throws failed to decrypt error") {
            XCTAssertEqual(decrytpionError, SecureEncryptionError.failedToDecrypt(cfError))
        }
        and("decrypted data is nil") {
            XCTAssertNil(decryptedData)
        }
    }
    
    func testCompleteEncryptionDecryptionScucceeds() {
        var stringToEncrypt: String!
        var encryptedData: Data?
        var decryptedData: Data?
        var encrytpionError: SecureEncryptionError?
        var decrytpionError: SecureEncryptionError?
        
        given("some string to encrypt") {
            stringToEncrypt = "String-to-Encrypt"
        }
        when("it is encrypted using standard algorithm") {
            do {
                encryptedData = try FakeSecureEncryptionHelper.encrypt(stringToEncrypt.data(using: .utf8)!, using: self.tagData)
            } catch let error as SecureEncryptionError {
                encrytpionError = error
            } catch {
                XCTFail()
            }
        }
        then("it succeeds without any error") {
            XCTAssertNil(encrytpionError)
            XCTAssertNotNil(encryptedData)
        }
        when("same encrypted data is decrypted") {
            do {
                decryptedData = try FakeSecureEncryptionHelper.decrypt(encryptedData!, using: self.tagData)
            } catch let error as SecureEncryptionError {
                decrytpionError = error
            } catch {
                XCTFail()
            }
        }
        then("it succeeds without any error") {
            XCTAssertNil(decrytpionError)
            XCTAssertNotNil(decryptedData)
        }
        and("original string is received") {
            XCTAssertEqual(stringToEncrypt, String(data: decryptedData!, encoding: .utf8))
        }
    }
}

class FakeSecureEncryptionHelper: SecureEncryptionHelper {
    static var generateSecureKeyError: Error? = nil
    static var accessControlError: CFError? = nil
    static var accessControlProtection: CFTypeRef? = nil
    static var accessControlFlags: SecAccessControlCreateFlags? = nil
    
    static var retievePrivateKeyError: Error? = nil
    
    static var copyItemError: OSStatus?
    static var copyItemQuery: CFDictionary?
    
    static var createRandomKeyError: CFError? = nil
    
    static var shouldReturnPublicKey: Bool = true
        
    static var createEncryptedDataError: CFError? = nil
    
    static var createDecryptedDataError: CFError? = nil
    
    override class func generateSecureKeyFor(_ tag: Data) throws -> SecKey {
        if let error = generateSecureKeyError {
            throw error
        }
        return try super.generateSecureKeyFor(tag)
    }
    
    override class func retrievePrivateKeyFor(_ tag: Data) throws -> SecKey {
        if let error = retievePrivateKeyError {
            throw error
        }
        return try super.retrievePrivateKeyFor(tag)
    }
    
    override class public func SecAccessControlCreateWithFlags(_ allocator: CFAllocator?, _ protection: CFTypeRef, _ flags: SecAccessControlCreateFlags, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> SecAccessControl? {
        if let errorValue = accessControlError {
            accessControlFlags = flags
            accessControlProtection = protection
            error?.pointee = Unmanaged.passRetained(errorValue)
            return nil
        }
        return super.SecAccessControlCreateWithFlags(allocator, protection, flags, error)
    }
    
    override class func SecKeyCreateRandomKey(_ parameters: CFDictionary, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> SecKey? {
        if let errorValue = createRandomKeyError {
            error?.pointee = Unmanaged.passRetained(errorValue)
            return nil
        }
        return super.SecKeyCreateRandomKey(parameters, error)
    }
    
    override class func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
        if let error = copyItemError {
            copyItemQuery = query
            return error
        }
        return super.SecItemCopyMatching(query, result)
    }
    
    override class func SecKeyCopyPublicKey(_ key: SecKey) -> SecKey? {
        if shouldReturnPublicKey {
            return super.SecKeyCopyPublicKey(key)
        }
        return nil
    }
    
    override class func SecKeyCreateEncryptedData(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ plaintext: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData? {
        if let errorValue = createEncryptedDataError {
            error?.pointee = Unmanaged.passRetained(errorValue)
            return nil
        }
        return super.SecKeyCreateEncryptedData(key, algorithm, plaintext, error)
    }
    
    override class func SecKeyCreateDecryptedData(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ ciphertext: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData? {
        if let errorValue = createDecryptedDataError {
            error?.pointee = Unmanaged.passRetained(errorValue)
            return nil
        }
        return super.SecKeyCreateDecryptedData(key, algorithm, ciphertext, error)
    }
}
