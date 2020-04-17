// Copyright (c) 2020 by Adarsh Rai. All rights reserved.

import Foundation
import Security

public enum SecureEncryptionError: Error, Equatable {
    case unsupportedAlgorithm(SecKeyAlgorithm)
    case failedToGenerateSecureKey(CFError?)
    case failedToReadPrivateKey
    case failedToReadPublicKey
    case failedToEncrypt(CFError?)
    case failedToDecrypt(CFError?)
    case unknown
}

public enum EncryptionConstants {
    public static let AESAlgorithm         = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    public static let EncryptionKeySize    = 256
}

public class SecureEncryptionHelper: NSObject {
    
    private override init() {}
    
    
    /// This method is used to generate secure access key for encryption and decryption.
    /// - Parameter tag: A tag to identify the encryption key.
    /// - This method generates a private and public key pair used for encryption and decryption.
    ///   Since we are using symmetric encryption, these public and private key pair are used
    ///   to encrypt and decrypt the key used for encryption/decryption.
    class func generateSecureKeyFor(_ tag: Data) throws -> SecKey {
        
        var accessControlFlagError: Unmanaged<CFError>?
        
        /// Below method creates the security parameters that will be applicable for creating and access the generated key.
        /// - Parameter kCFAllocatorDefault: Default allocator for CoreFoundation objects
        /// - Parameter kSecAttrAccessibleWhenUnlockedThisDeviceOnly: This parameter ensures that generated key is only available when device is unlocked and is not synced to other
        ///  devices of user via iCloud.
        /// - Parameter privateKeyUsage: This parameter ensures that key is available for signing and verifying the signature.
        let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     .privateKeyUsage,
                                                     &accessControlFlagError)
        guard let accessControlFlags = access else {
            throw SecureEncryptionError.failedToGenerateSecureKey(accessControlFlagError?.takeRetainedValue())
        }
        
        /// Below attributes are used to create and query the generated key. This also defines the configuration and sotrage of the key.
        /// - Parameter kSecAttrKeyTypeECSECPrimeRandom: This parameter ensures that elliptic curve keys are generated. This is the only type supported for keys stored in Secure Enclave.
        /// - Parameter kSecAttrKeySizeInBits: This attribute controls the size of key. We are using 256 bits here because we want to use AES-256 which requires 256 bit key size. Also,
        /// Secure Enclave only supports elliptic curve keys of 256 bit size.
        /// - Parameter kSecAttrTokenID: This attribute controls storage of the generated key. Currently it only supports kSecAttrTokenIDSecureEnclave as value which ensures that generated key
        /// is stored inside SecureEnclave and when the key is retrieved, it only returns a reference to the key instead of key data. This mechanism ensures that the key never leaves the Secure Enclave instead Encryption and Decryption methods pass the data to Secure Enclave with reference to the key and encryption/decryption takes place inside the Secure Enclave.
        /// - Parameter kSecPrivateKeyAttrs: This attribute contains private key attributes.
        let attributes: [String: Any] = [
            kSecAttrKeyType as String           : kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String     : EncryptionConstants.EncryptionKeySize,
            kSecAttrTokenID as String           : kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String       : [
                kSecAttrIsPermanent as String       : true,
                kSecAttrApplicationTag as String    : tag,
                kSecAttrAccessControl as String     : accessControlFlags
            ]
        ]
        
        var keyGenerationError: Unmanaged<CFError>?
        /// Below method is used to generate the private and public key pair based on the attributes we have defined above. If the keys are generated successfully, it returns the private key.
        /// But since we are using Secure Enclave to store the key, it only returns a reference to the actual key in Secure Enclave.
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &keyGenerationError) else {
            throw SecureEncryptionError.failedToGenerateSecureKey(keyGenerationError?.takeRetainedValue())
        }
        
        return privateKey
    }
    
    /// This method deletes the generated key based on provide key tag.
    /// - Parameter tag: Tag used to identify the key to be deleted.
    @discardableResult
    class func removeSecureKeyFor(_ tag: Data) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tag
        ]
        return SecItemDelete(query as CFDictionary)
    }
    
    
    /// This method reads the private key identified by the provide key tag. Since we are using Secure Enclave to store the keys, it only returns a pointet to the actual key.
    /// - Parameter tag: Tag to identify the key to be retrieved.
    class func retrievePrivateKeyFor(_ tag: Data) throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tag,
            kSecAttrKeyType as String           : kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String             : true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            throw SecureEncryptionError.failedToReadPrivateKey
        }
        
        return item as! SecKey
    }
    
    
    /// This method is used to retrieve the public key corresponding to the private key provided.
    /// - Parameter privateKey: The private key of which public key is required to be retrieved.
    class func retrievePublicKeyFor(_ privateKey: SecKey) throws -> SecKey {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEncryptionError.failedToReadPublicKey
        }
        return publicKey
    }
    
    
    /// This method is used to encrypt provided data using a secure access key generated and stored inside Secure Enclave.
    /// - Parameters:
    ///   - plainTextData: Data to be encrypted.
    ///   - keyTag: Tag to identify the generated key.
    ///   - algorithm: Algorithm to be used for encryption.
    /// - This mehod is used to encrypt provided data. It creates a secure access key pair, if does not already exist, using the provided keyTag. It also checks that generated key can be used for
    ///   for encryption using provided algorithm. Otherwise, it throws `SecureEncryptionError.unsupportedAlgorithm` error.
    public class func encrypt(_ plainTextData: Data, using keyTag: Data, algorithm: SecKeyAlgorithm = EncryptionConstants.AESAlgorithm) throws -> Data {
        let publicKeyForEncryption: SecKey
        do {
            let privateKey = try retrievePrivateKeyFor(keyTag)
            publicKeyForEncryption = try retrievePublicKeyFor(privateKey)
        } catch let error as SecureEncryptionError where error == .failedToReadPrivateKey || error == .failedToReadPublicKey {
            //Print log for public key failure since that should not happen.
            let privateKey = try generateSecureKeyFor(keyTag)
            publicKeyForEncryption = try retrievePublicKeyFor(privateKey)
        }
        
        guard SecKeyIsAlgorithmSupported(publicKeyForEncryption, .encrypt, algorithm) else {
            throw SecureEncryptionError.unsupportedAlgorithm(algorithm)
        }
        
        var encryptionError: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(publicKeyForEncryption, algorithm, plainTextData as CFData, &encryptionError) else {
            throw SecureEncryptionError.failedToEncrypt(encryptionError?.takeRetainedValue())
        }
        return encryptedData as Data
    }
    
    
    /// A method to decrypt already encrypted data.
    /// - Parameters:
    ///   - encryptedData: Data to be decrypted.
    ///   - keyTag: Tag to be used to identify the key to be used for decryption.
    ///   - algorithm: Algorithm to be used for decryption. It must be same as the one used for decryption.
    public class func decrypt(_ encryptedData: Data, using keyTag: Data, algorithm: SecKeyAlgorithm = EncryptionConstants.AESAlgorithm) throws -> Data {
        let privateKeyForDecryption = try retrievePrivateKeyFor(keyTag)
        guard SecKeyIsAlgorithmSupported(privateKeyForDecryption, .decrypt, algorithm) else {
            throw SecureEncryptionError.unsupportedAlgorithm(algorithm)
        }
        
        var decryptionError: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(privateKeyForDecryption, algorithm, encryptedData as CFData, &decryptionError) else {
            throw SecureEncryptionError.failedToDecrypt(decryptionError?.takeRetainedValue())
        }
        return decryptedData as Data
    }
}

#if DEBUG
/**
 * Below methods only exist to be able to override them in Unit Tests.
 */
extension SecureEncryptionHelper {
    @inline(__always)
    @objc class func SecAccessControlCreateWithFlags(_ allocator: CFAllocator?, _ protection: CFTypeRef, _ flags: SecAccessControlCreateFlags, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> SecAccessControl? {
        return Security.SecAccessControlCreateWithFlags(allocator, protection, flags, error)
    }
    
    @inline(__always)
    @objc class func SecKeyCreateRandomKey(_ parameters: CFDictionary, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> SecKey? {
        return Security.SecKeyCreateRandomKey(parameters, error)
    }
    
    @inline(__always)
    @objc class func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
        return Security.SecItemCopyMatching(query, result)
    }
    
    @inline(__always)
    @objc class func SecKeyCopyPublicKey(_ key: SecKey) -> SecKey? {
        return Security.SecKeyCopyPublicKey(key)
    }
    
    @inline(__always)
    @objc class func SecKeyCreateEncryptedData(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ plaintext: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData? {
        return Security.SecKeyCreateEncryptedData(key, algorithm, plaintext, error)
    }
    
    @inline(__always)
    @objc class func SecKeyCreateDecryptedData(_ key: SecKey, _ algorithm: SecKeyAlgorithm, _ ciphertext: CFData, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData? {
        return Security.SecKeyCreateDecryptedData(key, algorithm, ciphertext, error)
    }
}
#endif
