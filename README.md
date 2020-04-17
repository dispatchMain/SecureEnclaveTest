# SecureEnclaveTest
An app demonstrating usage of keys in iOS Secure Enclave for Symmetric Encryption and Decryption.

# Background
While implementing cryptographic operations like symmtric encryption and decryption, given the intricacies involved, it is very easy for developers to make mistakes, especially if they are not experts in cryptography. For example, generating keys of right size using random enough inputs, generating correct initialization vector, storing the generated keys securely and so on. Therefore, Apple has come up with APIs take care of all these intricacies internally and only leaves developers with choosing right alogorithm and their key size.

# Sample Code
 This sample code demonstrates how easy it is to encrypt and decrypt data using industry standard algorithms in few lines of code.

This app generates a public/private key pair in iOS Secure Enclave and then uses the keys to encrypt and decrypt the provided data. Since it is a symmtric encryption, the public/private key pair are used to encrypt and decrypt the symmetric key which is generated when ecryption is performed and then attached to the encrypted data by encrypting the secure key using public key. Then when data is decrypted using public key, first the symmetric key is used to decrypt the attched symmtric key which is turn is used to decrypt the cipher text.

Code is well documented and thoroughly unit tested.

It is suggested to read below Apple developer documents, from where this code is inspired, to understand it best.

[Generating Cyptographic Key](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys)  
[Storing Keys in Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave)  
[Getting an Existing Key](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/getting_an_existing_key)  
[Using Keys for Encryption](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/using_keys_for_encryption)