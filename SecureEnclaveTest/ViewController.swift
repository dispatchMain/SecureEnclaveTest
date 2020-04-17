// Copyright (c) 2020 by Adarsh Rai. All rights reserved.

import UIKit

class ViewController: UIViewController {

    @IBOutlet weak var inputTextField: UITextField!
    @IBOutlet weak var outputLabel: UILabel!
    var encryptedData: Data?
    let tagData = "com.personal.SecureEnclaveTest".data(using: .utf8)!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        SecureEncryptionHelper.removeSecureKeyFor(tagData)
    }
    
    @IBAction func encrypt(_ sender: UIButton) {
        guard let text = inputTextField.text, text.count > 0 else {
            UIAlertController.showAlertWith(description: "No plain text to encrypt", actions: [.okAction], from: self)
            return
        }
        inputTextField.text = ""
        let data = text.data(using: .utf8)!
        encryptedData = try? SecureEncryptionHelper.encrypt(data, using: tagData)
        outputLabel.text = encryptedData?.toHexString()
    }
    
    @IBAction func decrypt(_ sender: UIButton) {
        guard let cipherTextData = encryptedData else {
            UIAlertController.showAlertWith(description: "No cipher text to decrypt", actions: [.okAction], from: self)
            return
        }
        let decryptedData = try? SecureEncryptionHelper.decrypt(cipherTextData, using: tagData)
        inputTextField.text = String(data: decryptedData!, encoding: .utf8)
    }
}

extension Data {
    public func toHexString() -> String {
        return reduce("", {$0 + String(format: "%02X ", $1)})
    }
}


extension UIAlertController {
    class func showAlertWith(title: String? = nil, description: String, actions: [UIAlertAction], from controller: UIViewController) {
        let alertController = UIAlertController(title: title, message: description, preferredStyle: .alert)
        actions.forEach { alertController.addAction($0) }
        controller.present(alertController, animated: true)
    }
}

extension UIAlertAction {
    class var okAction: UIAlertAction {
        return UIAlertAction(title: "Ok", style: .default)
    }
}
