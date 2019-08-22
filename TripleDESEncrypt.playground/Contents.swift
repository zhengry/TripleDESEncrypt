import UIKit
import CommonCrypto


extension String {
    
    /**
     3DES的加密过程 和 解密过程
     
     - parameter op : CCOperation： 加密还是解密
     CCOperation（kCCEncrypt）加密
     CCOperation（kCCDecrypt) 解密
     
     - parameter key: 加解密key
     - returns      : 返回加密或解密的参数
     */
    func tripleDESEncryptOrDecrypt(op: CCOperation,key: String) -> String? {
        
        let iv:String? = ""
        // Key
        let keyData: NSData = (key as NSString).data(using: String.Encoding.utf8.rawValue)! as NSData
        let keyBytes = UnsafeRawPointer(keyData.bytes)
        
        // 加密或解密的内容
        var data: NSData = NSData()
        if op == CCOperation(kCCEncrypt) {
            data  = (self as NSString).data(using: String.Encoding.utf8.rawValue)! as NSData
        }
        else {
            data = NSData(base64Encoded: self, options: NSData.Base64DecodingOptions.ignoreUnknownCharacters)!
        }
        
        let dataLength = size_t(data.length)
        let dataBytes = UnsafeRawPointer(data.bytes)
        
        // 返回数据
        let cryptData = NSMutableData(length: Int(dataLength) + kCCBlockSize3DES)
        let cryptPointer = UnsafeMutableRawPointer(cryptData!.mutableBytes)
        let cryptLength = size_t(cryptData!.length)
        
        //  可选 的初始化向量
        let viData :NSData = (iv! as NSString).data(using: String.Encoding.utf8.rawValue)! as NSData
        let viDataBytes = UnsafeRawPointer(viData.bytes)
        
        // 特定的几个参数
        let keyLength = size_t(kCCKeySize3DES)
        let operation: CCOperation = UInt32(op)
        let algoritm: CCAlgorithm = UInt32(kCCAlgorithm3DES)
        let options: CCOptions = UInt32(kCCOptionECBMode + kCCOptionPKCS7Padding)
        
        var numBytesCrypted :size_t = 0
        
        let cryptStatus = CCCrypt(operation, // 加密还是解密
            algoritm, // 算法类型
            options,  // 密码块的设置选项
            keyBytes, // 秘钥的字节
            keyLength, // 秘钥的长度
            viDataBytes, // 可选初始化向量的字节
            dataBytes, // 加解密内容的字节
            dataLength, // 加解密内容的长度
            cryptPointer, // output data buffer
            cryptLength,  // output data length available
            &numBytesCrypted) // real output data length
        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            
            cryptData!.length = Int(numBytesCrypted)
            if op == CCOperation(kCCEncrypt)  {
                let base64cryptString = cryptData?.base64EncodedString(options: [])
                return base64cryptString
            }
            else {
                let base64cryptString = String.init(data: cryptData! as Data, encoding: String.Encoding(rawValue: String.Encoding.utf8.rawValue))
                return base64cryptString
            }
        }
        return nil
    }
}

func md5String(text:String)-> String{
    let strLen = CUnsignedInt(text.lengthOfBytes(using: String.Encoding.utf8))
    let digestLen = Int(CC_MD5_DIGEST_LENGTH)
    let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
    CC_MD5(text, strLen, result)
    let hash = NSMutableString()
    for i in 0 ..< digestLen {
        hash.appendFormat("%02x", result[i])
    }
    result.deinitialize(count: text.count)
    return String(format: hash as String)
}

var key = "012438BF-4E53-458F-8A07-D7DDFC8FA1F8190808173932337_"
let keyStr = md5String(text: key)
key = String(keyStr.prefix(24))


let text = "1234qwer"
var encryptText:String?
var decrptText:String?
encryptText = text.tripleDESEncryptOrDecrypt(op: CCOperation(kCCEncrypt), key: key)
decrptText = "labWVwRfO4BSWJA2swHTOg==".tripleDESEncryptOrDecrypt(op: CCOptions(kCCDecrypt), key: key)
print("加密结果："+(encryptText ?? "加密失败"))
print("解密结果："+(decrptText ?? "解密失败"))

