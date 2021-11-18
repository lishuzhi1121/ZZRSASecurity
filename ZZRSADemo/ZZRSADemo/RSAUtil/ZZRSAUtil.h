//
//  ZZRSAUtil.h
//  ZZRSADemo
//
//  Created by SandsLee on 2021/6/9.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN



@interface ZZRSAUtil : NSObject

#pragma mark - 加密

/// RSA 字符串公钥加密
/// @param plaintext 明文, 待加密的字符串
/// @param pubKey 公钥字符串
/// @return 密文, 加密后的base64字符串
+ (NSString *)zz_encrypt:(NSString *)plaintext publicKey:(NSString *)pubKey;

/// RSA 公钥文件加密
/// @param plaintext 明文, 待加密的字符串
/// @param pubKeyFilePath 公钥文件路径（支持der或者pem格式的密钥文件）
/// @return 密文, 加密后的base64字符串
+ (NSString *)zz_encrypt:(NSString *)plaintext publicKeyFilePath:(NSString *)pubKeyFilePath;

/// RSA 字符串私钥加密
/// @param plaintext 明文, 待加密的字符串
/// @param privKey 私钥字符串
/// @return 密文, 加密后的base64字符串
+ (NSString *)zz_encrypt:(NSString *)plaintext privateKey:(NSString *)privKey;

/// RSA 私钥文件加密
/// @param plaintext 明文, 待加密的字符串
/// @param privKeyFilePath 私钥文件路径（支持p12或者pem格式的密钥文件, pem的私钥需为pkcs8格式）
/// @param privKeyPasswd 私钥文件的密码, 没有密码则直接传nil
/// @return 密文, 加密后的base64字符串
+ (NSString *)zz_encrypt:(NSString *)plaintext
      privateKeyFilePath:(NSString *)privKeyFilePath
    privateKeyFilePasswd:(nullable NSString *)privKeyPasswd;;


#pragma mark - 解密

/// RSA 字符串公钥解密（私钥加密时用此解密）
/// @param ciphertext 密文, 需要解密的字符串
/// @param pubKey 公钥字符串
+ (NSString *)zz_decrypt:(NSString *)ciphertext publicKey:(NSString *)pubKey;

/// RSA 公钥文件解密（私钥加密时用此解密）
/// @param ciphertext 密文, 需要解密的字符串
/// @param pubKeyFilePath 公钥文件路径（支持der或者pem格式的密钥文件）
+ (NSString *)zz_decrypt:(NSString *)ciphertext publicKeyFilePath:(NSString *)pubKeyFilePath;

/// RSA 字符串私钥解密（公钥加密时用此解密）
/// @param ciphertext 密文, 需要解密的字符串
/// @param privKey 私钥字符串
+ (NSString *)zz_decrypt:(NSString *)ciphertext privateKey:(NSString *)privKey;

/// RSA 私钥文件解密（公钥加密时用此解密）
/// @param ciphertext 密文, 需要解密的字符串
/// @param privKeyFilePath 私钥文件路径（支持p12或者pem格式的密钥文件, pem的私钥需为pkcs8格式）
/// @param privKeyPasswd 私钥文件的密码, 没有密码则直接传nil
+ (NSString *)zz_decrypt:(NSString *)ciphertext
      privateKeyFilePath:(NSString *)privKeyFilePath
    privateKeyFilePasswd:(nullable NSString *)privKeyPasswd;

@end

NS_ASSUME_NONNULL_END
