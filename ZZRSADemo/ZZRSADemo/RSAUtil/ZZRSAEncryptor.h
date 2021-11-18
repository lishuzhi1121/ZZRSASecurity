//
//  ZZRSAEncryptor.h
//  ZZRSADemo
//
//  Created by SandsLee on 2021/6/12.
//

/**
 密钥文件生成:
 PEM 格式的私钥: openssl genrsa -out rsa_1024_private.pem 1024
 PEM 格式的公钥: openssl rsa -in rsa_1024_private.pem -pubout -out rsa_1024_public.pem
 
 iOS 用der和p12格式的公钥和私钥生成步骤:
 1. 生成私钥: openssl genrsa -out rsa_1024_private.pem 1024
 2. 生成证书请求文件: openssl req -new -out rsa_1024_csr.csr -key rsa_1024_private.pem -keyform PEM
 3. 请求证书: openssl x509 -req -in rsa_1024_csr.csr -out rsa_1024_cert.crt -signkey rsa_1024_private.pem -CAcreateserial -days 32120
 4. 导出der公钥文件: openssl x509 -in rsa_1024_cert.crt -outform der -out rsa_1024_public.der
 5. 导出p12私钥文件: pkcs12 -export -clcerts -in rsa_1024_cert.crt -inkey rsa_1024_private.pem -out rsa_1024_private.p12
 */


#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// RSA 密钥类型定义
typedef NS_ENUM(NSUInteger, ZZRSAKeyType) {
    ZZRSAKeyTypePublic = 0, // 公钥类型
    ZZRSAKeyTypePrivate,    // 私钥类型
};


@interface ZZRSAEncryptor : NSObject

#pragma mark - 加载密钥

/// 加载字符串公钥
/// @param pubKey 公钥字符串
+ (void)zz_loadPublicKeyString:(NSString *)pubKey;

/// 加载公钥文件
/// @param pubKeyFile 公钥文件路径（支持der或者pem格式的密钥文件, der必须为X.509格式）
+ (void)zz_loadPublicKeyFile:(NSString *)pubKeyFile;

/// 加载字符串私钥
/// @param privKey 私钥字符串
+ (void)zz_loadPrivateKeyString:(NSString *)privKey;

/// 加载私钥文件
/// @param privKeyFile 私钥文件路径（支持p12或者pem格式的密钥文件, pem的私钥需为pkcs8格式）
/// @param passwd 私钥文件密码, 没有密码则直接传nil
+ (void)zz_loadPrivateKeyFile:(NSString *)privKeyFile
                     password:(nullable NSString *)passwd;

#pragma mark - 加密 解密

/// RSA 加密, 默认公钥加密
/// @param plaintext 明文, 待加密的字符串
/// @return 密文, 加密后的base64字符串
+ (NSString *)zz_encrypt:(NSString *)plaintext;

/// RSA 加密
/// @param plaintext 明文, 待加密的字符串
/// @param type 密钥类型, 选择公钥加密则就要选择私钥解密, 选择私钥加密则就要选择公钥解密
/// @return 密文, 加密后的base64字符串
+ (NSString *)zz_encrypt:(NSString *)plaintext byKeyType:(ZZRSAKeyType)type;

/// RSA 解密, 默认私钥解密
/// @param ciphertext 密文, 需要解密的字符串
+ (NSString *)zz_decrypt:(NSString *)ciphertext;

/// RSA 解密
/// @param ciphertext 密文, 需要解密的字符串
/// @param type 密钥类型, 加密时选择的是公钥则解密就选择私钥, 加密时选择的是私钥则解密就选择公钥
+ (NSString *)zz_decrypt:(NSString *)ciphertext byKeyType:(ZZRSAKeyType)type;

@end

NS_ASSUME_NONNULL_END
