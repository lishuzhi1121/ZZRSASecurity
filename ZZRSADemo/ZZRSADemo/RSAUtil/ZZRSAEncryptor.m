//
//  ZZRSAEncryptor.m
//  ZZRSADemo
//
//  Created by SandsLee on 2021/6/12.
//

#import "ZZRSAEncryptor.h"

// 共钥存储tag
static NSString *const ZZ_RSAEncryptor_PubKey_TAG    = @"ZZ_RSAEncryptor_PubKey_TAG";
// 私钥存储tag
static NSString *const ZZ_RSAEncryptor_PrivKey_TAG   = @"ZZ_RSAEncryptor_PrivKey_TAG";

// 公钥
static SecKeyRef ZZ_RSAEncryptor_PubKeyRef  = NULL;
// 私钥
static SecKeyRef ZZ_RSAEncryptor_PrivKeyRef = NULL;

@implementation ZZRSAEncryptor

#pragma mark - 加载公钥

+ (void)zz_loadPublicKeyString:(NSString *)pubKey {
    BOOL validKey = [pubKey isKindOfClass:[NSString class]] && (pubKey.length > 0);
    NSAssert(validKey, @"公钥字符串不合法!");
    
    if (ZZ_RSAEncryptor_PubKeyRef) CFRelease(ZZ_RSAEncryptor_PubKeyRef);
    
    ZZ_RSAEncryptor_PubKeyRef = [self _addPublicKey:pubKey];
    NSAssert(ZZ_RSAEncryptor_PubKeyRef != NULL, @"公钥加载失败!");
}

+ (void)zz_loadPublicKeyFile:(NSString *)pubKeyFile {
    BOOL validKey = [pubKeyFile isKindOfClass:[NSString class]] && (pubKeyFile.length > 0);
    NSAssert(validKey, @"公钥文件路径不合法!");
    if ([pubKeyFile hasSuffix:@".pem"]) {
        // PEM 格式的公钥文件
        NSError *error = nil;
        NSString *pemStr = [NSString stringWithContentsOfFile:pubKeyFile
                                                     encoding:NSUTF8StringEncoding
                                                        error:&error];
        BOOL success = ((error == nil) && (pemStr.length > 0));
        NSAssert(success, @"PEM 格式的公钥文件读取失败 error: %@", error.localizedDescription);
        if (ZZ_RSAEncryptor_PubKeyRef) CFRelease(ZZ_RSAEncryptor_PubKeyRef);
        
        ZZ_RSAEncryptor_PubKeyRef = [self _addPublicKey:pemStr];
        NSAssert(ZZ_RSAEncryptor_PubKeyRef != NULL, @"公钥PEM文件加载失败!");
    } else if ([pubKeyFile hasSuffix:@".der"]) {
        // DER 格式的公钥文件
        if (ZZ_RSAEncryptor_PubKeyRef) CFRelease(ZZ_RSAEncryptor_PubKeyRef);
        ZZ_RSAEncryptor_PubKeyRef = [self _getPublicKeyRefWithContentsOfFile:pubKeyFile];
        NSAssert(ZZ_RSAEncryptor_PubKeyRef != NULL, @"公钥DER文件加载失败!");
    } else {
        NSAssert(NO, @"不支持的公钥文件格式!仅支持 .pem 或 .der 格式的公钥文件.");
    }
}

+ (SecKeyRef)_addPublicKey:(NSString *)pubKey {
    NSString *key = pubKey;
    NSString *header = @"-----BEGIN PUBLIC KEY-----";
    NSString *footer = @"-----END PUBLIC KEY-----";
    key = [key stringByReplacingOccurrencesOfString:header withString:@""];
    key = [key stringByReplacingOccurrencesOfString:footer withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\r"  withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n"  withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t"  withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "   withString:@""];
    
    // This key will be base64 encoded, decode it.
    NSData *data = zz_base64_decode_str(key);
    data = [self _stripPublicKeyHeader:data];
    if (!data) {
        return NULL;
    }
    
    // A tag to read/write keychain storage
    NSData *d_tag = [NSData dataWithBytes:[ZZ_RSAEncryptor_PubKey_TAG UTF8String]
                                   length:ZZ_RSAEncryptor_PubKey_TAG.length];
    // Delete any old lingering key with the same tag
    NSMutableDictionary *publicKey = [NSMutableDictionary dictionary];
    [publicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setValue:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    // Add persistent version of the key to system keychain
    [publicKey setValue:data forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [publicKey setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    if (persistKey != nil) {
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return NULL;
    }
    
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:@YES forKey:(__bridge id)kSecReturnRef];
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = NULL;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
    if (status != noErr) {
        return NULL;
    }
    return keyRef;
}

+ (NSData *)_stripPublicKeyHeader:(NSData *)d_key {
    // Skip ASN.1 public key header
    if (![d_key isKindOfClass:[NSData class]] || d_key.length == 0) {
        return nil;
    }
    
    NSUInteger      len     = d_key.length;
    unsigned char   *c_key  = (unsigned char *)(d_key.bytes);
    unsigned int    idx     = 0;
    
    if (c_key[idx++] != 0x30) {
        return nil;
    }
    
    if (c_key[idx] > 0x80) {
        idx += c_key[idx] - 0x80 + 1;
    } else {
        idx++;
    }
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] = {
        0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x01, 0x05, 0x00,
    };
    if (memcmp(&c_key[idx], seqiod, 15)) {
        return nil;
    }
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) {
        return nil;
    }
    
    if (c_key[idx] > 0x80) {
        idx += c_key[idx] - 0x80 + 1;
    } else {
        idx++;
    }
    
    if (c_key[idx++] != '\0') {
        return nil;
    }
    
    NSData *ret = [NSData dataWithBytes:&c_key[idx] length:len - idx];
    return ret;
}

// 从 DER 文件加载公钥
+ (SecKeyRef)_getPublicKeyRefWithContentsOfFile:(NSString *)filePath {
    if (![filePath isKindOfClass:[NSString class]] || filePath.length == 0) {
        return NULL;
    }
    NSData *certData = [NSData dataWithContentsOfFile:filePath];
    if (!certData) {
        return NULL;
    }
    
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, (CFDataRef)certData);
    SecKeyRef keyRef = NULL;
    SecPolicyRef policyRef = NULL;
    SecTrustRef trustRef = NULL;
    if (cert != NULL) {
        policyRef = SecPolicyCreateBasicX509();
        if (policyRef) {
            OSStatus status = SecTrustCreateWithCertificates((CFTypeRef)cert, (CFTypeRef)policyRef, &trustRef);
            if (status != noErr) {
                NSLog(@"SecTrustCreateWithCertificates failed. Error Code: %d", status);
                return NULL;
            }
            SecTrustResultType trustResult = 0;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            status = SecTrustEvaluate(trustRef, &trustResult);
#pragma clang diagnostic pop
            if (status == noErr) {
                if (@available(iOS 14.0, *)) {
                    keyRef = SecTrustCopyKey(trustRef);
                } else {
                    keyRef = SecTrustCopyPublicKey(trustRef);
                }
            }
            // TODO: 自签名的der证书使用 SecTrustEvaluateWithError 方法评估会报错
//            if (@available(iOS 13.0, *)) {
//                CFErrorRef errorRef = NULL;
//                bool success = SecTrustEvaluateWithError(trustRef, &errorRef);
//                if (success && !errorRef) {
//                    if (@available(iOS 14.0, *)) {
//                        keyRef = SecTrustCopyKey(trustRef);
//                    } else {
//                        keyRef = SecTrustCopyPublicKey(trustRef);
//                    }
//                }
//            } else {
//
//            }
        }
    }
    
    if (trustRef)   CFRelease(trustRef);
    if (policyRef)  CFRelease(policyRef);
    if (cert)       CFRelease(cert);
    
    return keyRef;
}


#pragma mark - 加载私钥

+ (void)zz_loadPrivateKeyString:(NSString *)privKey {
    BOOL validKey = [privKey isKindOfClass:[NSString class]] && (privKey.length > 0);
    NSAssert(validKey, @"私钥字符串不合法!");
    
    if (ZZ_RSAEncryptor_PrivKeyRef) CFRelease(ZZ_RSAEncryptor_PrivKeyRef);
    
    ZZ_RSAEncryptor_PrivKeyRef = [self _addPrivateKey:privKey];
    NSAssert(ZZ_RSAEncryptor_PrivKeyRef != NULL, @"私钥加载失败!");
}

+ (void)zz_loadPrivateKeyFile:(NSString *)privKeyFile
                     password:(nullable NSString *)passwd {
    BOOL validKey = [privKeyFile isKindOfClass:[NSString class]] && (privKeyFile.length > 0);
    NSAssert(validKey, @"私钥文件路径: %@ 不合法!", privKeyFile);
    
    if (![passwd isKindOfClass:[NSString class]]) passwd = @"";
    
    if ([privKeyFile hasSuffix:@".pem"]) {
        // PEM 格式的私钥文件
        NSError *error = nil;
        NSString *pemStr = [NSString stringWithContentsOfFile:privKeyFile
                                                     encoding:NSUTF8StringEncoding
                                                        error:&error];
        BOOL success = ((error == nil) && (pemStr.length > 0));
        NSAssert(success, @"PEM 格式的私钥文件读取失败 error: %@", error.localizedDescription);
        if (ZZ_RSAEncryptor_PrivKeyRef) CFRelease(ZZ_RSAEncryptor_PrivKeyRef);
        
        ZZ_RSAEncryptor_PrivKeyRef = [self _addPrivateKey:pemStr];
        NSAssert(ZZ_RSAEncryptor_PrivKeyRef != NULL, @"私钥PEM文件加载失败!");
    } else if ([privKeyFile hasSuffix:@".p12"]) {
        // p12 格式的私钥文件
        if (ZZ_RSAEncryptor_PrivKeyRef) CFRelease(ZZ_RSAEncryptor_PrivKeyRef);
        
        ZZ_RSAEncryptor_PrivKeyRef = [self _getPrivateKeyRefWithContentsOfFile:privKeyFile
                                                                      password:passwd];
        NSAssert(ZZ_RSAEncryptor_PrivKeyRef != NULL, @"私钥p12文件加载失败!");
    } else {
        NSAssert(NO, @"不支持的私钥文件格式!仅支持 .pem 或 .p12 格式的私钥文件.");
    }
}

+ (SecKeyRef)_addPrivateKey:(NSString *)privKey {
    NSString *key = privKey;
    NSString *header        = @"-----BEGIN RSA PRIVATE KEY-----";
    NSString *footer        = @"-----END RSA PRIVATE KEY-----";
    NSString *header_pkcs8  = @"-----BEGIN PRIVATE KEY-----";
    NSString *footer_pkcs8  = @"-----END PRIVATE KEY-----";
    key = [key stringByReplacingOccurrencesOfString:header  withString:@""];
    key = [key stringByReplacingOccurrencesOfString:footer  withString:@""];
    key = [key stringByReplacingOccurrencesOfString:header_pkcs8 withString:@""];
    key = [key stringByReplacingOccurrencesOfString:footer_pkcs8 withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\r"   withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n"   withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t"   withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "    withString:@""];
    
    // This key will be base64 encoded, decode it.
    NSData *data = zz_base64_decode_str(key);
    data = [self _stripPrivateKeyHeader:data];
    if (!data) {
        return NULL;
    }
    
    // a tag to read/write keychain storage
    NSData *d_tag = [NSData dataWithBytes:[ZZ_RSAEncryptor_PrivKey_TAG UTF8String]
                                   length:ZZ_RSAEncryptor_PrivKey_TAG.length];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *privateKey = [NSMutableDictionary dictionary];
    [privateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [privateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [privateKey setValue:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)privateKey);
    
    // Add persistent version of the key to system keychain
    [privateKey setValue:data forKey:(__bridge id)kSecValueData];
    [privateKey setObject:(__bridge id)kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [privateKey setObject:@YES forKey:(__bridge id)kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    status = SecItemAdd((__bridge CFDictionaryRef)privateKey, &persistKey);
    if (persistKey) {
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return NULL;
    }
    
    [privateKey removeObjectForKey:(__bridge id)kSecValueData];
    [privateKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [privateKey setObject:@YES forKey:(__bridge id)kSecReturnRef];
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = NULL;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)privateKey, (CFTypeRef *)&keyRef);
    if (status != noErr) {
        return NULL;
    }
    
    return keyRef;
}

+ (NSData *)_stripPrivateKeyHeader:(NSData *)d_key {
    // Skip ASN.1 private key header
    if (!d_key) {
        return nil;
    }
    
    NSUInteger      len     = d_key.length;
    unsigned char   *c_key  = (unsigned char *)(d_key.bytes);
    unsigned int    idx     = 22; //magic byte at offset 22
    
    if (c_key[idx++] != 0x04) {
        return nil;
    }
    
    // calculate length of the key
    unsigned int c_len = c_key[idx++];
    int det = c_len & 0x80;
    if (!det) {
        c_len = c_len & 0x7f;
    } else {
        int byteCount = c_len & 0x7f;
        if (byteCount + idx > len) {
            // rsa length field longer than buffer
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum << 8) + *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }
    
    NSData *ret = [d_key subdataWithRange:NSMakeRange(idx, c_len)];
    return ret;
}

// 从 p12 文件加载私钥
+ (SecKeyRef)_getPrivateKeyRefWithContentsOfFile:(NSString *)filePath
                                        password:(NSString *)passwd {
    if (![filePath isKindOfClass:[NSString class]] || filePath.length == 0) {
        return NULL;
    }
    NSData *p12Data = [NSData dataWithContentsOfFile:filePath];
    if (!p12Data) {
        return NULL;
    }
    
    SecKeyRef privKeyRef = NULL;
    CFArrayRef rawItems = NULL;
    NSDictionary *options = @{
        (__bridge id)kSecImportExportPassphrase: passwd
    };
    OSStatus status = SecPKCS12Import((CFDataRef)p12Data, (__bridge CFDictionaryRef)options, &rawItems);
    if (status != noErr) {
        if (rawItems) CFRelease(rawItems);
        return NULL;
    }
    
    NSArray *items = (NSArray *)CFBridgingRelease(rawItems);
    if (items.count > 0) {
        NSDictionary *firstItem = items.firstObject;
        SecIdentityRef identityRef = (SecIdentityRef)CFBridgingRetain(firstItem[(__bridge id)kSecImportItemIdentity]);
        status = SecIdentityCopyPrivateKey(identityRef, &privKeyRef);
        if (identityRef) CFRelease(identityRef);
        if (status != noErr) privKeyRef = NULL;
    }
    
    return privKeyRef;
}


#pragma mark - 加密

+ (NSString *)zz_encrypt:(NSString *)plaintext {
    return [self zz_encrypt:plaintext byKeyType:ZZRSAKeyTypePublic];
}

+ (NSString *)zz_encrypt:(NSString *)plaintext byKeyType:(ZZRSAKeyType)type {
    if (![plaintext isKindOfClass:[NSString class]] || plaintext.length == 0) {
        return nil;
    }
    
    NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    SecKeyRef keyRef = NULL;
    BOOL isSign = NO;
    if (type == ZZRSAKeyTypePublic) {
        NSAssert(ZZ_RSAEncryptor_PubKeyRef != NULL, @"RSA公钥尚未加载, 请加载公钥后重试!");
        keyRef = ZZ_RSAEncryptor_PubKeyRef;
        isSign = NO;
    } else if (type == ZZRSAKeyTypePrivate) {
        NSAssert(ZZ_RSAEncryptor_PrivKeyRef != NULL, @"RSA私钥尚未加载, 请加载私钥后重试!");
        keyRef = ZZ_RSAEncryptor_PrivKeyRef;
        isSign = YES;
    } else {
        NSLog(@"KeyType is invalid!");
        return nil;
    }
    NSData *data = [self _encryptData:plainData withKeyRef:keyRef isSign:isSign];
    NSString *result = zz_base64_encode_data(data);
    return result;
}

// isSign: 私钥加密时传YES, 公钥加密时传NO
+ (NSData *)_encryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef isSign:(BOOL)isSign {
    if (!keyRef) {
        return nil;
    }
    
    const uint8_t *srcbuf = (const uint8_t *)(data.bytes);
    size_t srclen = (size_t)(data.length);
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11; // 明文长度不能超过密钥长度, 分块循环加密
    
    NSMutableData *ret = [NSMutableData data];
    for (int idx = 0; idx < srclen; idx += src_block_size) {
        size_t data_len = srclen - idx;
        if (data_len > src_block_size) {
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        if (isSign) {
            status = SecKeyRawSign(keyRef,
                                   kSecPaddingPKCS1,
                                   srcbuf + idx,
                                   data_len,
                                   outbuf,
                                   &outlen);
        } else {
            status = SecKeyEncrypt(keyRef,
                                   kSecPaddingPKCS1,
                                   srcbuf + idx,
                                   data_len,
                                   outbuf,
                                   &outlen);
        }
        if (status != noErr) {
            NSLog(@"SecKeyEncrypt failed. Error Code: %d", status);
            ret = nil;
            break;
        } else {
            [ret appendBytes:outbuf length:outlen];
        }
    }
    
    free(outbuf);
    return ret;
}


#pragma mark - 解密

+ (NSString *)zz_decrypt:(NSString *)ciphertext {
    return [self zz_decrypt:ciphertext byKeyType:ZZRSAKeyTypePrivate];
}

+ (NSString *)zz_decrypt:(NSString *)ciphertext byKeyType:(ZZRSAKeyType)type {
    if (![ciphertext isKindOfClass:[NSString class]] || ciphertext.length == 0) {
        return nil;
    }
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (![data isKindOfClass:[NSData class]] || data.length == 0) {
        return nil;
    }
    SecKeyRef keyRef = NULL;
    if (type == ZZRSAKeyTypePublic) {
        NSAssert(ZZ_RSAEncryptor_PubKeyRef != NULL, @"RSA公钥尚未加载, 请加载公钥后重试!");
        keyRef = ZZ_RSAEncryptor_PubKeyRef;
    } else if (type == ZZRSAKeyTypePrivate) {
        NSAssert(ZZ_RSAEncryptor_PrivKeyRef != NULL, @"RSA私钥尚未加载, 请加载私钥后重试!");
        keyRef = ZZ_RSAEncryptor_PrivKeyRef;
    } else {
        NSLog(@"KeyType is invalid!");
        return nil;
    }
    data = [self _decryptData:data withKeyRef:keyRef];
    NSString *result = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return result;
}

+ (NSData *)_decryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef {
    if (!keyRef) {
        return nil;
    }
    
    const uint8_t *srcbuf = (const uint8_t *)(data.bytes);
    size_t srclen = (size_t)(data.length);
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    UInt8 *outbuf = malloc(block_size);
    size_t src_block_size = block_size;
    
    NSMutableData *ret = [NSMutableData data];
    for (int idx = 0; idx < srclen; idx += src_block_size) {
        size_t data_len = srclen - idx;
        if (data_len > src_block_size) {
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(keyRef,
                               kSecPaddingNone,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen);
        if (status != noErr) {
            NSLog(@"SecKeyDecrypt failed. Error Code: %d", status);
            ret = nil;
            break;
        } else {
            // the actual decrypted data is in the middle, locate it!
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for (int i = 0; i < outlen; i++) {
                if (outbuf[i] == 0) {
                    if (idxFirstZero < 0) {
                        idxFirstZero = i;
                    } else {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            
            [ret appendBytes:&outbuf[idxFirstZero + 1] length:idxNextZero - idxFirstZero - 1];
        }
    }
    
    free(outbuf);
    return ret;
}


#pragma mark - BASE64

/// BASE64加密
/// @param data 明文数据
static NSString *zz_base64_encode_data(NSData *data) {
    if (![data isKindOfClass:[NSData class]] || data.length == 0) {
        return nil;
    }
    data = [data base64EncodedDataWithOptions:0];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

/// BASE64解密
/// @param str 密文字符串
static NSData *zz_base64_decode_str(NSString *str) {
    if (![str isKindOfClass:[NSString class]] || str.length == 0) {
        return nil;
    }
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return data;
}


@end
