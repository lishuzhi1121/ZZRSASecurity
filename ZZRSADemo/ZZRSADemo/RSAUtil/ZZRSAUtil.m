//
//  ZZRSAUtil.m
//  ZZRSADemo
//
//  Created by SandsLee on 2021/6/9.
//

#import "ZZRSAUtil.h"

// 共钥存储tag
static NSString *const ZZ_RSAUtil_PubKey_TAG    = @"ZZ_RSAUtil_PubKey_TAG";
// 私钥存储tag
static NSString *const ZZ_RSAUtil_PrivKey_TAG   = @"ZZ_RSAUtil_PrivKey_TAG";

@implementation ZZRSAUtil

#pragma mark - 加密

// 公钥加密字符串
+ (NSString *)zz_encrypt:(NSString *)plaintext publicKey:(NSString *)pubKey {
    if (![plaintext isKindOfClass:[NSString class]] || plaintext.length == 0
        || ![pubKey isKindOfClass:[NSString class]] || pubKey.length == 0) {
        return nil;
    }
    NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [self _encryptData:plainData publicKey:pubKey];
    NSString *ret = zz_base64_encode_data(data);
    return ret;
}

// 公钥文件加密字符串
+ (NSString *)zz_encrypt:(NSString *)plaintext publicKeyFilePath:(NSString *)pubKeyFilePath {
    if (![plaintext isKindOfClass:[NSString class]] || plaintext.length == 0
        || ![pubKeyFilePath isKindOfClass:[NSString class]] || pubKeyFilePath.length == 0) {
        return nil;
    }
    NSString *result = nil;
    if ([pubKeyFilePath hasSuffix:@".pem"]) {
        // pem 格式的公钥文件
        NSString *pubKey = [self _readPubKeyFromPemFile:pubKeyFilePath];
        NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
        NSData *data = [self _encryptData:plainData publicKey:pubKey];
        result = zz_base64_encode_data(data);
    } else if ([pubKeyFilePath hasSuffix:@".der"]) {
        // der 格式的公钥文件
        SecKeyRef pubKeyRef = [self _getPublicKeyRefWithContentsOfFile:pubKeyFilePath];
        NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
        NSData *data = [self _encryptData:plainData withKeyRef:pubKeyRef isSign:NO];
        result = zz_base64_encode_data(data);
    }
    
    return result;
}

+ (NSString *)_readPubKeyFromPemFile:(NSString *)pemFilePath {
    if (![pemFilePath isKindOfClass:[NSString class]] || pemFilePath.length == 0
        || ![[NSFileManager defaultManager] fileExistsAtPath:pemFilePath]) {
        return nil;
    }
    NSError *error = nil;
    NSString *pemStr = [NSString stringWithContentsOfFile:pemFilePath
                                                 encoding:NSUTF8StringEncoding
                                                    error:&error];
    if (error || pemStr.length == 0) {
        NSLog(@"readPubKeyFromPemFile error: %@", error.localizedDescription);
        return nil;
    }
    NSString *header = @"-----BEGIN PUBLIC KEY-----";
    NSString *footer = @"-----END PUBLIC KEY-----";
    pemStr = [pemStr stringByReplacingOccurrencesOfString:header withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:footer withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\r"  withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\n"  withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\t"  withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@" "   withString:@""];
    
    return pemStr;
}

+ (SecKeyRef)_getPublicKeyRefWithContentsOfFile:(NSString *)filePath {
    if (![filePath isKindOfClass:[NSString class]] || filePath.length == 0
        || ![[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
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
            if (@available(iOS 13.0, *)) {
                CFErrorRef errorRef = NULL;
                bool success = SecTrustEvaluateWithError(trustRef, &errorRef);
                if (success && !errorRef) {
                    if (@available(iOS 14.0, *)) {
                        keyRef = SecTrustCopyKey(trustRef);
                    } else {
                        keyRef = SecTrustCopyPublicKey(trustRef);
                    }
                }
            } else {
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
            }
        }
    }
    
    if (trustRef)   CFRelease(trustRef);
    if (policyRef)  CFRelease(policyRef);
    if (cert)       CFRelease(cert);
    
    return keyRef;
}

// 私钥加密字符串
+ (NSString *)zz_encrypt:(NSString *)plaintext privateKey:(NSString *)privKey {
    if (![plaintext isKindOfClass:[NSString class]] || plaintext.length == 0
        || ![privKey isKindOfClass:[NSString class]] || privKey.length == 0) {
        return nil;
    }
    NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [self _encryptData:plainData privateKey:privKey];
    NSString *ret = zz_base64_encode_data(data);
    return ret;
}

// 私钥文件加密字符串
+ (NSString *)zz_encrypt:(NSString *)plaintext
      privateKeyFilePath:(NSString *)privKeyFilePath
    privateKeyFilePasswd:(NSString *)privKeyPasswd {
    if (![plaintext isKindOfClass:[NSString class]]
        || plaintext.length == 0
        || ![privKeyFilePath isKindOfClass:[NSString class]]
        || privKeyFilePath.length == 0) {
        return nil;
    }
    if (![privKeyPasswd isKindOfClass:[NSString class]]) privKeyPasswd = @"";
    
    NSString *result = nil;
    if ([privKeyFilePath hasSuffix:@".pem"]) {
        // pem 格式的私钥文件
        NSString *privKey = [self _readPrivKeyFromPemFile:privKeyFilePath];
        NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
        NSData *data = [self _encryptData:plainData privateKey:privKey];
        result = zz_base64_encode_data(data);
    } else if ([privKeyFilePath hasSuffix:@".p12"]) {
        // der 格式的私钥文件
        SecKeyRef privKeyRef = [self _getPrivateKeyRefWithContentsOfFile:privKeyFilePath
                                                                password:privKeyPasswd];
        NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
        NSData *data = [self _encryptData:plainData withKeyRef:privKeyRef isSign:YES];
        result = zz_base64_encode_data(data);
    }
    
    return result;
}

// 公钥加密数据
+ (NSData *)_encryptData:(NSData *)data publicKey:(NSString *)pubKey {
    if (![data isKindOfClass:[NSData class]] || data.length == 0
        ||![pubKey isKindOfClass:[NSString class]] || pubKey.length == 0) {
        return nil;
    }
    SecKeyRef keyRef = [self _addPublicKey:pubKey];
    NSData *enData = [self _encryptData:data withKeyRef:keyRef isSign:NO];
    if (keyRef) {
        CFRelease(keyRef);
    }
    
    return enData;
}

// 私钥加密数据
+ (NSData *)_encryptData:(NSData *)data privateKey:(NSString *)privKey {
    if (![data isKindOfClass:[NSData class]] || data.length == 0
        ||![privKey isKindOfClass:[NSString class]] || privKey.length == 0) {
        return nil;
    }
    SecKeyRef keyRef = [self _addPrivateKey:privKey];
    NSData *enData = [self _encryptData:data withKeyRef:keyRef isSign:YES];
    if (keyRef) {
        CFRelease(keyRef);
    }
    
    return enData;
}

+ (SecKeyRef)_addPublicKey:(NSString *)pubKey {
    NSString *key = nil;
    NSRange spos = [pubKey rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    NSRange epos = [pubKey rangeOfString:@"-----END PUBLIC KEY-----"];
    if (spos.location != NSNotFound && epos.location != NSNotFound) {
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e - s);
        key = [pubKey substringWithRange:range];
    } else {
        key = pubKey;
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    // This key will be base64 encoded, decode it.
    NSData *data = zz_base64_decode_str(key);
    data = [self _stripPublicKeyHeader:data];
    if (!data) {
        return nil;
    }
    
    // A tag to read/write keychain storage
    NSData *d_tag = [NSData dataWithBytes:[ZZ_RSAUtil_PubKey_TAG UTF8String]
                                   length:ZZ_RSAUtil_PubKey_TAG.length];
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
        return nil;
    }
    
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:@YES forKey:(__bridge id)kSecReturnRef];
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
    if (status != noErr) {
        return nil;
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

// 公钥解密字符串
+ (NSString *)zz_decrypt:(NSString *)ciphertext publicKey:(NSString *)pubKey {
    if (![ciphertext isKindOfClass:[NSString class]] || ciphertext.length == 0
        || ![pubKey isKindOfClass:[NSString class]] || pubKey.length == 0) {
        return nil;
    }
    NSData *data = [[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters];
    data = [self _decrypyData:data publicKey:pubKey];
    NSString *ret = [[NSString alloc] initWithData:data
                                          encoding:NSUTF8StringEncoding];
    
    return ret;
}

// 公钥文件解密字符串
+ (NSString *)zz_decrypt:(NSString *)ciphertext publicKeyFilePath:(NSString *)pubKeyFilePath {
    if (![ciphertext isKindOfClass:[NSString class]]
        || ciphertext.length == 0
        || ![pubKeyFilePath isKindOfClass:[NSString class]]
        || pubKeyFilePath.length == 0) {
        return nil;
    }
    
    NSString *result = nil;
    if ([pubKeyFilePath hasSuffix:@".pem"]) {
        // pem 格式的公钥文件
        NSString *pubKey = [self _readPubKeyFromPemFile:pubKeyFilePath];
        NSData *data = [[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters];
        data = [self _decrypyData:data publicKey:pubKey];
        result = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    } else if ([pubKeyFilePath hasSuffix:@".der"]) {
        // der 格式的公钥文件
        SecKeyRef pubKeyRef = [self _getPublicKeyRefWithContentsOfFile:pubKeyFilePath];
        NSData *data = [[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters];
        data = [self _decryptData:data withKeyRef:pubKeyRef];
        result = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    
    return result;
}

// 私钥解密字符串
+ (NSString *)zz_decrypt:(NSString *)ciphertext privateKey:(NSString *)privKey {
    if (![ciphertext isKindOfClass:[NSString class]] || ciphertext.length == 0
        || ![privKey isKindOfClass:[NSString class]] || privKey.length == 0) {
        return nil;
    }
    NSData *data = [[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters];
    data = [self _decrypyData:data privateKey:privKey];
    NSString *ret = [[NSString alloc] initWithData:data
                                          encoding:NSUTF8StringEncoding];
    
    return ret;
}

// 私钥文件解密字符串
+ (NSString *)zz_decrypt:(NSString *)ciphertext
      privateKeyFilePath:(NSString *)privKeyFilePath
    privateKeyFilePasswd:(NSString *)privKeyPasswd {
    if (![ciphertext isKindOfClass:[NSString class]]
        || ciphertext.length == 0
        || ![privKeyFilePath isKindOfClass:[NSString class]]
        || privKeyFilePath.length == 0) {
        return nil;
    }
    if (![privKeyPasswd isKindOfClass:[NSString class]]) privKeyPasswd = @"";
    
    NSString *result = nil;
    if ([privKeyFilePath hasSuffix:@".pem"]) {
        // pem 格式的私钥文件
        NSString *privKey = [self _readPrivKeyFromPemFile:privKeyFilePath];
        NSData *data = [[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters];
        data = [self _decrypyData:data privateKey:privKey];
        result = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    } else if ([privKeyFilePath hasSuffix:@".p12"]) {
        // p12 格式的私钥文件
        SecKeyRef privKeyRef = [self _getPrivateKeyRefWithContentsOfFile:privKeyFilePath
                                                                password:privKeyPasswd];
        NSData *data = [[NSData alloc] initWithBase64EncodedString:ciphertext options:NSDataBase64DecodingIgnoreUnknownCharacters];
        data = [self _decryptData:data withKeyRef:privKeyRef];
        result = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    
    return result;
}

+ (NSString *)_readPrivKeyFromPemFile:(NSString *)pemFilePath {
    if (![pemFilePath isKindOfClass:[NSString class]] || pemFilePath.length == 0
        || ![[NSFileManager defaultManager] fileExistsAtPath:pemFilePath]) {
        return nil;
    }
    NSError *error = nil;
    NSString *pemStr = [NSString stringWithContentsOfFile:pemFilePath
                                                 encoding:NSUTF8StringEncoding
                                                    error:&error];
    if (error || pemStr.length == 0) {
        NSLog(@"readPrivKeyFromPemFile error: %@", error.localizedDescription);
        return nil;
    }
    NSString *header = @"-----BEGIN RSA PRIVATE KEY-----";
    NSString *footer = @"-----END RSA PRIVATE KEY-----";
    NSString *header_pkcs8 = @"-----BEGIN PRIVATE KEY-----";
    NSString *footer_pkcs8 = @"-----END PRIVATE KEY-----";
    pemStr = [pemStr stringByReplacingOccurrencesOfString:header withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:footer withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:header_pkcs8 withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:footer_pkcs8 withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\r"  withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\n"  withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\t"  withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@" "   withString:@""];
    
    return pemStr;
}

+ (SecKeyRef)_getPrivateKeyRefWithContentsOfFile:(NSString *)filePath
                                        password:(NSString *)passwd {
    if (![filePath isKindOfClass:[NSString class]] || filePath.length == 0
        || ![[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
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

// 公钥解密数据
+ (NSData *)_decrypyData:(NSData *)data publicKey:(NSString *)pubKey {
    if (![data isKindOfClass:[NSData class]] || data.length == 0
        || ![pubKey isKindOfClass:[NSString class]] || pubKey.length == 0) {
        return nil;
    }
    SecKeyRef keyRef = [self _addPublicKey:pubKey];
    NSData *deData = [self _decryptData:data withKeyRef:keyRef];
    if (keyRef) {
        CFRelease(keyRef);
    }
    
    return deData;
}

// 私钥解密数据
+ (NSData *)_decrypyData:(NSData *)data privateKey:(NSString *)privKey {
    if (![data isKindOfClass:[NSData class]] || data.length == 0
        || ![privKey isKindOfClass:[NSString class]] || privKey.length == 0) {
        return nil;
    }
    SecKeyRef keyRef = [self _addPrivateKey:privKey];
    NSData *deData = [self _decryptData:data withKeyRef:keyRef];
    if (keyRef) {
        CFRelease(keyRef);
    }
    
    return deData;
}

+ (SecKeyRef)_addPrivateKey:(NSString *)privKey {
    NSString *key = nil;
    NSRange spos = [privKey rangeOfString:@"-----BEGIN RSA PRIVATE KEY-----"];
    NSRange epos = [privKey rangeOfString:@"-----END RSA PRIVATE KEY-----"];
    if (spos.location != NSNotFound && epos.location != NSNotFound) {
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e - s);
        key = [privKey substringWithRange:range];
    } else {
        key = privKey;
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    // This key will be base64 encoded, decode it.
    NSData *data = zz_base64_decode_str(key);
    data = [self _stripPrivateKeyHeader:data];
    if (!data) {
        return NULL;
    }
    
    // a tag to read/write keychain storage
    NSData *d_tag = [NSData dataWithBytes:[ZZ_RSAUtil_PrivKey_TAG UTF8String]
                                   length:ZZ_RSAUtil_PrivKey_TAG.length];
    
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
    SecKeyRef keyRef = nil;
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
