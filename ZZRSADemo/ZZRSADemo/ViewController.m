//
//  ViewController.m
//  ZZRSADemo
//
//  Created by SandsLee on 2021/6/9.
//

#import "ViewController.h"
#import "ZZRSAEncryptor.h"

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UITextField *textField;
@property (weak, nonatomic) IBOutlet UITextView *textView;

@property (nonatomic, copy) NSString *gPubkey; // 公钥
@property (nonatomic, copy) NSString *gPrikey; // 私钥

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    [self initValues];
    
    [self loadRSAKey];
    
    self.textField.text = [NSUUID UUID].UUIDString;
}

- (void)loadRSAKey {
    // 加载公钥字符串
//    [ZZRSAEncryptor zz_loadPublicKeyString:self.gPubkey];
    // 加载私钥字符串
//    [ZZRSAEncryptor zz_loadPrivateKeyString:self.gPrikey];
    
    // 加载1024位PEM公钥文件
//    NSString *pubFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_1024_public_key" ofType:@"pem"];
//    [ZZRSAEncryptor zz_loadPublicKeyFile:pubFilePath];
    // 加载1024位PEM私钥文件
//    NSString *privFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_1024_private_key_pkcs8" ofType:@"pem"];
//    [ZZRSAEncryptor zz_loadPrivateKeyFile:privFilePath password:nil];
    
    // 加载2048位PEM公钥文件
//    NSString *pubFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_2048_public_key" ofType:@"pem"];
//    [ZZRSAEncryptor zz_loadPublicKeyFile:pubFilePath];
    // 加载2048位PEM私钥文件
//    NSString *privFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_2048_private_key_pkcs8" ofType:@"pem"];
//    [ZZRSAEncryptor zz_loadPrivateKeyFile:privFilePath password:nil];
    
    // 加载2048位der公钥文件
    NSString *pubFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_2048_public" ofType:@"der"];
    [ZZRSAEncryptor zz_loadPublicKeyFile:pubFilePath];
    // 加载2048位p12私钥文件
    NSString *privFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_2048_private" ofType:@"p12"];
    [ZZRSAEncryptor zz_loadPrivateKeyFile:privFilePath password:@"1121"];
    
}



- (IBAction)rsaPub_PrivButtonClicked:(UIButton *)sender {
    [self.view endEditing:YES];
    NSString *plainText = self.textField.text;
    if (plainText.length == 0) {
        return;
    }
    NSLog(@"---- 公钥加密, 私钥解密 ----");
    // RSA 公钥字符串加密
//    NSString *encryptStr = [ZZRSAUtil zz_encrypt:plainText publicKey:self.gPubkey];
    
    // RSA 私钥字符串解密
//    NSString *decryptStr = [ZZRSAUtil zz_decrypt:encryptStr privateKey:self.gPrikey];
    
    // RSA 公钥1024位pem文件加密
//    NSString *pubFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_1024_public_key" ofType:@"pem"];
//    NSString *encryptStr = [ZZRSAUtil zz_encrypt:plainText publicKeyFilePath:pubFilePath];
    
    // RSA 私钥1024位pem文件解密
//    NSString *privFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_1024_private_key_pkcs8" ofType:@"pem"];
//    NSString *decryptStr = [ZZRSAUtil zz_decrypt:encryptStr
//                              privateKeyFilePath:privFilePath
//                            privateKeyFilePasswd:nil];
    
    // RSA 公钥2048位pem文件加密
//    NSString *pubFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_2048_public_key" ofType:@"pem"];
//    NSString *encryptStr = [ZZRSAUtil zz_encrypt:plainText publicKeyFilePath:pubFilePath];
    
    // RSA 私钥2048位pem文件解密
//    NSString *privFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_2048_private_key_pkcs8" ofType:@"pem"];
//    NSString *decryptStr = [ZZRSAUtil zz_decrypt:encryptStr
//                              privateKeyFilePath:privFilePath
//                            privateKeyFilePasswd:nil];
    
    // RSA 公钥2048位pem文件加密
//    NSString *pubFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_2048_public" ofType:@"pem"];
//    NSString *encryptStr = [ZZRSAUtil zz_encrypt:plainText publicKeyFilePath:pubFilePath];
    
    // RSA 私钥2048位p12文件解密
//    NSString *privFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_2048_private" ofType:@"p12"];
//    NSString *decryptStr = [ZZRSAUtil zz_decrypt:encryptStr
//                              privateKeyFilePath:privFilePath
//                            privateKeyFilePasswd:@"1121"];
    
    NSString *encryptStr = [ZZRSAEncryptor zz_encrypt:plainText byKeyType:ZZRSAKeyTypePublic];
    NSString *decryptStr = [ZZRSAEncryptor zz_decrypt:encryptStr byKeyType:ZZRSAKeyTypePrivate];
    
    
    NSMutableString *mStr = [NSMutableString stringWithString:self.textView.text];
    [mStr appendFormat:@"\nRSA加密密文：\n%@\nRSA解密结果：\n%@", encryptStr, decryptStr];
    self.textView.text = mStr;
    
}

- (IBAction)rsaPriv_PubButtonClicked:(UIButton *)sender {
    [self.view endEditing:YES];
    NSString *plainText = self.textField.text;
    if (plainText.length == 0) {
        return;
    }
    NSLog(@"---- 私钥加密, 公钥解密 ----");
    // RSA 私钥字符串加密
//    NSString *encryptStr = [ZZRSAUtil zz_encrypt:plainText privateKey:self.gPrikey];
    
    // RSA 公钥字符串解密
//    NSString *decryptStr = [ZZRSAUtil zz_decrypt:encryptStr publicKey:self.gPubkey];
    
    
    // RSA 私钥1024位pem文件加密
//    NSString *privFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_1024_private_key_pkcs8" ofType:@"pem"];
//    NSString *encryptStr = [ZZRSAUtil zz_encrypt:plainText
//                              privateKeyFilePath:privFilePath
//                            privateKeyFilePasswd:nil];
    
    // RSA 公钥1024位pem文件解密
//    NSString *pubFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_1024_public_key" ofType:@"pem"];
//    NSString *decryptStr = [ZZRSAUtil zz_decrypt:encryptStr publicKeyFilePath:pubFilePath];
    
    // RSA 私钥2048位pem文件加密
//    NSString *privFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_2048_private_key_pkcs8" ofType:@"pem"];
//    NSString *encryptStr = [ZZRSAUtil zz_encrypt:plainText
//                              privateKeyFilePath:privFilePath
//                            privateKeyFilePasswd:nil];
    
    // RSA 公钥2048位pem文件解密
//    NSString *pubFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_2048_public_key" ofType:@"pem"];
//    NSString *decryptStr = [ZZRSAUtil zz_decrypt:encryptStr publicKeyFilePath:pubFilePath];
    
    
    // RSA 私钥2048位p12文件加密
//    NSString *privFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_2048_private" ofType:@"p12"];
//    NSString *encryptStr = [ZZRSAUtil zz_encrypt:plainText
//                              privateKeyFilePath:privFilePath
//                            privateKeyFilePasswd:@"1121"];
    
    // RSA 公钥2048位pem文件解密
//    NSString *pubFilePath = [[NSBundle mainBundle] pathForResource:@"rsa_2048_public" ofType:@"pem"];
//    NSString *decryptStr = [ZZRSAUtil zz_decrypt:encryptStr publicKeyFilePath:pubFilePath];
    
    NSString *encryptStr = [ZZRSAEncryptor zz_encrypt:plainText byKeyType:ZZRSAKeyTypePrivate];
    NSString *decryptStr = [ZZRSAEncryptor zz_decrypt:encryptStr byKeyType:ZZRSAKeyTypePublic];
    
    NSMutableString *mStr = [NSMutableString stringWithString:self.textView.text];
    [mStr appendFormat:@"\nRSA加密密文：\n%@\nRSA解密结果：\n%@", encryptStr, decryptStr];
    self.textView.text = mStr;
    
}

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    [self.view endEditing:YES];
}


- (void)initValues {
    /*
     * 在线获取任意的公钥私钥字符串http://www.bm8.com.cn/webtool/rsa/
     * 注意：由于公钥私钥里面含有`/+=\n`等特殊字符串
     * 网络传输过程中导致转义，进而导致加密解密不成功，
     * 解决办法是传输前进行 URL 特殊符号编码解码(URLEncode 百分号转义)
     */
    self.gPubkey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTbZ6cNH9PgdF60aQKveLz3FTalyzHQwbp601y77SzmGHX3F5NoVUZbdK7UMdoCLK4FBziTewYD9DWvAErXZo9BFuI96bAop8wfl1VkZyyHTcznxNJFGSQd/B70/ExMgMBpEwkAAdyUqIjIdVGh1FQK/4acwS39YXwbS+IlHsPSQIDAQAB";
    //私钥
    self.gPrikey = @"MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANNtnpw0f0+B0XrRpAq94vPcVNqXLMdDBunrTXLvtLOYYdfcXk2hVRlt0rtQx2gIsrgUHOJN7BgP0Na8AStdmj0EW4j3psCinzB+XVWRnLIdNzOfE0kUZJB38HvT8TEyAwGkTCQAB3JSoiMh1UaHUVAr/hpzBLf1hfBtL4iUew9JAgMBAAECgYA1tGeQmAkqofga8XtwuxEWDoaDS9k0+EKeUoXGxzqoT/GyiihuIafjILFhoUA1ndf/yCQaG973sbTDhtfpMwqFNQq13+JAownslTjWgr7Hwf7qplYW92R7CU0v7wFfjqm1t/2FKU9JkHfaHfb7qqESMIbO/VMjER9o4tEx58uXDQJBAO0O4lnWDVjr1gN02cqvxPOtTY6DgFbQDeaAZF8obb6XqvCqGW/AVms3Bh8nVlUwdQ2K/xte8tHxjW9FtBQTLd8CQQDkUncO35gAqUF9Bhsdzrs7nO1J3VjLrM0ITrepqjqtVEvdXZc+1/UrkWVaIigWAXjQCVfmQzScdbznhYXPz5fXAkEAgB3KMRkhL4yNpmKRjhw+ih+ASeRCCSj6Sjfbhx4XaakYZmbXxnChg+JB+bZNz06YBFC5nLZM7y/n61o1f5/56wJBALw+ZVzE6ly5L34114uG04W9x0HcFgau7MiJphFjgUdAtd/H9xfgE4odMRPUD3q9Me9LlMYK6MiKpfm4c2+3dzcCQQC8y37NPgpNEkd9smMwPpSEjPW41aMlfcKvP4Da3z7G5bGlmuICrva9YDAiaAyDGGCK8LxC8K6HpKrFgYrXkRtt";
    
    
    //----------------URL编码解码，解决特殊符号问题----------------
    // 服务器传输过来的公钥字符串可能是这样的
    NSString *RSAPublickKeyFromServer = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTbZ6cNH9PgdF60aQKveLz3FTalyzHQwbp601y77SzmGHX3F5NoVUZbdK7UMdoCLK4FBziTewYD9DWvAErXZo9BFuI96bAop8wfl1VkZyyHTcznxNJFGSQd%2FB70%2FExMgMBpEwkAAdyUqIjIdVGh1FQK%2F4acwS39YXwbS%2BIlHsPSQIDAQAB";
    // RSAPublickKeyFromServer URLDecode解码后应该和 gPubkey 相同
    NSString *urlDecodePublicKey = RSAPublickKeyFromServer.stringByRemovingPercentEncoding;
    if ([urlDecodePublicKey isEqualToString:self.gPubkey]) {
        NSLog(@"解码后和标准公钥一致");
    } else {
        NSLog(@"解码后和标准公钥不一致");
    }
    // URLEncode，除数字字母外的符号都进行 URLEncode
    NSString *urlEncodePublicKey = [self.gPubkey stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.alphanumericCharacterSet];
    if ([urlEncodePublicKey isEqualToString:RSAPublickKeyFromServer]) {
        NSLog(@"编码后和服务器传过来的一致");
    } else {
        NSLog(@"编码后和服务器传过来的不一致");
    }
}


@end
