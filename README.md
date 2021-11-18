# ZZRSASecurity
基于RSA公钥算法的加密解密工具库iOS OC语言实现，依赖iOS系统的Security.framework。

##  RSA公钥算法

算法原理参考：
* [RSA算法原理（一）](ruanyifeng.com/blog/2013/06/rsa_algorithm_part_one.html) 
* [RSA算法原理（二）](http://www.ruanyifeng.com/blog/2013/07/rsa_algorithm_part_two.html)

## RSA密钥证书的生成

SSL 证书格式普及，PEM、CER、JKS、PKCS12（p12）
* .PEM，一般是文本格式，BASE64编码的字符串，可保存证书（公钥），也可保存私钥。
* .DER .CER，文件是二进制格式，只保存证书（公钥），不保存私钥。
* .CRT，可以是二进制格式，可以是文本格式，与 .DER 格式相同，不保存私钥。
* .PFX .P12，二进制格式，同时包含证书（公钥）和私钥，一般有密码保护。
* .JKS，二进制格式，同时包含证书（公钥）和私钥，一般有密码保护。

### PEM格式密钥证书的生成

密钥生成需要使用到 `openssl` 命令行工具。PEM格式密钥证书的生成需要两步：

1. 生成RSA私钥

    `openssl genrsa -out rsa_1024_private_key.pem 1024`
    
    密钥长度可选：512、768、1024、2048，一般采用1024位。私钥示例如下：
    
    ```
    -----BEGIN RSA PRIVATE KEY-----
    MIICWwIBAAKBgQDi2zhD1tyf+cCcYQ7MGzjbDU87+eEgdp/fupeEyoDMHanISisx
    yNNXoFeUAot55ul470Jt0qLk9OUlTdmN5CEpIDzJtjLbXy+phPknNgLOwpTGRvkd
    kUb0LeHbHnUf0vfBJkN2LSD1pA1EiaLEakwakIg3roUNiI8gtuLWWzCQkQIDAQAB
    AoGAFSrFRjcvINIp8a1wtwS3OmE0inEXW3MWGccMSjym5eTCqciZ3SxS4/M3GL1g
    DEDKehlBBoRH5LshAmkQKpglq8asoV+bDvkDQqdqg+F91JAUVV7DTHrU659Psdnv
    MO6h7poNMgezz6Hm9JErt4vzdy3dg6D8uQKCrXxlsfvufVECQQD8J+zz4xTr40v6
    DQPuYYerEpMENFaophyP71ah2wQkVurERGRC9vwlktYR3fMESfya9ajAE3xeLHiO
    hhbbW0pFAkEA5lCPDI+NWDPOFl1+awRzrlmStRJsz7PJqp5ygCiepBWLknEa1git
    sJtmokqAnUTCbhzQuJdpmBU1R2sB/tRX3QJACUPOSQfG9QPc/ssLoe6jdX2xOS5T
    IM85rXA11qydclhfN+braCp7CUZj5zQogbfWODtef/A3WZ54r4PtwxGPoQJAIrXf
    aUA1SCa+l4ZNqClKmesr/hghyAfLi+hHT2NPzWDl4RMkvT8fli9Ff44E5i7Xsqqr
    FjbTljUUC4hoC5TLDQJAUAjwB/Aw5DqGHKXxVa2yj/y/78vAoC88bzrW77g+dPim
    VTjItiL09hVAz00Xw9MuvN8F16BEg4hSEqoLciKM1Q==
    -----END RSA PRIVATE KEY-----
    ```
**注意：当使用PEM格式的私钥证书文件时，需要转为pkcs8的格式。** 转换命令如下：

`openssl pkcs8 -topk8 -inform PEM -in rsa_1024_private_key.pem -outform PEM -nocrypt > rsa_1024_private_key_pkcs8.pem`


2. 生成私钥对应的RSA公钥

    `openssl rsa -in rsa_1024_private_key.pem -pubout -out rsa_1024_public_key.pem`
    
    输入是私钥，输出是公钥。公钥示例如下：
    
    ```
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDi2zhD1tyf+cCcYQ7MGzjbDU87
    +eEgdp/fupeEyoDMHanISisxyNNXoFeUAot55ul470Jt0qLk9OUlTdmN5CEpIDzJ
    tjLbXy+phPknNgLOwpTGRvkdkUb0LeHbHnUf0vfBJkN2LSD1pA1EiaLEakwakIg3
    roUNiI8gtuLWWzCQkQIDAQAB
    -----END PUBLIC KEY-----
    ```

### DER格式密钥证书的生成

DER格式的证书一般只保存公钥，可由PEM格式转换得到，转换命令如下：

`openssl rsa -in rsa_1024_public_key.pem -pubin -outform DER -out rsa_1024_public_key.der`

**注意：iOS上使用的DER格式证书要求是x509编码的，所以不能用上面的命令生成，具体参考下面的p12密钥证书生成章节。**

当然，私钥也是可以转为DER格式的，但是一般不这么做。转换命令如下：

`openssl rsa -in rsa_1024_private_key.pem -outform DER -out rsa_1024_private_key.der`


### p12格式密钥证书的生成

p12证书是iOS上比较常用的。p12证书生成需要4步：

1. 生成RSA私钥文件
    
    `openssl genrsa -out rsa_2048_private_key.pem 2048`
    
2. 生成证书请求文件（.csr）

    `openssl req -new -out rsa_2048_private.csr -key rsa_2048_private_key.pem -keyform PEM`
    
    这条命令会开启一个交互式命令行，需要输入一些信息，如下图：
    ![csr](https://raw.githubusercontent.com/lishuzhi1121/oss/master/uPic/2021/06/11-175318-KEJzE6.png)

3. 请求证书文件（.cer）

    `openssl x509 -req -in rsa_2048_private.csr -out rsa_2048_cert.cer -signkey rsa_2048_private_key.pem -CAcreateserial -days 32120`
    
    输入是上面生成的csr证书请求文件，签名是最开始生成的私钥文件，输出是cer的证书文件。'-days 32120' 表示证书有效时间，单位天，365 * 88 = 32120，所以有效时间是88年。
    
    注意：在iOS系统中，cer/crt文件也不能直接使用。需要转成der文件，命令如下:
    
    `openssl x509 -in rsa_2048_cert.crt -outform der -out rsa_2048_public.der`

4. 导出为p12文件

    `openssl pkcs12 -export -clcerts -in rsa_2048_private_cert.cer -inkey rsa_2048_private_key.pem -out rsa_2048_private_key.p12`
    
    这条命令会开启一个交互式命令行，需要输入前面设置的证书密码，如果没有设置密码直接回车即可，如下图：
    ![p12](https://raw.githubusercontent.com/lishuzhi1121/oss/master/uPic/2021/06/11-174232-nEOIJb.png)
    
**注意：这里生成的p12密钥证书文件一般作为RSA私钥使用。配合使用的公钥是证书文件转换得到的der文件。**

