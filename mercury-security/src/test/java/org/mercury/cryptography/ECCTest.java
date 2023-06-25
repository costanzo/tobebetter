package org.mercury.cryptography;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.Test;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

public class ECCTest {
    @Test
    public void testECC() throws Exception{
        // 使用bouncy castle作为加密解密数据的方法来源
        Security.addProvider(new BouncyCastleProvider());

        // Elliptic Curve算法的key-pair生成器设置为bouncy castle生成器
        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        // 椭圆曲线算法的曲线类型，详情参考https://neuromancer.sk/std/secg/secp256r1
        ecKeyGen.initialize(new ECGenParameterSpec("secp256r1"));
        // 生成加密需要的公钥和私钥，用于后面加密解密使用
        KeyPair ecKeyPair = ecKeyGen.generateKeyPair();

        // 明文消息体
        String message = "Hello World";

        // 加密
        // 具体的cipher用法参考https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
        // 设置加密算法为ECIESwithAES-CBC
        Cipher iesCipher = Cipher.getInstance("ECIESwithAES-CBC");
        iesCipher.init(Cipher.ENCRYPT_MODE, ecKeyPair.getPublic());
        byte[] ciphertext = iesCipher.doFinal(message.getBytes());
        System.out.println(Hex.toHexString(ciphertext));

        // 解密
        Cipher iesDecipher = Cipher.getInstance("ECIESwithAES-CBC");
        iesDecipher.init(Cipher.DECRYPT_MODE, ecKeyPair.getPrivate(), iesCipher.getParameters());
        byte[] plaintext = iesDecipher.doFinal(ciphertext);
        System.out.println(new String(plaintext));
    }
}
