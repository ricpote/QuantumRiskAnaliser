package com.example.hard;

import static com.example.hard.CryptoConstants.ZERO_IV;

import io.jsonwebtoken.Jwts;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Gateway {
    byte[] fingerprint(byte[] data) throws Exception {
        return MessageDigest.getInstance(CryptoConstants.LEGACY_DIGEST).digest(data);   // constant from another file
    }

    Cipher legacyRsa() throws Exception {
        return Cipher.getInstance("RSA/ECB/NoPadding");                                  // textbook RSA
    }

    void keys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        kpg.initialize(3072);
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec spec = new ECGenParameterSpec("secp112r1");
        ec.initialize(spec);
    }

    void seal(SecretKey key) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ZERO_IV));                  // zero IV from another file
    }

    void open(SecretKey key, byte[] ivFromMessage) throws Exception {
        byte[] iv = new byte[16];
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));                       // decrypt only: not reported
    }

    String unsignedToken() {
        return Jwts.builder().setSubject("bob").compact();                               // no signWith(): alg none
    }
}
