package com.example.flow;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

public class Checkout {
    private final LegacyCipher legacy = new LegacyCipher("DES/ECB/PKCS5Padding");

    // inter-procedural: the digest name is passed by the caller below
    byte[] fingerprint(String alg, byte[] data) throws Exception {
        return MessageDigest.getInstance(alg).digest(data);
    }

    byte[] receiptId(byte[] data) throws Exception {
        return fingerprint("MD5", data);
    }

    // path-sensitive: the weak instance is replaced before use (always, mode is 2)
    void upgrade(int mode) throws Exception {
        Cipher c = Cipher.getInstance("RC4");
        if (mode > 1)
            c = Cipher.getInstance("AES/GCM/NoPadding");
        c.getBlockSize();
    }

    void run() throws Exception {
        int mode = 2;
        upgrade(mode);
    }

    // fixed IV, fixed salt, constant seed, fixed keystore password
    void staticMaterial(KeyStore ks, java.io.InputStream in) throws Exception {
        IvParameterSpec iv = new IvParameterSpec("0000000000000000".getBytes());
        byte[] salt = {(byte) 0xa2, (byte) 0x11};
        PBEParameterSpec pbe = new PBEParameterSpec(salt, 1000);
        SecureRandom sr = new SecureRandom();
        sr.setSeed(42L);
        ks.load(in, "changeit".toCharArray());
    }

    // trap: the IV is replaced by random bytes before use, iterations end up at 210000
    void randomMaterial(int mode) throws Exception {
        byte[] iv = "0000000000000000".getBytes();
        int count = 5;
        SecureRandom sr = new SecureRandom();
        if (mode > 0) {
            iv = new byte[16];
            sr.nextBytes(iv);
        }
        if (mode > 0)
            count = 210000;
        IvParameterSpec spec = new IvParameterSpec(iv);
        PBEParameterSpec pbe = new PBEParameterSpec(iv, count);
    }

    void go() throws Exception {
        randomMaterial(1);
    }
}
