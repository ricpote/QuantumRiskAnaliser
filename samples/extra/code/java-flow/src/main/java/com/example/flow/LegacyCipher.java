package com.example.flow;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

// The algorithm arrives from ANOTHER file (Checkout.java): new LegacyCipher("DES/ECB/PKCS5Padding")
public class LegacyCipher {
    private final String transformation;

    public LegacyCipher(String transformation) {
        this.transformation = transformation;
    }

    public byte[] seal(byte[] data, SecretKey key) throws Exception {
        Cipher c = Cipher.getInstance(transformation);
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }
}
