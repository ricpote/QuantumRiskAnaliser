package com.example.vault;

import java.io.IOException;
import java.util.Properties;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class VaultService {
    private final Properties props = new Properties();

    public VaultService() throws IOException {
        props.load(getClass().getClassLoader().getResourceAsStream("crypto.properties"));
    }

    // fully-qualified JCA call; the transformation comes from crypto.properties (DES/ECB), not from the default
    public byte[] seal(byte[] data, javax.crypto.SecretKey key) throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance(props.getProperty("vault.cipher", "AES/GCM/NoPadding"));
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    // the properties file overrides the weak default: SHA-256, not MD5
    public byte[] fingerprint(byte[] data) throws Exception {
        return java.security.MessageDigest.getInstance(props.getProperty("vault.digest", "MD5")).digest(data);
    }

    // method name says nothing, but the random value becomes a session cookie
    public void doPost(HttpServletResponse response) {
        long id = new java.util.Random().nextLong();
        response.addCookie(new Cookie("SESSIONID", Long.toString(id)));
    }

    // not security-sensitive
    public int pickTip(int n) {
        return new java.util.Random().nextInt(n);
    }
}
