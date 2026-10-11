package com.example.hard;

import java.security.AlgorithmParameterGenerator;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyGenerator;

public class KeyMaterial {

    public void provision() throws Exception {
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(3072);
        }
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
            kpg.initialize(1024);
        }
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(4096);
        gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("X9.62 prime192v2"));

        AlgorithmParameterGenerator dh = AlgorithmParameterGenerator.getInstance("DH");
        dh.init(1024);

        KeyGenerator aes = KeyGenerator.getInstance("AES");
        aes.init(64);
    }
}
