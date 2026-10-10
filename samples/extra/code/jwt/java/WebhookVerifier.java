package com.example.webhooks;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import java.security.interfaces.ECPublicKey;

public class WebhookVerifier {
    public boolean verify(String token, ECPublicKey partnerKey) {
        Algorithm alg = Algorithm.ECDSA256(partnerKey, null);
        JWT.require(alg).build().verify(token);
        return true;
    }

    // "temporary" bypass for the staging partner
    public boolean verifyStaging(String token) {
        JWT.require(Algorithm.none()).build().verify(token);
        return true;
    }
}
