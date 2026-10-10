package com.example.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.KeyPair;
import java.util.Date;

public class TokenIssuer {
    private static final String LEGACY_SECRET = "s3cr3t-k3y";

    public String issueAccessToken(KeyPair kp, String subject) {
        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(new Date())
                .signWith(kp.getPrivate(), SignatureAlgorithm.RS256)
                .compact();
    }

    // old jjwt API: HMAC with a string secret
    public String issueLegacyToken(String subject) {
        return Jwts.builder()
                .setSubject(subject)
                .signWith(SignatureAlgorithm.HS256, LEGACY_SECRET)
                .compact();
    }
}
