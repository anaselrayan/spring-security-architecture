package com.anas.authorization_server.authentication.services;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

public class JwtService {

    private final String SECRET = "!very*secret!";
    private final Long ACCESS_TOKEN_EXP = (long) (1000 * 60 * 60);          // 1 HOUR
    private final Long REFRESH_TOKEN_EXP = (long) (1000 * 60 * 60 * 24);    // 24 HOURS

    public String createAccessToken(UserDetails user) {
        var authorities = getUserAuthorities(user);
        return JWT.create()
                .withSubject(user.getUsername())
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXP))
                .withClaim("authorities", authorities)
                .sign(algorithm());
    }

    public String extractSubject(String token) {
        var decodedJwt = verifyToken(token);
        if (decodedJwt != null) {
            return decodedJwt.getSubject();
        }
        return null;
    }

    public String createRefreshToken(UserDetails user) {
        var authorities = getUserAuthorities(user);
        return JWT.create()
                .withSubject(user.getUsername())
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXP))
                .withClaim("authorities", authorities)
                .sign(algorithm());
    }

    public HashMap<String, String> createTokens(UserDetails user) {
        String accessToken = createAccessToken(user);
        String refreshToken = createRefreshToken(user);
        var tokens = new HashMap<String, String>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);
        return tokens;
    }

    public DecodedJWT verifyToken(String token) {
        try {
            JWTVerifier verifier = JWT.require(algorithm()).build();
            return verifier.verify(token);
        } catch (Exception e) {
            System.out.print("JWT-ERROR: ");
            System.err.print(e.getMessage() + "\n");
            return null;
        }
    }

    private Algorithm algorithm() {
        return Algorithm.HMAC256(SECRET.getBytes());
    }

    public boolean isValidAccessToken(String token) {
        var decodedJwt = verifyToken(token);
        if (decodedJwt != null) {
            Date iss = decodedJwt.getIssuedAt();
            Date exp = decodedJwt.getExpiresAt();
            return (exp.getTime() - iss.getTime()) == ACCESS_TOKEN_EXP;
        }
        return false;
    }

    public boolean isValidRefreshToken(String token) {
        var decodedJwt = verifyToken(token);
        if (decodedJwt != null) {
            Date iss = decodedJwt.getIssuedAt();
            Date exp = decodedJwt.getExpiresAt();
            return (exp.getTime() - iss.getTime()) == REFRESH_TOKEN_EXP;
        }
        return false;
    }

    private List<String> getUserAuthorities(UserDetails user) {
        return user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }
}
