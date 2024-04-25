package com.backend.security.service;

import com.backend.security.model.CustomUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtService {


    @Value("${spring.security.jwt.secret-key}")
    private String JWT_SECRET_KEY;

    @Value("${spring.security.jwt.expiration}")
    private long JWT_EXPIRATION;

    @Value("${spring.security.jwt.refresh-token.expiration}")
    private long REFRESH_TOKEN_EXPIRATION;


    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractUserId(String token) {
        return extractClaim(token, Claims::getId);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public String generateToken(CustomUserDetails user){

        return createToken(new HashMap<>(),user.getUsername(), String.valueOf(user.getId()), JWT_EXPIRATION);
    }

    public String generateLogoutToken(String token){
        return createToken(new HashMap<>()," ", extractUserId(token), 0);
    }

    public String generateRefreshToken(CustomUserDetails user) {
        return createToken(new HashMap<>(),user.getUsername(),  String.valueOf(user.getId()), REFRESH_TOKEN_EXPIRATION);
    }

    private String createToken(Map<String, Object> claims, String username, String userId, long expiration) {

        return Jwts.builder()
                .setClaims(claims)
                .setId(userId)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .setSubject(username)
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(JWT_SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
