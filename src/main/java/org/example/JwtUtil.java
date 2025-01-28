package org.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.util.Date;
import java.util.Map;

@Slf4j
public class JwtUtil {

    /**
     * Extracts the claims from the JWT token
     * @param jwt The JWT token
     * @return The claims extracted from the token
     */
    public Claims extractClaims(String jwt) {
        JwtParser jwtParser = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(getSecret().getBytes()))
                .build();
        try {
            return jwtParser.parseSignedClaims(jwt).getPayload();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Validates the JWT token
     * @param token The JWT token
     * @return True if the token is valid, false otherwise
     */
    public boolean validateToken(String token) {
        return extractClaims(token).getExpiration().before(new Date());
    }

    /**
     * Gets the secret from AWS Secrets Manager
     * @return The secret
     */
    private String getSecret() {
        String secretName = "JWT_Token";
        Region region = Region.of("ap-south-1");

        SecretsManagerClient client = SecretsManagerClient.builder()
                .region(region)
                .build();
        GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
                .secretId(secretName)
                .build();

        try {
            GetSecretValueResponse getSecretValueResponse = client.getSecretValue(getSecretValueRequest);
            String secretString = getSecretValueResponse.secretString();

            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, String> secretMap = objectMapper.readValue(secretString, Map.class);

            return secretMap.get("JWT_TOKEN");
        } catch (Exception e) {
            log.error("Error: {}", e.getMessage());
        }
        return null;
    }
}
