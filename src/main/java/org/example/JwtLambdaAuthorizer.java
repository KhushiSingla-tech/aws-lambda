package org.example;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayCustomAuthorizerEvent;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

@Slf4j
public class JwtLambdaAuthorizer implements RequestHandler<APIGatewayCustomAuthorizerEvent, Map<String, Object>> {

    private JwtUtil jwtUtil = new JwtUtil();

    /**
     * Handles the incoming request
     * @param event The incoming event
     * @param context The Lambda context
     * @return The response
     */
    @Override
    public Map<String, Object> handleRequest(APIGatewayCustomAuthorizerEvent event, Context context) {
        String token = event.getAuthorizationToken();
        if (token == null || token.isEmpty()) {
            log.info("Token is missing");
            throw new RuntimeException("Unauthorized");
        }
        try {
            Claims claims = jwtUtil.extractClaims(token);
            if (jwtUtil.validateToken(token)) {
                throw new RuntimeException("Unauthorized");
            }
            return generatePolicy(claims, "Allow", event.getMethodArn());
        } catch (Exception e) {
            log.error("Error validating token: {}", e.getMessage());
            throw new RuntimeException("Unauthorized");
        }
    }

    /**
     * Generates the policy
     * @param claims The claims extracted from the JWT token
     * @param effect The effect (Allow/Deny)
     * @param methodArn The method ARN
     * @return The policy
     */
    private Map<String, Object> generatePolicy(Claims claims, String effect, String methodArn) {
        Map<String, Object> response = new HashMap<>();

        Map<String, Object> policyDocument = new HashMap<>();
        policyDocument.put("Version", "2012-10-17");
        policyDocument.put("Statement", new Object[] {
                new HashMap<String, Object>() {{
                    put("Effect", effect);
                    put("Action", "execute-api:Invoke");
                    put("Resource", methodArn);
                }}
        });

        response.put("principalId", claims.getSubject());
        response.put("policyDocument", policyDocument);

        Map<String, String> context = new HashMap<>();
        context.put("user_id", (String) claims.get("user_id"));
        response.put("context", context);

        return response;
    }
}
